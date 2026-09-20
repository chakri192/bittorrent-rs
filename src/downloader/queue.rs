//! Thread-safe queue of pending pieces, shared across peer worker threads
//! via `Arc<WorkQueue>`. `Mutex`-protected structures are enough here;
//! contention is low (one lock per piece pop/requeue/availability-update,
//! not per block), which avoids pulling in an async runtime or lock-free
//! crate for a from-scratch client.
//!
//! Pieces are handed out **rarest-first**: `pop()` returns whichever
//! pending piece the fewest known peers have, not simply the first one
//! queued. This is standard BitTorrent piece-selection strategy -- if
//! every peer serves pieces in the same naive order (e.g. index order),
//! a piece only one peer in the swarm has can become unavailable the
//! moment that peer disconnects, stalling the whole download on it late.
//!
//! **Endgame mode** (BEP 3 §"Piece downloading strategy"): once nothing
//! is left in `pending`, `pop()` starts handing out *duplicates* of
//! pieces other workers have already claimed but not finished. Without
//! this, the last few pieces of a download are hostage to whichever
//! (possibly glacial) peer claimed them first -- the classic "99% then
//! crawls" tail. First verified copy wins: `mark_done` retires the piece
//! everywhere, and late duplicate downloads abandon via `is_done`.

use crate::downloader::piece_assembler::{PartialPiece, PieceWork};
use std::collections::{HashMap, HashSet};
use crate::sync::lock;
use std::sync::Mutex;

/// Which pending piece comes out first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Order {
    /// The piece fewest peers have (`--sequential` off). Keeps pieces from
    /// becoming unavailable, and gets the most out of a swarm.
    #[default]
    RarestFirst,
    /// The lowest index, whatever its rarity (`--sequential`), so a file
    /// can be played or inspected while it downloads. Costs the swarm
    /// health rarest-first buys: pieces only one peer has are fetched
    /// only when their turn comes.
    Sequential,
}

/// What [`WorkQueue::take_for`] found for a peer.
#[derive(Debug, Clone, PartialEq)]
pub enum Take {
    /// A piece to download from this peer.
    Piece(PieceWork),
    /// Pieces remain, but this peer has none of them (yet): wait for it to
    /// announce more, or let it go.
    NothingForThisPeer,
    /// Every piece is done.
    Done,
}

struct Inner {
    /// Not yet done, not currently claimed by any worker.
    pending: Vec<PieceWork>,
    /// Claimed by >= 1 worker, not yet verified-and-written. Keyed by
    /// piece index so endgame `pop` can hand out another copy.
    claimed: HashMap<u32, PieceWork>,
    /// Verified and written to disk.
    done: HashSet<u32>,
    /// Blocks of pieces whose connection failed part-way, for the next
    /// connection to start from. Bounded by [`MAX_STASHED_BYTES`].
    partial: HashMap<u32, PartialPiece>,
}

/// The most memory the queue keeps in partly downloaded pieces. Without a
/// bound, peers that keep failing part-way through different pieces could
/// leave a good part of the torrent held in memory.
pub const MAX_STASHED_BYTES: usize = 64 << 20;

pub struct WorkQueue {
    inner: Mutex<Inner>,
    /// `availability[i]` = how many peers this process has observed
    /// claiming to have piece `i` (via Bitfield or Have), across every
    /// connection this run has made. Never decremented -- a peer
    /// disconnecting doesn't un-teach us that piece was out there
    /// somewhere; treating a once-seen-available piece as "less rare"
    /// than it might currently be is a reasonable simplification for a
    /// downloader that doesn't track per-peer liveness at this layer.
    availability: Mutex<Vec<u32>>,
    order: Order,
    /// Pieces to hand out before any other (`--prefer`).
    preferred: HashSet<u32>,
}

impl WorkQueue {
    /// `total_pieces` sizes the availability table up front -- it must be
    /// at least as large as any piece index ever passed to `note_have` or
    /// present in `pieces` (in practice: `torrent.pieces.len()`).
    pub fn new(pieces: Vec<PieceWork>, total_pieces: usize) -> Self {
        WorkQueue {
            inner: Mutex::new(Inner { pending: pieces, claimed: HashMap::new(), done: HashSet::new(), partial: HashMap::new() }),
            availability: Mutex::new(vec![0u32; total_pieces]),
            order: Order::default(),
            preferred: HashSet::new(),
        }
    }

    /// Makes the pieces in `preferred` come out before all others, in
    /// whichever order is in force among themselves.
    pub fn with_preferred(mut self, preferred: HashSet<u32>) -> Self {
        self.preferred = preferred;
        self
    }

    /// Chooses which pending piece comes out first (rarest by default).
    pub fn with_order(mut self, order: Order) -> Self {
        self.order = order;
        self
    }

    /// Pops the rarest pending piece (ties broken arbitrarily) and marks
    /// it claimed. If nothing is pending but claimed pieces remain,
    /// returns a **duplicate** of the rarest claimed piece (endgame).
    /// Returns `None` only when every piece is done.
    ///
    /// For a source that has every piece (a web seed). A peer that may
    /// lack some should use [`take_for`](Self::take_for).
    pub fn pop(&self) -> Option<PieceWork> {
        match self.take_for(|_| true) {
            Take::Piece(work) => Some(work),
            Take::NothingForThisPeer | Take::Done => None,
        }
    }

    /// Hands out the rarest pending piece that `has` says this peer has,
    /// and marks it claimed. If nothing pending is on offer from this peer
    /// but some pieces are claimed, a duplicate of the rarest claimed one it
    /// has (endgame).
    ///
    /// The choice has to be made among the pieces the peer has. Rarity says
    /// which pieces matter most, and by definition few peers have the
    /// rarest; a worker given the rarest piece regardless would find its
    /// peer lacks it, and a peer holding only common pieces would sit idle
    /// for as long as the rare ones were unclaimed.
    ///
    /// Workers that can't finish the piece they were given (the download
    /// failed) call `push_back` to return it.
    pub fn take_for(&self, has: impl Fn(u32) -> bool) -> Take {
        self.take(has, true)
    }

    /// The next piece for a connection that is still busy with another, so that its requests can go on across the boundary:
    /// as `take_for`, but only a piece nobody has taken, and never a duplicate of one being fetched (an endgame piece is
    /// not looked ahead to), and never any if the queue is in endgame or has nothing this peer has.
    pub fn take_pending_for(&self, has: impl Fn(u32) -> bool) -> Option<PieceWork> {
        match self.take(has, false) {
            Take::Piece(work) => Some(work),
            Take::Done | Take::NothingForThisPeer => None,
        }
    }

    fn take(&self, has: impl Fn(u32) -> bool, endgame_duplicates: bool) -> Take {
        let mut inner = lock(&self.inner);
        let availability = lock(&self.availability);
        // Lower comes first. The index breaks ties, so the choice is
        // deterministic rather than an accident of the list's order.
        let order = self.order;
        let preferred = &self.preferred;
        let rank = |w: &PieceWork| {
            let later = u8::from(!preferred.contains(&w.index));
            match order {
                Order::RarestFirst => (later, availability.get(w.index as usize).copied().unwrap_or(0), w.index),
                Order::Sequential => (later, 0, w.index),
            }
        };

        let first_offered = inner.pending.iter().enumerate().filter(|(_, w)| has(w.index)).min_by_key(|(_, w)| rank(w)).map(|(i, _)| i);
        if let Some(index) = first_offered {
            // swap_remove is O(1) (vs. a true rarest-first-preserving
            // remove being O(n) regardless of representation) -- fine
            // since there is no ordering promise among equal-rarity
            // pieces to begin with.
            let work = inner.pending.swap_remove(index);
            inner.claimed.insert(work.index, work.clone());
            return Take::Piece(work);
        }

        // Endgame: nothing is pending at all, so duplicate-assign a
        // still-unfinished claimed piece this peer has. Only then: while
        // pieces remain pending that this peer lacks, letting it duplicate
        // claimed ones would have every partial peer in the swarm
        // downloading the same few pieces.
        if endgame_duplicates && inner.pending.is_empty() {
            if let Some(work) = inner.claimed.values().filter(|w| has(w.index)).min_by_key(|w| rank(w)).cloned() {
                return Take::Piece(work);
            }
        }

        if inner.pending.is_empty() && inner.claimed.is_empty() {
            Take::Done
        } else {
            Take::NothingForThisPeer
        }
    }

    /// Returns a piece to the queue after a failed attempt. No-ops if the
    /// piece has since been finished by another worker. Also clears any
    /// standing claim -- if some other worker is *still* downloading this
    /// piece, that's fine: it effectively continues as an endgame
    /// duplicate, and whichever copy verifies first retires the piece.
    pub fn push_back(&self, work: PieceWork) {
        let mut inner = lock(&self.inner);
        if inner.done.contains(&work.index) {
            return;
        }
        inner.claimed.remove(&work.index);
        if !inner.pending.iter().any(|w| w.index == work.index) {
            inner.pending.push(work);
        }
    }

    /// Keeps the blocks of a piece a connection had received when it failed,
    /// for whichever connection takes the piece next (see
    /// [`take_partial`](Self::take_partial)). Ignored if the piece is
    /// already done, or if keeping it would go over [`MAX_STASHED_BYTES`]
    /// (unless it replaces a smaller stash of the same piece). Where there
    /// is already a stash for the piece, the one with more blocks is kept.
    pub fn stash_partial(&self, index: u32, partial: PartialPiece) {
        let mut inner = lock(&self.inner);
        if inner.done.contains(&index) {
            return;
        }
        let held: usize = inner.partial.iter().filter(|(&i, _)| i != index).map(|(_, p)| p.size()).sum();
        if held + partial.size() > MAX_STASHED_BYTES {
            return;
        }
        match inner.partial.get(&index) {
            Some(existing) if existing.blocks_held() >= partial.blocks_held() => {}
            _ => {
                inner.partial.insert(index, partial);
            }
        }
    }

    /// Takes the stashed blocks of `index`, if any. Whoever takes them owns
    /// them: a second caller gets nothing, so two connections never
    /// resume the same stash.
    pub fn take_partial(&self, index: u32) -> Option<PartialPiece> {
        lock(&self.inner).partial.remove(&index)
    }

    /// Every stash held, to be kept across a stop (see [`crate::downloader::partial`]).
    pub fn partials(&self) -> Vec<(u32, PartialPiece)> {
        let mut all: Vec<(u32, PartialPiece)> = lock(&self.inner).partial.iter().map(|(&index, partial)| (index, partial.clone())).collect();
        all.sort_by_key(|(index, _)| *index);
        all
    }

    /// Whether the piece is still to be fetched (pending or being fetched).
    pub fn is_wanted(&self, index: u32) -> bool {
        let inner = lock(&self.inner);
        !inner.done.contains(&index) && (inner.claimed.contains_key(&index) || inner.pending.iter().any(|w| w.index == index))
    }

    /// Retires a piece everywhere after it has been verified and written.
    /// Returns `true` if this call was the first to mark it done (callers
    /// use this to avoid double-counting duplicate endgame completions).
    pub fn mark_done(&self, index: u32) -> bool {
        let mut inner = lock(&self.inner);
        let newly_done = inner.done.insert(index);
        inner.claimed.remove(&index);
        inner.pending.retain(|w| w.index != index);
        inner.partial.remove(&index);
        newly_done
    }

    /// Whether this piece has already been verified and written by some
    /// worker. Endgame workers poll this mid-download to abandon pieces
    /// that completed elsewhere instead of wasting the peer's bandwidth.
    pub fn is_done(&self, index: u32) -> bool {
        lock(&self.inner).done.contains(&index)
    }

    /// True once every piece is done (nothing pending, nothing claimed).
    pub fn is_empty(&self) -> bool {
        let inner = lock(&self.inner);
        inner.pending.is_empty() && inner.claimed.is_empty()
    }

    /// Pieces not yet done (pending + claimed).
    pub fn len(&self) -> usize {
        let inner = lock(&self.inner);
        inner.pending.len() + inner.claimed.len()
    }

    /// True while `pop` is handing out duplicates of claimed pieces.
    pub fn in_endgame(&self) -> bool {
        let inner = lock(&self.inner);
        inner.pending.is_empty() && !inner.claimed.is_empty()
    }

    /// Records that a peer claims to have `piece_index`. Out-of-range
    /// indices (a malformed or lying peer) are silently ignored rather
    /// than panicking -- this is untrusted network input.
    pub fn note_have(&self, piece_index: u32) {
        let mut availability = lock(&self.availability);
        if let Some(count) = availability.get_mut(piece_index as usize) {
            *count += 1;
        }
    }

    /// Records an entire bitfield at once (bit `i` = piece `i`, per BEP 3
    /// `bitfield` semantics already decoded by `PeerState`).
    pub fn note_bitfield(&self, have: &[bool]) {
        // One lock for the lot, and only as many entries as there are
        // pieces: a peer's bitfield can be far longer than the torrent.
        let mut availability = lock(&self.availability);
        for (count, &has_it) in availability.iter_mut().zip(have) {
            if has_it {
                *count += 1;
            }
        }
    }

    /// How many peers have been seen to hold each piece.
    #[cfg(test)]
    pub(crate) fn availability(&self) -> Vec<u32> {
        lock(&self.availability).clone()
    }

    /// How many pieces the torrent has (what the queue was built for).
    pub fn total_pieces(&self) -> usize {
        lock(&self.availability).len()
    }
}

#[derive(Debug, Clone)]
pub struct PieceResult {
    pub index: u32,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn work(index: u32) -> PieceWork {
        PieceWork { index, hash: [0; 20], length: 100, merkle: None }
    }

    #[test]
    fn pop_returns_rarest_piece_first() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)], 3);
        // Everyone has piece 0 and piece 2; only one peer has piece 1.
        q.note_have(0);
        q.note_have(0);
        q.note_have(1);
        q.note_have(2);
        q.note_have(2);

        let first = q.pop().unwrap();
        assert_eq!(first.index, 1, "the rarest piece (availability 1) should come out first");
    }

    #[test]
    fn pieces_with_equal_availability_are_still_all_returned() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)], 3);
        // No availability info at all -- everything ties at 0. mark_done
        // after each pop so the queue actually drains rather than
        // entering endgame.
        let mut seen = Vec::new();
        for _ in 0..3 {
            let w = q.pop().unwrap();
            seen.push(w.index);
            q.mark_done(w.index);
        }
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2]);
        assert!(q.pop().is_none());
    }

    #[test]
    fn note_bitfield_marks_every_set_bit() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2), work(3)], 4);
        q.note_bitfield(&[true, false, true, false]);
        q.note_have(1); // piece 1 seen from a second peer too
        q.note_have(1);

        // Piece 3 was never observed anywhere (availability 0) -- rarest.
        let first = q.pop().unwrap();
        assert_eq!(first.index, 3);
    }

    #[test]
    fn note_have_out_of_range_does_not_panic() {
        let q = WorkQueue::new(vec![work(0)], 1);
        q.note_have(9999); // must be silently ignored, not panic
        assert_eq!(q.pop().unwrap().index, 0);
    }

    #[test]
    fn push_back_makes_a_piece_poppable_again() {
        let q = WorkQueue::new(vec![work(0)], 1);
        let w = q.pop().unwrap();
        assert!(!q.is_empty(), "a claimed piece is not done yet");
        q.push_back(w);
        assert!(!q.in_endgame(), "pushed-back piece is pending again, not merely claimed");
        assert_eq!(q.pop().unwrap().index, 0);
    }

    #[test]
    fn len_counts_claimed_and_is_empty_requires_done() {
        let q = WorkQueue::new(vec![work(0)], 1);
        assert_eq!(q.len(), 1);
        let w = q.pop().unwrap();
        assert_eq!(q.len(), 1, "claimed-but-unfinished still counts as remaining");
        assert!(!q.is_empty());
        q.mark_done(w.index);
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
    }

    #[test]
    fn endgame_hands_out_duplicates_of_claimed_pieces() {
        let q = WorkQueue::new(vec![work(0)], 1);
        let first = q.pop().unwrap(); // normal claim
        assert!(q.in_endgame());
        let dup = q.pop().unwrap(); // endgame duplicate of the same piece
        assert_eq!(first.index, dup.index);
        // Still not done -- duplicates don't retire anything by themselves.
        assert!(!q.is_empty());
    }

    #[test]
    fn mark_done_stops_endgame_duplicates_and_reports_first_completion() {
        let q = WorkQueue::new(vec![work(0)], 1);
        let w = q.pop().unwrap();
        assert!(q.mark_done(w.index), "first completion");
        assert!(!q.mark_done(w.index), "second completion is a duplicate");
        assert!(q.pop().is_none(), "done pieces are never handed out again");
        assert!(q.is_empty());
        assert!(!q.in_endgame());
    }

    #[test]
    fn push_back_after_done_is_dropped() {
        let q = WorkQueue::new(vec![work(0)], 1);
        let w = q.pop().unwrap();
        let dup = q.pop().unwrap(); // endgame duplicate
        q.mark_done(w.index);
        q.push_back(dup); // late failure of the duplicate: must not resurrect
        assert!(q.is_empty());
        assert!(q.pop().is_none());
    }

    #[test]
    fn is_done_tracks_completion() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2);
        assert!(!q.is_done(0));
        let w = q.pop().unwrap();
        q.mark_done(w.index);
        assert!(q.is_done(w.index));
    }

    #[test]
    fn concurrent_workers_complete_every_piece_exactly_once() {
        const N: u32 = 200;
        let q = Arc::new(WorkQueue::new((0..N).map(work).collect(), N as usize));
        let mut handles = Vec::new();
        let completed = Arc::new(Mutex::new(Vec::new()));

        for _ in 0..8 {
            let q = Arc::clone(&q);
            let completed = Arc::clone(&completed);
            handles.push(thread::spawn(move || {
                while let Some(w) = q.pop() {
                    // mark_done returning true = this thread won the
                    // race; only the winner records it (mirrors how
                    // download.rs dedupes endgame duplicates).
                    if q.mark_done(w.index) {
                        completed.lock().unwrap().push(w.index);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let mut completed = completed.lock().unwrap().clone();
        completed.sort_unstable();
        assert_eq!(completed, (0..N).collect::<Vec<_>>());
        assert!(q.is_empty());
    }

    #[test]
    fn concurrent_note_have_calls_are_not_lost() {
        const N: u32 = 100;
        let q = Arc::new(WorkQueue::new(vec![], N as usize));
        let mut handles = Vec::new();
        for i in 0..N {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                q.note_have(i);
                q.note_have(i); // twice, from two "different peers"
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let availability = q.availability.lock().unwrap();
        assert!(availability.iter().all(|&c| c == 2), "every piece should show availability 2, got {:?}", availability);
    }

    /// A worker thread that panics while holding the queue's lock.
    fn poison(queue: &WorkQueue) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _inner = queue.inner.lock().unwrap();
            let _availability = queue.availability.lock().unwrap();
            panic!("a worker died holding the queue's locks");
        }));
        assert!(queue.inner.is_poisoned() && queue.availability.is_poisoned(), "the setup must really poison both");
    }

    #[test]
    fn a_worker_panicking_with_the_queue_locked_does_not_take_the_queue_down() {
        let q = WorkQueue::new((0..3).map(|i| PieceWork { index: i, hash: [0; 20], length: 16, merkle: None }).collect(), 3);
        let claimed = q.pop().expect("a piece to claim");
        poison(&q);

        // Every operation the other workers rely on still works, and still
        // remembers what happened before the panic.
        q.note_have(1);
        assert_eq!(q.len(), 3, "nothing was lost: 2 pending and the claimed one");
        q.push_back(claimed.clone());
        assert!(q.mark_done(claimed.index));
        assert!(q.is_done(claimed.index));
        assert!(q.pop().is_some());
        assert!(!q.is_empty());
        assert!(!q.in_endgame());
    }

    #[test]
    fn a_bitfield_longer_than_the_torrent_counts_only_real_pieces() {
        let q = WorkQueue::new((0..3).map(|i| PieceWork { index: i, hash: [0; 20], length: 16, merkle: None }).collect(), 3);
        assert_eq!(q.total_pieces(), 3);
        q.note_bitfield(&vec![true; 1_000_000]); // far more entries than pieces
        assert_eq!(q.total_pieces(), 3, "nothing grew");
        // Every real piece was counted once, so none is rarer than another.
        let popped: Vec<u32> = std::iter::from_fn(|| q.pop()).take(3).map(|w| w.index).collect();
        assert_eq!(popped.len(), 3);
    }

    #[test]
    fn a_short_bitfield_counts_the_pieces_it_covers() {
        let q = WorkQueue::new((0..4).map(|i| PieceWork { index: i, hash: [0; 20], length: 16, merkle: None }).collect(), 4);
        q.note_bitfield(&[true, false]); // piece 0 only
        // Pieces 1, 2, 3 have no holder, so all of them come out before 0.
        let order: Vec<u32> = std::iter::from_fn(|| q.pop()).take(4).map(|w| w.index).collect();
        assert_eq!(order.last(), Some(&0));
    }

    // ---- take_for: choosing among what the peer has ----

    fn has(set: &'static [u32]) -> impl Fn(u32) -> bool {
        move |piece| set.contains(&piece)
    }

    fn piece_index(take: Take) -> Option<u32> {
        match take {
            Take::Piece(w) => Some(w.index),
            _ => None,
        }
    }

    #[test]
    fn take_for_gives_the_rarest_piece_the_peer_has_not_the_rarest_overall() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)], 3);
        // Piece 0 is the rarest of all (nobody seen with it), then 1, then 2.
        q.note_have(1);
        q.note_have(2);
        q.note_have(2);

        // This peer lacks piece 0: rarest-first among 1 and 2 gives 1.
        assert_eq!(piece_index(q.take_for(has(&[1, 2]))), Some(1));
        assert_eq!(piece_index(q.take_for(has(&[2]))), Some(2));
    }

    #[test]
    fn take_for_leaves_the_pieces_the_peer_lacks_for_others() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2);
        assert_eq!(piece_index(q.take_for(has(&[1]))), Some(1));
        assert_eq!(q.len(), 2, "piece 0 is still pending and piece 1 is claimed");
        assert_eq!(piece_index(q.take_for(has(&[0]))), Some(0), "another peer gets the one this one lacked");
    }

    #[test]
    fn a_peer_with_none_of_what_is_pending_is_told_so_and_nothing_changes() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2);

        assert_eq!(q.take_for(has(&[7])), Take::NothingForThisPeer);
        assert_eq!(q.take_for(|_| false), Take::NothingForThisPeer);

        assert_eq!((q.len(), q.in_endgame()), (2, false), "nothing was claimed by asking");
        assert!(piece_index(q.take_for(has(&[0, 1]))).is_some());
    }

    #[test]
    fn done_is_reported_only_when_every_piece_is_done() {
        let q = WorkQueue::new(vec![work(0)], 1);
        assert_eq!(q.take_for(|_| false), Take::NothingForThisPeer, "a piece remains, even if this peer has nothing");
        let w = q.pop().unwrap();
        assert_eq!(q.take_for(|_| false), Take::NothingForThisPeer, "still claimed, not done");
        q.mark_done(w.index);
        assert_eq!(q.take_for(|_| false), Take::Done);
        assert_eq!(q.take_for(|_| true), Take::Done);
    }

    #[test]
    fn endgame_duplicates_go_only_to_peers_that_have_the_piece() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2);
        q.pop();
        q.pop(); // both claimed, nothing pending: endgame

        assert_eq!(q.take_for(has(&[1])), Take::Piece(work(1)), "a peer with piece 1 duplicates piece 1");
        assert_eq!(q.take_for(has(&[9])), Take::NothingForThisPeer, "a peer with neither gets nothing, and it is not Done");
    }

    #[test]
    fn a_peer_lacking_the_pending_pieces_does_not_duplicate_claimed_ones() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2);
        assert_eq!(piece_index(q.take_for(has(&[1]))), Some(1)); // piece 1 claimed, piece 0 pending
        // Another peer has only piece 1. Piece 0 is pending, so this is not
        // endgame, and it must not pile onto the piece already in progress.
        assert_eq!(q.take_for(has(&[1])), Take::NothingForThisPeer);
    }

    #[test]
    fn pop_still_serves_a_source_with_every_piece() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2);
        assert!(q.pop().is_some() && q.pop().is_some());
        assert!(q.pop().is_some(), "endgame duplicate");
        q.mark_done(0);
        q.mark_done(1);
        assert!(q.pop().is_none());
    }

    // ---- order ----

    #[test]
    fn sequential_gives_the_lowest_index_however_rare_the_others_are() {
        let q = WorkQueue::new(vec![work(2), work(0), work(1)], 3).with_order(Order::Sequential);
        // Piece 2 is the rarest and piece 0 the commonest.
        q.note_have(0);
        q.note_have(0);
        q.note_have(1);

        let order: Vec<u32> = std::iter::from_fn(|| piece_index(q.take_for(|_| true))).take(3).collect();

        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn sequential_takes_the_lowest_index_the_peer_has() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)], 3).with_order(Order::Sequential);
        assert_eq!(piece_index(q.take_for(has(&[1, 2]))), Some(1), "piece 0 is not on offer");
        assert_eq!(piece_index(q.take_for(has(&[0, 1, 2]))), Some(0));
    }

    #[test]
    fn sequential_duplicates_the_lowest_claimed_piece_in_endgame() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)], 3).with_order(Order::Sequential);
        for _ in 0..3 {
            q.pop();
        }
        assert_eq!(q.take_for(|_| true), Take::Piece(work(0)));
    }

    #[test]
    fn rarest_first_is_the_default_and_ties_go_to_the_lowest_index() {
        let q = WorkQueue::new(vec![work(2), work(0), work(1), work(3)], 4);
        q.note_have(0);
        q.note_have(1);
        // 2 and 3 are equally rare, and rarer than 0 and 1.
        let order: Vec<u32> = std::iter::from_fn(|| piece_index(q.take_for(|_| true))).take(4).collect();
        assert_eq!(order, vec![2, 3, 0, 1], "rarity first, then index, however the list was arranged");
    }

    // ---- partly downloaded pieces ----

    fn partial_of(index: u32, blocks: u32, length: u32) -> PartialPiece {
        let mut a = crate::downloader::piece_assembler::PieceAssembler::new(PieceWork { index, hash: [0; 20], length, merkle: None });
        for n in 0..blocks {
            let begin = n * crate::downloader::piece_assembler::BLOCK_SIZE;
            let len = (length - begin).min(crate::downloader::piece_assembler::BLOCK_SIZE) as usize;
            a.record_block(begin, &vec![n as u8; len]).unwrap();
        }
        a.into_partial().expect("at least one block")
    }

    const PIECE: u32 = 4 * 16384;

    #[test]
    fn a_stashed_partial_is_taken_once_by_whoever_asks_first() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2);
        q.stash_partial(1, partial_of(1, 2, PIECE));

        assert!(q.take_partial(0).is_none(), "another piece's");
        let got = q.take_partial(1).expect("the stash");
        assert_eq!(got.blocks_held(), 2);
        assert!(q.take_partial(1).is_none(), "gone: two connections never resume the same one");
    }

    #[test]
    fn a_finished_piece_has_no_stash_and_takes_none() {
        let q = WorkQueue::new(vec![work(0)], 1);
        q.stash_partial(0, partial_of(0, 1, PIECE));
        q.mark_done(0);
        assert!(q.take_partial(0).is_none(), "retiring the piece dropped it");

        q.stash_partial(0, partial_of(0, 1, PIECE));
        assert!(q.take_partial(0).is_none(), "and one arriving after is not kept");
    }

    #[test]
    fn where_there_are_two_stashes_the_fuller_one_is_kept() {
        let q = WorkQueue::new(vec![work(0)], 1);
        q.stash_partial(0, partial_of(0, 3, PIECE));
        q.stash_partial(0, partial_of(0, 1, PIECE));
        assert_eq!(q.take_partial(0).unwrap().blocks_held(), 3, "a smaller one does not replace it");

        q.stash_partial(0, partial_of(0, 1, PIECE));
        q.stash_partial(0, partial_of(0, 2, PIECE));
        assert_eq!(q.take_partial(0).unwrap().blocks_held(), 2, "a fuller one does");
    }

    #[test]
    fn the_stash_is_bounded_so_failing_peers_cannot_fill_memory() {
        // Two stashes of 40 MiB: the second would take it past the limit.
        let big = 40 << 20;
        let q = WorkQueue::new(vec![work(0), work(1)], 2);
        q.stash_partial(0, partial_of(0, 1, big));
        q.stash_partial(1, partial_of(1, 1, big));

        assert!(q.take_partial(0).is_some(), "the first fits");
        assert!(q.take_partial(1).is_none(), "the second does not");
        // Space freed by taking one makes room again.
        q.stash_partial(1, partial_of(1, 1, big));
        assert!(q.take_partial(1).is_some());
    }

    // ---- preferred pieces ----

    fn preferred(pieces: &[u32]) -> HashSet<u32> {
        pieces.iter().copied().collect()
    }

    #[test]
    fn preferred_pieces_come_out_first_however_common_they_are() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2), work(3)], 4).with_preferred(preferred(&[2, 3]));
        // Pieces 2 and 3 are the commonest, so plain rarest-first would leave them for last.
        for _ in 0..3 {
            q.note_have(2);
            q.note_have(3);
        }

        let order: Vec<u32> = std::iter::from_fn(|| piece_index(q.take_for(|_| true))).take(4).collect();

        assert_eq!(order, vec![2, 3, 0, 1], "the preferred first, then the rest");
    }

    #[test]
    fn among_the_preferred_the_usual_order_still_holds() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2), work(3)], 4).with_preferred(preferred(&[1, 2, 3]));
        q.note_have(1);
        q.note_have(1);
        q.note_have(2);
        // Rarest first among 1, 2 and 3: 3 (unseen), 2, 1; then 0.
        let order: Vec<u32> = std::iter::from_fn(|| piece_index(q.take_for(|_| true))).take(4).collect();
        assert_eq!(order, vec![3, 2, 1, 0]);
    }

    #[test]
    fn sequential_takes_the_preferred_pieces_in_order_before_the_rest() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2), work(3)], 4).with_order(Order::Sequential).with_preferred(preferred(&[2, 3]));
        let order: Vec<u32> = std::iter::from_fn(|| piece_index(q.take_for(|_| true))).take(4).collect();
        assert_eq!(order, vec![2, 3, 0, 1]);
    }

    #[test]
    fn a_preferred_piece_the_peer_lacks_does_not_hold_back_the_others() {
        let q = WorkQueue::new(vec![work(0), work(1)], 2).with_preferred(preferred(&[1]));
        assert_eq!(piece_index(q.take_for(has(&[0]))), Some(0), "the peer has only piece 0, so it gets that");
        assert_eq!(piece_index(q.take_for(has(&[0, 1]))), Some(1));
    }

    #[test]
    fn with_nothing_preferred_the_order_is_unchanged() {
        let q = WorkQueue::new(vec![work(2), work(0), work(1)], 3).with_preferred(HashSet::new());
        q.note_have(0);
        let order: Vec<u32> = std::iter::from_fn(|| piece_index(q.take_for(|_| true))).take(3).collect();
        assert_eq!(order, vec![1, 2, 0]);
    }

    #[test]
    fn every_stash_can_be_listed_in_order_and_a_piece_is_wanted_until_it_is_done() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)], 3);
        q.stash_partial(2, partial_of(2, 1, PIECE));
        q.stash_partial(0, partial_of(0, 2, PIECE));
        let all = q.partials();
        assert_eq!(all.iter().map(|(i, p)| (*i, p.blocks_held())).collect::<Vec<_>>(), vec![(0, 2), (2, 1)], "by piece, and the stash itself is untouched");
        assert!(q.take_partial(0).is_some(), "listing took nothing");

        assert!(q.is_wanted(1) && q.is_wanted(2));
        assert!(!q.is_wanted(7), "a piece the queue does not have");
        q.mark_done(1);
        assert!(!q.is_wanted(1), "nor one that is done");
    }

    #[test]
    fn a_piece_to_look_ahead_to_is_the_rarest_pending_one_this_peer_has_and_never_a_duplicate() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)], 3);
        q.note_bitfield(&[true, true, true]);
        q.note_bitfield(&[true, false, true]);
        // Piece 1 is the rare one (one peer has it, two have the others); a peer that has only 0 and 2 is offered the first of those.
        assert_eq!(q.take_pending_for(|p| p != 1).map(|w| w.index), Some(0), "the index breaks the tie");
        assert_eq!(q.take_pending_for(|p| p == 1).map(|w| w.index), Some(1));
        assert!(q.take_pending_for(|p| p == 0).is_none(), "0 is taken already, and taking it again would be a duplicate");
        assert_eq!(q.take_pending_for(|_| true).map(|w| w.index), Some(2), "what is left");
        // Nothing pending, all claimed: endgame, where `take_for` hands out duplicates and this does not.
        assert!(q.take_pending_for(|_| true).is_none());
        assert!(matches!(q.take_for(|_| true), Take::Piece(_)), "which is what a worker that has run out of its own gets");
    }
}
