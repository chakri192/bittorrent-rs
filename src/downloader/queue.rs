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

use crate::downloader::piece_assembler::PieceWork;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

struct Inner {
    /// Not yet done, not currently claimed by any worker.
    pending: Vec<PieceWork>,
    /// Claimed by >= 1 worker, not yet verified-and-written. Keyed by
    /// piece index so endgame `pop` can hand out another copy.
    claimed: HashMap<u32, PieceWork>,
    /// Verified and written to disk.
    done: HashSet<u32>,
}

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
}

impl WorkQueue {
    /// `total_pieces` sizes the availability table up front -- it must be
    /// at least as large as any piece index ever passed to `note_have` or
    /// present in `pieces` (in practice: `torrent.pieces.len()`).
    pub fn new(pieces: Vec<PieceWork>, total_pieces: usize) -> Self {
        WorkQueue {
            inner: Mutex::new(Inner { pending: pieces, claimed: HashMap::new(), done: HashSet::new() }),
            availability: Mutex::new(vec![0u32; total_pieces]),
        }
    }

    /// Pops the rarest pending piece (ties broken arbitrarily) and marks
    /// it claimed. If nothing is pending but claimed pieces remain,
    /// returns a **duplicate** of the rarest claimed piece (endgame).
    /// Returns `None` only when every piece is done.
    ///
    /// Workers that can't service the piece they popped (peer doesn't
    /// have it, download failed) call `push_back` to return it.
    pub fn pop(&self) -> Option<PieceWork> {
        let mut inner = self.inner.lock().unwrap();
        let availability = self.availability.lock().unwrap();
        let rarity = |w: &PieceWork| availability.get(w.index as usize).copied().unwrap_or(0);

        if !inner.pending.is_empty() {
            let rarest_idx = inner.pending.iter().enumerate().min_by_key(|(_, w)| rarity(w)).map(|(i, _)| i)?;
            // swap_remove is O(1) (vs. a true rarest-first-preserving
            // remove being O(n) regardless of representation) -- fine
            // since pop makes no ordering promise among equal-rarity
            // pieces to begin with.
            let work = inner.pending.swap_remove(rarest_idx);
            inner.claimed.insert(work.index, work.clone());
            return Some(work);
        }

        // Endgame: duplicate-assign a still-unfinished claimed piece.
        inner.claimed.values().min_by_key(|w| rarity(w)).cloned()
    }

    /// Returns a piece to the queue after a failed attempt. No-ops if the
    /// piece has since been finished by another worker. Also clears any
    /// standing claim -- if some other worker is *still* downloading this
    /// piece, that's fine: it effectively continues as an endgame
    /// duplicate, and whichever copy verifies first retires the piece.
    pub fn push_back(&self, work: PieceWork) {
        let mut inner = self.inner.lock().unwrap();
        if inner.done.contains(&work.index) {
            return;
        }
        inner.claimed.remove(&work.index);
        if !inner.pending.iter().any(|w| w.index == work.index) {
            inner.pending.push(work);
        }
    }

    /// Retires a piece everywhere after it has been verified and written.
    /// Returns `true` if this call was the first to mark it done (callers
    /// use this to avoid double-counting duplicate endgame completions).
    pub fn mark_done(&self, index: u32) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let newly_done = inner.done.insert(index);
        inner.claimed.remove(&index);
        inner.pending.retain(|w| w.index != index);
        newly_done
    }

    /// Whether this piece has already been verified and written by some
    /// worker. Endgame workers poll this mid-download to abandon pieces
    /// that completed elsewhere instead of wasting the peer's bandwidth.
    pub fn is_done(&self, index: u32) -> bool {
        self.inner.lock().unwrap().done.contains(&index)
    }

    /// True once every piece is done (nothing pending, nothing claimed).
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.pending.is_empty() && inner.claimed.is_empty()
    }

    /// Pieces not yet done (pending + claimed).
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.pending.len() + inner.claimed.len()
    }

    /// True while `pop` is handing out duplicates of claimed pieces.
    pub fn in_endgame(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.pending.is_empty() && !inner.claimed.is_empty()
    }

    /// Records that a peer claims to have `piece_index`. Out-of-range
    /// indices (a malformed or lying peer) are silently ignored rather
    /// than panicking -- this is untrusted network input.
    pub fn note_have(&self, piece_index: u32) {
        if let Ok(mut availability) = self.availability.lock() {
            if let Some(count) = availability.get_mut(piece_index as usize) {
                *count += 1;
            }
        }
    }

    /// Records an entire bitfield at once (bit `i` = piece `i`, per BEP 3
    /// `bitfield` semantics already decoded by `PeerState`).
    pub fn note_bitfield(&self, have: &[bool]) {
        for (i, &has_it) in have.iter().enumerate() {
            if has_it {
                self.note_have(i as u32);
            }
        }
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
        PieceWork { index, hash: [0; 20], length: 100 }
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
}
