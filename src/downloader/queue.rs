//! Thread-safe queue of pending pieces, shared across peer worker threads
//! via `Arc<WorkQueue>`. Two `Mutex`-protected structures -- pending work
//! and a per-piece availability count -- are enough here; contention is
//! low (one lock per piece pop/requeue/availability-update, not per
//! block), which avoids pulling in an async runtime or lock-free crate
//! for a from-scratch client.
//!
//! Pieces are handed out **rarest-first**: `pop()` returns whichever
//! pending piece the fewest known peers have, not simply the first one
//! queued. This is standard BitTorrent piece-selection strategy -- if
//! every peer serves pieces in the same naive order (e.g. index order),
//! a piece only one peer in the swarm has can become unavailable the
//! moment that peer disconnects, stalling the whole download on it late.
//! Prioritizing rare pieces spreads them across more peers earlier,
//! before they become a single point of failure.

use crate::downloader::piece_assembler::PieceWork;
use std::sync::Mutex;

pub struct WorkQueue {
    pending: Mutex<Vec<PieceWork>>,
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
        WorkQueue { pending: Mutex::new(pieces), availability: Mutex::new(vec![0u32; total_pieces]) }
    }

    /// Pops the piece with the lowest known availability among those
    /// still pending (ties broken arbitrarily -- whichever the scan
    /// finds first). Workers that can't service the piece they popped
    /// (peer doesn't have it, download failed) call `push_back` to
    /// return it for another worker to try.
    pub fn pop(&self) -> Option<PieceWork> {
        let mut pending = self.pending.lock().unwrap();
        if pending.is_empty() {
            return None;
        }
        let availability = self.availability.lock().unwrap();
        let rarest_idx = pending
            .iter()
            .enumerate()
            .min_by_key(|(_, w)| availability.get(w.index as usize).copied().unwrap_or(0))
            .map(|(i, _)| i)?;
        // swap_remove is O(1) (vs. a true rarest-first-preserving remove
        // being O(n) regardless of representation) -- fine here since pop
        // no longer promises any particular order among equal-rarity
        // pieces to begin with.
        Some(pending.swap_remove(rarest_idx))
    }

    pub fn push_back(&self, work: PieceWork) {
        self.pending.lock().unwrap().push(work);
    }

    pub fn is_empty(&self) -> bool {
        self.pending.lock().unwrap().is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
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
        // No availability info at all -- everything ties at 0.
        let mut seen = vec![q.pop().unwrap().index, q.pop().unwrap().index, q.pop().unwrap().index];
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
        assert!(q.is_empty());
        q.push_back(w);
        assert!(!q.is_empty());
        assert_eq!(q.pop().unwrap().index, 0);
    }

    #[test]
    fn len_and_is_empty_track_size() {
        let q = WorkQueue::new(vec![work(0)], 1);
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
        q.pop();
        assert!(q.is_empty());
    }

    #[test]
    fn concurrent_workers_drain_every_piece_exactly_once() {
        const N: u32 = 200;
        let q = Arc::new(WorkQueue::new((0..N).map(work).collect(), N as usize));
        let mut handles = Vec::new();
        let seen = Arc::new(Mutex::new(Vec::new()));

        for _ in 0..8 {
            let q = Arc::clone(&q);
            let seen = Arc::clone(&seen);
            handles.push(thread::spawn(move || {
                while let Some(w) = q.pop() {
                    seen.lock().unwrap().push(w.index);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let mut seen = seen.lock().unwrap().clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..N).collect::<Vec<_>>());
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
