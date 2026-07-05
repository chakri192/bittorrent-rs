//! Thread-safe queue of pending pieces, shared across peer worker threads
//! via `Arc<WorkQueue>`. A `std::sync::Mutex<VecDeque<_>>` is enough here
//! -- contention is low (one lock per piece pop/requeue, not per block)
//! and this avoids pulling in an async runtime or lock-free crate for a
//! from-scratch client.

use crate::downloader::piece_assembler::PieceWork;
use std::collections::VecDeque;
use std::sync::Mutex;

pub struct WorkQueue {
    pending: Mutex<VecDeque<PieceWork>>,
}

impl WorkQueue {
    pub fn new(pieces: Vec<PieceWork>) -> Self {
        WorkQueue { pending: Mutex::new(pieces.into_iter().collect()) }
    }

    /// Pops the next piece a worker should attempt. Workers that can't
    /// service it (peer doesn't have it, download failed) call
    /// `push_back` to return it for another worker to try.
    pub fn pop(&self) -> Option<PieceWork> {
        self.pending.lock().unwrap().pop_front()
    }

    pub fn push_back(&self, work: PieceWork) {
        self.pending.lock().unwrap().push_back(work);
    }

    pub fn is_empty(&self) -> bool {
        self.pending.lock().unwrap().is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
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
    fn pop_returns_pieces_in_fifo_order() {
        let q = WorkQueue::new(vec![work(0), work(1), work(2)]);
        assert_eq!(q.pop().unwrap().index, 0);
        assert_eq!(q.pop().unwrap().index, 1);
        assert_eq!(q.pop().unwrap().index, 2);
        assert!(q.pop().is_none());
    }

    #[test]
    fn push_back_requeues_at_the_end() {
        let q = WorkQueue::new(vec![work(0), work(1)]);
        let first = q.pop().unwrap();
        q.push_back(first);
        assert_eq!(q.pop().unwrap().index, 1);
        assert_eq!(q.pop().unwrap().index, 0);
    }

    #[test]
    fn len_and_is_empty_track_size() {
        let q = WorkQueue::new(vec![work(0)]);
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
        q.pop();
        assert!(q.is_empty());
    }

    #[test]
    fn concurrent_workers_drain_every_piece_exactly_once() {
        const N: u32 = 200;
        let q = Arc::new(WorkQueue::new((0..N).map(work).collect()));
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
}
