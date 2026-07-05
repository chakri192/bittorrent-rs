//! Tracks one piece's in-progress download: which 16 KiB blocks have been
//! requested, which have arrived, and the assembled buffer. Pure logic --
//! no I/O -- so it's fully testable without a socket; `worker.rs` is the
//! thin layer that actually sends/receives these over a `TcpStream`.

use sha1::{Digest, Sha1};

pub const BLOCK_SIZE: u32 = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceWork {
    pub index: u32,
    pub hash: [u8; 20],
    pub length: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AssemblerError {
    AlreadyComplete,
    BlockOutOfRange { begin: u32, len: u32, piece_length: u32 },
    UnexpectedBlockSize { begin: u32, expected: u32, got: u32 },
    HashMismatch,
}

impl std::fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssemblerError::AlreadyComplete => write!(f, "piece is already fully assembled"),
            AssemblerError::BlockOutOfRange { begin, len, piece_length } => {
                write!(f, "block [{}, {}) out of range for piece of length {}", begin, begin + len, piece_length)
            }
            AssemblerError::UnexpectedBlockSize { begin, expected, got } => {
                write!(f, "block at offset {} expected {} bytes, got {}", begin, expected, got)
            }
            AssemblerError::HashMismatch => write!(f, "assembled piece SHA-1 does not match the torrent's piece hash"),
        }
    }
}

impl std::error::Error for AssemblerError {}

/// A single outstanding or to-be-sent block request: `(piece_index, begin, length)`,
/// matching the fields of `Message::Request`.
pub type BlockRequest = (u32, u32, u32);

pub struct PieceAssembler {
    work: PieceWork,
    buf: Vec<u8>,
    received: Vec<bool>,
    /// Index of the next block (0-based, in BLOCK_SIZE units) that hasn't
    /// been requested yet -- lets `next_requests` hand out fresh block
    /// offsets without re-scanning `received` each call.
    next_unrequested_block: u32,
}

impl PieceAssembler {
    pub fn new(work: PieceWork) -> Self {
        let num_blocks = work.length.div_ceil(BLOCK_SIZE);
        PieceAssembler { buf: vec![0u8; work.length as usize], received: vec![false; num_blocks as usize], next_unrequested_block: 0, work }
    }

    pub fn piece_index(&self) -> u32 {
        self.work.index
    }

    fn num_blocks(&self) -> u32 {
        self.received.len() as u32
    }

    fn block_len(&self, block_idx: u32) -> u32 {
        let begin = block_idx * BLOCK_SIZE;
        (self.work.length - begin).min(BLOCK_SIZE)
    }

    /// Returns up to `max_new` fresh `(index, begin, length)` requests to
    /// send, advancing the internal cursor so the same block is never
    /// handed out twice. Used to keep `pipeline_depth` requests in flight
    /// at once per BEP 3's pipelining recommendation.
    pub fn next_requests(&mut self, max_new: usize) -> Vec<BlockRequest> {
        let mut out = Vec::with_capacity(max_new);
        while out.len() < max_new && self.next_unrequested_block < self.num_blocks() {
            let block_idx = self.next_unrequested_block;
            let begin = block_idx * BLOCK_SIZE;
            let len = self.block_len(block_idx);
            out.push((self.work.index, begin, len));
            self.next_unrequested_block += 1;
        }
        out
    }

    /// Records an arrived `Piece` message's payload at byte offset `begin`.
    pub fn record_block(&mut self, begin: u32, data: &[u8]) -> Result<(), AssemblerError> {
        if self.is_complete() {
            return Err(AssemblerError::AlreadyComplete);
        }
        let end = begin.checked_add(data.len() as u32).ok_or(AssemblerError::BlockOutOfRange { begin, len: data.len() as u32, piece_length: self.work.length })?;
        if end > self.work.length {
            return Err(AssemblerError::BlockOutOfRange { begin, len: data.len() as u32, piece_length: self.work.length });
        }
        let block_idx = begin / BLOCK_SIZE;
        let expected_len = self.block_len(block_idx);
        if data.len() as u32 != expected_len {
            return Err(AssemblerError::UnexpectedBlockSize { begin, expected: expected_len, got: data.len() as u32 });
        }
        self.buf[begin as usize..end as usize].copy_from_slice(data);
        self.received[block_idx as usize] = true;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|&r| r)
    }

    pub fn missing_block_count(&self) -> usize {
        self.received.iter().filter(|&&r| !r).count()
    }

    /// Consumes the assembler, returning the piece bytes iff complete AND
    /// its SHA-1 matches the torrent's recorded piece hash. This is the
    /// trust boundary before data ever reaches disk.
    pub fn finish(self) -> Result<Vec<u8>, AssemblerError> {
        if !self.is_complete() {
            return Err(AssemblerError::AlreadyComplete); // reuse variant: "not done" is the same "don't trust this yet" signal
        }
        let mut hasher = Sha1::new();
        hasher.update(&self.buf);
        let actual: [u8; 20] = hasher.finalize().into();
        if actual != self.work.hash {
            return Err(AssemblerError::HashMismatch);
        }
        Ok(self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize().into()
    }

    #[test]
    fn single_block_piece_full_flow() {
        let data = vec![0xABu8; 100];
        let work = PieceWork { index: 0, hash: hash_of(&data), length: 100 };
        let mut asm = PieceAssembler::new(work);

        let reqs = asm.next_requests(5);
        assert_eq!(reqs, vec![(0, 0, 100)]);
        assert_eq!(asm.next_requests(5), vec![]); // nothing left to request

        asm.record_block(0, &data).unwrap();
        assert!(asm.is_complete());
        assert_eq!(asm.finish().unwrap(), data);
    }

    #[test]
    fn multi_block_piece_pipelines_requests() {
        let length = BLOCK_SIZE * 3 + 100; // 3 full blocks + 1 short block
        let data = vec![0x11u8; length as usize];
        let work = PieceWork { index: 2, hash: hash_of(&data), length };
        let mut asm = PieceAssembler::new(work);

        let reqs = asm.next_requests(2);
        assert_eq!(reqs, vec![(2, 0, BLOCK_SIZE), (2, BLOCK_SIZE, BLOCK_SIZE)]);
        let more = asm.next_requests(2);
        assert_eq!(more, vec![(2, BLOCK_SIZE * 2, BLOCK_SIZE), (2, BLOCK_SIZE * 3, 100)]);
        assert_eq!(asm.next_requests(2), vec![]);

        for (_, begin, len) in reqs.into_iter().chain(more) {
            let chunk = &data[begin as usize..(begin + len) as usize];
            asm.record_block(begin, chunk).unwrap();
        }
        assert!(asm.is_complete());
        assert_eq!(asm.finish().unwrap(), data);
    }

    #[test]
    fn out_of_order_blocks_are_accepted() {
        let length = BLOCK_SIZE * 2;
        let data = vec![0x22u8; length as usize];
        let work = PieceWork { index: 0, hash: hash_of(&data), length };
        let mut asm = PieceAssembler::new(work);
        asm.next_requests(2);

        // second block arrives before the first
        asm.record_block(BLOCK_SIZE, &data[BLOCK_SIZE as usize..]).unwrap();
        assert!(!asm.is_complete());
        asm.record_block(0, &data[..BLOCK_SIZE as usize]).unwrap();
        assert!(asm.is_complete());
        assert_eq!(asm.finish().unwrap(), data);
    }

    #[test]
    fn rejects_block_extending_past_piece_length() {
        let work = PieceWork { index: 0, hash: [0; 20], length: 100 };
        let mut asm = PieceAssembler::new(work);
        let err = asm.record_block(90, &[0u8; 50]).unwrap_err();
        assert!(matches!(err, AssemblerError::BlockOutOfRange { .. }));
    }

    #[test]
    fn rejects_wrong_size_block() {
        let work = PieceWork { index: 0, hash: [0; 20], length: BLOCK_SIZE * 2 };
        let mut asm = PieceAssembler::new(work);
        let err = asm.record_block(0, &[0u8; 10]).unwrap_err(); // should be BLOCK_SIZE
        assert!(matches!(err, AssemblerError::UnexpectedBlockSize { .. }));
    }

    #[test]
    fn finish_fails_on_hash_mismatch() {
        let data = vec![0x33u8; 50];
        let work = PieceWork { index: 0, hash: [0; 20], length: 50 }; // wrong hash on purpose
        let mut asm = PieceAssembler::new(work);
        asm.record_block(0, &data).unwrap();
        assert!(matches!(asm.finish(), Err(AssemblerError::HashMismatch)));
    }

    #[test]
    fn missing_block_count_tracks_progress() {
        let length = BLOCK_SIZE * 4;
        let work = PieceWork { index: 0, hash: [0; 20], length };
        let mut asm = PieceAssembler::new(work);
        assert_eq!(asm.missing_block_count(), 4);
        asm.record_block(0, &vec![0u8; BLOCK_SIZE as usize]).unwrap();
        assert_eq!(asm.missing_block_count(), 3);
    }

    #[test]
    fn double_request_never_hands_out_same_block_twice() {
        let work = PieceWork { index: 0, hash: [0; 20], length: BLOCK_SIZE };
        let mut asm = PieceAssembler::new(work);
        assert_eq!(asm.next_requests(10).len(), 1);
        assert_eq!(asm.next_requests(10).len(), 0);
    }
}
