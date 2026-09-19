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

/// The blocks of a piece that arrived before the connection they came
/// over failed: what a later connection can start from instead of asking
/// for them again. Not verified -- only the whole piece has a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialPiece {
    data: Vec<u8>,
    received: Vec<bool>,
}

impl PartialPiece {
    /// How many blocks are in it.
    pub fn blocks_held(&self) -> usize {
        self.received.iter().filter(|&&r| r).count()
    }

    /// Bytes of memory it holds on to.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

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

    /// An assembler that starts from `partial`, so that only the blocks it
    /// lacks are requested. A partial that does not fit `work` (a different
    /// length) is ignored and the piece starts from nothing.
    pub fn resume(work: PieceWork, partial: PartialPiece) -> Self {
        let mut fresh = PieceAssembler::new(work);
        if partial.data.len() == fresh.buf.len() && partial.received.len() == fresh.received.len() {
            fresh.buf = partial.data;
            fresh.received = partial.received;
        }
        fresh
    }

    /// What has arrived so far, to be handed on. `None` if nothing has.
    pub fn into_partial(self) -> Option<PartialPiece> {
        let partial = PartialPiece { data: self.buf, received: self.received };
        (partial.blocks_held() > 0).then_some(partial)
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
    /// handed out twice, and never one that has already arrived. Used to
    /// keep `pipeline_depth` requests in flight at once per BEP 3's
    /// pipelining recommendation.
    pub fn next_requests(&mut self, max_new: usize) -> Vec<BlockRequest> {
        let mut out = Vec::with_capacity(max_new);
        while out.len() < max_new && self.next_unrequested_block < self.num_blocks() {
            let block_idx = self.next_unrequested_block;
            self.next_unrequested_block += 1;
            if self.received[block_idx as usize] {
                continue;
            }
            let begin = block_idx * BLOCK_SIZE;
            let len = self.block_len(block_idx);
            out.push((self.work.index, begin, len));
        }
        out
    }

    /// Forgets which blocks have been requested, so that the ones still
    /// missing are handed out again by `next_requests`. For when the peer
    /// has discarded every request it was sent (BEP 3: a choke does that).
    /// Blocks that have arrived are kept.
    pub fn forget_requests(&mut self) {
        self.next_unrequested_block = 0;
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

    #[test]
    fn requests_never_include_a_block_that_has_already_arrived() {
        let data = vec![7u8; (BLOCK_SIZE * 3) as usize];
        let mut a = PieceAssembler::new(PieceWork { index: 0, hash: hash_of(&data), length: data.len() as u32 });
        a.record_block(BLOCK_SIZE, &data[..BLOCK_SIZE as usize]).unwrap(); // the middle block, unasked

        let requests = a.next_requests(10);

        assert_eq!(requests.iter().map(|&(_, begin, _)| begin).collect::<Vec<_>>(), vec![0, 2 * BLOCK_SIZE], "the middle block is skipped");
    }

    #[test]
    fn forgetting_requests_makes_the_missing_blocks_come_round_again_and_only_those() {
        let data: Vec<u8> = (0..(BLOCK_SIZE * 4) as usize).map(|i| i as u8).collect();
        let mut a = PieceAssembler::new(PieceWork { index: 9, hash: hash_of(&data), length: data.len() as u32 });
        assert_eq!(a.next_requests(4).len(), 4, "everything requested");
        assert!(a.next_requests(4).is_empty(), "and nothing left to request");
        a.record_block(0, &data[..BLOCK_SIZE as usize]).unwrap();
        a.record_block(2 * BLOCK_SIZE, &data[2 * BLOCK_SIZE as usize..3 * BLOCK_SIZE as usize]).unwrap();

        a.forget_requests();
        let again = a.next_requests(4);

        assert_eq!(again.iter().map(|&(index, begin, _)| (index, begin)).collect::<Vec<_>>(), vec![(9, BLOCK_SIZE), (9, 3 * BLOCK_SIZE)], "blocks 1 and 3, the ones that never arrived");
        assert!(a.next_requests(4).is_empty());
    }

    // ---- handing a partly downloaded piece on ----

    fn four_block_piece() -> (Vec<u8>, PieceWork) {
        let data: Vec<u8> = (0..(BLOCK_SIZE * 4) as usize).map(|i| (i as u8).wrapping_mul(7)).collect();
        let work = PieceWork { index: 3, hash: hash_of(&data), length: data.len() as u32 };
        (data, work)
    }

    fn block(data: &[u8], n: u32) -> &[u8] {
        &data[(n * BLOCK_SIZE) as usize..((n + 1) * BLOCK_SIZE) as usize]
    }

    #[test]
    fn a_partial_piece_resumes_asking_only_for_what_is_missing_and_still_verifies() {
        let (data, work) = four_block_piece();
        let mut first = PieceAssembler::new(work.clone());
        first.next_requests(4);
        first.record_block(0, block(&data, 0)).unwrap();
        first.record_block(2 * BLOCK_SIZE, block(&data, 2)).unwrap();
        let partial = first.into_partial().expect("two blocks arrived");
        assert_eq!((partial.blocks_held(), partial.size()), (2, data.len()));

        let mut second = PieceAssembler::resume(work, partial);
        let asked: Vec<u32> = second.next_requests(10).iter().map(|&(_, begin, _)| begin).collect();

        assert_eq!(asked, vec![BLOCK_SIZE, 3 * BLOCK_SIZE], "blocks 1 and 3");
        second.record_block(BLOCK_SIZE, block(&data, 1)).unwrap();
        second.record_block(3 * BLOCK_SIZE, block(&data, 3)).unwrap();
        assert_eq!(second.finish().unwrap(), data, "the two halves make the piece");
    }

    #[test]
    fn nothing_received_means_nothing_to_hand_on() {
        let (_, work) = four_block_piece();
        assert!(PieceAssembler::new(work).into_partial().is_none());
    }

    #[test]
    fn a_partial_that_does_not_fit_the_piece_is_ignored() {
        let (data, work) = four_block_piece();
        let mut other = PieceAssembler::new(PieceWork { index: 3, hash: [0; 20], length: BLOCK_SIZE * 2 });
        other.record_block(0, block(&data, 0)).unwrap();
        let partial = other.into_partial().unwrap();

        let mut resumed = PieceAssembler::resume(work, partial);

        assert_eq!(resumed.next_requests(10).len(), 4, "started from nothing");
    }

    #[test]
    fn a_resumed_piece_with_a_bad_block_fails_its_hash_like_any_other() {
        let (data, work) = four_block_piece();
        let mut first = PieceAssembler::new(work.clone());
        let mut bad = block(&data, 0).to_vec();
        bad[10] ^= 0xFF;
        first.record_block(0, &bad).unwrap();
        let mut second = PieceAssembler::resume(work, first.into_partial().unwrap());
        for n in 1..4 {
            second.record_block(n * BLOCK_SIZE, block(&data, n)).unwrap();
        }
        assert_eq!(second.finish(), Err(AssemblerError::HashMismatch));
    }
}
