//! BEP 9: metadata exchange over the `ut_metadata` extended message.
//! Each message is a bencoded dict `{"msg_type": 0|1|2, "piece": N, ["total_size": N]}`
//! -- for `data` (msg_type 1) messages, the dict is immediately followed
//! by the raw 16 KiB (or shorter, for the last piece) metadata bytes,
//! *not* itself bencoded. This mirrors the `piece` wire message's
//! header-then-raw-bytes shape.

use crate::bencode::{self, Bencode, Decoder};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;

/// BEP 9 fixes this at 16 KiB for every piece except the last.
pub const METADATA_PIECE_SIZE: usize = 16 * 1024;

const MSG_TYPE_REQUEST: i64 = 0;
const MSG_TYPE_DATA: i64 = 1;
const MSG_TYPE_REJECT: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataMessage {
    Request { piece: u32 },
    Data { piece: u32, total_size: u32, data: Vec<u8> },
    Reject { piece: u32 },
}

#[derive(Debug)]
pub enum MetadataError {
    Decode(bencode::DecodeError),
    NotADict,
    MissingField(&'static str),
    UnknownMsgType(i64),
    PieceCountMismatch { expected: usize, got: usize },
    PieceOutOfRange { index: usize, count: usize },
    PieceSizeMismatch { index: usize, expected: usize, got: usize },
    IncompleteAssembly,
    InfoHashMismatch,
    /// The size a peer claims for the metadata is zero, negative, or over
    /// [`MAX_METADATA_SIZE`].
    SizeNotAcceptable(i64),
}

impl From<bencode::DecodeError> for MetadataError {
    fn from(e: bencode::DecodeError) -> Self {
        MetadataError::Decode(e)
    }
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataError::Decode(e) => write!(f, "bencode decode error: {}", e),
            MetadataError::NotADict => write!(f, "ut_metadata message header is not a dict"),
            MetadataError::MissingField(s) => write!(f, "ut_metadata message missing field: {}", s),
            MetadataError::UnknownMsgType(n) => write!(f, "unknown ut_metadata msg_type: {}", n),
            MetadataError::PieceCountMismatch { expected, got } => write!(f, "expected {} pieces, index implies {}", expected, got),
            MetadataError::PieceOutOfRange { index, count } => write!(f, "piece index {} out of range (have {} pieces)", index, count),
            MetadataError::PieceSizeMismatch { index, expected, got } => {
                write!(f, "piece {} wrong size: expected {}, got {}", index, expected, got)
            }
            MetadataError::IncompleteAssembly => write!(f, "not all metadata pieces received yet"),
            MetadataError::InfoHashMismatch => write!(f, "assembled metadata's SHA-1 does not match the magnet InfoHash"),
            MetadataError::SizeNotAcceptable(n) => write!(f, "peer claims {} bytes of metadata; between 1 and {} is acceptable", n, MAX_METADATA_SIZE),
        }
    }
}

impl std::error::Error for MetadataError {}

impl MetadataMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut dict = BTreeMap::new();
        match self {
            MetadataMessage::Request { piece } => {
                dict.insert(b"msg_type".to_vec(), Bencode::Int(MSG_TYPE_REQUEST));
                dict.insert(b"piece".to_vec(), Bencode::Int(*piece as i64));
                encode_bencode_dict(&dict)
            }
            MetadataMessage::Data { piece, total_size, data } => {
                dict.insert(b"msg_type".to_vec(), Bencode::Int(MSG_TYPE_DATA));
                dict.insert(b"piece".to_vec(), Bencode::Int(*piece as i64));
                dict.insert(b"total_size".to_vec(), Bencode::Int(*total_size as i64));
                let mut out = encode_bencode_dict(&dict);
                out.extend_from_slice(data);
                out
            }
            MetadataMessage::Reject { piece } => {
                dict.insert(b"msg_type".to_vec(), Bencode::Int(MSG_TYPE_REJECT));
                dict.insert(b"piece".to_vec(), Bencode::Int(*piece as i64));
                encode_bencode_dict(&dict)
            }
        }
    }

    /// Decodes a `ut_metadata` extended-message payload. The bencoded
    /// header may be followed by trailing raw bytes (only meaningful for
    /// `Data`); we track how many bytes the header consumed via
    /// `Decoder::decode_value_with_span` and treat everything after as
    /// the raw metadata chunk.
    pub fn decode(payload: &[u8]) -> Result<Self, MetadataError> {
        // Lenient: this header arrives over the wire from arbitrary
        // clients, and non-canonical key order must not cost us the
        // metadata (SHA-1 verification of the assembled dict is what
        // actually guards integrity).
        let mut dec = Decoder::new_lenient(payload);
        let (value, (_start, end)) = dec.decode_value_with_span()?;
        let dict = value.as_dict().ok_or(MetadataError::NotADict)?;

        let msg_type = dict.get(b"msg_type".as_slice()).and_then(Bencode::as_int).ok_or(MetadataError::MissingField("msg_type"))?;
        let piece = dict.get(b"piece".as_slice()).and_then(Bencode::as_int).ok_or(MetadataError::MissingField("piece"))? as u32;

        match msg_type {
            MSG_TYPE_REQUEST => Ok(MetadataMessage::Request { piece }),
            MSG_TYPE_REJECT => Ok(MetadataMessage::Reject { piece }),
            MSG_TYPE_DATA => {
                let total_size = dict.get(b"total_size".as_slice()).and_then(Bencode::as_int).ok_or(MetadataError::MissingField("total_size"))? as u32;
                Ok(MetadataMessage::Data { piece, total_size, data: payload[end..].to_vec() })
            }
            other => Err(MetadataError::UnknownMsgType(other)),
        }
    }
}

fn encode_bencode_dict(dict: &BTreeMap<Vec<u8>, Bencode>) -> Vec<u8> {
    // Local minimal encoder mirroring peer::extension's -- duplicated
    // rather than made a shared pub fn because the two call sites want
    // different top-level shapes and this keeps each module self-contained.
    let mut out = vec![b'd'];
    for (k, v) in dict {
        out.extend_from_slice(k.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(k);
        encode_value(v, &mut out);
    }
    out.push(b'e');
    out
}

fn encode_value(value: &Bencode, out: &mut Vec<u8>) {
    match value {
        Bencode::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        Bencode::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Bencode::List(items) => {
            out.push(b'l');
            for i in items {
                encode_value(i, out);
            }
            out.push(b'e');
        }
        Bencode::Dict(map) => out.extend_from_slice(&encode_bencode_dict(map)),
    }
}

/// Accumulates `Data` pieces until the full info dict is reassembled, then
/// validates it against the InfoHash the magnet link promised.
pub struct MetadataAssembler {
    total_size: usize,
    num_pieces: usize,
    pieces: Vec<Option<Vec<u8>>>,
}

/// The largest info dict accepted over BEP 9: 16 MiB, a thousand pieces.
/// Real ones are a few KB to a few MB (libtorrent's default limit is 3 MiB).
/// The size comes from the peer, and a table is allocated per 16 KiB of it,
/// so an unchecked `metadata_size` lets a stranger choose how much memory
/// to allocate.
pub const MAX_METADATA_SIZE: i64 = 16 << 20;

impl MetadataAssembler {
    /// An assembler for the size a *peer* claimed, refusing one that is
    /// zero, negative or absurd. Use this, not [`new`](Self::new), for any
    /// size that came off the network.
    pub fn for_claimed_size(claimed: i64) -> Result<Self, MetadataError> {
        if !(1..=MAX_METADATA_SIZE).contains(&claimed) {
            return Err(MetadataError::SizeNotAcceptable(claimed));
        }
        Ok(Self::new(claimed as usize))
    }

    pub fn new(total_size: usize) -> Self {
        let num_pieces = total_size.div_ceil(METADATA_PIECE_SIZE).max(1);
        MetadataAssembler { total_size, num_pieces, pieces: vec![None; num_pieces] }
    }

    pub fn num_pieces(&self) -> usize {
        self.num_pieces
    }

    /// Feeds one `Data` message in. Validates the piece's expected size
    /// (16 KiB, except the last piece which is `total_size % 16KiB`) so a
    /// malformed/malicious piece can't corrupt the assembly silently.
    pub fn add_piece(&mut self, index: usize, data: Vec<u8>) -> Result<(), MetadataError> {
        if index >= self.num_pieces {
            return Err(MetadataError::PieceOutOfRange { index, count: self.num_pieces });
        }
        let expected_len = if index == self.num_pieces - 1 {
            let rem = self.total_size % METADATA_PIECE_SIZE;
            if rem == 0 { METADATA_PIECE_SIZE } else { rem }
        } else {
            METADATA_PIECE_SIZE
        };
        if data.len() != expected_len {
            return Err(MetadataError::PieceSizeMismatch { index, expected: expected_len, got: data.len() });
        }
        self.pieces[index] = Some(data);
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.pieces.iter().all(Option::is_some)
    }

    pub fn missing_pieces(&self) -> Vec<usize> {
        self.pieces.iter().enumerate().filter_map(|(i, p)| if p.is_none() { Some(i) } else { None }).collect()
    }

    /// Concatenates all pieces once complete. Does not itself check the
    /// InfoHash -- use `assemble_and_verify` for that.
    pub fn assemble(&self) -> Result<Vec<u8>, MetadataError> {
        let mut out = Vec::with_capacity(self.total_size);
        for piece in &self.pieces {
            let Some(piece) = piece else { return Err(MetadataError::IncompleteAssembly) };
            out.extend_from_slice(piece);
        }
        Ok(out)
    }

    /// Assembles and SHA-1-checks the result against `expected_info_hash`
    /// (the hash from the magnet URI). This is the BEP 9 trust boundary:
    /// metadata comes from an untrusted peer, so it must never be used
    /// before this check passes.
    pub fn assemble_and_verify(&self, expected_info_hash: &[u8; 20]) -> Result<Vec<u8>, MetadataError> {
        let raw = self.assemble()?;
        let mut hasher = Sha1::new();
        hasher.update(&raw);
        let actual: [u8; 20] = hasher.finalize().into();
        if &actual != expected_info_hash {
            return Err(MetadataError::InfoHashMismatch);
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let msg = MetadataMessage::Request { piece: 3 };
        let bytes = msg.encode();
        assert_eq!(MetadataMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn reject_round_trips() {
        let msg = MetadataMessage::Reject { piece: 1 };
        let bytes = msg.encode();
        assert_eq!(MetadataMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn data_round_trips_with_trailing_raw_bytes() {
        let msg = MetadataMessage::Data { piece: 0, total_size: 5, data: vec![1, 2, 3, 4, 5] };
        let bytes = msg.encode();
        // header dict + 5 raw bytes appended, not bencoded
        assert_eq!(MetadataMessage::decode(&bytes).unwrap(), msg);
    }

    #[test]
    fn data_header_and_raw_bytes_are_correctly_split() {
        let msg = MetadataMessage::Data { piece: 2, total_size: 100, data: vec![0xAA; 16] };
        let bytes = msg.encode();
        // Sanity: header is valid bencode on its own even though more bytes follow.
        let mut dec = Decoder::new(&bytes);
        let (val, (_, end)) = dec.decode_value_with_span().unwrap();
        assert!(val.as_dict().is_some());
        assert_eq!(&bytes[end..], &[0xAAu8; 16][..]);
    }

    #[test]
    fn rejects_unknown_msg_type() {
        let raw = b"d8:msg_typei9e5:piecei0ee";
        assert!(matches!(MetadataMessage::decode(raw), Err(MetadataError::UnknownMsgType(9))));
    }

    #[test]
    fn assembler_single_piece_exact_multiple() {
        let mut asm = MetadataAssembler::new(16 * 1024);
        assert_eq!(asm.num_pieces(), 1);
        asm.add_piece(0, vec![0xAB; 16 * 1024]).unwrap();
        assert!(asm.is_complete());
        assert_eq!(asm.assemble().unwrap().len(), 16 * 1024);
    }

    #[test]
    fn assembler_multiple_pieces_with_short_last_piece() {
        let total = 16 * 1024 + 100;
        let mut asm = MetadataAssembler::new(total);
        assert_eq!(asm.num_pieces(), 2);
        asm.add_piece(0, vec![1u8; 16 * 1024]).unwrap();
        assert!(!asm.is_complete());
        assert_eq!(asm.missing_pieces(), vec![1]);
        asm.add_piece(1, vec![2u8; 100]).unwrap();
        assert!(asm.is_complete());
        let full = asm.assemble().unwrap();
        assert_eq!(full.len(), total);
        assert_eq!(&full[..16 * 1024], &vec![1u8; 16 * 1024][..]);
        assert_eq!(&full[16 * 1024..], &vec![2u8; 100][..]);
    }

    #[test]
    fn assembler_rejects_wrong_size_piece() {
        let mut asm = MetadataAssembler::new(16 * 1024 + 100);
        let err = asm.add_piece(0, vec![0u8; 10]).unwrap_err();
        assert!(matches!(err, MetadataError::PieceSizeMismatch { .. }));
    }

    #[test]
    fn assembler_rejects_wrong_size_last_piece() {
        let mut asm = MetadataAssembler::new(16 * 1024 + 100);
        let err = asm.add_piece(1, vec![0u8; 50]).unwrap_err(); // should be 100
        assert!(matches!(err, MetadataError::PieceSizeMismatch { .. }));
    }

    #[test]
    fn assembler_rejects_out_of_range_piece() {
        let mut asm = MetadataAssembler::new(16 * 1024);
        assert!(matches!(asm.add_piece(5, vec![0u8; 16 * 1024]), Err(MetadataError::PieceOutOfRange { .. })));
    }

    #[test]
    fn assemble_fails_before_complete() {
        let asm = MetadataAssembler::new(16 * 1024);
        assert!(matches!(asm.assemble(), Err(MetadataError::IncompleteAssembly)));
    }

    #[test]
    fn assemble_and_verify_succeeds_on_matching_hash() {
        let data = b"d4:name8:file.bin6:lengthi5ee".to_vec(); // a plausible-looking info dict
        let mut hasher = Sha1::new();
        hasher.update(&data);
        let hash: [u8; 20] = hasher.finalize().into();

        let mut asm = MetadataAssembler::new(data.len());
        asm.add_piece(0, data.clone()).unwrap();
        let verified = asm.assemble_and_verify(&hash).unwrap();
        assert_eq!(verified, data);
    }

    #[test]
    fn assemble_and_verify_fails_on_mismatched_hash() {
        let mut asm = MetadataAssembler::new(4);
        asm.add_piece(0, vec![1, 2, 3, 4]).unwrap();
        let wrong_hash = [0u8; 20];
        assert!(matches!(asm.assemble_and_verify(&wrong_hash), Err(MetadataError::InfoHashMismatch)));
    }

    #[test]
    fn a_claimed_metadata_size_is_accepted_only_within_bounds() {
        for ok in [1, 16384, 16385, MAX_METADATA_SIZE] {
            assert!(MetadataAssembler::for_claimed_size(ok).is_ok(), "{} should be accepted", ok);
        }
        for bad in [0, -1, i64::MIN, MAX_METADATA_SIZE + 1, i64::MAX] {
            assert!(matches!(MetadataAssembler::for_claimed_size(bad), Err(MetadataError::SizeNotAcceptable(n)) if n == bad), "{} should be refused", bad);
        }
    }

    #[test]
    fn the_largest_accepted_size_is_a_bounded_number_of_pieces() {
        assert_eq!(MetadataAssembler::for_claimed_size(MAX_METADATA_SIZE).unwrap().num_pieces(), 1024);
    }
}
