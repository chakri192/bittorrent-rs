//! Length-prefixed peer wire messages (BEP 3), post-handshake.
//! Frame: `length_prefix(u32 BE) [ message_id(u8) payload... ]`.
//! `length_prefix == 0` is a keep-alive with no id/payload.

use crate::bytes::be_u32;
use std::io::{self, Read, Write};

const MSG_CHOKE: u8 = 0;
const MSG_UNCHOKE: u8 = 1;
const MSG_INTERESTED: u8 = 2;
const MSG_NOT_INTERESTED: u8 = 3;
const MSG_HAVE: u8 = 4;
const MSG_BITFIELD: u8 = 5;
const MSG_REQUEST: u8 = 6;
const MSG_PIECE: u8 = 7;
const MSG_CANCEL: u8 = 8;
const MSG_PORT: u8 = 9;
// BEP 6, the Fast Extension.
const MSG_SUGGEST: u8 = 13;
const MSG_HAVE_ALL: u8 = 14;
const MSG_HAVE_NONE: u8 = 15;
const MSG_REJECT_REQUEST: u8 = 16;
const MSG_ALLOWED_FAST: u8 = 17;
// BEP 52, the hash messages of BitTorrent v2.
const MSG_HASH_REQUEST: u8 = 21;
const MSG_HASHES: u8 = 22;
const MSG_HASH_REJECT: u8 = 23;
/// BEP 10 extension protocol messages all share id 20; the extension
/// message id (ut_metadata, etc.) is negotiated separately and lives in
/// the payload. Handled fully in Phase 4 -- carried here as an opaque
/// payload so the framing layer doesn't need to know about it yet.
const MSG_EXTENDED: u8 = 20;

/// Caps a single message payload to guard against a malicious/buggy peer
/// sending a huge length prefix and exhausting memory before we even know
/// what kind of message it claims to be. 1 MiB comfortably exceeds the
/// largest legitimate message (a 16 KiB `piece` block plus its 8-byte
/// header, with room to spare).
const MAX_MESSAGE_LEN: u32 = 1 << 20;

/// What a BEP 52 hash request asks for, and what the `hashes` and `hash reject` answers repeat: hashes of one layer of a
/// file's merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashRequest {
    /// The file, by its `pieces root`.
    pub root: [u8; 32],
    /// Which layer: 0 for the 16 KiB leaf hashes, counting up.
    pub base_layer: u32,
    /// Where in that layer to start, in hashes: a multiple of `length`.
    pub index: u32,
    /// How many hashes: a power of two, at least two.
    pub length: u32,
    /// How many layers of uncle hashes come after them.
    pub proof_layers: u32,
}

const HASH_REQUEST_LEN: usize = 32 + 4 * 4;

impl HashRequest {
    fn write(&self, payload: &mut Vec<u8>) {
        payload.extend_from_slice(&self.root);
        for number in [self.base_layer, self.index, self.length, self.proof_layers] {
            payload.extend_from_slice(&number.to_be_bytes());
        }
    }

    fn read(payload: &[u8]) -> Result<HashRequest, WireError> {
        if payload.len() < HASH_REQUEST_LEN {
            return Err(WireError::Truncated { expected: HASH_REQUEST_LEN, got: payload.len() });
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&payload[..32]);
        Ok(HashRequest { root, base_layer: read_u32(payload, 32)?, index: read_u32(payload, 36)?, length: read_u32(payload, 40)?, proof_layers: read_u32(payload, 44)? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have { piece_index: u32 },
    Bitfield(Vec<u8>),
    Request { index: u32, begin: u32, length: u32 },
    Piece { index: u32, begin: u32, block: Vec<u8> },
    Cancel { index: u32, begin: u32, length: u32 },
    Port(u16),
    /// BEP 6: a piece the sender suggests the receiver fetch from it.
    Suggest { piece_index: u32 },
    /// BEP 6: the sender has every piece (in place of a full bitfield).
    HaveAll,
    /// BEP 6: the sender has no piece (in place of an empty bitfield).
    HaveNone,
    /// BEP 6: the sender will not answer this request. Sent instead of
    /// silence, so the requester need not wait to find out.
    RejectRequest { index: u32, begin: u32, length: u32 },
    /// BEP 6: the receiver may request this piece even while choked.
    AllowedFast { piece_index: u32 },
    /// Raw BEP 10 extended message: `id` is the negotiated extended
    /// message id (0 = handshake), `payload` is the bencoded dict (+
    /// trailing raw bytes for ut_metadata data pieces). Parsed further in
    /// Phase 4.
    Extended { id: u8, payload: Vec<u8> },
    /// BEP 52: asks for hashes from a file's merkle tree.
    HashRequest(HashRequest),
    /// BEP 52: the answer: the `length` hashes asked for, then the uncle hashes that carry them to the root.
    Hashes { request: HashRequest, hashes: Vec<[u8; 32]> },
    /// BEP 52: the peer will not answer that request.
    HashReject(HashRequest),
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    MessageTooLarge(u32),
    UnknownMessageId(u8),
    Truncated { expected: usize, got: usize },
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e)
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "io error: {}", e),
            WireError::MessageTooLarge(n) => write!(f, "message length {} exceeds cap {}", n, MAX_MESSAGE_LEN),
            WireError::UnknownMessageId(id) => write!(f, "unknown message id: {}", id),
            WireError::Truncated { expected, got } => write!(f, "payload truncated: expected {} bytes, got {}", expected, got),
        }
    }
}

impl std::error::Error for WireError {}

impl Message {
    fn id(&self) -> Option<u8> {
        match self {
            Message::KeepAlive => None,
            Message::Choke => Some(MSG_CHOKE),
            Message::Unchoke => Some(MSG_UNCHOKE),
            Message::Interested => Some(MSG_INTERESTED),
            Message::NotInterested => Some(MSG_NOT_INTERESTED),
            Message::Have { .. } => Some(MSG_HAVE),
            Message::Bitfield(_) => Some(MSG_BITFIELD),
            Message::Request { .. } => Some(MSG_REQUEST),
            Message::Piece { .. } => Some(MSG_PIECE),
            Message::Cancel { .. } => Some(MSG_CANCEL),
            Message::Port(_) => Some(MSG_PORT),
            Message::Suggest { .. } => Some(MSG_SUGGEST),
            Message::HaveAll => Some(MSG_HAVE_ALL),
            Message::HaveNone => Some(MSG_HAVE_NONE),
            Message::RejectRequest { .. } => Some(MSG_REJECT_REQUEST),
            Message::AllowedFast { .. } => Some(MSG_ALLOWED_FAST),
            Message::Extended { .. } => Some(MSG_EXTENDED),
            Message::HashRequest(_) => Some(MSG_HASH_REQUEST),
            Message::Hashes { .. } => Some(MSG_HASHES),
            Message::HashReject(_) => Some(MSG_HASH_REJECT),
        }
    }

    /// Serializes to the exact on-wire byte sequence, length prefix included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let Some(id) = self.id() else {
            return 0u32.to_be_bytes().to_vec(); // keep-alive: length 0, no id/payload
        };

        let mut payload = Vec::new();
        match self {
            Message::Have { piece_index } | Message::Suggest { piece_index } | Message::AllowedFast { piece_index } => payload.extend_from_slice(&piece_index.to_be_bytes()),
            Message::Bitfield(bits) => payload.extend_from_slice(bits),
            Message::Request { index, begin, length } | Message::Cancel { index, begin, length } | Message::RejectRequest { index, begin, length } => {
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(&begin.to_be_bytes());
                payload.extend_from_slice(&length.to_be_bytes());
            }
            Message::Piece { index, begin, block } => {
                payload.extend_from_slice(&index.to_be_bytes());
                payload.extend_from_slice(&begin.to_be_bytes());
                payload.extend_from_slice(block);
            }
            Message::Port(port) => payload.extend_from_slice(&port.to_be_bytes()),
            Message::Extended { id: ext_id, payload: ext_payload } => {
                payload.push(*ext_id);
                payload.extend_from_slice(ext_payload);
            }
            Message::HashRequest(request) | Message::HashReject(request) => request.write(&mut payload),
            Message::Hashes { request, hashes } => {
                request.write(&mut payload);
                for hash in hashes {
                    payload.extend_from_slice(hash);
                }
            }
            // No payload. (KeepAlive has no id and returned above.)
            Message::Choke | Message::Unchoke | Message::Interested | Message::NotInterested | Message::HaveAll | Message::HaveNone | Message::KeepAlive => {}
        }

        let len = 1 + payload.len() as u32; // +1 for the id byte
        let mut out = Vec::with_capacity(4 + len as usize);
        out.extend_from_slice(&len.to_be_bytes());
        out.push(id);
        out.extend_from_slice(&payload);
        out
    }

    /// Blocking read of exactly one framed message from `reader`.
    pub fn read_from<R: Read + ?Sized>(reader: &mut R) -> Result<Message, WireError> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf);

        if len == 0 {
            return Ok(Message::KeepAlive);
        }
        if len > MAX_MESSAGE_LEN {
            return Err(WireError::MessageTooLarge(len));
        }

        let mut body = vec![0u8; len as usize];
        reader.read_exact(&mut body)?;
        let id = body[0];
        let payload = &body[1..];

        Ok(match id {
            MSG_CHOKE => Message::Choke,
            MSG_UNCHOKE => Message::Unchoke,
            MSG_INTERESTED => Message::Interested,
            MSG_NOT_INTERESTED => Message::NotInterested,
            MSG_HAVE => Message::Have { piece_index: read_u32(payload, 0)? },
            MSG_BITFIELD => Message::Bitfield(payload.to_vec()),
            MSG_REQUEST => Message::Request {
                index: read_u32(payload, 0)?,
                begin: read_u32(payload, 4)?,
                length: read_u32(payload, 8)?,
            },
            MSG_PIECE => {
                if payload.len() < 8 {
                    return Err(WireError::Truncated { expected: 8, got: payload.len() });
                }
                Message::Piece {
                    index: read_u32(payload, 0)?,
                    begin: read_u32(payload, 4)?,
                    block: payload[8..].to_vec(),
                }
            }
            MSG_CANCEL => Message::Cancel {
                index: read_u32(payload, 0)?,
                begin: read_u32(payload, 4)?,
                length: read_u32(payload, 8)?,
            },
            MSG_SUGGEST => Message::Suggest { piece_index: read_u32(payload, 0)? },
            MSG_HAVE_ALL => Message::HaveAll,
            MSG_HAVE_NONE => Message::HaveNone,
            MSG_REJECT_REQUEST => Message::RejectRequest { index: read_u32(payload, 0)?, begin: read_u32(payload, 4)?, length: read_u32(payload, 8)? },
            MSG_ALLOWED_FAST => Message::AllowedFast { piece_index: read_u32(payload, 0)? },
            MSG_PORT => {
                if payload.len() < 2 {
                    return Err(WireError::Truncated { expected: 2, got: payload.len() });
                }
                Message::Port(u16::from_be_bytes([payload[0], payload[1]]))
            }
            MSG_HASH_REQUEST => Message::HashRequest(HashRequest::read(payload)?),
            MSG_HASH_REJECT => Message::HashReject(HashRequest::read(payload)?),
            MSG_HASHES => {
                let request = HashRequest::read(payload)?;
                let rest = &payload[HASH_REQUEST_LEN..];
                if rest.len() & 31 != 0 {
                    return Err(WireError::Truncated { expected: HASH_REQUEST_LEN + rest.len().div_ceil(32) * 32, got: payload.len() });
                }
                Message::Hashes { request, hashes: rest.as_chunks::<32>().0.to_vec() }
            }
            MSG_EXTENDED => {
                if payload.is_empty() {
                    return Err(WireError::Truncated { expected: 1, got: 0 });
                }
                Message::Extended { id: payload[0], payload: payload[1..].to_vec() }
            }
            other => return Err(WireError::UnknownMessageId(other)),
        })
    }

    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), WireError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, WireError> {
    be_u32(payload, offset).ok_or(WireError::Truncated { expected: offset.saturating_add(4), got: payload.len() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn round_trip(msg: Message) {
        let bytes = msg.to_bytes();
        let mut cursor = Cursor::new(bytes);
        let parsed = Message::read_from(&mut cursor).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn keep_alive_is_four_zero_bytes() {
        assert_eq!(Message::KeepAlive.to_bytes(), vec![0, 0, 0, 0]);
        round_trip(Message::KeepAlive);
    }

    #[test]
    fn choke_unchoke_interested_not_interested_round_trip() {
        round_trip(Message::Choke);
        round_trip(Message::Unchoke);
        round_trip(Message::Interested);
        round_trip(Message::NotInterested);
    }

    #[test]
    fn zero_length_messages_have_length_prefix_one() {
        assert_eq!(&Message::Choke.to_bytes()[..4], &1u32.to_be_bytes());
    }

    #[test]
    fn have_round_trips() {
        round_trip(Message::Have { piece_index: 1234 });
    }

    #[test]
    fn bitfield_round_trips() {
        round_trip(Message::Bitfield(vec![0xFF, 0x00, 0xAB]));
    }

    #[test]
    fn empty_bitfield_round_trips() {
        round_trip(Message::Bitfield(vec![]));
    }

    #[test]
    fn request_round_trips() {
        round_trip(Message::Request { index: 1, begin: 16384, length: 16384 });
    }

    #[test]
    fn piece_round_trips_with_block_data() {
        round_trip(Message::Piece { index: 2, begin: 0, block: vec![1, 2, 3, 4, 5] });
    }

    #[test]
    fn piece_round_trips_with_empty_block() {
        round_trip(Message::Piece { index: 0, begin: 0, block: vec![] });
    }

    #[test]
    fn cancel_round_trips() {
        round_trip(Message::Cancel { index: 3, begin: 32768, length: 16384 });
    }

    #[test]
    fn port_round_trips() {
        round_trip(Message::Port(6881));
    }

    #[test]
    fn extended_round_trips() {
        round_trip(Message::Extended { id: 0, payload: vec![0x64, 0x65] }); // arbitrary bytes stand-in for bencode
    }

    #[test]
    fn rejects_oversized_length_prefix() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_LEN + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);
        assert!(matches!(Message::read_from(&mut cursor), Err(WireError::MessageTooLarge(_))));
    }

    #[test]
    fn rejects_unknown_message_id() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(200); // not a valid id
        let mut cursor = Cursor::new(buf);
        assert!(matches!(Message::read_from(&mut cursor), Err(WireError::UnknownMessageId(200))));
    }

    #[test]
    fn rejects_truncated_have_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_be_bytes()); // claims id + 1 byte, but have needs id + 4
        buf.push(MSG_HAVE);
        buf.push(0xFF);
        let mut cursor = Cursor::new(buf);
        assert!(matches!(Message::read_from(&mut cursor), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn reads_two_messages_back_to_back_from_same_stream() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&Message::Unchoke.to_bytes());
        buf.extend_from_slice(&Message::Interested.to_bytes());
        let mut cursor = Cursor::new(buf);
        assert_eq!(Message::read_from(&mut cursor).unwrap(), Message::Unchoke);
        assert_eq!(Message::read_from(&mut cursor).unwrap(), Message::Interested);
    }

    #[test]
    fn write_to_matches_to_bytes() {
        let msg = Message::Have { piece_index: 7 };
        let mut buf = Vec::new();
        msg.write_to(&mut buf).unwrap();
        assert_eq!(buf, msg.to_bytes());
    }

    #[test]
    fn the_hash_messages_have_their_ids_and_layout_and_round_trip() {
        let request = HashRequest { root: [7; 32], base_layer: 2, index: 4, length: 8, proof_layers: 3 };
        let bytes = Message::HashRequest(request).to_bytes();
        assert_eq!(bytes[..5], [0, 0, 0, 49, 21], "a length of 1 + 32 + 4 * 4, and id 21");
        assert_eq!(bytes[5..37], [7u8; 32]);
        assert_eq!(bytes[37..], [0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 8, 0, 0, 0, 3], "four big-endian numbers after the root");
        assert_eq!(Message::HashReject(request).to_bytes()[4], 23);
        let answer = Message::Hashes { request, hashes: vec![[1; 32], [2; 32], [3; 32]] };
        let bytes = answer.to_bytes();
        assert_eq!((bytes[4], bytes.len()), (22, 4 + 1 + 48 + 96));
        for msg in [Message::HashRequest(request), Message::HashReject(request), answer, Message::Hashes { request, hashes: Vec::new() }, Message::HashRequest(HashRequest { root: [0xFF; 32], base_layer: u32::MAX, index: u32::MAX, length: u32::MAX, proof_layers: u32::MAX })] {
            round_trip(msg);
        }
    }

    #[test]
    fn a_truncated_or_ragged_hash_message_is_an_error_not_a_panic() {
        let request = HashRequest { root: [7; 32], base_layer: 0, index: 0, length: 2, proof_layers: 0 };
        let bytes = Message::Hashes { request, hashes: vec![[1; 32]] }.to_bytes();
        for cut in 5..bytes.len() {
            let mut shortened = bytes[..cut].to_vec();
            let len = (cut - 4) as u32;
            shortened[..4].copy_from_slice(&len.to_be_bytes());
            let read = Message::read_from(&mut Cursor::new(shortened));
            assert!(read.is_err() || cut == bytes.len() - 32 || cut == bytes.len(), "cut at {}: {:?}", cut, read);
        }
        // A tail that is not a whole number of hashes.
        let mut ragged = bytes.clone();
        ragged.extend_from_slice(&[9; 5]);
        let len = (ragged.len() - 4) as u32;
        ragged[..4].copy_from_slice(&len.to_be_bytes());
        assert!(matches!(Message::read_from(&mut Cursor::new(ragged)), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn the_fast_extension_messages_have_their_ids_and_round_trip() {
        assert_eq!(Message::Suggest { piece_index: 7 }.to_bytes(), vec![0, 0, 0, 5, 13, 0, 0, 0, 7]);
        assert_eq!(Message::HaveAll.to_bytes(), vec![0, 0, 0, 1, 14]);
        assert_eq!(Message::HaveNone.to_bytes(), vec![0, 0, 0, 1, 15]);
        assert_eq!(Message::RejectRequest { index: 1, begin: 2, length: 3 }.to_bytes(), vec![0, 0, 0, 13, 16, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
        assert_eq!(Message::AllowedFast { piece_index: 9 }.to_bytes(), vec![0, 0, 0, 5, 17, 0, 0, 0, 9]);
        for msg in [Message::Suggest { piece_index: 1 }, Message::HaveAll, Message::HaveNone, Message::RejectRequest { index: u32::MAX, begin: 0, length: 16384 }, Message::AllowedFast { piece_index: 0 }] {
            round_trip(msg);
        }
    }

    #[test]
    fn truncated_fast_extension_messages_are_errors_not_panics() {
        for (id, payload_len) in [(13u8, 3usize), (16, 11), (17, 0)] {
            let mut frame = ((1 + payload_len) as u32).to_be_bytes().to_vec();
            frame.push(id);
            frame.extend(vec![0u8; payload_len]);
            assert!(matches!(Message::read_from(&mut Cursor::new(frame)), Err(WireError::Truncated { .. })), "id {}", id);
        }
    }
}
