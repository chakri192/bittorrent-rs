//! Length-prefixed peer wire messages (BEP 3), post-handshake.
//! Frame: `length_prefix(u32 BE) [ message_id(u8) payload... ]`.
//! `length_prefix == 0` is a keep-alive with no id/payload.

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
    /// Raw BEP 10 extended message: `id` is the negotiated extended
    /// message id (0 = handshake), `payload` is the bencoded dict (+
    /// trailing raw bytes for ut_metadata data pieces). Parsed further in
    /// Phase 4.
    Extended { id: u8, payload: Vec<u8> },
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
            Message::Extended { .. } => Some(MSG_EXTENDED),
        }
    }

    /// Serializes to the exact on-wire byte sequence, length prefix included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let Some(id) = self.id() else {
            return 0u32.to_be_bytes().to_vec(); // keep-alive: length 0, no id/payload
        };

        let mut payload = Vec::new();
        match self {
            Message::Have { piece_index } => payload.extend_from_slice(&piece_index.to_be_bytes()),
            Message::Bitfield(bits) => payload.extend_from_slice(bits),
            Message::Request { index, begin, length } | Message::Cancel { index, begin, length } => {
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
            Message::Choke | Message::Unchoke | Message::Interested | Message::NotInterested => {}
            Message::KeepAlive => unreachable!(),
        }

        let len = 1 + payload.len() as u32; // +1 for the id byte
        let mut out = Vec::with_capacity(4 + len as usize);
        out.extend_from_slice(&len.to_be_bytes());
        out.push(id);
        out.extend_from_slice(&payload);
        out
    }

    /// Blocking read of exactly one framed message from `reader`.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Message, WireError> {
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
            MSG_PORT => {
                if payload.len() < 2 {
                    return Err(WireError::Truncated { expected: 2, got: payload.len() });
                }
                Message::Port(u16::from_be_bytes([payload[0], payload[1]]))
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

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), WireError> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, WireError> {
    if payload.len() < offset + 4 {
        return Err(WireError::Truncated { expected: offset + 4, got: payload.len() });
    }
    Ok(u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap()))
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
}
