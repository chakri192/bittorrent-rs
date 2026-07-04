//! BEP 10 Extension Protocol: the extended handshake itself. Carried as
//! `Message::Extended { id: 0, payload }` where `payload` is a bencoded
//! dict `{"m": {"ut_metadata": <id>, ...}, "metadata_size": <n>, "v": <str>, "p": <port>}`.
//! `id: 0` is reserved by BEP 10 to mean "this is the handshake, not a
//! negotiated extension message".

use crate::bencode::{self, Bencode, DecodeError};
use std::collections::BTreeMap;

pub const EXTENDED_HANDSHAKE_ID: u8 = 0;
/// The name both sides register under `m` for BEP 9 metadata exchange.
pub const UT_METADATA: &str = "ut_metadata";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExtendedHandshake {
    /// extension name -> the *sender's* chosen id for that extension.
    /// E.g. if `m` contains `("ut_metadata", 3)`, send that peer
    /// `Extended { id: 3, .. }` to talk ut_metadata to them.
    pub m: BTreeMap<String, u8>,
    /// Total size in bytes of the info dict, present once the sender
    /// actually knows it (the whole point of BEP 9 is that the requester
    /// doesn't know this yet -- it learns it from the *peer's* handshake).
    pub metadata_size: Option<i64>,
    pub client_version: Option<String>,
    pub listen_port: Option<u16>,
}

#[derive(Debug)]
pub enum ExtensionError {
    Decode(DecodeError),
    NotADict,
    MissingMDict,
}

impl From<DecodeError> for ExtensionError {
    fn from(e: DecodeError) -> Self {
        ExtensionError::Decode(e)
    }
}

impl std::fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtensionError::Decode(e) => write!(f, "bencode decode error: {}", e),
            ExtensionError::NotADict => write!(f, "extended handshake payload is not a dict"),
            ExtensionError::MissingMDict => write!(f, "extended handshake missing 'm' dict"),
        }
    }
}

impl std::error::Error for ExtensionError {}

impl ExtendedHandshake {
    /// Builds our outbound handshake: we advertise support for
    /// `ut_metadata` under local id `our_ut_metadata_id` (an id *we* pick
    /// for messages *we* receive -- the peer picks its own separately).
    /// `metadata_size` is `Some` only once we actually have the info dict
    /// (e.g. we're seeding metadata to someone else); a pure downloader
    /// starting from a magnet link sends `None`.
    pub fn build(our_ut_metadata_id: u8, metadata_size: Option<i64>) -> Vec<u8> {
        let mut m = BTreeMap::new();
        m.insert(UT_METADATA.as_bytes().to_vec(), Bencode::Int(our_ut_metadata_id as i64));

        let mut top = BTreeMap::new();
        top.insert(b"m".to_vec(), Bencode::Dict(m));
        if let Some(size) = metadata_size {
            top.insert(b"metadata_size".to_vec(), Bencode::Int(size));
        }
        top.insert(b"v".to_vec(), Bencode::Bytes(b"bittorrent-rs/0.1".to_vec()));

        encode_bencode(&Bencode::Dict(top))
    }

    pub fn parse(payload: &[u8]) -> Result<Self, ExtensionError> {
        let value = bencode::decode(payload)?;
        let dict = value.as_dict().ok_or(ExtensionError::NotADict)?;

        let m_dict = dict.get(b"m".as_slice()).and_then(Bencode::as_dict).ok_or(ExtensionError::MissingMDict)?;
        let m = m_dict
            .iter()
            .filter_map(|(k, v)| {
                let name = std::str::from_utf8(k).ok()?.to_string();
                let id = v.as_int()? as u8;
                Some((name, id))
            })
            .collect();

        let metadata_size = value.get("metadata_size").and_then(Bencode::as_int);
        let client_version = value.get("v").and_then(Bencode::as_str).map(str::to_string);
        let listen_port = value.get("p").and_then(Bencode::as_int).map(|p| p as u16);

        Ok(ExtendedHandshake { m, metadata_size, client_version, listen_port })
    }

    /// The peer's chosen id for `ut_metadata`, if they advertised support.
    /// Send this as the `id` field of `Message::Extended` to talk metadata
    /// exchange to *this* peer.
    pub fn peer_ut_metadata_id(&self) -> Option<u8> {
        self.m.get(UT_METADATA).copied()
    }
}

/// Minimal bencode encoder (the decoder in `bencode.rs` has no inverse --
/// we've only ever needed to *read* torrent/tracker data until now). Only
/// handles the value shapes BEP 10/9 messages actually use.
fn encode_bencode(value: &Bencode) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Bencode, out: &mut Vec<u8>) {
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
            for item in items {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        Bencode::Dict(map) => {
            out.push(b'd');
            // BTreeMap already iterates in sorted key order, matching BEP 3.
            for (k, v) in map {
                encode_into(&Bencode::Bytes(k.clone()), out);
                encode_into(v, out);
            }
            out.push(b'e');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_parse_round_trips_ut_metadata_id() {
        let bytes = ExtendedHandshake::build(5, None);
        let parsed = ExtendedHandshake::parse(&bytes).unwrap();
        assert_eq!(parsed.peer_ut_metadata_id(), Some(5));
        assert!(parsed.metadata_size.is_none());
    }

    #[test]
    fn build_then_parse_round_trips_metadata_size() {
        let bytes = ExtendedHandshake::build(3, Some(48213));
        let parsed = ExtendedHandshake::parse(&bytes).unwrap();
        assert_eq!(parsed.metadata_size, Some(48213));
        assert_eq!(parsed.peer_ut_metadata_id(), Some(3));
    }

    #[test]
    fn build_includes_client_version() {
        let bytes = ExtendedHandshake::build(1, None);
        let parsed = ExtendedHandshake::parse(&bytes).unwrap();
        assert_eq!(parsed.client_version.as_deref(), Some("bittorrent-rs/0.1"));
    }

    #[test]
    fn parses_handshake_from_a_real_looking_client() {
        // Mimics a libtorrent-style handshake with extra unrecognized keys.
        let raw = b"d1:md11:ut_metadatai2e6:ut_pexi1ee13:metadata_sizei34521e1:pi6881e4:reqqi500e1:v12:libtorrent/1e";
        let parsed = ExtendedHandshake::parse(raw).unwrap();
        assert_eq!(parsed.peer_ut_metadata_id(), Some(2));
        assert_eq!(parsed.metadata_size, Some(34521));
        assert_eq!(parsed.listen_port, Some(6881));
        assert_eq!(parsed.client_version.as_deref(), Some("libtorrent/1"));
    }

    #[test]
    fn rejects_payload_missing_m_dict() {
        let raw = b"d13:metadata_sizei100ee";
        assert!(matches!(ExtendedHandshake::parse(raw), Err(ExtensionError::MissingMDict)));
    }

    #[test]
    fn peer_without_ut_metadata_support_returns_none() {
        let raw = b"d1:md6:ut_pexi1eee";
        let parsed = ExtendedHandshake::parse(raw).unwrap();
        assert_eq!(parsed.peer_ut_metadata_id(), None);
    }

    #[test]
    fn encode_bencode_matches_hand_written_bytes_for_simple_dict() {
        let mut m = BTreeMap::new();
        m.insert(b"a".to_vec(), Bencode::Int(1));
        let bytes = encode_bencode(&Bencode::Dict(m));
        assert_eq!(bytes, b"d1:ai1ee");
    }
}
