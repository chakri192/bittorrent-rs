//! BEP 11 Peer Exchange (ut_pex), receive side.
//!
//! Once both sides advertise `ut_pex` in their BEP 10 handshake, peers
//! periodically push `{"added": <compact v4>, "added6": <compact v6>,
//! "dropped": ...}` dicts. For a downloader the value is `added`/`added6`:
//! free peer addresses without another tracker round trip -- often the
//! only fresh-peer source in a swarm whose trackers have gone stale.
//!
//! The send side is deliberately not implemented: a client that mostly
//! leeches has little of value to exchange, and BEP 11 makes the message
//! strictly optional in either direction.

use crate::bencode::{self, Bencode};
use crate::tracker::{parse_compact_peers, parse_compact_peers_v6};
use std::net::SocketAddr;

#[derive(Debug)]
pub enum PexError {
    Decode(bencode::DecodeError),
    NotADict,
    MalformedCompactPeers,
}

impl std::fmt::Display for PexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PexError::Decode(e) => write!(f, "bencode decode error: {}", e),
            PexError::NotADict => write!(f, "ut_pex payload is not a dict"),
            PexError::MalformedCompactPeers => write!(f, "ut_pex added/added6 not valid compact peer lists"),
        }
    }
}

impl std::error::Error for PexError {}

/// Parses a ut_pex message payload, returning every address in `added`
/// and `added6`. `dropped`/flag fields are ignored -- this client treats
/// PEX purely as a peer-discovery feed; dead addresses get weeded out by
/// the connect attempt itself.
pub fn parse_ut_pex(payload: &[u8]) -> Result<Vec<SocketAddr>, PexError> {
    // Lenient decode: this is wire data from an arbitrary remote client.
    let value = bencode::decode_lenient(payload).map_err(PexError::Decode)?;
    let dict = value.as_dict().ok_or(PexError::NotADict)?;

    let mut peers: Vec<SocketAddr> = Vec::new();

    if let Some(added) = dict.get(b"added".as_slice()).and_then(Bencode::as_bytes) {
        let v4 = parse_compact_peers(added).map_err(|_| PexError::MalformedCompactPeers)?;
        peers.extend(v4.into_iter().map(SocketAddr::V4));
    }
    if let Some(added6) = dict.get(b"added6".as_slice()).and_then(Bencode::as_bytes) {
        let v6 = parse_compact_peers_v6(added6).map_err(|_| PexError::MalformedCompactPeers)?;
        peers.extend(v6);
    }

    // Port 0 is never dialable; a handful of clients pad PEX messages
    // with zeroed entries.
    peers.retain(|p| p.port() != 0);
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn compact_v4(entries: &[(Ipv4Addr, u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (ip, port) in entries {
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        out
    }

    fn bencode_pex(added: &[u8], added6: Option<&[u8]>) -> Vec<u8> {
        // Hand-rolled: d 5:added <len>:<bytes> [6:added6 ...] e
        let mut out = Vec::new();
        out.push(b'd');
        out.extend_from_slice(format!("5:added{}:", added.len()).as_bytes());
        out.extend_from_slice(added);
        if let Some(a6) = added6 {
            out.extend_from_slice(format!("6:added6{}:", a6.len()).as_bytes());
            out.extend_from_slice(a6);
        }
        out.push(b'e');
        out
    }

    #[test]
    fn parses_added_v4_peers() {
        let compact = compact_v4(&[(Ipv4Addr::new(10, 0, 0, 1), 6881), (Ipv4Addr::new(192, 168, 1, 2), 51413)]);
        let payload = bencode_pex(&compact, None);
        let peers = parse_ut_pex(&payload).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], "10.0.0.1:6881".parse().unwrap());
        assert_eq!(peers[1], "192.168.1.2:51413".parse().unwrap());
    }

    #[test]
    fn parses_added6_peers() {
        let mut a6 = Vec::new();
        a6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        a6.extend_from_slice(&6881u16.to_be_bytes());
        let payload = bencode_pex(&[], Some(&a6));
        let peers = parse_ut_pex(&payload).unwrap();
        assert_eq!(peers, vec!["[::1]:6881".parse().unwrap()]);
    }

    #[test]
    fn drops_port_zero_entries() {
        let compact = compact_v4(&[(Ipv4Addr::new(10, 0, 0, 1), 0), (Ipv4Addr::new(10, 0, 0, 2), 6881)]);
        let payload = bencode_pex(&compact, None);
        let peers = parse_ut_pex(&payload).unwrap();
        assert_eq!(peers, vec!["10.0.0.2:6881".parse().unwrap()]);
    }

    #[test]
    fn empty_dict_yields_no_peers() {
        assert!(parse_ut_pex(b"de").unwrap().is_empty());
    }

    #[test]
    fn rejects_non_dict_payload() {
        assert!(matches!(parse_ut_pex(b"le"), Err(PexError::NotADict)));
    }

    #[test]
    fn rejects_malformed_compact_list() {
        let payload = bencode_pex(&[1, 2, 3], None); // not a multiple of 6
        assert!(matches!(parse_ut_pex(&payload), Err(PexError::MalformedCompactPeers)));
    }
}
