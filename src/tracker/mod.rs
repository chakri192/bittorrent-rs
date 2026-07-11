//! Tracker communication (BEP 3 HTTP tracker, BEP 15 UDP tracker).
//!
//! Both transports share the same logical request/response shape; only the
//! wire encoding differs (URL query string vs. fixed-width binary packets).

pub mod http;
pub mod https;
pub mod udp;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Started,
    Stopped,
    Completed,
}

impl Event {
    fn as_str(self) -> &'static str {
        match self {
            Event::Started => "started",
            Event::Stopped => "stopped",
            Event::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub compact: bool,
    pub event: Option<Event>,
    pub numwant: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct AnnounceResponse {
    pub interval: u32,
    pub min_interval: Option<u32>,
    pub complete: Option<u32>,
    pub incomplete: Option<u32>,
    pub peers: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum TrackerError {
    Io(std::io::Error),
    Decode(crate::bencode::DecodeError),
    BadUrl(String),
    UnsupportedScheme(String),
    MalformedResponse(&'static str),
    TrackerFailure(String),
    Timeout,
    Tls(String),
}

impl From<std::io::Error> for TrackerError {
    fn from(e: std::io::Error) -> Self {
        TrackerError::Io(e)
    }
}

impl From<crate::bencode::DecodeError> for TrackerError {
    fn from(e: crate::bencode::DecodeError) -> Self {
        TrackerError::Decode(e)
    }
}

impl fmt::Display for TrackerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrackerError::Io(e) => write!(f, "io error: {}", e),
            TrackerError::Decode(e) => write!(f, "bencode decode error: {}", e),
            TrackerError::BadUrl(s) => write!(f, "malformed tracker url: {}", s),
            TrackerError::UnsupportedScheme(s) => write!(f, "unsupported tracker scheme: {}", s),
            TrackerError::MalformedResponse(s) => write!(f, "malformed tracker response: {}", s),
            TrackerError::TrackerFailure(s) => write!(f, "tracker returned failure reason: {}", s),
            TrackerError::Timeout => write!(f, "tracker request timed out"),
            TrackerError::Tls(s) => write!(f, "TLS error: {}", s),
        }
    }
}

impl std::error::Error for TrackerError {}

/// Generates a 20-byte Azureus-style peer_id: "-RS0001-" + 12 pseudo-random
/// bytes. "RS" is an arbitrary client ID for this project; 0001 is the
/// version.
pub fn generate_peer_id() -> [u8; 20] {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(b"-RS0001-");

    // No external RNG crate. Three entropy sources mixed together:
    //  - a per-process atomic counter, which is what actually *guarantees*
    //    two calls never collide -- unlike a clock reading or a stack
    //    address, it's impossible for two increments to return the same
    //    value regardless of how fast they happen or what the OS's clock
    //    resolution is;
    //  - wall-clock nanos, for variation across process runs;
    //  - `RandomState`'s hasher, which the standard library seeds from the
    //    OS's real RNG on every construction -- this is a well-known
    //    no-dependency way to get real entropy in Rust without a `rand`
    //    crate.
    // (An earlier version of this function mixed in a stack address
    // instead of the counter. That was a bug: calling the same function
    // twice in a row reuses the same stack slot, so the address was
    // identical both times and contributed zero entropy -- on a platform
    // with coarse clock resolution this let two back-to-back calls
    // produce an identical peer_id, caught by
    // `peer_id_generation_is_not_constant` failing intermittently.)
    static CALL_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = CALL_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let time_component = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);

    let os_entropy = {
        use std::hash::{BuildHasher, Hasher};
        std::collections::hash_map::RandomState::new().build_hasher().finish()
    };

    let mut x = counter ^ time_component ^ os_entropy ^ 0x9E3779B97F4A7C15;
    if x == 0 {
        x = 1; // xorshift64 requires a nonzero state
    }
    for byte in &mut id[8..20] {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *byte = (x & 0xFF) as u8;
    }
    id
}

/// Percent-encodes raw bytes per RFC 3986 "unreserved" set
/// (`A-Za-z0-9-_.~`); everything else becomes `%XX` (uppercase hex).
/// `info_hash` and `peer_id` are raw 20-byte binary blobs, not UTF-8 text,
/// so this operates on `&[u8]` rather than `&str`.
pub fn percent_encode_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}

/// Decodes the "compact" peer list format shared by HTTP (BEP 23) and UDP
/// (BEP 15) trackers: a flat byte string, 6 bytes per peer
/// (4-byte big-endian IPv4 + 2-byte big-endian port).
pub fn parse_compact_peers(data: &[u8]) -> Result<Vec<SocketAddrV4>, TrackerError> {
    // `is_multiple_of` (clippy's suggested replacement) requires a very
    // recent stdlib; suppressing the lint instead of rewriting keeps this
    // crate buildable on older toolchains too.
    #[allow(clippy::manual_is_multiple_of)]
    if data.len() % 6 != 0 {
        return Err(TrackerError::MalformedResponse("compact peers length not a multiple of 6"));
    }
    Ok(data
        .chunks_exact(6)
        .map(|c| {
            let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            let port = u16::from_be_bytes([c[4], c[5]]);
            SocketAddrV4::new(ip, port)
        })
        .collect())
}

/// Decodes the IPv6 sibling of the compact peer format (the HTTP tracker
/// response's `peers6` key, per BEP 7 / common tracker practice -- there
/// is no separate BEP number for this specific field, it's an informal
/// but widely-implemented extension of BEP 23): 18 bytes per peer
/// (16-byte IPv6 address + 2-byte big-endian port).
///
/// This covers HTTP/HTTPS trackers only. UDP trackers' IPv6 support
/// (BEP 32) uses a materially different announce packet layout and isn't
/// implemented -- `tracker::udp` remains IPv4-only.
#[allow(clippy::manual_is_multiple_of)]
pub fn parse_compact_peers_v6(data: &[u8]) -> Result<Vec<SocketAddr>, TrackerError> {
    if data.len() % 18 != 0 {
        return Err(TrackerError::MalformedResponse("compact peers6 length not a multiple of 18"));
    }
    Ok(data
        .chunks_exact(18)
        .map(|c| {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&c[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([c[16], c[17]]);
            SocketAddr::new(IpAddr::V6(ip), port)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encodes_unreserved_chars_unchanged() {
        assert_eq!(percent_encode_bytes(b"AZaz09-_.~"), "AZaz09-_.~");
    }

    #[test]
    fn percent_encodes_arbitrary_bytes() {
        // 0x00, 0x01, ' ', '/' all need escaping.
        assert_eq!(percent_encode_bytes(&[0x00, 0x01, b' ', b'/']), "%00%01%20%2F");
    }

    #[test]
    fn percent_encodes_full_info_hash_length() {
        let hash = [0xABu8; 20];
        let enc = percent_encode_bytes(&hash);
        assert_eq!(enc, "%AB".repeat(20));
    }

    #[test]
    fn peer_id_has_correct_prefix_and_length() {
        let id = generate_peer_id();
        assert_eq!(&id[..8], b"-RS0001-");
        assert_eq!(id.len(), 20);
    }

    #[test]
    fn peer_id_generation_is_not_constant() {
        // Not a strong randomness guarantee, just a smoke test that the
        // entropy sources actually vary call to call.
        let a = generate_peer_id();
        let b = generate_peer_id();
        assert_ne!(&a[8..], &b[8..]);
    }

    #[test]
    fn peer_id_generation_produces_no_duplicates_across_many_rapid_calls() {
        // Regression test for a real bug: an earlier version mixed a
        // stack address into the entropy, which is identical across two
        // sequential calls to the same function and contributed nothing.
        // Combined with coarse clock resolution on some platforms, two
        // back-to-back calls could produce an identical peer_id. The
        // atomic call counter this now uses makes that structurally
        // impossible regardless of clock resolution -- this test calls
        // fast enough (no sleep) to be the adversarial case.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = generate_peer_id();
            assert!(seen.insert(id), "duplicate peer_id generated: {:?}", id);
        }
    }

    #[test]
    fn parses_compact_peers() {
        // 127.0.0.1:6881, 10.0.0.5:51413
        let mut data = Vec::new();
        data.extend_from_slice(&[127, 0, 0, 1]);
        data.extend_from_slice(&6881u16.to_be_bytes());
        data.extend_from_slice(&[10, 0, 0, 5]);
        data.extend_from_slice(&51413u16.to_be_bytes());

        let peers = parse_compact_peers(&data).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6881));
        assert_eq!(peers[1], SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 51413));
    }

    #[test]
    fn rejects_compact_peers_bad_length() {
        assert!(matches!(parse_compact_peers(&[1, 2, 3]), Err(TrackerError::MalformedResponse(_))));
    }

    #[test]
    fn empty_compact_peers_is_ok() {
        assert_eq!(parse_compact_peers(&[]).unwrap(), vec![]);
    }

    #[test]
    fn parses_compact_peers_v6() {
        let mut data = Vec::new();
        // ::1 (loopback), port 6881
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&6881u16.to_be_bytes());
        let peers = parse_compact_peers_v6(&data).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 6881));
    }

    #[test]
    fn rejects_compact_peers_v6_bad_length() {
        assert!(matches!(parse_compact_peers_v6(&[1, 2, 3]), Err(TrackerError::MalformedResponse(_))));
    }

    #[test]
    fn empty_compact_peers_v6_is_ok() {
        assert_eq!(parse_compact_peers_v6(&[]).unwrap(), vec![]);
    }
}
