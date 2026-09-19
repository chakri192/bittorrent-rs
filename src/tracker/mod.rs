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
    /// The tracker answered with an HTTP status that is neither success nor
    /// a redirect it gave a location for.
    HttpStatus(u16),
    /// The tracker redirected to this location. Not an error to the caller
    /// of [`announce_http`], which follows it.
    Redirect(String),
    TooManyRedirects,
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
            TrackerError::HttpStatus(code) => write!(f, "tracker replied HTTP {}", code),
            TrackerError::Redirect(to) => write!(f, "redirected to {}", to),
            TrackerError::TooManyRedirects => write!(f, "too many redirects (more than {})", MAX_REDIRECTS),
        }
    }
}

impl std::error::Error for TrackerError {}

/// How many redirects an announce follows before giving up.
pub const MAX_REDIRECTS: usize = 5;

/// An HTTP or HTTPS announce that follows redirects. Trackers do redirect
/// -- `http://` to `https://`, an old address to a new one -- and answering
/// such a reply with an error lost every peer they would have given. A
/// redirect from `https://` to `http://` is refused: the URL often carries a
/// private tracker's passkey, and sending it in the clear is not what
/// whoever chose `https` agreed to.
pub fn announce_http(url: &str, req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    let mut current = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let result = if current.starts_with("https://") { https::announce(&current, req) } else { http::announce(&current, req) };
        match result {
            Err(TrackerError::Redirect(location)) => {
                let next = resolve_redirect(&current, &location)?;
                check_redirect_allowed(&current, &next)?;
                current = next;
            }
            other => return other,
        }
    }
    Err(TrackerError::TooManyRedirects)
}

/// Refuses a redirect that would send a secure request over plain HTTP.
fn check_redirect_allowed(from: &str, to: &str) -> Result<(), TrackerError> {
    if from.starts_with("https://") && to.starts_with("http://") {
        return Err(TrackerError::BadUrl(format!("refusing a redirect from https to http: {}", to)));
    }
    Ok(())
}

/// The absolute URL a `Location` header points to, from the URL that was
/// requested: an absolute URL as it is, `//host/path` with the same scheme,
/// `/path` on the same host, and `path` relative to the requested one's
/// directory.
fn resolve_redirect(base: &str, location: &str) -> Result<String, TrackerError> {
    let location = location.trim();
    if location.is_empty() {
        return Err(TrackerError::MalformedResponse("empty redirect location"));
    }
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    // Some other scheme (`ftp://...`): not something to announce to.
    if let Some((scheme, _)) = location.split_once("://") {
        if !scheme.is_empty() && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
            return Err(TrackerError::UnsupportedScheme(scheme.to_string()));
        }
    }
    let (scheme, rest) = base.split_once("://").ok_or_else(|| TrackerError::BadUrl(base.to_string()))?;
    if let Some(rest_of_location) = location.strip_prefix("//") {
        return Ok(format!("{}://{}", scheme, rest_of_location));
    }
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path_and_query) = rest.split_at(authority_end);
    if location.starts_with('/') {
        return Ok(format!("{}://{}{}", scheme, authority, location));
    }
    // Relative to the directory of the requested path (its query dropped).
    let path = path_and_query.split('?').next().unwrap_or("");
    let directory = &path[..path.rfind('/').map_or(0, |i| i + 1)];
    let directory = if directory.is_empty() { "/" } else { directory };
    Ok(format!("{}://{}{}{}", scheme, authority, directory, location))
}

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

    // ---- redirects ----

    #[test]
    fn a_location_is_resolved_against_the_url_that_was_requested() {
        let base = "http://tracker.example:8080/dir/announce?passkey=k";
        assert_eq!(resolve_redirect(base, "https://other.example/a").unwrap(), "https://other.example/a", "absolute");
        assert_eq!(resolve_redirect(base, "//cdn.example/a").unwrap(), "http://cdn.example/a", "same scheme");
        assert_eq!(resolve_redirect(base, "/new/announce").unwrap(), "http://tracker.example:8080/new/announce", "same host and port");
        assert_eq!(resolve_redirect(base, "sibling").unwrap(), "http://tracker.example:8080/dir/sibling", "relative to the directory");
        assert_eq!(resolve_redirect("http://tracker.example", "a").unwrap(), "http://tracker.example/a", "a base with no path");
        assert_eq!(resolve_redirect("https://t.example?x=1", "/a").unwrap(), "https://t.example/a", "a query straight after the host");
        assert!(resolve_redirect(base, "   ").is_err(), "an empty location goes nowhere");
        assert!(matches!(resolve_redirect(base, "ftp://x/y"), Err(TrackerError::UnsupportedScheme(ref s)) if s == "ftp"), "another scheme is not an announce URL");
        assert_eq!(resolve_redirect(base, "a:b/c").unwrap(), "http://tracker.example:8080/dir/a:b/c", "a colon in a relative path is not a scheme");
    }

    #[test]
    fn a_redirect_may_upgrade_to_https_but_never_downgrade_from_it() {
        assert!(check_redirect_allowed("http://a/x", "https://a/x").is_ok());
        assert!(check_redirect_allowed("http://a/x", "http://b/x").is_ok());
        assert!(check_redirect_allowed("https://a/x", "https://b/x").is_ok());
        let err = check_redirect_allowed("https://a/x?passkey=k", "http://b/x").unwrap_err();
        assert!(matches!(err, TrackerError::BadUrl(ref m) if m.contains("refusing")), "{}", err);
    }

    /// A one-thread HTTP server: `handler` gets each request's head and
    /// returns the whole reply. Returns the port and the heads seen.
    fn serve(handler: impl Fn(&str) -> Vec<u8> + Send + 'static) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&heads);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let response = handler(&head);
                seen.lock().unwrap().push(head);
                let _ = stream.write_all(&response);
            }
        });
        (port, heads)
    }

    fn ok_with_one_peer() -> Vec<u8> {
        let body = b"d8:intervali900e5:peers6:\x0a\x00\x00\x07\x1a\xe1e";
        let mut reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
        reply.extend_from_slice(body);
        reply
    }

    fn request() -> AnnounceRequest {
        AnnounceRequest { info_hash: [1; 20], peer_id: [2; 20], port: 6881, uploaded: 0, downloaded: 0, left: 1, compact: true, event: None, numwant: None }
    }

    #[test]
    fn an_announce_follows_a_redirect_to_another_server_and_gets_its_peers() {
        let (final_port, final_heads) = serve(|_| ok_with_one_peer());
        let (first_port, first_heads) = serve(move |_| format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/moved?x=1\r\nContent-Length: 0\r\n\r\n", final_port).into_bytes());

        let response = announce_http(&format!("http://127.0.0.1:{}/announce", first_port), &request()).expect("the redirect is followed");

        assert_eq!(response.peers.len(), 1, "the peers from the server it was sent to");
        assert_eq!(first_heads.lock().unwrap().len(), 1);
        let heads = final_heads.lock().unwrap();
        assert_eq!(heads.len(), 1);
        assert!(heads[0].starts_with("GET /moved?x=1&info_hash="), "the new path and its own query kept, the announce added: {:?}", heads[0]);
    }

    #[test]
    fn a_relative_redirect_stays_on_the_same_server() {
        let (port, heads) = serve(|head| if head.starts_with("GET /announce?") { b"HTTP/1.1 301 Moved\r\nLocation: /v2/announce\r\nContent-Length: 0\r\n\r\n".to_vec() } else { ok_with_one_peer() });

        let response = announce_http(&format!("http://127.0.0.1:{}/announce", port), &request()).unwrap();

        assert_eq!(response.peers.len(), 1);
        let heads = heads.lock().unwrap();
        assert_eq!(heads.len(), 2);
        assert!(heads[1].starts_with("GET /v2/announce?"), "{:?}", heads[1]);
    }

    #[test]
    fn a_redirect_loop_is_given_up_on_after_a_bounded_number_of_hops() {
        let (port, heads) = serve(|_| b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n".to_vec());

        let result = announce_http(&format!("http://127.0.0.1:{}/announce", port), &request());

        assert!(matches!(result, Err(TrackerError::TooManyRedirects)), "{:?}", result.err());
        assert_eq!(heads.lock().unwrap().len(), 6, "the first request and five redirects, no more");
    }

    #[test]
    fn a_redirect_to_a_scheme_that_is_not_http_is_refused() {
        let (port, _) = serve(|_| b"HTTP/1.1 302 Found\r\nLocation: ftp://elsewhere/announce\r\nContent-Length: 0\r\n\r\n".to_vec());
        let result = announce_http(&format!("http://127.0.0.1:{}/announce", port), &request());
        assert!(matches!(result, Err(TrackerError::UnsupportedScheme(_))), "{:?}", result.err());
    }

    #[test]
    fn a_plain_failure_status_is_reported_with_its_code() {
        let (port, heads) = serve(|_| b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec());
        let result = announce_http(&format!("http://127.0.0.1:{}/announce", port), &request());
        assert!(matches!(result, Err(TrackerError::HttpStatus(503))), "{:?}", result.err());
        assert_eq!(heads.lock().unwrap().len(), 1, "no retry, no redirect");
    }
}
