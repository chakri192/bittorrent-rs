//! HTTP tracker announce (BEP 3), implemented over a raw `TcpStream` --
//! no `reqwest`/`hyper`/`curl`. This only needs a GET, a handful of request
//! headers, and just enough response parsing (status line, headers,
//! Content-Length OR chunked transfer-encoding) to get the bencoded body.
//! `https://` trackers are handled by `tracker::https`, which reuses
//! everything here except the transport (TLS-wrapped stream instead of a
//! bare `TcpStream`) via `perform_request_and_parse`.

use super::{percent_encode_bytes, parse_compact_peers, AnnounceRequest, AnnounceResponse, TrackerError};
use crate::bencode::{self, Bencode};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Bare-bones parsed `scheme://host[:port]/path[?query]` URL. No userinfo,
/// no fragment -- trackers don't use them.
pub(crate) struct ParsedUrl {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path_and_query: String,
}

fn parse_http_url(url: &str) -> Result<ParsedUrl, TrackerError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| TrackerError::UnsupportedScheme(url.split("://").next().unwrap_or(url).to_string()))?;
    parse_authority_and_path(url, rest, 80)
}

/// Shared by `http.rs` and `https.rs`: both are the same `host[:port]/path`
/// grammar, differing only in the scheme prefix already stripped by the
/// caller and the default port when none is given.
pub(crate) fn parse_authority_and_path(full_url: &str, rest: &str, default_port: u16) -> Result<ParsedUrl, TrackerError> {
    let (authority, path_and_query) = match rest.find('/') {
        Some(idx) => (&rest[..idx], rest[idx..].to_string()),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(TrackerError::BadUrl(full_url.to_string()));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| TrackerError::BadUrl(full_url.to_string()))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), default_port),
    };

    Ok(ParsedUrl { host, port, path_and_query })
}

pub(crate) fn build_query(req: &AnnounceRequest) -> String {
    let mut q = String::new();
    q.push_str("info_hash=");
    q.push_str(&percent_encode_bytes(&req.info_hash));
    q.push_str("&peer_id=");
    q.push_str(&percent_encode_bytes(&req.peer_id));
    q.push_str(&format!("&port={}", req.port));
    q.push_str(&format!("&uploaded={}", req.uploaded));
    q.push_str(&format!("&downloaded={}", req.downloaded));
    q.push_str(&format!("&left={}", req.left));
    q.push_str(&format!("&compact={}", if req.compact { 1 } else { 0 }));
    if let Some(event) = req.event {
        q.push_str("&event=");
        q.push_str(event.as_str());
    }
    if let Some(numwant) = req.numwant {
        q.push_str(&format!("&numwant={}", numwant));
    }
    q
}

/// The most a tracker's whole HTTP response (headers and body) may be.
/// A real announce reply is a few KB: fifty peers are 300 bytes.
const MAX_RESPONSE_BYTES: usize = 4 << 20;

/// Reads an HTTP/1.1 response off `stream` until the body is fully
/// received, and returns just the body bytes. Handles `Content-Length`
/// and `Transfer-Encoding: chunked`; falls back to "read until EOF" if
/// neither header is present (valid for `Connection: close` responses,
/// which is what we always request). Generic over `Read` so the same
/// logic serves both a plain `TcpStream` (this module) and a TLS-wrapped
/// stream (`tracker::https`).
pub(crate) fn read_http_response_body<S: Read>(stream: &mut S) -> Result<Vec<u8>, TrackerError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                // The read timeout restarts with every read, so a tracker
                // that never stops sending would otherwise fill memory.
                if buf.len() > MAX_RESPONSE_BYTES {
                    return Err(TrackerError::MalformedResponse("tracker response too large"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(TrackerError::Io(e)),
        }
    }

    let header_end = find_subslice(&buf, b"\r\n\r\n").ok_or(TrackerError::MalformedResponse("no header/body separator"))?;
    let (header_bytes, body_start) = (&buf[..header_end], header_end + 4);
    let header_text = String::from_utf8_lossy(header_bytes);

    let status_line = header_text.lines().next().unwrap_or("");
    let status_code: u16 = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    if !(200..300).contains(&status_code) {
        return Err(TrackerError::MalformedResponse("non-2xx HTTP status from tracker"));
    }

    let is_chunked = header_text.to_ascii_lowercase().contains("transfer-encoding: chunked");
    let content_length: Option<usize> = header_text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok());

    let raw_body = &buf[body_start..];

    if is_chunked {
        decode_chunked_body(raw_body)
    } else if let Some(len) = content_length {
        if raw_body.len() < len {
            return Err(TrackerError::MalformedResponse("response truncated before Content-Length"));
        }
        Ok(raw_body[..len].to_vec())
    } else {
        // Connection: close, no length header -- whatever we read is the body.
        Ok(raw_body.to_vec())
    }
}

fn decode_chunked_body(mut data: &[u8]) -> Result<Vec<u8>, TrackerError> {
    let mut out = Vec::new();
    loop {
        let line_end = find_subslice(data, b"\r\n").ok_or(TrackerError::MalformedResponse("bad chunk size line"))?;
        let size_line = std::str::from_utf8(&data[..line_end]).map_err(|_| TrackerError::MalformedResponse("non-utf8 chunk size"))?;
        // Chunk size may have ";extensions" after it -- ignore those.
        let size_str = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| TrackerError::MalformedResponse("invalid chunk size hex"))?;
        data = &data[line_end + 2..];
        if size == 0 {
            break;
        }
        // `size` is whatever the tracker wrote: `size + 2` can overflow.
        if size.checked_add(2).is_none_or(|needed| data.len() < needed) {
            return Err(TrackerError::MalformedResponse("chunk body truncated"));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..]; // skip chunk data + trailing \r\n
    }
    Ok(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Performs an HTTP GET announce against `tracker_url` and parses the
/// bencoded response into an `AnnounceResponse`.
pub fn announce(tracker_url: &str, req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    let url = parse_http_url(tracker_url)?;
    let mut stream = TcpStream::connect((url.host.as_str(), url.port))?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    perform_request_and_parse(&mut stream, &url, req)
}

/// Sends the GET request and parses the response over any already-connected
/// `Read + Write` transport -- a bare `TcpStream` here, or a TLS-wrapped
/// stream in `tracker::https`. Both schemes speak identical HTTP/1.1 once
/// the transport is set up; only `parse_*_url` and the transport differ.
pub(crate) fn perform_request_and_parse<S: Read + Write>(stream: &mut S, url: &ParsedUrl, req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    let query = build_query(req);
    let separator = if url.path_and_query.contains('?') { "&" } else { "?" };
    let request = format!(
        "GET {}{}{} HTTP/1.1\r\nHost: {}\r\nUser-Agent: bittorrent-rs/0.1\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        url.path_and_query, separator, query, url.host
    );
    stream.write_all(request.as_bytes())?;

    let body = read_http_response_body(stream)?;
    parse_announce_body(&body)
}

fn parse_announce_body(body: &[u8]) -> Result<AnnounceResponse, TrackerError> {
    // Lenient: tracker responses are wire data from arbitrary
    // implementations; non-canonical key order shouldn't cost us the
    // whole peer list.
    let value = bencode::decode_lenient(body)?;
    let dict = value.as_dict().ok_or(TrackerError::MalformedResponse("response is not a dict"))?;

    if let Some(reason) = dict.get(b"failure reason".as_slice()).and_then(Bencode::as_str) {
        return Err(TrackerError::TrackerFailure(reason.to_string()));
    }

    let interval = value.get("interval").and_then(Bencode::as_int).ok_or(TrackerError::MalformedResponse("missing interval"))? as u32;
    let min_interval = value.get("min interval").and_then(Bencode::as_int).map(|v| v as u32);
    let complete = value.get("complete").and_then(Bencode::as_int).map(|v| v as u32);
    let incomplete = value.get("incomplete").and_then(Bencode::as_int).map(|v| v as u32);

    let mut peers: Vec<std::net::SocketAddr> = match value.get("peers") {
        Some(Bencode::Bytes(compact)) => parse_compact_peers(compact)?.into_iter().map(std::net::SocketAddr::V4).collect(),
        Some(Bencode::List(list)) => {
            // Non-compact fallback: list of {ip, port} dicts.
            list.iter()
                .filter_map(|p| {
                    let ip: std::net::Ipv4Addr = p.get("ip")?.as_str()?.parse().ok()?;
                    let port = p.get("port")?.as_int()? as u16;
                    Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
                })
                .collect()
        }
        _ => return Err(TrackerError::MalformedResponse("missing or malformed peers")),
    };

    // `peers6` (IPv6 compact peers) is optional and additive -- absence
    // isn't an error, it just means this tracker only returned IPv4 (or
    // the swarm has no IPv6 peers to offer right now).
    if let Some(Bencode::Bytes(compact_v6)) = value.get("peers6") {
        if let Ok(v6_peers) = super::parse_compact_peers_v6(compact_v6) {
            peers.extend(v6_peers);
        }
    }

    Ok(AnnounceResponse { interval, min_interval, complete, incomplete, peers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_url_with_explicit_port_and_path() {
        let u = parse_http_url("http://tracker.example.com:6969/announce").unwrap();
        assert_eq!(u.host, "tracker.example.com");
        assert_eq!(u.port, 6969);
        assert_eq!(u.path_and_query, "/announce");
    }

    #[test]
    fn parses_url_defaulting_to_port_80_and_root_path() {
        let u = parse_http_url("http://tracker.example.com").unwrap();
        assert_eq!(u.port, 80);
        assert_eq!(u.path_and_query, "/");
    }

    #[test]
    fn rejects_https_scheme() {
        assert!(matches!(parse_http_url("https://tracker.example.com/announce"), Err(TrackerError::UnsupportedScheme(_))));
    }

    #[test]
    fn build_query_contains_all_required_fields() {
        let req = AnnounceRequest {
            info_hash: [0xAA; 20],
            peer_id: [0xBB; 20],
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 1000,
            compact: true,
            event: Some(super::super::Event::Started),
            numwant: Some(50),
        };
        let q = build_query(&req);
        assert!(q.contains("info_hash=%AA%AA"));
        assert!(q.contains("peer_id=%BB%BB"));
        assert!(q.contains("port=6881"));
        assert!(q.contains("left=1000"));
        assert!(q.contains("compact=1"));
        assert!(q.contains("event=started"));
        assert!(q.contains("numwant=50"));
    }

    #[test]
    fn decodes_chunked_body() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let decoded = decode_chunked_body(raw).unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn parses_compact_announce_response() {
        let mut peers = Vec::new();
        peers.extend_from_slice(&[192, 168, 1, 1]);
        peers.extend_from_slice(&6881u16.to_be_bytes());
        let body = format!("d8:intervali1800e5:peers{}:", peers.len());
        let mut full = body.into_bytes();
        full.extend_from_slice(&peers);
        full.push(b'e');

        let resp = parse_announce_body(&full).unwrap();
        assert_eq!(resp.interval, 1800);
        assert_eq!(resp.peers.len(), 1);
    }

    #[test]
    fn surfaces_failure_reason() {
        let body = b"d14:failure reason17:torrent not founde";
        let err = parse_announce_body(body).unwrap_err();
        assert!(matches!(err, TrackerError::TrackerFailure(_)));
    }

    /// A stream that never ends and never stalls: a hostile or broken
    /// tracker that keeps sending.
    struct Endless;

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            buf.fill(b'a');
            Ok(buf.len())
        }
    }

    #[test]
    fn an_endless_response_is_cut_off_instead_of_filling_memory() {
        let started = std::time::Instant::now();
        let result = read_http_response_body(&mut Endless);
        assert!(matches!(result, Err(TrackerError::MalformedResponse("tracker response too large"))), "{:?}", result.err());
        assert!(started.elapsed() < Duration::from_secs(5), "and promptly, not after reading gigabytes");
    }

    #[test]
    fn a_large_but_reasonable_response_is_still_read_in_full() {
        let body = vec![b'x'; 1 << 20];
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        response.extend_from_slice(&body);
        assert_eq!(read_http_response_body(&mut response.as_slice()).unwrap().len(), 1 << 20);
    }

    #[test]
    fn a_chunk_size_that_overflows_is_an_error_not_a_panic() {
        // `size + 2` overflowed on these, and the slice after it then ran
        // off the end of the buffer.
        for size in ["ffffffffffffffff", "fffffffffffffffe", "fffffffffffffffd", "7fffffffffffffff", "8000000000000000"] {
            let response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{}\r\nabc\r\n0\r\n\r\n", size);
            let result = read_http_response_body(&mut response.as_bytes());
            assert!(matches!(result, Err(TrackerError::MalformedResponse(_))), "chunk size {}: {:?}", size, result.err());
        }
    }

    #[test]
    fn well_formed_chunks_still_decode() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(read_http_response_body(&mut response.as_slice()).unwrap(), b"abcde");
    }
}
