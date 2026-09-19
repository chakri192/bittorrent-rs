//! UDP tracker protocol (BEP 15). Two round trips: `connect` (obtain a
//! connection_id, valid ~60s) then `announce` (info_hash, peer_id, byte
//! counters -> compact peer list). No external UDP/torrent crate; this is
//! `std::net::UdpSocket` and manual big-endian packing.

use super::{parse_compact_peers, AnnounceRequest, AnnounceResponse, Event, TrackerError};
use crate::bytes::{be_u32, be_u64};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Magic constant from BEP 15 that identifies this as a v1 tracker protocol
/// packet (distinguishes it from arbitrary UDP traffic on the same port).
const PROTOCOL_ID: u64 = 0x0000_0417_2710_1980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const ACTION_ERROR: u32 = 3;

fn build_connect_request(transaction_id: u32) -> [u8; 16] {
    let mut pkt = [0u8; 16];
    pkt[0..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    pkt[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    pkt[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    pkt
}

/// A big-endian `u32` field of a tracker response.
fn field_u32(resp: &[u8], at: usize) -> Result<u32, TrackerError> {
    be_u32(resp, at).ok_or(TrackerError::MalformedResponse("response too short for its fields"))
}

/// Returns `connection_id` on success.
fn parse_connect_response(resp: &[u8], expected_txn: u32) -> Result<u64, TrackerError> {
    if resp.len() < 16 {
        return Err(TrackerError::MalformedResponse("connect response too short"));
    }
    let action = field_u32(resp, 0)?;
    let txn = field_u32(resp, 4)?;
    if txn != expected_txn {
        return Err(TrackerError::MalformedResponse("connect response transaction_id mismatch"));
    }
    if action == ACTION_ERROR {
        let msg = String::from_utf8_lossy(&resp[8..]).to_string();
        return Err(TrackerError::TrackerFailure(msg));
    }
    if action != ACTION_CONNECT {
        return Err(TrackerError::MalformedResponse("unexpected action in connect response"));
    }
    be_u64(resp, 8).ok_or(TrackerError::MalformedResponse("connect response too short"))
}

fn event_code(event: Option<Event>) -> u32 {
    match event {
        None => 0,
        Some(Event::Completed) => 1,
        Some(Event::Started) => 2,
        Some(Event::Stopped) => 3,
    }
}

/// Builds the 98-byte IPv4 announce packet body (everything after the
/// 16-byte connect handshake is a fixed-layout struct per BEP 15).
fn build_announce_request(connection_id: u64, transaction_id: u32, req: &AnnounceRequest) -> [u8; 98] {
    let mut pkt = [0u8; 98];
    pkt[0..8].copy_from_slice(&connection_id.to_be_bytes());
    pkt[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    pkt[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    pkt[16..36].copy_from_slice(&req.info_hash);
    pkt[36..56].copy_from_slice(&req.peer_id);
    pkt[56..64].copy_from_slice(&req.downloaded.to_be_bytes());
    pkt[64..72].copy_from_slice(&req.left.to_be_bytes());
    pkt[72..80].copy_from_slice(&req.uploaded.to_be_bytes());
    pkt[80..84].copy_from_slice(&event_code(req.event).to_be_bytes());
    pkt[84..88].copy_from_slice(&0u32.to_be_bytes()); // ip_address: 0 = tracker infers it
    pkt[88..92].copy_from_slice(&0u32.to_be_bytes()); // key: unused, 0 is valid
    let numwant = req.numwant.map(|n| n as i32).unwrap_or(-1); // -1 = default
    pkt[92..96].copy_from_slice(&numwant.to_be_bytes());
    pkt[96..98].copy_from_slice(&req.port.to_be_bytes());
    pkt
}

fn parse_announce_response(resp: &[u8], expected_txn: u32) -> Result<AnnounceResponse, TrackerError> {
    if resp.len() < 20 {
        return Err(TrackerError::MalformedResponse("announce response too short"));
    }
    let action = field_u32(resp, 0)?;
    let txn = field_u32(resp, 4)?;
    if txn != expected_txn {
        return Err(TrackerError::MalformedResponse("announce response transaction_id mismatch"));
    }
    if action == ACTION_ERROR {
        let msg = String::from_utf8_lossy(&resp[8..]).to_string();
        return Err(TrackerError::TrackerFailure(msg));
    }
    if action != ACTION_ANNOUNCE {
        return Err(TrackerError::MalformedResponse("unexpected action in announce response"));
    }
    let interval = field_u32(resp, 8)?;
    let incomplete = field_u32(resp, 12)?;
    let complete = field_u32(resp, 16)?;
    // BEP 15 (UDP tracker) is IPv4-only in this client -- see the doc
    // comment on `parse_compact_peers_v6` for why IPv6 UDP (BEP 32) isn't
    // implemented. `.map(SocketAddr::V4)` just widens the type to match
    // `AnnounceResponse::peers`, which HTTP trackers can also populate
    // with real IPv6 entries.
    let peers = parse_compact_peers(&resp[20..])?.into_iter().map(std::net::SocketAddr::V4).collect();

    Ok(AnnounceResponse {
        interval,
        min_interval: None,
        complete: Some(complete),
        incomplete: Some(incomplete),
        peers,
    })
}

/// Sends `packet`, retrying with BEP 15's exponential backoff
/// (`15 * 2^n` seconds, n = 0..=8) until a response arrives or all
/// retries are exhausted. Returns the raw response bytes.
fn send_with_retries(sock: &UdpSocket, packet: &[u8], max_retries: u32) -> Result<Vec<u8>, TrackerError> {
    let mut buf = [0u8; 4096];
    for n in 0..=max_retries {
        sock.send(packet)?;
        let timeout = Duration::from_secs(15 * (1u64 << n));
        sock.set_read_timeout(Some(timeout))?;
        match sock.recv(&mut buf) {
            Ok(len) => return Ok(buf[..len].to_vec()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(TrackerError::Io(e)),
        }
    }
    Err(TrackerError::Timeout)
}

/// Performs the full connect+announce exchange against `tracker_addr`
/// (host:port, no scheme -- e.g. "tracker.example.com:6969").
pub fn announce(tracker_addr: &str, req: &AnnounceRequest) -> Result<AnnounceResponse, TrackerError> {
    let addr: SocketAddr = tracker_addr
        .to_socket_addrs()
        .map_err(|e| TrackerError::BadUrl(format!("{}: DNS resolution failed ({})", tracker_addr, e)))?
        .next()
        .ok_or_else(|| TrackerError::BadUrl(format!("{}: hostname resolved to zero addresses", tracker_addr)))?;

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(addr)?;

    let connect_txn = generate_transaction_id();
    let connect_pkt = build_connect_request(connect_txn);
    // BEP 15 caps retries at n=8 (15 * 2^8 ~= 64 min) before giving up;
    // we use a smaller ceiling suitable for an interactive client.
    let connect_resp = send_with_retries(&sock, &connect_pkt, 4)?;
    let connection_id = parse_connect_response(&connect_resp, connect_txn)?;

    let announce_txn = generate_transaction_id();
    let announce_pkt = build_announce_request(connection_id, announce_txn, req);
    let announce_resp = send_with_retries(&sock, &announce_pkt, 4)?;
    parse_announce_response(&announce_resp, announce_txn)
}

fn generate_transaction_id() -> u32 {
    // For connectionless UDP, the transaction id is the primary defense
    // against off-path response spoofing, so it must be unpredictable. The
    // socket's connect() already filters by source address, but a guessable
    // id would weaken that. Use the OS CSPRNG; fall back to a time-seeded
    // value only if the RNG is somehow unavailable, rather than aborting the
    // announce outright.
    let mut buf = [0u8; 4];
    if getrandom::getrandom(&mut buf).is_ok() {
        return u32::from_be_bytes(buf);
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0x1234_5678)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_has_protocol_id_and_action_and_txn() {
        let pkt = build_connect_request(0xDEADBEEF);
        assert_eq!(&pkt[0..8], &PROTOCOL_ID.to_be_bytes());
        assert_eq!(u32::from_be_bytes(pkt[8..12].try_into().unwrap()), ACTION_CONNECT);
        assert_eq!(u32::from_be_bytes(pkt[12..16].try_into().unwrap()), 0xDEADBEEFu32);
    }

    #[test]
    fn parses_valid_connect_response() {
        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
        resp[4..8].copy_from_slice(&42u32.to_be_bytes());
        resp[8..16].copy_from_slice(&0x0102030405060708u64.to_be_bytes());
        let cid = parse_connect_response(&resp, 42).unwrap();
        assert_eq!(cid, 0x0102030405060708);
    }

    #[test]
    fn rejects_connect_response_with_wrong_transaction_id() {
        let mut resp = [0u8; 16];
        resp[0..4].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
        resp[4..8].copy_from_slice(&42u32.to_be_bytes());
        assert!(matches!(parse_connect_response(&resp, 99), Err(TrackerError::MalformedResponse(_))));
    }

    #[test]
    fn connect_error_response_surfaces_message() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&ACTION_ERROR.to_be_bytes());
        resp.extend_from_slice(&7u32.to_be_bytes());
        resp.extend_from_slice(b"bad request");
        let err = parse_connect_response(&resp, 7).unwrap_err();
        assert!(matches!(err, TrackerError::TrackerFailure(_)));
    }

    #[test]
    fn announce_request_is_98_bytes_with_correct_layout() {
        let req = AnnounceRequest {
            info_hash: [0x11; 20],
            peer_id: [0x22; 20],
            port: 6881,
            uploaded: 111,
            downloaded: 222,
            left: 333,
            compact: true,
            event: Some(Event::Started),
            numwant: Some(50),
        };
        let pkt = build_announce_request(0xAABBCCDDu64, 7, &req);
        assert_eq!(pkt.len(), 98);
        assert_eq!(u64::from_be_bytes(pkt[0..8].try_into().unwrap()), 0xAABBCCDD);
        assert_eq!(u32::from_be_bytes(pkt[8..12].try_into().unwrap()), ACTION_ANNOUNCE);
        assert_eq!(&pkt[16..36], &[0x11; 20]);
        assert_eq!(&pkt[36..56], &[0x22; 20]);
        assert_eq!(u64::from_be_bytes(pkt[56..64].try_into().unwrap()), 222); // downloaded
        assert_eq!(u64::from_be_bytes(pkt[64..72].try_into().unwrap()), 333); // left
        assert_eq!(u64::from_be_bytes(pkt[72..80].try_into().unwrap()), 111); // uploaded
        assert_eq!(u32::from_be_bytes(pkt[80..84].try_into().unwrap()), 2); // event=started
        assert_eq!(i32::from_be_bytes(pkt[92..96].try_into().unwrap()), 50); // numwant
        assert_eq!(u16::from_be_bytes(pkt[96..98].try_into().unwrap()), 6881);
    }

    #[test]
    fn numwant_none_encodes_as_negative_one() {
        let req = AnnounceRequest {
            info_hash: [0; 20],
            peer_id: [0; 20],
            port: 1,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            compact: true,
            event: None,
            numwant: None,
        };
        let pkt = build_announce_request(1, 1, &req);
        assert_eq!(i32::from_be_bytes(pkt[92..96].try_into().unwrap()), -1);
    }

    #[test]
    fn parses_valid_announce_response_with_two_peers() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
        resp.extend_from_slice(&5u32.to_be_bytes()); // txn
        resp.extend_from_slice(&1800u32.to_be_bytes()); // interval
        resp.extend_from_slice(&3u32.to_be_bytes()); // leechers
        resp.extend_from_slice(&7u32.to_be_bytes()); // seeders
        resp.extend_from_slice(&[192, 168, 0, 1]);
        resp.extend_from_slice(&6881u16.to_be_bytes());
        resp.extend_from_slice(&[10, 0, 0, 1]);
        resp.extend_from_slice(&6882u16.to_be_bytes());

        let parsed = parse_announce_response(&resp, 5).unwrap();
        assert_eq!(parsed.interval, 1800);
        assert_eq!(parsed.incomplete, Some(3));
        assert_eq!(parsed.complete, Some(7));
        assert_eq!(parsed.peers.len(), 2);
    }
}
