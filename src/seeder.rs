//! Upload side: accept inbound peer connections and serve verified
//! pieces off disk. Runs concurrently with a download (serving whatever
//! is verified so far) and standalone after completion (`--seed`).
//!
//! A peer is told of every piece verified after it connected, with `Have`.
//!
//! Policy is deliberately simple for a from-scratch client: every
//! interested peer gets unchoked, bounded by a global inbound-connection
//! cap, with no tit-for-tat rate measurement. Real tit-for-tat exists to
//! allocate *scarce* upload slots among competing leechers; a cap on
//! concurrent connections bounds the same resource honestly without the
//! choke-round machinery (README documents this as a known
//! simplification).

use crate::downloader::file_writer::{read_block, FileSpan};
use crate::peer::handshake::{Handshake, HANDSHAKE_LEN};
use crate::peer::message::Message;
use crate::peer::state::PeerState;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::sync;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// Largest `Request.length` honored. BEP 3 clients conventionally use
/// 16 KiB; anything above 128 KiB is either a very old client or an
/// attempt to make us allocate absurd buffers -- those get the
/// connection dropped, matching mainline behavior.
const MAX_REQUEST_LEN: u32 = 128 * 1024;
/// Concurrent inbound peers served at once; connections beyond this are
/// accepted-and-closed immediately so the backlog doesn't grow unbounded.
const MAX_INBOUND_PEERS: usize = 40;
/// An inbound peer silent for this long gets dropped.
const IDLE_DISCONNECT: Duration = Duration::from_secs(300);
/// Send a keep-alive if we've written nothing for this long (BEP 3
/// suggests 2 minutes).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(110);
/// Per-read socket timeout inside the serve loop -- also the granularity
/// at which shutdown, idle and new-piece checks run, so it is how long a
/// peer waits to hear that a piece has been verified.
const SERVE_READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Thread-safe record of which pieces are verified on disk -- written by
/// download workers/resume as pieces complete, read by the seeder to
/// build bitfields and validate requests.
pub struct HaveMap {
    bits: RwLock<Vec<bool>>,
    /// Bumped whenever a piece is added, so a connection can tell cheaply
    /// whether there is anything new to announce.
    version: AtomicU64,
}

impl HaveMap {
    pub fn new(total_pieces: usize) -> Self {
        HaveMap { bits: RwLock::new(vec![false; total_pieces]), version: AtomicU64::new(0) }
    }

    pub fn set(&self, index: u32) {
        if let Some(b) = sync::write(&self.bits).get_mut(index as usize) {
            if !*b {
                *b = true;
                self.version.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// Changes each time a piece is added (and never otherwise).
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    pub fn get(&self, index: u32) -> bool {
        sync::read(&self.bits).get(index as usize).copied().unwrap_or(false)
    }

    pub fn snapshot(&self) -> Vec<bool> {
        sync::read(&self.bits).clone()
    }

    pub fn count(&self) -> usize {
        sync::read(&self.bits).iter().filter(|&&x| x).count()
    }
}

/// Everything the serve loop needs, shared across all inbound-peer threads.
struct SeederShared {
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
    spans: Arc<Vec<FileSpan>>,
    piece_length: u64,
    total_length: u64,
    have: Arc<HaveMap>,
    /// Shared limit on the bytes uploaded across every peer (`--max-up`).
    up_limit: Option<Arc<crate::ratelimit::RateLimiter>>,
    running: Arc<AtomicBool>,
    uploaded: Arc<AtomicU64>,
    active_conns: AtomicUsize,
}

impl SeederShared {
    /// Actual byte length of `piece_index` (the final piece is usually
    /// shorter than `piece_length`).
    fn piece_len(&self, piece_index: u32) -> u64 {
        let start = piece_index as u64 * self.piece_length;
        self.piece_length.min(self.total_length.saturating_sub(start))
    }
}

/// Handle to a running seeder. Dropping it does NOT stop the seeder;
/// call `stop()` (idempotent) or flip the shared `running` flag.
pub struct SeederHandle {
    /// The port actually bound -- differs from the requested port if that
    /// was taken and the seeder fell back to an ephemeral one. This is
    /// the port to put in tracker announces.
    pub port: u16,
    pub uploaded: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    accept_thread: Option<thread::JoinHandle<()>>,
}

impl SeederHandle {
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(h) = self.accept_thread.take() {
            let _ = h.join();
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    preferred_port: u16,
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
    spans: Arc<Vec<FileSpan>>,
    piece_length: u64,
    total_length: u64,
    have: Arc<HaveMap>,
    up_limit: Option<Arc<crate::ratelimit::RateLimiter>>,
) -> std::io::Result<SeederHandle> {
    // Preferred port first (conventionally 6881), ephemeral fallback --
    // another client on the same machine owning 6881 shouldn't stop this
    // one from seeding at all.
    let listener = TcpListener::bind(("0.0.0.0", preferred_port)).or_else(|_| TcpListener::bind(("0.0.0.0", 0)))?;
    let port = listener.local_addr()?.port();
    listener.set_nonblocking(true)?;

    let running = Arc::new(AtomicBool::new(true));
    let uploaded = Arc::new(AtomicU64::new(0));
    let shared = Arc::new(SeederShared {
        info_hash,
        our_peer_id,
        spans,
        piece_length,
        total_length,
        have,
        up_limit,
        running: Arc::clone(&running),
        uploaded: Arc::clone(&uploaded),
        active_conns: AtomicUsize::new(0),
    });

    let accept_shared = Arc::clone(&shared);
    let accept_thread = thread::spawn(move || {
        while accept_shared.running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    if accept_shared.active_conns.load(Ordering::SeqCst) >= MAX_INBOUND_PEERS {
                        drop(stream); // over cap: close immediately
                        continue;
                    }
                    accept_shared.active_conns.fetch_add(1, Ordering::SeqCst);
                    let conn_shared = Arc::clone(&accept_shared);
                    thread::spawn(move || {
                        let _ = serve_peer(stream, &conn_shared);
                        conn_shared.active_conns.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(_) => thread::sleep(Duration::from_millis(200)), // transient accept failure; keep listening
            }
        }
    });

    Ok(SeederHandle { port, uploaded, running, accept_thread: Some(accept_thread) })
}

/// Serves one inbound peer: handshake, bitfield, then Request/Piece until
/// the peer leaves, goes idle too long, or the seeder shuts down.
fn serve_peer(mut stream: TcpStream, shared: &SeederShared) -> std::io::Result<()> {
    stream.set_read_timeout(Some(SERVE_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Inbound side of the BEP 3 handshake: they send first, we validate
    // the info_hash and answer. A mismatch (peer wants a torrent this
    // seeder isn't serving) just closes the connection.
    let mut hs_buf = [0u8; HANDSHAKE_LEN];
    stream.read_exact(&mut hs_buf)?;
    let their_hs = Handshake::from_bytes(&hs_buf).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed inbound handshake"))?;
    if their_hs.info_hash != shared.info_hash {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "inbound handshake for a different info_hash"));
    }
    // No extension support advertised on the upload path: this loop
    // serves piece requests only, so inviting extended messages would
    // just be traffic to ignore.
    let ours = Handshake::new(shared.info_hash, shared.our_peer_id, false);
    stream.write_all(&ours.to_bytes())?;

    // What we can serve right now, honest at connect time as BEP 3
    // requires. Pieces verified afterwards are announced with `Have` as
    // they appear (see `announce_new_pieces`). The version is read first:
    // a piece added between the two reads then shows up as a difference
    // to announce, never as one that is missed.
    let mut seen_version = shared.have.version();
    let mut advertised = shared.have.snapshot();
    Message::Bitfield(PeerState::encode_bitfield(&advertised)).write_to(&mut stream).map_err(wire_to_io)?;

    let mut peer_unchoked = false;
    let mut last_heard = Instant::now();
    let mut last_sent = Instant::now();

    loop {
        if !shared.running.load(Ordering::SeqCst) {
            return Ok(()); // seeder shutting down
        }
        if last_heard.elapsed() >= IDLE_DISCONNECT {
            return Ok(()); // peer wandered off
        }
        if last_sent.elapsed() >= KEEPALIVE_INTERVAL {
            Message::KeepAlive.write_to(&mut stream).map_err(wire_to_io)?;
            last_sent = Instant::now();
        }

        if announce_new_pieces(&mut stream, &shared.have, &mut seen_version, &mut advertised)? {
            last_sent = Instant::now();
        }

        let msg = match Message::read_from(&mut stream) {
            Ok(m) => m,
            Err(crate::peer::message::WireError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                continue; // quiet interval; loop re-checks shutdown/idle
            }
            Err(crate::peer::message::WireError::Io(e)) => return Err(e),
            Err(_) => return Ok(()), // protocol garbage; drop quietly
        };
        last_heard = Instant::now();

        match msg {
            Message::Interested => {
                if !peer_unchoked {
                    Message::Unchoke.write_to(&mut stream).map_err(wire_to_io)?;
                    peer_unchoked = true;
                    last_sent = Instant::now();
                }
            }
            Message::NotInterested => {
                // Leave them unchoked; they'll either re-request or idle out.
            }
            Message::Request { index, begin, length } => {
                if !peer_unchoked {
                    continue; // BEP 3: requests while choked are ignored
                }
                if length > MAX_REQUEST_LEN {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "oversized block request"));
                }
                let piece_len = shared.piece_len(index);
                let in_bounds = shared.have.get(index) && (begin as u64).saturating_add(length as u64) <= piece_len;
                if !in_bounds {
                    continue; // request for data we don't have / can't have; ignore
                }
                let block = read_block(&shared.spans, index, shared.piece_length, begin, length)?;
                if let Some(limit) = &shared.up_limit {
                    limit.acquire(length as usize);
                }
                Message::Piece { index, begin, block }.write_to(&mut stream).map_err(wire_to_io)?;
                shared.uploaded.fetch_add(length as u64, Ordering::Relaxed);
                last_sent = Instant::now();
            }
            // Piece-availability chatter from a fellow leecher; a pure
            // serve loop has no use for it. Cancel is inherently
            // best-effort (we serve synchronously, so there's never a
            // queued request to cancel). Choke/Unchoke describe *their*
            // upload policy toward us -- irrelevant, we request nothing.
            Message::Have { .. } | Message::Bitfield(_) | Message::Cancel { .. } | Message::Choke | Message::Unchoke | Message::KeepAlive | Message::Piece { .. } | Message::Port(_) | Message::Extended { .. } => {}
        }
    }
}

/// Tells a connected peer about pieces verified since it was last told: a
/// `Have` for each. Without this a peer that connected early would never
/// learn of what this client downloads afterwards, and a client that is
/// still downloading would be a poor source. Returns whether it sent any.
fn announce_new_pieces(stream: &mut TcpStream, have: &HaveMap, seen_version: &mut u64, advertised: &mut [bool]) -> std::io::Result<bool> {
    let version = have.version();
    if version == *seen_version {
        return Ok(false);
    }
    *seen_version = version;
    let now = have.snapshot();
    let mut sent = false;
    for (index, (&has, told)) in now.iter().zip(advertised.iter_mut()).enumerate() {
        if has && !*told {
            Message::Have { piece_index: index as u32 }.write_to(stream).map_err(wire_to_io)?;
            *told = true;
            sent = true;
        }
    }
    Ok(sent)
}

fn wire_to_io(e: crate::peer::message::WireError) -> std::io::Error {
    match e {
        crate::peer::message::WireError::Io(io) => io,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::file_writer::{build_file_spans, write_piece};
    use std::fs;
    use std::net::SocketAddr;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-seeder-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Minimal leecher: handshake + read bitfield, returns the stream.
    fn leech_connect(port: u16, info_hash: [u8; 20]) -> (TcpStream, Vec<bool>) {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let hs = Handshake::new(info_hash, [0x21; 20], false);
        stream.write_all(&hs.to_bytes()).unwrap();
        let mut buf = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut buf).unwrap();
        let theirs = Handshake::from_bytes(&buf).unwrap();
        assert_eq!(theirs.info_hash, info_hash);
        let bitfield = loop {
            match Message::read_from(&mut stream).unwrap() {
                Message::Bitfield(bits) => {
                    let mut scratch = PeerState::new();
                    scratch.apply_message(&Message::Bitfield(bits));
                    break scratch.peer_has_pieces;
                }
                _ => continue,
            }
        };
        (stream, bitfield)
    }

    fn start_test_seeder(dir: &std::path::Path, pieces: &[Vec<u8>], piece_length: u64, have_indices: &[u32]) -> (SeederHandle, [u8; 20]) {
        start_limited_seeder(dir, pieces, piece_length, have_indices, None)
    }

    fn start_limited_seeder(dir: &std::path::Path, pieces: &[Vec<u8>], piece_length: u64, have_indices: &[u32], up_limit: Option<Arc<crate::ratelimit::RateLimiter>>) -> (SeederHandle, [u8; 20]) {
        let (handle, info_hash, _have) = start_seeder_with_map(dir, pieces, piece_length, have_indices, up_limit);
        (handle, info_hash)
    }

    /// A seeder that also gives back its have-map, for tests that verify
    /// more pieces after peers have connected.
    fn start_seeder_with_map(dir: &std::path::Path, pieces: &[Vec<u8>], piece_length: u64, have_indices: &[u32], up_limit: Option<Arc<crate::ratelimit::RateLimiter>>) -> (SeederHandle, [u8; 20], Arc<HaveMap>) {
        let total: i64 = pieces.iter().map(|p| p.len() as i64).sum();
        let files = vec![(vec!["seed.bin".to_string()], total)];
        let spans = Arc::new(build_file_spans(dir, &files));
        for (i, p) in pieces.iter().enumerate() {
            write_piece(&spans, i as u32, piece_length, p).unwrap();
        }
        let have = Arc::new(HaveMap::new(pieces.len()));
        for &i in have_indices {
            have.set(i);
        }
        let info_hash = [0x66; 20];
        let handle = start(0, info_hash, [0x20; 20], spans, piece_length, total as u64, Arc::clone(&have), up_limit).unwrap();
        (handle, info_hash, have)
    }

    /// The next `Have` the peer sends, skipping anything else; `None` if
    /// nothing arrives within the stream's read timeout.
    fn next_have(stream: &mut TcpStream) -> Option<u32> {
        loop {
            match Message::read_from(stream) {
                Ok(Message::Have { piece_index }) => return Some(piece_index),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    }

    fn three_pieces() -> Vec<Vec<u8>> {
        (0..3u8).map(|i| vec![i + 1; 16384]).collect()
    }

    #[test]
    fn a_piece_verified_after_a_peer_connected_is_announced_to_it() {
        let dir = tmp_dir("have-broadcast");
        let (mut handle, info_hash, have) = start_seeder_with_map(&dir, &three_pieces(), 16384, &[0], None);
        let (mut stream, bitfield) = leech_connect(handle.port, info_hash);
        assert_eq!(&bitfield[..3], &[true, false, false], "the bitfield was honest at connect time");

        have.set(1);

        assert_eq!(next_have(&mut stream), Some(1), "the peer hears about the new piece without asking");
        handle.stop();
    }

    #[test]
    fn each_new_piece_is_announced_once_and_only_the_new_one() {
        let dir = tmp_dir("have-once");
        let (mut handle, info_hash, have) = start_seeder_with_map(&dir, &three_pieces(), 16384, &[0], None);
        let (mut stream, _) = leech_connect(handle.port, info_hash);

        have.set(1);
        assert_eq!(next_have(&mut stream), Some(1));
        have.set(2);
        assert_eq!(next_have(&mut stream), Some(2), "the second announcement is for piece 2, not piece 1 again");

        // Setting what is already set changes nothing, so nothing is sent.
        stream.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
        have.set(1);
        have.set(0);
        assert_eq!(next_have(&mut stream), None, "nothing new, nothing announced");
        handle.stop();
    }

    #[test]
    fn a_peer_that_connects_later_learns_of_the_piece_from_its_bitfield_not_a_have() {
        let dir = tmp_dir("have-late");
        let (mut handle, info_hash, have) = start_seeder_with_map(&dir, &three_pieces(), 16384, &[0], None);
        have.set(1);

        let (mut stream, bitfield) = leech_connect(handle.port, info_hash);

        assert_eq!(&bitfield[..3], &[true, true, false]);
        stream.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
        assert_eq!(next_have(&mut stream), None, "already in the bitfield, so not announced again");
        handle.stop();
    }

    #[test]
    fn the_have_map_changes_version_only_when_a_piece_is_added() {
        let have = HaveMap::new(4);
        let v0 = have.version();
        have.set(2);
        let v1 = have.version();
        assert_ne!(v0, v1, "a new piece");
        have.set(2);
        assert_eq!(have.version(), v1, "the same piece again");
        have.set(99);
        assert_eq!(have.version(), v1, "a piece the torrent does not have");
        have.set(3);
        assert_ne!(have.version(), v1);
    }

    #[test]
    fn serves_a_block_to_an_interested_leecher_and_counts_upload() {
        let dir = tmp_dir("serve");
        let piece = vec![0xABu8; 16384];
        let (mut handle, info_hash) = start_test_seeder(&dir, std::slice::from_ref(&piece), 16384, &[0]);

        let (mut stream, bitfield) = leech_connect(handle.port, info_hash);
        assert!(bitfield[0], "seeder must advertise the piece it has");

        Message::Interested.write_to(&mut stream).unwrap();
        loop {
            match Message::read_from(&mut stream).unwrap() {
                Message::Unchoke => break,
                _ => continue,
            }
        }
        Message::Request { index: 0, begin: 4096, length: 8192 }.write_to(&mut stream).unwrap();
        let block = loop {
            match Message::read_from(&mut stream).unwrap() {
                Message::Piece { index: 0, begin: 4096, block } => break block,
                _ => continue,
            }
        };
        assert_eq!(block, vec![0xABu8; 8192]);
        assert_eq!(handle.uploaded.load(Ordering::Relaxed), 8192);
        handle.stop();
    }

    #[test]
    fn ignores_requests_while_choked_and_for_missing_pieces() {
        let dir = tmp_dir("choked");
        let p0 = vec![0x01u8; 8192];
        let p1 = vec![0x02u8; 8192];
        // Seeder has piece 0 verified but NOT piece 1.
        let (mut handle, info_hash) = start_test_seeder(&dir, &[p0.clone(), p1], 8192, &[0]);

        let (mut stream, bitfield) = leech_connect(handle.port, info_hash);
        assert!(bitfield[0]);
        assert!(!bitfield[1]);

        // Request before Interested/Unchoke: must be ignored (no Piece back).
        Message::Request { index: 0, begin: 0, length: 1024 }.write_to(&mut stream).unwrap();

        Message::Interested.write_to(&mut stream).unwrap();
        loop {
            match Message::read_from(&mut stream).unwrap() {
                Message::Unchoke => break,
                Message::Piece { .. } => panic!("served a request sent while choked"),
                _ => continue,
            }
        }
        // Request for the piece the seeder doesn't have: ignored too.
        Message::Request { index: 1, begin: 0, length: 1024 }.write_to(&mut stream).unwrap();
        // Then a valid one -- proves the loop survived both ignores.
        Message::Request { index: 0, begin: 0, length: 1024 }.write_to(&mut stream).unwrap();
        let (idx, block) = loop {
            match Message::read_from(&mut stream).unwrap() {
                Message::Piece { index, begin: 0, block } => break (index, block),
                _ => continue,
            }
        };
        assert_eq!(idx, 0, "only the valid request may be served");
        assert_eq!(block, vec![0x01u8; 1024]);
        handle.stop();
    }

    #[test]
    fn drops_connection_on_wrong_info_hash() {
        let dir = tmp_dir("wrong-hash");
        let piece = vec![0x0Fu8; 1024];
        let (mut handle, _info_hash) = start_test_seeder(&dir, &[piece], 1024, &[0]);

        let addr: SocketAddr = format!("127.0.0.1:{}", handle.port).parse().unwrap();
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let hs = Handshake::new([0xDE; 20], [0x21; 20], false); // not the seeded torrent
        stream.write_all(&hs.to_bytes()).unwrap();
        // Seeder must close without answering; the read eventually fails
        // (EOF) rather than yielding a handshake.
        let mut buf = [0u8; HANDSHAKE_LEN];
        assert!(stream.read_exact(&mut buf).is_err());
        handle.stop();
    }

    #[test]
    fn have_map_set_get_count() {
        let have = HaveMap::new(4);
        assert_eq!(have.count(), 0);
        have.set(1);
        have.set(3);
        have.set(99); // out of range: ignored, no panic
        assert!(have.get(1));
        assert!(!have.get(0));
        assert!(!have.get(99));
        assert_eq!(have.count(), 2);
        assert_eq!(have.snapshot(), vec![false, true, false, true]);
    }

    #[test]
    fn a_thread_panicking_with_the_have_map_locked_does_not_freeze_it() {
        let have = HaveMap::new(4);
        have.set(1);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = have.bits.write().unwrap();
            panic!("a worker died holding the have-map's write lock");
        }));
        assert!(have.bits.is_poisoned(), "the setup must really poison it");

        // A piece verified after the panic must still be advertised to peers.
        have.set(2);
        assert!(have.get(1) && have.get(2) && !have.get(0));
        assert_eq!(have.count(), 2);
        assert_eq!(have.snapshot(), vec![false, true, true, false]);
    }

    #[test]
    fn an_upload_limit_slows_what_a_leecher_receives_but_not_its_correctness() {
        // Two 16 KiB blocks at 20,000 B/s: the first fits the burst, the
        // second waits out the rest.
        let dir = tmp_dir("limited");
        let pieces = vec![vec![0x11u8; 16384], vec![0x22u8; 16384]];
        let limiter = Arc::new(crate::ratelimit::RateLimiter::new(20_000));
        let (mut handle, info_hash) = start_limited_seeder(&dir, &pieces, 16384, &[0, 1], Some(limiter));
        let (mut stream, _) = leech_connect(handle.port, info_hash);
        Message::Interested.write_to(&mut stream).unwrap();
        while !matches!(Message::read_from(&mut stream).unwrap(), Message::Unchoke) {}

        let started = std::time::Instant::now();
        for (i, piece) in pieces.iter().enumerate() {
            Message::Request { index: i as u32, begin: 0, length: 16384 }.write_to(&mut stream).unwrap();
            let block = loop {
                if let Message::Piece { block, .. } = Message::read_from(&mut stream).unwrap() {
                    break block;
                }
            };
            assert_eq!(&block, piece);
        }

        assert!(started.elapsed() >= Duration::from_millis(500), "32 KiB at 20,000 B/s cannot take {:?}", started.elapsed());
        handle.stop();
    }
}
