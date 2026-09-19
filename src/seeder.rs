//! Upload side: accept inbound peer connections and serve verified
//! pieces off disk. Runs concurrently with a download (serving whatever
//! is verified so far) and standalone after completion (`--seed`).
//!
//! A peer is told of every piece verified after it connected, with `Have`.
//!
//! Who is served is decided by [`crate::choker`]: a few unchoke slots,
//! most to the peers taking the most from us and one rotating optimistic
//! slot, re-decided every [`RECHOKE_INTERVAL`]. Everyone else is choked and
//! their requests ignored. (Only the seeding half of tit-for-tat: inbound
//! peers are never downloaded from, so there is no reciprocation to reward.)
//!
//! What follows is the older description of the policy, kept for its
//! reasoning about the connection cap.
//!
//! Policy is deliberately simple for a from-scratch client: every
//! interested peer gets unchoked, bounded by a global inbound-connection
//! cap, with no tit-for-tat rate measurement. Real tit-for-tat exists to
//! allocate *scarce* upload slots among competing leechers; a cap on
//! concurrent connections bounds the same resource honestly without the
//! choke-round machinery (README documents this as a known
//! simplification).

use crate::choker::{Choker, DEFAULT_SLOTS};
use crate::downloader::file_writer::{read_block, FileSpan};
use crate::metadata::{MetadataMessage, METADATA_PIECE_SIZE};
use crate::peer::extension::{ExtendedHandshake, EXTENDED_HANDSHAKE_ID};
use crate::peer::handshake::{Handshake, HANDSHAKE_LEN};
use crate::peer::message::Message;
use crate::peer::state::PeerState;
use crate::peer::fast::allowed_fast_set;
use crate::peer::mse::MseStream;
use crate::peer::PeerStream;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::sync;
use crate::sync::lock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
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
/// The id peers send `ut_metadata` requests to us under.
const SEEDER_UT_METADATA_ID: u8 = 1;
/// How many pieces a peer using the Fast Extension may request while choked.
const ALLOWED_FAST_PIECES: usize = 5;
/// How often the choice of who to unchoke is made again.
pub const RECHOKE_INTERVAL: Duration = Duration::from_secs(10);
/// An inbound peer silent for this long gets dropped.
const IDLE_DISCONNECT: Duration = Duration::from_secs(300);
/// Send a keep-alive if we've written nothing for this long (BEP 3
/// suggests 2 minutes).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(110);
/// How long a peer has to send its handshake after connecting. Far longer
/// than [`SERVE_READ_TIMEOUT`]: a peer on a slow or distant link may take
/// seconds, and that is no reason to drop it.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
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

    /// How many pieces the torrent has, verified or not.
    pub fn total(&self) -> usize {
        sync::read(&self.bits).len()
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
    /// Cleared when this torrent stops being served.
    running: Arc<AtomicBool>,
    uploaded: Arc<AtomicU64>,
    /// Who is unchoked.
    choker: Arc<Choker>,
    /// The info dictionary, for peers that ask for it.
    metadata: Option<Arc<Vec<u8>>>,
    piece_lengths: Option<Arc<Vec<u32>>>,
}

impl SeederShared {
    /// Actual byte length of `piece_index` (the final piece is usually
    /// shorter than `piece_length`).
    fn piece_len(&self, piece_index: u32) -> u64 {
        // In a v2 torrent every file's last piece is short.
        if let Some(lengths) = &self.piece_lengths {
            return lengths.get(piece_index as usize).map_or(0, |&length| u64::from(length));
        }
        let start = piece_index as u64 * self.piece_length;
        self.piece_length.min(self.total_length.saturating_sub(start))
    }
}

/// The torrents a listener serves, and the connections it has taken. One
/// listener serves any number of torrents on its one port: a peer says which
/// it wants in its handshake.
struct Registry {
    torrents: Mutex<HashMap<[u8; 20], Arc<SeederShared>>>,
    /// Peers being served, over every torrent.
    active_conns: AtomicUsize,
    /// Whether encrypted connections (MSE) are accepted, and whether plain ones are.
    encryption: crate::peer::Encryption,
    /// Cleared when the listener stops.
    running: AtomicBool,
}

impl Registry {
    fn hashes(&self) -> Vec<[u8; 20]> {
        lock(&self.torrents).keys().copied().collect()
    }

    fn get(&self, info_hash: &[u8; 20]) -> Option<Arc<SeederShared>> {
        lock(&self.torrents).get(info_hash).cloned()
    }
}

/// How a listener is set up: what it takes, on which port. What it serves is
/// registered on it afterwards.
#[derive(Debug, Clone)]
pub struct ListenerOptions {
    /// Whether encrypted connections (MSE) are accepted, and whether plain ones are.
    pub encryption: crate::peer::Encryption,
    /// Take IPv6 connections too, on the same port number (BEP 32 announces IPv6
    /// addresses, which are of no use if nothing listens on them).
    pub ipv6: bool,
    /// A uTP socket to take connections on as well as TCP ones (BEP 29).
    pub utp: Option<Arc<crate::utp::UtpSocket>>,
}

impl Default for ListenerOptions {
    fn default() -> Self {
        // Both kinds are accepted by default: a peer that offers encryption is
        // taken up on it, and one that does not is served all the same.
        ListenerOptions { encryption: crate::peer::Encryption::Prefer, ipv6: false, utp: None }
    }
}

/// A port that takes inbound peers for any number of torrents, each
/// [registered](Listener::register) on it. It stops when [`stop`](Listener::stop)
/// is called (dropping it does not stop it).
pub struct Listener {
    /// The port actually bound -- differs from the requested port if that
    /// was taken and the listener fell back to an ephemeral one. This is
    /// the port to put in tracker announces.
    pub port: u16,
    /// Whether IPv6 connections are taken too, on the same port.
    pub ipv6: bool,
    registry: Arc<Registry>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Listener {
    /// Binds `preferred_port` (or, if that is taken, an ephemeral one) and starts
    /// taking connections. Nothing is served until a torrent is registered.
    pub fn start(preferred_port: u16, options: ListenerOptions) -> std::io::Result<Listener> {
        // Preferred port first (conventionally 6881), ephemeral fallback --
        // another client on the same machine owning 6881 shouldn't stop this
        // one from seeding at all.
        let listener = TcpListener::bind(("0.0.0.0", preferred_port)).or_else(|_| TcpListener::bind(("0.0.0.0", 0)))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let registry = Arc::new(Registry { torrents: Mutex::new(HashMap::new()), active_conns: AtomicUsize::new(0), encryption: options.encryption, running: AtomicBool::new(true) });

        let mut threads = Vec::new();
        let accepting = Arc::clone(&registry);
        threads.push(thread::spawn(move || accept_loop(listener, accepting)));
        // The same, on IPv6, if that is wanted and the port is free there. (Not a failure if it is not.)
        let listener6 = if options.ipv6 { bind_tcp_v6_only(port).ok().filter(|l| l.set_nonblocking(true).is_ok()) } else { None };
        let ipv6 = listener6.is_some();
        if let Some(listener) = listener6 {
            let accepting = Arc::clone(&registry);
            threads.push(thread::spawn(move || accept_loop(listener, accepting)));
        }

        // uTP connections, if there is a socket for them: served just as TCP ones are.
        if let Some(utp) = options.utp.clone() {
            utp.listen();
            let accepting = Arc::clone(&registry);
            threads.push(thread::spawn(move || {
                while accepting.running.load(Ordering::SeqCst) {
                    let Some(stream) = utp.accept(Duration::from_millis(200)) else { continue };
                    let peer_ip = Some(stream.peer_addr().ip());
                    admit(&accepting, Box::new(stream), peer_ip);
                }
            }));
        }
        Ok(Listener { port, ipv6, registry, threads })
    }

    /// Starts serving a torrent on this listener: peers that ask for `info_hash`
    /// get its verified pieces, with the choking policy and metadata `options`
    /// give. (Its `encryption`, `utp` and `ipv6` belong to the listener and are
    /// not looked at here.) Registering the same info hash again replaces it.
    #[allow(clippy::too_many_arguments)]
    pub fn register(&self, info_hash: [u8; 20], our_peer_id: [u8; 20], spans: Arc<Vec<FileSpan>>, piece_length: u64, total_length: u64, have: Arc<HaveMap>, up_limit: Option<Arc<crate::ratelimit::RateLimiter>>, options: SeederOptions) -> SeederHandle {
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
            choker: Arc::new(Choker::new(options.unchoke_slots)),
            metadata: options.metadata.clone(),
            piece_lengths: options.piece_lengths.clone(),
        });

        // The rounds: who is served changes here, and each connection notices
        // within a read timeout and tells its peer.
        let rechoke_shared = Arc::clone(&shared);
        let rechoke_interval = options.rechoke_interval;
        let rechoke_thread = thread::spawn(move || {
            let mut waited = Duration::ZERO;
            while rechoke_shared.running.load(Ordering::SeqCst) {
                let slice = Duration::from_millis(50);
                thread::sleep(slice);
                waited += slice;
                if waited >= rechoke_interval {
                    waited = Duration::ZERO;
                    rechoke_shared.choker.rechoke();
                }
            }
        });

        if let Some(replaced) = lock(&self.registry.torrents).insert(info_hash, Arc::clone(&shared)) {
            replaced.running.store(false, Ordering::SeqCst);
        }
        SeederHandle { port: self.port, uploaded, ipv6: self.ipv6, info_hash, torrent: shared, registry: Arc::clone(&self.registry), rechoke_thread: Some(rechoke_thread), owned: None }
    }

    /// How many torrents are registered.
    pub fn torrent_count(&self) -> usize {
        lock(&self.registry.torrents).len()
    }

    /// Stops taking connections (those under way end within a read timeout) and
    /// forgets every torrent. Safe to call twice.
    pub fn stop(&mut self) {
        self.registry.running.store(false, Ordering::SeqCst);
        for torrent in lock(&self.registry.torrents).drain().map(|(_, t)| t) {
            torrent.running.store(false, Ordering::SeqCst);
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Handle to one torrent being served. Dropping it does NOT stop serving;
/// call `stop()` (idempotent).
pub struct SeederHandle {
    /// The port actually bound -- differs from the requested port if that
    /// was taken and the seeder fell back to an ephemeral one. This is
    /// the port to put in tracker announces.
    pub port: u16,
    pub uploaded: Arc<AtomicU64>,
    /// Whether IPv6 connections are taken too, on the same port.
    pub ipv6: bool,
    info_hash: [u8; 20],
    torrent: Arc<SeederShared>,
    registry: Arc<Registry>,
    rechoke_thread: Option<thread::JoinHandle<()>>,
    /// The listener, if this seeder has one to itself and so ends it too.
    owned: Option<Listener>,
}

impl SeederHandle {
    /// The limit this torrent's uploads are held to, for tests to see whose it is.
    #[cfg(test)]
    pub(crate) fn up_limit(&self) -> Option<Arc<crate::ratelimit::RateLimiter>> {
        self.torrent.up_limit.clone()
    }

    /// Stops serving this torrent: peers already connected are let go within a
    /// read timeout, and new ones asking for it are refused.
    pub fn stop(&mut self) {
        self.torrent.running.store(false, Ordering::SeqCst);
        {
            let mut torrents = lock(&self.registry.torrents);
            // (Only if it is still this torrent: registering again replaces it.)
            if torrents.get(&self.info_hash).is_some_and(|t| Arc::ptr_eq(t, &self.torrent)) {
                torrents.remove(&self.info_hash);
            }
        }
        if let Some(thread) = self.rechoke_thread.take() {
            let _ = thread.join();
        }
        if let Some(mut listener) = self.owned.take() {
            listener.stop();
        }
    }
}

/// How the seeder chooses who to serve.
#[derive(Debug, Clone)]
pub struct SeederOptions {
    /// Peers served at once (see [`crate::choker`]).
    pub unchoke_slots: usize,
    /// How often that choice is made again.
    pub rechoke_interval: Duration,
    /// Whether encrypted connections (MSE) are accepted, and whether plain
    /// ones are.
    pub encryption: crate::peer::Encryption,
    /// The torrent's info dictionary, exactly as its hash was taken over,
    /// to offer to peers that ask for it (BEP 9). Without it the seeder
    /// speaks no extensions.
    pub metadata: Option<Arc<Vec<u8>>>,
    /// A uTP socket to take connections on as well as TCP ones (BEP 29).
    pub utp: Option<Arc<crate::utp::UtpSocket>>,
    /// The length of every piece, where they are not all `piece_length` but for
    /// the last (a v2 torrent, whose pieces never span files).
    pub piece_lengths: Option<Arc<Vec<u32>>>,
    /// Take IPv6 connections too, on the same port number (BEP 32 announces IPv6
    /// addresses, which are of no use if nothing listens on them).
    pub ipv6: bool,
}

impl Default for SeederOptions {
    fn default() -> Self {
        // Both are accepted by default: a peer that offers encryption is
        // taken up on it, and one that does not is served all the same.
        SeederOptions { unchoke_slots: DEFAULT_SLOTS, rechoke_interval: RECHOKE_INTERVAL, encryption: crate::peer::Encryption::Prefer, metadata: None, utp: None, piece_lengths: None, ipv6: false }
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
    start_with(preferred_port, info_hash, our_peer_id, spans, piece_length, total_length, have, up_limit, SeederOptions::default())
}

/// [`start`] with the choking policy chosen.
#[allow(clippy::too_many_arguments)]
pub fn start_with(
    preferred_port: u16,
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
    spans: Arc<Vec<FileSpan>>,
    piece_length: u64,
    total_length: u64,
    have: Arc<HaveMap>,
    up_limit: Option<Arc<crate::ratelimit::RateLimiter>>,
    options: SeederOptions,
) -> std::io::Result<SeederHandle> {
    // One listener, for this torrent alone: it goes when the torrent's seeder does.
    let listener = Listener::start(preferred_port, ListenerOptions { encryption: options.encryption, ipv6: options.ipv6, utp: options.utp.clone() })?;
    let mut handle = listener.register(info_hash, our_peer_id, spans, piece_length, total_length, have, up_limit, options);
    handle.owned = Some(listener);
    Ok(handle)
}

/// Takes connections on `listener` (non-blocking) until it stops, each served on a thread of its own.
fn accept_loop(listener: TcpListener, registry: Arc<Registry>) {
    while registry.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // The listener is non-blocking so that it can notice a stop,
                // and where an accepted socket inherits that (macOS, the
                // BSDs) each read on it would fail at once when nothing has
                // arrived yet: a peer whose handshake came after the accept
                // would be dropped. The serving thread wants to block, with
                // its own read timeout.
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
                admit(&registry, Box::new(stream), peer_ip);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(200));
            }
            Err(_) => thread::sleep(Duration::from_millis(200)), // transient accept failure; keep listening
        }
    }
}

/// Serves `stream` on a thread of its own, unless too many are being served.
fn admit(registry: &Arc<Registry>, stream: Box<dyn PeerStream>, peer_ip: Option<std::net::IpAddr>) {
    if registry.active_conns.load(Ordering::SeqCst) >= MAX_INBOUND_PEERS {
        return; // over cap: dropped, which closes it
    }
    registry.active_conns.fetch_add(1, Ordering::SeqCst);
    let registry = Arc::clone(registry);
    thread::spawn(move || {
        let _ = serve_peer(stream, peer_ip, &registry);
        registry.active_conns.fetch_sub(1, Ordering::SeqCst);
    });
}

/// A TCP listener on `[::]:port` for IPv6 only, so that it does not also try to take the IPv4 port.
#[cfg(unix)]
fn bind_tcp_v6_only(port: u16) -> std::io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain socket calls with valid arguments; the descriptor is closed
    // on every failure path and otherwise handed to the TcpListener.
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fail = |fd: libc::c_int| {
            let error = std::io::Error::last_os_error();
            libc::close(fd);
            Err(error)
        };
        let on: libc::c_int = 1;
        let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        for (level, option) in [(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY), (libc::SOL_SOCKET, libc::SO_REUSEADDR)] {
            if libc::setsockopt(fd, level, option, &on as *const libc::c_int as *const libc::c_void, size) < 0 {
                return fail(fd);
            }
        }
        let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sa.sin6_port = port.to_be();
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
        {
            sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        }
        if libc::bind(fd, &sa as *const libc::sockaddr_in6 as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t) < 0 || libc::listen(fd, 128) < 0 {
            return fail(fd);
        }
        Ok(TcpListener::from_raw_fd(fd))
    }
}

#[cfg(not(unix))]
fn bind_tcp_v6_only(port: u16) -> std::io::Result<TcpListener> {
    // Where IPv6 sockets are IPv6 only by default (Windows).
    TcpListener::bind(("::", port))
}

/// Serves one inbound peer: handshake, bitfield, then Request/Piece until
/// the peer leaves, goes idle too long, or the seeder shuts down.
fn serve_peer(stream: Box<dyn PeerStream>, peer_ip: Option<std::net::IpAddr>, registry: &Registry) -> std::io::Result<()> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Plain or encrypted (MSE), whichever the peer began with; from here on
    // it makes no difference to what follows.
    // (Encrypted, the peer names its torrent by proving it knows the info hash, so every one served is a candidate.)
    let (mut stream, _encrypted) = crate::peer::mse::accept(stream, &registry.hashes(), registry.encryption).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    // Inbound side of the BEP 3 handshake: they send first and say which
    // torrent they want, we look it up and answer. A torrent this listener
    // isn't serving just closes the connection.
    let mut hs_buf = [0u8; HANDSHAKE_LEN];
    stream.read_exact(&mut hs_buf)?;
    let their_hs = Handshake::from_bytes(&hs_buf).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed inbound handshake"))?;
    let Some(shared) = registry.get(&their_hs.info_hash) else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "inbound handshake for a torrent not being served"));
    };
    let shared = &*shared;
    // Extensions are offered only when there is something to offer through
    // them: the info dictionary, for a peer that has only a magnet link.
    let ours = Handshake::new(shared.info_hash, shared.our_peer_id, shared.metadata.is_some()).with_fast(true);
    stream.write_all(&ours.to_bytes())?;
    // The Fast Extension (BEP 6) is in use only if both sides said so.
    let fast = their_hs.supports_fast();
    let speaks_extensions = shared.metadata.is_some() && their_hs.supports_extensions();
    // From here the loop wakes often to check for a stop, new pieces and a
    // change of choke.
    stream.set_read_timeout(Some(SERVE_READ_TIMEOUT))?;

    // What we can serve right now, honest at connect time as BEP 3
    // requires. Pieces verified afterwards are announced with `Have` as
    // they appear (see `announce_new_pieces`). The version is read first:
    // a piece added between the two reads then shows up as a difference
    // to announce, never as one that is missed.
    let mut seen_version = shared.have.version();
    let mut advertised = shared.have.snapshot();
    let first = if !fast {
        Message::Bitfield(PeerState::encode_bitfield(&advertised))
    } else if advertised.iter().all(|&has| has) && !advertised.is_empty() {
        Message::HaveAll
    } else if advertised.iter().all(|&has| !has) {
        Message::HaveNone
    } else {
        Message::Bitfield(PeerState::encode_bitfield(&advertised))
    };
    first.write_to(&mut stream).map_err(wire_to_io)?;
    // Pieces this peer may request while choked: the BEP 6 recipe, from its
    // address and the torrent, limited to what there is to serve.
    let mut allowed_fast = std::collections::HashSet::new();
    if let (true, Some(std::net::IpAddr::V4(ip))) = (fast, peer_ip) {
        for piece in allowed_fast_set(ip, &shared.info_hash, advertised.len() as u32, ALLOWED_FAST_PIECES) {
            if advertised[piece as usize] {
                Message::AllowedFast { piece_index: piece }.write_to(&mut stream).map_err(wire_to_io)?;
                allowed_fast.insert(piece);
            }
        }
    }
    if let (true, Some(metadata)) = (speaks_extensions, &shared.metadata) {
        // A seed says so (BEP 21): nothing is to be gained by offering it pieces.
        let seed = shared.have.count() == shared.have.total();
        Message::Extended { id: EXTENDED_HANDSHAKE_ID, payload: ExtendedHandshake::build_for_seeding(SEEDER_UT_METADATA_ID, metadata.len(), seed) }.write_to(&mut stream).map_err(wire_to_io)?;
    }
    // The id the peer wants metadata requests answered under, once it has
    // said, and how many it has made (bounded: see MAX_METADATA_REQUESTS).
    let mut peer_metadata_id: Option<u8> = None;
    let mut metadata_requests = 0usize;

    let choker_id = shared.choker.register();
    // Forgets the peer, freeing any slot it held, however this function ends.
    struct Leaving<'a>(&'a Choker, crate::choker::PeerId);
    impl Drop for Leaving<'_> {
        fn drop(&mut self) {
            self.0.unregister(self.1);
        }
    }
    let _leaving = Leaving(&shared.choker, choker_id);
    // Whether the peer has been told it is unchoked.
    let mut told_unchoked = false;
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

        // Tell the peer when the choker has changed its mind.
        let allowed = shared.choker.is_unchoked(choker_id);
        if allowed != told_unchoked {
            (if allowed { Message::Unchoke } else { Message::Choke }).write_to(&mut stream).map_err(wire_to_io)?;
            told_unchoked = allowed;
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
                shared.choker.set_interested(choker_id, true);
                // A free slot is theirs at once; the loop tells them next time round.
                shared.choker.grant_if_free(choker_id);
            }
            Message::NotInterested => shared.choker.set_interested(choker_id, false),
            Message::Request { index, begin, length } => {
                // Choked peers get nothing, except the pieces the Fast
                // Extension lets them ask for anyway. A fast peer is told when
                // a request will not be answered; others are left in silence
                // (BEP 3).
                let reject = |stream: &mut MseStream| -> std::io::Result<()> { if fast { Message::RejectRequest { index, begin, length }.write_to(stream).map_err(wire_to_io) } else { Ok(()) } };
                if !shared.choker.is_unchoked(choker_id) && !allowed_fast.contains(&index) {
                    reject(&mut stream)?;
                    continue;
                }
                if length > MAX_REQUEST_LEN {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "oversized block request"));
                }
                let piece_len = shared.piece_len(index);
                let in_bounds = shared.have.get(index) && (begin as u64).saturating_add(length as u64) <= piece_len;
                if !in_bounds {
                    reject(&mut stream)?; // data we don't have / can't have
                    continue;
                }
                let block = read_block(&shared.spans, index, shared.piece_length, begin, length)?;
                if let Some(limit) = &shared.up_limit {
                    limit.acquire(length as usize);
                }
                Message::Piece { index, begin, block }.write_to(&mut stream).map_err(wire_to_io)?;
                shared.uploaded.fetch_add(length as u64, Ordering::Relaxed);
                shared.choker.record_upload(choker_id, length as u64);
                last_sent = Instant::now();
            }
            Message::Extended { id: EXTENDED_HANDSHAKE_ID, payload } if speaks_extensions => {
                peer_metadata_id = ExtendedHandshake::parse(&payload).ok().and_then(|hs| hs.peer_ut_metadata_id());
            }
            Message::Extended { id: SEEDER_UT_METADATA_ID, payload } if speaks_extensions => {
                let (Some(metadata), Some(reply_id)) = (&shared.metadata, peer_metadata_id) else { continue };
                let Ok(MetadataMessage::Request { piece }) = MetadataMessage::decode(&payload) else { continue };
                metadata_requests += 1;
                // The whole dictionary a few times over is plenty; more is a
                // peer using us to move data for nothing.
                if metadata_requests > 2 * metadata.len().div_ceil(METADATA_PIECE_SIZE) + 8 {
                    return Ok(());
                }
                let start = piece as usize * METADATA_PIECE_SIZE;
                let reply = if start < metadata.len() {
                    let chunk = &metadata[start..(start + METADATA_PIECE_SIZE).min(metadata.len())];
                    if let Some(limit) = &shared.up_limit {
                        limit.acquire(chunk.len());
                    }
                    MetadataMessage::Data { piece, total_size: metadata.len() as u32, data: chunk.to_vec() }
                } else {
                    MetadataMessage::Reject { piece }
                };
                Message::Extended { id: reply_id, payload: reply.encode() }.write_to(&mut stream).map_err(wire_to_io)?;
                last_sent = Instant::now();
            }
            // Piece-availability chatter from a fellow leecher; a pure
            // serve loop has no use for it. Cancel is inherently
            // best-effort (we serve synchronously, so there's never a
            // queued request to cancel). Choke/Unchoke describe *their*
            // upload policy toward us -- irrelevant, we request nothing.
            Message::Have { .. } | Message::Bitfield(_) | Message::Cancel { .. } | Message::Choke | Message::Unchoke | Message::KeepAlive | Message::Piece { .. } | Message::Port(_) | Message::Extended { .. } => {}
            // The Fast Extension's other messages describe the *peer's*
            // side: what it has, what it will not send us, what it suggests
            // we fetch. We request nothing from an inbound peer.
            Message::Suggest { .. } | Message::HaveAll | Message::HaveNone | Message::RejectRequest { .. } | Message::AllowedFast { .. } => {}
        }
    }
}

/// Tells a connected peer about pieces verified since it was last told: a
/// `Have` for each. Without this a peer that connected early would never
/// learn of what this client downloads afterwards, and a client that is
/// still downloading would be a poor source. Returns whether it sent any.
fn announce_new_pieces(stream: &mut dyn PeerStream, have: &HaveMap, seen_version: &mut u64, advertised: &mut [bool]) -> std::io::Result<bool> {
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
    use std::net::{SocketAddr, TcpStream};

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

    #[test]
    fn a_peer_can_leech_from_the_seeder_over_utp() {
        use crate::utp::UtpSocket;
        let dir = tmp_dir("utp");
        let pieces = [vec![0x11u8; 256], vec![0x22u8; 256], vec![0x33u8; 100]];
        let total: i64 = pieces.iter().map(|p| p.len() as i64).sum();
        let spans = Arc::new(build_file_spans(&dir, &[(vec!["seed.bin".to_string()], total)]));
        for (i, p) in pieces.iter().enumerate() {
            write_piece(&spans, i as u32, 256, p).unwrap();
        }
        let have = Arc::new(HaveMap::new(3));
        (0..3).for_each(|i| have.set(i));
        let info_hash = [0x67; 20];
        let socket = Arc::new(UtpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());
        let options = SeederOptions { utp: Some(Arc::clone(&socket)), ..Default::default() };
        let mut seeder = start_with(0, info_hash, [0x20; 20], spans, 256, total as u64, have, None, options).unwrap();

        let leech = Arc::new(UtpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());
        let mut stream = leech.connect(SocketAddr::from(([127, 0, 0, 1], socket.local_addr().unwrap().port())), Duration::from_secs(5)).expect("the seeder takes uTP connections");
        crate::peer::PeerStream::set_read_timeout(&stream, Some(Duration::from_secs(5))).unwrap();
        stream.write_all(&Handshake::new(info_hash, [0x21; 20], false).to_bytes()).unwrap();
        let mut hs = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut hs).unwrap();
        assert_eq!(Handshake::from_bytes(&hs).unwrap().info_hash, info_hash);
        Message::Interested.write_to(&mut stream).unwrap();
        let mut unchoked = false;
        while !unchoked {
            unchoked = matches!(Message::read_from(&mut stream).unwrap(), Message::Unchoke);
        }
        Message::Request { index: 1, begin: 0, length: 256 }.write_to(&mut stream).unwrap();
        let block = loop {
            if let Message::Piece { index: 1, block, .. } = Message::read_from(&mut stream).unwrap() {
                break block;
            }
        };
        assert_eq!(block, pieces[1]);
        assert!(seeder.uploaded.load(Ordering::SeqCst) >= 256, "and it counts what it served");
        drop(stream);
        seeder.stop();
    }

    #[test]
    fn a_seeder_without_a_utp_socket_does_not_listen_for_utp() {
        let dir = tmp_dir("no-utp");
        let (mut seeder, _) = start_test_seeder(&dir, &[vec![1u8; 256]], 256, &[0]);
        assert_eq!(seeder.owned.as_ref().map(|l| l.threads.len()), Some(1), "one thread taking TCP connections, none for uTP");
        seeder.stop();
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

    // ---- choking ----

    fn start_choking_seeder(dir: &std::path::Path, slots: usize, interval: Duration) -> (SeederHandle, [u8; 20]) {
        let pieces = [vec![0x5Au8; 16384]];
        let files = vec![(vec!["seed.bin".to_string()], 16384i64)];
        let spans = Arc::new(build_file_spans(dir, &files));
        write_piece(&spans, 0, 16384, &pieces[0]).unwrap();
        let have = Arc::new(HaveMap::new(1));
        have.set(0);
        let info_hash = [0x67; 20];
        let options = SeederOptions { unchoke_slots: slots, rechoke_interval: interval, metadata: None, ..Default::default() };
        let handle = start_with(0, info_hash, [0x20; 20], spans, 16384, 16384, have, None, options).unwrap();
        (handle, info_hash)
    }

    /// A leecher that has connected and said it is interested.
    fn interested_leecher(port: u16, info_hash: [u8; 20]) -> TcpStream {
        let (mut stream, _) = leech_connect(port, info_hash);
        Message::Interested.write_to(&mut stream).unwrap();
        stream
    }

    /// The next Choke or Unchoke the peer sends within `wait`, skipping the rest.
    fn next_choke_message(stream: &mut TcpStream, wait: Duration) -> Option<Message> {
        stream.set_read_timeout(Some(wait)).unwrap();
        loop {
            match Message::read_from(stream) {
                Ok(m @ (Message::Choke | Message::Unchoke)) => return Some(m),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    }

    #[test]
    fn only_as_many_peers_are_unchoked_as_there_are_slots() {
        let dir = tmp_dir("slots");
        let (mut handle, info_hash) = start_choking_seeder(&dir, 2, Duration::from_secs(3600));
        let mut leechers: Vec<TcpStream> = (0..4).map(|_| interested_leecher(handle.port, info_hash)).collect();

        let told: Vec<Option<Message>> = leechers.iter_mut().map(|l| next_choke_message(l, Duration::from_millis(700))).collect();

        assert_eq!(told[0], Some(Message::Unchoke));
        assert_eq!(told[1], Some(Message::Unchoke));
        assert_eq!(told[2], None, "no slot left, so no Unchoke");
        assert_eq!(told[3], None);
        handle.stop();
    }

    #[test]
    fn a_choked_peers_requests_are_ignored_and_an_unchoked_peers_are_served() {
        let dir = tmp_dir("choked-requests");
        let (mut handle, info_hash) = start_choking_seeder(&dir, 1, Duration::from_secs(3600));
        let mut first = interested_leecher(handle.port, info_hash);
        let mut second = interested_leecher(handle.port, info_hash);
        assert_eq!(next_choke_message(&mut first, Duration::from_secs(2)), Some(Message::Unchoke));

        Message::Request { index: 0, begin: 0, length: 16384 }.write_to(&mut second).unwrap();
        Message::Request { index: 0, begin: 0, length: 16384 }.write_to(&mut first).unwrap();

        first.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let served = loop {
            match Message::read_from(&mut first) {
                Ok(Message::Piece { block, .. }) => break Some(block.len()),
                Ok(_) => continue,
                Err(_) => break None,
            }
        };
        assert_eq!(served, Some(16384), "the unchoked peer got its block");
        second.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let mut got_piece = false;
        while let Ok(m) = Message::read_from(&mut second) {
            got_piece |= matches!(m, Message::Piece { .. });
        }
        assert!(!got_piece, "the choked peer got nothing");
        handle.stop();
    }

    #[test]
    fn a_round_hands_a_slot_on_to_a_peer_that_was_waiting_and_tells_the_one_that_lost_it() {
        let dir = tmp_dir("rotation");
        // One regular slot and one optimistic; rounds every 150 ms.
        let (mut handle, info_hash) = start_choking_seeder(&dir, 2, Duration::from_millis(150));
        let mut a = interested_leecher(handle.port, info_hash);
        let mut b = interested_leecher(handle.port, info_hash);
        let mut c = interested_leecher(handle.port, info_hash);
        assert_eq!(next_choke_message(&mut a, Duration::from_secs(2)), Some(Message::Unchoke));
        assert_eq!(next_choke_message(&mut b, Duration::from_secs(2)), Some(Message::Unchoke));

        // The optimistic slot goes round the interested peers, so c, which
        // had no slot, gets one, and whoever it displaces is choked.
        assert_eq!(next_choke_message(&mut c, Duration::from_secs(6)), Some(Message::Unchoke), "the peer that waited got its turn");
        let choked = next_choke_message(&mut b, Duration::from_secs(3));
        assert_eq!(choked, Some(Message::Choke), "and b, which had the optimistic slot, was told it lost it");
        handle.stop();
    }

    #[test]
    fn a_slot_freed_by_a_peer_leaving_goes_to_the_next_at_the_following_round() {
        let dir = tmp_dir("slot-freed");
        let (mut handle, info_hash) = start_choking_seeder(&dir, 1, Duration::from_millis(150));
        let mut first = interested_leecher(handle.port, info_hash);
        let mut second = interested_leecher(handle.port, info_hash);
        assert_eq!(next_choke_message(&mut first, Duration::from_secs(2)), Some(Message::Unchoke));
        assert_eq!(next_choke_message(&mut second, Duration::from_millis(400)), None, "one slot, taken");

        drop(first);

        assert_eq!(next_choke_message(&mut second, Duration::from_secs(4)), Some(Message::Unchoke), "the waiting peer is served once the slot is free");
        handle.stop();
    }

    #[test]
    fn a_peer_that_says_it_is_no_longer_interested_is_choked() {
        let dir = tmp_dir("not-interested");
        let (mut handle, info_hash) = start_choking_seeder(&dir, 2, Duration::from_secs(3600));
        let mut a = interested_leecher(handle.port, info_hash);
        assert_eq!(next_choke_message(&mut a, Duration::from_secs(2)), Some(Message::Unchoke));

        Message::NotInterested.write_to(&mut a).unwrap();

        assert_eq!(next_choke_message(&mut a, Duration::from_secs(2)), Some(Message::Choke));
        handle.stop();
    }

    #[test]
    fn the_peer_taking_the_most_keeps_its_slot_while_the_others_take_turns() {
        let dir = tmp_dir("keeps-slot");
        // One slot by speed, one optimistic, rounds every 100 ms.
        let (mut handle, info_hash) = start_choking_seeder(&dir, 2, Duration::from_millis(100));
        let mut idle = interested_leecher(handle.port, info_hash); // connects first, so wins any tie
        let mut busy = interested_leecher(handle.port, info_hash);
        let mut waiting = interested_leecher(handle.port, info_hash);
        assert_eq!(next_choke_message(&mut idle, Duration::from_secs(2)), Some(Message::Unchoke));
        assert_eq!(next_choke_message(&mut busy, Duration::from_secs(2)), Some(Message::Unchoke));

        // `busy` downloads as fast as it can for a couple of seconds.
        let (choked_tx, choked_rx) = std::sync::mpsc::channel();
        let downloader = thread::spawn(move || {
            busy.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            let until = Instant::now() + Duration::from_millis(2500);
            let mut blocks = 0;
            while Instant::now() < until {
                let _ = Message::Request { index: 0, begin: 0, length: 16384 }.write_to(&mut busy);
                while let Ok(m) = Message::read_from(&mut busy) {
                    match m {
                        Message::Choke => {
                            let _ = choked_tx.send(());
                        }
                        Message::Piece { .. } => blocks += 1,
                        _ => {}
                    }
                }
            }
            blocks
        });
        // Meanwhile the others are told in turn, as the optimistic slot moves.
        let turns = next_choke_message(&mut waiting, Duration::from_secs(3)).is_some() | next_choke_message(&mut idle, Duration::from_millis(50)).is_some();
        let blocks = downloader.join().unwrap();

        assert!(blocks > 10, "the busy peer was actually served: {}", blocks);
        assert!(choked_rx.try_recv().is_err(), "and never choked, for it took the most every round");
        assert!(turns, "while the others were told about their turns");
        handle.stop();
    }

    // ---- serving the info dictionary (BEP 9) and saying it is a seed (BEP 21) ----

    use crate::peer::extension::{ExtendedHandshake as ExtHs, EXTENDED_HANDSHAKE_ID as EXT_HS_ID};
    use sha1::{Digest, Sha1};

    /// A seeder that offers `metadata`, with all or none of its one piece.
    fn start_metadata_seeder(dir: &std::path::Path, metadata: Option<Vec<u8>>, complete: bool) -> (SeederHandle, [u8; 20]) {
        let files = vec![(vec!["seed.bin".to_string()], 16384i64)];
        let spans = Arc::new(build_file_spans(dir, &files));
        write_piece(&spans, 0, 16384, &[0x5Au8; 16384]).unwrap();
        let have = Arc::new(HaveMap::new(1));
        if complete {
            have.set(0);
        }
        // The seeder's info hash is the metadata's, as a real torrent's is.
        let info_hash: [u8; 20] = metadata.as_ref().map_or([0x66; 20], |m| Sha1::digest(m).into());
        let options = SeederOptions { metadata: metadata.map(Arc::new), ..Default::default() };
        (start_with(0, info_hash, [0x20; 20], spans, 16384, 16384, have, None, options).unwrap(), info_hash)
    }

    fn some_metadata(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect()
    }

    /// Connects as a peer that speaks extensions and returns the stream, the
    /// seeder's handshake and (if it sent one) its extended handshake.
    fn extension_leecher(port: u16, info_hash: [u8; 20]) -> (TcpStream, Handshake, Option<ExtHs>) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.write_all(&Handshake::new(info_hash, [0x21; 20], true).to_bytes()).unwrap();
        let mut buf = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut buf).unwrap();
        let theirs = Handshake::from_bytes(&buf).unwrap();
        // Say hello in the extension protocol too, asking for replies under id 9.
        Message::Extended { id: EXT_HS_ID, payload: ExtHs::build(9, None) }.write_to(&mut stream).unwrap();
        let mut ext = None;
        stream.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
        while let Ok(m) = Message::read_from(&mut stream) {
            if let Message::Extended { id: EXT_HS_ID, payload } = m {
                ext = Some(ExtHs::parse(&payload).unwrap());
                break;
            }
        }
        (stream, theirs, ext)
    }

    #[test]
    fn the_seeders_own_metadata_client_can_fetch_the_info_dict_from_it_across_several_pieces() {
        use crate::session::metadata::{fetch_metadata, MetadataConfig};
        use crate::session::sink::RecordingSink;
        use std::sync::atomic::AtomicBool;
        let dir = tmp_dir("serve-metadata");
        let metadata = some_metadata(40_000); // three pieces of 16 KiB, the last short
        let (mut handle, info_hash) = start_metadata_seeder(&dir, Some(metadata.clone()), true);
        let peer: std::net::SocketAddr = format!("127.0.0.1:{}", handle.port).parse().unwrap();
        let config = MetadataConfig { budget: Duration::from_secs(5), parallelism: 1, connect_timeout: Duration::from_secs(2), transport: Default::default(), encryption: Default::default() };

        let fetched = fetch_metadata(info_hash, [7; 20], vec![peer], None, &config, &RecordingSink::default(), &AtomicBool::new(false)).expect("the seeder serves the metadata");

        assert_eq!(fetched.raw_info, metadata, "every byte, verified against the hash by the fetcher");
        handle.stop();
    }

    #[test]
    fn a_seeder_with_all_its_pieces_says_upload_only_and_one_without_does_not() {
        let dir = tmp_dir("upload-only");
        let (mut seed, hash_a) = start_metadata_seeder(&dir, Some(some_metadata(100)), true);
        let (_, _, ext) = extension_leecher(seed.port, hash_a);
        let ext = ext.expect("an extended handshake");
        assert!(ext.upload_only, "a seed says so (BEP 21)");
        assert_eq!(ext.metadata_size, Some(100));
        assert!(ext.peer_ut_metadata_id().is_some());
        assert!(ext.peer_ut_pex_id().is_none(), "and it offers no peer exchange");
        seed.stop();

        let dir = tmp_dir("not-upload-only");
        let (mut partial, hash_b) = start_metadata_seeder(&dir, Some(some_metadata(100)), false);
        let (_, _, ext) = extension_leecher(partial.port, hash_b);
        assert!(!ext.expect("an extended handshake").upload_only, "a client still downloading does not");
        partial.stop();
    }

    #[test]
    fn a_seeder_with_no_metadata_speaks_no_extensions() {
        let dir = tmp_dir("no-extensions");
        let (mut handle, info_hash) = start_metadata_seeder(&dir, None, true);

        let (_, theirs, ext) = extension_leecher(handle.port, info_hash);

        assert!(!theirs.supports_extensions(), "the extension bit is clear");
        assert!(ext.is_none(), "and no extended handshake is sent");
        handle.stop();
    }

    #[test]
    fn a_request_past_the_end_is_rejected_and_one_before_the_peers_own_handshake_is_ignored() {
        let dir = tmp_dir("metadata-edge");
        let (mut handle, info_hash) = start_metadata_seeder(&dir, Some(some_metadata(100)), true);
        let (mut stream, _, _) = extension_leecher(handle.port, info_hash);
        let ut_metadata_id = 1; // the id the seeder advertised

        Message::Extended { id: ut_metadata_id, payload: MetadataMessage::Request { piece: 5 }.encode() }.write_to(&mut stream).unwrap();

        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let reply = loop {
            match Message::read_from(&mut stream) {
                Ok(Message::Extended { id: 9, payload }) => break MetadataMessage::decode(&payload).unwrap(),
                Ok(_) => continue,
                Err(e) => panic!("no reply: {:?}", e),
            }
        };
        assert_eq!(reply, MetadataMessage::Reject { piece: 5 });
        handle.stop();

        // A peer that never sent its extended handshake has told us no id to reply under.
        let dir = tmp_dir("metadata-no-hello");
        let (mut handle, info_hash) = start_metadata_seeder(&dir, Some(some_metadata(100)), true);
        let mut silent = TcpStream::connect(("127.0.0.1", handle.port)).unwrap();
        silent.write_all(&Handshake::new(info_hash, [0x22; 20], true).to_bytes()).unwrap();
        let mut buf = [0u8; HANDSHAKE_LEN];
        silent.read_exact(&mut buf).unwrap();
        Message::Extended { id: 1, payload: MetadataMessage::Request { piece: 0 }.encode() }.write_to(&mut silent).unwrap();
        silent.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let mut got_data = false;
        while let Ok(m) = Message::read_from(&mut silent) {
            got_data |= matches!(m, Message::Extended { id, .. } if id != EXT_HS_ID);
        }
        assert!(!got_data, "nothing to answer under");
        handle.stop();
    }

    #[test]
    fn a_peer_that_keeps_asking_for_the_metadata_is_eventually_dropped() {
        let dir = tmp_dir("metadata-flood");
        let (mut handle, info_hash) = start_metadata_seeder(&dir, Some(some_metadata(100)), true);
        let (mut stream, _, _) = extension_leecher(handle.port, info_hash);

        // Set before the seeder hangs up: macOS refuses to set it on a closed socket.
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        // One piece, so 2 * 1 + 8 = 10 requests are allowed.
        for _ in 0..40 {
            let request = Message::Extended { id: 1, payload: MetadataMessage::Request { piece: 0 }.encode() };
            if request.write_to(&mut stream).is_err() {
                break;
            }
        }

        let mut answers = 0;
        let ended = loop {
            match Message::read_from(&mut stream) {
                Ok(Message::Extended { id: 9, .. }) => answers += 1,
                Ok(_) => {}
                Err(_) => break true,
            }
            if answers > 40 {
                break false;
            }
        };
        assert!(ended, "the connection was closed");
        assert!(answers <= 10, "after at most ten answers: {}", answers);
        handle.stop();
    }

    #[test]
    fn a_peer_whose_handshake_arrives_after_the_connection_is_accepted_is_still_served() {
        // The listener polls without blocking, so a connection is often
        // accepted before its first byte arrives. Where an accepted socket
        // inherits the listener's non-blocking mode (macOS, the BSDs) the
        // handshake read then failed at once and the peer was dropped.
        let dir = tmp_dir("late-handshake");
        let (mut handle, info_hash) = start_test_seeder(&dir, &[vec![0x11u8; 16384]], 16384, &[0]);
        let mut stream = TcpStream::connect(("127.0.0.1", handle.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

        thread::sleep(Duration::from_millis(1300)); // several accept polls pass, and the serve timeout, with nothing sent
        stream.write_all(&Handshake::new(info_hash, [0x23; 20], false).to_bytes()).unwrap();

        let mut buf = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut buf).expect("the seeder answered a handshake that came late");
        assert_eq!(Handshake::from_bytes(&buf).unwrap().info_hash, info_hash);
        handle.stop();
    }

    // ---- encrypted connections (MSE) ----

    fn start_encryption_seeder(dir: &std::path::Path, mode: crate::peer::Encryption) -> (SeederHandle, [u8; 20]) {
        let files = vec![(vec!["seed.bin".to_string()], 16384i64)];
        let spans = Arc::new(build_file_spans(dir, &files));
        write_piece(&spans, 0, 16384, &[0x5Au8; 16384]).unwrap();
        let have = Arc::new(HaveMap::new(1));
        have.set(0);
        let info_hash = [0x68; 20];
        let options = SeederOptions { encryption: mode, ..Default::default() };
        (start_with(0, info_hash, [0x20; 20], spans, 16384, 16384, have, None, options).unwrap(), info_hash)
    }

    #[test]
    fn an_encrypted_leecher_is_served_a_block_like_any_other() {
        use crate::peer::mse;
        let dir = tmp_dir("mse-serve");
        let (mut handle, info_hash) = start_encryption_seeder(&dir, crate::peer::Encryption::Prefer);
        let tcp = TcpStream::connect(("127.0.0.1", handle.port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut stream = mse::initiate(Box::new(tcp), &info_hash, false, &Handshake::new(info_hash, [0x24; 20], false).to_bytes()).expect("the seeder takes an encrypted connection");
        assert!(stream.is_encrypted());

        let mut buf = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(Handshake::from_bytes(&buf).unwrap().info_hash, info_hash, "its handshake comes back through the cipher");
        Message::Interested.write_to(&mut stream).unwrap();
        let mut unchoked = false;
        while !unchoked {
            unchoked = matches!(Message::read_from(&mut stream).unwrap(), Message::Unchoke);
        }
        Message::Request { index: 0, begin: 0, length: 16384 }.write_to(&mut stream).unwrap();
        let block = loop {
            if let Message::Piece { block, .. } = Message::read_from(&mut stream).unwrap() {
                break block;
            }
        };
        assert_eq!(block, vec![0x5Au8; 16384], "the block, decrypted, is the data");
        handle.stop();
    }

    #[test]
    fn a_seeder_that_requires_encryption_turns_away_a_plain_handshake() {
        let dir = tmp_dir("mse-require");
        let (mut handle, info_hash) = start_encryption_seeder(&dir, crate::peer::Encryption::Require);
        let mut stream = TcpStream::connect(("127.0.0.1", handle.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

        stream.write_all(&Handshake::new(info_hash, [0x24; 20], false).to_bytes()).unwrap();

        let mut buf = [0u8; HANDSHAKE_LEN];
        assert!(stream.read_exact(&mut buf).is_err(), "no handshake comes back: the connection is closed");
        handle.stop();
    }

    #[test]
    fn a_seeder_with_encryption_off_does_not_understand_an_encrypted_attempt_but_serves_plain_ones() {
        use crate::peer::mse;
        let dir = tmp_dir("mse-off");
        let (mut handle, info_hash) = start_encryption_seeder(&dir, crate::peer::Encryption::Off);
        let tcp = TcpStream::connect(("127.0.0.1", handle.port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        assert!(mse::initiate(Box::new(tcp), &info_hash, false, b"").is_err());

        let (_, bitfield) = leech_connect(handle.port, info_hash);
        assert_eq!(bitfield.first(), Some(&true), "a plain peer is served as usual");
        handle.stop();
    }

    // ---- the Fast Extension (BEP 6) ----

    /// A seeder with `have` of `pieces` 16 KiB pieces and no unchoke slots,
    /// so nobody is ever unchoked.
    fn start_fast_seeder(dir: &std::path::Path, pieces: usize, have: &[usize]) -> (SeederHandle, [u8; 20]) {
        let files = vec![(vec!["seed.bin".to_string()], (pieces * 16384) as i64)];
        let spans = Arc::new(build_file_spans(dir, &files));
        for i in 0..pieces {
            write_piece(&spans, i as u32, 16384, &vec![i as u8 + 1; 16384]).unwrap();
        }
        let map = Arc::new(HaveMap::new(pieces));
        for &i in have {
            map.set(i as u32);
        }
        let info_hash = [0x69; 20];
        let options = SeederOptions { unchoke_slots: 0, ..Default::default() };
        (start_with(0, info_hash, [0x20; 20], spans, 16384, (pieces * 16384) as u64, map, None, options).unwrap(), info_hash)
    }

    /// Connects saying it speaks the Fast Extension (or not), and collects
    /// what the seeder sends first.
    fn fast_leecher(port: u16, info_hash: [u8; 20], fast: bool) -> (TcpStream, Handshake, Vec<Message>) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(&Handshake::new(info_hash, [0x25; 20], false).with_fast(fast).to_bytes()).unwrap();
        let mut buf = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut buf).unwrap();
        let theirs = Handshake::from_bytes(&buf).unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let mut first = Vec::new();
        while let Ok(m) = Message::read_from(&mut stream) {
            first.push(m);
        }
        (stream, theirs, first)
    }

    #[test]
    fn a_fast_peer_is_told_of_a_full_seed_in_one_message_and_a_partial_one_the_usual_way() {
        let dir = tmp_dir("fast-have-all");
        let (mut seed, hash) = start_fast_seeder(&dir, 8, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let (_, theirs, first) = fast_leecher(seed.port, hash, true);
        assert!(theirs.supports_fast(), "the seeder speaks it too");
        assert_eq!(first[0], Message::HaveAll);
        seed.stop();

        let dir = tmp_dir("fast-have-none");
        let (mut empty, hash) = start_fast_seeder(&dir, 8, &[]);
        assert_eq!(fast_leecher(empty.port, hash, true).2[0], Message::HaveNone);
        empty.stop();

        let dir = tmp_dir("fast-partial");
        let (mut partial, hash) = start_fast_seeder(&dir, 8, &[1, 5]);
        assert!(matches!(&fast_leecher(partial.port, hash, true).2[0], Message::Bitfield(bits) if *bits == vec![0b0100_0100]));
        partial.stop();
    }

    #[test]
    fn a_peer_that_does_not_speak_it_gets_an_ordinary_bitfield_and_nothing_fast() {
        let dir = tmp_dir("fast-off");
        let (mut seed, hash) = start_fast_seeder(&dir, 8, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let (_, _, first) = fast_leecher(seed.port, hash, false);
        assert_eq!(first, vec![Message::Bitfield(vec![0xFF])], "a bitfield, and no allowed-fast messages");
        seed.stop();
    }

    #[test]
    fn the_allowed_fast_pieces_are_the_recipes_and_only_ones_the_seeder_has() {
        let dir = tmp_dir("fast-allowed");
        let pieces = 40;
        // Every other piece is missing.
        let have: Vec<usize> = (0..pieces).step_by(2).collect();
        let (mut seed, hash) = start_fast_seeder(&dir, pieces, &have);

        let (_, _, first) = fast_leecher(seed.port, hash, true);

        let sent: Vec<u32> = first.iter().filter_map(|m| if let Message::AllowedFast { piece_index } = m { Some(*piece_index) } else { None }).collect();
        let recipe = allowed_fast_set(std::net::Ipv4Addr::LOCALHOST, &hash, pieces as u32, ALLOWED_FAST_PIECES);
        let expected: Vec<u32> = recipe.into_iter().filter(|p| p % 2 == 0).collect();
        assert_eq!(sent, expected, "the recipe's pieces, less those the seeder cannot serve");
        assert!(sent.len() <= ALLOWED_FAST_PIECES);
        seed.stop();
    }

    #[test]
    fn a_choked_fast_peer_is_served_an_allowed_piece_and_rejected_for_any_other() {
        let dir = tmp_dir("fast-serve");
        let pieces = 40;
        let all: Vec<usize> = (0..pieces).collect();
        let (mut seed, hash) = start_fast_seeder(&dir, pieces, &all);
        let (mut stream, _, first) = fast_leecher(seed.port, hash, true);
        let allowed: Vec<u32> = first.iter().filter_map(|m| if let Message::AllowedFast { piece_index } = m { Some(*piece_index) } else { None }).collect();
        assert!(!allowed.is_empty());
        let not_allowed = (0..pieces as u32).find(|p| !allowed.contains(p)).unwrap();

        // Never unchoked (no slots), yet an allowed piece is served ...
        Message::Request { index: allowed[0], begin: 0, length: 16384 }.write_to(&mut stream).unwrap();
        // ... and any other is rejected, naming exactly the request.
        Message::Request { index: not_allowed, begin: 0, length: 16384 }.write_to(&mut stream).unwrap();

        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let (mut served, mut rejected) = (None, None);
        while served.is_none() || rejected.is_none() {
            match Message::read_from(&mut stream).unwrap() {
                Message::Piece { index, block, .. } => served = Some((index, block)),
                Message::RejectRequest { index, begin, length } => rejected = Some((index, begin, length)),
                _ => {}
            }
        }
        assert_eq!(served, Some((allowed[0], vec![allowed[0] as u8 + 1; 16384])), "the block, without an unchoke");
        assert_eq!(rejected, Some((not_allowed, 0, 16384)));
        seed.stop();
    }

    #[test]
    fn a_fast_peer_asking_for_a_piece_the_seeder_lacks_or_out_of_range_is_rejected_not_left_waiting() {
        let dir = tmp_dir("fast-reject-missing");
        let (mut seed, hash) = start_fast_seeder(&dir, 8, &[0, 1, 2, 3]);
        let (mut stream, _, first) = fast_leecher(seed.port, hash, true);
        let allowed: Vec<u32> = first.iter().filter_map(|m| if let Message::AllowedFast { piece_index } = m { Some(*piece_index) } else { None }).collect();
        let usable = allowed.first().copied().expect("some allowed piece among those it has");

        // An allowed piece, but past the end of it.
        Message::Request { index: usable, begin: 16384, length: 16384 }.write_to(&mut stream).unwrap();

        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let reply = loop {
            match Message::read_from(&mut stream).unwrap() {
                m @ Message::RejectRequest { .. } => break m,
                _ => continue,
            }
        };
        assert_eq!(reply, Message::RejectRequest { index: usable, begin: 16384, length: 16384 });
        seed.stop();
    }

    #[test]
    fn a_non_fast_peer_asking_while_choked_is_still_met_with_silence() {
        let dir = tmp_dir("fast-silence");
        let (mut seed, hash) = start_fast_seeder(&dir, 8, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let (mut stream, _, _) = fast_leecher(seed.port, hash, false);

        Message::Request { index: 0, begin: 0, length: 16384 }.write_to(&mut stream).unwrap();

        stream.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let mut got = Vec::new();
        while let Ok(m) = Message::read_from(&mut stream) {
            got.push(m);
        }
        assert!(got.iter().all(|m| !matches!(m, Message::RejectRequest { .. } | Message::Piece { .. })), "BEP 3: ignored, not rejected: {:?}", got);
        seed.stop();
    }

    #[test]
    fn a_v2_seeder_knows_each_pieces_own_length_and_serves_it_from_the_aligned_layout() {
        use crate::downloader::file_writer::build_file_spans_aligned;
        let dir = tmp_dir("v2-seed");
        // a: 300 bytes in pieces of 256 (256 + 44), b: 100 bytes (one piece).
        let files = vec![(vec!["a".to_string()], 300i64), (vec!["b".to_string()], 100)];
        let spans = Arc::new(build_file_spans_aligned(&dir, &files, 256));
        let pieces = [vec![0x11u8; 256], vec![0x22u8; 44], vec![0x33u8; 100]];
        for (i, p) in pieces.iter().enumerate() {
            write_piece(&spans, i as u32, 256, p).unwrap();
        }
        let have = Arc::new(HaveMap::new(3));
        (0..3).for_each(|i| have.set(i));
        let info_hash = [0x68; 20];
        let options = SeederOptions { piece_lengths: Some(Arc::new(vec![256, 44, 100])), ..Default::default() };
        let mut seeder = start_with(0, info_hash, [0x20; 20], spans, 256, 400, have, None, options).unwrap();

        let (mut stream, bitfield) = leech_connect(seeder.port, info_hash);
        assert_eq!(&bitfield[..3], &[true, true, true]);
        Message::Interested.write_to(&mut stream).unwrap();
        loop {
            if matches!(Message::read_from(&mut stream).unwrap(), Message::Unchoke) {
                break;
            }
        }
        for (index, expected) in pieces.iter().enumerate() {
            Message::Request { index: index as u32, begin: 0, length: expected.len() as u32 }.write_to(&mut stream).unwrap();
            let block = loop {
                if let Message::Piece { index: i, block, .. } = Message::read_from(&mut stream).unwrap() {
                    if i as usize == index {
                        break block;
                    }
                }
            };
            assert_eq!(&block, expected, "piece {}", index);
        }
        // Past the end of a short piece is not served, though the arithmetic of a
        // uniform piece length would have allowed it.
        Message::Request { index: 1, begin: 0, length: 100 }.write_to(&mut stream).unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
        assert!(Message::read_from(&mut stream).is_err(), "nothing comes back for a request longer than the piece is");
        seeder.stop();
    }

    /// A seeder over one 256-byte piece, with `options`.
    fn tiny_seeder(name: &str, options: SeederOptions) -> (SeederHandle, [u8; 20]) {
        let dir = tmp_dir(name);
        let spans = Arc::new(build_file_spans(&dir, &[(vec!["seed.bin".to_string()], 256)]));
        write_piece(&spans, 0, 256, &[7u8; 256]).unwrap();
        let have = Arc::new(HaveMap::new(1));
        have.set(0);
        let info_hash = [0x69; 20];
        (start_with(0, info_hash, [0x20; 20], spans, 256, 256, have, None, options).unwrap(), info_hash)
    }

    fn handshake_over(addr: SocketAddr, info_hash: [u8; 20]) -> std::io::Result<Handshake> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(&Handshake::new(info_hash, [0x21; 20], false).to_bytes())?;
        let mut hs = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut hs)?;
        Ok(Handshake::from_bytes(&hs).unwrap())
    }

    #[test]
    fn with_ipv6_the_seeder_takes_ipv6_connections_on_the_same_port_and_says_so() {
        if std::net::TcpListener::bind("[::1]:0").is_err() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        let (mut seeder, info_hash) = tiny_seeder("v6-seeder", SeederOptions { ipv6: true, ..Default::default() });
        assert!(seeder.ipv6);
        let over6 = handshake_over(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, seeder.port)), info_hash).expect("served over IPv6");
        assert_eq!(over6.info_hash, info_hash);
        let over4 = handshake_over(SocketAddr::from(([127, 0, 0, 1], seeder.port)), info_hash).expect("and over IPv4 still");
        assert_eq!(over4.info_hash, info_hash);
        seeder.stop();
        assert!(handshake_over(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, seeder.port)), info_hash).is_err(), "and stopping closes it");
    }

    #[test]
    fn without_ipv6_asked_for_the_seeder_listens_on_ipv4_only() {
        if std::net::TcpListener::bind("[::1]:0").is_err() {
            return;
        }
        let (mut seeder, info_hash) = tiny_seeder("v4-seeder", SeederOptions::default());
        assert!(!seeder.ipv6);
        assert!(handshake_over(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, seeder.port)), info_hash).is_err(), "nothing listens on IPv6");
        assert!(handshake_over(SocketAddr::from(([127, 0, 0, 1], seeder.port)), info_hash).is_ok());
        seeder.stop();
    }

    // ---- one listener, several torrents ----

    /// A torrent of one 256-byte piece filled with `fill`, registered on `listener`.
    fn register_tiny(listener: &Listener, name: &str, hash: [u8; 20], fill: u8) -> SeederHandle {
        let dir = tmp_dir(name);
        let spans = Arc::new(build_file_spans(&dir, &[(vec![format!("{}.bin", name)], 256)]));
        write_piece(&spans, 0, 256, &[fill; 256]).unwrap();
        let have = Arc::new(HaveMap::new(1));
        have.set(0);
        listener.register(hash, [0x20; 20], spans, 256, 256, have, None, SeederOptions::default())
    }

    /// Asks the listener at `port` for piece 0 of `hash`, as a leecher would.
    fn fetch_piece(port: u16, hash: [u8; 20]) -> std::io::Result<Vec<u8>> {
        let (mut stream, _) = std::panic::catch_unwind(|| leech_connect(port, hash)).map_err(|_| std::io::Error::other("the listener would not take that torrent"))?;
        Message::Interested.write_to(&mut stream).map_err(|e| std::io::Error::other(format!("{:?}", e)))?;
        loop {
            match Message::read_from(&mut stream) {
                Ok(Message::Unchoke) => break,
                Ok(_) => continue,
                Err(e) => return Err(std::io::Error::other(format!("{:?}", e))),
            }
        }
        Message::Request { index: 0, begin: 0, length: 256 }.write_to(&mut stream).map_err(|e| std::io::Error::other(format!("{:?}", e)))?;
        loop {
            match Message::read_from(&mut stream) {
                Ok(Message::Piece { block, .. }) => return Ok(block),
                Ok(_) => continue,
                Err(e) => return Err(std::io::Error::other(format!("{:?}", e))),
            }
        }
    }

    #[test]
    fn one_listener_serves_each_of_its_torrents_its_own_data_on_the_one_port() {
        let mut listener = Listener::start(0, ListenerOptions::default()).unwrap();
        let (a, b) = ([0xA1; 20], [0xB2; 20]);
        let mut first = register_tiny(&listener, "multi-a", a, 0x11);
        let mut second = register_tiny(&listener, "multi-b", b, 0x22);
        assert_eq!((first.port, second.port), (listener.port, listener.port), "the same port, to announce for both");
        assert_eq!(listener.torrent_count(), 2);

        assert_eq!(fetch_piece(listener.port, a).unwrap(), vec![0x11; 256]);
        assert_eq!(fetch_piece(listener.port, b).unwrap(), vec![0x22; 256]);

        first.stop();
        second.stop();
        listener.stop();
    }

    #[test]
    fn a_torrent_that_is_not_registered_is_refused_at_the_handshake() {
        let mut listener = Listener::start(0, ListenerOptions::default()).unwrap();
        let mut only = register_tiny(&listener, "multi-only", [0xA1; 20], 0x11);
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(&Handshake::new([0xEE; 20], [0x21; 20], false).to_bytes()).unwrap();
        let mut buf = [0u8; HANDSHAKE_LEN];
        assert!(stream.read_exact(&mut buf).is_err(), "no handshake back: the connection is closed");
        only.stop();
        listener.stop();
    }

    #[test]
    fn stopping_one_torrent_stops_serving_it_and_leaves_the_others() {
        let mut listener = Listener::start(0, ListenerOptions::default()).unwrap();
        let (a, b) = ([0xA1; 20], [0xB2; 20]);
        let mut first = register_tiny(&listener, "stop-a", a, 0x11);
        let mut second = register_tiny(&listener, "stop-b", b, 0x22);

        first.stop();

        assert_eq!(listener.torrent_count(), 1);
        assert!(fetch_piece(listener.port, a).is_err(), "the one that was stopped is refused");
        assert_eq!(fetch_piece(listener.port, b).unwrap(), vec![0x22; 256], "and the other is served as before");
        first.stop(); // and again is harmless
        second.stop();
        listener.stop();
    }

    #[test]
    fn a_torrent_registered_after_the_listener_is_running_is_served() {
        let mut listener = Listener::start(0, ListenerOptions::default()).unwrap();
        assert_eq!(listener.torrent_count(), 0);
        let mut late = register_tiny(&listener, "late", [0xC3; 20], 0x33);
        assert_eq!(fetch_piece(listener.port, [0xC3; 20]).unwrap(), vec![0x33; 256]);
        late.stop();
        listener.stop();
    }

    #[test]
    fn registering_a_torrent_again_replaces_it_and_the_old_handle_does_not_take_the_new_one_down() {
        let mut listener = Listener::start(0, ListenerOptions::default()).unwrap();
        let hash = [0xD4; 20];
        let mut old = register_tiny(&listener, "again-1", hash, 0x11);
        let (mut connected, _) = leech_connect(listener.port, hash);
        connected.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut new = register_tiny(&listener, "again-2", hash, 0x44);
        assert_eq!(listener.torrent_count(), 1);
        while Message::read_from(&mut connected).is_ok() {} // what was connected to the old registration is let go
        assert!(!old.torrent.running.load(Ordering::SeqCst) && new.torrent.running.load(Ordering::SeqCst));
        old.stop();
        assert_eq!(fetch_piece(listener.port, hash).unwrap(), vec![0x44; 256], "what the second registration serves");
        new.stop();
        listener.stop();
    }

    #[test]
    fn encrypted_peers_reach_the_torrent_they_prove_they_know_among_several() {
        use crate::peer::{connect_and_handshake_with, Encryption, Transport};
        let mut listener = Listener::start(0, ListenerOptions { encryption: Encryption::Prefer, ..Default::default() }).unwrap();
        let (a, b) = ([0xA1; 20], [0xB2; 20]);
        let mut first = register_tiny(&listener, "mse-a", a, 0x11);
        let mut second = register_tiny(&listener, "mse-b", b, 0x22);
        for (hash, fill) in [(a, 0x11u8), (b, 0x22)] {
            let addr = SocketAddr::from(([127, 0, 0, 1], listener.port));
            let (mut stream, theirs) = connect_and_handshake_with(addr, hash, [0x21; 20], false, false, Duration::from_secs(5), Encryption::Require, &Transport::default()).expect("an encrypted connection for one of several torrents");
            assert_eq!(theirs.info_hash, hash);
            Message::Interested.write_to(&mut stream).unwrap();
            let unchoked = loop {
                match Message::read_from(&mut stream).unwrap() {
                    Message::Unchoke => break true,
                    _ => continue,
                }
            };
            assert!(unchoked);
            Message::Request { index: 0, begin: 0, length: 256 }.write_to(&mut stream).unwrap();
            let block = loop {
                if let Message::Piece { block, .. } = Message::read_from(&mut stream).unwrap() {
                    break block;
                }
            };
            assert_eq!(block, vec![fill; 256]);
        }
        first.stop();
        second.stop();
        listener.stop();
    }

    #[test]
    fn a_listener_that_requires_encryption_turns_plain_peers_away_whatever_they_ask_for() {
        let mut listener = Listener::start(0, ListenerOptions { encryption: crate::peer::Encryption::Require, ..Default::default() }).unwrap();
        let mut only = register_tiny(&listener, "require", [0xA1; 20], 0x11);
        assert!(fetch_piece(listener.port, [0xA1; 20]).is_err());
        only.stop();
        listener.stop();
    }

    #[test]
    fn a_connected_peer_is_let_go_when_its_torrent_stops() {
        let mut listener = Listener::start(0, ListenerOptions::default()).unwrap();
        let mut only = register_tiny(&listener, "letgo", [0xA1; 20], 0x11);
        let (mut stream, _) = leech_connect(listener.port, [0xA1; 20]);
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        only.stop();

        let started = Instant::now();
        let ended = loop {
            match Message::read_from(&mut stream) {
                Ok(_) => continue,
                Err(_) => break true,
            }
        };
        assert!(ended && started.elapsed() < Duration::from_secs(5), "the connection ends: {:?}", started.elapsed());
        listener.stop();
    }

    #[test]
    fn the_cap_on_peers_served_is_for_the_listener_as_a_whole_not_each_torrent() {
        let mut listener = Listener::start(0, ListenerOptions::default()).unwrap();
        let mut first = register_tiny(&listener, "cap-a", [0xA1; 20], 0x11);
        let mut second = register_tiny(&listener, "cap-b", [0xB2; 20], 0x22);
        // Forty peers that connect and say nothing hold every place there is.
        let idle: Vec<TcpStream> = (0..MAX_INBOUND_PEERS).map(|_| TcpStream::connect(("127.0.0.1", listener.port)).unwrap()).collect();
        let until = Instant::now() + Duration::from_secs(5);
        while listener.registry.active_conns.load(Ordering::SeqCst) < MAX_INBOUND_PEERS && Instant::now() < until {
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(listener.registry.active_conns.load(Ordering::SeqCst), MAX_INBOUND_PEERS);

        assert!(fetch_piece(listener.port, [0xA1; 20]).is_err() && fetch_piece(listener.port, [0xB2; 20]).is_err(), "neither torrent gets a place");

        drop(idle); // the places free up
        let until = Instant::now() + Duration::from_secs(15);
        while fetch_piece(listener.port, [0xB2; 20]).is_err() {
            assert!(Instant::now() < until, "a place never came free");
            thread::sleep(Duration::from_millis(200));
        }
        first.stop();
        second.stop();
        listener.stop();
    }
}
