//! Local Service Discovery (BEP 14): finding peers on the same network by
//! multicast, with no tracker and no DHT.
//!
//! Each client announces the torrents it has, every few minutes, to a
//! multicast group that every other client on the link listens to:
//!
//! ```text
//! BT-SEARCH * HTTP/1.1\r\n
//! Host: 239.192.152.143:6771\r\n
//! Port: 6881\r\n
//! Infohash: 0123456789abcdef0123456789abcdef01234567\r\n
//! cookie: bittorrent-rs-1a2b3c4d\r\n
//! \r\n
//! \r\n
//! ```
//!
//! A client that hears one for a torrent it is on has a peer: the address the
//! datagram came from, on the port it names. The cookie is how a client
//! recognises its own announcement coming back round.
//!
//! What is heard is only ever a candidate to dial; nothing a datagram says is
//! trusted beyond that, and it is bounded like every other thing read off a
//! network. IPv4 only.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The multicast group and port BEP 14 uses for IPv4.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 192, 152, 143);
pub const PORT: u16 = 6771;

/// How often a torrent is announced. BEP 14 asks for no more than once in
/// five minutes.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

/// The least time between two announcements made in answer to newcomers.
pub const REPLY_INTERVAL: Duration = Duration::from_secs(20);

/// The largest announcement accepted: BEP 14 fits them in one packet.
const MAX_DATAGRAM: usize = 1400;
/// Most info hashes in one announcement (a client sends as many as fit).
const MAX_INFO_HASHES: usize = 16;
/// Longest cookie accepted.
const MAX_COOKIE: usize = 64;
/// How many peers one run remembers having reported, to say each once.
const MAX_REMEMBERED: usize = 1024;

const REQUEST_LINE: &str = "BT-SEARCH * HTTP/1.1";

/// A parsed announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    /// The sender's TCP listening port.
    pub port: u16,
    pub info_hashes: Vec<[u8; 20]>,
    pub cookie: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsdError {
    TooLong,
    NotText,
    NotAnAnnouncement,
    BadHeader(String),
    NoPort,
    NoInfoHash,
    TooManyInfoHashes,
}

impl std::fmt::Display for LsdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LsdError::TooLong => write!(f, "datagram is longer than an announcement can be"),
            LsdError::NotText => write!(f, "datagram is not text"),
            LsdError::NotAnAnnouncement => write!(f, "datagram is not a BT-SEARCH announcement"),
            LsdError::BadHeader(what) => write!(f, "bad header: {}", what),
            LsdError::NoPort => write!(f, "announcement has no usable port"),
            LsdError::NoInfoHash => write!(f, "announcement names no info hash"),
            LsdError::TooManyInfoHashes => write!(f, "announcement names too many info hashes"),
        }
    }
}

impl std::error::Error for LsdError {}

/// An announcement of `info_hash`, listening on TCP `port`, as sent to
/// `host` (the `Host` header; the group's address in practice).
pub fn announcement(host: SocketAddr, port: u16, info_hash: &[u8; 20], cookie: &str) -> Vec<u8> {
    let hex: String = info_hash.iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}\r\nHost: {}\r\nPort: {}\r\nInfohash: {}\r\ncookie: {}\r\n\r\n\r\n", REQUEST_LINE, host, port, hex, cookie).into_bytes()
}

fn parse_info_hash(text: &str) -> Option<[u8; 20]> {
    if text.len() != 40 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 20];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Reads one announcement from a datagram.
pub fn parse(datagram: &[u8]) -> Result<Announcement, LsdError> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(LsdError::TooLong);
    }
    let text = std::str::from_utf8(datagram).map_err(|_| LsdError::NotText)?;
    let mut lines = text.split('\n').map(|line| line.strip_suffix('\r').unwrap_or(line));
    if lines.next() != Some(REQUEST_LINE) {
        return Err(LsdError::NotAnAnnouncement);
    }
    let (mut port, mut info_hashes, mut cookie) = (None, Vec::new(), None);
    // Headers run to the first blank line.
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(LsdError::BadHeader(format!("{:?} has no colon", line.chars().take(40).collect::<String>())));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "port" if port.is_none() => port = Some(value.parse::<u16>().ok().filter(|&p| p != 0).ok_or(LsdError::NoPort)?),
            "infohash" => {
                if info_hashes.len() >= MAX_INFO_HASHES {
                    return Err(LsdError::TooManyInfoHashes);
                }
                info_hashes.push(parse_info_hash(value).ok_or_else(|| LsdError::BadHeader("an info hash that is not 40 hex digits".to_string()))?);
            }
            "cookie" if cookie.is_none() => {
                if value.len() > MAX_COOKIE {
                    return Err(LsdError::BadHeader("a cookie too long".to_string()));
                }
                cookie = Some(value.to_string());
            }
            _ => {} // Host, and whatever a newer version adds
        }
    }
    if info_hashes.is_empty() {
        return Err(LsdError::NoInfoHash);
    }
    Ok(Announcement { port: port.ok_or(LsdError::NoPort)?, info_hashes, cookie })
}

/// Where a service listens and announces.
#[derive(Debug, Clone)]
pub struct LsdConfig {
    /// Where announcements are sent: the multicast group, or in a test the
    /// address of whoever is to hear them.
    pub send_to: SocketAddr,
    /// The address to listen on.
    pub listen: SocketAddr,
    /// Join this multicast group on listening. `None` for a unicast test.
    pub join: Option<Ipv4Addr>,
    /// Let other clients on this machine listen on the same port, as they
    /// must for every one of them to hear the group.
    pub share_port: bool,
    pub interval: Duration,
    /// When a peer not heard of before announces, announce again at once, so
    /// that it learns of us too; but not more often than this. A client that
    /// starts hears those already running only if they say something, and
    /// they would otherwise not for another `interval`. (Counted from the last
    /// such answer, not from the last announcement of any kind: a newcomer
    /// usually turns up soon after we began.)
    pub reply_interval: Duration,
}

impl LsdConfig {
    /// The real thing: BEP 14's group and port.
    pub fn multicast() -> Self {
        LsdConfig { send_to: SocketAddr::from((GROUP, PORT)), listen: SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)), join: Some(GROUP), share_port: true, interval: ANNOUNCE_INTERVAL, reply_interval: REPLY_INTERVAL }
    }
}

/// A running discovery service: announces one torrent and reports the peers
/// that announce the same one.
pub struct LsdService {
    /// Batches of peer addresses heard of, to be dialed.
    pub peers_rx: Receiver<Vec<SocketAddr>>,
    /// Where it is listening.
    pub listen_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LsdService {
    /// Starts announcing `info_hash` (listening on TCP `tcp_port`) and
    /// listening for others. Fails if the socket cannot be set up, which a
    /// machine with no multicast route will do; the caller carries on
    /// without.
    pub fn start(config: LsdConfig, info_hash: [u8; 20], tcp_port: u16) -> io::Result<LsdService> {
        let socket = bind(&config)?;
        let listen_addr = socket.local_addr()?;
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        // One hop: the announcement is for this link, not beyond it. And loop
        // back, so that other clients on this very machine hear it.
        socket.set_multicast_ttl_v4(1)?;
        socket.set_multicast_loop_v4(true)?;

        let cookie = new_cookie();
        let (tx, peers_rx) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::Builder::new().name("lsd".to_string()).spawn(move || run(&socket, &config, info_hash, tcp_port, &cookie, &tx, &flag))?;
        Ok(LsdService { peers_rx, listen_addr, stop, handle: Some(handle) })
    }

    /// Stops the service and waits for its thread.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LsdService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn new_cookie() -> String {
    let mut random = [0u8; 4];
    // Without randomness the cookie only has to differ from another client's; the pid does that.
    if getrandom::getrandom(&mut random).is_err() {
        random = std::process::id().to_be_bytes();
    }
    format!("bittorrent-rs-{}", random.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

fn bind(config: &LsdConfig) -> io::Result<UdpSocket> {
    let socket = match config.listen {
        SocketAddr::V4(addr) if config.share_port => bind_shared(addr)?,
        addr => UdpSocket::bind(addr)?,
    };
    if let Some(group) = config.join {
        socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
    }
    Ok(socket)
}

/// A UDP socket on `addr` that other sockets may share. Every client on a
/// machine listens on the same LSD port, which an ordinary bind does not allow.
#[cfg(unix)]
fn bind_shared(addr: std::net::SocketAddrV4) -> io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain socket calls with valid arguments; the descriptor is
    // closed on every failure path and otherwise handed to the UdpSocket.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fail = |fd: libc::c_int| {
            let error = io::Error::last_os_error();
            libc::close(fd);
            Err(error)
        };
        let on: libc::c_int = 1;
        for option in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            if libc::setsockopt(fd, libc::SOL_SOCKET, option, &on as *const libc::c_int as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) < 0 {
                return fail(fd);
            }
        }
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = addr.port().to_be();
        sa.sin_addr = libc::in_addr { s_addr: u32::from(*addr.ip()).to_be() };
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
        {
            sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        if libc::bind(fd, &sa as *const libc::sockaddr_in as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) < 0 {
            return fail(fd);
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
}

#[cfg(not(unix))]
fn bind_shared(_addr: std::net::SocketAddrV4) -> io::Result<UdpSocket> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "sharing the LSD port is only implemented on Unix"))
}

fn run(socket: &UdpSocket, config: &LsdConfig, info_hash: [u8; 20], tcp_port: u16, cookie: &str, peers: &Sender<Vec<SocketAddr>>, stop: &AtomicBool) {
    let message = announcement(config.send_to, tcp_port, &info_hash, cookie);
    let mut next_announce = Instant::now();
    let mut last_reply: Option<Instant> = None;
    let mut reported: HashSet<SocketAddr> = HashSet::new();
    let mut buf = [0u8; MAX_DATAGRAM + 1];
    while !stop.load(Ordering::SeqCst) {
        if Instant::now() >= next_announce {
            // Best effort: a link with nobody on it, or none at all, is no failure.
            let _ = socket.send_to(&message, config.send_to);
            next_announce = Instant::now() + config.interval;
        }
        let (len, from) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => continue,
            // A datagram we could not take (a stray ICMP error, say) is not the end of discovery.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(_) => return,
        };
        let Some(peer) = heard(&buf[..len], from, &info_hash, cookie) else { continue };
        if reported.len() >= MAX_REMEMBERED {
            reported.clear();
        }
        if reported.insert(peer) {
            if peers.send(vec![peer]).is_err() {
                return; // nobody is listening any more
            }
            // Someone new: let them hear of us, without waiting for the next round.
            let now = Instant::now();
            if last_reply.is_none_or(|at| now.duration_since(at) >= config.reply_interval) {
                let _ = socket.send_to(&message, config.send_to);
                last_reply = Some(now);
                next_announce = now + config.interval;
            }
        }
    }
}

/// The peer a datagram from `from` tells of, if it announces `info_hash` and
/// is not our own announcement (`cookie`) coming back.
fn heard(datagram: &[u8], from: SocketAddr, info_hash: &[u8; 20], cookie: &str) -> Option<SocketAddr> {
    let announcement = parse(datagram).ok()?;
    if announcement.cookie.as_deref() == Some(cookie) || !announcement.info_hashes.contains(info_hash) {
        return None;
    }
    Some(SocketAddr::new(from.ip(), announcement.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 20] = [0xAB; 20];

    fn host() -> SocketAddr {
        SocketAddr::from((GROUP, PORT))
    }

    #[test]
    fn an_announcement_is_the_text_the_bep_shows() {
        let text = String::from_utf8(announcement(host(), 6881, &[0x01; 20], "cook")).unwrap();
        assert_eq!(text, "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\nInfohash: 0101010101010101010101010101010101010101\r\ncookie: cook\r\n\r\n\r\n");
    }

    #[test]
    fn what_is_built_is_read_back() {
        let parsed = parse(&announcement(host(), 51413, &HASH, "abc")).unwrap();
        assert_eq!(parsed, Announcement { port: 51413, info_hashes: vec![HASH], cookie: Some("abc".to_string()) });
    }

    #[test]
    fn other_clients_announcements_are_read_too() {
        // Lower-case header names, bare line feeds, upper-case hex, several hashes, no cookie.
        let text = "BT-SEARCH * HTTP/1.1\nHost: 239.192.152.143:6771\nport: 6881\ninfohash: ABABABABABABABABABABABABABABABABABABABAB\nInfoHash: 0000000000000000000000000000000000000001\n\n";
        let parsed = parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.port, 6881);
        assert_eq!(parsed.info_hashes, vec![HASH, { let mut h = [0u8; 20]; h[19] = 1; h }]);
        assert_eq!(parsed.cookie, None);
    }

    fn rejected(text: &str) -> LsdError {
        parse(text.as_bytes()).unwrap_err()
    }

    #[test]
    fn things_that_are_not_announcements_are_refused() {
        assert_eq!(rejected("GET / HTTP/1.1\r\n\r\n"), LsdError::NotAnAnnouncement);
        assert_eq!(rejected(""), LsdError::NotAnAnnouncement);
        assert_eq!(rejected("BT-SEARCH * HTTP/1.0\r\n\r\n"), LsdError::NotAnAnnouncement);
        assert_eq!(parse(&[0xFF, 0xFE, 0x00]), Err(LsdError::NotText));
        assert_eq!(parse(&vec![b'a'; MAX_DATAGRAM + 1]), Err(LsdError::TooLong));
    }

    #[test]
    fn a_port_that_cannot_be_dialed_is_refused() {
        let hash = "abababababababababababababababababababab";
        for port in ["0", "65536", "-1", "", "http", "6881x"] {
            let text = format!("BT-SEARCH * HTTP/1.1\r\nPort: {}\r\nInfohash: {}\r\n\r\n", port, hash);
            assert_eq!(rejected(&text), LsdError::NoPort, "port {:?}", port);
        }
        assert_eq!(rejected(&format!("BT-SEARCH * HTTP/1.1\r\nInfohash: {}\r\n\r\n", hash)), LsdError::NoPort, "no port at all");
    }

    #[test]
    fn a_bad_or_missing_info_hash_is_refused() {
        assert_eq!(rejected("BT-SEARCH * HTTP/1.1\r\nPort: 1\r\n\r\n"), LsdError::NoInfoHash);
        for hash in ["", "abab", "zzabababababababababababababababababababab", &"ab".repeat(21), &format!("{}é", "a".repeat(38))] {
            let text = format!("BT-SEARCH * HTTP/1.1\r\nPort: 1\r\nInfohash: {}\r\n\r\n", hash);
            assert!(matches!(rejected(&text), LsdError::BadHeader(_)), "hash {:?}", hash);
        }
    }

    #[test]
    fn a_header_without_a_colon_is_refused() {
        assert!(matches!(rejected("BT-SEARCH * HTTP/1.1\r\nPort 6881\r\n\r\n"), LsdError::BadHeader(_)));
    }

    #[test]
    fn the_count_of_info_hashes_and_the_length_of_the_cookie_are_bounded() {
        let one = "abababababababababababababababababababab";
        let many = |n: usize| format!("BT-SEARCH * HTTP/1.1\r\nPort: 1\r\n{}\r\n", format!("Infohash: {}\r\n", one).repeat(n));
        assert_eq!(parse(many(MAX_INFO_HASHES).as_bytes()).unwrap().info_hashes.len(), MAX_INFO_HASHES);
        assert_eq!(rejected(&many(MAX_INFO_HASHES + 1)), LsdError::TooManyInfoHashes);
        let cookie = |n: usize| format!("BT-SEARCH * HTTP/1.1\r\nPort: 1\r\nInfohash: {}\r\ncookie: {}\r\n\r\n", one, "c".repeat(n));
        assert!(parse(cookie(MAX_COOKIE).as_bytes()).is_ok());
        assert!(matches!(rejected(&cookie(MAX_COOKIE + 1)), LsdError::BadHeader(_)));
    }

    #[test]
    fn headers_stop_at_the_blank_line() {
        // Whatever follows is not part of the announcement.
        let text = "BT-SEARCH * HTTP/1.1\r\nPort: 7\r\nInfohash: abababababababababababababababababababab\r\n\r\nPort: 8\r\nnonsense with no colon\r\n";
        assert_eq!(parse(text.as_bytes()).unwrap().port, 7);
    }

    #[test]
    fn a_first_port_or_cookie_wins_over_a_repeat() {
        let text = "BT-SEARCH * HTTP/1.1\r\nPort: 7\r\nPort: 8\r\ncookie: a\r\ncookie: b\r\nInfohash: abababababababababababababababababababab\r\n\r\n";
        let parsed = parse(text.as_bytes()).unwrap();
        assert_eq!((parsed.port, parsed.cookie.as_deref()), (7, Some("a")));
    }

    fn from(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, 9], port))
    }

    #[test]
    fn a_peer_is_the_sender_on_the_port_it_names() {
        let datagram = announcement(host(), 6881, &HASH, "theirs");
        // The datagram came from some other port; the address to dial is the port announced.
        assert_eq!(heard(&datagram, from(40000), &HASH, "mine"), Some(from(6881)));
    }

    #[test]
    fn our_own_announcement_and_other_torrents_are_not_peers() {
        assert_eq!(heard(&announcement(host(), 6881, &HASH, "mine"), from(1), &HASH, "mine"), None, "our own, come back");
        assert_eq!(heard(&announcement(host(), 6881, &[0x11; 20], "theirs"), from(1), &HASH, "mine"), None, "another torrent");
        assert_eq!(heard(b"garbage", from(1), &HASH, "mine"), None);
    }

    #[test]
    fn a_torrent_among_several_is_found() {
        let text = format!("BT-SEARCH * HTTP/1.1\r\nPort: 99\r\nInfohash: {}\r\nInfohash: {}\r\n\r\n", "11".repeat(20), "ab".repeat(20));
        assert_eq!(heard(text.as_bytes(), from(1), &HASH, "mine"), Some(from(99)));
    }

    #[test]
    fn a_datagram_without_a_cookie_is_still_taken() {
        let text = format!("BT-SEARCH * HTTP/1.1\r\nPort: 99\r\nInfohash: {}\r\n\r\n", "ab".repeat(20));
        assert_eq!(heard(text.as_bytes(), from(1), &HASH, "mine"), Some(from(99)));
    }

    #[test]
    fn cookies_differ_between_runs() {
        assert_ne!(new_cookie(), new_cookie());
    }

    // ---- two services, over loopback ------------------------------------

    /// A config that listens on an ephemeral loopback port and announces to `send_to`.
    fn loopback(send_to: SocketAddr, interval: Duration) -> LsdConfig {
        LsdConfig { send_to, listen: SocketAddr::from(([127, 0, 0, 1], 0)), join: None, share_port: false, interval , reply_interval: Duration::from_secs(3600) }
    }

    /// Two sockets that each know the other's address are two clients on one link.
    fn pair() -> (UdpSocket, UdpSocket) {
        (UdpSocket::bind("127.0.0.1:0").unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap())
    }

    #[test]
    fn a_service_announces_and_says_whose_torrent() {
        let (listener, _) = pair();
        listener.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut service = LsdService::start(loopback(listener.local_addr().unwrap(), Duration::from_secs(60)), HASH, 6881).unwrap();

        let mut buf = [0u8; 2000];
        let (len, _) = listener.recv_from(&mut buf).expect("it announces at once");
        let heard = parse(&buf[..len]).unwrap();
        assert_eq!((heard.port, heard.info_hashes), (6881, vec![HASH]));
        assert!(heard.cookie.is_some_and(|c| c.starts_with("bittorrent-rs-")));
        service.stop();
    }

    #[test]
    fn it_announces_again_after_the_interval_and_not_before() {
        let (listener, _) = pair();
        listener.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let mut service = LsdService::start(loopback(listener.local_addr().unwrap(), Duration::from_millis(1500)), HASH, 6881).unwrap();
        let mut buf = [0u8; 2000];
        assert!(listener.recv_from(&mut buf).is_ok(), "the first");
        assert!(listener.recv_from(&mut buf).is_err(), "nothing 700 ms later");
        listener.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(listener.recv_from(&mut buf).is_ok(), "the second, once the interval is up");
        service.stop();
    }

    #[test]
    fn a_peer_that_announces_the_same_torrent_is_reported_once() {
        let (sender, _) = pair();
        // The service announces to nobody in particular (the sender's own socket, unread).
        let mut service = LsdService::start(loopback(sender.local_addr().unwrap(), Duration::from_secs(60)), HASH, 6881).unwrap();
        let datagram = announcement(host(), 7000, &HASH, "someone-else");
        for _ in 0..3 {
            sender.send_to(&datagram, service.listen_addr).unwrap();
        }
        let batch = service.peers_rx.recv_timeout(Duration::from_secs(5)).expect("a peer");
        assert_eq!(batch, vec![SocketAddr::from(([127, 0, 0, 1], 7000))]);
        thread::sleep(Duration::from_millis(500));
        assert!(service.peers_rx.try_recv().is_err(), "the repeats add nothing");
        service.stop();
    }

    #[test]
    fn its_own_announcement_arriving_back_is_not_a_peer() {
        // Announces to its own address, as a multicast group it has joined would.
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        let mut service = LsdService::start(LsdConfig { send_to: addr, listen: addr, join: None, share_port: false, interval: Duration::from_millis(100), reply_interval: Duration::from_secs(3600) }, HASH, 6881).unwrap();
        thread::sleep(Duration::from_millis(700));
        assert!(service.peers_rx.try_recv().is_err(), "several announcements went round, none was taken for a peer");
        service.stop();
    }

    #[test]
    fn junk_and_other_torrents_over_the_wire_are_ignored_and_the_service_carries_on() {
        let (sender, _) = pair();
        let mut service = LsdService::start(loopback(sender.local_addr().unwrap(), Duration::from_secs(60)), HASH, 6881).unwrap();
        sender.send_to(b"\xff\xff\xff", service.listen_addr).unwrap();
        sender.send_to(&vec![b'x'; 5000], service.listen_addr).unwrap();
        sender.send_to(&announcement(host(), 7000, &[0x22; 20], "x"), service.listen_addr).unwrap();
        sender.send_to(&announcement(host(), 7001, &HASH, "x"), service.listen_addr).unwrap();
        let batch = service.peers_rx.recv_timeout(Duration::from_secs(5)).expect("the good one still arrives");
        assert_eq!(batch, vec![SocketAddr::from(([127, 0, 0, 1], 7001))]);
        service.stop();
    }

    #[test]
    fn one_service_finds_another_by_its_announcement() {
        // B announces to nowhere in particular; A, told where B listens, announces there.
        let mut b = LsdService::start(loopback(SocketAddr::from(([127, 0, 0, 1], 9)), Duration::from_secs(60)), HASH, 2222).unwrap();
        let mut a = LsdService::start(loopback(b.listen_addr, Duration::from_secs(60)), HASH, 1111).unwrap();
        let batch = b.peers_rx.recv_timeout(Duration::from_secs(5)).expect("B hears A");
        assert_eq!(batch, vec![SocketAddr::from(([127, 0, 0, 1], 1111))], "the address it came from, on the port A announced");
        assert!(a.peers_rx.try_recv().is_err(), "and A, which nobody announced to, heard of no one");
        a.stop();
        b.stop();
    }

    #[test]
    fn stopping_ends_the_thread_promptly() {
        let mut service = LsdService::start(loopback(SocketAddr::from(([127, 0, 0, 1], 9)), Duration::from_secs(60)), HASH, 6881).unwrap();
        let started = Instant::now();
        service.stop();
        assert!(started.elapsed() < Duration::from_secs(2));
        service.stop(); // and again is harmless
    }

    #[cfg(unix)]
    #[test]
    fn two_services_with_a_shared_port_can_both_listen_on_it() {
        // As every client on one machine must, on the real port.
        let config = |port: u16| LsdConfig { send_to: SocketAddr::from(([127, 0, 0, 1], 9)), listen: SocketAddr::from(([127, 0, 0, 1], port)), join: None, share_port: true, interval: Duration::from_secs(60), reply_interval: Duration::from_secs(3600) };
        let mut first = LsdService::start(config(0), HASH, 1).unwrap();
        let mut second = LsdService::start(config(first.listen_addr.port()), HASH, 2).expect("a second listener on the same port");
        first.stop();
        second.stop();
    }

    /// The real group, between two services on this machine. A machine with no
    /// multicast route (a container, say) cannot do it, and the test says so and passes.
    #[cfg(unix)]
    #[test]
    fn two_services_on_the_real_multicast_group_find_each_other() {
        let config = LsdConfig { interval: Duration::from_millis(200), ..LsdConfig::multicast() };
        let (mut a, mut b) = match (LsdService::start(config.clone(), HASH, 1111), LsdService::start(config, HASH, 2222)) {
            (Ok(a), Ok(b)) => (a, b),
            (a, b) => {
                eprintln!("no multicast here ({:?}, {:?}); the group is not tested", a.err(), b.err());
                return;
            }
        };
        // Everything each hears for up to fifteen seconds, or until both have heard something.
        let (mut heard_by_a, mut heard_by_b) = (Vec::new(), Vec::new());
        let until = Instant::now() + Duration::from_secs(15);
        while (heard_by_a.is_empty() || heard_by_b.is_empty()) && Instant::now() < until {
            heard_by_a.extend(a.peers_rx.try_iter().flatten().map(|p| p.port()));
            heard_by_b.extend(b.peers_rx.try_iter().flatten().map(|p| p.port()));
            thread::sleep(Duration::from_millis(50));
        }
        if heard_by_a.is_empty() && heard_by_b.is_empty() {
            eprintln!("multicast joined but nothing came back (a firewall, or loopback of multicast is off); the group is not tested");
        } else {
            assert!(heard_by_a.iter().all(|&p| p == 2222) && heard_by_b.iter().all(|&p| p == 1111), "each hears the other and never itself: A heard {:?}, B heard {:?}", heard_by_a, heard_by_b);
            if heard_by_a.is_empty() || heard_by_b.is_empty() {
                // Where multicast is slow to start (the first datagram has taken several seconds), one side may not have heard yet.
                eprintln!("only one side heard within the wait: A {:?}, B {:?}", heard_by_a, heard_by_b);
            }
        }
        a.stop();
        b.stop();
    }

    #[cfg(unix)]
    #[test]
    fn two_sockets_can_share_the_port_on_unix() {
        let first = bind_shared(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = first.local_addr().unwrap().port();
        let second = bind_shared(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)).expect("SO_REUSEPORT lets a second one in");
        assert_eq!(second.local_addr().unwrap().port(), port);
        assert!(UdpSocket::bind(("127.0.0.1", port)).is_err(), "where an ordinary bind would not");
    }

    fn replying(send_to: SocketAddr, reply_interval: Duration) -> LsdConfig {
        LsdConfig { reply_interval, ..loopback(send_to, Duration::from_secs(3600)) }
    }

    #[test]
    fn a_newcomer_that_announces_is_answered_at_once_and_not_left_until_the_next_round() {
        let watcher = UdpSocket::bind("127.0.0.1:0").unwrap();
        watcher.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut service = LsdService::start(replying(watcher.local_addr().unwrap(), Duration::from_millis(100)), HASH, 6881).unwrap();
        let mut buf = [0u8; 2000];
        watcher.recv_from(&mut buf).expect("its own first announcement");
        // (The regular round is an hour away.)

        let neighbour = UdpSocket::bind("127.0.0.1:0").unwrap();
        thread::sleep(Duration::from_millis(150));
        neighbour.send_to(&announcement(host(), 7000, &HASH, "the-neighbour"), service.listen_addr).unwrap();

        let (len, _) = watcher.recv_from(&mut buf).expect("and it announces again, to let the newcomer hear it");
        assert_eq!(parse(&buf[..len]).unwrap().port, 6881);
        service.stop();
    }

    #[test]
    fn answers_to_newcomers_are_no_more_frequent_than_the_reply_interval_and_only_for_new_ones() {
        let watcher = UdpSocket::bind("127.0.0.1:0").unwrap();
        watcher.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
        let mut service = LsdService::start(replying(watcher.local_addr().unwrap(), Duration::from_secs(3600)), HASH, 6881).unwrap();
        let mut buf = [0u8; 2000];
        watcher.recv_from(&mut buf).unwrap(); // its first, at start

        let neighbour = UdpSocket::bind("127.0.0.1:0").unwrap();
        for port in [7001, 7002, 7003] {
            neighbour.send_to(&announcement(host(), port, &HASH, "n"), service.listen_addr).unwrap();
        }
        watcher.recv_from(&mut buf).expect("the first newcomer is answered, though the service began only a moment ago");
        assert!(watcher.recv_from(&mut buf).is_err(), "and the other two, within the interval of that answer, are not");
        service.stop();

        let mut service = LsdService::start(replying(watcher.local_addr().unwrap(), Duration::from_millis(50)), HASH, 6881).unwrap();
        watcher.recv_from(&mut buf).unwrap();
        thread::sleep(Duration::from_millis(100));
        for _ in 0..3 {
            neighbour.send_to(&announcement(host(), 7005, &HASH, "n"), service.listen_addr).unwrap();
        }
        watcher.recv_from(&mut buf).expect("one answer, for the newcomer");
        assert!(watcher.recv_from(&mut buf).is_err(), "and none for the same one saying it again");
        service.stop();
    }
}
