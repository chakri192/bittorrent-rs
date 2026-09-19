//! uTP over a real UDP socket: one socket carries any number of connections,
//! each a blocking byte stream like a TCP one.
//!
//! A thread reads the socket and hands each datagram to the connection it
//! belongs to (found by the peer's address and the connection id), and
//! every few milliseconds lets each connection deal with timers. The
//! protocol itself is in [`Connection`](super::conn::Connection), which
//! knows nothing of sockets or threads; this is the part that does.
//!
//! A datagram that is not uTP is handed to whoever asked for those, which is
//! how the DHT can use the same UDP port: its messages begin with `d`, and
//! no uTP packet does.

use super::conn::{Connection, State};
use super::packet::{Packet, PacketError, PacketType};
use crate::peer::{Closer, PeerStream};
use crate::sync::lock;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How often connections are given the time.
const TICK: Duration = Duration::from_millis(5);
/// Connections waiting to be accepted, beyond which requests are ignored.
const MAX_PENDING: usize = 32;
/// How long a connection the application has let go of is given to get its
/// last data and its FIN across.
const LINGER: Duration = Duration::from_secs(20);

type Key = (SocketAddr, u16);

/// A datagram that is not uTP, and who sent it.
pub type Foreign = (Vec<u8>, SocketAddr);

/// One connection: the state machine, and what a blocked reader or writer
/// waits on.
struct Link {
    remote: SocketAddr,
    conn: Mutex<Connection>,
    changed: Condvar,
    /// When the application let go of it.
    abandoned: Mutex<Option<Instant>>,
}

struct Shared {
    socket: UdpSocket,
    links: Mutex<HashMap<Key, Arc<Link>>>,
    pending: Mutex<VecDeque<UtpStream>>,
    pending_changed: Condvar,
    accepting: AtomicBool,
    stop: AtomicBool,
    /// Where datagrams that are not uTP go.
    others: Mutex<Option<Sender<Foreign>>>,
}

impl Shared {
    fn send_all(&self, to: SocketAddr, datagrams: Vec<Vec<u8>>) {
        for datagram in datagrams {
            // Best effort: a datagram that does not go is one the protocol will send again.
            let _ = self.socket.send_to(&datagram, to);
        }
    }

    /// Sends what `link`'s connection has to say.
    fn flush(&self, link: &Link, now: Instant) {
        let out = {
            let mut conn = lock(&link.conn);
            conn.flush(now);
            conn.take_outgoing()
        };
        self.send_all(link.remote, out);
    }

    fn insert(&self, key: Key, link: &Arc<Link>) {
        lock(&self.links).insert(key, Arc::clone(link));
    }

    fn handle(self: &Arc<Self>, datagram: &[u8], from: SocketAddr, now: Instant) {
        let packet = match Packet::decode(datagram) {
            Ok(packet) => packet,
            Err(PacketError::NotUtp) => {
                if let Some(tx) = lock(&self.others).as_ref() {
                    let _ = tx.send((datagram.to_vec(), from));
                }
                return;
            }
            Err(_) => return,
        };
        // A request is filed under the id its sender will be answered on, plus one.
        let key = (from, if packet.kind == PacketType::Syn { packet.connection_id.wrapping_add(1) } else { packet.connection_id });
        let existing = lock(&self.links).get(&key).cloned();
        if let Some(link) = existing {
            let out = {
                let mut conn = lock(&link.conn);
                conn.on_packet(now, &packet);
                conn.take_outgoing()
            };
            link.changed.notify_all();
            self.send_all(from, out);
            return;
        }
        match packet.kind {
            PacketType::Syn if self.accepting.load(Ordering::SeqCst) && lock(&self.pending).len() < MAX_PENDING => {
                let mut conn = Connection::accept(now, &packet, random_u16());
                let out = conn.take_outgoing();
                let link = Arc::new(Link { remote: from, conn: Mutex::new(conn), changed: Condvar::new(), abandoned: Mutex::new(None) });
                self.insert(key, &link);
                self.send_all(from, out);
                lock(&self.pending).push_back(UtpStream::new(Arc::clone(self), link));
                self.pending_changed.notify_all();
            }
            // A connection we know nothing of: say so, unless it is itself a reset.
            PacketType::Reset | PacketType::Syn => {}
            _ => {
                let reset = Packet { kind: PacketType::Reset, connection_id: packet.connection_id, timestamp: 0, timestamp_diff: 0, wnd_size: 0, seq_nr: random_u16(), ack_nr: packet.seq_nr, sack: Vec::new(), payload: Vec::new() };
                self.send_all(from, vec![reset.encode()]);
            }
        }
    }

    /// Timers, for every connection; and forgetting the ones that are over.
    fn tick(&self, now: Instant) {
        let links: Vec<(Key, Arc<Link>)> = lock(&self.links).iter().map(|(k, l)| (*k, Arc::clone(l))).collect();
        let mut gone = Vec::new();
        for (key, link) in links {
            let (out, finished) = {
                let mut conn = lock(&link.conn);
                conn.on_tick(now);
                let abandoned = *lock(&link.abandoned);
                let over = conn.is_finished() && (abandoned.is_some() || conn.error().is_some());
                let lingered = abandoned.is_some_and(|at| now.duration_since(at) >= LINGER || (conn.is_flushed() && conn.fin_acked()));
                (conn.take_outgoing(), over || lingered)
            };
            link.changed.notify_all();
            self.send_all(link.remote, out);
            if finished {
                gone.push(key);
            }
        }
        if !gone.is_empty() {
            let mut links = lock(&self.links);
            for key in gone {
                links.remove(&key);
            }
        }
    }

    /// Ends every connection, as a socket going away must.
    fn abort_all(&self) {
        let links: Vec<Arc<Link>> = lock(&self.links).drain().map(|(_, l)| l).collect();
        for link in links {
            let out = {
                let mut conn = lock(&link.conn);
                conn.abort(Instant::now());
                conn.take_outgoing()
            };
            link.changed.notify_all();
            self.send_all(link.remote, out);
        }
        self.pending_changed.notify_all();
    }
}

fn random_u16() -> u16 {
    let mut bytes = [0u8; 2];
    if getrandom::getrandom(&mut bytes).is_err() {
        // Without randomness, the clock will do: nothing here depends on it being unguessable.
        return Instant::now().elapsed().subsec_nanos() as u16 ^ std::process::id() as u16;
    }
    u16::from_be_bytes(bytes)
}

/// A UDP port speaking uTP.
pub struct UtpSocket {
    shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
}

impl UtpSocket {
    /// Binds `addr` and starts serving it.
    pub fn bind(addr: SocketAddr) -> io::Result<UtpSocket> {
        UtpSocket::with_socket(UdpSocket::bind(addr)?, None)
    }

    /// Serves `socket`. Datagrams that are not uTP go to `others`, if given.
    pub fn with_socket(socket: UdpSocket, others: Option<Sender<Foreign>>) -> io::Result<UtpSocket> {
        socket.set_read_timeout(Some(TICK))?;
        let shared = Arc::new(Shared { socket, links: Mutex::new(HashMap::new()), pending: Mutex::new(VecDeque::new()), pending_changed: Condvar::new(), accepting: AtomicBool::new(false), stop: AtomicBool::new(false), others: Mutex::new(others) });
        let serving = Arc::clone(&shared);
        let handle = thread::Builder::new().name("utp".to_string()).spawn(move || serve(&serving))?;
        Ok(UtpSocket { shared, handle: Some(handle) })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.shared.socket.local_addr()
    }

    /// Sends a datagram that is not uTP from this socket, as the DHT does.
    pub fn send_other(&self, data: &[u8], to: SocketAddr) -> io::Result<()> {
        self.shared.socket.send_to(data, to).map(|_| ())
    }

    /// Starts taking connection requests. Until then they are ignored.
    pub fn listen(&self) {
        self.shared.accepting.store(true, Ordering::SeqCst);
    }

    /// The next connection a peer has made to us, waiting up to `timeout`.
    pub fn accept(&self, timeout: Duration) -> Option<UtpStream> {
        let deadline = Instant::now() + timeout;
        let mut pending = lock(&self.shared.pending);
        loop {
            if let Some(stream) = pending.pop_front() {
                return Some(stream);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            if self.shared.stop.load(Ordering::SeqCst) {
                return None;
            }
            pending = match self.shared.pending_changed.wait_timeout(pending, left) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    /// Opens a connection to `addr`, waiting up to `timeout` for the answer.
    pub fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<UtpStream> {
        let now = Instant::now();
        let (recv_id, link) = {
            let mut links = lock(&self.shared.links);
            // An id no other connection to this peer is using, on either of its two ids.
            let recv_id = (0..64).map(|_| random_u16()).find(|id| !links.contains_key(&(addr, *id)) && !links.contains_key(&(addr, id.wrapping_add(1)))).ok_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "no free connection id"))?;
            let conn = Connection::connect(now, recv_id);
            let link = Arc::new(Link { remote: addr, conn: Mutex::new(conn), changed: Condvar::new(), abandoned: Mutex::new(None) });
            links.insert((addr, recv_id), Arc::clone(&link));
            (recv_id, link)
        };
        let out = lock(&link.conn).take_outgoing();
        self.shared.send_all(addr, out);

        let deadline = now + timeout;
        let mut conn = lock(&link.conn);
        let result = loop {
            match (conn.state(), conn.error()) {
                (State::Open, _) => break Ok(()),
                (State::Ended, error) => break Err(io::Error::new(error.unwrap_or(io::ErrorKind::ConnectionAborted), "uTP connection failed")),
                (State::Connecting, _) => {}
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else { break Err(io::Error::new(io::ErrorKind::TimedOut, "uTP connect timed out")) };
            conn = match link.changed.wait_timeout(conn, left) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        };
        drop(conn);
        match result {
            Ok(()) => Ok(UtpStream::new(Arc::clone(&self.shared), link)),
            Err(e) => {
                lock(&self.shared.links).remove(&(addr, recv_id));
                Err(e)
            }
        }
    }

    /// How many connections are being kept.
    pub fn connection_count(&self) -> usize {
        lock(&self.shared.links).len()
    }
}

impl Drop for UtpSocket {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.pending_changed.notify_all();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        // Connections never accepted hold the shared state, which holds them; break the loop
        // so the socket is closed and the port is free.
        lock(&self.shared.pending).clear();
    }
}

fn serve(shared: &Arc<Shared>) {
    let mut buf = vec![0u8; 65_536];
    let mut last_tick = Instant::now();
    while !shared.stop.load(Ordering::SeqCst) {
        match shared.socket.recv_from(&mut buf) {
            Ok((len, from)) => shared.handle(&buf[..len], from, Instant::now()),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionReset) => {}
            Err(_) => break,
        }
        let now = Instant::now();
        if now.duration_since(last_tick) >= TICK {
            shared.tick(now);
            last_tick = now;
        }
    }
    shared.abort_all();
}

/// A uTP connection, used like a TCP stream.
pub struct UtpStream {
    shared: Arc<Shared>,
    link: Arc<Link>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
}

impl std::fmt::Debug for UtpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UtpStream({})", self.link.remote)
    }
}

impl UtpStream {
    fn new(shared: Arc<Shared>, link: Arc<Link>) -> UtpStream {
        UtpStream { shared, link, read_timeout: Mutex::new(None), write_timeout: Mutex::new(None) }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.link.remote
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "uTP operation timed out")
}

fn wait<'a>(link: &'a Link, guard: std::sync::MutexGuard<'a, Connection>, deadline: Option<Instant>) -> io::Result<std::sync::MutexGuard<'a, Connection>> {
    let wait = match deadline {
        None => Duration::from_secs(1), // woken sooner by any change; the bound is only to notice a stop
        Some(deadline) => deadline.checked_duration_since(Instant::now()).ok_or_else(timed_out)?,
    };
    Ok(match link.changed.wait_timeout(guard, wait) {
        Ok((guard, _)) => guard,
        Err(poisoned) => poisoned.into_inner().0,
    })
}

impl Read for UtpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = (*lock(&self.read_timeout)).map(|t| Instant::now() + t);
        let mut conn = lock(&self.link.conn);
        loop {
            let n = conn.read(buf);
            if n > 0 {
                // (Room made in the buffer is told to the sender by the next tick.)
                return Ok(n);
            }
            if conn.is_eof() {
                return Ok(0);
            }
            if let Some(error) = conn.error() {
                return Err(io::Error::new(error, "uTP connection ended"));
            }
            if conn.is_finished() {
                return Ok(0);
            }
            conn = wait(&self.link, conn, deadline)?;
        }
    }
}

impl Write for UtpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = (*lock(&self.write_timeout)).map(|t| Instant::now() + t);
        let mut conn = lock(&self.link.conn);
        loop {
            if let Some(error) = conn.error() {
                return Err(io::Error::new(error, "uTP connection ended"));
            }
            if conn.is_finished() {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "uTP connection is closed"));
            }
            let n = conn.write(buf);
            if n > 0 {
                conn.flush(Instant::now());
                let out = conn.take_outgoing();
                drop(conn);
                self.shared.send_all(self.link.remote, out);
                return Ok(n);
            }
            conn = wait(&self.link, conn, deadline)?;
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for UtpStream {
    fn drop(&mut self) {
        // Let go: what was written is still sent, then the FIN, and the socket
        // forgets the connection once that is done or has taken too long.
        *lock(&self.link.abandoned) = Some(Instant::now());
        lock(&self.link.conn).close();
        self.shared.flush(&self.link, Instant::now());
    }
}

struct UtpCloser {
    shared: Arc<Shared>,
    link: Arc<Link>,
}

impl std::fmt::Debug for UtpCloser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UtpCloser({})", self.link.remote)
    }
}

impl Closer for UtpCloser {
    fn close(&self) {
        let out = {
            let mut conn = lock(&self.link.conn);
            conn.abort(Instant::now());
            conn.take_outgoing()
        };
        self.link.changed.notify_all();
        self.shared.send_all(self.link.remote, out);
    }
}

impl PeerStream for UtpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *lock(&self.read_timeout) = timeout;
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        *lock(&self.write_timeout) = timeout;
        Ok(())
    }

    fn closer(&self) -> io::Result<Arc<dyn Closer>> {
        Ok(Arc::new(UtpCloser { shared: Arc::clone(&self.shared), link: Arc::clone(&self.link) }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn loopback() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
    }

    /// A listening socket and a connected pair of streams: (client, server, the two sockets).
    fn connected() -> (UtpStream, UtpStream, UtpSocket, UtpSocket) {
        let server = UtpSocket::bind(loopback()).unwrap();
        server.listen();
        let client = UtpSocket::bind(loopback()).unwrap();
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, server.local_addr().unwrap().port()));
        let stream = client.connect(to, Duration::from_secs(5)).expect("connects");
        let accepted = server.accept(Duration::from_secs(5)).expect("the server sees the connection");
        (stream, accepted, client, server)
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u32).wrapping_mul(2654435761) as u8 ^ (i >> 8) as u8).collect()
    }

    #[test]
    fn a_connection_is_made_and_bytes_go_both_ways() {
        let (mut client, mut server, _c, _s) = connected();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        client.write_all(b"hello over uTP").unwrap();
        let mut got = [0u8; 14];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello over uTP");

        server.write_all(b"and back").unwrap();
        let mut got = [0u8; 8];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"and back");
    }

    #[test]
    fn a_large_transfer_over_real_udp_arrives_intact() {
        let (mut client, mut server, _c, _s) = connected();
        let data = pattern(3_000_000);
        let expect = data.clone();
        let writer = thread::spawn(move || {
            client.write_all(&data).unwrap();
            client // kept until the reader is done, so it is not closed early
        });
        server.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut got = vec![0u8; expect.len()];
        server.read_exact(&mut got).unwrap();
        assert!(got == expect);
        drop(writer.join().unwrap());
    }

    #[test]
    fn the_end_of_a_stream_is_seen_when_the_other_side_lets_go() {
        let (mut client, mut server, _c, _s) = connected();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.write_all(b"the last words").unwrap();
        drop(client);

        let mut all = Vec::new();
        server.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"the last words", "everything, then the end");
    }

    #[test]
    fn a_read_gives_up_after_its_timeout_and_the_error_is_one_the_workers_treat_as_quiet() {
        let (mut client, _server, _c, _s) = connected();
        client.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        let started = Instant::now();
        let err = client.read(&mut [0u8; 1]).unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock), "{:?}", err);
        assert!(started.elapsed() >= Duration::from_millis(140) && started.elapsed() < Duration::from_secs(2));
        // And the connection is fine afterwards.
        _server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut server = _server;
        client.write_all(b"x").unwrap();
        assert_eq!(server.read(&mut [0u8; 1]).unwrap(), 1);
    }

    #[test]
    fn a_closer_ends_a_read_blocked_on_another_thread_at_once() {
        let (mut client, _server, _c, _s) = connected();
        let closer = client.closer().unwrap();
        let reader = thread::spawn(move || {
            let started = Instant::now();
            let result = client.read(&mut [0u8; 1]);
            (result.is_err() || result.is_ok_and(|n| n == 0), started.elapsed())
        });
        thread::sleep(Duration::from_millis(200));

        closer.close();

        let (ended, waited) = reader.join().unwrap();
        assert!(ended && waited < Duration::from_secs(3), "{:?}", waited);
    }

    #[test]
    fn closing_from_one_end_reaches_the_other_as_a_reset() {
        let (client, mut server, _c, _s) = connected();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.closer().unwrap().close();
        let err = server.read(&mut [0u8; 1]).unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::ConnectionReset), "{:?}", err);
    }

    #[test]
    fn nobody_listening_is_a_timeout_not_a_hang() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UtpSocket::bind(loopback()).unwrap();
        let started = Instant::now();
        let err = client.connect(silent.local_addr().unwrap(), Duration::from_millis(400)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(client.connection_count(), 0, "and nothing is left behind");
    }

    #[test]
    fn a_socket_that_is_not_listening_ignores_requests_and_one_that_is_answers_them() {
        let quiet = UtpSocket::bind(loopback()).unwrap();
        let client = UtpSocket::bind(loopback()).unwrap();
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, quiet.local_addr().unwrap().port()));
        assert!(client.connect(to, Duration::from_millis(300)).is_err());
        assert!(quiet.accept(Duration::from_millis(50)).is_none());
        quiet.listen();
        assert!(client.connect(to, Duration::from_secs(5)).is_ok());
        assert!(quiet.accept(Duration::from_secs(5)).is_some());
    }

    #[test]
    fn many_connections_share_one_socket_without_crosstalk() {
        let server = UtpSocket::bind(loopback()).unwrap();
        server.listen();
        let client = UtpSocket::bind(loopback()).unwrap();
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, server.local_addr().unwrap().port()));
        let mut pairs = Vec::new();
        for i in 0..8u8 {
            let c = client.connect(to, Duration::from_secs(5)).unwrap();
            let s = server.accept(Duration::from_secs(5)).unwrap();
            pairs.push((i, c, s));
        }
        let handles: Vec<_> = pairs
            .into_iter()
            .map(|(i, mut c, mut s)| {
                thread::spawn(move || {
                    let data = vec![i; 100_000 + i as usize];
                    let expect = data.clone();
                    let writer = thread::spawn(move || {
                        c.write_all(&data).unwrap();
                        c
                    });
                    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
                    let mut got = vec![0u8; expect.len()];
                    s.read_exact(&mut got).unwrap();
                    drop(writer.join().unwrap());
                    got == expect
                })
            })
            .collect();
        for h in handles {
            assert!(h.join().unwrap(), "every connection got exactly its own bytes");
        }
    }

    #[test]
    fn a_datagram_that_is_not_utp_goes_to_whoever_asked_for_those() {
        let (tx, rx) = std::sync::mpsc::channel();
        let socket = UtpSocket::with_socket(UdpSocket::bind("127.0.0.1:0").unwrap(), Some(tx)).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe", socket.local_addr().unwrap()).unwrap();
        let (bytes, from) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(bytes.starts_with(b"d1:a"));
        assert_eq!(from, sender.local_addr().unwrap());
        // And the socket can answer from the same port.
        socket.send_other(b"reply", from).unwrap();
        let mut buf = [0u8; 16];
        sender.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (n, back) = sender.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], back), (&b"reply"[..], socket.local_addr().unwrap()));
    }

    #[test]
    fn a_packet_for_a_connection_that_does_not_exist_is_answered_with_a_reset() {
        let socket = UtpSocket::bind(loopback()).unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let stray = Packet { kind: PacketType::Data, connection_id: 777, timestamp: 0, timestamp_diff: 0, wnd_size: 1000, seq_nr: 5, ack_nr: 0, sack: Vec::new(), payload: b"x".to_vec() };
        peer.send_to(&stray.encode(), socket.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 100];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        let reply = Packet::decode(&buf[..n]).unwrap();
        assert_eq!((reply.kind, reply.connection_id, reply.ack_nr), (PacketType::Reset, 777, 5));
        // A reset is not itself answered, or two sockets could go on for ever.
        let reset = Packet { kind: PacketType::Reset, ..stray };
        peer.send_to(&reset.encode(), socket.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        assert!(peer.recv_from(&mut buf).is_err());
    }

    #[test]
    fn a_repeated_connection_request_does_not_make_a_second_connection() {
        let server = UtpSocket::bind(loopback()).unwrap();
        server.listen();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let syn = Packet { kind: PacketType::Syn, connection_id: 4000, timestamp: 0, timestamp_diff: 0, wnd_size: 1 << 20, seq_nr: 1, ack_nr: 0, sack: Vec::new(), payload: Vec::new() };
        for _ in 0..3 {
            peer.send_to(&syn.encode(), server.local_addr().unwrap()).unwrap();
            let mut buf = [0u8; 100];
            let (n, _) = peer.recv_from(&mut buf).unwrap();
            let answer = Packet::decode(&buf[..n]).unwrap();
            assert_eq!((answer.kind, answer.connection_id, answer.ack_nr), (PacketType::State, 4000, 1), "answered each time, on the id the request named");
        }
        assert_eq!(server.connection_count(), 1);
        assert!(server.accept(Duration::from_secs(1)).is_some());
        assert!(server.accept(Duration::from_millis(100)).is_none(), "and it was accepted once");
    }

    #[test]
    fn a_connection_the_application_lets_go_of_is_forgotten_once_it_is_done() {
        let (client, mut server, c, s) = connected();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        drop(client);
        let mut all = Vec::new();
        server.read_to_end(&mut all).unwrap();
        drop(server);
        let until = Instant::now() + Duration::from_secs(10);
        while (c.connection_count() > 0 || s.connection_count() > 0) && Instant::now() < until {
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!((c.connection_count(), s.connection_count()), (0, 0), "neither socket keeps a finished connection");
    }

    #[test]
    fn dropping_the_socket_resets_its_connections_so_the_other_end_finds_out_at_once() {
        let (mut client, server_stream, c, s) = connected();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        drop(s); // the stream on it is still held
        let started = Instant::now();
        let err = client.read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset, "{:?}", err);
        assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
        drop((server_stream, c));
    }

    #[test]
    fn requests_beyond_the_pending_limit_are_not_answered() {
        let server = UtpSocket::bind(loopback()).unwrap();
        server.listen();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut answered = 0;
        for id in 0..(MAX_PENDING as u16 + 10) {
            let syn = Packet { kind: PacketType::Syn, connection_id: 1000 + id * 4, timestamp: 0, timestamp_diff: 0, wnd_size: 1 << 20, seq_nr: 1, ack_nr: 0, sack: Vec::new(), payload: Vec::new() };
            peer.send_to(&syn.encode(), server.local_addr().unwrap()).unwrap();
            let mut buf = [0u8; 64];
            if peer.recv_from(&mut buf).is_ok() {
                answered += 1;
            }
        }
        assert_eq!(answered, MAX_PENDING, "nobody accepted any, so that many were taken and no more");
    }

    #[test]
    fn dropping_the_socket_frees_its_port_even_with_a_connection_nobody_accepted() {
        let server = UtpSocket::bind(loopback()).unwrap();
        server.listen();
        let port = server.local_addr().unwrap().port();
        let client = UtpSocket::bind(loopback()).unwrap();
        let _stream = client.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_secs(5)).unwrap();
        drop(server); // the connection was never accepted
        assert!(UdpSocket::bind(("127.0.0.1", port)).is_ok(), "the port is free again");
    }

    /// An endpoint written separately, in Python, from the BEP alone: it acknowledges every
    /// packet and sends one at a time, and has no congestion control, so it is only fit for a
    /// clean loopback. What it shows is that the header layout, the ids, the sequence numbers
    /// and the handshake mean the same to it as to this code.
    const PYTHON_PEER: &str = r#"
import socket, struct, sys, os, time
HDR = '>BBHIIIHH'
ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN = 0, 1, 2, 3, 4
def pkt(t, cid, seq, ack, payload=b''):
    return struct.pack(HDR, (t << 4) | 1, 0, cid, int(time.time() * 1e6) & 0xffffffff, 0, 1 << 20, seq, ack) + payload
def parse(d):
    ver, ext, cid, ts, td, wnd, seq, ack = struct.unpack(HDR, d[:20])
    assert ver & 0xf == 1, 'version'
    off = 20
    while ext:
        nxt, ln = d[off], d[off + 1]
        off += 2 + ln
        ext = nxt
    return ver >> 4, cid, seq, ack, d[off:]
mode, port, total = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
data = bytes((i * 7 + 3) & 0xff for i in range(total))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)
peer = ('127.0.0.1', port)

def send_stop_and_wait(t, cid, seq, ack, payload, my_recv_cid):
    for _ in range(5):
        s.sendto(pkt(t, cid, seq, ack, payload), peer)
        try:
            while True:
                d, _ = s.recvfrom(4096)
                ty, c, sq, ak, pl = parse(d)
                if c == my_recv_cid and ty == ST_STATE and ak == seq:
                    return True
        except socket.timeout:
            continue
    return False

if mode == 'connect':
    rid = 0x1234
    s.sendto(pkt(ST_SYN, rid, 1, 0), peer)
    d, _ = s.recvfrom(4096)
    ty, c, sq, ak, pl = parse(d)
    assert ty == ST_STATE and c == rid and ak == 1, ('answer', ty, c, ak)
    their_next = sq            # a state packet uses no number: their first data is numbered sq
    seq = 2
    sent = 0
    got = b''
    ack = sq - 1
    while sent < total:
        chunk = data[sent:sent + 1000]
        assert send_stop_and_wait(ST_DATA, rid + 1, seq, ack, chunk, rid), 'no ack'
        seq += 1; sent += len(chunk)
    # now read the echo
    while len(got) < total:
        d, _ = s.recvfrom(4096)
        ty, c, sq, ak, pl = parse(d)
        if c != rid or ty != ST_DATA: continue
        if sq == ((ack + 1) & 0xffff):
            got += pl; ack = sq
        s.sendto(pkt(ST_STATE, rid + 1, seq, ack), peer)
    assert got == data, 'echo differs'
    print('OK')
else:
    s.bind(('127.0.0.1', port))
    d, addr = s.recvfrom(4096)
    peer = addr
    ty, cid, sq, ak, pl = parse(d)
    assert ty == ST_SYN
    my_seq = 500
    s.sendto(pkt(ST_STATE, cid, my_seq, sq), peer)
    ack = sq
    got = b''
    while len(got) < total:
        d, _ = s.recvfrom(4096)
        ty, c, sq, ak, pl = parse(d)
        if c != cid + 1 or ty != ST_DATA: continue
        if sq == ((ack + 1) & 0xffff):
            got += pl; ack = sq
        s.sendto(pkt(ST_STATE, cid, my_seq, ack), peer)
    assert got == data, 'received data differs'
    sent = 0
    while sent < total:
        chunk = data[sent:sent + 1000]
        assert send_stop_and_wait(ST_DATA, cid, my_seq, ack, chunk, cid + 1), 'no ack of echo'
        my_seq += 1; sent += len(chunk)
    print('OK')
"#;

    fn python_available() -> bool {
        std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success())
    }

    #[test]
    fn a_separately_written_python_endpoint_can_connect_to_it_and_be_connected_to() {
        if !python_available() {
            eprintln!("no python3 here; the interoperability check is skipped");
            return;
        }
        let total = 40_000usize;
        let expect: Vec<u8> = (0..total).map(|i| (i * 7 + 3) as u8).collect();

        // Python connects to us, sends bytes, and reads them back.
        let server = UtpSocket::bind(loopback()).unwrap();
        server.listen();
        let port = server.local_addr().unwrap().port();
        let python = std::process::Command::new("python3").args(["-c", PYTHON_PEER, "connect", &port.to_string(), &total.to_string()]).spawn().unwrap();
        let mut accepted = server.accept(Duration::from_secs(10)).expect("Python's connection request is understood");
        accepted.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut got = vec![0u8; total];
        accepted.read_exact(&mut got).unwrap();
        assert!(got == expect, "what Python sent");
        accepted.write_all(&got).unwrap();
        let out = python.wait_with_output().unwrap();
        assert!(out.status.success(), "Python was content with the echo");

        // We connect to Python, which echoes.
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let py_port = listener.local_addr().unwrap().port();
        drop(listener);
        let python = std::process::Command::new("python3").args(["-c", PYTHON_PEER, "accept", &py_port.to_string(), &total.to_string()]).stdout(std::process::Stdio::piped()).spawn().unwrap();
        thread::sleep(Duration::from_millis(600));
        let client = UtpSocket::bind(loopback()).unwrap();
        let mut stream = client.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, py_port)), Duration::from_secs(10)).expect("Python answers our request");
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream.write_all(&expect).unwrap();
        let mut echoed = vec![0u8; total];
        stream.read_exact(&mut echoed).unwrap();
        assert!(echoed == expect, "what Python echoed");
        let out = python.wait_with_output().unwrap();
        assert!(out.status.success() && String::from_utf8_lossy(&out.stdout).contains("OK"));
    }
}
