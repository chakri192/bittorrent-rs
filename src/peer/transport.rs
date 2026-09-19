//! How a connection to a peer is opened: over TCP, over uTP (BEP 29), or over
//! TCP with uTP as the second try.

use super::connection::ConnectionError;
use super::stream::PeerStream;
use crate::utp::UtpSocket;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    /// TCP only. The default: it is what every client speaks.
    #[default]
    Tcp,
    /// uTP only.
    Utp,
    /// TCP, and uTP for a peer that TCP cannot reach.
    Both,
}

impl TransportMode {
    pub fn parse(text: &str) -> Option<TransportMode> {
        match text {
            "tcp" => Some(TransportMode::Tcp),
            "utp" => Some(TransportMode::Utp),
            "both" => Some(TransportMode::Both),
            _ => None,
        }
    }

    /// Whether a uTP socket is wanted at all.
    pub fn wants_utp(self) -> bool {
        self != TransportMode::Tcp
    }
}

/// The means of opening connections: which kinds, and the uTP socket to open
/// them on.
#[derive(Debug, Clone, Default)]
pub struct Transport {
    pub mode: TransportMode,
    pub utp: Option<Arc<UtpSocket>>,
}

impl Transport {
    /// Opens a connection to `addr`, giving each attempt `timeout`, and sets
    /// that as the read and write timeout of what it returns.
    pub fn open(&self, addr: SocketAddr, timeout: Duration) -> Result<Box<dyn PeerStream>, ConnectionError> {
        let over_utp = |socket: &Option<Arc<UtpSocket>>| -> Result<Box<dyn PeerStream>, ConnectionError> {
            let socket = socket.as_ref().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Unsupported, "uTP is not running"))?;
            Ok(Box::new(socket.connect(addr, timeout)?))
        };
        let stream: Box<dyn PeerStream> = match self.mode {
            TransportMode::Tcp => Box::new(open_tcp(addr, timeout)?),
            TransportMode::Utp => over_utp(&self.utp)?,
            TransportMode::Both => match open_tcp(addr, timeout) {
                Ok(stream) => Box::new(stream),
                Err(tcp_error) => over_utp(&self.utp).map_err(|_| tcp_error)?,
            },
        };
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(stream)
    }
}

fn open_tcp(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, ConnectionError> {
    Ok(TcpStream::connect_timeout(&addr, timeout)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::connection::connect_and_handshake_with;
    use crate::peer::handshake::{Handshake, HANDSHAKE_LEN};
    use crate::peer::Encryption;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    const HASH: [u8; 20] = [0x42; 20];

    fn utp_socket() -> Arc<UtpSocket> {
        let socket = UtpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        socket.listen();
        Arc::new(socket)
    }

    fn at(socket: &UtpSocket) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, socket.local_addr().unwrap().port()))
    }

    /// A port where TCP is refused: bound once, then let go.
    fn closed_tcp_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn the_modes_are_named_as_the_flag_and_config_name_them() {
        assert_eq!(TransportMode::parse("tcp"), Some(TransportMode::Tcp));
        assert_eq!(TransportMode::parse("utp"), Some(TransportMode::Utp));
        assert_eq!(TransportMode::parse("both"), Some(TransportMode::Both));
        assert_eq!(TransportMode::parse("udp"), None);
        assert_eq!(TransportMode::parse(""), None);
        assert_eq!(TransportMode::default(), TransportMode::Tcp, "TCP unless asked");
        assert!(!TransportMode::Tcp.wants_utp() && TransportMode::Utp.wants_utp() && TransportMode::Both.wants_utp());
    }

    #[test]
    fn tcp_mode_dials_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = thread::spawn(move || listener.accept().is_ok());
        Transport::default().open(addr, Duration::from_secs(5)).expect("connects");
        assert!(accepted.join().unwrap());
    }

    #[test]
    fn utp_mode_dials_utp_and_never_tcp() {
        let server = utp_socket();
        let client = Transport { mode: TransportMode::Utp, utp: Some(utp_socket()) };
        // A TCP listener on the same port number would be the tell-tale of a TCP attempt.
        let watcher = TcpListener::bind(("127.0.0.1", server.local_addr().unwrap().port())).ok();
        let mut stream = client.open(at(&server), Duration::from_secs(5)).expect("connects over uTP");
        let mut accepted = server.accept(Duration::from_secs(5)).expect("and is accepted as uTP");
        stream.write_all(b"hi").unwrap();
        let mut got = [0u8; 2];
        accepted.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        accepted.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hi");
        if let Some(watcher) = watcher {
            watcher.set_nonblocking(true).unwrap();
            assert!(watcher.accept().is_err(), "nothing came to TCP");
        }
    }

    #[test]
    fn utp_mode_without_a_socket_is_an_error_not_a_panic() {
        let err = Transport { mode: TransportMode::Utp, utp: None }.open(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, ConnectionError::Io(ref e) if e.kind() == std::io::ErrorKind::Unsupported), "{:?}", err);
    }

    #[test]
    fn both_mode_goes_by_tcp_when_tcp_answers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = UtpSocket::bind(addr).ok(); // the same port number, for uTP, if it is free
        if let Some(server) = &server {
            server.listen();
        }
        let accepted = thread::spawn(move || listener.accept().is_ok());
        Transport { mode: TransportMode::Both, utp: Some(utp_socket()) }.open(addr, Duration::from_secs(5)).unwrap();
        assert!(accepted.join().unwrap(), "TCP was the first choice, and it worked");
        if let Some(server) = server {
            assert!(server.accept(Duration::from_millis(100)).is_none(), "so uTP was not tried");
        }
    }

    #[test]
    fn both_mode_falls_back_to_utp_when_tcp_is_refused() {
        let server = utp_socket();
        let port = server.local_addr().unwrap().port();
        // Nothing listens on TCP at that port (or, should something happen to, this test cannot say anything).
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            return;
        }
        let client = Transport { mode: TransportMode::Both, utp: Some(utp_socket()) };
        client.open(at(&server), Duration::from_secs(5)).expect("TCP is refused, uTP answers");
        assert!(server.accept(Duration::from_secs(5)).is_some());
    }

    #[test]
    fn both_mode_reports_the_tcp_error_when_neither_works() {
        let dead = SocketAddr::from((Ipv4Addr::LOCALHOST, closed_tcp_port()));
        let started = std::time::Instant::now();
        let err = Transport { mode: TransportMode::Both, utp: Some(utp_socket()) }.open(dead, Duration::from_millis(400)).unwrap_err();
        assert!(matches!(err, ConnectionError::Io(ref e) if e.kind() == std::io::ErrorKind::ConnectionRefused), "the refusal, which is the first and most telling failure: {:?}", err);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn what_is_opened_has_the_timeout_asked_for() {
        let server = utp_socket();
        let client = utp_socket();
        let mut stream = Transport { mode: TransportMode::Utp, utp: Some(Arc::clone(&client)) }.open(at(&server), Duration::from_millis(200)).unwrap();
        let _keep = server.accept(Duration::from_secs(5));
        // On a thread, so that a stream with no timeout fails this test rather than hanging it.
        let started = std::time::Instant::now();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(stream.read(&mut [0u8; 1]).map_err(|e| e.kind()));
        });
        let outcome = rx.recv_timeout(Duration::from_secs(5)).expect("the read gave up by itself");
        assert!(matches!(outcome, Err(std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)), "{:?}", outcome);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn the_handshake_is_done_over_utp_and_with_encryption_over_utp() {
        for encryption in [Encryption::Off, Encryption::Require] {
            let server = utp_socket();
            let addr = at(&server);
            let peer = thread::spawn(move || {
                let stream = server.accept(Duration::from_secs(5)).expect("a connection");
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let (mut stream, encrypted) = crate::peer::mse::accept(Box::new(stream), &[HASH], Encryption::Prefer).unwrap();
                let mut theirs = [0u8; HANDSHAKE_LEN];
                stream.read_exact(&mut theirs).unwrap();
                stream.write_all(&Handshake::new(HASH, [0x99; 20], false).to_bytes()).unwrap();
                encrypted
            });
            let transport = Transport { mode: TransportMode::Utp, utp: Some(utp_socket()) };
            let (_stream, theirs) = connect_and_handshake_with(addr, HASH, [0x11; 20], false, false, Duration::from_secs(5), encryption, &transport).expect("the handshake works over uTP");
            assert_eq!(theirs.peer_id, [0x99; 20]);
            assert_eq!(peer.join().unwrap(), encryption == Encryption::Require, "encrypted exactly when asked, over uTP too");
        }
    }
}
