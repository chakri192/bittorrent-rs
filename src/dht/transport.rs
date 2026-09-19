//! How the DHT talks to the network, behind a trait so the responder and
//! the lookup can be tested against a scripted in-memory transport.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub trait Transport: Send {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()>;
    /// Blocks up to `timeout`; `Ok(None)` on timeout (not an error).
    fn recv(&self, timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>>;
}

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Binds `0.0.0.0:port`, falling back to an ephemeral port if taken.
    pub fn bind(port: u16) -> io::Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", port)).or_else(|_| UdpSocket::bind(("0.0.0.0", 0)))?;
        Ok(UdpTransport { socket })
    }

    pub fn local_port(&self) -> u16 {
        self.socket.local_addr().map(|a| a.port()).unwrap_or(0)
    }
}

impl Transport for UdpTransport {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_to(data, addr).map(|_| ())
    }

    fn recv(&self, timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        self.socket.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; 2048]; // KRPC messages are far smaller than one MTU in practice
        match self.socket.recv_from(&mut buf) {
            Ok((n, from)) => Ok(Some((buf[..n].to_vec(), from))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A DHT transport that shares a UDP port with uTP: it sends through the
/// same socket and receives the datagrams that are not uTP, which the socket
/// sets aside for it. This is how one port can serve both, as peers expect.
pub struct SharedTransport {
    socket: std::sync::Arc<crate::utp::UtpSocket>,
    incoming: std::sync::Mutex<std::sync::mpsc::Receiver<crate::utp::socket::Foreign>>,
}

impl SharedTransport {
    pub fn new(socket: std::sync::Arc<crate::utp::UtpSocket>, incoming: std::sync::mpsc::Receiver<crate::utp::socket::Foreign>) -> Self {
        SharedTransport { socket, incoming: std::sync::Mutex::new(incoming) }
    }

    pub fn local_port(&self) -> u16 {
        self.socket.local_addr().map(|a| a.port()).unwrap_or(0)
    }
}

impl Transport for SharedTransport {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_other(data, addr)
    }

    fn recv(&self, timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        let incoming = crate::sync::lock(&self.incoming);
        match incoming.recv_timeout(timeout) {
            Ok(datagram) => Ok(Some(datagram)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "the uTP socket has stopped")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn a_datagram_sent_from_one_transport_arrives_at_the_other() {
        let a = UdpTransport::bind(0).unwrap();
        let b = UdpTransport::bind(0).unwrap();

        a.send_to(b"hello", loopback(b.local_port())).unwrap();

        let (data, from) = b.recv(Duration::from_secs(2)).unwrap().expect("the datagram arrives");
        assert_eq!(data, b"hello");
        assert_eq!(from.port(), a.local_port(), "and says where it came from");
    }

    #[test]
    fn recv_reports_a_quiet_socket_as_none_not_an_error() {
        let t = UdpTransport::bind(0).unwrap();
        assert!(t.recv(Duration::from_millis(50)).unwrap().is_none());
    }

    #[test]
    fn a_taken_port_falls_back_to_an_ephemeral_one() {
        let first = UdpTransport::bind(0).unwrap();
        let second = UdpTransport::bind(first.local_port()).expect("binding a taken port must not fail");
        assert_ne!(second.local_port(), first.local_port());
        assert_ne!(second.local_port(), 0);
    }

    #[test]
    fn a_shared_transport_sends_from_the_utp_socket_and_receives_what_is_not_utp() {
        let (tx, rx) = std::sync::mpsc::channel();
        let socket = std::sync::Arc::new(crate::utp::UtpSocket::with_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), Some(tx)).unwrap());
        let shared = SharedTransport::new(std::sync::Arc::clone(&socket), rx);
        let other = UdpTransport::bind(0).unwrap();

        other.send_to(b"d1:y1:qe", loopback(shared.local_port())).unwrap();
        let (bytes, from) = shared.recv(Duration::from_secs(5)).unwrap().expect("the DHT message is handed over");
        assert_eq!((&bytes[..], from.port()), (&b"d1:y1:qe"[..], other.local_port()));
        assert!(shared.recv(Duration::from_millis(50)).unwrap().is_none(), "and nothing else is waiting");

        shared.send_to(b"answer", loopback(other.local_port())).unwrap();
        let (bytes, from) = other.recv(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!((&bytes[..], from.port()), (&b"answer"[..], shared.local_port()), "from the port everyone knows us by");
    }

    #[test]
    fn a_shared_transport_reports_a_stopped_socket_instead_of_waiting_for_ever() {
        let (tx, rx) = std::sync::mpsc::channel();
        let socket = std::sync::Arc::new(crate::utp::UtpSocket::with_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap(), Some(tx)).unwrap());
        let shared = SharedTransport::new(std::sync::Arc::clone(&socket), rx);
        socket.shutdown();
        // A DHT thread waiting on it must find out, and not wait out its timeouts for ever.
        let err = shared.recv(Duration::from_secs(5)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
