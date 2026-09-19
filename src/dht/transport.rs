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
}
