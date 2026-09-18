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
