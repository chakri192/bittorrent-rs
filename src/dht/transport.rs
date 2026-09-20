//! How the DHT talks to the network, behind a trait so the responder and
//! the lookup can be tested against a scripted in-memory transport.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub trait Transport: Send {
    /// Whether this is an IPv6 socket, which talks to IPv6 nodes only (BEP 32:
    /// a node keeps a routing table for each family, and does not mix them).
    fn ipv6(&self) -> bool {
        false
    }

    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()>;
    /// Blocks up to `timeout`; `Ok(None)` on timeout (not an error).
    fn recv(&self, timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>>;
}

/// A transport whose kind is not known where it is used: one node of either family, one shared with uTP or not.
impl Transport for Box<dyn Transport> {
    fn ipv6(&self) -> bool {
        (**self).ipv6()
    }

    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        (**self).send_to(data, addr)
    }

    fn recv(&self, timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        (**self).recv(timeout)
    }
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

    /// Binds `[::]:port` for IPv6 only (BEP 32), falling back to an ephemeral
    /// port if taken. Left to the system a wildcard IPv6 socket may also take
    /// IPv4, which would put the IPv4 DHT node's traffic on this one.
    pub fn bind_v6(port: u16) -> io::Result<Self> {
        let socket = bind_v6_only(port).or_else(|_| bind_v6_only(0))?;
        Ok(UdpTransport { socket })
    }

    /// Wraps a socket already bound, of either family.
    pub fn from_socket(socket: UdpSocket) -> Self {
        UdpTransport { socket }
    }

    pub fn local_port(&self) -> u16 {
        self.socket.local_addr().map(|a| a.port()).unwrap_or(0)
    }
}

impl Transport for UdpTransport {
    fn ipv6(&self) -> bool {
        self.socket.local_addr().is_ok_and(|a| a.is_ipv6())
    }

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

#[cfg(unix)]
fn bind_v6_only(port: u16) -> io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain socket calls with valid arguments; the descriptor is closed
    // on every failure path and otherwise handed to the UdpSocket.
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fail = |fd: libc::c_int| {
            let error = io::Error::last_os_error();
            libc::close(fd);
            Err(error)
        };
        let on: libc::c_int = 1;
        if libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &on as *const libc::c_int as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) < 0 {
            return fail(fd);
        }
        let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
        sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sa.sin6_port = port.to_be();
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
        {
            sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        }
        if libc::bind(fd, &sa as *const libc::sockaddr_in6 as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t) < 0 {
            return fail(fd);
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
}

#[cfg(not(unix))]
fn bind_v6_only(port: u16) -> io::Result<UdpSocket> {
    // Where IPv6 sockets are IPv6 only by default (Windows).
    UdpSocket::bind(("::", port))
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

    /// Whether this machine has IPv6 on loopback, without which the tests of the IPv6 socket say so and pass.
    fn has_ipv6_loopback() -> bool {
        UdpSocket::bind("[::1]:0").is_ok()
    }

    #[test]
    fn an_ipv6_transport_says_so_and_an_ipv4_one_does_not() {
        assert!(!UdpTransport::bind(0).unwrap().ipv6());
        if !has_ipv6_loopback() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        assert!(UdpTransport::bind_v6(0).unwrap().ipv6());
    }

    #[test]
    fn a_datagram_crosses_ipv6_loopback_between_two_transports() {
        if !has_ipv6_loopback() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        let a = UdpTransport::bind_v6(0).unwrap();
        let b = UdpTransport::bind_v6(0).unwrap();
        a.send_to(b"hello6", SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, b.local_port()))).unwrap();
        let (bytes, from) = b.recv(Duration::from_secs(5)).unwrap().expect("it arrives");
        assert_eq!(bytes, b"hello6");
        assert_eq!(from, SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, a.local_port())));
    }

    #[test]
    fn an_ipv6_only_socket_does_not_take_ipv4_traffic() {
        // The IPv4 node has its own socket; a wildcard IPv6 one that also took IPv4
        // would put that traffic in the wrong routing table.
        if !has_ipv6_loopback() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        let six = UdpTransport::bind_v6(0).unwrap();
        let four = UdpSocket::bind("127.0.0.1:0").unwrap();
        four.send_to(b"v4", ("127.0.0.1", six.local_port())).unwrap();
        assert!(six.recv(Duration::from_millis(300)).unwrap().is_none(), "nothing arrives");
        // (And the port is free for an IPv4 socket, which is what lets both nodes use one number.)
        assert!(UdpSocket::bind(("0.0.0.0", six.local_port())).is_ok());
    }
}
