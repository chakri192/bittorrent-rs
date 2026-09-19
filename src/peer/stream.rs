//! What a connection to a peer has to be, so that the same worker code can
//! run over a plain TCP socket, an encrypted one (message stream
//! encryption), or any other byte stream.
//!
//! A peer connection reads and writes bytes, has read and write timeouts
//! (the workers depend on a read returning after a while), and can be
//! ended from another thread so that a read blocked on a silent peer
//! returns at once when the client is stopping.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Ends a connection from any thread. Whatever is blocked reading or
/// writing on it returns an error promptly.
pub trait Closer: Send + Sync + std::fmt::Debug {
    fn close(&self);
}

/// A byte stream to a peer.
pub trait PeerStream: Read + Write + Send + std::fmt::Debug {
    /// How long a read may block before failing with `WouldBlock` or
    /// `TimedOut`; `None` for no limit.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// A handle that ends this connection from another thread. It stays
    /// valid, and keeps the connection's resources alive, until dropped.
    fn closer(&self) -> io::Result<Arc<dyn Closer>>;
}

#[derive(Debug)]
struct TcpCloser(TcpStream);

impl Closer for TcpCloser {
    fn close(&self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

impl PeerStream for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }

    fn closer(&self) -> io::Result<Arc<dyn Closer>> {
        Ok(Arc::new(TcpCloser(self.try_clone()?)))
    }
}

impl<S: PeerStream + ?Sized> PeerStream for Box<S> {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        (**self).set_write_timeout(timeout)
    }

    fn closer(&self) -> io::Result<Arc<dyn Closer>> {
        (**self).closer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn a_tcp_stream_is_a_peer_stream_with_working_timeouts() {
        let (client, _server) = pair();
        let mut boxed: Box<dyn PeerStream> = Box::new(client);
        boxed.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 1];
        let err = boxed.read(&mut buf).unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut), "{:?}", err);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_closer_ends_a_read_blocked_on_another_thread() {
        let (client, _server) = pair();
        let closer = client.closer().unwrap();
        let reader = thread::spawn(move || {
            let mut client = client;
            client.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let started = Instant::now();
            let mut buf = [0u8; 1];
            (client.read(&mut buf).is_ok_and(|n| n == 0), started.elapsed())
        });
        thread::sleep(Duration::from_millis(150));

        closer.close();

        let (ended, waited) = reader.join().unwrap();
        assert!(ended && waited < Duration::from_secs(5), "{:?}", waited);
    }

    #[test]
    fn a_boxed_stream_forwards_everything_to_the_stream_inside() {
        let (client, mut server) = pair();
        let mut boxed: Box<dyn PeerStream> = Box::new(client);
        boxed.write_all(b"hi").unwrap();
        let mut got = [0u8; 2];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hi");
        assert!(boxed.closer().is_ok());
        assert!(boxed.set_write_timeout(Some(Duration::from_secs(1))).is_ok());
    }
}
