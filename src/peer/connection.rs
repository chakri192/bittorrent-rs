//! Ties `handshake` and `message` to an actual `TcpStream`. Untestable
//! against a real peer in this sandbox (no BitTorrent peers reachable),
//! so this stays a thin, obviously-correct wrapper -- all the actual
//! parsing/serialization logic it calls into is unit-tested in
//! `handshake.rs` and `message.rs` against in-memory buffers.

use super::handshake::{Handshake, HandshakeError, HANDSHAKE_LEN};
use super::message::{Message, WireError};
use super::mse::{self, Encryption, MseError};
use super::stream::PeerStream;
use super::transport::Transport;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug)]
pub enum ConnectionError {
    Io(std::io::Error),
    Handshake(HandshakeError),
    Wire(WireError),
    InfoHashMismatch,
    /// The encryption handshake (MSE) failed.
    Encryption(MseError),
}

impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        ConnectionError::Io(e)
    }
}
impl From<HandshakeError> for ConnectionError {
    fn from(e: HandshakeError) -> Self {
        ConnectionError::Handshake(e)
    }
}
impl From<MseError> for ConnectionError {
    fn from(e: MseError) -> Self {
        ConnectionError::Encryption(e)
    }
}
impl From<WireError> for ConnectionError {
    fn from(e: WireError) -> Self {
        ConnectionError::Wire(e)
    }
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::Io(e) => write!(f, "io error: {}", e),
            ConnectionError::Handshake(e) => write!(f, "handshake error: {}", e),
            ConnectionError::Wire(e) => write!(f, "wire protocol error: {}", e),
            ConnectionError::InfoHashMismatch => write!(f, "peer's handshake info_hash did not match ours"),
            ConnectionError::Encryption(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ConnectionError {}

/// Opens a TCP connection to `addr` and performs the BitTorrent handshake:
/// sends ours first, then reads and validates the peer's. Returns the
/// connected stream plus the peer's parsed handshake (its `peer_id` is
/// needed by the caller to identify the peer; `supports_extensions()` on
/// it drives whether Phase 4's extended handshake should follow).
pub fn connect_and_handshake(
    addr: SocketAddr,
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
    support_extensions: bool,
    timeout: Duration,
) -> Result<(Box<dyn PeerStream>, Handshake), ConnectionError> {
    connect_and_handshake_with(addr, info_hash, our_peer_id, support_extensions, false, timeout, Encryption::Off, &Transport::default())
}

/// Reads the peer's handshake off `stream` and checks it is for `info_hash`.
fn read_handshake(stream: &mut dyn PeerStream, info_hash: [u8; 20]) -> Result<Handshake, ConnectionError> {
    let mut buf = [0u8; HANDSHAKE_LEN];
    stream.read_exact(&mut buf)?;
    let peer_handshake = Handshake::from_bytes(&buf)?;
    if peer_handshake.info_hash != info_hash {
        return Err(ConnectionError::InfoHashMismatch);
    }
    Ok(peer_handshake)
}

/// [`connect_and_handshake`] with a choice about the Fast Extension
/// (`support_fast` sets its handshake bit, BEP 6) and about encryption (MSE). With
/// [`Prefer`](Encryption::Prefer) an encrypted connection is tried first and,
/// if the peer will not do it, a plain one is made; with
/// [`Require`](Encryption::Require) there is no second try. A peer that
/// cannot be reached at all is not tried twice. `transport` says whether to
/// dial over TCP, uTP or both.
#[allow(clippy::too_many_arguments)]
pub fn connect_and_handshake_with(
    addr: SocketAddr,
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
    support_extensions: bool,
    support_fast: bool,
    timeout: Duration,
    encryption: Encryption,
    transport: &Transport,
) -> Result<(Box<dyn PeerStream>, Handshake), ConnectionError> {
    let outbound = Handshake::new(info_hash, our_peer_id, support_extensions).with_fast(support_fast).to_bytes();

    if encryption != Encryption::Off {
        let stream = transport.open(addr, timeout)?;
        // Our handshake goes ahead as the initial payload, saving a round trip.
        match mse::initiate(stream, &info_hash, encryption == Encryption::Prefer, &outbound) {
            Ok(secured) => {
                let mut secured: Box<dyn PeerStream> = Box::new(secured);
                let peer_handshake = read_handshake(&mut *secured, info_hash)?;
                return Ok((secured, peer_handshake));
            }
            Err(e) if encryption == Encryption::Require => return Err(e.into()),
            // The peer would not, or cannot: ask again the ordinary way.
            Err(_) => {}
        }
    }

    let mut stream = transport.open(addr, timeout)?;
    stream.write_all(&outbound)?;
    let peer_handshake = read_handshake(&mut *stream, info_hash)?;
    Ok((stream, peer_handshake))
}

/// Reads the next framed message from an already-handshaken stream.
pub fn read_message(stream: &mut dyn PeerStream) -> Result<Message, ConnectionError> {
    Ok(Message::read_from(stream)?)
}

/// Writes a framed message to an already-handshaken stream.
pub fn send_message(stream: &mut dyn PeerStream, msg: &Message) -> Result<(), ConnectionError> {
    msg.write_to(stream)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::mse::{self, Accept};
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Instant;

    const HASH: [u8; 20] = [0x42; 20];

    /// What a peer that took a connection found it to be.
    #[derive(Debug, Clone, PartialEq)]
    enum Saw {
        Encrypted,
        Plain,
        Nothing,
    }

    /// A peer that answers one connection at a time, `connections` times,
    /// with the handshake for `HASH`: encrypted if `understands_mse`, else
    /// only plaintext (an encrypted attempt is garbage to it and is dropped,
    /// as a client that has never heard of MSE does). Records what each
    /// connection turned out to be.
    fn peer(understands_mse: bool, connections: usize) -> (SocketAddr, Arc<Mutex<Vec<Saw>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        thread::spawn(move || {
            for _ in 0..connections {
                let Ok((stream, _)) = listener.accept() else { return };
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mode = if understands_mse { Encryption::Prefer } else { Encryption::Off };
                let Ok((mut stream, encrypted)) = mse::accept(Box::new(stream), &[HASH], mode) else {
                    record.lock().unwrap().push(Saw::Nothing);
                    continue;
                };
                let mut theirs = [0u8; HANDSHAKE_LEN];
                if stream.read_exact(&mut theirs).is_err() {
                    record.lock().unwrap().push(Saw::Nothing);
                    continue;
                }
                let _ = stream.write_all(&Handshake::new(HASH, [0x99; 20], false).to_bytes());
                record.lock().unwrap().push(if encrypted { Saw::Encrypted } else { Saw::Plain });
            }
        });
        (addr, seen)
    }

    fn connect(addr: SocketAddr, encryption: Encryption) -> Result<(), ConnectionError> {
        connect_and_handshake_with(addr, HASH, [0x11; 20], false, false, Duration::from_secs(5), encryption, &Transport::default()).map(|(_, hs)| assert_eq!(hs.info_hash, HASH))
    }

    fn settle(seen: &Arc<Mutex<Vec<Saw>>>, count: usize) -> Vec<Saw> {
        let until = Instant::now() + Duration::from_secs(5);
        while seen.lock().unwrap().len() < count && Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        seen.lock().unwrap().clone()
    }

    #[test]
    fn with_encryption_off_the_connection_is_plain() {
        let (addr, seen) = peer(true, 1);
        connect(addr, Encryption::Off).unwrap();
        assert_eq!(settle(&seen, 1), vec![Saw::Plain]);
    }

    #[test]
    fn preferring_encryption_encrypts_when_the_peer_will() {
        let (addr, seen) = peer(true, 1);
        connect(addr, Encryption::Prefer).unwrap();
        assert_eq!(settle(&seen, 1), vec![Saw::Encrypted], "one connection, and encrypted");
    }

    #[test]
    fn preferring_encryption_falls_back_to_plain_when_the_peer_will_not() {
        let (addr, seen) = peer(false, 2);
        connect(addr, Encryption::Prefer).expect("the second, plain, attempt works");
        assert_eq!(settle(&seen, 2), vec![Saw::Nothing, Saw::Plain], "the encrypted try was garbage to it, then a plain one");
    }

    #[test]
    fn requiring_encryption_does_not_fall_back() {
        let (addr, seen) = peer(false, 2);
        let err = connect(addr, Encryption::Require).unwrap_err();
        assert!(matches!(err, ConnectionError::Encryption(_)), "{:?}", err);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(seen.lock().unwrap().len(), 1, "no second connection");
    }

    #[test]
    fn requiring_encryption_works_with_a_peer_that_does_it() {
        let (addr, seen) = peer(true, 1);
        connect(addr, Encryption::Require).unwrap();
        assert_eq!(settle(&seen, 1), vec![Saw::Encrypted]);
    }

    #[test]
    fn an_unreachable_peer_is_not_tried_a_second_time_plain() {
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let started = Instant::now();
        let err = connect(dead, Encryption::Prefer).unwrap_err();
        assert!(matches!(err, ConnectionError::Io(_)), "a refused connection is an io error, not an encryption one: {:?}", err);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_peer_for_another_torrent_is_still_caught_after_encryption() {
        // Answers with the wrong info hash inside the encrypted stream.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let (mut stream, _) = mse::respond(Box::new(stream), &[], &[HASH], Accept { allow_rc4: true, allow_plaintext: false }).unwrap();
            let mut theirs = [0u8; HANDSHAKE_LEN];
            stream.read_exact(&mut theirs).unwrap();
            let _ = stream.write_all(&Handshake::new([0x77; 20], [0x99; 20], false).to_bytes());
        });
        let err = connect(addr, Encryption::Require).unwrap_err();
        assert!(matches!(err, ConnectionError::InfoHashMismatch), "{:?}", err);
    }

    /// A plain peer that reads our handshake, answers with one that says
    /// `it_is_fast`, and reports what ours said about the Fast Extension.
    fn fast_peer(it_is_fast: bool) -> (SocketAddr, std::sync::mpsc::Receiver<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut theirs = [0u8; HANDSHAKE_LEN];
            stream.read_exact(&mut theirs).unwrap();
            let _ = tx.send(Handshake::from_bytes(&theirs).unwrap().supports_fast());
            let _ = stream.write_all(&Handshake::new(HASH, [0x99; 20], false).with_fast(it_is_fast).to_bytes());
        });
        (addr, rx)
    }

    #[test]
    fn the_fast_extension_is_offered_only_when_asked_for() {
        for asked in [true, false] {
            let (addr, said) = fast_peer(true);
            let (_, theirs) = connect_and_handshake_with(addr, HASH, [0x11; 20], false, asked, Duration::from_secs(5), Encryption::Off, &Transport::default()).unwrap();
            assert_eq!(said.recv_timeout(Duration::from_secs(5)).unwrap(), asked, "our handshake");
            assert!(theirs.supports_fast(), "and the peer's bit is handed back for the caller to combine with ours");
        }
    }
}
