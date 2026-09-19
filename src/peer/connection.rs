//! Ties `handshake` and `message` to an actual `TcpStream`. Untestable
//! against a real peer in this sandbox (no BitTorrent peers reachable),
//! so this stays a thin, obviously-correct wrapper -- all the actual
//! parsing/serialization logic it calls into is unit-tested in
//! `handshake.rs` and `message.rs` against in-memory buffers.

use super::handshake::{Handshake, HandshakeError, HANDSHAKE_LEN};
use super::message::{Message, WireError};
use super::stream::PeerStream;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug)]
pub enum ConnectionError {
    Io(std::io::Error),
    Handshake(HandshakeError),
    Wire(WireError),
    InfoHashMismatch,
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
    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut stream: Box<dyn PeerStream> = Box::new(stream);
    let outbound = Handshake::new(info_hash, our_peer_id, support_extensions);
    stream.write_all(&outbound.to_bytes())?;

    let mut buf = [0u8; HANDSHAKE_LEN];
    stream.read_exact(&mut buf)?;
    let peer_handshake = Handshake::from_bytes(&buf)?;

    if peer_handshake.info_hash != info_hash {
        return Err(ConnectionError::InfoHashMismatch);
    }

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
