//! Bridges Phase 3 (wire protocol) + Phase 4 (BEP 10/9) into the one
//! thing a magnet link actually needs before any piece download can
//! start: getting the info dict itself from some peer. This is the piece
//! that was scaffolded but never wired up in Phase 4 -- everything it
//! calls was already unit-tested there; what's new here is the orchestration.

use crate::metadata::{MetadataAssembler, MetadataError, MetadataMessage};
use crate::peer::connection::{read_message, send_message, ConnectionError};
use crate::peer::extension::{ExtendedHandshake, ExtensionError};
use crate::peer::message::Message;
use std::net::SocketAddr;
use std::time::Duration;

/// The id we advertise for `ut_metadata` in our own extended handshake.
/// Arbitrary (any value 1-255 works) -- the peer will echo it back to us
/// on every metadata message they send, and we use it to recognize those
/// messages among whatever else the peer sends.
const OUR_UT_METADATA_ID: u8 = 1;

#[derive(Debug)]
pub enum MetadataFetchError {
    Connection(ConnectionError),
    Extension(ExtensionError),
    Metadata(MetadataError),
    PeerLacksExtensionProtocol,
    PeerLacksUtMetadata,
    PeerDoesNotKnowMetadataSizeYet,
    PeerRejectedPiece(u32),
}

impl From<ConnectionError> for MetadataFetchError {
    fn from(e: ConnectionError) -> Self {
        MetadataFetchError::Connection(e)
    }
}
impl From<ExtensionError> for MetadataFetchError {
    fn from(e: ExtensionError) -> Self {
        MetadataFetchError::Extension(e)
    }
}
impl From<MetadataError> for MetadataFetchError {
    fn from(e: MetadataError) -> Self {
        MetadataFetchError::Metadata(e)
    }
}

impl std::fmt::Display for MetadataFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataFetchError::Connection(e) => write!(f, "connection error: {}", e),
            MetadataFetchError::Extension(e) => write!(f, "extension handshake error: {}", e),
            MetadataFetchError::Metadata(e) => write!(f, "metadata message error: {}", e),
            MetadataFetchError::PeerLacksExtensionProtocol => write!(f, "peer does not support BEP 10 extensions"),
            MetadataFetchError::PeerLacksUtMetadata => write!(f, "peer does not advertise ut_metadata support"),
            MetadataFetchError::PeerDoesNotKnowMetadataSizeYet => write!(f, "peer hasn't got the full metadata yet (no metadata_size)"),
            MetadataFetchError::PeerRejectedPiece(n) => write!(f, "peer rejected metadata piece {}", n),
        }
    }
}

impl std::error::Error for MetadataFetchError {}

/// Connects to `addr`, performs the BEP 3 handshake (requiring BEP 10
/// support) and BEP 10 extended handshake, then requests every ut_metadata
/// piece in sequence and assembles+verifies the result against
/// `info_hash` (the hash from the magnet URI). Returns the raw info dict
/// bytes on success -- ready for `torrent::from_info_dict_bytes`.
pub fn fetch_metadata_from_peer(addr: SocketAddr, info_hash: [u8; 20], our_peer_id: [u8; 20], timeout: Duration, encryption: crate::peer::Encryption) -> Result<Vec<u8>, MetadataFetchError> {
    let (mut stream, peer_handshake) = crate::peer::connect_and_handshake_with(addr, info_hash, our_peer_id, true, false, timeout, encryption)?;
    if !peer_handshake.supports_extensions() {
        return Err(MetadataFetchError::PeerLacksExtensionProtocol);
    }

    send_message(&mut stream, &Message::Extended { id: 0, payload: ExtendedHandshake::build(OUR_UT_METADATA_ID, None) })?;

    // Read until the peer's own extended handshake (id 0) arrives,
    // ignoring ordinary wire messages (Bitfield/Have/Choke/...) that may
    // be interleaved with it -- we're not downloading pieces on this
    // connection, so those don't need any state tracking here.
    let (peer_ut_metadata_id, total_size) = loop {
        match read_message(&mut stream)? {
            Message::Extended { id: 0, payload } => {
                let hs = ExtendedHandshake::parse(&payload)?;
                let their_id = hs.peer_ut_metadata_id().ok_or(MetadataFetchError::PeerLacksUtMetadata)?;
                let size = hs.metadata_size.ok_or(MetadataFetchError::PeerDoesNotKnowMetadataSizeYet)?;
                break (their_id, size);
            }
            _ => continue,
        }
    };

    // The size is the peer's claim, and sizes an allocation: check it first.
    let mut assembler = MetadataAssembler::for_claimed_size(total_size)?;
    for piece in 0..assembler.num_pieces() as u32 {
        send_message(&mut stream, &Message::Extended { id: peer_ut_metadata_id, payload: MetadataMessage::Request { piece }.encode() })?;
    }

    while !assembler.is_complete() {
        match read_message(&mut stream)? {
            Message::Extended { id, payload } if id == OUR_UT_METADATA_ID => match MetadataMessage::decode(&payload)? {
                MetadataMessage::Data { piece, data, .. } => assembler.add_piece(piece as usize, data)?,
                MetadataMessage::Reject { piece } => return Err(MetadataFetchError::PeerRejectedPiece(piece)),
                MetadataMessage::Request { .. } => {} // peers don't request metadata from a pure downloader; ignore
            },
            _ => continue, // unrelated wire message, e.g. Have/Bitfield/KeepAlive
        }
    }

    Ok(assembler.assemble_and_verify(&info_hash)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::handshake::Handshake;
    use crate::peer::message::Message as WireMessage;
    use sha1::{Digest, Sha1};
    use std::net::TcpListener;
    use std::thread;

    /// Mock peer: performs the handshake with the extension bit set,
    /// sends its own extended handshake advertising `ut_metadata` at a
    /// (deliberately different, to prove id-remapping works) id, then
    /// serves metadata piece requests by splitting `info_bytes`.
    fn spawn_mock_metadata_peer(listener: TcpListener, info_hash: [u8; 20], info_bytes: Vec<u8>) -> thread::JoinHandle<()> {
        const MOCK_UT_METADATA_ID: u8 = 7;
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            let mut hs_buf = [0u8; 68];
            std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
            let their_hs = Handshake::from_bytes(&hs_buf).unwrap();
            assert!(their_hs.supports_extensions());

            let our_hs = Handshake::new(info_hash, [0x55; 20], true);
            std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();

            // Read the requester's extended handshake first.
            let their_ext_hs = loop {
                match WireMessage::read_from(&mut stream).unwrap() {
                    WireMessage::Extended { id: 0, payload } => break ExtendedHandshake::parse(&payload).unwrap(),
                    _ => continue,
                }
            };
            let requester_id = their_ext_hs.peer_ut_metadata_id().unwrap();

            let our_hs_payload = ExtendedHandshake::build(MOCK_UT_METADATA_ID, Some(info_bytes.len() as i64));
            WireMessage::Extended { id: 0, payload: our_hs_payload }.write_to(&mut stream).unwrap();

            let mut asm_pieces_served = 0;
            let num_pieces = info_bytes.len().div_ceil(crate::metadata::METADATA_PIECE_SIZE);
            while asm_pieces_served < num_pieces {
                match WireMessage::read_from(&mut stream).unwrap() {
                    WireMessage::Extended { id, payload } if id == MOCK_UT_METADATA_ID => {
                        if let MetadataMessage::Request { piece } = MetadataMessage::decode(&payload).unwrap() {
                            let start = piece as usize * crate::metadata::METADATA_PIECE_SIZE;
                            let end = (start + crate::metadata::METADATA_PIECE_SIZE).min(info_bytes.len());
                            let chunk = info_bytes[start..end].to_vec();
                            let response = MetadataMessage::Data { piece, total_size: info_bytes.len() as u32, data: chunk };
                            WireMessage::Extended { id: requester_id, payload: response.encode() }.write_to(&mut stream).unwrap();
                            asm_pieces_served += 1;
                        }
                    }
                    _ => continue,
                }
            }
        })
    }

    #[test]
    fn fetches_and_verifies_metadata_end_to_end() {
        let info_bytes = b"d6:lengthi123456e4:name9:movie.mkv12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaae".to_vec();
        let mut hasher = Sha1::new();
        hasher.update(&info_bytes);
        let info_hash: [u8; 20] = hasher.finalize().into();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = spawn_mock_metadata_peer(listener, info_hash, info_bytes.clone());

        let fetched = fetch_metadata_from_peer(addr, info_hash, [0x33; 20], Duration::from_secs(5), Default::default()).unwrap();
        assert_eq!(fetched, info_bytes);
        mock.join().unwrap();
    }

    #[test]
    fn fetched_metadata_builds_a_valid_torrent_file_via_the_adapter() {
        let info_bytes = b"d6:lengthi5e4:name1:a12:piece lengthi5e6:pieces20:bbbbbbbbbbbbbbbbbbbbe".to_vec();
        let mut hasher = Sha1::new();
        hasher.update(&info_bytes);
        let info_hash: [u8; 20] = hasher.finalize().into();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = spawn_mock_metadata_peer(listener, info_hash, info_bytes.clone());

        let fetched = fetch_metadata_from_peer(addr, info_hash, [0x44; 20], Duration::from_secs(5), Default::default()).unwrap();
        let torrent = crate::torrent::from_info_dict_bytes(&fetched, info_hash, None, vec![]).unwrap();
        assert_eq!(torrent.name, "a");
        assert_eq!(torrent.total_length(), 5);
        mock.join().unwrap();
    }

    /// A peer that completes both handshakes and advertises `size` as the
    /// metadata size, then goes quiet.
    fn peer_claiming_metadata_size(size: i64) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut hs = [0u8; 68];
            if std::io::Read::read_exact(&mut stream, &mut hs).is_err() {
                return;
            }
            let ours = Handshake::new(Handshake::from_bytes(&hs).unwrap().info_hash, [0x55; 20], true);
            let _ = std::io::Write::write_all(&mut stream, &ours.to_bytes());
            let _ = WireMessage::Extended { id: 0, payload: ExtendedHandshake::build(7, Some(size)) }.write_to(&mut stream);
            thread::sleep(Duration::from_secs(2));
        });
        addr
    }

    #[test]
    fn a_peer_claiming_an_absurd_metadata_size_is_refused_before_anything_is_allocated() {
        // The size decides how much memory the assembler asks for. A peer
        // could pick it: 2^63 - 1 pieces' worth, or a negative number that
        // becomes one when cast to usize.
        for size in [-1, 0, i64::MIN, crate::metadata::MAX_METADATA_SIZE + 1, i64::MAX] {
            let addr = peer_claiming_metadata_size(size);
            let result = fetch_metadata_from_peer(addr, [0x11; 20], [0x22; 20], Duration::from_secs(2), Default::default());
            assert!(matches!(result, Err(MetadataFetchError::Metadata(crate::metadata::MetadataError::SizeNotAcceptable(n))) if n == size), "size {}: {:?}", size, result.err());
        }
    }
}
