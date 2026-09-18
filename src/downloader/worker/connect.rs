//! Getting a connection ready to download from.

use super::{absorb, is_read_timeout, PexSender, WorkerConfig, WorkerError};
use crate::downloader::queue::WorkQueue;
use crate::peer::{connect_and_handshake, ConnectionError, ExtendedHandshake, Message, PeerState, WireError};
use std::net::{SocketAddr, TcpStream};

/// How many read timeouts in a row to sit through while waiting for the
/// peer to unchoke us before giving up on it.
const MAX_UNCHOKE_WAIT_TIMEOUTS: u32 = 6;

/// Connects to `peer_addr`, does the BitTorrent handshake and (if the peer
/// supports it) the extended one, tells the peer we are interested, and
/// waits to be unchoked. Returns the connection and what is known of the
/// peer, ready for block requests.
///
/// Bitfield, Have and PEX messages that arrive while waiting update the
/// shared rarity tracker and the PEX feed as a side effect.
pub(super) fn establish(peer_addr: SocketAddr, config: &WorkerConfig, queue: &WorkQueue, pex_tx: Option<&PexSender>) -> Result<(TcpStream, PeerState), WorkerError> {
    let (mut stream, peer_handshake) =
        connect_and_handshake(peer_addr, config.info_hash, config.our_peer_id, true, config.connect_timeout).map_err(|e| WorkerError::Connection { stage: "connect_and_handshake", error: e })?;

    let mut state = PeerState::new();
    state.supports_extensions = peer_handshake.supports_extensions();

    if state.supports_extensions {
        // BEP 10 extended handshake, sent first thing after the BT
        // handshake per convention. Advertises ut_pex (and ut_metadata,
        // though piece workers never serve metadata) so peers know they
        // can push us PEX updates -- but only when a `pex_tx` exists to
        // receive them. The caller passes `None` for private torrents
        // (BEP 27), and advertising PEX we'd then discard is pointless.
        crate::peer::connection::send_message(&mut stream, &Message::Extended { id: 0, payload: ExtendedHandshake::build_with_pex(1, None, pex_tx.is_some()) })
            .map_err(|e| WorkerError::Connection { stage: "send_extended_handshake", error: e })?;
    }

    crate::peer::connection::send_message(&mut stream, &Message::Interested).map_err(|e| WorkerError::Connection { stage: "send_interested", error: e })?;
    state.am_interested = true;

    // Drain messages until unchoked or the peer disconnects. Bitfield/
    // Have/Extended messages that arrive in the meantime update `state`
    // (and the shared rarity tracker / PEX feed) as a side effect.
    //
    // Read timeouts here are NOT fatal: many clients unchoke lazily
    // (choke-algorithm rounds run every 10-30s), so with a 10s read
    // timeout the first read can legitimately time out several times in
    // a row against a perfectly good peer. Bounded so a peer that never
    // unchokes still frees its slot: with the default 10s read timeout
    // this waits up to ~60s, roughly two choke-algorithm rounds.
    let mut unchoke_timeouts = 0u32;
    while state.peer_choking {
        match crate::peer::connection::read_message(&mut stream) {
            Ok(msg) => {
                absorb(&msg, &mut state, queue, pex_tx);
            }
            Err(ref e) if is_read_timeout(e) => {
                unchoke_timeouts += 1;
                if unchoke_timeouts >= MAX_UNCHOKE_WAIT_TIMEOUTS {
                    return Err(WorkerError::Connection {
                        stage: "peer_never_unchoked",
                        error: ConnectionError::Wire(WireError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "peer stayed choked through the whole wait budget"))),
                    });
                }
                // Show liveness so the peer's own idle-timeout doesn't
                // reap us while we politely wait out its choke round.
                crate::peer::connection::send_message(&mut stream, &Message::KeepAlive).map_err(|e| WorkerError::Connection { stage: "keepalive_during_unchoke_wait", error: e })?;
            }
            Err(e) => return Err(WorkerError::Connection { stage: "wait_for_unchoke", error: e }),
        }
    }

    Ok((stream, state))
}
