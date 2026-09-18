//! What a worker does with each message a peer sends it.

use super::PexSender;
use crate::downloader::queue::WorkQueue;
use crate::peer::extension::OUR_UT_PEX_ID;
use crate::peer::pex::parse_ut_pex;
use crate::peer::{ConnectionError, Message, PeerState, WireError};

/// A read timeout on a blocking socket surfaces as `WouldBlock` on Unix
/// (`SO_RCVTIMEO` semantics) and `TimedOut` on Windows. Either way it
/// means "no data yet", **not** "connection dead" -- a distinction this
/// client originally got wrong, dropping the only peer in a swarm that
/// had completed the handshake because it took >10s to unchoke.
pub(super) fn is_read_timeout(e: &ConnectionError) -> bool {
    matches!(
        e,
        ConnectionError::Wire(WireError::Io(io_err))
            if io_err.kind() == std::io::ErrorKind::WouldBlock || io_err.kind() == std::io::ErrorKind::TimedOut
    )
}

/// Applies an incoming message to every piece of shared/per-peer state a
/// worker tracks: the rarity tracker (Bitfield/Have), the peer's
/// choke/interest/bitfield state, and PEX peer discovery (Extended
/// ut_pex). Returns `true` if the message affected peer state (used as
/// the "this peer is still doing something relevant" signal).
pub(super) fn absorb(msg: &Message, state: &mut PeerState, queue: &WorkQueue, pex_tx: Option<&PexSender>) -> bool {
    match msg {
        Message::Bitfield(_) => {
            // `PeerState::apply_message` decodes the raw bytes into
            // per-piece bools; reuse that instead of re-implementing the
            // bit-unpacking here.
            let mut scratch = PeerState::new();
            scratch.apply_message(msg);
            queue.note_bitfield(&scratch.peer_has_pieces);
        }
        Message::Have { piece_index } => queue.note_have(*piece_index),
        Message::Extended { id, payload } if *id == OUR_UT_PEX_ID => {
            // Peers push these unprompted once we advertise ut_pex in the
            // extended handshake -- free peer addresses for the dial
            // queue. Parse failures are ignored: PEX is best-effort
            // gravy, never worth dropping a working piece connection over.
            if let (Some(tx), Ok(peers)) = (pex_tx, parse_ut_pex(payload)) {
                if !peers.is_empty() {
                    let _ = tx.send(peers);
                }
            }
            return true; // an active extension message = live peer
        }
        _ => {}
    }
    state.apply_message(msg)
}
