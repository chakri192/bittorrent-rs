//! What a worker does with each message a peer sends it.

use super::{PexSender, WorkerError};
use crate::downloader::queue::WorkQueue;
use crate::peer::extension::{ExtendedHandshake, OUR_UT_PEX_ID};
use crate::peer::pex::parse_ut_pex;
use crate::peer::{ConnectionError, Message, PeerState, PeerStream, WireError};
use crate::serving::Serving;

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
        // BEP 6: the same as a bitfield with every bit set.
        Message::HaveAll => {
            let mut scratch = PeerState::for_torrent(queue.total_pieces());
            scratch.apply_message(msg);
            queue.note_bitfield(&scratch.peer_has_pieces);
        }
        Message::Have { piece_index } => queue.note_have(*piece_index),
        // The peer's extended handshake (BEP 10): the one thing the worker
        // takes from it is how many requests the peer will queue.
        Message::Extended { id: 0, payload } => {
            if let Ok(handshake) = ExtendedHandshake::parse(payload) {
                state.peer_request_limit = handshake.reqq.map(|n| n as usize);
            }
        }
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

/// What a peer sent, taken by both halves of the connection: the upload side answers what is asked of it
/// (a block, the info dictionary, hashes) and hears of the peer's interest, and then the download side
/// applies it. Says whether it showed the peer to be doing something. A connection with nothing to serve
/// only does the second.
pub(super) fn take(msg: &Message, state: &mut PeerState, queue: &WorkQueue, pex_tx: Option<&PexSender>, serving: &mut Option<Serving>, stream: &mut dyn PeerStream) -> Result<bool, WorkerError> {
    let asked = match serving {
        Some(serving) => serving.handle(msg, stream).map_err(|e| WorkerError::Connection { stage: "serve_peer", error: ConnectionError::Io(e) })?,
        None => false,
    };
    Ok(absorb(msg, state, queue, pex_tx) || asked)
}

/// What the upload side has to say between messages: the pieces verified since, and a change of who is unchoked.
pub(super) fn keep_serving(serving: &mut Option<Serving>, stream: &mut dyn PeerStream) -> Result<(), WorkerError> {
    match serving {
        Some(serving) => serving.tick(stream).map_err(|e| WorkerError::Connection { stage: "serve_peer", error: ConnectionError::Io(e) }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::PieceWork;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use std::sync::mpsc;

    fn queue(pieces: usize) -> WorkQueue {
        WorkQueue::new((0..pieces).map(|i| PieceWork { index: i as u32, hash: [0; 20], length: 16, merkle: None }).collect(), pieces)
    }

    /// A ut_pex payload announcing the given compact peers.
    fn pex(peers: &[[u8; 6]]) -> Vec<u8> {
        let added = peers.concat();
        let mut payload = format!("d5:added{}:", added.len()).into_bytes();
        payload.extend_from_slice(&added);
        payload.push(b'e');
        payload
    }

    fn pex_message(payload: Vec<u8>) -> Message {
        Message::Extended { id: OUR_UT_PEX_ID, payload }
    }

    /// The order the queue would hand pieces out in, which is rarest first.
    fn pop_order(q: &WorkQueue) -> Vec<u32> {
        std::iter::from_fn(|| q.pop()).map(|w| w.index).take(q.len()).collect()
    }

    #[test]
    fn a_bitfield_updates_the_peers_state_and_the_queues_rarity() {
        let q = queue(4);
        let mut state = PeerState::new();

        // The peer has pieces 0 and 3 (bits are most-significant first).
        let active = absorb(&Message::Bitfield(vec![0b1001_0000]), &mut state, &q, None);

        assert!(active, "a bitfield is the peer doing something");
        assert_eq!(&state.peer_has_pieces[..4], &[true, false, false, true]);
        // Pieces 1 and 2 now have no holder, so they are the rarest and go
        // first. (With no rarity data the queue would hand out 0 and 3
        // first, so this fails if the bitfield is not fed to it.)
        let order = pop_order(&q);
        assert_eq!(order.iter().take(2).copied().collect::<std::collections::BTreeSet<_>>(), [1, 2].into(), "got {:?}", order);
    }

    #[test]
    fn have_all_counts_every_piece_as_held_by_the_peer_like_a_full_bitfield() {
        let q = queue(4);
        let mut state = PeerState::for_torrent(4);
        let active = absorb(&Message::HaveAll, &mut state, &q, None);

        assert!(active);
        assert_eq!(state.peer_has_pieces, vec![true; 4]);
        assert_eq!(q.availability(), vec![1, 1, 1, 1]);
    }

    fn extended_handshake(body: &str) -> Message {
        Message::Extended { id: 0, payload: body.as_bytes().to_vec() }
    }

    #[test]
    fn the_peers_extended_handshake_tells_the_worker_how_many_requests_it_queues() {
        let q = queue(1);
        let mut state = PeerState::new();
        assert_eq!(state.peer_request_limit, None);

        absorb(&extended_handshake("d1:mde4:reqqi42ee"), &mut state, &q, None);

        assert_eq!(state.peer_request_limit, Some(42));
    }

    #[test]
    fn a_handshake_without_reqq_or_with_nonsense_leaves_no_limit_and_never_costs_the_connection() {
        let q = queue(1);
        let mut state = PeerState::new();

        absorb(&extended_handshake("d1:mdee"), &mut state, &q, None);
        assert_eq!(state.peer_request_limit, None, "no reqq, no limit");

        state.peer_request_limit = Some(7);
        absorb(&extended_handshake("this is not bencode"), &mut state, &q, None);
        assert_eq!(state.peer_request_limit, Some(7), "garbage changes nothing");

        absorb(&extended_handshake("d1:mde4:reqqi0ee"), &mut state, &q, None);
        assert_eq!(state.peer_request_limit, None, "a zero reqq is no limit at all");
    }

    #[test]
    fn a_have_makes_that_piece_less_rare() {
        let q = queue(4);
        let mut state = PeerState::new();

        assert!(absorb(&Message::Have { piece_index: 2 }, &mut state, &q, None));

        assert_eq!(pop_order(&q).last(), Some(&2), "piece 2 has a holder now, so it is handed out last");
    }

    #[test]
    fn pex_addresses_go_to_the_channel_and_count_as_activity() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();

        let active = absorb(&pex_message(pex(&[[10, 1, 2, 3, 0x1a, 0x0b]])), &mut state, &queue(1), Some(&tx));

        assert!(active);
        assert_eq!(rx.try_recv().unwrap(), vec!["10.1.2.3:6667".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn without_a_channel_pex_is_dropped_but_the_peer_still_counts_as_alive() {
        // The caller passes no channel for a private torrent (BEP 27).
        let mut state = PeerState::new();
        assert!(absorb(&pex_message(pex(&[[10, 1, 2, 3, 0x1a, 0x0b]])), &mut state, &queue(1), None));
    }

    #[test]
    fn an_empty_pex_batch_is_not_forwarded() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();
        assert!(absorb(&pex_message(b"d5:added0:e".to_vec()), &mut state, &queue(1), Some(&tx)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_malformed_pex_payload_is_ignored_and_never_costs_the_connection() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();
        assert!(absorb(&pex_message(b"this is not bencode".to_vec()), &mut state, &queue(1), Some(&tx)), "still a live peer");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn an_extension_message_we_did_not_ask_for_is_ordinary_traffic() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();
        let other = Message::Extended { id: OUR_UT_PEX_ID + 1, payload: pex(&[[10, 1, 2, 3, 0x1a, 0x0b]]) };

        assert!(!absorb(&other, &mut state, &queue(1), Some(&tx)), "it changes nothing, so it is not evidence of activity");
        assert!(rx.try_recv().is_err(), "and its payload is not read as PEX");
    }

    #[test]
    fn choke_and_unchoke_change_the_peers_state() {
        let mut state = PeerState::new();
        assert!(state.peer_choking);
        assert!(absorb(&Message::Unchoke, &mut state, &queue(1), None));
        assert!(!state.peer_choking);
        assert!(absorb(&Message::Choke, &mut state, &queue(1), None));
        assert!(state.peer_choking);
    }

    fn wire_io(kind: ErrorKind) -> ConnectionError {
        ConnectionError::Wire(WireError::Io(std::io::Error::new(kind, "x")))
    }

    #[test]
    fn a_read_timeout_is_told_apart_from_a_dead_connection() {
        // WouldBlock on Unix, TimedOut on Windows: both mean "nothing yet".
        assert!(is_read_timeout(&wire_io(ErrorKind::WouldBlock)));
        assert!(is_read_timeout(&wire_io(ErrorKind::TimedOut)));
        assert!(!is_read_timeout(&wire_io(ErrorKind::UnexpectedEof)));
        assert!(!is_read_timeout(&wire_io(ErrorKind::ConnectionReset)));
        assert!(!is_read_timeout(&ConnectionError::InfoHashMismatch));
    }

    #[test]
    fn a_timeout_from_the_socket_itself_is_not_a_read_timeout() {
        // Only a timeout while reading a message counts: a connect or write
        // that times out is a real failure.
        assert!(!is_read_timeout(&ConnectionError::Io(std::io::Error::new(ErrorKind::TimedOut, "x"))));
    }
}
