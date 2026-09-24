//! What a worker does with each message a peer sends it.

use super::{Holepunch, PexSender, WorkerConfig, WorkerError};
use crate::downloader::queue::WorkQueue;
use crate::peer::extension::{ExtendedHandshake, OUR_UT_HOLEPUNCH_ID, OUR_UT_PEX_ID};
use crate::peer::holepunch::{ErrorCode, HolepunchMessage};
use crate::peer::pex::parse_ut_pex;
use crate::peer::{ConnectionError, Message, PeerState, PeerStream, WireError};
use crate::serving::Serving;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

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
pub(super) fn absorb(msg: &Message, state: &mut PeerState, queue: &WorkQueue, pex_tx: Option<&PexSender>, holepunch: &mut Holepunch) -> bool {
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
        // takes from it is how many requests the peer will queue, and (BEP
        // 55) the id to reach it with for ut_holepunch, if it offers one.
        // `their_id` is set before the shared flag, so another connection
        // that sees the flag flip can never race ahead of it (see
        // `relay_pending_holepunch`'s own doc comment).
        Message::Extended { id: 0, payload } => {
            if let Ok(handshake) = ExtendedHandshake::parse(payload) {
                state.peer_request_limit = handshake.reqq.map(|n| n as usize);
                if let Some(id) = handshake.peer_ut_holepunch_id() {
                    holepunch.their_id = Some(id);
                    holepunch.supports.store(true, Ordering::Relaxed);
                }
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
        Message::Extended { id, .. } if *id == OUR_UT_HOLEPUNCH_ID => return true, // handled in `handle_holepunch`; still evidence of a live peer
        _ => {}
    }
    state.apply_message(msg)
}

/// BEP 55: reacts to an incoming `ut_holepunch` message, if `msg` is one. Everything else about a
/// rendezvous/connect/error's effect needs either a reply on `stream` (this same connection) or a
/// relay onto another one (`config.holepunch`), neither of which `absorb` has, hence a function of
/// its own rather than another `absorb` branch.
///
/// - `rendezvous` (we are the relay, "R"): silently ignored if the sender (`peer_addr`) never
///   itself advertised the extension (a bare handshake bit is our only proof it understands a
///   reply, per the BEP's own implementation note); otherwise a `connect` is relayed to the named
///   target if we are connected to it and it supports the extension too, with a `connect` naming
///   the target sent straight back over `stream` as well; anything else earns an error reply
///   (`NotConnected` or `NoSupport`) rather than silence, per BEP 55.
/// - `connect` (we are either side of the introduction): queues the endpoint for the coordinator
///   to dial over uTP, unless we are already connected to it (silently ignored either way if we
///   are -- the BEP requires exactly that, and dialing a peer we already have would be pointless).
/// - `error`: nothing to act on (this client tracks no pending rendezvous to resolve); read and
///   discarded rather than treated as a protocol violation.
fn handle_holepunch(msg: &Message, holepunch: &Holepunch, config: &WorkerConfig, peer_addr: SocketAddr, stream: &mut dyn PeerStream) -> Result<(), WorkerError> {
    let Message::Extended { id, payload } = msg else { return Ok(()) };
    if *id != OUR_UT_HOLEPUNCH_ID {
        return Ok(());
    }
    let Ok(parsed) = HolepunchMessage::decode(payload) else { return Ok(()) };
    match parsed {
        HolepunchMessage::Rendezvous { target } => {
            if holepunch.their_id.is_none() {
                return Ok(()); // the sender never advertised it; BEP 55 says ignore silently
            }
            let reply = if config.holepunch.relay(target, HolepunchMessage::Connect { endpoint: peer_addr }) {
                HolepunchMessage::Connect { endpoint: target }
            } else if config.holepunch.is_unsupported(&target) {
                HolepunchMessage::Error { target, code: ErrorCode::NoSupport }
            } else {
                HolepunchMessage::Error { target, code: ErrorCode::NotConnected }
            };
            send_holepunch(stream, reply)?;
        }
        HolepunchMessage::Connect { endpoint } => {
            if !config.peers.contains(&endpoint) {
                config.holepunch.request_dial(endpoint);
            }
        }
        HolepunchMessage::Error { .. } => {}
    }
    Ok(())
}

/// Writes one holepunch reply back on this same connection, tagged with *our own* id for it
/// (fixed, unlike the peer's -- see [`OUR_UT_HOLEPUNCH_ID`]).
fn send_holepunch(stream: &mut dyn PeerStream, msg: HolepunchMessage) -> Result<(), WorkerError> {
    crate::peer::connection::send_message(stream, &Message::Extended { id: OUR_UT_HOLEPUNCH_ID, payload: msg.encode() }).map_err(|e| WorkerError::Connection { stage: "reply_holepunch", error: e })
}

/// What a peer sent, taken by both halves of the connection: the upload side answers what is asked of it
/// (a block, the info dictionary, hashes) and hears of the peer's interest, and then the download side
/// applies it. Says whether it showed the peer to be doing something. A connection with nothing to serve
/// only does the second.
#[allow(clippy::too_many_arguments)]
pub(super) fn take(msg: &Message, state: &mut PeerState, queue: &WorkQueue, pex_tx: Option<&PexSender>, config: &WorkerConfig, peer_addr: SocketAddr, serving: &mut Option<Serving>, holepunch: &mut Holepunch, stream: &mut dyn PeerStream) -> Result<bool, WorkerError> {
    let asked = match serving {
        Some(serving) => serving.handle(msg, stream).map_err(|e| WorkerError::Connection { stage: "serve_peer", error: ConnectionError::Io(e) })?,
        None => false,
    };
    let active = absorb(msg, state, queue, pex_tx, holepunch);
    handle_holepunch(msg, holepunch, config, peer_addr, stream)?;
    Ok(active || asked)
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
    use super::super::HolepunchHub;
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

    /// A `Holepunch` with nothing of its own to say, for tests that don't care about BEP 55.
    fn no_holepunch(hub: &HolepunchHub) -> Holepunch<'_> {
        Holepunch::register(hub, "10.0.0.9:1".parse().unwrap())
    }

    #[test]
    fn a_bitfield_updates_the_peers_state_and_the_queues_rarity() {
        let q = queue(4);
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);

        // The peer has pieces 0 and 3 (bits are most-significant first).
        let active = absorb(&Message::Bitfield(vec![0b1001_0000]), &mut state, &q, None, &mut holepunch);

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
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        let active = absorb(&Message::HaveAll, &mut state, &q, None, &mut holepunch);

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
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        assert_eq!(state.peer_request_limit, None);

        absorb(&extended_handshake("d1:mde4:reqqi42ee"), &mut state, &q, None, &mut holepunch);

        assert_eq!(state.peer_request_limit, Some(42));
    }

    #[test]
    fn the_peers_extended_handshake_sets_its_holepunch_id_and_marks_it_supported() {
        let q = queue(1);
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        assert_eq!(holepunch.their_id, None);
        assert!(!holepunch.supports.load(Ordering::Relaxed));

        absorb(&extended_handshake("d1:md12:ut_holepunchi7eee"), &mut state, &q, None, &mut holepunch);

        assert_eq!(holepunch.their_id, Some(7));
        assert!(holepunch.supports.load(Ordering::Relaxed), "another connection's relay lookup must see this");
    }

    #[test]
    fn a_handshake_without_ut_holepunch_leaves_it_unset() {
        let q = queue(1);
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);

        absorb(&extended_handshake("d1:mdee"), &mut state, &q, None, &mut holepunch);

        assert_eq!(holepunch.their_id, None);
        assert!(!holepunch.supports.load(Ordering::Relaxed));
    }

    #[test]
    fn a_handshake_without_reqq_or_with_nonsense_leaves_no_limit_and_never_costs_the_connection() {
        let q = queue(1);
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);

        absorb(&extended_handshake("d1:mdee"), &mut state, &q, None, &mut holepunch);
        assert_eq!(state.peer_request_limit, None, "no reqq, no limit");

        state.peer_request_limit = Some(7);
        absorb(&extended_handshake("this is not bencode"), &mut state, &q, None, &mut holepunch);
        assert_eq!(state.peer_request_limit, Some(7), "garbage changes nothing");

        absorb(&extended_handshake("d1:mde4:reqqi0ee"), &mut state, &q, None, &mut holepunch);
        assert_eq!(state.peer_request_limit, None, "a zero reqq is no limit at all");
    }

    #[test]
    fn a_have_makes_that_piece_less_rare() {
        let q = queue(4);
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);

        assert!(absorb(&Message::Have { piece_index: 2 }, &mut state, &q, None, &mut holepunch));

        assert_eq!(pop_order(&q).last(), Some(&2), "piece 2 has a holder now, so it is handed out last");
    }

    #[test]
    fn pex_addresses_go_to_the_channel_and_count_as_activity() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);

        let active = absorb(&pex_message(pex(&[[10, 1, 2, 3, 0x1a, 0x0b]])), &mut state, &queue(1), Some(&tx), &mut holepunch);

        assert!(active);
        assert_eq!(rx.try_recv().unwrap(), vec!["10.1.2.3:6667".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn without_a_channel_pex_is_dropped_but_the_peer_still_counts_as_alive() {
        // The caller passes no channel for a private torrent (BEP 27).
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        assert!(absorb(&pex_message(pex(&[[10, 1, 2, 3, 0x1a, 0x0b]])), &mut state, &queue(1), None, &mut holepunch));
    }

    #[test]
    fn an_empty_pex_batch_is_not_forwarded() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        assert!(absorb(&pex_message(b"d5:added0:e".to_vec()), &mut state, &queue(1), Some(&tx), &mut holepunch));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_malformed_pex_payload_is_ignored_and_never_costs_the_connection() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        assert!(absorb(&pex_message(b"this is not bencode".to_vec()), &mut state, &queue(1), Some(&tx), &mut holepunch), "still a live peer");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn an_extension_message_we_did_not_ask_for_is_ordinary_traffic() {
        let (tx, rx) = mpsc::channel();
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        // Not 0 (the handshake), OUR_UT_PEX_ID or OUR_UT_HOLEPUNCH_ID -- an id this client has claimed for nothing.
        let other = Message::Extended { id: 99, payload: pex(&[[10, 1, 2, 3, 0x1a, 0x0b]]) };

        assert!(!absorb(&other, &mut state, &queue(1), Some(&tx), &mut holepunch), "it changes nothing, so it is not evidence of activity");
        assert!(rx.try_recv().is_err(), "and its payload is not read as PEX");
    }

    #[test]
    fn choke_and_unchoke_change_the_peers_state() {
        let mut state = PeerState::new();
        let hub = HolepunchHub::default();
        let mut holepunch = no_holepunch(&hub);
        assert!(state.peer_choking);
        assert!(absorb(&Message::Unchoke, &mut state, &queue(1), None, &mut holepunch));
        assert!(!state.peer_choking);
        assert!(absorb(&Message::Choke, &mut state, &queue(1), None, &mut holepunch));
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

    // ---- BEP 55: handle_holepunch ----

    mod holepunch_tests {
        use super::*;
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::time::Duration;

        fn addr(last: u8) -> SocketAddr {
            format!("10.0.0.{}:6881", last).parse().unwrap()
        }

        /// A connected loopback pair: writes to `.0` (what `handle_holepunch` is given as `stream`)
        /// arrive readable on `.1` (what a test reads a reply back from).
        fn stream_pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            client.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            server.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            (client, server)
        }

        fn config() -> WorkerConfig {
            WorkerConfig { info_hash: [1; 20], our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None, holepunch: Default::default(), utp6: None }
        }

        fn rendezvous(target: SocketAddr) -> Message {
            Message::Extended { id: OUR_UT_HOLEPUNCH_ID, payload: HolepunchMessage::Rendezvous { target }.encode() }
        }

        /// Reads one holepunch reply from `stream`, decoded.
        fn read_reply(stream: &mut TcpStream) -> HolepunchMessage {
            let Message::Extended { id, payload } = Message::read_from(stream).expect("a reply") else { panic!("not an extended message") };
            assert_eq!(id, OUR_UT_HOLEPUNCH_ID);
            HolepunchMessage::decode(&payload).expect("a valid holepunch payload")
        }

        #[test]
        fn a_rendezvous_from_a_peer_that_never_advertised_support_is_ignored_silently() {
            let config = config();
            let hub = HolepunchHub::default();
            let holepunch = no_holepunch(&hub); // their_id stays None: never advertised
            let (mut client, mut server) = stream_pair();

            handle_holepunch(&rendezvous(addr(9)), &holepunch, &config, addr(1), &mut client).unwrap();

            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            server.read_to_end(&mut buf).unwrap();
            assert!(buf.is_empty(), "not even an error is sent back, per the BEP's own note");
        }

        /// A `Holepunch` whose sender has advertised support (so rendezvous is not ignored outright).
        fn supporting_holepunch(hub: &HolepunchHub, addr: SocketAddr) -> Holepunch<'_> {
            let mut h = Holepunch::register(hub, addr);
            h.their_id = Some(7);
            h
        }

        #[test]
        fn a_rendezvous_naming_a_peer_we_are_not_connected_to_gets_not_connected() {
            let config = config();
            let hub = HolepunchHub::default();
            let holepunch = supporting_holepunch(&hub, addr(1));
            let (mut client, mut server) = stream_pair();
            let target = addr(9);

            handle_holepunch(&rendezvous(target), &holepunch, &config, addr(1), &mut client).unwrap();

            assert_eq!(read_reply(&mut server), HolepunchMessage::Error { target, code: ErrorCode::NotConnected });
        }

        #[test]
        fn a_rendezvous_naming_a_connected_peer_that_does_not_support_it_gets_no_support() {
            let config = config();
            let hub = HolepunchHub::default();
            let holepunch = supporting_holepunch(&hub, addr(1));
            let target = addr(9);
            let (_target_entry, _target_rx) = config.holepunch.enter(target); // connected, but never marked supported
            let (mut client, mut server) = stream_pair();

            handle_holepunch(&rendezvous(target), &holepunch, &config, addr(1), &mut client).unwrap();

            assert_eq!(read_reply(&mut server), HolepunchMessage::Error { target, code: ErrorCode::NoSupport });
        }

        #[test]
        fn a_rendezvous_naming_a_capable_connected_peer_relays_connect_and_answers_the_sender() {
            let config = config();
            let hub = HolepunchHub::default();
            let sender_addr = addr(1);
            let holepunch = supporting_holepunch(&hub, sender_addr);
            let target = addr(9);
            let (target_entry, target_rx) = config.holepunch.enter(target);
            target_entry.supports.store(true, Ordering::Relaxed);
            let (mut client, mut server) = stream_pair();

            handle_holepunch(&rendezvous(target), &holepunch, &config, sender_addr, &mut client).unwrap();

            assert_eq!(read_reply(&mut server), HolepunchMessage::Connect { endpoint: target }, "the sender is told the target's endpoint");
            assert_eq!(target_rx.try_recv().unwrap(), HolepunchMessage::Connect { endpoint: sender_addr }, "and the target is relayed the sender's");
        }

        fn connect_msg(endpoint: SocketAddr) -> Message {
            Message::Extended { id: OUR_UT_HOLEPUNCH_ID, payload: HolepunchMessage::Connect { endpoint }.encode() }
        }

        #[test]
        fn a_connect_to_an_address_already_connected_is_ignored_and_nothing_is_queued() {
            let config = config();
            let hub = HolepunchHub::default();
            let holepunch = no_holepunch(&hub);
            let endpoint = addr(9);
            let _already = config.peers.enter(endpoint, std::time::Instant::now());
            let (mut client, _server) = stream_pair();

            handle_holepunch(&connect_msg(endpoint), &holepunch, &config, addr(1), &mut client).unwrap();

            assert!(config.holepunch.take_dial_targets().is_empty(), "already connected, so not queued for a reactive dial");
        }

        #[test]
        fn a_connect_to_a_fresh_address_is_queued_for_a_reactive_dial() {
            let config = config();
            let hub = HolepunchHub::default();
            let holepunch = no_holepunch(&hub);
            let endpoint = addr(9);
            let (mut client, _server) = stream_pair();

            handle_holepunch(&connect_msg(endpoint), &holepunch, &config, addr(1), &mut client).unwrap();

            assert_eq!(config.holepunch.take_dial_targets(), vec![endpoint]);
        }

        #[test]
        fn an_error_message_is_read_and_discarded_without_a_reply() {
            let config = config();
            let hub = HolepunchHub::default();
            let holepunch = no_holepunch(&hub);
            let (mut client, mut server) = stream_pair();
            let msg = Message::Extended { id: OUR_UT_HOLEPUNCH_ID, payload: HolepunchMessage::Error { target: addr(9), code: ErrorCode::NotConnected }.encode() };

            handle_holepunch(&msg, &holepunch, &config, addr(1), &mut client).unwrap();

            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            server.read_to_end(&mut buf).unwrap();
            assert!(buf.is_empty());
        }

        #[test]
        fn a_message_with_a_different_extension_id_is_not_treated_as_holepunch() {
            let config = config();
            let hub = HolepunchHub::default();
            let holepunch = supporting_holepunch(&hub, addr(1));
            let (mut client, mut server) = stream_pair();
            let msg = Message::Extended { id: OUR_UT_HOLEPUNCH_ID + 1, payload: HolepunchMessage::Rendezvous { target: addr(9) }.encode() };

            handle_holepunch(&msg, &holepunch, &config, addr(1), &mut client).unwrap();

            client.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            server.read_to_end(&mut buf).unwrap();
            assert!(buf.is_empty(), "wrong id: not ours to answer");
        }
    }
}
