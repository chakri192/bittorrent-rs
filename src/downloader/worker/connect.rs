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

    let mut state = PeerState::for_torrent(queue.total_pieces());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::PieceWork;
    use crate::peer::handshake::Handshake;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const INFO_HASH: [u8; 20] = [0x42; 20];

    fn config() -> WorkerConfig {
        WorkerConfig { info_hash: INFO_HASH, our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2) }
    }

    fn queue(pieces: usize) -> WorkQueue {
        WorkQueue::new((0..pieces).map(|i| PieceWork { index: i as u32, hash: [0; 20], length: 16 }).collect(), pieces)
    }

    /// A peer that completes the handshake (advertising BEP 10 support or
    /// not) and then follows `script`, which is handed the connection.
    fn fake_peer(supports_extensions: bool, script: impl FnOnce(&mut TcpStream) + Send + 'static) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hs = [0u8; 68];
            stream.read_exact(&mut hs).unwrap();
            stream.write_all(&Handshake::new(INFO_HASH, [9; 20], supports_extensions).to_bytes()).unwrap();
            script(&mut stream);
        });
        addr
    }

    /// Reads messages from the client until one satisfies `want`.
    fn read_until(stream: &mut TcpStream, want: impl Fn(&Message) -> bool) -> Message {
        loop {
            let msg = Message::read_from(stream).expect("the client should keep talking");
            if want(&msg) {
                return msg;
            }
        }
    }

    #[test]
    fn establish_says_it_is_interested_and_returns_once_the_peer_unchokes() {
        let (seen_tx, seen_rx) = mpsc::channel();
        let addr = fake_peer(false, move |stream| {
            // A real peer will not unchoke us until we have said we are interested.
            read_until(stream, |m| matches!(m, Message::Interested));
            seen_tx.send(()).unwrap();
            Message::Unchoke.write_to(stream).unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        let (_stream, state) = establish(addr, &config(), &queue(1), None).expect("connected and unchoked");

        seen_rx.try_recv().expect("the peer received Interested before it unchoked us");
        assert!(!state.peer_choking);
        assert!(state.am_interested);
        assert!(!state.supports_extensions, "the peer did not advertise BEP 10");
    }

    /// Whether the client's extended handshake offered ut_pex, when it is
    /// given a PEX channel (`Some`) or not (`None`, a private torrent).
    fn offers_pex(channel: Option<PexSender>) -> bool {
        let (tx, rx) = mpsc::channel();
        let addr = fake_peer(true, move |stream| {
            let Message::Extended { payload, .. } = read_until(stream, |m| matches!(m, Message::Extended { id: 0, .. })) else { unreachable!() };
            tx.send(ExtendedHandshake::parse(&payload).unwrap().peer_ut_pex_id().is_some()).unwrap();
            read_until(stream, |m| matches!(m, Message::Interested));
            Message::Unchoke.write_to(stream).unwrap();
            thread::sleep(Duration::from_millis(200));
        });
        establish(addr, &config(), &queue(1), channel.as_ref()).expect("connected and unchoked");
        rx.recv_timeout(Duration::from_secs(2)).expect("the peer saw an extended handshake")
    }

    #[test]
    fn an_extension_capable_peer_is_offered_pex_only_when_there_is_a_channel_for_it() {
        let (tx, _rx) = mpsc::channel();
        assert!(offers_pex(Some(tx)));
        assert!(!offers_pex(None), "BEP 27: a private torrent's workers do not advertise ut_pex");
    }

    #[test]
    fn what_the_peer_says_while_choked_updates_the_state_and_the_queue() {
        let addr = fake_peer(false, |stream| {
            Message::Bitfield(vec![0b0110_0000]).write_to(stream).unwrap();
            Message::Unchoke.write_to(stream).unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        let (_stream, state) = establish(addr, &config(), &queue(4), None).unwrap();

        assert_eq!(&state.peer_has_pieces[..4], &[false, true, true, false], "the bitfield sent before the unchoke was kept");
    }

    #[test]
    fn a_peer_that_hangs_up_before_unchoking_is_a_named_failure() {
        let addr = fake_peer(false, |_stream| {}); // handshake, then close

        let err = establish(addr, &config(), &queue(1), None).expect_err("no unchoke ever comes");

        // Depending on timing the client notices on its write or on its read.
        assert!(matches!(err, WorkerError::Connection { stage, .. } if stage == "wait_for_unchoke" || stage == "send_interested"), "got {:?}", err);
    }

    #[test]
    fn an_unreachable_peer_fails_at_the_connect_stage() {
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let err = establish(dead, &config(), &queue(1), None).expect_err("nothing is listening");
        assert!(matches!(err, WorkerError::Connection { stage: "connect_and_handshake", .. }), "got {:?}", err);
    }

    #[test]
    fn a_hostile_have_and_oversized_bitfield_cannot_grow_the_peers_state() {
        let addr = fake_peer(false, |stream| {
            Message::Have { piece_index: u32::MAX }.write_to(stream).unwrap();
            Message::Bitfield(vec![0xff; 1000]).write_to(stream).unwrap();
            Message::Unchoke.write_to(stream).unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        let (_stream, state) = establish(addr, &config(), &queue(4), None).unwrap();

        assert_eq!(state.peer_has_pieces.len(), 4, "the torrent has 4 pieces, whatever the peer claims");
    }
}
