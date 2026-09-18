//! The actual per-peer event loop: connect, handshake, pipeline block
//! requests to keep the peer's pipe full, assemble+verify each piece, and
//! write it to disk. Like `peer::connection`, this is a thin orchestration
//! layer over primitives that are independently unit-tested
//! (`piece_assembler.rs`, `queue.rs`, `file_writer.rs`, `peer::*`).

use crate::downloader::file_writer::{write_piece, FileSpan};
use crate::downloader::piece_assembler::PieceAssembler;
use crate::downloader::queue::{PieceResult, WorkQueue};
use crate::peer::extension::OUR_UT_PEX_ID;
use crate::peer::pex::parse_ut_pex;
use crate::peer::{connect_and_handshake, ConnectionError, ExtendedHandshake, Message, PeerState, WireError};
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

pub struct WorkerConfig {
    pub info_hash: [u8; 20],
    pub our_peer_id: [u8; 20],
    /// Max outstanding (requested, not-yet-received) blocks per piece.
    /// 5 is the long-standing convention (mainline/libtorrent default
    /// range is ~5-10) that keeps a 16 KiB*5 = 80 KiB window in flight --
    /// enough to hide one round trip's latency without over-committing to
    /// a peer that turns out to be slow.
    pub pipeline_depth: usize,
    pub connect_timeout: Duration,
}

/// Addresses learned from a peer via ut_pex (BEP 11), reported back to
/// the coordinator so they can join the dial queue.
pub type PexSender = Sender<Vec<SocketAddr>>;

#[derive(Debug)]
pub enum WorkerError {
    /// `stage` names exactly where in the exchange the failure happened
    /// (e.g. "connect_and_handshake", "wait_for_unchoke",
    /// "read_message_during_piece_download") -- an `UnexpectedEof` right
    /// after connecting means something very different from one after
    /// 500 successfully-received blocks, and the two used to be
    /// indistinguishable from the caller's side.
    Connection { stage: &'static str, error: ConnectionError },
    PieceHashMismatch,
}

impl From<ConnectionError> for WorkerError {
    fn from(e: ConnectionError) -> Self {
        // Fallback for call sites that haven't been given a specific
        // stage; every site in this file is tagged explicitly below, so
        // in practice this only fires if a future call site forgets to.
        WorkerError::Connection { stage: "unspecified", error: e }
    }
}

/// A read timeout on a blocking socket surfaces as `WouldBlock` on Unix
/// (`SO_RCVTIMEO` semantics) and `TimedOut` on Windows. Either way it
/// means "no data yet", **not** "connection dead" -- a distinction this
/// client originally got wrong, dropping the only peer in a swarm that
/// had completed the handshake because it took >10s to unchoke.
fn is_read_timeout(e: &ConnectionError) -> bool {
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
fn absorb(msg: &Message, state: &mut PeerState, queue: &WorkQueue, pex_tx: Option<&PexSender>) -> bool {
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

/// Runs against a single peer until the work queue is drained or the
/// connection fails. On failure, any piece this worker had partially
/// claimed is pushed back to `queue` for another worker to retry -- the
/// queue only ever hands out whole pieces, so a crash mid-piece just
/// costs the work already done on it.
pub fn run_worker(
    peer_addr: SocketAddr,
    config: &WorkerConfig,
    queue: &Arc<WorkQueue>,
    spans: &Arc<Vec<FileSpan>>,
    piece_length: u64,
    results_tx: &Sender<PieceResult>,
    pex_tx: Option<&PexSender>,
) -> Result<(), WorkerError> {
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
    const MAX_UNCHOKE_WAIT_TIMEOUTS: u32 = 6;
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

    /// After this many consecutive "peer doesn't have anything we still
    /// need" cycles with no new relevant Have/Bitfield arriving, give up
    /// on this connection rather than holding the slot indefinitely. A
    /// peer that's alive but useless (or has gone silent without
    /// formally disconnecting) would otherwise never free its slot for
    /// the coordinator to try someone else.
    const MAX_IRRELEVANT_CYCLES: u32 = 50;
    let mut irrelevant_cycles = 0u32;

    while let Some(work) = queue.pop() {
        let piece_index = work.index;
        if !state.peer_has_pieces.get(piece_index as usize).copied().unwrap_or(false) {
            queue.push_back(work);

            // Rather than busy-looping on push_back/pop, actually read
            // whatever the peer sends next -- a Have/Bitfield here might
            // be exactly the piece we're waiting on, updating `state`
            // as a side effect. A read timeout just means the peer's
            // quiet right now, not that it's gone.
            match crate::peer::connection::read_message(&mut stream) {
                Ok(msg) => {
                    // `absorb` returns true for any state-affecting
                    // message (Choke/Unchoke/Have/Bitfield/...), which is
                    // an approximation of "this peer is still doing
                    // something" -- good enough for a stuck-connection
                    // safety net without needing to prove the exact piece
                    // we're blocked on became available this cycle.
                    let peer_is_active = absorb(&msg, &mut state, queue, pex_tx);
                    irrelevant_cycles = if peer_is_active { 0 } else { irrelevant_cycles + 1 };
                }
                Err(ref e) if is_read_timeout(e) => {
                    irrelevant_cycles += 1;
                }
                Err(e) => return Err(WorkerError::Connection { stage: "wait_for_relevant_have", error: e }),
            }

            if irrelevant_cycles >= MAX_IRRELEVANT_CYCLES {
                return Err(WorkerError::Connection {
                    stage: "peer_has_no_needed_pieces",
                    error: ConnectionError::Wire(WireError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "peer never offered a piece we still need"))),
                });
            }
            continue;
        }
        irrelevant_cycles = 0;

        match download_one_piece(&mut stream, &mut state, queue, work.clone(), config.pipeline_depth, pex_tx) {
            Ok(Some(data)) => {
                if let Err(e) = write_piece(spans, piece_index, piece_length, &data) {
                    // Disk failure isn't the peer's fault; requeue and bail
                    // out of this worker entirely rather than risk more
                    // writes to a broken filesystem.
                    queue.push_back(work);
                    return Err(WorkerError::Connection { stage: "write_piece_to_disk", error: ConnectionError::Io(e) });
                }
                // First completion wins (endgame duplicates lose the race
                // here and stay silent -- the coordinator only ever hears
                // about a piece once).
                if queue.mark_done(piece_index) {
                    let _ = results_tx.send(PieceResult { index: piece_index, data });
                }
            }
            Ok(None) => {
                // Endgame: another worker finished this piece while we
                // were mid-download; nothing to write, nothing to report.
            }
            Err(e) => {
                // Hash mismatch or wire error on this piece: give another
                // peer a chance rather than trusting this connection
                // further.
                queue.push_back(work);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Downloads one piece. Returns `Ok(None)` if the piece was abandoned
/// because another worker completed it first (endgame duplicate).
fn download_one_piece(
    stream: &mut std::net::TcpStream,
    state: &mut PeerState,
    queue: &WorkQueue,
    work: crate::downloader::piece_assembler::PieceWork,
    pipeline_depth: usize,
    pex_tx: Option<&PexSender>,
) -> Result<Option<Vec<u8>>, WorkerError> {
    let piece_index = work.index;
    let mut assembler = PieceAssembler::new(work);
    let mut blocks_received = 0u32;
    // Outstanding (begin, length) requests -- what we'd need to Cancel
    // (BEP 3) if this piece completes elsewhere mid-flight.
    let mut in_flight: Vec<(u32, u32)> = Vec::new();

    loop {
        // Endgame check: if a duplicate of this piece verified elsewhere,
        // stop asking for more of it and cancel what's still in flight so
        // the peer's upload slots go to blocks somebody actually needs.
        if queue.is_done(piece_index) {
            for &(begin, length) in &in_flight {
                let _ = crate::peer::connection::send_message(stream, &Message::Cancel { index: piece_index, begin, length });
            }
            return Ok(None);
        }

        while in_flight.len() < pipeline_depth {
            let reqs = assembler.next_requests(pipeline_depth - in_flight.len());
            if reqs.is_empty() {
                break;
            }
            for (index, begin, length) in reqs {
                crate::peer::connection::send_message(stream, &Message::Request { index, begin, length })
                    .map_err(|e| WorkerError::Connection { stage: stage_label("send_request", blocks_received), error: e })?;
                in_flight.push((begin, length));
            }
        }

        if assembler.is_complete() {
            break;
        }

        let msg = crate::peer::connection::read_message(stream).map_err(|e| WorkerError::Connection { stage: stage_label("read_message_during_piece_download", blocks_received), error: e })?;
        match &msg {
            Message::Piece { index, begin, block } if *index == piece_index => {
                let _ = assembler.record_block(*begin, block);
                in_flight.retain(|&(b, _)| b != *begin);
                blocks_received += 1;
            }
            Message::Piece { .. } => {
                // A block for some *other* piece -- typically a straggler
                // from an endgame-abandoned piece. Feeding it into this
                // piece's assembler would corrupt the buffer and waste
                // the whole piece on a hash mismatch; drop it instead.
            }
            other => {
                absorb(other, state, queue, pex_tx);
            }
        }
    }

    assembler.finish().map(Some).map_err(|_| WorkerError::PieceHashMismatch)
}

/// Bakes "how many blocks of this piece we'd already received before this
/// failure" into the stage label, since `&'static str` can't hold a
/// runtime number directly. `0` means the connection died before this
/// worker got a single byte of piece data from it -- a materially
/// different failure than dying after 40 successful blocks.
fn stage_label(base: &'static str, blocks_received: u32) -> &'static str {
    if blocks_received == 0 {
        base
    } else {
        // Can't format a runtime count into a &'static str without
        // allocating (which the WorkerError::Connection field type
        // doesn't support); the two fixed variants below at least
        // distinguish "died immediately" from "died after some progress",
        // which is the distinction that actually mattered in practice.
        match base {
            "send_request" => "send_request_after_prior_progress",
            "read_message_during_piece_download" => "read_message_after_prior_progress",
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    //! A mock peer on loopback (127.0.0.1) is just a `TcpListener`, no
    //! outbound network access needed, so these end-to-end-exercise
    //! `run_worker` against fake-but-protocol-correct peers.
    use super::*;
    use crate::downloader::file_writer::build_file_spans;
    use crate::downloader::piece_assembler::PieceWork;
    use crate::peer::handshake::Handshake;
    use crate::peer::message::Message as WireMessage;
    use sha1::{Digest, Sha1};
    use std::fs;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-worker-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sha1_of(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize().into()
    }

    /// A protocol-correct-enough fake peer: performs the handshake,
    /// announces it has every piece via `Bitfield`, unchokes after
    /// `unchoke_delay`, then serves `Request`s with matching `Piece`
    /// responses until the worker disconnects.
    fn spawn_mock_peer(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>, unchoke_delay: Duration) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            let mut hs_buf = [0u8; 68];
            std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
            let their_hs = Handshake::from_bytes(&hs_buf).unwrap();
            assert_eq!(their_hs.info_hash, info_hash);

            let our_hs = Handshake::new(info_hash, [0x99; 20], false);
            std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();

            // Bitfield: one bit per piece, MSB-first, all set.
            let num_pieces = pieces.len();
            let mut bits = vec![0u8; num_pieces.div_ceil(8)];
            for i in 0..num_pieces {
                bits[i / 8] |= 1 << (7 - (i % 8));
            }
            WireMessage::Bitfield(bits).write_to(&mut stream).unwrap();
            if !unchoke_delay.is_zero() {
                thread::sleep(unchoke_delay);
            }
            WireMessage::Unchoke.write_to(&mut stream).unwrap();

            loop {
                let msg = match WireMessage::read_from(&mut stream) {
                    Ok(m) => m,
                    Err(_) => return, // worker closed the connection; done
                };
                if let WireMessage::Request { index, begin, length } = msg {
                    let piece = &pieces[index as usize];
                    let block = piece[begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(&mut stream).unwrap();
                }
            }
        })
    }

    #[test]
    fn run_worker_downloads_all_pieces_from_mock_peer_and_writes_to_disk() {
        let piece0 = vec![0xAAu8; 16384];
        let piece1 = vec![0xBBu8; 16384];
        let info_hash = [0x42; 20];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone(), piece1.clone()], Duration::ZERO);

        let work = vec![
            PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 },
            PieceWork { index: 1, hash: sha1_of(&piece1), length: 16384 },
        ];
        let queue = Arc::new(WorkQueue::new(work, 2));

        let dir = tmp_dir("e2e");
        let files = vec![(vec!["out.bin".to_string()], 32768i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));

        let (tx, rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

        run_worker(addr, &config, &queue, &spans, 16384, &tx, None).unwrap();
        mock.join().unwrap();

        let mut results: Vec<_> = rx.try_iter().collect();
        results.sort_by_key(|r| r.index);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].data, piece0);
        assert_eq!(results[1].data, piece1);
        assert!(queue.is_empty());

        let mut on_disk = Vec::new();
        fs::File::open(dir.join("out.bin")).unwrap().read_to_end(&mut on_disk).unwrap();
        assert_eq!(&on_disk[..16384], &piece0[..]);
        assert_eq!(&on_disk[16384..], &piece1[..]);
    }

    #[test]
    fn run_worker_survives_a_peer_that_unchokes_slower_than_the_read_timeout() {
        // Regression test for the field failure that dropped the only
        // handshake-complete peer in a swarm: read timeout was 10s, the
        // peer's unchoke came later than that, and the resulting
        // WouldBlock was treated as fatal at stage "wait_for_unchoke".
        // Here: read timeout 100ms, unchoke after 350ms -- several
        // timeouts *must* be tolerated for this download to succeed.
        let piece0 = vec![0xCDu8; 16384];
        let info_hash = [0x43; 20];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone()], Duration::from_millis(350));

        let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 }];
        let queue = Arc::new(WorkQueue::new(work, 1));
        let dir = tmp_dir("slow-unchoke");
        let files = vec![(vec!["out.bin".to_string()], 16384i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));
        let (tx, rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100) };

        run_worker(addr, &config, &queue, &spans, 16384, &tx, None).unwrap();
        mock.join().unwrap();

        let results: Vec<_> = rx.try_iter().collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, piece0);
    }

    #[test]
    fn run_worker_gives_up_on_a_peer_that_never_unchokes() {
        // The other side of the coin: tolerance must stay bounded, or a
        // permanently-choking peer holds its slot forever.
        let info_hash = [0x44; 20];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hs_buf = [0u8; 68];
            std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
            let our_hs = Handshake::new(info_hash, [0x99; 20], false);
            std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();
            // Never unchoke; just linger longer than the worker's budget.
            thread::sleep(Duration::from_secs(3));
        });

        let work = vec![PieceWork { index: 0, hash: [0; 20], length: 100 }];
        let queue = Arc::new(WorkQueue::new(work, 1));
        let dir = tmp_dir("never-unchokes");
        let files = vec![(vec!["out.bin".to_string()], 100i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));
        let (tx, _rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100) };

        let result = run_worker(addr, &config, &queue, &spans, 100, &tx, None);
        assert!(matches!(result, Err(WorkerError::Connection { stage: "peer_never_unchoked", .. })), "expected bounded give-up, got: {:?}", result);
        assert_eq!(queue.len(), 1, "piece must remain available for another peer");
        let _ = mock.join();
    }

    #[test]
    fn run_worker_gives_up_on_peer_with_no_needed_pieces_instead_of_hanging() {
        let info_hash = [0x88; 20];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Mock peer: real handshake, but its bitfield claims it has ZERO
        // pieces -- there is nothing this worker can ever get from it.
        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hs_buf = [0u8; 68];
            std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
            let our_hs = Handshake::new(info_hash, [0x99; 20], false);
            std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();
            WireMessage::Bitfield(vec![0x00]).write_to(&mut stream).unwrap(); // claims: has piece 0..7, all false
            WireMessage::Unchoke.write_to(&mut stream).unwrap();
            // Then just... never send anything else relevant. Read
            // whatever the worker sends (Interested) and go quiet.
            let _ = WireMessage::read_from(&mut stream);
            thread::sleep(Duration::from_secs(8));
        });

        let work = vec![PieceWork { index: 0, hash: [0; 20], length: 100 }];
        let queue = Arc::new(WorkQueue::new(work, 1));
        let dir = tmp_dir("no-needed-pieces");
        let files = vec![(vec!["out.bin".to_string()], 100i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));
        let (tx, _rx) = mpsc::channel();
        // Short connect_timeout also governs the per-read timeout on the
        // stream, so this test doesn't take anywhere near 8 real seconds
        // despite the mock peer sleeping that long.
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_millis(100) };

        let result = run_worker(addr, &config, &queue, &spans, 100, &tx, None);
        assert!(matches!(result, Err(WorkerError::Connection { stage: "peer_has_no_needed_pieces", .. })), "expected bounded give-up, got: {:?}", result);
        assert_eq!(queue.len(), 1); // piece went back for another peer

        let _ = mock.join();
    }

    #[test]
    fn run_worker_requeues_piece_on_hash_mismatch_and_stops() {
        let piece0 = vec![0xCCu8; 16384];
        let info_hash = [0x77; 20];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone()], Duration::ZERO);

        // Deliberately wrong hash -- the mock peer serves real data, but
        // the assembler should refuse to hand it back as verified.
        let work = vec![PieceWork { index: 0, hash: [0u8; 20], length: 16384 }];
        let queue = Arc::new(WorkQueue::new(work, 1));

        let dir = tmp_dir("hash-mismatch");
        let files = vec![(vec!["out.bin".to_string()], 16384i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));

        let (tx, _rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x22; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

        let result = run_worker(addr, &config, &queue, &spans, 16384, &tx, None);
        assert!(matches!(result, Err(WorkerError::PieceHashMismatch)));
        let _ = mock.join();

        // The piece went back on the queue for another peer to try.
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn worker_reports_pex_peers_from_a_pex_sending_peer() {
        // Mock peer with the extension bit set: exchanges extended
        // handshakes, pushes a ut_pex message with one added peer, then
        // unchokes and serves the piece normally.
        let piece0 = vec![0xEEu8; 16384];
        let info_hash = [0x55; 20];
        let piece0_for_mock = piece0.clone();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mock = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hs_buf = [0u8; 68];
            std::io::Read::read_exact(&mut stream, &mut hs_buf).unwrap();
            let their_hs = Handshake::from_bytes(&hs_buf).unwrap();
            assert!(their_hs.supports_extensions());
            let our_hs = Handshake::new(info_hash, [0x99; 20], true);
            std::io::Write::write_all(&mut stream, &our_hs.to_bytes()).unwrap();

            // Their extended handshake arrives first; read until we see it
            // and learn the ut_pex id they chose for inbound PEX.
            let their_ut_pex = loop {
                match WireMessage::read_from(&mut stream).unwrap() {
                    WireMessage::Extended { id: 0, payload } => {
                        break crate::peer::ExtendedHandshake::parse(&payload).unwrap().peer_ut_pex_id().unwrap();
                    }
                    _ => continue,
                }
            };

            // Our own extended handshake back, then a PEX push:
            // added = 10.1.2.3:6881 (compact v4).
            WireMessage::Extended { id: 0, payload: crate::peer::ExtendedHandshake::build(7, None) }.write_to(&mut stream).unwrap();
            let mut pex = Vec::new();
            pex.extend_from_slice(b"d5:added6:");
            pex.extend_from_slice(&[10, 1, 2, 3]);
            pex.extend_from_slice(&6881u16.to_be_bytes());
            pex.push(b'e');
            WireMessage::Extended { id: their_ut_pex, payload: pex }.write_to(&mut stream).unwrap();

            WireMessage::Bitfield(vec![0b1000_0000]).write_to(&mut stream).unwrap();
            WireMessage::Unchoke.write_to(&mut stream).unwrap();
            loop {
                let msg = match WireMessage::read_from(&mut stream) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                if let WireMessage::Request { index, begin, length } = msg {
                    let block = piece0_for_mock[begin as usize..(begin + length) as usize].to_vec();
                    WireMessage::Piece { index, begin, block }.write_to(&mut stream).unwrap();
                }
            }
        });

        let work = vec![PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 }];
        let queue = Arc::new(WorkQueue::new(work, 1));
        let dir = tmp_dir("pex");
        let files = vec![(vec!["out.bin".to_string()], 16384i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));
        let (tx, _rx) = mpsc::channel();
        let (pex_tx, pex_rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

        run_worker(addr, &config, &queue, &spans, 16384, &tx, Some(&pex_tx)).unwrap();
        let _ = mock.join();

        let pex_peers: Vec<SocketAddr> = pex_rx.try_iter().flatten().collect();
        assert_eq!(pex_peers, vec!["10.1.2.3:6881".parse().unwrap()]);
    }
}
