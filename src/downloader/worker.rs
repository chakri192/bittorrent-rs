//! The actual per-peer event loop: connect, handshake, pipeline block
//! requests to keep the peer's pipe full, assemble+verify each piece, and
//! write it to disk. Like `peer::connection`, this is a thin orchestration
//! layer over primitives that are independently unit-tested
//! (`piece_assembler.rs`, `queue.rs`, `file_writer.rs`, `peer::*`) --
//! untestable here against a real peer since none are reachable from this
//! sandbox's network allowlist.

use crate::downloader::file_writer::{write_piece, FileSpan};
use crate::downloader::piece_assembler::PieceAssembler;
use crate::downloader::queue::{PieceResult, WorkQueue};
use crate::peer::{connect_and_handshake, ConnectionError, Message, PeerState};
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

#[derive(Debug)]
pub enum WorkerError {
    Connection(ConnectionError),
    PieceHashMismatch,
}

impl From<ConnectionError> for WorkerError {
    fn from(e: ConnectionError) -> Self {
        WorkerError::Connection(e)
    }
}

/// Runs against a single peer until the work queue is empty or the
/// connection fails. On failure, any piece this worker had partially
/// claimed is pushed back to `queue` for another worker to retry -- the
/// queue only ever hands out whole, not-yet-succeeded pieces, so a crash
/// mid-piece just costs the work already done on it.
pub fn run_worker(
    peer_addr: SocketAddr,
    config: &WorkerConfig,
    queue: &Arc<WorkQueue>,
    spans: &Arc<Vec<FileSpan>>,
    piece_length: u64,
    results_tx: &Sender<PieceResult>,
) -> Result<(), WorkerError> {
    let (mut stream, peer_handshake) = connect_and_handshake(peer_addr, config.info_hash, config.our_peer_id, true, config.connect_timeout)?;
    let _ = peer_handshake; // available for BEP10 negotiation in a fuller integration; unused at the wire-protocol level itself

    let mut state = PeerState::new();
    crate::peer::connection::send_message(&mut stream, &Message::Interested)?;
    state.am_interested = true;

    // Drain messages until unchoked or the peer disconnects. Bitfield/Have
    // messages that arrive in the meantime update `state` as a side effect.
    while state.peer_choking {
        let msg = crate::peer::connection::read_message(&mut stream)?;
        state.apply_message(&msg);
    }

    while let Some(work) = queue.pop() {
        let piece_index = work.index;
        if !state.peer_has_pieces.is_empty() && !state.peer_has_pieces.get(piece_index as usize).copied().unwrap_or(false) {
            queue.push_back(work);
            continue;
        }

        match download_one_piece(&mut stream, &mut state, work.clone(), config.pipeline_depth) {
            Ok(data) => {
                if let Err(e) = write_piece(spans, piece_index, piece_length, &data) {
                    // Disk failure isn't the peer's fault; requeue and bail
                    // out of this worker entirely rather than risk more
                    // writes to a broken filesystem.
                    queue.push_back(work);
                    return Err(WorkerError::Connection(ConnectionError::Io(e)));
                }
                let _ = results_tx.send(PieceResult { index: piece_index, data });
            }
            Err(e) => {
                // Hash mismatch or wire error on this piece: give another
                // peer a chance rather than trusting this connection
                // further. Previously this returned Ok(()), which silently
                // discarded the reason and made a single-peer failure look
                // like a clean, silent no-op to the caller -- now the
                // caller (e.g. `download.rs`'s per-thread error print)
                // actually sees why this peer was dropped.
                queue.push_back(work);
                return Err(e);
            }
        }
    }
    Ok(())
}

fn download_one_piece(
    stream: &mut std::net::TcpStream,
    state: &mut PeerState,
    work: crate::downloader::piece_assembler::PieceWork,
    pipeline_depth: usize,
) -> Result<Vec<u8>, WorkerError> {
    let mut assembler = PieceAssembler::new(work);
    let mut in_flight = 0usize;

    loop {
        while in_flight < pipeline_depth {
            let reqs = assembler.next_requests(pipeline_depth - in_flight);
            if reqs.is_empty() {
                break;
            }
            for (index, begin, length) in reqs {
                crate::peer::connection::send_message(stream, &Message::Request { index, begin, length })?;
                in_flight += 1;
            }
        }

        if assembler.is_complete() {
            break;
        }

        let msg = crate::peer::connection::read_message(stream)?;
        match &msg {
            Message::Piece { index: _, begin, block } => {
                let _ = assembler.record_block(*begin, block);
                in_flight = in_flight.saturating_sub(1);
            }
            other => {
                state.apply_message(other);
            }
        }
    }

    assembler.finish().map_err(|_| WorkerError::PieceHashMismatch)
}

#[cfg(test)]
mod tests {
    //! Unlike the rest of this module's doc comment claims, this *is*
    //! testable: a mock peer on loopback (127.0.0.1) is still just a
    //! `TcpListener`, no outbound network access needed, so this
    //! end-to-end-exercises `run_worker` against a fake-but-protocol-correct
    //! peer instead of leaving the whole module untested.
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
    /// announces it has every piece via `Bitfield`, unchokes immediately,
    /// then serves `Request`s with matching `Piece` responses until the
    /// worker disconnects.
    fn spawn_mock_peer(listener: TcpListener, info_hash: [u8; 20], pieces: Vec<Vec<u8>>) -> thread::JoinHandle<()> {
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
        let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone(), piece1.clone()]);

        let work = vec![
            PieceWork { index: 0, hash: sha1_of(&piece0), length: 16384 },
            PieceWork { index: 1, hash: sha1_of(&piece1), length: 16384 },
        ];
        let queue = Arc::new(WorkQueue::new(work));

        let dir = tmp_dir("e2e");
        let files = vec![(vec!["out.bin".to_string()], 32768i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));

        let (tx, rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x11; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

        run_worker(addr, &config, &queue, &spans, 16384, &tx).unwrap();
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
    fn run_worker_requeues_piece_on_hash_mismatch_and_stops() {
        let piece0 = vec![0xCCu8; 16384];
        let info_hash = [0x77; 20];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mock = spawn_mock_peer(listener, info_hash, vec![piece0.clone()]);

        // Deliberately wrong hash -- the mock peer serves real data, but
        // the assembler should refuse to hand it back as verified.
        let work = vec![PieceWork { index: 0, hash: [0u8; 20], length: 16384 }];
        let queue = Arc::new(WorkQueue::new(work));

        let dir = tmp_dir("hash-mismatch");
        let files = vec![(vec!["out.bin".to_string()], 16384i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));

        let (tx, _rx) = mpsc::channel();
        let config = WorkerConfig { info_hash, our_peer_id: [0x22; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(5) };

        let result = run_worker(addr, &config, &queue, &spans, 16384, &tx);
        assert!(matches!(result, Err(WorkerError::PieceHashMismatch)));
        let _ = mock.join();

        // The piece went back on the queue for another peer to try.
        assert_eq!(queue.len(), 1);
    }
}
