//! The actual per-peer event loop: connect, handshake, pipeline block
//! requests to keep the peer's pipe full, assemble+verify each piece, and
//! write it to disk. Like `peer::connection`, this is a thin orchestration
//! layer over primitives that are independently unit-tested
//! (`piece_assembler.rs`, `queue.rs`, `file_writer.rs`, `peer::*`).
//!
//! `run_worker` is the connection's lifecycle and lives here. What it does
//! with each incoming message is in `messages`, and fetching one piece is
//! in `piece`; the tests, which drive it against a mock peer on loopback,
//! are in `tests`.

mod messages;
mod piece;
#[cfg(test)]
mod tests;

use crate::downloader::file_writer::{write_piece, FileSpan};
use crate::downloader::queue::{PieceResult, WorkQueue};
use crate::peer::{connect_and_handshake, ConnectionError, ExtendedHandshake, Message, PeerState, WireError};
use messages::{absorb, is_read_timeout};
use piece::download_one_piece;
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
