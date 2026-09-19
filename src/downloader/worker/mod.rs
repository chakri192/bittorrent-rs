//! The actual per-peer event loop: connect, handshake, pipeline block
//! requests to keep the peer's pipe full, assemble+verify each piece, and
//! write it to disk. Like `peer::connection`, this is a thin orchestration
//! layer over primitives that are independently unit-tested
//! (`piece_assembler.rs`, `queue.rs`, `file_writer.rs`, `peer::*`).
//!
//! `run_worker` is the connection's lifecycle and lives here: get a
//! connection ready (`connect`), then work through the queue. What it does
//! with each incoming message is in `messages`, and fetching one piece is
//! in `piece`; the tests, which drive it against a mock peer on loopback,
//! are in `tests`.

mod connect;
mod messages;
mod piece;
#[cfg(test)]
mod tests;

use crate::downloader::file_writer::{write_piece, FileSpan};
use crate::downloader::queue::{PieceResult, WorkQueue};
use crate::ratelimit::RateLimiter;
use crate::peer::{ConnectionError, WireError};
use connect::establish;
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
    /// Shared limit on the bytes downloaded across every connection
    /// (`--max-down`), if any.
    pub down_limit: Option<Arc<RateLimiter>>,
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
    let (mut stream, mut state) = establish(peer_addr, config, queue, pex_tx)?;

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

        match download_one_piece(&mut stream, &mut state, queue, work.clone(), config.pipeline_depth, pex_tx, config.down_limit.as_deref()) {
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
