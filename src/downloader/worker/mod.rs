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
mod pipeline;
#[cfg(test)]
mod tests;

use crate::downloader::file_writer::{write_piece, FileSpan};
use crate::downloader::queue::{PieceResult, Take, WorkQueue};
use crate::ratelimit::RateLimiter;
use crate::peer::{ConnectionError, WireError};
use connect::establish;
use messages::{absorb, is_read_timeout};
use piece::download_one_piece;
use pipeline::Throughput;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::mpsc::Sender;
use crate::sync::lock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct WorkerConfig {
    pub info_hash: [u8; 20],
    pub our_peer_id: [u8; 20],
    /// The fewest outstanding (requested, not-yet-received) blocks to keep
    /// with a peer. 5 is the long-standing convention (mainline and
    /// libtorrent use roughly 5-10): an 80 KiB window, enough to start
    /// without over-committing to a peer that turns out to be slow. A peer
    /// that proves fast is sent more, up to what it says it will queue:
    /// see [`pipeline`].
    pub pipeline_depth: usize,
    pub connect_timeout: Duration,
    /// Shared limit on the bytes downloaded across every connection
    /// (`--max-down`), if any.
    pub down_limit: Option<Arc<RateLimiter>>,
    /// Lets the coordinator cut short workers blocked on the network.
    pub interrupt: Interrupt,
}

/// A way to end workers that are blocked reading from a peer.
///
/// A blocked read cannot be interrupted from outside, but its socket can be
/// shut down, which makes the read return at once. Each worker registers
/// its connection here; [`trigger`](Self::trigger) shuts them all. Without
/// it, stopping the client waited out the read timeout of any peer that had
/// gone silent, up to ten seconds.
///
/// Registering keeps a second handle on the socket, and a connection only
/// closes when *every* handle is gone. So a registration lasts exactly as
/// long as its worker: dropping the [`Registration`] removes and closes the
/// handle, and the worker's own drop then really closes the connection.
#[derive(Debug, Default)]
pub struct Interrupt {
    triggered: AtomicBool,
    next_id: AtomicU64,
    streams: Mutex<Vec<(u64, TcpStream)>>,
}

/// A connection tracked by an [`Interrupt`], untracked when dropped.
#[derive(Debug)]
pub struct Registration<'a> {
    interrupt: &'a Interrupt,
    id: Option<u64>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            lock(&self.interrupt.streams).retain(|(other, _)| *other != id);
        }
    }
}

impl Interrupt {
    /// Tracks `stream` until the returned registration is dropped, so a
    /// trigger in the meantime can shut it down. If the interrupt has
    /// already been triggered, the stream is shut down now.
    pub fn register(&self, stream: &TcpStream) -> Registration<'_> {
        let Ok(clone) = stream.try_clone() else { return Registration { interrupt: self, id: None } };
        let mut streams = lock(&self.streams);
        if self.triggered.load(Ordering::SeqCst) {
            let _ = clone.shutdown(Shutdown::Both);
            return Registration { interrupt: self, id: None };
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        streams.push((id, clone));
        Registration { interrupt: self, id: Some(id) }
    }

    /// Shuts down every registered connection. Safe to call repeatedly.
    pub fn trigger(&self) {
        let mut streams = lock(&self.streams);
        self.triggered.store(true, Ordering::SeqCst);
        for (_, stream) in streams.drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    pub fn is_triggered(&self) -> bool {
        self.triggered.load(Ordering::SeqCst)
    }
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

/// After this many consecutive cycles with nothing new on offer from a
/// peer, its connection is given up.
const MAX_IRRELEVANT_CYCLES: u32 = 50;

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
    // The registration is held to the end of the run: dropping it is what lets the connection close.
    let (mut stream, mut state, _registration) = establish(peer_addr, config, queue, pex_tx)?;

    let mut irrelevant_cycles = 0u32;
    // How fast this peer delivers, which sets how many requests to queue.
    let mut throughput = Throughput::default();

    loop {
        // The rarest piece *this peer has*: one it lacks is no use to it.
        let work = match queue.take_for(|piece| state.peer_has_pieces.get(piece as usize).copied().unwrap_or(false)) {
            Take::Piece(work) => work,
            Take::Done => break,
            Take::NothingForThisPeer => {
                wait_for_a_piece_it_has(&mut stream, &mut state, queue, pex_tx, &mut irrelevant_cycles)?;
                continue;
            }
        };
        irrelevant_cycles = 0;
        let piece_index = work.index;

        match download_one_piece(&mut stream, &mut state, queue, work.clone(), config, &mut throughput, pex_tx) {
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

/// Pieces remain, but this peer has none of them. Rather than
/// busy-looping, reads whatever the peer sends next: a Have or Bitfield
/// might be exactly what is being waited for, and updates `state` as a side
/// effect. A read timeout just means the peer is quiet, not that it has
/// gone. After [`MAX_IRRELEVANT_CYCLES`] in a row with nothing new the
/// connection is given up rather than holding its slot for good: a peer
/// that is alive but useless (or silent without formally disconnecting)
/// would otherwise never free it for the coordinator to try someone else.
fn wait_for_a_piece_it_has(stream: &mut TcpStream, state: &mut crate::peer::PeerState, queue: &WorkQueue, pex_tx: Option<&PexSender>, irrelevant_cycles: &mut u32) -> Result<(), WorkerError> {
    match crate::peer::connection::read_message(stream) {
        Ok(msg) => {
            // `absorb` returns true for any state-affecting message
            // (Choke/Unchoke/Have/Bitfield/...), an approximation of
            // "this peer is still doing something" that is good enough for
            // a stuck-connection safety net.
            let peer_is_active = absorb(&msg, state, queue, pex_tx);
            *irrelevant_cycles = if peer_is_active { 0 } else { *irrelevant_cycles + 1 };
        }
        Err(ref e) if is_read_timeout(e) => {
            *irrelevant_cycles += 1;
        }
        Err(e) => return Err(WorkerError::Connection { stage: "wait_for_relevant_have", error: e }),
    }

    if *irrelevant_cycles >= MAX_IRRELEVANT_CYCLES {
        return Err(WorkerError::Connection {
            stage: "peer_has_no_needed_pieces",
            error: ConnectionError::Wire(WireError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "peer never offered a piece we still need"))),
        });
    }
    Ok(())
}
