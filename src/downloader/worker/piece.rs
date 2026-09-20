//! Downloading one piece from a peer: pipelining its block requests,
//! assembling the blocks, and verifying the result.

use super::connect::MAX_UNCHOKE_WAIT_TIMEOUTS;
use super::peer_stats::{Activity, PeerStat};
use super::pipeline::{depth_for, Throughput};
use super::messages::{keep_serving, take};
use super::{is_read_timeout, PexSender, WorkerConfig, WorkerError};
use crate::serving::Serving;
use crate::downloader::piece_assembler::{PieceAssembler, PieceWork};
use crate::downloader::queue::WorkQueue;
use crate::peer::{Message, PeerState, PeerStream};
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

/// How a piece download ended, short of the connection failing.
pub(super) enum Downloaded {
    /// The piece is whole and matches its hash.
    Verified(Vec<u8>),
    /// Another worker completed it first (endgame duplicate).
    Abandoned,
    /// The peer keeps refusing to send it (BEP 6 `reject request`); worth
    /// trying elsewhere, not worth dropping the connection over.
    Refused,
}

/// A piece taken from the queue while the one before it was still being fetched, with what has been asked of the peer for it
/// so far. A request pipeline that ended with each piece would stall a round trip at every boundary -- which, for a peer with a
/// long round trip and small pieces, is most of the time -- so once the piece being fetched has all its blocks asked for, the
/// spare depth goes on the next one, and the one after that as far as it reaches.
pub(super) struct Lookahead {
    pub(super) work: PieceWork,
    assembler: PieceAssembler,
    /// Whether the assembler began from blocks another connection had received.
    resumed: bool,
    in_flight: Vec<(u32, u32)>,
    refusals: u32,
}

impl Lookahead {
    /// Gives the piece back, with the blocks that arrived, for another connection (or this one, later): its requests
    /// stay with the peer, and what comes of them is dropped as a stray block.
    pub(super) fn release(self, queue: &WorkQueue) {
        if let Some(partial) = self.assembler.into_partial() {
            queue.stash_partial(self.work.index, partial);
        }
        queue.push_back(self.work);
    }
}

/// The most pieces looked ahead to at once: enough to fill any request queue (at most 128 blocks) with 16 KiB pieces, and no
/// more of the queue held by one connection than that.
pub(super) const MAX_LOOKAHEAD: usize = 8;

/// The assembler for a piece: from the blocks another connection left in the queue if there are any.
fn open(queue: &WorkQueue, work: &PieceWork) -> (PieceAssembler, bool) {
    match queue.take_partial(work.index) {
        Some(partial) => (PieceAssembler::resume(work.clone(), partial), true),
        None => (PieceAssembler::new(work.clone()), false),
    }
}

/// Downloads one piece.
///
/// `config.pipeline_depth` requests are kept in flight at least; how many more depends
/// on how fast this peer has been delivering (`throughput`, which carries
/// over from piece to piece) and on what it says it will queue. When the piece has
/// all its blocks asked for and there is still room, the next piece is taken and its blocks asked for
/// too (`ahead`, in the order they will be fetched): `started` is such a piece, taken on the last call, and `ahead` is where the
/// ones taken on this call are left.
///
/// If an earlier connection failed part-way through this piece, its blocks
/// are picked up from the queue and only the missing ones are requested;
/// and if this connection fails part-way, what it received is left there
/// for the next. Blocks from another connection cannot be blamed on this
/// peer, so if a piece assembled from them fails its hash it is fetched
/// again from this peer alone, and only a failure of *that* is the peer's.
#[allow(clippy::too_many_arguments)]
pub(super) fn download_one_piece(
    stream: &mut dyn PeerStream,
    state: &mut PeerState,
    queue: &WorkQueue,
    work: PieceWork,
    started: Option<Lookahead>,
    refused: &HashSet<u32>,
    ahead: &mut VecDeque<Lookahead>,
    config: &WorkerConfig,
    meter: Meter,
    pex_tx: Option<&PexSender>,
    serving: &mut Option<Serving>,
) -> Result<Downloaded, WorkerError> {
    let (assembler, resumed, in_flight) = match started {
        Some(la) => (la.assembler, la.resumed, la.in_flight),
        None => {
            let (assembler, resumed) = open(queue, &work);
            (assembler, resumed, Vec::new())
        }
    };
    let mut link = Link { stream, state, queue, config, meter, pex_tx, refused, ahead, serving };
    match attempt(&mut link, assembler, in_flight)? {
        Attempt::Verified(data) => Ok(Downloaded::Verified(data)),
        Attempt::Abandoned => Ok(Downloaded::Abandoned),
        Attempt::Refused => Ok(Downloaded::Refused),
        Attempt::Mismatch if resumed => match attempt(&mut link, PieceAssembler::new(work), Vec::new())? {
            Attempt::Verified(data) => Ok(Downloaded::Verified(data)),
            Attempt::Abandoned => Ok(Downloaded::Abandoned),
            Attempt::Refused => Ok(Downloaded::Refused),
            Attempt::Mismatch => Err(WorkerError::PieceHashMismatch),
        },
        Attempt::Mismatch => Err(WorkerError::PieceHashMismatch),
    }
}

/// What is measured about a peer as its pieces arrive: how fast, which
/// sizes its request queue, and what the dashboard shows.
pub(super) struct Meter<'a> {
    pub throughput: &'a mut Throughput,
    pub stat: &'a PeerStat,
}

/// The connection and the shared things a piece download works with.
struct Link<'a> {
    stream: &'a mut dyn PeerStream,
    state: &'a mut PeerState,
    queue: &'a WorkQueue,
    config: &'a WorkerConfig,
    meter: Meter<'a>,
    pex_tx: Option<&'a PexSender>,
    /// Pieces this peer keeps refusing to send: not looked ahead to.
    refused: &'a HashSet<u32>,
    /// The pieces after this one that have been taken, in order.
    ahead: &'a mut VecDeque<Lookahead>,
    /// The upload side of the connection, if the peer may ask for pieces on it.
    serving: &'a mut Option<Serving>,
}

/// How a try at a piece ended.
enum Attempt {
    Verified(Vec<u8>),
    Mismatch,
    Abandoned,
    Refused,
}

/// Fetches what `assembler` lacks and checks the result. If the connection
/// fails first, the blocks that did arrive are left in the queue. `in_flight` is what has been asked for already.
fn attempt(link: &mut Link, mut assembler: PieceAssembler, in_flight: Vec<(u32, u32)>) -> Result<Attempt, WorkerError> {
    let piece_index = assembler.piece_index();
    match fetch_blocks(link, &mut assembler, in_flight) {
        Ok(Fetched::Complete) => Ok(match assembler.finish() {
            Ok(data) => Attempt::Verified(data),
            Err(_) => Attempt::Mismatch,
        }),
        Ok(Fetched::Abandoned) => Ok(Attempt::Abandoned),
        Ok(Fetched::Refused) => {
            // What did arrive is kept for the next peer, as when a connection fails.
            if let Some(partial) = assembler.into_partial() {
                link.queue.stash_partial(piece_index, partial);
            }
            Ok(Attempt::Refused)
        }
        Err(e) => {
            if let Some(partial) = assembler.into_partial() {
                link.queue.stash_partial(piece_index, partial);
            }
            Err(e)
        }
    }
}

enum Fetched {
    Complete,
    Abandoned,
    Refused,
}

/// The most messages read to salvage what a peer sent before a write to it failed.
const MAX_SALVAGE_MESSAGES: usize = 256;

/// A write to the peer has failed, most likely because it hung up. What it sent before hanging up may still be waiting to be
/// read -- including blocks of the piece in hand or of those looked ahead to -- and would be lost with the connection, so it
/// is read (until the connection says it has no more) and the blocks kept, for whoever fetches the pieces next.
fn salvage_after_failed_write(stream: &mut dyn PeerStream, piece_index: u32, assembler: &mut PieceAssembler, ahead: &mut VecDeque<Lookahead>) {
    for _ in 0..MAX_SALVAGE_MESSAGES {
        match crate::peer::connection::read_message(stream) {
            Ok(Message::Piece { index, begin, block }) if index == piece_index => {
                let _ = assembler.record_block(begin, &block);
            }
            Ok(Message::Piece { index, begin, block }) => {
                if let Some(next) = ahead.iter_mut().find(|next| next.work.index == index) {
                    let _ = next.assembler.record_block(begin, &block);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

/// How many times a peer may refuse requests for one piece before it is
/// given up on for that piece.
const MAX_REFUSALS_PER_PIECE: u32 = 8;

/// Requests and receives blocks until `assembler` has them all.
fn fetch_blocks(link: &mut Link, assembler: &mut PieceAssembler, mut in_flight: Vec<(u32, u32)>) -> Result<Fetched, WorkerError> {
    let Link { stream, state, queue, config, meter, pex_tx, refused, ahead, serving } = link;
    let piece_index = assembler.piece_index();
    let mut blocks_received = 0u32;
    // (`in_flight` -- the outstanding (begin, length) requests -- is what we'd need to Cancel (BEP 3) if this piece
    // completes elsewhere mid-flight.)
    // Read timeouts sat through in a row while the peer has us choked.
    let mut choked_timeouts = 0u32;
    let mut refusals = 0u32;
    // Pieces given back after their look-ahead was refused: not taken for it again.
    let mut declined: HashSet<u32> = HashSet::new();

    loop {
        keep_serving(serving, &mut **stream)?;
        // Endgame check: if a duplicate of this piece verified elsewhere,
        // stop asking for more of it and cancel what's still in flight so
        // the peer's upload slots go to blocks somebody actually needs.
        if queue.is_done(piece_index) {
            for &(begin, length) in &in_flight {
                let _ = crate::peer::connection::send_message(&mut **stream, &Message::Cancel { index: piece_index, begin, length });
            }
            return Ok(Fetched::Abandoned);
        }

        if !state.may_request(piece_index) {
            // A choke makes the peer discard every request it has not yet
            // answered, and it will not send them after an unchoke. Forget
            // them here too, so that once unchoked the blocks still missing
            // are asked for again; the ones that arrived are kept. Nothing
            // is requested while choked -- except, with the Fast Extension,
            // for the pieces the peer has said we may have regardless.
            in_flight.clear();
            assembler.forget_requests();
            for next in ahead.iter_mut() {
                next.in_flight.clear();
                next.assembler.forget_requests();
            }
            meter.stat.set(Activity::Choked);
        } else {
            if !state.peer_choking {
                choked_timeouts = 0;
            }
            meter.stat.set(Activity::Downloading);
            let depth = depth_for(meter.throughput.rate(Instant::now()), config.pipeline_depth, state.peer_request_limit);
            loop {
                let outstanding = in_flight.len() + ahead.iter().map(|next| next.in_flight.len()).sum::<usize>();
                if outstanding >= depth {
                    break;
                }
                let room = depth - outstanding;
                let reqs = assembler.next_requests(room);
                if !reqs.is_empty() {
                    for (index, begin, length) in reqs {
                        if let Err(e) = crate::peer::connection::send_message(&mut **stream, &Message::Request { index, begin, length }) {
                            salvage_after_failed_write(&mut **stream, piece_index, assembler, ahead);
                            return Err(WorkerError::Connection { stage: stage_label("send_request", blocks_received), error: e });
                        }
                        in_flight.push((begin, length));
                    }
                    continue;
                }
                // Every block of this piece is asked for and there is room to spare: the next piece's go now, and when all of
                // that one's are asked for, the next's.
                let mut sent = false;
                for next in ahead.iter_mut() {
                    let reqs = next.assembler.next_requests(room);
                    if reqs.is_empty() {
                        continue;
                    }
                    for (index, begin, length) in reqs {
                        if let Err(e) = crate::peer::connection::send_message(&mut **stream, &Message::Request { index, begin, length }) {
                            salvage_after_failed_write(&mut **stream, piece_index, assembler, ahead);
                            return Err(WorkerError::Connection { stage: stage_label("send_request", blocks_received), error: e });
                        }
                        next.in_flight.push((begin, length));
                    }
                    sent = true;
                    break;
                }
                if sent {
                    continue;
                }
                // Every piece taken is fully asked for: take another, if the room is there for it.
                if ahead.len() >= MAX_LOOKAHEAD {
                    break;
                }
                let taken: Vec<u32> = ahead.iter().map(|next| next.work.index).collect();
                let next = queue.take_pending_for(|piece| piece != piece_index && !taken.contains(&piece) && state.peer_has_pieces.get(piece as usize).copied().unwrap_or(false) && state.may_request(piece) && !refused.contains(&piece) && !declined.contains(&piece));
                let Some(work) = next else { break };
                let (next_assembler, resumed) = open(queue, &work);
                ahead.push_back(Lookahead { work, assembler: next_assembler, resumed, in_flight: Vec::new(), refusals: 0 });
            }
        }

        if assembler.is_complete() {
            break;
        }

        let msg = match crate::peer::connection::read_message(&mut **stream) {
            Ok(msg) => msg,
            // Waiting out a choke is not a failure -- peers unchoke in
            // rounds of 10-30 seconds -- so a quiet spell is put up with
            // (for as long as the wait for an unchoke at connect time is).
            Err(ref e) if state.peer_choking && is_read_timeout(e) => {
                choked_timeouts += 1;
                if choked_timeouts >= MAX_UNCHOKE_WAIT_TIMEOUTS {
                    return Err(WorkerError::Connection {
                        stage: "peer_choked_us_mid_piece",
                        error: crate::peer::ConnectionError::Wire(crate::peer::WireError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "peer stayed choked through the whole wait budget"))),
                    });
                }
                crate::peer::connection::send_message(&mut **stream, &Message::KeepAlive).map_err(|e| WorkerError::Connection { stage: "keepalive_while_choked", error: e })?;
                continue;
            }
            Err(e) => return Err(WorkerError::Connection { stage: stage_label("read_message_during_piece_download", blocks_received), error: e }),
        };
        match &msg {
            Message::Piece { index, begin, block } if *index == piece_index || ahead.iter().any(|next| next.work.index == *index) => {
                if *index == piece_index {
                    let _ = assembler.record_block(*begin, block);
                    in_flight.retain(|&(b, _)| b != *begin);
                } else if let Some(next) = ahead.iter_mut().find(|next| next.work.index == *index) {
                    let _ = next.assembler.record_block(*begin, block);
                    next.in_flight.retain(|&(b, _)| b != *begin);
                }
                blocks_received += 1;
                meter.throughput.record(Instant::now(), block.len());
                meter.stat.add_bytes(block.len());
                if let Some(serving) = serving.as_ref() {
                    serving.record_download(block.len() as u64);
                }
                // Reading slowly is backpressure: the peer's window fills.
                if let Some(limiter) = config.down_limit.as_deref() {
                    // Not past the point where the client is stopping.
                    limiter.acquire_while(block.len(), || !config.interrupt.is_triggered());
                }
            }
            // BEP 6: the peer will not send this block. Ask again, a few
            // times; a request we had already forgotten (the reply to a choke)
            // is nothing to act on.
            Message::RejectRequest { index, begin, length } if *index == piece_index && in_flight.contains(&(*begin, *length)) => {
                in_flight.retain(|&(b, _)| b != *begin);
                assembler.refuse_request(*begin);
                refusals += 1;
                if refusals >= MAX_REFUSALS_PER_PIECE {
                    return Ok(Fetched::Refused);
                }
            }
            // The same for the piece looked ahead to, which is given back if the peer will not send it.
            Message::RejectRequest { index, begin, length } if ahead.iter().any(|next| next.work.index == *index && next.in_flight.contains(&(*begin, *length))) => {
                if let Some(at) = ahead.iter().position(|next| next.work.index == *index) {
                    let next = &mut ahead[at];
                    next.in_flight.retain(|&(b, _)| b != *begin);
                    next.assembler.refuse_request(*begin);
                    next.refusals += 1;
                    if next.refusals >= MAX_REFUSALS_PER_PIECE {
                        if let Some(next) = ahead.remove(at) {
                            declined.insert(next.work.index);
                            next.release(queue);
                        }
                    }
                }
            }
            Message::Piece { .. } => {
                // A block for some *other* piece -- typically a straggler
                // from an endgame-abandoned piece. Feeding it into this
                // piece's assembler would corrupt the buffer and waste
                // the whole piece on a hash mismatch; drop it instead.
            }
            other => {
                take(other, state, queue, *pex_tx, serving, &mut **stream)?;
            }
        }
    }

    Ok(Fetched::Complete)
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
    use super::*;

    #[test]
    fn before_any_block_arrives_the_stage_keeps_its_plain_name() {
        assert_eq!(stage_label("send_request", 0), "send_request");
        assert_eq!(stage_label("read_message_during_piece_download", 0), "read_message_during_piece_download");
    }

    #[test]
    fn after_some_progress_the_stage_says_so() {
        // A peer dying after 500 blocks is not the same failure as one
        // dying before its first, and the label is how the log tells them apart.
        assert_eq!(stage_label("send_request", 1), "send_request_after_prior_progress");
        assert_eq!(stage_label("read_message_during_piece_download", 500), "read_message_after_prior_progress");
    }

    #[test]
    fn a_stage_with_no_progress_variant_is_left_alone() {
        assert_eq!(stage_label("connect_and_handshake", 7), "connect_and_handshake");
    }
}
