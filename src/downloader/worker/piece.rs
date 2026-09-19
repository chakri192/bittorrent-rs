//! Downloading one piece from a peer: pipelining its block requests,
//! assembling the blocks, and verifying the result.

use super::connect::MAX_UNCHOKE_WAIT_TIMEOUTS;
use super::pipeline::{depth_for, Throughput};
use super::{absorb, is_read_timeout, PexSender, WorkerConfig, WorkerError};
use crate::downloader::piece_assembler::PieceAssembler;
use crate::downloader::queue::WorkQueue;
use crate::peer::{Message, PeerState};
use std::time::Instant;

/// Downloads one piece. Returns `Ok(None)` if the piece was abandoned
/// because another worker completed it first (endgame duplicate).
///
/// `config.pipeline_depth` requests are kept in flight at least; how many more depends
/// on how fast this peer has been delivering (`throughput`, which carries
/// over from piece to piece) and on what it says it will queue.
pub(super) fn download_one_piece(
    stream: &mut std::net::TcpStream,
    state: &mut PeerState,
    queue: &WorkQueue,
    work: crate::downloader::piece_assembler::PieceWork,
    config: &WorkerConfig,
    throughput: &mut Throughput,
    pex_tx: Option<&PexSender>,
) -> Result<Option<Vec<u8>>, WorkerError> {
    let piece_index = work.index;
    let mut assembler = PieceAssembler::new(work);
    let mut blocks_received = 0u32;
    // Outstanding (begin, length) requests -- what we'd need to Cancel
    // (BEP 3) if this piece completes elsewhere mid-flight.
    let mut in_flight: Vec<(u32, u32)> = Vec::new();
    // Read timeouts sat through in a row while the peer has us choked.
    let mut choked_timeouts = 0u32;

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

        if state.peer_choking {
            // A choke makes the peer discard every request it has not yet
            // answered, and it will not send them after an unchoke. Forget
            // them here too, so that once unchoked the blocks still missing
            // are asked for again; the ones that arrived are kept. Nothing
            // is requested while choked.
            in_flight.clear();
            assembler.forget_requests();
        } else {
            choked_timeouts = 0;
            let depth = depth_for(throughput.rate(Instant::now()), config.pipeline_depth, state.peer_request_limit);
            while in_flight.len() < depth {
                let reqs = assembler.next_requests(depth - in_flight.len());
                if reqs.is_empty() {
                    break;
                }
                for (index, begin, length) in reqs {
                    crate::peer::connection::send_message(stream, &Message::Request { index, begin, length })
                        .map_err(|e| WorkerError::Connection { stage: stage_label("send_request", blocks_received), error: e })?;
                    in_flight.push((begin, length));
                }
            }
        }

        if assembler.is_complete() {
            break;
        }

        let msg = match crate::peer::connection::read_message(stream) {
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
                crate::peer::connection::send_message(stream, &Message::KeepAlive).map_err(|e| WorkerError::Connection { stage: "keepalive_while_choked", error: e })?;
                continue;
            }
            Err(e) => return Err(WorkerError::Connection { stage: stage_label("read_message_during_piece_download", blocks_received), error: e }),
        };
        match &msg {
            Message::Piece { index, begin, block } if *index == piece_index => {
                let _ = assembler.record_block(*begin, block);
                in_flight.retain(|&(b, _)| b != *begin);
                blocks_received += 1;
                throughput.record(Instant::now(), block.len());
                // Reading slowly is backpressure: the peer's window fills.
                if let Some(limiter) = config.down_limit.as_deref() {
                    // Not past the point where the client is stopping.
                    limiter.acquire_while(block.len(), || !config.interrupt.is_triggered());
                }
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
