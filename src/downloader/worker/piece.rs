//! Downloading one piece from a peer: pipelining its block requests,
//! assembling the blocks, and verifying the result.

use super::{absorb, PexSender, WorkerError};
use crate::downloader::piece_assembler::PieceAssembler;
use crate::downloader::queue::WorkQueue;
use crate::peer::{Message, PeerState};

/// Downloads one piece. Returns `Ok(None)` if the piece was abandoned
/// because another worker completed it first (endgame duplicate).
pub(super) fn download_one_piece(
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
