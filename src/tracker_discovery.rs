//! Given a torrent's list of tracker URLs (mixed http:// and udp://),
//! announces to each *concurrently* and merges the peer lists. A single
//! bad or unreachable tracker doesn't abort the whole discovery -- we
//! only fail if *every* tracker fails, which is the actual "no peers
//! findable" case.
//!
//! Trackers are queried in parallel (one thread each) with an overall
//! deadline, rather than waiting for every tracker to individually finish
//! or time out. Two reasons this matters:
//!
//!  - A magnet link routinely lists several `udp://` trackers; querying
//!    them one after another (not just launching them one after another,
//!    but *waiting* for each before starting the next) means the total
//!    wait is the *sum* of every tracker's timeout.
//!  - Even with all trackers launched concurrently, a single `udp://`
//!    tracker that silently drops packets (rather than actively
//!    rejecting) can retry with BEP 15's exponential backoff for several
//!    minutes on its own before giving up -- waiting for *that one
//!    straggler* before returning any result at all would still make an
//!    otherwise-healthy announce feel hung.
//!
//! The fix for both: launch every tracker query on its own thread
//! immediately, then collect whatever responses arrive within
//! `OVERALL_ANNOUNCE_DEADLINE`, using an mpsc channel with
//! `recv_timeout` rather than joining threads one at a time. Slow
//! stragglers keep running in the background and are simply not waited
//! on; their result (if any) is just never used for this particular call.

use crate::tracker::{http, https, udp, AnnounceRequest, Event};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Generous enough for every real-world tracker this client has been
/// tested against to respond well within it (typically well under 2s),
/// but bounded enough that "a tracker is silently dropping packets"
/// doesn't turn into "this program looks hung for a quarter of an hour."
const OVERALL_ANNOUNCE_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub struct TrackerAttempt {
    pub url: String,
    pub error: String,
}

/// Announces to every URL in `tracker_urls` concurrently, returning the
/// deduplicated union of all peers any tracker returned, the list of
/// trackers that failed *or didn't answer within the deadline* (for
/// diagnostics -- not fatal unless *all* of them are in this list), and
/// the re-announce interval to wait before trying again.
///
/// The interval is the *maximum* `interval` (or `min_interval` if a
/// tracker sent one) across every tracker that responded -- i.e. the most
/// conservative choice. Re-announcing faster than any tracker's requested
/// interval is how clients get themselves rate-limited or banned; using
/// the max rather than the min means we never violate the slowest
/// tracker's request just because a faster one also happened to answer.
pub fn announce_to_all(tracker_urls: &[String], req: &AnnounceRequest) -> (Vec<SocketAddr>, Vec<TrackerAttempt>, Option<u32>) {
    let (tx, rx) = mpsc::channel();

    for url in tracker_urls {
        let url = url.clone();
        let req = req.clone();
        let tx = tx.clone();
        thread::spawn(move || {
            let result = if let Some(host_port) = url.strip_prefix("udp://") {
                // udp:// tracker URLs sometimes have a trailing
                // "/announce" path segment (no meaning for UDP
                // trackers) -- strip it.
                let host_port = host_port.split('/').next().unwrap_or(host_port).to_string();
                udp::announce(&host_port, &req).map_err(|e| e.to_string())
            } else if url.starts_with("https://") {
                https::announce(&url, &req).map_err(|e| e.to_string())
            } else if url.starts_with("http://") {
                http::announce(&url, &req).map_err(|e| e.to_string())
            } else {
                Err(format!("unsupported tracker scheme: {}", url))
            };
            // Ignore send errors: they only happen if the receiver
            // (below) already gave up waiting and dropped `rx`, which is
            // exactly the "this thread became a straggler" case this
            // whole function exists to not block on.
            let _ = tx.send((url, result));
        });
    }
    drop(tx); // our own copy; the loop above holds the rest via clones

    let mut peers = HashSet::new();
    let mut failures = Vec::new();
    let mut max_interval: Option<u32> = None;
    let mut answered: HashSet<String> = HashSet::new();

    let deadline = Instant::now() + OVERALL_ANNOUNCE_DEADLINE;
    while answered.len() < tracker_urls.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok((url, result)) => {
                answered.insert(url.clone());
                match result {
                    Ok(resp) => {
                        peers.extend(resp.peers);
                        let wait = resp.min_interval.unwrap_or(resp.interval);
                        max_interval = Some(max_interval.map_or(wait, |cur| cur.max(wait)));
                    }
                    Err(e) => failures.push(TrackerAttempt { url, error: e }),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // shouldn't happen while any sender clone is alive, but don't hang if it does
        }
    }

    // Anything that never answered within the deadline is reported as a
    // failure too, distinctly from an active rejection, so `download.rs`'s
    // "warning: tracker X failed: ..." output tells the truth about what
    // happened instead of silently omitting slow trackers.
    for url in tracker_urls {
        if !answered.contains(url) {
            failures.push(TrackerAttempt { url: url.clone(), error: format!("no response within {}s", OVERALL_ANNOUNCE_DEADLINE.as_secs()) });
        }
    }

    (peers.into_iter().collect(), failures, max_interval)
}

/// Session transfer totals reported to trackers (BEP 3): `uploaded`/
/// `downloaded` are bytes moved *this session*; `left` is bytes still
/// needed to complete the torrent (0 once seeding).
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferTotals {
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
}

/// The one true announce-request builder; the convenience wrappers below
/// cover the two fixed shapes older call sites used.
pub fn build_request(info_hash: [u8; 20], peer_id: [u8; 20], port: u16, totals: TransferTotals, event: Option<Event>) -> AnnounceRequest {
    AnnounceRequest {
        info_hash,
        peer_id,
        port,
        uploaded: totals.uploaded,
        downloaded: totals.downloaded,
        left: totals.left,
        compact: true,
        event,
        numwant: Some(50),
    }
}

/// Initial discovery (`Started`) with `left` set to the full torrent size.
pub fn build_started_request(info_hash: [u8; 20], peer_id: [u8; 20], port: u16, total_length: u64) -> AnnounceRequest {
    build_request(info_hash, peer_id, port, TransferTotals { uploaded: 0, downloaded: 0, left: total_length }, Some(Event::Started))
}

/// A periodic re-announce (BEP 3): `event` is omitted (not `Started`
/// again) since this is neither the first announce nor a stop/complete
/// notification -- just "still here, still want peers."
pub fn build_regular_request(info_hash: [u8; 20], peer_id: [u8; 20], port: u16, total_length: u64) -> AnnounceRequest {
    build_request(info_hash, peer_id, port, TransferTotals { uploaded: 0, downloaded: 0, left: total_length }, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_scheme_is_recorded_as_a_failure_not_a_panic() {
        let req = build_started_request([0; 20], [0; 20], 6881, 1000);
        let (peers, failures, interval) = announce_to_all(&["ftp://example.com".to_string()], &req);
        assert!(peers.is_empty());
        assert_eq!(failures.len(), 1);
        assert!(failures[0].error.contains("unsupported"));
        assert_eq!(interval, None);
    }

    #[test]
    fn empty_tracker_list_returns_no_peers_no_failures() {
        let req = build_started_request([0; 20], [0; 20], 6881, 1000);
        let (peers, failures, interval) = announce_to_all(&[], &req);
        assert!(peers.is_empty());
        assert!(failures.is_empty());
        assert_eq!(interval, None);
    }

    #[test]
    fn build_started_request_sets_event_and_left() {
        let req = build_started_request([1; 20], [2; 20], 6881, 12345);
        assert_eq!(req.left, 12345);
        assert_eq!(req.event, Some(Event::Started));
        assert!(req.compact);
    }
}
