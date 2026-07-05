//! Given a torrent's list of tracker URLs (mixed http:// and udp://),
//! announces to each in turn and merges the peer lists. A single bad or
//! unreachable tracker doesn't abort the whole discovery -- we only fail
//! if *every* tracker fails, which is the actual "no peers findable" case.

use crate::tracker::{http, udp, AnnounceRequest, Event};
use std::collections::HashSet;
use std::net::SocketAddrV4;

#[derive(Debug)]
pub struct TrackerAttempt {
    pub url: String,
    pub error: String,
}

/// Announces to every URL in `tracker_urls`, returning the deduplicated
/// union of all peers any tracker returned, plus the list of trackers
/// that failed (for diagnostics -- not fatal unless *all* of them are in
/// this list). `udp://` URLs are stripped to `host:port` for
/// `tracker::udp::announce`; unrecognized schemes are recorded as failures.
pub fn announce_to_all(tracker_urls: &[String], req: &AnnounceRequest) -> (Vec<SocketAddrV4>, Vec<TrackerAttempt>) {
    let mut peers = HashSet::new();
    let mut failures = Vec::new();

    for url in tracker_urls {
        let result = if let Some(host_port) = url.strip_prefix("udp://") {
            // udp:// tracker URLs sometimes have a trailing "/announce"
            // path segment (no meaning for UDP trackers) -- strip it.
            let host_port = host_port.split('/').next().unwrap_or(host_port);
            udp::announce(host_port, req).map_err(|e| e.to_string())
        } else if url.starts_with("http://") {
            http::announce(url, req).map_err(|e| e.to_string())
        } else {
            Err(format!("unsupported tracker scheme: {}", url))
        };

        match result {
            Ok(resp) => peers.extend(resp.peers),
            Err(e) => failures.push(TrackerAttempt { url: url.clone(), error: e }),
        }
    }

    (peers.into_iter().collect(), failures)
}

/// Convenience for building the request each of the (at most two, per
/// torrent lifecycle) announces in `download.rs` needs: initial discovery
/// (`Started`) with `left` set to the full torrent size.
pub fn build_started_request(info_hash: [u8; 20], peer_id: [u8; 20], port: u16, total_length: u64) -> AnnounceRequest {
    AnnounceRequest {
        info_hash,
        peer_id,
        port,
        uploaded: 0,
        downloaded: 0,
        left: total_length,
        compact: true,
        event: Some(Event::Started),
        numwant: Some(50),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_scheme_is_recorded_as_a_failure_not_a_panic() {
        let req = build_started_request([0; 20], [0; 20], 6881, 1000);
        let (peers, failures) = announce_to_all(&["ftp://example.com".to_string()], &req);
        assert!(peers.is_empty());
        assert_eq!(failures.len(), 1);
        assert!(failures[0].error.contains("unsupported"));
    }

    #[test]
    fn empty_tracker_list_returns_no_peers_no_failures() {
        let req = build_started_request([0; 20], [0; 20], 6881, 1000);
        let (peers, failures) = announce_to_all(&[], &req);
        assert!(peers.is_empty());
        assert!(failures.is_empty());
    }

    #[test]
    fn build_started_request_sets_event_and_left() {
        let req = build_started_request([1; 20], [2; 20], 6881, 12345);
        assert_eq!(req.left, 12345);
        assert_eq!(req.event, Some(Event::Started));
        assert!(req.compact);
    }
}
