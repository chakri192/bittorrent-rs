//! Given a torrent's list of tracker URLs (mixed http:// and udp://),
//! announces to each in turn and merges the peer lists. A single bad or
//! unreachable tracker doesn't abort the whole discovery -- we only fail
//! if *every* tracker fails, which is the actual "no peers findable" case.

use crate::tracker::{http, https, udp, AnnounceRequest, Event};
use std::collections::HashSet;
use std::net::SocketAddrV4;

#[derive(Debug)]
pub struct TrackerAttempt {
    pub url: String,
    pub error: String,
}

/// Announces to every URL in `tracker_urls`, returning the deduplicated
/// union of all peers any tracker returned, the list of trackers that
/// failed (for diagnostics -- not fatal unless *all* of them are in this
/// list), and the re-announce interval to wait before trying again.
///
/// The interval is the *maximum* `interval` (or `min_interval` if a
/// tracker sent one) across every tracker that responded -- i.e. the most
/// conservative choice. Re-announcing faster than any tracker's requested
/// interval is how clients get themselves rate-limited or banned; using
/// the max rather than the min means we never violate the slowest
/// tracker's request just because a faster one also happened to answer.
pub fn announce_to_all(tracker_urls: &[String], req: &AnnounceRequest) -> (Vec<SocketAddrV4>, Vec<TrackerAttempt>, Option<u32>) {
    let mut peers = HashSet::new();
    let mut failures = Vec::new();
    let mut max_interval: Option<u32> = None;

    for url in tracker_urls {
        let result = if let Some(host_port) = url.strip_prefix("udp://") {
            // udp:// tracker URLs sometimes have a trailing "/announce"
            // path segment (no meaning for UDP trackers) -- strip it.
            let host_port = host_port.split('/').next().unwrap_or(host_port);
            udp::announce(host_port, req).map_err(|e| e.to_string())
        } else if url.starts_with("https://") {
            https::announce(url, req).map_err(|e| e.to_string())
        } else if url.starts_with("http://") {
            http::announce(url, req).map_err(|e| e.to_string())
        } else {
            Err(format!("unsupported tracker scheme: {}", url))
        };

        match result {
            Ok(resp) => {
                peers.extend(resp.peers);
                let wait = resp.min_interval.unwrap_or(resp.interval);
                max_interval = Some(max_interval.map_or(wait, |cur| cur.max(wait)));
            }
            Err(e) => failures.push(TrackerAttempt { url: url.clone(), error: e }),
        }
    }

    (peers.into_iter().collect(), failures, max_interval)
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

/// A periodic re-announce (BEP 3): `event` is omitted (not `Started`
/// again) since this is neither the first announce nor a stop/complete
/// notification -- just "still here, still want peers."
pub fn build_regular_request(info_hash: [u8; 20], peer_id: [u8; 20], port: u16, total_length: u64) -> AnnounceRequest {
    AnnounceRequest {
        info_hash,
        peer_id,
        port,
        uploaded: 0,
        downloaded: 0,
        left: total_length,
        compact: true,
        event: None,
        numwant: Some(50),
    }
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
