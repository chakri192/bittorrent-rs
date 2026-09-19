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

use crate::tracker::{announce_http, udp, AnnounceRequest, Event};
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
    announce_to_all_within(tracker_urls, req, OVERALL_ANNOUNCE_DEADLINE)
}

/// [`announce_to_all`] with a caller-chosen deadline, for announces that
/// must not hold anything up for long -- the `stopped` one sent as the
/// client exits.
pub fn announce_to_all_within(tracker_urls: &[String], req: &AnnounceRequest, deadline: Duration) -> (Vec<SocketAddr>, Vec<TrackerAttempt>, Option<u32>) {
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
            } else if url.starts_with("https://") || url.starts_with("http://") {
                announce_http(&url, &req).map_err(|e| e.to_string())
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

    let give_up_at = Instant::now() + deadline;
    while answered.len() < tracker_urls.len() {
        let remaining = give_up_at.saturating_duration_since(Instant::now());
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
            failures.push(TrackerAttempt { url: url.clone(), error: format!("no response within {}", describe(deadline)) });
        }
    }

    (peers.into_iter().collect(), failures, max_interval)
}

/// A deadline as a person would say it: "20s", or "500ms" when under a second.
fn describe(deadline: Duration) -> String {
    if deadline.subsec_nanos() == 0 {
        format!("{}s", deadline.as_secs())
    } else {
        format!("{}ms", deadline.as_millis())
    }
}

/// How a torrent's trackers are asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrackerMode {
    /// As BEP 12 says: the announce list is a list of tiers; a tier's trackers are tried in order until one
    /// answers, which then goes to the front of its tier, and a tier is tried only if every one before it failed.
    #[default]
    Tiered,
    /// Every tracker at once, and the union of what they say: more peers sooner, and more requests to trackers.
    Concurrent,
}

impl TrackerMode {
    pub fn parse(text: &str) -> Option<TrackerMode> {
        match text {
            "tiered" => Some(TrackerMode::Tiered),
            "concurrent" => Some(TrackerMode::Concurrent),
            _ => None,
        }
    }
}

/// How long a tracker in a tier is given before the next one is tried. (Concurrent announces wait longer for
/// stragglers, since they cost nothing to wait for; here each one waited for delays the next.)
pub const TIERED_TRACKER_DEADLINE: Duration = Duration::from_secs(8);

/// Asks the trackers of `tiers` as BEP 12 has it, with `ask` making one announce to one URL: the tiers in order and
/// each tier's trackers in order, stopping at the first that answers, which is moved to the front of its tier so that
/// it is asked first next time. Returns that tracker and what it said, if one answered; and the trackers asked that
/// did not, in the order asked.
pub fn walk_tiers<T>(tiers: &mut [Vec<String>], mut ask: impl FnMut(&str) -> Result<T, String>) -> (Option<(String, T)>, Vec<TrackerAttempt>) {
    let mut failures = Vec::new();
    for tier in tiers.iter_mut() {
        for i in 0..tier.len() {
            match ask(&tier[i]) {
                Ok(answer) => {
                    let url = tier.remove(i);
                    tier.insert(0, url.clone());
                    return (Some((url, answer)), failures);
                }
                Err(error) => failures.push(TrackerAttempt { url: tier[i].clone(), error }),
            }
        }
    }
    (None, failures)
}

/// Puts each tier in a random order, as BEP 12 has clients do so that the load is spread over a tier's trackers.
pub fn shuffled(mut tiers: Vec<Vec<String>>) -> Vec<Vec<String>> {
    for tier in tiers.iter_mut() {
        for i in (1..tier.len()).rev() {
            let mut byte = [0u8; 4];
            // (If the system has no randomness the order is left as it was.)
            if getrandom::getrandom(&mut byte).is_err() {
                return tiers;
            }
            tier.swap(i, u32::from_le_bytes(byte) as usize % (i + 1));
        }
    }
    tiers
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

    /// A tracker that accepts the connection and never says a word.
    fn silent_tracker() -> (String, std::net::TcpListener) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        (format!("http://{}/announce", listener.local_addr().unwrap()), listener)
    }

    #[test]
    fn a_tracker_that_never_answers_is_given_up_on_at_the_deadline() {
        let (url, _listener) = silent_tracker(); // connections queue in the backlog, unanswered
        let req = build_started_request([0; 20], [0; 20], 6881, 1000);

        let started = Instant::now();
        let (peers, failures, _) = announce_to_all_within(std::slice::from_ref(&url), &req, Duration::from_millis(400));
        let waited = started.elapsed();

        assert!(peers.is_empty());
        assert!(waited >= Duration::from_millis(400), "it waited the deadline out: {:?}", waited);
        assert!(waited < Duration::from_secs(5), "and not the 15 s the request itself would allow: {:?}", waited);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].url, url);
        assert_eq!(failures[0].error, "no response within 400ms");
    }

    #[test]
    fn a_whole_second_deadline_is_described_in_seconds() {
        assert_eq!(describe(Duration::from_secs(20)), "20s");
        assert_eq!(describe(Duration::from_millis(1500)), "1500ms");
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

    #[test]
    fn a_tracker_that_redirects_still_gives_its_peers_to_the_announce_round() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let reply: Vec<u8> = if head.starts_with(b"GET /old") {
                    b"HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n".to_vec()
                } else {
                    let body = b"d8:intervali900e5:peers6:\x0a\x00\x00\x07\x1a\xe1e";
                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                    r.extend_from_slice(body);
                    r
                };
                let _ = stream.write_all(&reply);
            }
        });
        let req = build_started_request([0; 20], [0; 20], 6881, 1000);

        let (peers, failures, interval) = announce_to_all(&[format!("http://127.0.0.1:{}/old", port)], &req);

        assert!(failures.is_empty(), "{:?}", failures);
        assert_eq!(peers.len(), 1);
        assert_eq!(interval, Some(900));
    }

    // ---- tiers ------------------------------------------------------------

    fn tiers(list: &[&[&str]]) -> Vec<Vec<String>> {
        list.iter().map(|tier| tier.iter().map(|u| u.to_string()).collect()).collect()
    }

    #[test]
    fn the_first_tracker_that_answers_ends_the_walk_and_goes_to_the_front_of_its_tier() {
        let mut list = tiers(&[&["a", "b", "c"], &["d"]]);
        let mut asked = Vec::new();
        let (found, failures) = walk_tiers(&mut list, |url| {
            asked.push(url.to_string());
            if url == "b" { Ok(7) } else { Err(format!("{} is down", url)) }
        });
        assert_eq!(asked, vec!["a", "b"], "in order, and no further once one answered: not c, and not the next tier");
        assert_eq!(found, Some(("b".to_string(), 7)));
        assert_eq!(failures.iter().map(|f| (f.url.as_str(), f.error.as_str())).collect::<Vec<_>>(), vec![("a", "a is down")]);
        assert_eq!(list, tiers(&[&["b", "a", "c"], &["d"]]), "the one that answered is asked first next time");
    }

    #[test]
    fn a_tier_is_tried_only_once_every_tracker_before_it_has_failed() {
        let mut list = tiers(&[&["a", "b"], &["c", "d"], &["e"]]);
        let mut asked = Vec::new();
        let (found, failures) = walk_tiers(&mut list, |url| {
            asked.push(url.to_string());
            if url == "d" { Ok(()) } else { Err("no".to_string()) }
        });
        assert_eq!(asked, vec!["a", "b", "c", "d"]);
        assert_eq!(found.map(|(url, _)| url), Some("d".to_string()));
        assert_eq!(failures.len(), 3);
        assert_eq!(list, tiers(&[&["a", "b"], &["d", "c"], &["e"]]), "only its own tier is reordered");
    }

    #[test]
    fn when_every_tracker_fails_they_all_were_asked_and_none_answered() {
        let mut list = tiers(&[&["a"], &["b", "c"]]);
        let (found, failures) = walk_tiers(&mut list, |_| Err::<(), _>("no".to_string()));
        assert!(found.is_none());
        assert_eq!(failures.iter().map(|f| f.url.as_str()).collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(list, tiers(&[&["a"], &["b", "c"]]), "nothing reordered");
        assert!(walk_tiers(&mut Vec::<Vec<String>>::new(), |_| Ok::<(), String>(())).0.is_none(), "no trackers, no answer");
    }

    #[test]
    fn shuffling_keeps_every_tracker_in_its_tier_and_does_change_the_order() {
        let original = tiers(&[&["a", "b", "c", "d", "e", "f", "g", "h"], &["i"], &[]]);
        let mut changed = false;
        for _ in 0..20 {
            let shuffled = shuffled(original.clone());
            assert_eq!(shuffled.len(), 3);
            for (before, after) in original.iter().zip(&shuffled) {
                let (mut b, mut a) = (before.clone(), after.clone());
                b.sort();
                a.sort();
                assert_eq!(a, b, "the same trackers, in the same tier");
            }
            changed |= shuffled[0] != original[0];
        }
        assert!(changed, "twenty shuffles of eight, and the order never once differed");
    }

    #[test]
    fn a_tracker_mode_is_read_from_its_name() {
        assert_eq!(TrackerMode::parse("tiered"), Some(TrackerMode::Tiered));
        assert_eq!(TrackerMode::parse("concurrent"), Some(TrackerMode::Concurrent));
        assert_eq!(TrackerMode::parse("Tiered"), None);
        assert_eq!(TrackerMode::default(), TrackerMode::Tiered, "BEP 12 is the default");
    }
}
