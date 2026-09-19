//! Turning a magnet link into a torrent: find peers, then ask them for the
//! info dict (BEP 9) until one hands over a copy that matches the link's
//! hash.

use crate::dht::DhtService;
use crate::magnet::MagnetLink;
use crate::magnet_fetch::fetch_metadata_from_peer;
use crate::session::ProgressSink;
use crate::sync::lock;
use crate::torrent::{self, TorrentFile};
use crate::tracker::Event;
use crate::tracker_discovery::{announce_to_all, build_request, TransferTotals};
use crate::ui::Snapshot;
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How hard to try to get the metadata.
pub struct MetadataConfig {
    /// Give up, calling the swarm unreachable, after this long.
    pub budget: Duration,
    /// Concurrent BEP 9 probes. Thin swarms are mostly dead peers, so
    /// probing many at once is the difference between resolving in seconds
    /// and blowing the budget on a handful of timeouts.
    pub parallelism: usize,
    /// How long to wait on each peer's connection.
    pub connect_timeout: Duration,
    /// Whether to use message stream encryption with the peers.
    pub encryption: crate::peer::Encryption,
    /// How the peers are dialed.
    pub transport: crate::peer::Transport,
}

/// What a successful search found.
pub struct Fetched {
    /// The info dict's exact bytes, verified against the info-hash.
    pub raw_info: Vec<u8>,
    /// Every peer address learned along the way; they seed the download
    /// phase's dial queue.
    pub known_peers: Vec<SocketAddr>,
}

/// Bootstraps a magnet link into a full `TorrentFile`: gathers peers from
/// the magnet's trackers and the DHT, then probes them concurrently for
/// the info dict (BEP 9) until one delivers a copy that SHA-1-verifies
/// against the magnet's InfoHash. Returns the torrent plus every peer
/// address gathered (they seed the download phase's dial queue).
pub fn resolve_magnet(magnet: &MagnetLink, our_peer_id: [u8; 20], announce_port: u16, dht: Option<&DhtService>, config: &MetadataConfig, sink: &dyn ProgressSink, stop: &AtomicBool) -> Result<(TorrentFile, Vec<SocketAddr>), String> {
    let mut initial_peers = Vec::new();
    if !magnet.trackers.is_empty() {
        sink.log(format!("querying {} tracker(s) to bootstrap peer list", magnet.trackers.len()));
        let bootstrap_req = build_request(magnet.info_hash, our_peer_id, announce_port, TransferTotals { uploaded: 0, downloaded: 0, left: 1 }, Some(Event::Started));
        let (peers, failures, _interval) = announce_to_all(&magnet.trackers, &bootstrap_req);
        for f in &failures {
            sink.log(format!("tracker {} failed: {}", f.url, f.error));
        }
        initial_peers = peers;
    } else if magnet.peers.is_empty() {
        sink.log("magnet link has no trackers; waiting on the DHT for peers".to_string());
    }
    if !magnet.peers.is_empty() {
        sink.log(format!("the magnet link names {} peer(s) to try directly", magnet.peers.len()));
        initial_peers.extend(magnet.peers.iter().copied());
    }

    let fetched = fetch_metadata(magnet.info_hash, our_peer_id, initial_peers, dht, config, sink, stop)?;

    let announce = magnet.trackers.first().cloned();
    // One tier of every tracker in the link; none if it had none.
    let announce_list = if magnet.trackers.is_empty() { Vec::new() } else { vec![magnet.trackers.clone()] };
    let mut torrent = torrent::from_info_dict_bytes(&fetched.raw_info, magnet.info_hash, announce, announce_list).map_err(|e| format!("building torrent from metadata: {}", e))?;
    // The info dict carries no web seeds; the link may.
    torrent.url_list = magnet.web_seeds.clone();
    Ok((torrent, fetched.known_peers))
}

/// Probes peers concurrently for the info dict of `info_hash`, starting
/// from `initial_peers` and adding whatever the DHT turns up, until one
/// delivers a copy that verifies, `stop` is set, or the budget runs out.
pub fn fetch_metadata(info_hash: [u8; 20], our_peer_id: [u8; 20], initial_peers: Vec<SocketAddr>, dht: Option<&DhtService>, config: &MetadataConfig, sink: &dyn ProgressSink, stop: &AtomicBool) -> Result<Fetched, String> {
    let mut known: HashSet<SocketAddr> = HashSet::new();
    let untried: Arc<Mutex<VecDeque<SocketAddr>>> = Arc::new(Mutex::new(VecDeque::new()));
    {
        let mut q = lock(&untried);
        for p in initial_peers {
            if known.insert(p) {
                q.push_back(p);
            }
        }
    }

    // Concurrent BEP 9 probe pool. First worker to verify metadata wins.
    let pool_stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let last_err = Arc::new(Mutex::new(String::from("no peer source produced any address")));
    let (found_tx, found_rx) = mpsc::channel::<Vec<u8>>();

    let mut workers = Vec::with_capacity(config.parallelism);
    for _ in 0..config.parallelism {
        let untried = Arc::clone(&untried);
        let pool_stop = Arc::clone(&pool_stop);
        let attempts = Arc::clone(&attempts);
        let last_err = Arc::clone(&last_err);
        let found_tx = found_tx.clone();
        let connect_timeout = config.connect_timeout;
        let encryption = config.encryption;
        let transport = config.transport.clone();
        workers.push(thread::spawn(move || {
            while !pool_stop.load(Ordering::SeqCst) {
                let Some(peer) = lock(&untried).pop_front() else {
                    thread::sleep(Duration::from_millis(200));
                    continue;
                };
                attempts.fetch_add(1, Ordering::Relaxed);
                match fetch_metadata_from_peer(peer, info_hash, our_peer_id, connect_timeout, encryption, &transport) {
                    Ok(raw_info) => {
                        if !pool_stop.swap(true, Ordering::SeqCst) {
                            let _ = found_tx.send(raw_info);
                        }
                        return;
                    }
                    Err(e) => *lock(&last_err) = e.to_string(),
                }
            }
        }));
    }
    drop(found_tx);

    let deadline = Instant::now() + config.budget;
    let mut last_log = Instant::now();
    let raw_info = loop {
        if stop.load(Ordering::SeqCst) {
            break None; // user quit
        }
        if let Some(dht) = dht {
            let mut q = lock(&untried);
            for batch in dht.peers_rx.try_iter() {
                for p in batch {
                    if known.insert(p) {
                        q.push_back(p);
                    }
                }
            }
        }

        // Keep the dashboard alive during resolution.
        sink.set_snapshot(Snapshot {
            known_peers: known.len(),
            dht_nodes: dht.map(|d| d.nodes.load(Ordering::SeqCst)).unwrap_or(0),
            status: "resolving",
            ..Default::default()
        });
        if last_log.elapsed() >= Duration::from_secs(3) {
            sink.log(format!("resolving metadata: {} peer(s) probed, {} known, {}s left", attempts.load(Ordering::Relaxed), known.len(), deadline.saturating_duration_since(Instant::now()).as_secs()));
            last_log = Instant::now();
        }

        match found_rx.recv_timeout(Duration::from_millis(300)) {
            Ok(raw) => break Some(raw),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= deadline {
                    break None;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break None,
        }
    };
    pool_stop.store(true, Ordering::SeqCst);
    for w in workers {
        let _ = w.join();
    }

    match raw_info {
        Some(raw_info) => {
            sink.log("metadata received and verified against magnet InfoHash".to_string());
            Ok(Fetched { raw_info, known_peers: known.into_iter().collect() })
        }
        None => {
            let n = attempts.load(Ordering::Relaxed);
            let last = lock(&last_err).clone();
            Err(if stop.load(Ordering::SeqCst) {
                "stopped before metadata could be resolved".to_string()
            } else if Instant::now() >= deadline {
                format!("metadata resolution budget ({}s) exhausted after {} concurrent probe(s) across {} known peer(s) (last error: {})", config.budget.as_secs(), n, known.len(), last)
            } else {
                format!("no peer among {} would provide metadata after {} probe(s) (last error: {})", known.len(), n, last)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::magnet::parse_magnet_uri;
    use crate::metadata::{MetadataMessage, METADATA_PIECE_SIZE};
    use crate::peer::handshake::Handshake;
    use crate::peer::message::Message;
    use crate::peer::ExtendedHandshake;
    use crate::session::sink::RecordingSink;
    use crate::session::testing::{dead_addr, tracker};
    use sha1::{Digest, Sha1};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// The extended-message id the test peers use for ut_metadata; not the
    /// one the client picks, so the client must use the one it is told.
    const PEER_UT_METADATA_ID: u8 = 7;

    fn info_bytes() -> Vec<u8> {
        let mut v = b"d6:lengthi1024e4:name8:file.bin12:piece lengthi16384e6:pieces20:".to_vec();
        v.extend_from_slice(&[0xAB; 20]);
        v.push(b'e');
        v
    }

    fn info_hash() -> [u8; 20] {
        Sha1::digest(info_bytes()).into()
    }

    /// A peer that speaks BEP 9: it advertises `served` as the info dict
    /// and serves it. If `served` is not the real info dict, the client's
    /// verification against the info-hash must reject it.
    fn metadata_peer(served: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let served = served.clone();
                thread::spawn(move || {
                    let mut hs = [0u8; 68];
                    if stream.read_exact(&mut hs).is_err() || stream.write_all(&Handshake::new(info_hash(), [0x55; 20], true).to_bytes()).is_err() {
                        return;
                    }
                    let mut client_id = None;
                    while let Ok(msg) = Message::read_from(&mut stream) {
                        match msg {
                            Message::Extended { id: 0, payload } => {
                                client_id = ExtendedHandshake::parse(&payload).ok().and_then(|h| h.peer_ut_metadata_id());
                                let reply = ExtendedHandshake::build(PEER_UT_METADATA_ID, Some(served.len() as i64));
                                if (Message::Extended { id: 0, payload: reply }).write_to(&mut stream).is_err() {
                                    return;
                                }
                            }
                            Message::Extended { id, payload } if id == PEER_UT_METADATA_ID => {
                                let (Some(reply_id), Ok(MetadataMessage::Request { piece })) = (client_id, MetadataMessage::decode(&payload)) else { continue };
                                let start = piece as usize * METADATA_PIECE_SIZE;
                                let end = (start + METADATA_PIECE_SIZE).min(served.len());
                                let data = MetadataMessage::Data { piece, total_size: served.len() as u32, data: served[start..end].to_vec() };
                                if (Message::Extended { id: reply_id, payload: data.encode() }).write_to(&mut stream).is_err() {
                                    return;
                                }
                            }
                            _ => {}
                        }
                    }
                });
            }
        });
        addr
    }

    fn good_peer() -> SocketAddr {
        metadata_peer(info_bytes())
    }

    /// Same length as the real info dict, one byte different.
    fn corrupt_peer() -> SocketAddr {
        let mut bad = info_bytes();
        let last = bad.len() - 2;
        bad[last] ^= 0xFF;
        metadata_peer(bad)
    }

    fn config() -> MetadataConfig {
        MetadataConfig { budget: Duration::from_secs(1), parallelism: 4, connect_timeout: Duration::from_secs(1), encryption: Default::default(), transport: Default::default() }
    }

    fn fetch(peers: Vec<SocketAddr>, stop: &AtomicBool, sink: &RecordingSink) -> Result<Fetched, String> {
        fetch_metadata(info_hash(), [2; 20], peers, None, &config(), sink, stop)
    }

    #[test]
    fn the_one_peer_that_has_the_metadata_is_found_among_dead_ones() {
        let sink = RecordingSink::default();
        let good = good_peer();
        let peers = vec![dead_addr(), dead_addr(), good, dead_addr()];

        let fetched = fetch(peers.clone(), &AtomicBool::new(false), &sink).expect("one good peer is enough");

        assert_eq!(fetched.raw_info, info_bytes());
        assert_eq!(fetched.known_peers.len(), 4, "every address offered is remembered for the download phase");
        assert!(peers.iter().all(|p| fetched.known_peers.contains(p)));
        assert!(sink.logged("metadata received and verified against magnet InfoHash"));
    }

    #[test]
    fn a_peer_serving_metadata_that_fails_verification_is_passed_over() {
        let sink = RecordingSink::default();
        let fetched = fetch(vec![corrupt_peer(), good_peer()], &AtomicBool::new(false), &sink).expect("the honest peer still delivers");
        assert_eq!(fetched.raw_info, info_bytes());
    }

    #[test]
    fn only_a_corrupt_peer_means_no_metadata_and_the_reason_says_why() {
        let sink = RecordingSink::default();
        let Err(reason) = fetch(vec![corrupt_peer()], &AtomicBool::new(false), &sink) else { panic!("corrupt metadata must never be accepted") };
        assert!(reason.contains("budget (1s) exhausted after 1 concurrent probe(s) across 1 known peer(s)"), "{}", reason);
        assert!(reason.contains("last error:"), "{}", reason);
    }

    #[test]
    fn with_nobody_reachable_the_budget_runs_out_and_the_reason_counts_the_probes() {
        let sink = RecordingSink::default();
        let Err(reason) = fetch(vec![dead_addr(), dead_addr()], &AtomicBool::new(false), &sink) else { panic!("nobody has the metadata") };
        assert!(reason.contains("metadata resolution budget (1s) exhausted after 2 concurrent probe(s) across 2 known peer(s)"), "{}", reason);
    }

    #[test]
    fn a_stop_request_ends_the_search_at_once() {
        let sink = RecordingSink::default();
        let started = Instant::now();
        let Err(reason) = fetch(vec![dead_addr()], &AtomicBool::new(true), &sink) else { panic!("stopped before anything was fetched") };
        assert_eq!(reason, "stopped before metadata could be resolved");
        assert!(started.elapsed() < Duration::from_millis(900), "it did not wait out the 1s budget");
    }

    #[test]
    fn an_address_offered_twice_is_probed_and_remembered_once() {
        // A corrupt peer never yields metadata, so the search runs out its
        // budget and reports how many probes it made: one, not two.
        let sink = RecordingSink::default();
        let bad = corrupt_peer();
        let Err(reason) = fetch(vec![bad, bad], &AtomicBool::new(false), &sink) else { panic!("corrupt metadata must never be accepted") };
        assert!(reason.contains("after 1 concurrent probe(s) across 1 known peer(s)"), "{}", reason);
    }

    #[test]
    fn the_dashboard_shows_resolving_with_the_number_of_peers_known() {
        let sink = RecordingSink::default();
        let _ = fetch(vec![dead_addr(), dead_addr(), dead_addr()], &AtomicBool::new(false), &sink);
        let snap = sink.last_snapshot();
        assert_eq!((snap.status, snap.known_peers), ("resolving", 3));
    }

    fn magnet(trackers: &[String]) -> MagnetLink {
        let hash: String = info_hash().iter().map(|b| format!("{:02x}", b)).collect();
        let mut uri = format!("magnet:?xt=urn:btih:{}", hash);
        for t in trackers {
            uri.push_str(&format!("&tr={}", t.replace(':', "%3A").replace('/', "%2F")));
        }
        parse_magnet_uri(&uri).unwrap()
    }

    #[test]
    fn a_magnet_link_becomes_a_torrent_through_its_tracker_and_a_peer() {
        let sink = RecordingSink::default();
        let peer = good_peer();
        let (url, requests) = tracker(peer);

        let (torrent, known) = resolve_magnet(&magnet(std::slice::from_ref(&url)), [2; 20], 6881, None, &config(), &sink, &AtomicBool::new(false)).expect("tracker -> peer -> metadata -> torrent");

        assert_eq!((torrent.name.as_str(), torrent.pieces.len(), torrent.total_length()), ("file.bin", 1, 1024));
        assert_eq!(torrent.info_hash, info_hash());
        assert_eq!(torrent.announce.as_deref(), Some(url.as_str()), "the magnet's tracker becomes the torrent's");
        assert_eq!(known, vec![peer]);
        assert!(sink.logged("querying 1 tracker(s) to bootstrap peer list"));

        // The bootstrap announce reports a leecher of unknown size: left=1.
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("left=1&") && requests[0].contains("event=started") && requests[0].contains("port=6881"), "{}", requests[0]);
    }

    #[test]
    fn a_magnet_link_with_no_trackers_says_it_is_waiting_on_the_dht() {
        let sink = RecordingSink::default();
        let result = resolve_magnet(&magnet(&[]), [2; 20], 6881, None, &config(), &sink, &AtomicBool::new(false));
        assert!(result.is_err(), "no trackers and no DHT means no peers");
        assert!(sink.logged("magnet link has no trackers; waiting on the DHT for peers"));
    }

    #[test]
    fn a_failing_tracker_is_logged_and_the_search_goes_on() {
        let sink = RecordingSink::default();
        let dead_tracker = format!("http://{}/announce", dead_addr());
        let _ = resolve_magnet(&magnet(std::slice::from_ref(&dead_tracker)), [2; 20], 6881, None, &config(), &sink, &AtomicBool::new(false));
        assert!(sink.logged(&format!("tracker {} failed:", dead_tracker)));
    }

    #[test]
    fn a_peer_named_in_the_link_is_used_with_no_tracker_at_all() {
        let sink = RecordingSink::default();
        let peer = good_peer();
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}&x.pe={}", info_hash().iter().map(|b| format!("{:02x}", b)).collect::<String>(), peer)).unwrap();

        let (torrent, known) = resolve_magnet(&link, [2; 20], 6881, None, &config(), &sink, &AtomicBool::new(false)).expect("the hinted peer serves the metadata");

        assert_eq!(torrent.info_hash, info_hash());
        assert_eq!(known, vec![peer]);
        assert!(sink.logged("names 1 peer(s) to try directly"));
        assert!(!sink.logged("waiting on the DHT"), "there was somewhere to start");
        assert!(torrent.announce.is_none() && torrent.announce_list.is_empty(), "no tracker, no empty tier either");
    }

    #[test]
    fn web_seeds_in_the_link_become_the_torrents() {
        let sink = RecordingSink::default();
        let peer = good_peer();
        let hex: String = info_hash().iter().map(|b| format!("{:02x}", b)).collect();
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}&x.pe={}&ws=http%3A%2F%2Fmirror%2Ffile.bin", hex, peer)).unwrap();

        let (torrent, _) = resolve_magnet(&link, [2; 20], 6881, None, &config(), &sink, &AtomicBool::new(false)).unwrap();

        assert_eq!(torrent.url_list, vec!["http://mirror/file.bin".to_string()]);
    }
}
