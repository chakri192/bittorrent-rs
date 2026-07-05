//! End-to-end CLI tying every phase together:
//!   .torrent file OR magnet link
//!     -> (magnet only) fetch+verify info dict from a peer (BEP 9/10)
//!     -> announce to tracker(s) (HTTP/UDP) for peer addresses
//!     -> spawn one worker thread per peer, sharing a piece work queue
//!     -> each piece is hash-verified before it touches disk
//!
//! Usage: download <file.torrent | magnet:?xt=urn:btih:...> [--out DIR] [--peers N]
//!
//! Known limitations (see README): no DHT/PEX (tracker-only peer
//! discovery), no seeding/uploading, single upfront tracker announce (no
//! periodic re-announce), no resume support (always starts from piece 0).

use bittorrent_rs::downloader::{build_file_spans, build_work_queue, run_worker, WorkQueue, WorkerConfig};
use bittorrent_rs::magnet::parse_magnet_uri;
use bittorrent_rs::magnet_fetch::fetch_metadata_from_peer;
use bittorrent_rs::torrent::{self, TorrentFile};
use bittorrent_rs::tracker::generate_peer_id;
use bittorrent_rs::tracker_discovery::{announce_to_all, build_started_request};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Conventional BitTorrent port. We never actually bind/listen on it --
/// this client is outbound-only (no seeding) -- but trackers expect a
/// plausible port in the announce regardless.
const ANNOUNCE_PORT: u16 = 6881;
const DEFAULT_MAX_PEERS: usize = 30;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PIPELINE_DEPTH: usize = 5;

struct Args {
    source: String,
    out_dir: PathBuf,
    max_peers: usize,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let source = argv.next().ok_or_else(usage)?;
    if source == "--help" || source == "-h" {
        return Err(usage());
    }

    let mut out_dir = PathBuf::from("downloads");
    let mut max_peers = DEFAULT_MAX_PEERS;

    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--out" => out_dir = PathBuf::from(argv.next().ok_or("--out requires a directory argument")?),
            "--peers" => {
                let n = argv.next().ok_or("--peers requires a number argument")?;
                max_peers = n.parse().map_err(|_| format!("--peers: not a number: {}", n))?;
            }
            other => return Err(format!("unrecognized argument: {}", other)),
        }
    }

    Ok(Args { source, out_dir, max_peers })
}

fn usage() -> String {
    "usage: download <file.torrent | magnet:?xt=urn:btih:...> [--out DIR] [--peers N]".to_string()
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{}", msg);
            return ExitCode::FAILURE;
        }
    };

    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {}", msg);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    let our_peer_id = generate_peer_id();

    let (torrent, mut initial_peers) = if args.source.starts_with("magnet:?") {
        resolve_magnet(&args.source, our_peer_id)?
    } else {
        let bytes = fs::read(&args.source).map_err(|e| format!("reading {}: {}", args.source, e))?;
        let torrent = torrent::parse_torrent_file(&bytes).map_err(|e| format!("parsing {}: {}", args.source, e))?;
        (torrent, Vec::new())
    };

    println!("torrent: {} ({} bytes, {} pieces)", torrent.name, torrent.total_length(), torrent.pieces.len());

    // Real announce now that we know the true size (`left`). This is
    // additive to any peers already found while bootstrapping a magnet
    // link -- a failure here doesn't strand us if that bootstrap already
    // found peers.
    let tracker_urls = collect_tracker_urls(&torrent);
    if !tracker_urls.is_empty() {
        let req = build_started_request(torrent.info_hash, our_peer_id, ANNOUNCE_PORT, torrent.total_length());
        let (peers, failures) = announce_to_all(&tracker_urls, &req);
        for f in &failures {
            eprintln!("warning: tracker {} failed: {}", f.url, f.error);
        }
        initial_peers.extend(peers.into_iter().map(SocketAddr::V4));
    }
    initial_peers.sort_by_key(|a| a.to_string());
    initial_peers.dedup();

    if initial_peers.is_empty() {
        return Err("no peers found from any tracker".to_string());
    }
    println!("found {} peer(s), connecting up to {}", initial_peers.len(), args.max_peers);

    let base_dir = if torrent.files.len() > 1 { args.out_dir.join(&torrent.name) } else { args.out_dir.clone() };
    let spans = Arc::new(build_file_spans(&base_dir, &torrent.files));
    let queue = Arc::new(WorkQueue::new(build_work_queue(&torrent)));
    let total_pieces = torrent.pieces.len();
    let piece_length = torrent.piece_length as u64;

    let (tx, rx) = mpsc::channel();
    let config = Arc::new(WorkerConfig { info_hash: torrent.info_hash, our_peer_id, pipeline_depth: PIPELINE_DEPTH, connect_timeout: CONNECT_TIMEOUT });

    let mut handles = Vec::new();
    for addr in initial_peers.into_iter().take(args.max_peers) {
        let queue = Arc::clone(&queue);
        let spans = Arc::clone(&spans);
        let config = Arc::clone(&config);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = run_worker(addr, &config, &queue, &spans, piece_length, &tx) {
                eprintln!("peer {} disconnected: {:?}", addr, e);
            }
        }));
    }
    drop(tx); // so rx below ends once every worker's clone is dropped

    let mut verified = 0usize;
    for result in rx {
        verified += 1;
        println!("piece {} verified ({}/{})", result.index, verified, total_pieces);
    }

    for h in handles {
        let _ = h.join();
    }

    if queue.is_empty() {
        println!("download complete: {} -> {}", torrent.name, base_dir.display());
        Ok(())
    } else {
        Err(format!("incomplete: {} piece(s) never downloaded (ran out of usable peers)", queue.len()))
    }
}

/// Bootstraps a magnet link: announces to its trackers with an unknown
/// (`left = 1`, a harmless placeholder) size just to get *some* peer
/// addresses, then asks peers in turn for the info dict until one
/// succeeds. Returns the built `TorrentFile` plus whichever peers
/// responded (reused for the download phase so a slow/flaky real
/// announce afterward doesn't throw away already-known-good peers).
fn resolve_magnet(uri: &str, our_peer_id: [u8; 20]) -> Result<(TorrentFile, Vec<SocketAddr>), String> {
    let magnet = parse_magnet_uri(uri).map_err(|e| format!("parsing magnet uri: {}", e))?;
    if magnet.trackers.is_empty() {
        // No DHT/PEX in this client (see module doc) -- a magnet link with
        // no tracker gives us no way to find any peer at all.
        return Err("magnet link has no trackers and this client has no DHT/PEX support".to_string());
    }

    let bootstrap_req = build_started_request(magnet.info_hash, our_peer_id, ANNOUNCE_PORT, 1);
    let (peers, failures) = announce_to_all(&magnet.trackers, &bootstrap_req);
    for f in &failures {
        eprintln!("warning: tracker {} failed: {}", f.url, f.error);
    }
    if peers.is_empty() {
        return Err("no peers found for magnet link (all trackers failed or returned none)".to_string());
    }

    let mut last_err = String::new();
    for peer in &peers {
        match fetch_metadata_from_peer(SocketAddr::V4(*peer), magnet.info_hash, our_peer_id, CONNECT_TIMEOUT) {
            Ok(raw_info) => {
                let announce = magnet.trackers.first().cloned();
                let announce_list = vec![magnet.trackers.clone()];
                let torrent = torrent::from_info_dict_bytes(&raw_info, magnet.info_hash, announce, announce_list).map_err(|e| format!("building torrent from metadata: {}", e))?;
                return Ok((torrent, peers.into_iter().map(SocketAddr::V4).collect()));
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(format!("no peer among {} would provide metadata (last error: {})", peers.len(), last_err))
}

fn collect_tracker_urls(torrent: &TorrentFile) -> Vec<String> {
    let mut urls: Vec<String> = torrent.announce.iter().cloned().collect();
    for tier in &torrent.announce_list {
        urls.extend(tier.iter().cloned());
    }
    urls.sort();
    urls.dedup();
    urls
}
