//! End-to-end CLI tying every phase together:
//!   .torrent file OR magnet link
//!     -> (magnet only) fetch+verify info dict from a peer (BEP 9/10)
//!     -> peer discovery: tracker announces (HTTP/HTTPS/UDP) + DHT
//!        (BEP 5) + PEX (BEP 11), all feeding one dial queue
//!     -> up to --peers concurrent worker threads share a piece queue
//!        (rarest-first, endgame duplication for the final stretch)
//!     -> every piece is hash-verified before it touches disk
//!     -> verified pieces are served back to the swarm while
//!        downloading, and afterward with --seed
//!
//! Usage: download <file.torrent | magnet:?xt=urn:btih:...> [options]

use bittorrent_rs::dht;
use bittorrent_rs::downloader::{build_file_spans, build_work_queue, load_and_verify, progress_file_path, rewrite_compact, run_worker, PexSender, ResumeWriter, WorkQueue, WorkerConfig};
use bittorrent_rs::magnet::parse_magnet_uri;
use bittorrent_rs::magnet_fetch::fetch_metadata_from_peer;
use bittorrent_rs::seeder::{self, HaveMap};
use bittorrent_rs::torrent::{self, TorrentFile};
use bittorrent_rs::tracker::{generate_peer_id, Event};
use bittorrent_rs::tracker_discovery::{announce_to_all, build_request, TransferTotals};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Conventional BitTorrent port: preferred TCP listen port for the
/// seeder and UDP bind for the DHT node (both fall back to ephemeral if
/// taken). Trackers and DHT announces carry whatever port was actually
/// bound.
const DEFAULT_PORT: u16 = 6881;
const DEFAULT_MAX_PEERS: usize = 30;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PIPELINE_DEPTH: usize = 5;
/// Floor on re-announce spacing regardless of what a tracker requests --
/// guards against a misbehaving tracker asking for an unreasonably tight
/// loop and this client happily hammering it. Also the fast-path wait
/// when the dial queue runs completely dry.
const MIN_REANNOUNCE: Duration = Duration::from_secs(30);
/// Ceiling used only when no tracker told us an interval at all.
const DEFAULT_REANNOUNCE: Duration = Duration::from_secs(120);
/// How often the main loop wakes up to check queue/handle state between
/// re-announces -- just a responsiveness tick, not a network operation.
const POLL_TICK: Duration = Duration::from_secs(2);
/// Give up only after this many consecutive re-announce rounds where NO
/// discovery source (tracker, DHT, PEX) produced a single new address
/// *and* no worker was running -- bounds "keep trying forever" against a
/// genuinely dead swarm without ever giving up while anything is alive.
const MAX_FRUITLESS_ROUNDS: u32 = 5;
/// How often to print a throughput/ETA summary line during an active
/// download (separate from the "waiting" heartbeat, which only fires
/// when nothing's happening).
const PROGRESS_SUMMARY_INTERVAL: Duration = Duration::from_secs(10);
/// Overall budget for resolving a magnet link's metadata across every
/// peer source before declaring the swarm unreachable.
const METADATA_RESOLVE_BUDGET: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

struct Args {
    source: String,
    out_dir: PathBuf,
    max_peers: usize,
    /// Overrides the tracker's requested re-announce interval. Still
    /// floored at `MIN_REANNOUNCE` even when explicitly set -- an
    /// override is for impatient manual testing, not for ignoring the
    /// floor that exists to avoid hammering a tracker.
    reannounce_override: Option<u64>,
    verbosity: Verbosity,
    /// Overall wall-clock budget for the whole run. `None` means no
    /// limit -- bounded only by `MAX_FRUITLESS_ROUNDS`.
    timeout: Option<Duration>,
    /// Preferred listen port (TCP seeder + UDP DHT).
    port: u16,
    /// Keep seeding after the download completes, until killed.
    seed: bool,
    no_dht: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let source = argv.next().ok_or_else(usage)?;
    if source == "--help" || source == "-h" {
        return Err(usage());
    }

    let mut out_dir = default_downloads_dir();
    let mut max_peers = DEFAULT_MAX_PEERS;
    let mut reannounce_override = None;
    let mut verbosity = Verbosity::Normal;
    let mut timeout = None;
    let mut port = DEFAULT_PORT;
    let mut seed = false;
    let mut no_dht = false;

    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--out" => out_dir = PathBuf::from(argv.next().ok_or("--out requires a directory argument")?),
            "--peers" => {
                let n = argv.next().ok_or("--peers requires a number argument")?;
                max_peers = n.parse().map_err(|_| format!("--peers: not a number: {}", n))?;
                if max_peers == 0 {
                    return Err("--peers must be at least 1".to_string());
                }
            }
            "--reannounce" => {
                let n = argv.next().ok_or("--reannounce requires a number of seconds")?;
                reannounce_override = Some(n.parse().map_err(|_| format!("--reannounce: not a number: {}", n))?);
            }
            "--timeout" => {
                let n = argv.next().ok_or("--timeout requires a number of seconds")?;
                let secs: u64 = n.parse().map_err(|_| format!("--timeout: not a number: {}", n))?;
                timeout = Some(Duration::from_secs(secs));
            }
            "--port" => {
                let n = argv.next().ok_or("--port requires a port number")?;
                port = n.parse().map_err(|_| format!("--port: not a valid port: {}", n))?;
            }
            "--seed" => seed = true,
            "--no-dht" => no_dht = true,
            "--quiet" | "-q" => {
                if verbosity == Verbosity::Verbose {
                    return Err("--quiet and --verbose are mutually exclusive".to_string());
                }
                verbosity = Verbosity::Quiet;
            }
            "--verbose" | "-v" => {
                if verbosity == Verbosity::Quiet {
                    return Err("--quiet and --verbose are mutually exclusive".to_string());
                }
                verbosity = Verbosity::Verbose;
            }
            other => return Err(format!("unrecognized argument: {}", other)),
        }
    }

    Ok(Args { source, out_dir, max_peers, reannounce_override, verbosity, timeout, port, seed, no_dht })
}

fn usage() -> String {
    "usage: download <file.torrent | magnet:?xt=urn:btih:...> [--out DIR] [--peers N] [--port PORT] [--seed] [--no-dht] [--reannounce SECONDS] [--timeout SECONDS] [--quiet | --verbose]".to_string()
}

/// Default `--out`: the user's actual `~/Downloads`, not a `./downloads`
/// created wherever the binary happens to be invoked from. Falls back to
/// `./downloads` only if `$HOME` isn't set at all (e.g. some minimal
/// containers) -- better than panicking over a missing default.
fn default_downloads_dir() -> PathBuf {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Downloads")).unwrap_or_else(|| PathBuf::from("downloads"))
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

/// One dial queue fed by every discovery source (tracker, DHT, PEX,
/// magnet bootstrap). `known` remembers every address ever seen so a
/// peer is dialed at most once per run, no matter how many sources
/// report it; `reserve` holds the ones not yet dialed.
struct PeerPool {
    known: HashSet<SocketAddr>,
    reserve: VecDeque<SocketAddr>,
}

impl PeerPool {
    fn new() -> Self {
        PeerPool { known: HashSet::new(), reserve: VecDeque::new() }
    }

    /// Adds addresses, returning how many were genuinely new.
    fn add(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> usize {
        let mut fresh = 0;
        for addr in addrs {
            if addr.port() == 0 {
                continue; // never dialable
            }
            if self.known.insert(addr) {
                self.reserve.push_back(addr);
                fresh += 1;
            }
        }
        fresh
    }

    fn next_to_dial(&mut self) -> Option<SocketAddr> {
        self.reserve.pop_front()
    }

    fn reserve_is_empty(&self) -> bool {
        self.reserve.is_empty()
    }

    fn dialed(&self) -> usize {
        self.known.len() - self.reserve.len()
    }
}

fn run(args: Args) -> Result<(), String> {
    let our_peer_id = generate_peer_id();
    let quiet = args.verbosity == Verbosity::Quiet;

    // The DHT learns our real TCP listen port only once the seeder has
    // bound it (0 = "don't announce yet") -- but the DHT node itself must
    // start *before* metadata resolution, because a trackerless magnet
    // has no other way to find its first peer.
    let dht_announce_port = Arc::new(AtomicU16::new(0));

    let (torrent, mut dht_service, bootstrap_peers) = if args.source.starts_with("magnet:?") {
        let magnet = parse_magnet_uri(&args.source).map_err(|e| format!("parsing magnet uri: {}", e))?;
        let dht_service = start_dht(&args, magnet.info_hash, &dht_announce_port, quiet);
        if magnet.trackers.is_empty() && dht_service.is_none() {
            return Err("magnet link has no trackers and DHT is disabled (--no-dht) -- no way to find any peer".to_string());
        }
        let (torrent, peers) = resolve_magnet(&magnet, our_peer_id, args.verbosity, args.port, dht_service.as_ref().map(|d| &d.peers_rx))?;
        (torrent, dht_service, peers)
    } else {
        let bytes = fs::read(&args.source).map_err(|e| format!("reading {}: {}", args.source, e))?;
        let torrent = torrent::parse_torrent_file(&bytes).map_err(|e| format!("parsing {}: {}", args.source, e))?;
        let dht_service = start_dht(&args, torrent.info_hash, &dht_announce_port, quiet);
        (torrent, dht_service, Vec::new())
    };

    if !quiet {
        println!("torrent: {} ({} bytes, {} pieces)", torrent.name, torrent.total_length(), torrent.pieces.len());
    }

    let tracker_urls = collect_tracker_urls(&torrent);
    let base_dir = if torrent.files.len() > 1 { args.out_dir.join(&torrent.name) } else { args.out_dir.clone() };
    let spans = Arc::new(build_file_spans(&base_dir, &torrent.files));
    let total_pieces = torrent.pieces.len();
    let total_length = torrent.total_length();
    let piece_length = torrent.piece_length as u64;

    // Resume: re-verify any pieces a previous run claimed complete
    // against their *actual* current bytes on disk before trusting them
    // (see downloader::resume -- a stale claim never gets blindly
    // trusted). Confirmed pieces are excluded from the work queue and
    // their bytes counted toward progress from the start.
    fs::create_dir_all(&args.out_dir).map_err(|e| format!("creating output directory {}: {}", args.out_dir.display(), e))?;
    let progress_path = progress_file_path(&args.out_dir, &torrent.info_hash);
    let confirmed_resumed = load_and_verify(&progress_path, &spans, &torrent);
    if !confirmed_resumed.is_empty() {
        if !quiet {
            println!("resuming: {} piece(s) already verified on disk, skipping", confirmed_resumed.len());
        }
        rewrite_compact(&progress_path, &confirmed_resumed).map_err(|e| format!("writing resume file: {}", e))?;
    }
    let mut resume_writer = ResumeWriter::create(&progress_path).map_err(|e| format!("opening resume file: {}", e))?;

    // Upload side: serve verified pieces to inbound peers for the whole
    // run. A bind failure downgrades to download-only with a warning --
    // never fatal.
    let have = Arc::new(HaveMap::new(total_pieces));
    for &idx in &confirmed_resumed {
        have.set(idx);
    }
    let mut seeder_handle = match seeder::start(args.port, torrent.info_hash, our_peer_id, Arc::clone(&spans), piece_length, total_length, Arc::clone(&have)) {
        Ok(handle) => {
            if !quiet {
                println!("listening for inbound peers on port {}", handle.port);
            }
            dht_announce_port.store(handle.port, Ordering::SeqCst);
            Some(handle)
        }
        Err(e) => {
            eprintln!("warning: could not start listener (continuing download-only): {}", e);
            None
        }
    };
    let announce_port = seeder_handle.as_ref().map(|s| s.port).unwrap_or(args.port);

    let all_work = build_work_queue(&torrent);
    let bytes_already_done: u64 = all_work.iter().filter(|w| confirmed_resumed.contains(&w.index)).map(|w| w.length as u64).sum();
    let remaining_work: Vec<_> = all_work.into_iter().filter(|w| !confirmed_resumed.contains(&w.index)).collect();
    let queue = Arc::new(WorkQueue::new(remaining_work, total_pieces));

    let mut pool = PeerPool::new();
    pool.add(bootstrap_peers);

    let uploaded = || seeder_handle.as_ref().map(|s| s.uploaded.load(Ordering::Relaxed)).unwrap_or(0);
    let mut bytes_downloaded_this_run: u64 = 0;

    // First real announce, now that we know the true size.
    let mut reannounce_wait = DEFAULT_REANNOUNCE;
    if !tracker_urls.is_empty() {
        let totals = TransferTotals { uploaded: uploaded(), downloaded: 0, left: total_length.saturating_sub(bytes_already_done) };
        let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, Some(Event::Started));
        let (peers, failures, interval) = announce_to_all(&tracker_urls, &req);
        if !quiet {
            for f in &failures {
                eprintln!("warning: tracker {} failed: {}", f.url, f.error);
            }
        }
        if let Some(secs) = interval {
            reannounce_wait = Duration::from_secs(secs as u64).max(MIN_REANNOUNCE);
        }
        pool.add(peers);
    }
    if let Some(secs) = args.reannounce_override {
        reannounce_wait = Duration::from_secs(secs).max(MIN_REANNOUNCE);
    }

    if pool.known.is_empty() && dht_service.is_none() {
        return Err("no peers found from any tracker (and DHT is disabled)".to_string());
    }
    if !quiet {
        println!("found {} peer(s); dialing up to {} concurrently", pool.known.len(), args.max_peers);
        println!("re-announce interval: {}s{}", reannounce_wait.as_secs(), if args.reannounce_override.is_some() { " (overridden via --reannounce)" } else { "" });
    }

    let (tx, rx) = mpsc::channel();
    let (pex_tx, pex_rx): (PexSender, Receiver<Vec<SocketAddr>>) = mpsc::channel();
    let config = Arc::new(WorkerConfig { info_hash: torrent.info_hash, our_peer_id, pipeline_depth: PIPELINE_DEPTH, connect_timeout: CONNECT_TIMEOUT });

    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut verified = confirmed_resumed.len();
    let run_start = Instant::now();
    let mut last_announce = Instant::now();
    let mut last_heartbeat = Instant::now();
    let mut last_progress_summary = Instant::now();
    let mut fruitless_rounds = 0u32;
    let mut fresh_since_announce = 0usize;
    let mut endgame_announced = false;

    macro_rules! spawn_up_to_cap {
        () => {
            while handles.len() < args.max_peers && !queue.is_empty() {
                let Some(addr) = pool.next_to_dial() else { break };
                if args.verbosity == Verbosity::Verbose {
                    println!("connecting to peer {}...", addr);
                }
                let queue = Arc::clone(&queue);
                let spans = Arc::clone(&spans);
                let config = Arc::clone(&config);
                let tx = tx.clone();
                let pex_tx = pex_tx.clone();
                let verbosity = args.verbosity;
                handles.push(thread::spawn(move || {
                    if let Err(e) = run_worker(addr, &config, &queue, &spans, piece_length, &tx, Some(&pex_tx)) {
                        if verbosity != Verbosity::Quiet {
                            eprintln!("peer {} disconnected: {:?}", addr, e);
                        }
                    }
                }));
            }
        };
    }

    spawn_up_to_cap!();

    loop {
        if let Some(timeout) = args.timeout {
            if run_start.elapsed() >= timeout {
                eprintln!("warning: --timeout of {}s reached with {} piece(s) still remaining", timeout.as_secs(), queue.len());
                break;
            }
        }

        match rx.recv_timeout(POLL_TICK) {
            Ok(result) => {
                verified += 1;
                bytes_downloaded_this_run += result.data.len() as u64;
                have.set(result.index);
                if let Err(e) = resume_writer.record(result.index) {
                    // A failed resume-write doesn't invalidate the piece
                    // itself (already verified and on disk) -- just means
                    // a future run might needlessly re-download it. Not
                    // worth aborting an otherwise-healthy download over.
                    eprintln!("warning: failed to record resume progress for piece {}: {}", result.index, e);
                }
                if !quiet {
                    println!("piece {} verified ({}/{})", result.index, verified, total_pieces);
                }
                last_heartbeat = Instant::now(); // a real download event counts as activity too
                continue;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // unreachable while we hold tx, but don't hang if it happens
        }

        if queue.is_empty() {
            break;
        }

        handles.retain(|h| !h.is_finished());

        // Passive discovery feeds: PEX pushes from connected peers, DHT
        // lookups from the service thread. Both go straight into the
        // dial queue.
        let pex_fresh: usize = pex_rx.try_iter().map(|batch| pool.add(batch)).sum();
        if pex_fresh > 0 && args.verbosity == Verbosity::Verbose {
            println!("PEX: {} new peer address(es) from connected peers", pex_fresh);
        }
        fresh_since_announce += pex_fresh;
        if let Some(dht) = &dht_service {
            let dht_fresh: usize = dht.peers_rx.try_iter().map(|batch| pool.add(batch)).sum();
            if dht_fresh > 0 && !quiet {
                println!("DHT: {} new peer address(es)", dht_fresh);
            }
            fresh_since_announce += dht_fresh;
        }

        spawn_up_to_cap!();

        if !endgame_announced && queue.in_endgame() {
            endgame_announced = true;
            if !quiet {
                println!("endgame: {} piece(s) left in flight, requesting duplicates from every capable peer", queue.len());
            }
        }

        if !quiet && last_progress_summary.elapsed() >= PROGRESS_SUMMARY_INTERVAL && bytes_downloaded_this_run > 0 {
            let elapsed = run_start.elapsed().as_secs_f64().max(0.001);
            let rate = bytes_downloaded_this_run as f64 / elapsed;
            let done = bytes_already_done + bytes_downloaded_this_run;
            let remaining_bytes = total_length.saturating_sub(done);
            print!("progress: {} ", format_bytes(done));
            print!("/ {} ", format_bytes(total_length));
            print!("({:.1}%), {}/s down, {} uploaded", 100.0 * done as f64 / total_length.max(1) as f64, format_bytes(rate as u64), format_bytes(uploaded()));
            if rate > 0.0 {
                println!(", ETA {}", format_duration(Duration::from_secs_f64(remaining_bytes as f64 / rate)));
            } else {
                println!();
            }
            last_progress_summary = Instant::now();
        }

        // When every worker is dead AND nothing is left to dial, honoring
        // a 30-minute tracker interval would mean 30 minutes of certain
        // nothing; trackers accept a floor-respecting early re-announce
        // when a client's peer supply collapses.
        let starved = handles.is_empty() && pool.reserve_is_empty();
        let effective_wait = if starved { MIN_REANNOUNCE } else { reannounce_wait };

        if last_announce.elapsed() < effective_wait {
            // Waiting is normal (honoring the tracker's interval), but
            // waiting *silently* looks identical to hung from a terminal.
            // Print a heartbeat periodically so it's visibly still alive.
            if !quiet && last_heartbeat.elapsed() >= Duration::from_secs(15) {
                let remaining = effective_wait.saturating_sub(last_announce.elapsed()).as_secs();
                println!(
                    "waiting: {} active connection(s), {} undialed peer(s), {} piece(s) remaining, next re-announce in {}s",
                    handles.len(),
                    pool.reserve.len(),
                    queue.len(),
                    remaining
                );
                last_heartbeat = Instant::now();
            }
            continue;
        }
        last_announce = Instant::now();

        if !tracker_urls.is_empty() {
            if !quiet {
                println!("{} piece(s) remaining, re-announcing to trackers...", queue.len());
            }
            let totals = TransferTotals { uploaded: uploaded(), downloaded: bytes_downloaded_this_run, left: total_length.saturating_sub(bytes_already_done + bytes_downloaded_this_run) };
            let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, None);
            let (peers, failures, interval) = announce_to_all(&tracker_urls, &req);
            if !quiet {
                for f in &failures {
                    eprintln!("warning: tracker {} failed: {}", f.url, f.error);
                }
            }
            if args.reannounce_override.is_none() {
                if let Some(secs) = interval {
                    reannounce_wait = Duration::from_secs(secs as u64).max(MIN_REANNOUNCE);
                }
            }
            fresh_since_announce += pool.add(peers);
        }

        spawn_up_to_cap!();

        // A round is fruitless only if EVERY source came up empty for the
        // whole interval and nothing is running -- one PEX/DHT address is
        // enough to keep hope (and the loop) alive.
        if fresh_since_announce == 0 && handles.is_empty() && pool.reserve_is_empty() {
            fruitless_rounds += 1;
            if !quiet {
                println!("no new peers from any source ({}/{} fruitless rounds)", fruitless_rounds, MAX_FRUITLESS_ROUNDS);
            }
            if fruitless_rounds >= MAX_FRUITLESS_ROUNDS {
                break;
            }
        } else {
            fruitless_rounds = 0;
        }
        fresh_since_announce = 0;
    }

    drop(tx);
    drop(pex_tx);
    for h in handles {
        let _ = h.join();
    }
    // Workers may have verified pieces between our last channel read and
    // their exit -- drain them so the resume file and counters don't
    // silently lose the tail.
    for result in rx.try_iter() {
        verified += 1;
        bytes_downloaded_this_run += result.data.len() as u64;
        have.set(result.index);
        let _ = resume_writer.record(result.index);
        if !quiet {
            println!("piece {} verified ({}/{})", result.index, verified, total_pieces);
        }
    }

    let outcome = if queue.is_empty() {
        // Nothing left to resume -- drop the sidecar file so a future
        // unrelated run in the same output directory never sees it.
        bittorrent_rs::downloader::resume::clear(&progress_path);
        println!("download complete: {} -> {}", torrent.name, base_dir.display());

        if !tracker_urls.is_empty() && bytes_downloaded_this_run > 0 {
            // BEP 3: `completed` fires when a download actually finishes
            // (not when starting an already-complete torrent).
            let totals = TransferTotals { uploaded: uploaded(), downloaded: bytes_downloaded_this_run, left: 0 };
            let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, Some(Event::Completed));
            let _ = announce_to_all(&tracker_urls, &req);
        }

        if args.seed && seeder_handle.is_some() {
            seed_forever(&torrent, our_peer_id, &tracker_urls, announce_port, reannounce_wait, &uploaded, bytes_downloaded_this_run, quiet);
            // unreachable (seed_forever loops until the process is killed)
        }
        Ok(())
    } else {
        Err(format!(
            "incomplete: {} piece(s) never downloaded ({} peer(s) dialed across {} fruitless final round(s)) -- rerun the same command to resume",
            queue.len(),
            pool.dialed(),
            fruitless_rounds
        ))
    };

    if let Some(s) = seeder_handle.as_mut() {
        s.stop();
    }
    if let Some(d) = dht_service.as_mut() {
        d.stop();
    }
    outcome
}

/// Post-completion seeding: keep the listener and DHT alive, re-announce
/// with `left = 0` on the tracker interval, report upload totals. Runs
/// until the process is killed (Ctrl-C) -- the OS tears down threads and
/// sockets; there is no state that needs a clean shutdown (the resume
/// sidecar is already gone, uploads are stateless).
#[allow(clippy::too_many_arguments)]
fn seed_forever(
    torrent: &TorrentFile,
    our_peer_id: [u8; 20],
    tracker_urls: &[String],
    announce_port: u16,
    reannounce_wait: Duration,
    uploaded: &dyn Fn() -> u64,
    downloaded_this_run: u64,
    quiet: bool,
) -> ! {
    println!("seeding {} on port {} -- Ctrl-C to stop", torrent.name, announce_port);
    let mut last_report = 0u64;
    loop {
        thread::sleep(reannounce_wait.max(MIN_REANNOUNCE));
        if !tracker_urls.is_empty() {
            let totals = TransferTotals { uploaded: uploaded(), downloaded: downloaded_this_run, left: 0 };
            let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, None);
            let _ = announce_to_all(tracker_urls, &req);
        }
        let up = uploaded();
        if !quiet && up != last_report {
            println!("seeding: {} uploaded so far", format_bytes(up));
            last_report = up;
        }
    }
}

fn start_dht(args: &Args, info_hash: [u8; 20], announce_port: &Arc<AtomicU16>, quiet: bool) -> Option<dht::DhtService> {
    if args.no_dht {
        return None;
    }
    match dht::spawn_service(args.port, dht::DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()).collect(), info_hash, Arc::clone(announce_port)) {
        Ok(service) => {
            if !quiet {
                println!("DHT node running on UDP port {}", service.port);
            }
            Some(service)
        }
        Err(e) => {
            eprintln!("warning: DHT disabled (couldn't bind UDP socket): {}", e);
            None
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{}{}", bytes, UNITS[0])
    } else {
        format!("{:.1}{}", size, UNITS[unit])
    }
}

fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{}h{}m", h, m)
    } else if m > 0 {
        format!("{}m{}s", m, s)
    } else {
        format!("{}s", s)
    }
}

/// Bootstraps a magnet link into a full `TorrentFile`: gathers peer
/// addresses from the magnet's trackers and (concurrently) the DHT, then
/// asks peers in turn for the info dict (BEP 9) until one delivers a
/// copy that SHA-1-verifies against the magnet's InfoHash. Returns the
/// torrent plus every peer address gathered along the way (they seed the
/// download phase's dial queue).
fn resolve_magnet(
    magnet: &bittorrent_rs::magnet::MagnetLink,
    our_peer_id: [u8; 20],
    verbosity: Verbosity,
    announce_port: u16,
    dht_peers: Option<&Receiver<Vec<SocketAddr>>>,
) -> Result<(TorrentFile, Vec<SocketAddr>), String> {
    let quiet = verbosity == Verbosity::Quiet;
    if !quiet {
        if let Some(name) = &magnet.display_name {
            println!("magnet: {}", name);
        }
    }

    let mut known: HashSet<SocketAddr> = HashSet::new();
    let mut untried: VecDeque<SocketAddr> = VecDeque::new();

    if !magnet.trackers.is_empty() {
        if !quiet {
            println!("querying {} tracker(s) to bootstrap peer list...", magnet.trackers.len());
        }
        // `left = 1` placeholder: the true size is unknown until the
        // metadata arrives, and trackers only care that it's nonzero.
        let bootstrap_req = build_request(magnet.info_hash, our_peer_id, announce_port, TransferTotals { uploaded: 0, downloaded: 0, left: 1 }, Some(Event::Started));
        let (peers, failures, _interval) = announce_to_all(&magnet.trackers, &bootstrap_req);
        if !quiet {
            for f in &failures {
                eprintln!("warning: tracker {} failed: {}", f.url, f.error);
            }
        }
        for p in peers {
            if known.insert(p) {
                untried.push_back(p);
            }
        }
    } else if !quiet {
        println!("magnet link has no trackers; waiting on DHT for peers...");
    }

    let deadline = Instant::now() + METADATA_RESOLVE_BUDGET;
    let mut attempt = 0usize;
    let mut last_err = String::from("no peer source produced any address");

    loop {
        while let Some(peer) = untried.pop_front() {
            attempt += 1;
            if !quiet {
                println!("  requesting metadata (BEP 9), attempt {} ({} known peer(s)): {}...", attempt, known.len(), peer);
            }
            match fetch_metadata_from_peer(peer, magnet.info_hash, our_peer_id, CONNECT_TIMEOUT) {
                Ok(raw_info) => {
                    if !quiet {
                        println!("metadata received and verified against magnet InfoHash");
                    }
                    let announce = magnet.trackers.first().cloned();
                    let announce_list = vec![magnet.trackers.clone()];
                    let torrent = torrent::from_info_dict_bytes(&raw_info, magnet.info_hash, announce, announce_list).map_err(|e| format!("building torrent from metadata: {}", e))?;
                    // Everything gathered (tried or not) seeds the
                    // download phase; dead ones cost one failed dial.
                    return Ok((torrent, known.into_iter().collect()));
                }
                Err(e) => {
                    if !quiet {
                        println!("  peer {} couldn't provide metadata: {}", peer, e);
                    }
                    last_err = e.to_string();
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("metadata resolution budget ({}s) exhausted after {} attempt(s) (last error: {})", METADATA_RESOLVE_BUDGET.as_secs(), attempt, last_err));
            }
            // Fold in whatever the DHT found while we were dialing.
            if let Some(rx) = dht_peers {
                for batch in rx.try_iter() {
                    for p in batch {
                        if known.insert(p) {
                            untried.push_back(p);
                        }
                    }
                }
            }
        }

        // Out of addresses. Block on the DHT (the only replenishing
        // source at this stage) until the budget runs out.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Some(rx) = dht_peers else { break };
        if !quiet {
            println!("  no untried peers; waiting on DHT (up to {}s left)...", remaining.as_secs());
        }
        match rx.recv_timeout(remaining.min(Duration::from_secs(15))) {
            Ok(batch) => {
                for p in batch {
                    if known.insert(p) {
                        untried.push_back(p);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue, // re-check deadline
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    Err(format!("no peer among {} would provide metadata (last error: {})", known.len(), last_err))
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
