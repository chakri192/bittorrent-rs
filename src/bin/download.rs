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
//! The orchestration runs on a background thread and publishes to a live
//! `tui` dashboard (or plain status lines when stdout isn't a TTY);
//! high-volume detail goes to a log file. Usage:
//!   download <file.torrent | magnet:?xt=urn:btih:...> [options]

use bittorrent_rs::config::Config;
use bittorrent_rs::dht;
use bittorrent_rs::downloader::{build_file_spans, load_and_verify, progress_file_path, rewrite_compact, run_worker, PexSender, ResumeWriter, WorkQueue, WorkerConfig};
use bittorrent_rs::magnet::{parse_magnet_uri, MagnetLink};
use bittorrent_rs::magnet_fetch::fetch_metadata_from_peer;
use bittorrent_rs::seeder::{self, HaveMap};
use bittorrent_rs::session::{DownloadPlan, Outstanding, PeerPool, Progress, RateSampler, Services};
use bittorrent_rs::torrent::{self, TorrentFile};
use bittorrent_rs::tracker::{generate_peer_id, Event};
use bittorrent_rs::tracker_discovery::{announce_to_all, build_request, TransferTotals};
use bittorrent_rs::tui::{self, Ui};
use bittorrent_rs::ui::{self, Logger, Snapshot};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::IsTerminal;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Conventional BitTorrent port: preferred TCP listen port for the
/// seeder and UDP bind for the DHT node (both fall back to ephemeral if
/// taken). Trackers and DHT announces carry whatever port was bound.
const DEFAULT_PORT: u16 = 6881;
const DEFAULT_MAX_PEERS: usize = 30;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PIPELINE_DEPTH: usize = 5;
/// Floor on re-announce spacing regardless of what a tracker requests,
/// and the fast-path wait when the dial queue runs completely dry.
const MIN_REANNOUNCE: Duration = Duration::from_secs(30);
const DEFAULT_REANNOUNCE: Duration = Duration::from_secs(120);
/// Main-loop cadence: also the dashboard refresh interval.
const UI_TICK: Duration = Duration::from_millis(250);
/// Give up only after this many consecutive re-announce rounds where NO
/// discovery source produced a single new address *and* nothing is
/// running -- bounds "retry forever" against a genuinely dead swarm.
const MAX_FRUITLESS_ROUNDS: u32 = 5;
/// Budget for resolving a magnet's metadata before declaring the swarm
/// unreachable.
const METADATA_RESOLVE_BUDGET: Duration = Duration::from_secs(120);
/// Concurrent BEP 9 metadata probes -- thin swarms are mostly dead peers,
/// so probing many at once is the difference between resolving in seconds
/// and blowing the budget on a handful of timeouts.
const METADATA_PARALLELISM: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

/// Whether to dial IPv6 peers. `Auto` probes for a local IPv6 route once
/// at startup and enables v6 only if one exists -- dialing v6 addresses
/// on a v4-only host just burns connect timeouts on guaranteed
/// `NetworkUnreachable`/`HostUnreachable` failures (the dominant failure
/// mode observed in the wild).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6Mode {
    Auto,
    Always,
    Never,
}

/// Probes for outbound IPv6 connectivity without sending a single packet:
/// a UDP `connect` only resolves a route and fixes the default
/// destination. No route (v4-only host) fails immediately with
/// `NetworkUnreachable`, so this is a cheap, side-effect-free egress test.
fn has_ipv6_egress() -> bool {
    match UdpSocket::bind("[::]:0") {
        // 2001:4860:4860::8888 is a well-known global v6 address (Google
        // DNS); we never talk to it, only ask the kernel if it's routable.
        Ok(sock) => sock.connect("[2001:4860:4860::8888]:53").is_ok(),
        Err(_) => false,
    }
}

struct Args {
    source: String,
    out_dir: PathBuf,
    max_peers: usize,
    reannounce_override: Option<u64>,
    verbosity: Verbosity,
    timeout: Option<Duration>,
    port: u16,
    seed: bool,
    no_dht: bool,
    no_portmap: bool,
    no_webseed: bool,
    ipv6: Ipv6Mode,
    /// Case-insensitive path substrings selecting which files to download.
    only: Vec<String>,
    /// 1-based file indices selecting which files to download.
    files_sel: Vec<usize>,
    /// Print the torrent's file list (with selection marks) and exit.
    list: bool,
    /// Explicit log path; `None` uses `<out_dir>/bittorrent-rs.log`.
    log: Option<PathBuf>,
    no_log: bool,
    /// Force the plain (non-dashboard) interface even on a TTY.
    no_tui: bool,
}

/// Scans argv for `--config PATH` / `--no-config` and loads the config
/// (or defaults) before the main parse, so config values can seed the
/// flag defaults. The chosen path is honored again as a no-op in the main
/// parse loop.
fn load_config_from_args() -> Result<Config, String> {
    let mut argv = std::env::args().skip(1);
    let mut explicit: Option<PathBuf> = None;
    let mut disabled = false;
    while let Some(a) = argv.next() {
        match a.as_str() {
            "--no-config" => disabled = true,
            "--config" => explicit = Some(PathBuf::from(argv.next().ok_or("--config requires a path")?)),
            _ => {}
        }
    }
    if disabled {
        return Ok(Config::default());
    }
    match explicit.or_else(Config::default_path) {
        Some(path) => Config::load_optional(&path),
        None => Ok(Config::default()),
    }
}

fn parse_args(cfg: &Config) -> Result<Args, String> {
    let mut argv = std::env::args().skip(1);
    let source = argv.next().ok_or_else(usage)?;
    if source == "--help" || source == "-h" {
        return Err(usage());
    }

    // Defaults come from the config file (if any), then built-ins; CLI
    // flags below override both.
    let mut out_dir = cfg.out.clone().unwrap_or_else(default_downloads_dir);
    let mut max_peers = cfg.peers.filter(|&n| n > 0).unwrap_or(DEFAULT_MAX_PEERS);
    let mut reannounce_override = cfg.reannounce;
    let mut verbosity = Verbosity::Normal;
    let mut timeout = None;
    let mut port = cfg.port.unwrap_or(DEFAULT_PORT);
    let mut seed = cfg.seed.unwrap_or(false);
    let mut no_dht = !cfg.dht.unwrap_or(true);
    let mut no_portmap = !cfg.portmap.unwrap_or(true);
    let mut no_webseed = !cfg.webseed.unwrap_or(true);
    let mut ipv6 = match cfg.ipv6.as_deref() {
        Some("always") => Ipv6Mode::Always,
        Some("never") => Ipv6Mode::Never,
        _ => Ipv6Mode::Auto,
    };
    let mut only: Vec<String> = Vec::new();
    let mut files_sel: Vec<usize> = Vec::new();
    let mut list = false;
    let mut log = cfg.log.clone();
    let mut no_log = false;
    let mut no_tui = !cfg.tui.unwrap_or(true);

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
            "--log" => log = Some(PathBuf::from(argv.next().ok_or("--log requires a file path")?)),
            "--no-log" => no_log = true,
            "--no-tui" => no_tui = true,
            "--seed" => seed = true,
            "--no-seed" => seed = false,
            "--no-dht" => no_dht = true,
            "--dht" => no_dht = false,
            "--no-portmap" => no_portmap = true,
            "--portmap" => no_portmap = false,
            "--no-webseed" => no_webseed = true,
            "--webseed" => no_webseed = false,
            "--tui" => no_tui = false,
            // Consumed in the pre-scan (`load_config_from_args`); accepted
            // here so they aren't flagged as unrecognized.
            "--no-config" => {}
            "--config" => {
                argv.next();
            }
            "--ipv6" => ipv6 = Ipv6Mode::Always,
            "--no-ipv6" => ipv6 = Ipv6Mode::Never,
            "--only" => only.push(argv.next().ok_or("--only requires a path substring")?),
            "--files" => {
                let list_arg = argv.next().ok_or("--files requires a comma-separated list of 1-based indices")?;
                for part in list_arg.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    files_sel.push(part.parse().map_err(|_| format!("--files: not a number: {}", part))?);
                }
            }
            "--list" => list = true,
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

    Ok(Args { source, out_dir, max_peers, reannounce_override, verbosity, timeout, port, seed, no_dht, no_portmap, no_webseed, ipv6, only, files_sel, list, log, no_log, no_tui })
}

fn usage() -> String {
    "usage: download <file.torrent | magnet:?xt=urn:btih:...> [--out DIR] [--peers N] [--port PORT] [--seed | --no-seed] [--dht | --no-dht] [--portmap | --no-portmap] [--webseed | --no-webseed] [--ipv6 | --no-ipv6] [--only SUBSTR]... [--files 1,3,5] [--list] [--reannounce SECONDS] [--timeout SECONDS] [--config FILE | --no-config] [--log FILE | --no-log] [--tui | --no-tui] [--quiet | --verbose]".to_string()
}

fn default_downloads_dir() -> PathBuf {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Downloads")).unwrap_or_else(|| PathBuf::from("downloads"))
}

fn main() -> ExitCode {
    let cfg = match load_config_from_args() {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{}", msg);
            return ExitCode::FAILURE;
        }
    };
    let args = match parse_args(&cfg) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{}", msg);
            return ExitCode::FAILURE;
        }
    };

    let quiet = args.verbosity == Verbosity::Quiet;
    let _ = fs::create_dir_all(&args.out_dir);

    // Logger first, so the orchestration thread can log from its very
    // first line. A logfile open failure is a warning, never fatal.
    let (log, log_path_display) = if args.no_log {
        (Logger::disabled(), None)
    } else {
        let path = args.log.clone().unwrap_or_else(|| args.out_dir.join("bittorrent-rs.log"));
        match Logger::to_file(&path) {
            Ok(l) => (l, Some(path.display().to_string())),
            Err(e) => {
                eprintln!("warning: could not open log file {}: {} (continuing without a log)", path.display(), e);
                (Logger::disabled(), None)
            }
        }
    };

    let ui = Ui::new("starting\u{2026}", args.out_dir.display().to_string(), log);
    ui.set_log_path(log_path_display);

    // `--list` is a quick print-and-exit; never spin up the dashboard for it.
    let interactive = !quiet && !args.no_tui && !args.list && std::io::stdout().is_terminal();
    let stop = Arc::new(AtomicBool::new(false));

    let orchestration = {
        let ui = ui.clone();
        let stop = Arc::clone(&stop);
        thread::spawn(move || orchestrate(args, &ui, &stop))
    };

    let shared = ui.shared();
    let user_quit = if quiet {
        tui::run_silent(&shared, &stop)
    } else if interactive {
        tui::run(&shared, &stop)
    } else {
        tui::run_plain(&shared, &stop)
    };
    stop.store(true, Ordering::SeqCst);

    let result = orchestration.join().unwrap_or_else(|_| Err("download thread panicked".to_string()));

    if user_quit {
        if !quiet {
            println!("stopped \u{2014} rerun the same command to resume.");
        }
        return ExitCode::SUCCESS;
    }
    match result {
        Ok(summary) => {
            if !quiet {
                println!("{}", summary);
            }
            ExitCode::SUCCESS
        }
        // Errors always print, even under --quiet.
        Err(reason) => {
            eprintln!("error: {}", reason);
            ExitCode::FAILURE
        }
    }
}

/// The whole download, start to finish, publishing to `ui`. Returns a
/// human-readable completion summary (`Ok`) or a failure reason (`Err`);
/// either way it also calls `ui.finish` so the dashboard can wind down
/// (except in `--seed` mode, which keeps the UI live until the user
/// quits via `stop`).
fn orchestrate(args: Args, ui: &Ui, stop: &AtomicBool) -> Result<String, String> {
    let our_peer_id = generate_peer_id();

    // Dropping `services` (including on any early `return Err`) stops the
    // DHT, the listener and the port mapping.
    let mut services = Services::new();

    let (torrent, bootstrap_peers) = if args.source.starts_with("magnet:?") {
        let magnet = parse_magnet_uri(&args.source).map_err(|e| finish_err(ui, format!("parsing magnet uri: {}", e)))?;
        if !args.no_dht {
            services.start_dht(args.port, magnet.info_hash, |m| ui.log(m));
        }
        if magnet.trackers.is_empty() && services.dht().is_none() {
            return Err(finish_err(ui, "magnet link has no trackers and DHT is disabled (--no-dht) -- no way to find any peer".to_string()));
        }
        let (torrent, peers) = resolve_magnet(&magnet, our_peer_id, args.port, services.dht(), ui, stop)?;
        // The DHT had to run to fetch the metadata, since a magnet link
        // doesn't say whether the torrent is private until the info dict
        // arrives. Now that it has, shut the DHT down: no lookups, no
        // announces, no answering queries for a private info-hash.
        if torrent.private {
            services.stop_dht();
        }
        (torrent, peers)
    } else {
        let bytes = fs::read(&args.source).map_err(|e| finish_err(ui, format!("reading {}: {}", args.source, e)))?;
        let torrent = torrent::parse_torrent_file(&bytes).map_err(|e| finish_err(ui, format!("parsing {}: {}", args.source, e)))?;
        // A `.torrent` already carries the file list, so `--list` needs no
        // network at all.
        if !args.no_dht && !args.list && !torrent.private {
            services.start_dht(args.port, torrent.info_hash, |m| ui.log(m));
        }
        (torrent, Vec::new())
    };
    if torrent.private && !args.list {
        ui.log("private torrent (BEP 27): DHT and peer exchange disabled, peers come from the tracker only");
    }

    ui.set_title(torrent.name.clone());
    ui.log(format!("torrent: {} ({}, {} pieces)", torrent.name, ui::format_bytes(torrent.total_length()), torrent.pieces.len()));

    let total_pieces = torrent.pieces.len();
    let total_length = torrent.total_length();
    let piece_length = torrent.piece_length as u64;

    // File selection (--only / --files). `--list` prints the file table
    // and exits without downloading anything.
    let mask = bittorrent_rs::selection::build_mask(&torrent.files, &args.files_sel, &args.only).map_err(|e| finish_err(ui, e))?;
    if args.list {
        let listing = bittorrent_rs::selection::format_list(&torrent.name, &torrent.files, &mask);
        services.shutdown();
        ui.finish(Ok(listing.clone()));
        return Ok(listing);
    }
    // `display_total` / `goal_pieces` drive the progress UI for the
    // selected subset. The *true* torrent length still governs on-disk
    // piece math (spans, seeder), so those stay `total_length`.
    let plan = DownloadPlan::new(&torrent, &mask);
    let (selective, display_total, goal_pieces) = (plan.is_selective(), plan.display_total(), plan.goal_pieces());
    if selective {
        ui.log(format!("selective download: {} of {} file(s), {} piece(s), {}", mask.iter().filter(|&&b| b).count(), torrent.files.len(), goal_pieces, ui::format_bytes(display_total)));
    }

    let tracker_urls = collect_tracker_urls(&torrent);
    let base_dir = if torrent.files.len() > 1 { args.out_dir.join(&torrent.name) } else { args.out_dir.clone() };
    let spans = Arc::new(build_file_spans(&base_dir, &torrent.files));

    // Resume: re-verify any pieces a previous run claimed complete against
    // their actual current bytes on disk before trusting them.
    fs::create_dir_all(&args.out_dir).map_err(|e| finish_err(ui, format!("creating output directory {}: {}", args.out_dir.display(), e)))?;
    let progress_path = progress_file_path(&args.out_dir, &torrent.info_hash);
    let confirmed_resumed = load_and_verify(&progress_path, &spans, &torrent);
    if !confirmed_resumed.is_empty() {
        ui.log(format!("resuming: {} piece(s) already verified on disk", confirmed_resumed.len()));
        rewrite_compact(&progress_path, &confirmed_resumed).map_err(|e| finish_err(ui, format!("writing resume file: {}", e)))?;
    }
    let resume_writer = ResumeWriter::create(&progress_path).map_err(|e| finish_err(ui, format!("opening resume file: {}", e)))?;

    // Upload side: serve verified pieces to inbound peers for the whole
    // run. A bind failure downgrades to download-only with a warning.
    let have = Arc::new(HaveMap::new(total_pieces));
    for &idx in &confirmed_resumed {
        have.set(idx);
    }
    match seeder::start(args.port, torrent.info_hash, our_peer_id, Arc::clone(&spans), piece_length, total_length, Arc::clone(&have)) {
        Ok(handle) => {
            ui.log(format!("listening for inbound peers on port {}", handle.port));
            services.attach_seeder(handle);
        }
        Err(e) => ui.log(format!("warning: could not start listener (download-only): {}", e)),
    }
    let announce_port = services.announce_port(args.port);
    // A separate handle on the upload counter, so it stays readable
    // whatever happens to the seeder itself.
    let uploaded_counter = services.uploaded_counter();
    let uploaded = || uploaded_counter.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);

    // Best-effort port forwarding (UPnP/NAT-PMP) so inbound peers and DHT
    // queries reach us behind a home router. Runs on its own thread and
    // never blocks; silently no-ops if the router doesn't cooperate.
    if !args.no_portmap {
        let logger = ui.clone();
        services.start_portmap(move |m| logger.log(m));
    }

    // Only wanted pieces enter the queue and the progress totals; already-
    // verified wanted pieces count as done from the start. (Resumed
    // *unwanted* pieces from a prior full run stay advertised for seeding
    // via `have` above, but don't count toward this run's goal.)
    let Outstanding { work, pieces_done, bytes_done: bytes_already_done } = plan.outstanding(&torrent, &confirmed_resumed);
    let queue = Arc::new(WorkQueue::new(work, total_pieces));

    let allow_ipv6 = match args.ipv6 {
        Ipv6Mode::Always => true,
        Ipv6Mode::Never => false,
        Ipv6Mode::Auto => has_ipv6_egress(),
    };
    ui.log(if allow_ipv6 {
        "IPv6 peers enabled".to_string()
    } else {
        format!("IPv6 peers disabled ({})", if args.ipv6 == Ipv6Mode::Never { "--no-ipv6" } else { "no local IPv6 route" })
    });
    let mut pool = PeerPool::new(allow_ipv6);
    pool.add(bootstrap_peers);

    let mut trackers_ok = 0usize;
    let mut pex_total = 0usize;

    // First real announce, now that the true size is known.
    let mut reannounce_wait = DEFAULT_REANNOUNCE;
    if !tracker_urls.is_empty() {
        let totals = TransferTotals { uploaded: uploaded(), downloaded: 0, left: display_total.saturating_sub(bytes_already_done) };
        let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, Some(Event::Started));
        let (peers, failures, interval) = announce_to_all(&tracker_urls, &req);
        trackers_ok = tracker_urls.len().saturating_sub(failures.len());
        for f in &failures {
            ui.log(format!("tracker {} failed: {}", f.url, f.error));
        }
        if let Some(secs) = interval {
            reannounce_wait = Duration::from_secs(secs as u64).max(MIN_REANNOUNCE);
        }
        pool.add(peers);
    }
    if let Some(secs) = args.reannounce_override {
        reannounce_wait = Duration::from_secs(secs).max(MIN_REANNOUNCE);
    }

    // BEP 19 web seeds (from the torrent's url-list). These can carry the
    // whole download even with zero peers, so their presence keeps the run
    // alive below.
    let web_seeds: Vec<String> = if args.no_webseed { Vec::new() } else { torrent.url_list.clone() };

    if pool.known_count() == 0 && services.dht().is_none() && web_seeds.is_empty() {
        return Err(finish_err(ui, "no peers found from any tracker (and DHT + web seeds unavailable)".to_string()));
    }
    ui.log(format!("{} peer(s) known; dialing up to {} concurrently", pool.known_count(), args.max_peers));
    if pool.skipped_ipv6() > 0 {
        ui.log(format!("skipped {} IPv6 peer(s) with no local route (pass --ipv6 to force)", pool.skipped_ipv6()));
    }

    let private = torrent.private;
    let (tx, rx) = mpsc::channel();
    let (pex_tx, pex_rx): (PexSender, mpsc::Receiver<Vec<SocketAddr>>) = mpsc::channel();
    let config = Arc::new(WorkerConfig { info_hash: torrent.info_hash, our_peer_id, pipeline_depth: PIPELINE_DEPTH, connect_timeout: CONNECT_TIMEOUT });

    // Web-seed workers: one thread per url-list entry, draining the same
    // shared queue into the same verify-write-record pipeline as peers.
    let web_stop = Arc::new(AtomicBool::new(false));
    let mut web_handles: Vec<thread::JoinHandle<()>> = Vec::new();
    if !web_seeds.is_empty() {
        ui.log(format!("web seed: {} url(s) from the torrent's url-list", web_seeds.len()));
        let files_arc = Arc::new(torrent.files.clone());
        for url in &web_seeds {
            let url = url.clone();
            let name = torrent.name.clone();
            let files = Arc::clone(&files_arc);
            let queue = Arc::clone(&queue);
            let spans = Arc::clone(&spans);
            let tx = tx.clone();
            let web_stop = Arc::clone(&web_stop);
            let ui2 = ui.clone();
            web_handles.push(thread::spawn(move || {
                bittorrent_rs::webseed::run_web_worker(&url, &name, &files, &queue, &spans, piece_length, total_length, &tx, &web_stop, move |m| ui2.log(m));
            }));
        }
    }

    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut progress = Progress::new(Arc::clone(&have), resume_writer, goal_pieces, pieces_done, bytes_already_done);
    let run_start = Instant::now();
    let mut last_announce = Instant::now();
    let mut fruitless_rounds = 0u32;
    let mut fresh_since_announce = 0usize;
    let mut endgame_announced = false;

    // Rate sampling / smoothing for the dashboard. Resumed bytes are the
    // baseline, so they don't read as a burst of throughput.
    let mut rates = RateSampler::new(Instant::now(), bytes_already_done, uploaded());

    macro_rules! spawn_up_to_cap {
        () => {
            while handles.len() < args.max_peers && !queue.is_empty() {
                let Some(addr) = pool.next_to_dial() else { break };
                let queue = Arc::clone(&queue);
                let spans = Arc::clone(&spans);
                let config = Arc::clone(&config);
                let tx = tx.clone();
                // No PEX channel for private torrents (BEP 27): the worker
                // then neither advertises ut_pex nor forwards what it hears.
                let pex_tx = (!private).then(|| pex_tx.clone());
                let ui2 = ui.clone();
                handles.push(thread::spawn(move || {
                    if let Err(e) = run_worker(addr, &config, &queue, &spans, piece_length, &tx, pex_tx.as_ref()) {
                        ui2.log(format!("peer {} disconnected: {:?}", addr, e));
                    }
                }));
            }
        };
    }

    macro_rules! publish_snapshot {
        () => {{
            let done = progress.bytes_done();
            if rates.sample(Instant::now(), done, uploaded()) {
                ui.push_rates(rates.down_rate() as u64, rates.up_rate() as u64);
                ui.set_pieces(have.snapshot()); // drives the piece-map heatmap
            }
            let remaining = display_total.saturating_sub(done);
            let eta_secs = if rates.down_rate() > 1.0 { Some((remaining as f64 / rates.down_rate()) as u64) } else { None };
            let web_active = web_handles.iter().any(|h| !h.is_finished());
            let status = if queue.in_endgame() {
                "endgame"
            } else if progress.bytes_this_run() > 0 || web_active {
                "downloading"
            } else if handles.is_empty() && pool.reserve_is_empty() {
                "waiting"
            } else {
                "connecting"
            };
            ui.set_snapshot(Snapshot {
                total_length: display_total,
                total_pieces: goal_pieces,
                verified: progress.verified(),
                done_bytes: done,
                down_rate: rates.down_rate(),
                up_bytes: uploaded(),
                up_rate: rates.up_rate(),
                active_peers: handles.len(),
                dialed_peers: pool.dialed(),
                known_peers: pool.known_count(),
                endgame: queue.in_endgame(),
                trackers_ok,
                trackers_total: tracker_urls.len(),
                dht_nodes: services.dht().map(|d| d.nodes.load(Ordering::SeqCst)).unwrap_or(0),
                pex_total,
                web_seeds: web_handles.iter().filter(|h| !h.is_finished()).count(),
                eta_secs,
                elapsed_secs: run_start.elapsed().as_secs(),
                status,
            });
        }};
    }

    spawn_up_to_cap!();
    publish_snapshot!();

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if let Some(timeout) = args.timeout {
            if run_start.elapsed() >= timeout {
                ui.log(format!("--timeout of {}s reached with {} piece(s) remaining", timeout.as_secs(), queue.len()));
                break;
            }
        }

        match rx.recv_timeout(UI_TICK) {
            Ok(result) => progress.absorb(result, |m| ui.log(m)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if queue.is_empty() {
            break;
        }

        handles.retain(|h| !h.is_finished());

        // Passive discovery feeds -> dial queue.
        let pex_fresh: usize = pex_rx.try_iter().map(|batch| pool.add(batch)).sum();
        if pex_fresh > 0 {
            pex_total += pex_fresh;
            ui.log(format!("PEX: {} new peer address(es) from connected peers", pex_fresh));
        }
        fresh_since_announce += pex_fresh;
        if let Some(dht) = services.dht() {
            let dht_fresh: usize = dht.peers_rx.try_iter().map(|batch| pool.add(batch)).sum();
            if dht_fresh > 0 {
                ui.log(format!("DHT: {} new peer address(es)", dht_fresh));
            }
            fresh_since_announce += dht_fresh;
        }

        spawn_up_to_cap!();

        if !endgame_announced && queue.in_endgame() {
            endgame_announced = true;
            ui.log(format!("endgame: {} piece(s) left, requesting duplicates from every capable peer", queue.len()));
        }

        publish_snapshot!();

        let starved = handles.is_empty() && pool.reserve_is_empty();
        let effective_wait = if starved { MIN_REANNOUNCE } else { reannounce_wait };
        if last_announce.elapsed() < effective_wait {
            continue;
        }
        last_announce = Instant::now();

        if !tracker_urls.is_empty() {
            ui.log(format!("{} piece(s) remaining, re-announcing to trackers", queue.len()));
            let totals = TransferTotals { uploaded: uploaded(), downloaded: progress.bytes_this_run(), left: display_total.saturating_sub(progress.bytes_done()) };
            let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, None);
            let (peers, failures, interval) = announce_to_all(&tracker_urls, &req);
            trackers_ok = tracker_urls.len().saturating_sub(failures.len());
            for f in &failures {
                ui.log(format!("tracker {} failed: {}", f.url, f.error));
            }
            if args.reannounce_override.is_none() {
                if let Some(secs) = interval {
                    reannounce_wait = Duration::from_secs(secs as u64).max(MIN_REANNOUNCE);
                }
            }
            fresh_since_announce += pool.add(peers);
        }

        spawn_up_to_cap!();

        // A run isn't fruitless while a web seed is still pulling pieces --
        // it can finish the whole download with no peers at all.
        let web_active = web_handles.iter().any(|h| !h.is_finished());
        if fresh_since_announce == 0 && handles.is_empty() && pool.reserve_is_empty() && !web_active {
            fruitless_rounds += 1;
            ui.log(format!("no new peers from any source ({}/{} fruitless rounds)", fruitless_rounds, MAX_FRUITLESS_ROUNDS));
            if fruitless_rounds >= MAX_FRUITLESS_ROUNDS {
                break;
            }
        } else {
            fruitless_rounds = 0;
        }
        fresh_since_announce = 0;
    }

    web_stop.store(true, Ordering::SeqCst);
    drop(tx);
    drop(pex_tx);
    for h in handles {
        let _ = h.join();
    }
    for h in web_handles {
        let _ = h.join();
    }
    for result in rx.try_iter() {
        progress.absorb(result, |m| ui.log(m));
    }

    let complete = queue.is_empty();
    let elapsed = run_start.elapsed();
    let avg = progress.bytes_this_run() as f64 / elapsed.as_secs_f64().max(0.001);

    if complete {
        bittorrent_rs::downloader::resume::clear(&progress_path);
        let scope = if selective { format!("{} selected", ui::format_bytes(display_total)) } else { ui::format_bytes(total_length) };
        let summary = format!(
            "download complete: {} -> {}\n  {} in {} \u{b7} {} avg \u{b7} {} uploaded",
            torrent.name,
            base_dir.display(),
            scope,
            ui::format_duration(elapsed.as_secs()),
            ui::format_rate(avg),
            ui::format_bytes(uploaded()),
        );
        ui.log("download complete");

        if !tracker_urls.is_empty() && progress.bytes_this_run() > 0 {
            let totals = TransferTotals { uploaded: uploaded(), downloaded: progress.bytes_this_run(), left: 0 };
            let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, Some(Event::Completed));
            let _ = announce_to_all(&tracker_urls, &req);
        }

        if args.seed && services.has_seeder() {
            // Keep the UI live and seeding until the user quits. The UI
            // totals reflect the selected subset (display_total/goal).
            seed_loop(&torrent, our_peer_id, &tracker_urls, announce_port, reannounce_wait, uploaded_counter.clone(), display_total, goal_pieces, progress.bytes_this_run(), ui, stop);
        } else {
            ui.finish(Ok(summary.clone()));
        }

        services.shutdown();
        Ok(summary)
    } else {
        let reason = format!("incomplete: {} piece(s) never downloaded ({} peer(s) dialed) -- rerun the same command to resume", queue.len(), pool.dialed());
        services.shutdown();
        // If we're here because the user quit, don't flash a failure
        // banner -- main prints the "stopped" line.
        if !stop.load(Ordering::SeqCst) {
            ui.finish(Err(reason.clone()));
        }
        Err(reason)
    }
}

/// Convenience: record a fatal reason on the dashboard and return it so
/// the `?` operator can bubble it up as the orchestration's `Err`.
fn finish_err(ui: &Ui, reason: String) -> String {
    ui.finish(Err(reason.clone()));
    reason
}

/// Post-completion seeding: keep the listener and DHT alive, re-announce
/// with `left = 0` on the tracker interval, publish upload stats. Returns
/// when `stop` is set (user quit).
#[allow(clippy::too_many_arguments)]
fn seed_loop(
    torrent: &TorrentFile,
    our_peer_id: [u8; 20],
    tracker_urls: &[String],
    announce_port: u16,
    reannounce_wait: Duration,
    uploaded_counter: Option<Arc<AtomicU64>>,
    total_length: u64,
    total_pieces: usize,
    downloaded_this_run: u64,
    ui: &Ui,
    stop: &AtomicBool,
) {
    let uploaded = || uploaded_counter.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
    ui.log(format!("seeding {} on port {} -- press q to stop", torrent.name, announce_port));

    let mut last_announce = Instant::now();
    // Seeding downloads nothing, so the down total stays at 0.
    let mut rates = RateSampler::new(Instant::now(), 0, uploaded());

    while !stop.load(Ordering::SeqCst) {
        if rates.sample(Instant::now(), 0, uploaded()) {
            ui.push_rates(0, rates.up_rate() as u64);
        }
        ui.set_snapshot(Snapshot {
            total_length,
            total_pieces,
            verified: total_pieces,
            done_bytes: total_length,
            down_rate: 0.0,
            up_bytes: uploaded(),
            up_rate: rates.up_rate(),
            endgame: false,
            status: "seeding",
            ..Default::default()
        });

        if !tracker_urls.is_empty() && last_announce.elapsed() >= reannounce_wait.max(MIN_REANNOUNCE) {
            let totals = TransferTotals { uploaded: uploaded(), downloaded: downloaded_this_run, left: 0 };
            let req = build_request(torrent.info_hash, our_peer_id, announce_port, totals, None);
            let _ = announce_to_all(tracker_urls, &req);
            last_announce = Instant::now();
        }
        thread::sleep(UI_TICK);
    }
}

/// Bootstraps a magnet link into a full `TorrentFile`: gathers peers from
/// the magnet's trackers and the DHT, then probes them concurrently for
/// the info dict (BEP 9) until one delivers a copy that SHA-1-verifies
/// against the magnet's InfoHash. Returns the torrent plus every peer
/// address gathered (they seed the download phase's dial queue).
fn resolve_magnet(magnet: &MagnetLink, our_peer_id: [u8; 20], announce_port: u16, dht: Option<&dht::DhtService>, ui: &Ui, stop: &AtomicBool) -> Result<(TorrentFile, Vec<SocketAddr>), String> {
    if let Some(name) = &magnet.display_name {
        ui.set_title(name.clone());
    }

    let mut known: HashSet<SocketAddr> = HashSet::new();
    let untried: Arc<Mutex<VecDeque<SocketAddr>>> = Arc::new(Mutex::new(VecDeque::new()));

    if !magnet.trackers.is_empty() {
        ui.log(format!("querying {} tracker(s) to bootstrap peer list", magnet.trackers.len()));
        let bootstrap_req = build_request(magnet.info_hash, our_peer_id, announce_port, TransferTotals { uploaded: 0, downloaded: 0, left: 1 }, Some(Event::Started));
        let (peers, failures, _interval) = announce_to_all(&magnet.trackers, &bootstrap_req);
        for f in &failures {
            ui.log(format!("tracker {} failed: {}", f.url, f.error));
        }
        let mut q = untried.lock().unwrap();
        for p in peers {
            if known.insert(p) {
                q.push_back(p);
            }
        }
    } else {
        ui.log("magnet link has no trackers; waiting on the DHT for peers");
    }

    // Concurrent BEP 9 probe pool. First worker to verify metadata wins.
    let pool_stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let last_err = Arc::new(Mutex::new(String::from("no peer source produced any address")));
    let (found_tx, found_rx) = mpsc::channel::<Vec<u8>>();

    let mut workers = Vec::with_capacity(METADATA_PARALLELISM);
    for _ in 0..METADATA_PARALLELISM {
        let untried = Arc::clone(&untried);
        let pool_stop = Arc::clone(&pool_stop);
        let attempts = Arc::clone(&attempts);
        let last_err = Arc::clone(&last_err);
        let found_tx = found_tx.clone();
        let info_hash = magnet.info_hash;
        workers.push(thread::spawn(move || {
            while !pool_stop.load(Ordering::SeqCst) {
                let Some(peer) = untried.lock().unwrap().pop_front() else {
                    thread::sleep(Duration::from_millis(200));
                    continue;
                };
                attempts.fetch_add(1, Ordering::Relaxed);
                match fetch_metadata_from_peer(peer, info_hash, our_peer_id, CONNECT_TIMEOUT) {
                    Ok(raw_info) => {
                        if !pool_stop.swap(true, Ordering::SeqCst) {
                            let _ = found_tx.send(raw_info);
                        }
                        return;
                    }
                    Err(e) => *last_err.lock().unwrap() = e.to_string(),
                }
            }
        }));
    }
    drop(found_tx);

    let deadline = Instant::now() + METADATA_RESOLVE_BUDGET;
    let mut last_log = Instant::now();
    let raw_info = loop {
        if stop.load(Ordering::SeqCst) {
            break None; // user quit
        }
        if let Some(dht) = dht {
            let mut q = untried.lock().unwrap();
            for batch in dht.peers_rx.try_iter() {
                for p in batch {
                    if known.insert(p) {
                        q.push_back(p);
                    }
                }
            }
        }

        // Keep the dashboard alive during resolution.
        ui.set_snapshot(Snapshot {
            known_peers: known.len(),
            dht_nodes: dht.map(|d| d.nodes.load(Ordering::SeqCst)).unwrap_or(0),
            status: "resolving",
            ..Default::default()
        });
        if last_log.elapsed() >= Duration::from_secs(3) {
            ui.log(format!("resolving metadata: {} peer(s) probed, {} known, {}s left", attempts.load(Ordering::Relaxed), known.len(), deadline.saturating_duration_since(Instant::now()).as_secs()));
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
        Some(raw) => {
            ui.log("metadata received and verified against magnet InfoHash");
            let announce = magnet.trackers.first().cloned();
            let announce_list = vec![magnet.trackers.clone()];
            let torrent = torrent::from_info_dict_bytes(&raw, magnet.info_hash, announce, announce_list).map_err(|e| finish_err(ui, format!("building torrent from metadata: {}", e)))?;
            Ok((torrent, known.into_iter().collect()))
        }
        None => {
            let n = attempts.load(Ordering::Relaxed);
            let last = last_err.lock().unwrap().clone();
            let reason = if stop.load(Ordering::SeqCst) {
                "stopped before metadata could be resolved".to_string()
            } else if Instant::now() >= deadline {
                format!("metadata resolution budget ({}s) exhausted after {} concurrent probe(s) across {} known peer(s) (last error: {})", METADATA_RESOLVE_BUDGET.as_secs(), n, known.len(), last)
            } else {
                format!("no peer among {} would provide metadata after {} probe(s) (last error: {})", known.len(), n, last)
            };
            Err(finish_err(ui, reason))
        }
    }
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
