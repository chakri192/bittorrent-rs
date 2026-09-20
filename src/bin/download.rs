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
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

use bittorrent_rs::config::Config;
use bittorrent_rs::magnet::parse_magnet_uri;
use bittorrent_rs::session::env::{dht_bootstrap, lsd_config};
use bittorrent_rs::session::{prepare, resolve_magnet, seed_limits, Ipv6Mode, MetadataConfig, Options, ProgressSink, SeedEnd, SeedLimits, Services};
use bittorrent_rs::torrent;
use bittorrent_rs::tracker::generate_peer_id;
use bittorrent_rs::tui::{self, Ui};
use bittorrent_rs::ui::{self, Logger};
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Conventional BitTorrent port: preferred TCP listen port for the
/// seeder and UDP bind for the DHT node (both fall back to ephemeral if
/// taken). Trackers and DHT announces carry whatever port was bound.
const DEFAULT_PORT: u16 = 6881;
const DEFAULT_MAX_PEERS: usize = 30;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PIPELINE_DEPTH: usize = 5;
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

struct Args {
    source: String,
    out_dir: PathBuf,
    max_peers: usize,
    reannounce_override: Option<u64>,
    /// First delay before retrying a peer that failed.
    retry_delay: Duration,
    /// Verify every piece on disk instead of trusting the resume file.
    recheck: bool,
    /// Message stream encryption, if chosen.
    encryption: Option<bittorrent_rs::peer::Encryption>,
    /// TCP, uTP, or TCP with uTP as the second try.
    transport: bittorrent_rs::peer::TransportMode,
    /// BEP 12 tiers, or every tracker at once.
    tracker_mode: bittorrent_rs::tracker_discovery::TrackerMode,
    /// Fetch pieces in order rather than rarest first.
    sequential: bool,
    /// Case-insensitive path substrings of files to fetch first.
    prefer: Vec<String>,
    /// Where to write the torrent's `.torrent` file, if asked.
    save_torrent: Option<PathBuf>,
    /// Write status as JSON lines on stdout instead of a dashboard.
    json: bool,
    /// Check the files on disk against the torrent and exit, touching no network.
    verify: bool,
    /// Bytes per second limits on download and upload, if set.
    max_down: Option<u64>,
    max_up: Option<u64>,
    verbosity: Verbosity,
    timeout: Option<Duration>,
    port: u16,
    seed: bool,
    /// When to stop seeding on its own; unset means only when told to.
    seed_limits: SeedLimits,
    no_dht: bool,
    no_lsd: bool,
    no_portmap: bool,
    no_webseed: bool,
    /// Peers to try, given as `HOST:PORT` (`--peer`), before any tracker or the DHT has named one.
    peers_hint: Vec<std::net::SocketAddr>,
    ipv6: Ipv6Mode,
    /// Case-insensitive path substrings selecting which files to download.
    only: Vec<String>,
    /// 1-based file indices selecting which files to download.
    files_sel: Vec<usize>,
    /// Print the torrent's file list (with selection marks) and exit.
    list: bool,
    /// Ask its trackers how many seeders and leechers it has (BEP 48) and exit.
    scrape: bool,
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
    parse_args_from(cfg, std::env::args().skip(1))
}

fn parse_args_from(cfg: &Config, mut argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let source = argv.next().ok_or_else(usage)?;
    if source == "--help" || source == "-h" {
        return Err(usage());
    }

    // Defaults come from the config file (if any), then built-ins; CLI
    // flags below override both.
    let mut out_dir = cfg.out.clone().unwrap_or_else(default_downloads_dir);
    let mut max_peers = cfg.peers.filter(|&n| n > 0).unwrap_or(DEFAULT_MAX_PEERS);
    let mut reannounce_override = cfg.reannounce;
    let mut retry_delay = Duration::from_secs(15);
    let mut recheck = false;
    let mut sequential = false;
    let mut peers_hint: Vec<std::net::SocketAddr> = Vec::new();
    let mut tracker_mode = cfg.tracker_mode.as_deref().map(|t| bittorrent_rs::tracker_discovery::TrackerMode::parse(t).ok_or_else(|| format!("config tracker_mode: {:?} is not tiered or concurrent", t))).transpose()?.unwrap_or_default();
    let mut transport = cfg.transport.as_deref().map(|t| bittorrent_rs::peer::TransportMode::parse(t).ok_or_else(|| format!("config transport: {:?} is not tcp, utp or both", t))).transpose()?.unwrap_or_default();
    let mut encryption = cfg.encryption.as_deref().map(bittorrent_rs::peer::Encryption::parse).transpose().map_err(|e| format!("config encryption: {}", e))?;
    let mut prefer: Vec<String> = Vec::new();
    let mut save_torrent = None;
    let mut json = false;
    let mut verify = false;
    let mut max_down = None;
    let mut max_up = None;
    let mut verbosity = Verbosity::Normal;
    let mut timeout = None;
    let mut port = cfg.port.unwrap_or(DEFAULT_PORT);
    let mut seed = cfg.seed.unwrap_or(false);
    let mut seed_limits = SeedLimits {
        ratio: cfg.seed_ratio.map(seed_limits::check_ratio).transpose().map_err(|e| format!("config seed_ratio: {}", e))?,
        time: cfg.seed_time.as_deref().map(seed_limits::parse_duration).transpose().map_err(|e| format!("config seed_time: {}", e))?,
    };
    let mut no_seed_flag = false;
    let mut no_dht = !cfg.dht.unwrap_or(true);
    let mut no_lsd = !cfg.lsd.unwrap_or(true);
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
    let mut scrape = false;
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
            "--recheck" => recheck = true,
            "--sequential" => sequential = true,
            "--encryption" => {
                let v = argv.next().ok_or("--encryption requires off, prefer or require")?;
                encryption = Some(bittorrent_rs::peer::Encryption::parse(&v).map_err(|e| format!("--encryption: {}", e))?);
            }
            "--transport" => {
                let v = argv.next().ok_or("--transport requires tcp, utp or both")?;
                transport = bittorrent_rs::peer::TransportMode::parse(&v).ok_or_else(|| format!("--transport: {:?} is not tcp, utp or both", v))?;
            }
            "--tracker-mode" => {
                let v = argv.next().ok_or("--tracker-mode requires tiered or concurrent")?;
                tracker_mode = bittorrent_rs::tracker_discovery::TrackerMode::parse(&v).ok_or_else(|| format!("--tracker-mode: {:?} is not tiered or concurrent", v))?;
            }
            "--prefer" => prefer.push(argv.next().ok_or("--prefer requires a path substring")?),
            "--json" => json = true,
            "--verify" => verify = true,
            "--save-torrent" => save_torrent = Some(PathBuf::from(argv.next().ok_or("--save-torrent requires a file name")?)),
            "--max-down" => {
                let v = argv.next().ok_or("--max-down requires a rate such as 500K or 2M")?;
                max_down = Some(bittorrent_rs::ratelimit::parse_rate(&v).map_err(|e| format!("--max-down: {}", e))?);
            }
            "--max-up" => {
                let v = argv.next().ok_or("--max-up requires a rate such as 500K or 2M")?;
                max_up = Some(bittorrent_rs::ratelimit::parse_rate(&v).map_err(|e| format!("--max-up: {}", e))?);
            }
            "--retry-delay" => {
                let n = argv.next().ok_or("--retry-delay requires a number of seconds")?;
                retry_delay = Duration::from_secs(n.parse().map_err(|_| format!("--retry-delay: not a number: {}", n))?);
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
            "--no-seed" => {
                seed = false;
                no_seed_flag = true;
            }
            "--seed-ratio" => {
                let v = argv.next().ok_or("--seed-ratio requires a ratio such as 1 or 2.5")?;
                seed_limits.ratio = Some(seed_limits::parse_ratio(&v).map_err(|e| format!("--seed-ratio: {}", e))?);
            }
            "--seed-time" => {
                let v = argv.next().ok_or("--seed-time requires a duration such as 30m, 12h or 1d")?;
                seed_limits.time = Some(seed_limits::parse_duration(&v).map_err(|e| format!("--seed-time: {}", e))?);
            }
            "--no-dht" => no_dht = true,
            "--dht" => no_dht = false,
            "--no-lsd" => no_lsd = true,
            "--lsd" => no_lsd = false,
            "--no-portmap" => no_portmap = true,
            "--portmap" => no_portmap = false,
            "--no-webseed" => no_webseed = true,
            "--peer" => {
                let v = argv.next().ok_or("--peer requires an address such as 192.0.2.5:6881 or [2001:db8::1]:6881")?;
                peers_hint.push(v.parse().map_err(|_| format!("--peer: {:?} is not ADDRESS:PORT", v))?);
            }
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
            "--scrape" => scrape = true,
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

    if verify && list {
        return Err("--verify and --list are mutually exclusive".to_string());
    }
    if scrape && (verify || list) {
        return Err("--scrape cannot be combined with --verify or --list".to_string());
    }
    if verify && source.starts_with("magnet:?") {
        return Err("--verify needs a .torrent file: a magnet link has no file list until its metadata has been fetched from the network".to_string());
    }
    if json && verbosity == Verbosity::Quiet {
        return Err("--json and --quiet are mutually exclusive".to_string());
    }

    // A seeding limit is a request to seed.
    if seed_limits.is_set() {
        if no_seed_flag {
            return Err("--no-seed cannot be combined with --seed-ratio or --seed-time".to_string());
        }
        seed = true;
    }

    Ok(Args { source, out_dir, max_peers, reannounce_override, retry_delay, recheck, encryption, transport, tracker_mode, sequential, prefer, save_torrent, json, verify, max_down, max_up, verbosity, timeout, port, seed, seed_limits, no_dht, no_lsd, no_portmap, no_webseed, peers_hint, ipv6, only, files_sel, list, scrape, log, no_log, no_tui })
}

fn usage() -> String {
    "usage: download <file.torrent | magnet:?xt=urn:btih:...> [--out DIR] [--peers N] [--port PORT] [--seed | --no-seed] [--seed-ratio RATIO] [--seed-time DURATION] [--dht | --no-dht] [--lsd | --no-lsd] [--portmap | --no-portmap] [--webseed | --no-webseed] [--peer ADDRESS:PORT]... [--ipv6 | --no-ipv6] [--only SUBSTR]... [--files 1,3,5] [--list] [--scrape] [--reannounce SECONDS] [--retry-delay SECONDS] [--recheck] [--encryption off|prefer|require] [--transport tcp|utp|both] [--tracker-mode tiered|concurrent] [--sequential] [--prefer SUBSTR]... [--save-torrent FILE] [--json] [--verify] [--max-down RATE] [--max-up RATE] [--timeout SECONDS] [--config FILE | --no-config] [--log FILE | --no-log] [--tui | --no-tui] [--quiet | --verbose]".to_string()
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
    let json = args.json;
    let interactive = !quiet && !json && !args.no_tui && !args.list && !args.verify && !args.scrape && std::io::stdout().is_terminal();
    let stop = Arc::new(AtomicBool::new(false));
    // Ctrl-C and `kill` wind the client down like the dashboard's `q`, even
    // with no terminal: the port mapping is removed, not left on the router.
    bittorrent_rs::signal::install(Arc::clone(&stop));

    let orchestration = {
        let ui = ui.clone();
        let stop = Arc::clone(&stop);
        thread::spawn(move || orchestrate(args, &ui, &stop))
    };

    let shared = ui.shared();
    let user_quit = if quiet {
        tui::run_silent(&shared, &stop)
    } else if json {
        tui::run_json(&shared, &stop)
    } else if interactive {
        tui::run(&shared, &stop)
    } else {
        tui::run_plain(&shared, &stop)
    };
    stop.store(true, Ordering::SeqCst);

    let result = orchestration.join().unwrap_or_else(|_| Err("download thread panicked".to_string()));

    if user_quit || bittorrent_rs::signal::received() {
        if !quiet && !json {
            println!("stopped \u{2014} rerun the same command to resume.");
        }
        return ExitCode::SUCCESS;
    }
    match result {
        Ok(summary) => {
            // In JSON mode the `done` event has already said it.
            if !quiet && !json {
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

/// How long `--scrape` waits for the trackers before saying which have not answered.
const SCRAPE_WAIT: Duration = Duration::from_secs(20);

/// `--scrape`: asks every tracker of the torrent (its `.torrent` file's, or its magnet link's) how many seeders and leechers it has for
/// it, and how many times it has been finished, and prints what comes back. It looks for no peer and fetches no metadata: only the info
/// hash and the tracker URLs are needed.
fn scrape_trackers(args: &Args, ui: &Ui) -> Result<String, String> {
    let (name, info_hash, trackers) = if args.source.starts_with("magnet:?") {
        let magnet = parse_magnet_uri(&args.source).map_err(|e| finish_err(ui, format!("parsing magnet uri: {}", e)))?;
        let name = magnet.display_name.clone().unwrap_or_else(|| torrent::info_hash_hex(&magnet.info_hash));
        (name, magnet.info_hash, magnet.trackers)
    } else {
        let bytes = fs::read(&args.source).map_err(|e| finish_err(ui, format!("reading {}: {}", args.source, e)))?;
        let torrent = torrent::parse_torrent_file(&bytes).map_err(|e| finish_err(ui, format!("parsing {}: {}", args.source, e)))?;
        let mut trackers: Vec<String> = Vec::new();
        for url in torrent.tracker_tiers().into_iter().flatten() {
            if !trackers.contains(&url) {
                trackers.push(url);
            }
        }
        (torrent.name.clone(), torrent.info_hash, trackers)
    };
    if trackers.is_empty() {
        return Err(finish_err(ui, "the torrent names no tracker to ask".to_string()));
    }

    let (tx, rx) = std::sync::mpsc::channel();
    for url in &trackers {
        let (url, tx) = (url.clone(), tx.clone());
        std::thread::spawn(move || {
            let _ = tx.send((url.clone(), bittorrent_rs::tracker::scrape::scrape(&url, &info_hash).map_err(|e| e.to_string())));
        });
    }
    drop(tx);
    let deadline = Instant::now() + SCRAPE_WAIT;
    let mut answers: Vec<(String, Result<bittorrent_rs::tracker::scrape::ScrapeStats, String>)> = Vec::new();
    while answers.len() < trackers.len() {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else { break };
        match rx.recv_timeout(left) {
            Ok(answer) => answers.push(answer),
            Err(_) => break,
        }
    }
    // In the order the torrent lists them, with those that said nothing at the end of it.
    let mut lines = Vec::new();
    let mut answered = 0;
    for url in &trackers {
        let result = answers.iter().find(|(asked, _)| asked == url).map(|(_, result)| result.clone()).unwrap_or_else(|| Err(format!("no answer in {} seconds", SCRAPE_WAIT.as_secs())));
        let line = match &result {
            Ok(stats) => {
                answered += 1;
                bittorrent_rs::json::Object::new().string("event", "scrape").string("tracker", url).boolean("ok", true).uint("seeders", stats.complete.into()).uint("leechers", stats.incomplete.into()).uint("completed", stats.downloaded.into()).finish()
            }
            Err(why) => bittorrent_rs::json::Object::new().string("event", "scrape").string("tracker", url).boolean("ok", false).string("error", why).finish(),
        };
        lines.push((url.clone(), result, line));
    }
    let text = {
        let mut out = format!("{} \u{2014} {} tracker(s) asked, {} answered:\n", name, trackers.len(), answered);
        for (url, result, _) in &lines {
            match result {
                Ok(stats) => out.push_str(&format!("  {}  {} seeder(s), {} leecher(s), {} completed\n", url, stats.complete, stats.incomplete, stats.downloaded)),
                Err(why) => out.push_str(&format!("  {}  {}\n", url, why)),
            }
        }
        out
    };
    if args.json {
        for (_, _, line) in lines {
            ui.event(line);
        }
    }
    if answered == 0 {
        return Err(finish_err(ui, format!("no tracker answered:\n{}", text.trim_end())));
    }
    ui.finish(Ok(if args.json { format!("{} of {} tracker(s) answered", answered, trackers.len()) } else { text.clone() }));
    Ok(text)
}

/// Whether the DHT gets an IPv6 node (BEP 32): when peers over IPv6 are wanted,
/// as `--ipv6` and `--no-ipv6` and a probe for a route decide.
fn dht_ipv6(args: &Args) -> bool {
    match args.ipv6 {
        bittorrent_rs::session::Ipv6Mode::Always => true,
        bittorrent_rs::session::Ipv6Mode::Never => false,
        bittorrent_rs::session::Ipv6Mode::Auto => bittorrent_rs::session::has_ipv6_egress(),
    }
}

/// Asks peers for the piece layers a v2 torrent lacks (BEP 52), until it has them or gives up.
fn fetch_layers_if_missing(torrent: &mut torrent::TorrentFile, bootstrap_peers: &[std::net::SocketAddr], services: &Services, args: &Args, our_peer_id: [u8; 20], ui: &Ui, stop: &AtomicBool) -> Result<(), String> {
    use bittorrent_rs::session::layers::{complete_torrent, Discovery, LayerConfig, LAYER_BUDGET};
    let transport = bittorrent_rs::peer::Transport { mode: if services.utp().is_some() { args.transport } else { Default::default() }, utp: services.utp() };
    let config = LayerConfig { our_peer_id, timeout: CONNECT_TIMEOUT, encryption: args.encryption.unwrap_or_default(), transport };
    let discovery = Discovery { bootstrap: bootstrap_peers.to_vec(), dht: services.dht(), trackers: torrent.tracker_tiers(), announce_port: args.port };
    complete_torrent(torrent, discovery, &config, LAYER_BUDGET, stop, &|m| ui.log(m))
}

/// The whole download, start to finish, publishing to `ui`. Returns a
/// human-readable completion summary (`Ok`) or a failure reason (`Err`);
/// either way it also calls `ui.finish` so the dashboard can wind down
/// (except in `--seed` mode, which keeps the UI live until the user
/// quits via `stop`).
fn orchestrate(args: Args, ui: &Ui, stop: &AtomicBool) -> Result<String, String> {
    if args.scrape {
        return scrape_trackers(&args, ui);
    }
    let our_peer_id = generate_peer_id();

    // Dropping `services` (including on any early `return Err`) stops the
    // DHT, the listener and the port mapping.
    let mut services = Services::new();

    let (mut torrent, bootstrap_peers, link_selection) = if args.source.starts_with("magnet:?") {
        let mut magnet = parse_magnet_uri(&args.source).map_err(|e| finish_err(ui, format!("parsing magnet uri: {}", e)))?;
        magnet.peers.extend(args.peers_hint.iter().copied());
        if args.transport.wants_utp() {
            services.start_utp(args.port, |m| ui.log(m));
        }
        if !args.no_dht {
            services.start_dht(args.port, magnet.info_hash, dht_ipv6(&args), dht_bootstrap(), |m| ui.log(m));
        }
        if magnet.trackers.is_empty() && magnet.peers.is_empty() && services.dht().is_none() {
            return Err(finish_err(ui, "magnet link has no trackers or peers and DHT is disabled (--no-dht) -- no way to find any peer".to_string()));
        }
        if let Some(name) = &magnet.display_name {
            ui.set_title(name.clone());
        }
        let metadata = MetadataConfig { budget: METADATA_RESOLVE_BUDGET, parallelism: METADATA_PARALLELISM, connect_timeout: CONNECT_TIMEOUT, encryption: args.encryption.unwrap_or_default(), transport: bittorrent_rs::peer::Transport { mode: if services.utp().is_some() { args.transport } else { Default::default() }, utp: services.utp() } };
        let (torrent, peers) = resolve_magnet(&magnet, our_peer_id, args.port, services.dht(), &metadata, ui, stop).map_err(|e| finish_err(ui, e))?;
        // The DHT had to run to fetch the metadata, since a magnet link
        // doesn't say whether the torrent is private until the info dict
        // arrives. Now that it has, shut the DHT down: no lookups, no
        // announces, no answering queries for a private info-hash.
        if torrent.private {
            services.stop_dht();
        }
        // BEP 53's `so`, counted from 1 as `--files` counts.
        (torrent, peers, magnet.select_only.iter().map(|index| index + 1).collect::<Vec<usize>>())
    } else {
        let bytes = fs::read(&args.source).map_err(|e| finish_err(ui, format!("reading {}: {}", args.source, e)))?;
        let torrent = torrent::parse_torrent_file(&bytes).map_err(|e| finish_err(ui, format!("parsing {}: {}", args.source, e)))?;
        // A `.torrent` already carries the file list, so `--list` needs no
        // network at all.
        if args.transport.wants_utp() && !args.list && !args.verify {
            services.start_utp(args.port, |m| ui.log(m));
        }
        if !args.no_dht && !args.list && !args.verify && !torrent.private {
            services.start_dht(args.port, torrent.info_hash, dht_ipv6(&args), dht_bootstrap(), |m| ui.log(m));
        }
        (torrent, args.peers_hint.clone(), Vec::new())
    };
    // A v2 torrent that does not carry its piece layers (a magnet link's never does) gets them from peers.
    if torrent.is_v2_only() && !torrent.v2_ready() && !args.list && !args.verify {
        fetch_layers_if_missing(&mut torrent, &bootstrap_peers, &services, &args, our_peer_id, ui, stop).map_err(|e| finish_err(ui, e))?;
    }
    if let Some(path) = &args.save_torrent {
        bittorrent_rs::create::save_torrent(&torrent, path).map_err(|e| finish_err(ui, format!("--save-torrent: {}", e)))?;
        ui.log(format!("saved the torrent to {}", path.display()));
    }
    if torrent.private && !args.list {
        ui.log("private torrent (BEP 27): DHT and peer exchange disabled, peers come from the tracker only");
    }

    ui.set_title(torrent.name.clone());
    ui.set_info_hash(torrent::info_hash_hex(&torrent.info_hash));
    ui.log(format!("torrent: {} ({}, {} pieces)", torrent.name, ui::format_bytes(torrent.total_length()), torrent.pieces.len()));

    // File selection (--only / --files). `--list` prints the file table
    // and exits without downloading anything.
    // A magnet link's `so` (BEP 53) says which files it is for; what was asked for on the command line overrides it.
    let files_sel = if args.files_sel.is_empty() && args.only.is_empty() && !link_selection.is_empty() {
        ui.log(format!("the magnet link selects file(s) {} (so=)", link_selection.iter().map(usize::to_string).collect::<Vec<_>>().join(",")));
        link_selection
    } else {
        args.files_sel.clone()
    };
    let mask = bittorrent_rs::selection::build_mask_for(&torrent, &files_sel, &args.only).map_err(|e| finish_err(ui, e))?;
    if args.list {
        let (visible, visible_mask) = (torrent.visible_files(), torrent.visible_mask(&mask));
        let listing = bittorrent_rs::selection::format_list(&torrent.name, &visible, &visible_mask);
        services.shutdown();
        if args.json {
            for line in bittorrent_rs::selection::list_events(&visible, &visible_mask) {
                ui.event(line);
            }
            ui.finish(Ok(format!("{} file(s)", visible.len())));
        } else {
            ui.finish(Ok(listing.clone()));
        }
        return Ok(listing);
    }
    if args.verify {
        services.shutdown();
        return verify_files(&torrent, &mask, &args, ui, stop);
    }
    let options = Options {
        out_dir: args.out_dir.clone(),
        port: args.port,
        max_peers: args.max_peers,
        reannounce_override: args.reannounce_override.map(Duration::from_secs),
        retry_delay: args.retry_delay,
        recheck: args.recheck,
        encryption: args.encryption,
        transport: args.transport,
        tracker_mode: args.tracker_mode,
        sequential: args.sequential,
        prefer: bittorrent_rs::selection::build_prefer_mask_for(&torrent, &args.prefer).map_err(|e| finish_err(ui, e))?,
        max_down: args.max_down,
        max_up: args.max_up,
        ipv6: args.ipv6,
        no_portmap: args.no_portmap,
        no_webseed: args.no_webseed,
        lsd: (!args.no_lsd).then(lsd_config),
        timeout: args.timeout,
        pipeline_depth: PIPELINE_DEPTH,
        connect_timeout: CONNECT_TIMEOUT,
    };
    let sink: Arc<dyn ProgressSink> = Arc::new(ui.clone());
    let prepared = prepare(&torrent, &mask, bootstrap_peers, our_peer_id, &options, &mut services, &sink).map_err(|e| finish_err(ui, e))?;
    let info = prepared.info.clone();
    let mut session = prepared.into_session(&*sink, &services);
    let report = session.run(stop);

    if report.complete {
        bittorrent_rs::downloader::resume::clear(&info.progress_path);
        let scope = if info.selective { format!("{} selected", ui::format_bytes(info.display_total)) } else { ui::format_bytes(info.total_length) };
        let avg = report.bytes_this_run as f64 / report.elapsed.as_secs_f64().max(0.001);
        // Built again after seeding, when there is more to say about uploads.
        let summarize = |uploaded: u64, seed_end: Option<SeedEnd>| {
            let mut text = format!(
                "download complete: {} -> {}\n  {} in {} \u{b7} {} avg \u{b7} {} uploaded",
                torrent.name,
                info.base_dir.display(),
                scope,
                ui::format_duration(report.elapsed.as_secs()),
                ui::format_rate(avg),
                ui::format_bytes(uploaded),
            );
            if let Some(end) = seed_end {
                text.push_str(&format!("\n  {}, seeding finished", end));
            }
            text
        };
        let mut summary = summarize(session.uploaded_bytes(), None);
        ui.log("download complete");

        session.announce_completed();

        if args.seed && services.has_seeder() {
            // Keep the UI live and seeding until the user quits or a seed
            // limit is reached. The UI totals reflect the selected subset
            // (info.display_total/goal).
            if let Some(end) = session.seed(&torrent.name, info.announce_port, stop, args.seed_limits) {
                summary = summarize(session.uploaded_bytes(), Some(end));
                ui.finish(Ok(summary.clone()));
            }
        } else {
            ui.finish(Ok(summary.clone()));
        }

        session.announce_stopped();
        services.shutdown();
        Ok(summary)
    } else {
        let reason = match &report.aborted {
            Some(why) => format!("cannot write to disk: {} -- {} piece(s) not downloaded; fix that and rerun the same command to resume", why, report.remaining),
            None => format!("incomplete: {} piece(s) never downloaded ({} peer(s) dialed) -- rerun the same command to resume", report.remaining, report.dialed),
        };
        session.announce_stopped();
        services.shutdown();
        // If we're here because the user quit, don't flash a failure
        // banner -- main prints the "stopped" line.
        if !stop.load(Ordering::SeqCst) {
            ui.finish(Err(reason.clone()));
        }
        Err(reason)
    }
}

/// `--verify`: hash what is on disk against the torrent, telling the
/// dashboard as it goes, and say which files are whole. `Err` when anything
/// wanted is missing or damaged, so the exit status says so.
fn verify_files(torrent: &torrent::TorrentFile, mask: &[bool], args: &Args, ui: &Ui, stop: &AtomicBool) -> Result<String, String> {
    use bittorrent_rs::ui::Snapshot;
    let base_dir = if torrent.multi_file { args.out_dir.join(&torrent.name) } else { args.out_dir.clone() };
    let (_, wanted_bytes) = bittorrent_rs::selection::selected_pieces_of(torrent, mask);
    ui.log(format!("verifying {} against {}", torrent.name, base_dir.display()));
    let mut last_shown = 0;
    let report = bittorrent_rs::session::verify::verify(torrent, mask, &base_dir, |checked, of| {
        // Not on every piece: a large torrent has hundreds of thousands.
        if checked == of || checked >= last_shown + 64 {
            last_shown = checked;
            ui.set_snapshot(Snapshot { total_length: wanted_bytes, total_pieces: of, verified: checked, status: "verifying", ..Default::default() });
        }
        !stop.load(Ordering::SeqCst)
    });
    let Some(report) = report else {
        // Interrupted: main prints the "stopped" line.
        return Err("verification was stopped".to_string());
    };
    let summary = report.describe(&torrent.name, false);
    if report.is_whole() {
        ui.finish(Ok(summary.clone()));
        Ok(summary)
    } else {
        Err(finish_err(ui, summary))
    }
}

/// Convenience: record a fatal reason on the dashboard and return it so
/// the `?` operator can bubble it up as the orchestration's `Err`.
fn finish_err(ui: &Ui, reason: String) -> String {
    ui.finish(Err(reason.clone()));
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn parse(cfg: &Config, args: &[&str]) -> Result<Args, String> {
        parse_args_from(cfg, args.iter().map(|a| a.to_string()))
    }

    fn cfg_from(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn prefer_can_be_given_more_than_once() {
        assert!(parse(&Config::default(), &["x"]).unwrap().prefer.is_empty());
        assert_eq!(parse(&Config::default(), &["x", "--prefer", ".nfo", "--prefer", "ep1"]).unwrap().prefer, vec![".nfo".to_string(), "ep1".to_string()]);
        assert!(parse(&Config::default(), &["x", "--prefer"]).err().unwrap().contains("requires"));
    }

    #[test]
    fn local_discovery_is_on_unless_the_flag_or_config_says_otherwise_and_the_flag_wins() {
        assert!(!parse(&Config::default(), &["x"]).unwrap().no_lsd, "on by default");
        assert!(parse(&Config::default(), &["x", "--no-lsd"]).unwrap().no_lsd);
        let off = cfg_from("lsd = false");
        assert!(parse(&off, &["x"]).unwrap().no_lsd);
        assert!(!parse(&off, &["x", "--lsd"]).unwrap().no_lsd, "the flag wins over the config");
        assert!(!parse(&cfg_from("lsd = true"), &["x"]).unwrap().no_lsd);
        assert!(!parse(&Config::default(), &["x", "--no-dht"]).unwrap().no_lsd, "and it is not the same switch as the DHT's");
    }

    #[test]
    fn transport_is_chosen_by_flag_or_config_and_the_flag_wins() {
        use bittorrent_rs::peer::TransportMode;
        assert_eq!(parse(&Config::default(), &["x"]).unwrap().transport, TransportMode::Tcp, "TCP unless asked");
        assert_eq!(parse(&Config::default(), &["x", "--transport", "utp"]).unwrap().transport, TransportMode::Utp);
        let cfg = cfg_from("transport = \"both\"");
        assert_eq!(parse(&cfg, &["x"]).unwrap().transport, TransportMode::Both);
        assert_eq!(parse(&cfg, &["x", "--transport", "tcp"]).unwrap().transport, TransportMode::Tcp);
        assert!(parse(&Config::default(), &["x", "--transport", "udp"]).err().unwrap().starts_with("--transport:"));
        assert!(parse(&Config::default(), &["x", "--transport"]).err().unwrap().contains("requires"));
        assert!(parse(&cfg_from("transport = \"udp\""), &["x"]).err().unwrap().starts_with("config transport:"));
    }

    #[test]
    fn trackers_are_asked_by_tier_unless_the_flag_or_config_says_concurrent_and_the_flag_wins() {
        use bittorrent_rs::tracker_discovery::TrackerMode;
        assert_eq!(parse(&Config::default(), &["x"]).unwrap().tracker_mode, TrackerMode::Tiered, "BEP 12 unless asked");
        assert_eq!(parse(&Config::default(), &["x", "--tracker-mode", "concurrent"]).unwrap().tracker_mode, TrackerMode::Concurrent);
        let cfg = cfg_from("tracker_mode = \"concurrent\"");
        assert_eq!(parse(&cfg, &["x"]).unwrap().tracker_mode, TrackerMode::Concurrent);
        assert_eq!(parse(&cfg, &["x", "--tracker-mode", "tiered"]).unwrap().tracker_mode, TrackerMode::Tiered);
        assert!(parse(&Config::default(), &["x", "--tracker-mode", "all"]).err().unwrap().starts_with("--tracker-mode:"));
        assert!(parse(&Config::default(), &["x", "--tracker-mode"]).err().unwrap().contains("requires"));
        assert!(parse(&cfg_from("tracker_mode = \"all\""), &["x"]).err().unwrap().starts_with("config tracker_mode:"));
    }

    #[test]
    fn peers_can_be_named_on_the_command_line() {
        assert!(parse(&Config::default(), &["x"]).unwrap().peers_hint.is_empty());
        let args = parse(&Config::default(), &["x", "--peer", "192.0.2.5:6881", "--peer", "[2001:db8::1]:7000"]).unwrap();
        assert_eq!(args.peers_hint, vec!["192.0.2.5:6881".parse().unwrap(), "[2001:db8::1]:7000".parse().unwrap()]);
        assert!(parse(&Config::default(), &["x", "--peer", "example.com:6881"]).err().unwrap().starts_with("--peer:"), "an address, not a name");
        assert!(parse(&Config::default(), &["x", "--peer", "1.2.3.4"]).err().unwrap().starts_with("--peer:"), "with its port");
        assert!(parse(&Config::default(), &["x", "--peer"]).err().unwrap().contains("requires"));
    }

    #[test]
    fn encryption_is_chosen_by_flag_or_config_and_the_flag_wins() {
        use bittorrent_rs::peer::Encryption;
        assert_eq!(parse(&Config::default(), &["x"]).unwrap().encryption, None, "unset: plain out, either in");
        assert_eq!(parse(&Config::default(), &["x", "--encryption", "require"]).unwrap().encryption, Some(Encryption::Require));
        let cfg = cfg_from("encryption = \"prefer\"");
        assert_eq!(parse(&cfg, &["x"]).unwrap().encryption, Some(Encryption::Prefer));
        assert_eq!(parse(&cfg, &["x", "--encryption", "off"]).unwrap().encryption, Some(Encryption::Off));
        assert!(parse(&Config::default(), &["x", "--encryption", "maybe"]).err().unwrap().starts_with("--encryption:"));
        assert!(parse(&Config::default(), &["x", "--encryption"]).err().unwrap().contains("requires"));
        assert!(parse(&cfg_from("encryption = \"maybe\""), &["x"]).err().unwrap().starts_with("config encryption:"));
    }

    #[test]
    fn scrape_is_off_unless_asked_for_and_cannot_be_combined_with_list_or_verify() {
        assert!(!parse(&Config::default(), &["x"]).unwrap().scrape);
        assert!(parse(&Config::default(), &["x", "--scrape"]).unwrap().scrape);
        assert!(parse(&Config::default(), &["x", "--scrape", "--list"]).err().unwrap().contains("--scrape"));
        assert!(parse(&Config::default(), &["x", "--verify", "--scrape"]).err().unwrap().contains("--scrape"));
    }

    #[test]
    fn verify_is_off_unless_asked_for_and_cannot_be_combined_with_list() {
        assert!(!parse(&Config::default(), &["x"]).unwrap().verify);
        assert!(parse(&Config::default(), &["x", "--verify"]).unwrap().verify);
        assert!(parse(&Config::default(), &["x", "--verify", "--list"]).err().unwrap().contains("mutually exclusive"));
        assert!(parse(&Config::default(), &["magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567", "--verify"]).err().unwrap().contains(".torrent file"));
    }

    #[test]
    fn json_is_off_unless_asked_for_and_refuses_quiet() {
        assert!(!parse(&Config::default(), &["x"]).unwrap().json);
        assert!(parse(&Config::default(), &["x", "--json"]).unwrap().json);
        assert!(parse(&Config::default(), &["x", "--json", "--verbose"]).unwrap().json);
        assert!(parse(&Config::default(), &["x", "--json", "--quiet"]).err().unwrap().contains("mutually exclusive"));
        assert!(parse(&Config::default(), &["x", "--quiet", "--json"]).err().unwrap().contains("mutually exclusive"));
    }

    #[test]
    fn save_torrent_takes_a_file_name() {
        assert_eq!(parse(&Config::default(), &["x"]).unwrap().save_torrent, None);
        assert_eq!(parse(&Config::default(), &["x", "--save-torrent", "kept.torrent"]).unwrap().save_torrent, Some(PathBuf::from("kept.torrent")));
        assert!(parse(&Config::default(), &["x", "--save-torrent"]).err().unwrap().contains("requires"));
    }

    #[test]
    fn sequential_is_off_unless_asked_for() {
        assert!(!parse(&Config::default(), &["x.torrent"]).unwrap().sequential);
        assert!(parse(&Config::default(), &["x.torrent", "--sequential"]).unwrap().sequential);
    }

    #[test]
    fn seeding_is_off_and_unlimited_unless_asked_for() {
        let args = parse(&Config::default(), &["x.torrent"]).unwrap();
        assert!(!args.seed);
        assert!(!args.seed_limits.is_set());
    }

    #[test]
    fn a_seed_limit_on_the_command_line_turns_seeding_on() {
        let args = parse(&Config::default(), &["x.torrent", "--seed-ratio", "1.5"]).unwrap();
        assert!(args.seed);
        assert_eq!(args.seed_limits, SeedLimits { ratio: Some(1.5), time: None });

        let args = parse(&Config::default(), &["x.torrent", "--seed-time", "90m"]).unwrap();
        assert!(args.seed);
        assert_eq!(args.seed_limits, SeedLimits { ratio: None, time: Some(Duration::from_secs(5400)) });
    }

    #[test]
    fn both_limits_can_be_given_and_seed_is_not_needed_beside_them() {
        let args = parse(&Config::default(), &["x.torrent", "--seed", "--seed-ratio", "2", "--seed-time", "1h"]).unwrap();
        assert!(args.seed);
        assert_eq!(args.seed_limits, SeedLimits { ratio: Some(2.0), time: Some(Duration::from_secs(3600)) });
    }

    #[test]
    fn a_seed_limit_contradicts_no_seed() {
        for args in [["x.torrent", "--no-seed", "--seed-ratio", "2"], ["x.torrent", "--seed-time", "2h", "--no-seed"]] {
            let err = parse(&Config::default(), &args).err().expect("refused");
            assert!(err.contains("--no-seed"), "{}", err);
        }
    }

    #[test]
    fn a_bad_limit_is_refused_naming_the_flag() {
        assert!(parse(&Config::default(), &["x.torrent", "--seed-ratio", "0"]).err().unwrap().starts_with("--seed-ratio:"));
        assert!(parse(&Config::default(), &["x.torrent", "--seed-time", "soon"]).err().unwrap().starts_with("--seed-time:"));
        assert!(parse(&Config::default(), &["x.torrent", "--seed-ratio"]).err().unwrap().contains("requires"));
        assert!(parse(&Config::default(), &["x.torrent", "--seed-time"]).err().unwrap().contains("requires"));
    }

    #[test]
    fn the_config_file_can_set_the_limits_and_the_command_line_overrides_them() {
        let cfg = cfg_from("seed_ratio = 3.0\nseed_time = \"12h\"\n");

        let args = parse(&cfg, &["x.torrent"]).unwrap();
        assert!(args.seed, "a limit in the config file means seeding too");
        assert_eq!(args.seed_limits, SeedLimits { ratio: Some(3.0), time: Some(Duration::from_secs(12 * 3600)) });

        let args = parse(&cfg, &["x.torrent", "--seed-ratio", "1"]).unwrap();
        assert_eq!(args.seed_limits.ratio, Some(1.0), "the flag wins");
        assert_eq!(args.seed_limits.time, Some(Duration::from_secs(12 * 3600)), "what it does not mention stays");
    }

    #[test]
    fn a_bad_limit_in_the_config_file_is_refused_naming_the_key() {
        assert!(parse(&cfg_from("seed_ratio = -1.0"), &["x.torrent"]).err().unwrap().starts_with("config seed_ratio:"));
        assert!(parse(&cfg_from("seed_time = \"later\""), &["x.torrent"]).err().unwrap().starts_with("config seed_time:"));
    }
}
