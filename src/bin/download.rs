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
use bittorrent_rs::session::{prepare, resolve_magnet, Ipv6Mode, MetadataConfig, Options, ProgressSink, Services};
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
use std::time::Duration;

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
    /// Bytes per second limits on download and upload, if set.
    max_down: Option<u64>,
    max_up: Option<u64>,
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
    let mut retry_delay = Duration::from_secs(15);
    let mut recheck = false;
    let mut max_down = None;
    let mut max_up = None;
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
            "--recheck" => recheck = true,
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

    Ok(Args { source, out_dir, max_peers, reannounce_override, retry_delay, recheck, max_down, max_up, verbosity, timeout, port, seed, no_dht, no_portmap, no_webseed, ipv6, only, files_sel, list, log, no_log, no_tui })
}

fn usage() -> String {
    "usage: download <file.torrent | magnet:?xt=urn:btih:...> [--out DIR] [--peers N] [--port PORT] [--seed | --no-seed] [--dht | --no-dht] [--portmap | --no-portmap] [--webseed | --no-webseed] [--ipv6 | --no-ipv6] [--only SUBSTR]... [--files 1,3,5] [--list] [--reannounce SECONDS] [--retry-delay SECONDS] [--recheck] [--max-down RATE] [--max-up RATE] [--timeout SECONDS] [--config FILE | --no-config] [--log FILE | --no-log] [--tui | --no-tui] [--quiet | --verbose]".to_string()
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
        if let Some(name) = &magnet.display_name {
            ui.set_title(name.clone());
        }
        let metadata = MetadataConfig { budget: METADATA_RESOLVE_BUDGET, parallelism: METADATA_PARALLELISM, connect_timeout: CONNECT_TIMEOUT };
        let (torrent, peers) = resolve_magnet(&magnet, our_peer_id, args.port, services.dht(), &metadata, ui, stop).map_err(|e| finish_err(ui, e))?;
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

    // File selection (--only / --files). `--list` prints the file table
    // and exits without downloading anything.
    let mask = bittorrent_rs::selection::build_mask(&torrent.files, &args.files_sel, &args.only).map_err(|e| finish_err(ui, e))?;
    if args.list {
        let listing = bittorrent_rs::selection::format_list(&torrent.name, &torrent.files, &mask);
        services.shutdown();
        ui.finish(Ok(listing.clone()));
        return Ok(listing);
    }
    let options = Options {
        out_dir: args.out_dir.clone(),
        port: args.port,
        max_peers: args.max_peers,
        reannounce_override: args.reannounce_override.map(Duration::from_secs),
        retry_delay: args.retry_delay,
        recheck: args.recheck,
        max_down: args.max_down,
        max_up: args.max_up,
        ipv6: args.ipv6,
        no_portmap: args.no_portmap,
        no_webseed: args.no_webseed,
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
        let summary = format!(
            "download complete: {} -> {}\n  {} in {} \u{b7} {} avg \u{b7} {} uploaded",
            torrent.name,
            info.base_dir.display(),
            scope,
            ui::format_duration(report.elapsed.as_secs()),
            ui::format_rate(avg),
            ui::format_bytes(session.uploaded_bytes()),
        );
        ui.log("download complete");

        session.announce_completed();

        if args.seed && services.has_seeder() {
            // Keep the UI live and seeding until the user quits. The UI
            // totals reflect the selected subset (info.display_total/goal).
            session.seed(&torrent.name, info.announce_port, stop);
        } else {
            ui.finish(Ok(summary.clone()));
        }

        services.shutdown();
        Ok(summary)
    } else {
        let reason = format!("incomplete: {} piece(s) never downloaded ({} peer(s) dialed) -- rerun the same command to resume", report.remaining, report.dialed);
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

