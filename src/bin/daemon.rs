//! Downloads and seeds any number of torrents at once, on one port, and is told what to do over
//! a local socket.
//!
//!   daemon run [options]                        start the daemon
//!   daemon add <file.torrent | magnet:?...>     give it a torrent
//!   daemon list | status ID | remove ID | stop  see what it is doing, or end it
//!
//! Where the `download` client runs one torrent and stops, this keeps running: the listener, the
//! DHT node, the uTP socket, the port mapping and the rate limits are shared by every torrent, and
//! what it has been given is remembered in a state directory and started again after a restart.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("the daemon is controlled over a Unix socket, which this system does not have");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(unix)]
mod unix {
    use bittorrent_rs::daemon::control::{self, Reply, Request, Server};
    use bittorrent_rs::daemon::state::Store;
    use bittorrent_rs::daemon::{JobDefaults, JobOptions, Manager};
    use bittorrent_rs::json::Value;
    use bittorrent_rs::peer::{Encryption, TransportMode};
    use bittorrent_rs::ratelimit::parse_rate;
    use bittorrent_rs::session::env::{dht_bootstrap, lsd_config};
    use bittorrent_rs::tracker_discovery::TrackerMode;
    use bittorrent_rs::session::{has_ipv6_egress, seed_limits, Ipv6Mode, NetworkConfig, SeedLimits, SharedNetwork};
    use bittorrent_rs::tracker::generate_peer_id;
    use bittorrent_rs::ui::format_rate;
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    const DEFAULT_PORT: u16 = 6881;

    /// What was asked for.
    #[derive(Debug, PartialEq)]
    pub enum Command {
        Run(Box<RunArgs>),
        Add { source: String, out: Option<PathBuf>, options: JobOptions },
        List,
        Status { id: String },
        Remove { id: String },
        Pause { id: String },
        Resume { id: String },
        Stop,
    }

    /// The daemon's own settings.
    #[derive(Debug, PartialEq)]
    pub struct RunArgs {
        pub port: u16,
        pub max_up: Option<u64>,
        pub max_down: Option<u64>,
        pub dht: bool,
        pub lsd: bool,
        pub portmap: bool,
        pub ipv6: Ipv6Mode,
        pub transport: TransportMode,
        pub tracker_mode: TrackerMode,
        pub encryption: Option<Encryption>,
        pub max_peers: usize,
        pub seed_limits: SeedLimits,
        pub quiet: bool,
    }

    #[derive(Debug, PartialEq)]
    pub struct Args {
        pub command: Command,
        pub state_dir: Option<PathBuf>,
        pub socket: Option<PathBuf>,
        pub json: bool,
    }

    fn usage() -> String {
        "usage: daemon run [--state-dir DIR] [--socket PATH] [--port PORT] [--max-up RATE] [--max-down RATE] [--peers N] [--dht | --no-dht] [--lsd | --no-lsd] [--portmap | --no-portmap] [--ipv6 | --no-ipv6] [--transport tcp|utp|both] [--tracker-mode tiered|concurrent] [--encryption off|prefer|require] [--seed-ratio RATIO] [--seed-time DURATION] [--quiet]\n\
         \x20      daemon add <file.torrent | magnet:?...> [--out DIR] [--socket PATH] [--json]\n\
         \x20      daemon list | status ID | remove ID | stop [--socket PATH] [--json]\n\
         \n\
         `run` starts the daemon: every torrent it is given is downloaded and then seeded, on one port, with the DHT node, the rate limits and the port mapping shared. The state directory (default ~/.local/state/bittorrent-rs) is where it remembers them; the socket (default daemon.sock in it) is where the other commands reach it. An ID is an info hash, or the start of one. `add` takes the torrent's own limits, which hold as well as the daemon's; `pause` sets a torrent aside until `resume`, which also starts a finished or failed one again."
            .to_string()
    }

    pub fn parse_args(argv: impl Iterator<Item = String>) -> Result<Args, String> {
        let mut argv = argv.peekable();
        let command = argv.next().ok_or_else(usage)?;
        if command == "--help" || command == "-h" || command == "help" {
            return Err(usage());
        }
        let mut positional = None;
        let mut args = Args { command: Command::List, state_dir: None, socket: None, json: false };
        let mut run = RunArgs { port: DEFAULT_PORT, max_up: None, max_down: None, dht: true, lsd: true, portmap: true, ipv6: Ipv6Mode::Auto, transport: TransportMode::Tcp, tracker_mode: TrackerMode::Tiered, encryption: None, max_peers: 30, seed_limits: SeedLimits::default(), quiet: false };
        let mut out = None;
        let mut job = JobOptions::default();

        while let Some(flag) = argv.next() {
            let mut value = |what: &str| argv.next().ok_or_else(|| format!("{} requires {}", flag, what));
            match flag.as_str() {
                "--state-dir" => args.state_dir = Some(PathBuf::from(value("a directory")?)),
                "--socket" => args.socket = Some(PathBuf::from(value("a path")?)),
                "--json" => args.json = true,
                "--out" | "-o" => out = Some(PathBuf::from(value("a directory")?)),
                "--only" => job.only.push(value("part of a file's path")?),
                "--prefer" => job.prefer.push(value("part of a file's path")?),
                "--sequential" => job.sequential = true,
                "--port" => run.port = value("a port")?.parse().map_err(|_| "--port: not a port number".to_string())?,
                "--max-up" => run.max_up = Some(parse_rate(&value("a rate such as 500K or 2M")?).map_err(|e| format!("--max-up: {}", e))?),
                "--max-down" => run.max_down = Some(parse_rate(&value("a rate such as 500K or 2M")?).map_err(|e| format!("--max-down: {}", e))?),
                "--peers" => run.max_peers = value("a number")?.parse().ok().filter(|&n| n > 0).ok_or("--peers: not a positive number")?,
                "--dht" => run.dht = true,
                "--no-dht" => run.dht = false,
                "--lsd" => run.lsd = true,
                "--no-lsd" => run.lsd = false,
                "--portmap" => run.portmap = true,
                "--no-portmap" => run.portmap = false,
                "--ipv6" => run.ipv6 = Ipv6Mode::Always,
                "--no-ipv6" => run.ipv6 = Ipv6Mode::Never,
                "--transport" => run.transport = TransportMode::parse(&value("tcp, utp or both")?).ok_or("--transport: expected tcp, utp or both")?,
                "--tracker-mode" => run.tracker_mode = TrackerMode::parse(&value("tiered or concurrent")?).ok_or("--tracker-mode: expected tiered or concurrent")?,
                "--encryption" => run.encryption = Some(Encryption::parse(&value("off, prefer or require")?).map_err(|e| format!("--encryption: {}", e))?),
                "--seed-ratio" => run.seed_limits.ratio = Some(seed_limits::parse_ratio(&value("a ratio such as 1 or 2.5")?).map_err(|e| format!("--seed-ratio: {}", e))?),
                "--seed-time" => run.seed_limits.time = Some(seed_limits::parse_duration(&value("a duration such as 30m, 12h or 1d")?).map_err(|e| format!("--seed-time: {}", e))?),
                "--quiet" | "-q" => run.quiet = true,
                other if !other.starts_with('-') && positional.is_none() => positional = Some(other.to_string()),
                other => return Err(format!("unrecognized argument: {}", other)),
            }
        }

        // (`--max-up` and `--max-down` are the daemon's for `run` and the torrent's for `add`.)
        job.max_up = run.max_up;
        job.max_down = run.max_down;
        if command != "add" && (!job.only.is_empty() || !job.prefer.is_empty() || job.sequential) {
            return Err(format!("--only, --prefer and --sequential are for `add`, not {}", command));
        }
        let need = |what: &str, given: Option<String>| given.ok_or_else(|| format!("{} needs {}", command, what));
        args.command = match command.as_str() {
            "run" => Command::Run(Box::new(run)),
            "add" => Command::Add { source: need("a .torrent file or a magnet link", positional.take())?, out, options: job },
            "pause" => Command::Pause { id: need("a torrent's ID", positional.take())? },
            "resume" => Command::Resume { id: need("a torrent's ID", positional.take())? },
            "list" => Command::List,
            "status" => Command::Status { id: need("a torrent's ID", positional.take())? },
            "remove" => Command::Remove { id: need("a torrent's ID", positional.take())? },
            "stop" => Command::Stop,
            other => return Err(format!("no command {:?}\n{}", other, usage())),
        };
        if positional.is_some() {
            return Err(format!("{} takes no argument", command));
        }
        Ok(args)
    }

    /// Where the daemon keeps what it remembers, unless told.
    fn default_state_dir() -> PathBuf {
        if let Some(dir) = std::env::var_os("BITTORRENT_RS_STATE_DIR") {
            return PathBuf::from(dir);
        }
        if let Some(dir) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(dir).join("bittorrent-rs");
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join(".local/state/bittorrent-rs")
    }

    fn socket_path(args: &Args) -> PathBuf {
        args.socket.clone().unwrap_or_else(|| args.state_dir.clone().unwrap_or_else(default_state_dir).join("daemon.sock"))
    }

    pub fn main() -> ExitCode {
        let args = match parse_args(std::env::args().skip(1)) {
            Ok(args) => args,
            Err(message) => {
                eprintln!("{}", message);
                return ExitCode::from(2);
            }
        };
        let result = match &args.command {
            Command::Run(run) => run_daemon(&args, run),
            _ => client(&args),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("error: {}", message);
                ExitCode::FAILURE
            }
        }
    }

    fn run_daemon(args: &Args, run: &RunArgs) -> Result<(), String> {
        let state_dir = args.state_dir.clone().unwrap_or_else(default_state_dir);
        let store = Store::open(&state_dir).map_err(|e| format!("state directory {}: {}", state_dir.display(), e))?;
        let socket = socket_path(args);
        let quiet = run.quiet;
        let say = move |message: String| {
            if !quiet {
                println!("{}", message);
            }
        };

        // Listened for, so that a second daemon on the same socket is refused before it takes the ports.
        let stop = Arc::new(AtomicBool::new(false));
        bittorrent_rs::signal::install(Arc::clone(&stop));
        let ipv6 = match run.ipv6 {
            Ipv6Mode::Always => true,
            Ipv6Mode::Never => false,
            Ipv6Mode::Auto => has_ipv6_egress(),
        };
        let config = NetworkConfig { port: run.port, transport: run.transport, encryption: run.encryption, dht: run.dht, dht_bootstrap: dht_bootstrap(), ipv6, portmap: run.portmap, max_up: run.max_up, max_down: run.max_down };
        let network = Arc::new(SharedNetwork::start(&config, say).map_err(|e| format!("cannot listen: {}", e))?);
        let defaults = JobDefaults { max_peers: run.max_peers, ipv6: run.ipv6, lsd: run.lsd.then(lsd_config), encryption: run.encryption, transport: run.transport, tracker_mode: run.tracker_mode, seed_limits: run.seed_limits, ..Default::default() };
        let manager = Manager::new(Arc::clone(&network), generate_peer_id(), defaults, Some(store));
        let server = match Server::start(&socket, Arc::clone(&manager), Arc::clone(&stop)) {
            Ok(server) => server,
            Err(e) => {
                network.shutdown();
                return Err(format!("control socket {}: {}", socket.display(), e));
            }
        };
        for warning in manager.restore() {
            eprintln!("warning: {}", warning);
        }
        if !run.quiet {
            println!("daemon running: port {}, control socket {}", network.port, socket.display());
        }

        let mut shown: Vec<([u8; 20], &'static str)> = Vec::new();
        while !stop.load(Ordering::SeqCst) && !bittorrent_rs::signal::received() {
            std::thread::sleep(Duration::from_millis(250));
            if !run.quiet {
                // A line whenever a torrent changes state, so that the daemon's own output says what it is up to.
                for status in manager.list() {
                    let now = (status.info_hash, status.state.name());
                    if !shown.contains(&now) {
                        shown.retain(|(hash, _)| *hash != status.info_hash);
                        shown.push(now);
                        println!("{} {}: {}", &bittorrent_rs::torrent::info_hash_hex(&status.info_hash)[..8], status.name, status.state.name());
                    }
                }
            }
        }

        if !run.quiet {
            println!("stopping");
        }
        server.stop();
        manager.shutdown();
        network.shutdown();
        Ok(())
    }

    /// Sends the command to a running daemon and prints what it says.
    fn client(args: &Args) -> Result<(), String> {
        let socket = socket_path(args);
        let request = match &args.command {
            Command::Add { source, out, options } => {
                // The daemon has a working directory of its own: it is given paths that mean the same to it.
                let source = if source.starts_with("magnet:?") { source.clone() } else { std::fs::canonicalize(source).map_err(|e| format!("{}: {}", source, e))?.to_string_lossy().into_owned() };
                let out = std::path::absolute(out.clone().unwrap_or_else(|| PathBuf::from("."))).map_err(|e| format!("output directory: {}", e))?;
                Request::Add { source, out, options: options.clone() }
            }
            Command::List => Request::List,
            Command::Status { id } => Request::Status { id: id.clone() },
            Command::Remove { id } => Request::Remove { id: id.clone() },
            Command::Pause { id } => Request::Pause { id: id.clone() },
            Command::Resume { id } => Request::Resume { id: id.clone() },
            Command::Stop => Request::Shutdown,
            Command::Run(_) => return Err("not a client command".to_string()),
        }
        .to_line();
        let replies = control::ask(&socket, &request)?;
        if args.json {
            for reply in &replies {
                println!("{}", reply_json(reply));
            }
            return Ok(());
        }
        match &args.command {
            Command::List if replies.is_empty() => println!("no torrents"),
            Command::List => {
                println!("{:<9} {:<12} {:>6} {:>11} {:>11}  NAME", "ID", "STATE", "DONE", "DOWN", "UP");
                for reply in &replies {
                    println!("{}", row(reply));
                }
            }
            Command::Stop => println!("stopping"),
            _ => {
                for reply in &replies {
                    println!("{}", row(reply));
                    if let Some(log) = text(reply, "log").filter(|l| !l.is_empty()) {
                        println!("\n{}", log);
                    }
                }
            }
        }
        Ok(())
    }

    fn text<'a>(reply: &'a Reply, key: &str) -> Option<&'a str> {
        reply.get(key).and_then(Value::as_str)
    }

    fn number(reply: &Reply, key: &str) -> f64 {
        reply.get(key).and_then(Value::as_f64).unwrap_or(0.0)
    }

    /// One torrent as a line of the table.
    pub fn row(reply: &Reply) -> String {
        let id = text(reply, "torrent").unwrap_or("?");
        let state = match text(reply, "reason") {
            Some(reason) => format!("{} ({})", text(reply, "state").unwrap_or("?"), reason),
            None => text(reply, "state").unwrap_or("?").to_string(),
        };
        format!("{:<9} {:<12} {:>5.1}% {:>11} {:>11}  {}", &id[..id.len().min(8)], state, number(reply, "progress") * 100.0, format_rate(number(reply, "down_rate")), format_rate(number(reply, "up_rate")), text(reply, "name").unwrap_or("?"))
    }

    /// A reply as the line it came as.
    fn reply_json(reply: &Reply) -> String {
        let mut object = bittorrent_rs::json::Object::new();
        for (key, value) in reply {
            object = match value {
                Value::String(s) => object.string(key, s),
                Value::Number(n) if n.fract() == 0.0 && *n >= 0.0 => object.uint(key, *n as u64),
                Value::Number(n) => object.float(key, *n, 4),
                Value::Bool(b) => object.boolean(key, *b),
                Value::Null => object.null(key),
            };
        }
        object.finish()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn parse(args: &[&str]) -> Result<Args, String> {
            parse_args(args.iter().map(|a| a.to_string()))
        }

        #[test]
        fn run_takes_the_daemons_settings_and_has_defaults_for_all() {
            let Command::Run(defaults) = parse(&["run"]).unwrap().command else { panic!("run") };
            assert_eq!((defaults.port, defaults.dht, defaults.lsd, defaults.portmap, defaults.ipv6, defaults.transport), (6881, true, true, true, Ipv6Mode::Auto, TransportMode::Tcp));
            assert_eq!(defaults.tracker_mode, TrackerMode::Tiered);
            assert_eq!((defaults.max_up, defaults.max_down, defaults.encryption, defaults.max_peers, defaults.quiet), (None, None, None, 30, false));

            let args = parse(&["run", "--state-dir", "/s", "--socket", "/s/x.sock", "--port", "7000", "--max-up", "1M", "--max-down", "2K", "--peers", "12", "--no-dht", "--no-lsd", "--no-portmap", "--no-ipv6", "--transport", "both", "--tracker-mode", "concurrent", "--encryption", "require", "--seed-ratio", "1.5", "--seed-time", "2h", "--quiet"]).unwrap();
            assert_eq!((args.state_dir, args.socket), (Some(PathBuf::from("/s")), Some(PathBuf::from("/s/x.sock"))));
            let Command::Run(run) = args.command else { panic!("run") };
            assert_eq!((run.port, run.max_up, run.max_down, run.max_peers), (7000, Some(1 << 20), Some(2048), 12));
            assert_eq!((run.dht, run.lsd, run.portmap, run.ipv6, run.transport, run.encryption, run.quiet), (false, false, false, Ipv6Mode::Never, TransportMode::Both, Some(Encryption::Require), true));
            assert_eq!(run.tracker_mode, TrackerMode::Concurrent);
            assert_eq!((run.seed_limits.ratio, run.seed_limits.time), (Some(1.5), Some(Duration::from_secs(7200))));
        }

        #[test]
        fn the_client_commands_take_what_they_need() {
            assert_eq!(parse(&["add", "a.torrent", "--out", "/d"]).unwrap().command, Command::Add { source: "a.torrent".into(), out: Some(PathBuf::from("/d")), options: JobOptions::default() });
            assert_eq!(parse(&["add", "--out", "/d", "magnet:?xt=urn:btih:00"]).unwrap().command, Command::Add { source: "magnet:?xt=urn:btih:00".into(), out: Some(PathBuf::from("/d")), options: JobOptions::default() }, "in either order");
            let Command::Add { options, .. } = parse(&["add", "a.torrent", "--only", ".mkv", "--only", "x y", "--prefer", "nfo", "--sequential", "--max-up", "100K", "--max-down", "1M"]).unwrap().command else { panic!("add") };
            assert_eq!(options, JobOptions { only: vec![".mkv".into(), "x y".into()], prefer: vec!["nfo".into()], sequential: true, max_up: Some(102_400), max_down: Some(1 << 20) });
            assert_eq!(parse(&["pause", "ab12"]).unwrap().command, Command::Pause { id: "ab12".into() });
            assert_eq!(parse(&["resume", "ab12"]).unwrap().command, Command::Resume { id: "ab12".into() });
            assert!(parse(&["list", "--json"]).unwrap().json);
            assert_eq!(parse(&["status", "ab12"]).unwrap().command, Command::Status { id: "ab12".into() });
            assert_eq!(parse(&["remove", "ab12", "--socket", "/x"]).unwrap().socket, Some(PathBuf::from("/x")));
            assert_eq!(parse(&["stop"]).unwrap().command, Command::Stop);
        }

        #[test]
        fn bad_arguments_are_refused_with_the_reason() {
            assert!(parse(&[]).unwrap_err().starts_with("usage:"));
            assert!(parse(&["--help"]).unwrap_err().starts_with("usage:"));
            assert!(parse(&["fly"]).unwrap_err().starts_with("no command \"fly\""));
            assert!(parse(&["add"]).unwrap_err().contains("needs a .torrent file or a magnet link"));
            assert!(parse(&["status"]).unwrap_err().contains("needs a torrent's ID"));
            assert!(parse(&["remove"]).unwrap_err().contains("needs a torrent's ID"));
            assert!(parse(&["list", "extra"]).unwrap_err().contains("takes no argument"));
            assert!(parse(&["add", "a", "b"]).unwrap_err().contains("unrecognized argument: b"));
            assert!(parse(&["run", "--bogus"]).unwrap_err().contains("unrecognized"));
            assert!(parse(&["run", "--port", "big"]).unwrap_err().starts_with("--port:"));
            assert!(parse(&["run", "--port", "70000"]).unwrap_err().starts_with("--port:"));
            assert!(parse(&["run", "--peers", "0"]).unwrap_err().starts_with("--peers:"));
            assert!(parse(&["run", "--max-up", "fast"]).unwrap_err().starts_with("--max-up:"));
            assert!(parse(&["run", "--transport", "udp"]).unwrap_err().starts_with("--transport:"));
            assert!(parse(&["run", "--encryption", "maybe"]).unwrap_err().starts_with("--encryption:"));
            assert!(parse(&["run", "--seed-ratio", "-1"]).is_err());
            assert!(parse(&["run", "--tracker-mode", "all"]).unwrap_err().starts_with("--tracker-mode:"));
            for flag in ["--tracker-mode", "--state-dir", "--socket", "--port", "--max-up", "--max-down", "--peers", "--transport", "--encryption", "--seed-ratio", "--seed-time"] {
                assert!(parse(&["run", flag]).unwrap_err().contains("requires"), "{} with no value", flag);
            }
            assert!(parse(&["add", "x", "--out"]).unwrap_err().contains("requires"));
            assert!(parse(&["pause"]).unwrap_err().contains("needs a torrent's ID"));
            assert!(parse(&["resume"]).unwrap_err().contains("needs a torrent's ID"));
            assert!(parse(&["list", "--only", "x"]).unwrap_err().contains("are for `add`"));
            assert!(parse(&["run", "--sequential"]).unwrap_err().contains("are for `add`"));
            assert!(parse(&["add", "x", "--only"]).unwrap_err().contains("requires"));
        }

        #[test]
        fn the_socket_is_in_the_state_directory_unless_named() {
            assert_eq!(socket_path(&parse(&["list", "--state-dir", "/s"]).unwrap()), PathBuf::from("/s/daemon.sock"));
            assert_eq!(socket_path(&parse(&["list", "--state-dir", "/s", "--socket", "/t/x"]).unwrap()), PathBuf::from("/t/x"));
        }

        fn reply(line: &str) -> Reply {
            bittorrent_rs::json::parse_object(line).unwrap()
        }

        #[test]
        fn a_row_shows_id_state_progress_rates_and_name() {
            let line = row(&reply(r#"{"torrent":"0123456789abcdef0123456789abcdef01234567","name":"a name","state":"downloading","reason":null,"progress":0.5,"down_rate":2048,"up_rate":0}"#));
            assert!(line.starts_with("01234567 ") && line.contains(" downloading "), "{}", line);
            assert!(line.contains(" 50.0% ") && line.contains("2.0 KiB/s") && line.ends_with("  a name"), "{}", line);
            let failed = row(&reply(r#"{"torrent":"0123456789abcdef0123456789abcdef01234567","name":"n","state":"failed","reason":"no peers","progress":0}"#));
            assert!(failed.contains("failed (no peers)"), "{}", failed);
        }

        #[test]
        fn a_reply_written_as_json_reads_back_as_it_was() {
            let original = reply(r#"{"torrent":"ab","state":"seeding","progress":0.25,"size":1000,"reason":null,"flag":true}"#);
            assert_eq!(reply(&reply_json(&original)), original);
        }
    }
}
