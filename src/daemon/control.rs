//! The socket the daemon is told what to do on. A client connects to a Unix socket and sends one
//! flat JSON object to a line; each gets, in return, some lines about the torrents it asked about
//! (each with a `"torrent"` key) and then a last line that says `"ok":true`, or `"ok":false` with
//! an `"error"`. Only whoever owns the socket file can use it, and it is made readable by its
//! owner alone.
//!
//! ```text
//! {"cmd":"add","source":"magnet:?xt=urn:btih:...","out":"/downloads"}
//! {"cmd":"list"}
//! {"cmd":"status","id":"3f2a"}
//! {"cmd":"remove","id":"3f2a"}
//! {"cmd":"shutdown"}
//! ```

use super::job::{JobState, JobStatus};
use super::manager::Manager;
use crate::json::{self, Object, Value};
use crate::sync::lock;
use crate::torrent::info_hash_hex;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// The longest request line taken: a magnet link and a path are far shorter, and a client that
/// sends more is not one to keep listening to.
const MAX_REQUEST: u64 = 64 * 1024;
/// How long a connection may sit silent before the daemon lets it go.
const IDLE: Duration = Duration::from_secs(30);
/// How many lines of a torrent's log a `status` includes.
const STATUS_LOG_LINES: usize = 10;

/// What a client can ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Add { source: String, out: PathBuf },
    List,
    Status { id: String },
    Remove { id: String },
    Shutdown,
}

/// Reads a request from one line.
pub fn parse_request(line: &str) -> Result<Request, String> {
    let fields = json::parse_object(line).map_err(|e| format!("not a JSON object: {}", e))?;
    let text = |key: &str| -> Result<String, String> { fields.get(key).and_then(Value::as_str).map(str::to_string).ok_or_else(|| format!("\"{}\" is needed, as a string", key)) };
    match fields.get("cmd").and_then(Value::as_str) {
        Some("add") => Ok(Request::Add { source: text("source")?, out: PathBuf::from(text("out")?) }),
        Some("list") => Ok(Request::List),
        Some("status") => Ok(Request::Status { id: text("id")? }),
        Some("remove") => Ok(Request::Remove { id: text("id")? }),
        Some("shutdown") => Ok(Request::Shutdown),
        Some(other) => Err(format!("no command {:?}: they are add, list, status, remove and shutdown", other)),
        None => Err("\"cmd\" is needed, as a string".to_string()),
    }
}

/// The line about one torrent. `detail` adds the latest of what it logged.
pub fn torrent_line(status: &JobStatus, detail: bool) -> String {
    let reason = match &status.state {
        JobState::Failed(reason) | JobState::Finished(reason) => Some(reason.as_str()),
        _ => None,
    };
    let snapshot = &status.snapshot;
    let mut line = Object::new()
        .string("torrent", &info_hash_hex(&status.info_hash))
        .string("name", &status.name)
        .string("state", status.state.name())
        .opt_string("reason", reason)
        .float("progress", status.progress(), 4)
        .uint("size", snapshot.total_length)
        .uint("done", snapshot.done_bytes)
        .float("down_rate", snapshot.down_rate, 0)
        .float("up_rate", snapshot.up_rate, 0)
        .uint("uploaded", snapshot.up_bytes)
        .uint("peers", snapshot.active_peers as u64)
        .string("out", &status.out_dir.to_string_lossy());
    if detail {
        let from = status.log.len().saturating_sub(STATUS_LOG_LINES);
        line = line.string("log", &status.log[from..].join("\n"));
    }
    line.finish()
}

fn failure(reason: &str) -> String {
    Object::new().boolean("ok", false).string("error", reason).finish()
}

fn success() -> String {
    Object::new().boolean("ok", true).finish()
}

/// Does what a request asks; the lines to answer with, the last of them being the verdict.
/// `stop` is set by `shutdown`.
pub fn handle(manager: &Manager, request: Request, stop: &AtomicBool) -> Vec<String> {
    let one = |result: Result<JobStatus, String>| match result {
        Ok(status) => vec![torrent_line(&status, false), success()],
        Err(reason) => vec![failure(&reason)],
    };
    match request {
        Request::Add { source, out } => one(manager.add(&source, out)),
        Request::Remove { id } => one(manager.remove(&id)),
        Request::Status { id } => match manager.status(&id) {
            Ok(status) => vec![torrent_line(&status, true), success()],
            Err(reason) => vec![failure(&reason)],
        },
        Request::List => {
            let mut lines: Vec<String> = manager.list().iter().map(|status| torrent_line(status, false)).collect();
            lines.push(success());
            lines
        }
        Request::Shutdown => {
            stop.store(true, Ordering::SeqCst);
            vec![success()]
        }
    }
}

/// Serves one client until it hangs up.
fn serve(stream: UnixStream, manager: &Manager, stop: &AtomicBool) {
    // A connection that goes quiet, or is left open, does not hold a thread for ever.
    let _ = stream.set_read_timeout(Some(IDLE));
    let Ok(mut writer) = stream.try_clone() else { return };
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        // (Read through `take`, so a line with no end cannot fill the memory.)
        match reader.by_ref().take(MAX_REQUEST + 1).read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) if line.len() as u64 > MAX_REQUEST => {
                let _ = writeln!(writer, "{}", failure("that request is too long"));
                return;
            }
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        let replies = match parse_request(line.trim()) {
            Ok(request) => handle(manager, request, stop),
            Err(reason) => vec![failure(&reason)],
        };
        for reply in replies {
            if writeln!(writer, "{}", reply).is_err() {
                return;
            }
        }
    }
}

/// The daemon's end of the socket.
pub struct Server {
    path: PathBuf,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl Server {
    /// Listens on `path`. If a socket file is there already it is replaced, unless somebody
    /// answers on it, which means a daemon is running.
    pub fn start(path: &Path, manager: Arc<Manager>, stop: Arc<AtomicBool>) -> io::Result<Server> {
        if path.exists() {
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("a daemon is already listening on {}", path.display())));
            }
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let running = Arc::new(AtomicBool::new(true));
        let thread = {
            let running = Arc::clone(&running);
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            // Blocking, with a timeout of its own, on a thread of its own.
                            if stream.set_nonblocking(false).is_err() {
                                continue;
                            }
                            let (manager, stop) = (Arc::clone(&manager), Arc::clone(&stop));
                            thread::spawn(move || serve(stream, &manager, &stop));
                        }
                        Err(_) => thread::sleep(Duration::from_millis(50)),
                    }
                }
            })
        };
        Ok(Server { path: path.to_path_buf(), running, thread: Mutex::new(Some(thread)) })
    }

    /// Stops listening and removes the socket file. Safe to call twice.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(thread) = lock(&self.thread).take() {
            let _ = thread.join();
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// One line of an answer, read.
pub type Reply = BTreeMap<String, Value>;

/// Sends `request` (one JSON object) to the daemon on `socket`, and returns the lines it answers with, the last
/// being its verdict. `Err` is a reason the daemon could not be asked, or that it said no.
pub fn ask(socket: &Path, request: &str) -> Result<Vec<Reply>, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| format!("no daemon on {}: {}", socket.display(), e))?;
    stream.set_read_timeout(Some(Duration::from_secs(120))).map_err(|e| e.to_string())?;
    writeln!(stream, "{}", request.trim()).map_err(|e| format!("sending the request: {}", e))?;
    let mut replies = Vec::new();
    for line in BufReader::new(stream).lines() {
        let line = line.map_err(|e| format!("reading the answer: {}", e))?;
        let reply = json::parse_object(&line).map_err(|e| format!("the daemon's answer is not JSON ({}): {}", e, line))?;
        match reply.get("ok").and_then(Value::as_bool) {
            Some(true) => return Ok(replies),
            Some(false) => return Err(reply.get("error").and_then(Value::as_str).unwrap_or("the daemon said no").to_string()),
            None => replies.push(reply),
        }
    }
    Err("the daemon hung up before it had answered".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::JobDefaults;
    use crate::session::network::tests::{no_dht, quiet_network};
    use crate::session::SharedNetwork;
    use crate::ui::Snapshot;

    const MAGNET: &str = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&tr=http%3A%2F%2F127.0.0.1%3A9%2Fannounce";

    fn request(line: &str) -> Request {
        parse_request(line).unwrap()
    }

    #[test]
    fn every_command_is_read() {
        assert_eq!(request(r#"{"cmd":"add","source":"magnet:?x","out":"/d"}"#), Request::Add { source: "magnet:?x".into(), out: PathBuf::from("/d") });
        assert_eq!(request(r#"{"cmd":"list"}"#), Request::List);
        assert_eq!(request(r#"{"cmd":"status","id":"ab12"}"#), Request::Status { id: "ab12".into() });
        assert_eq!(request(r#"{"cmd":"remove","id":"ab12"}"#), Request::Remove { id: "ab12".into() });
        assert_eq!(request(r#"  {"cmd" : "shutdown"}  "#), Request::Shutdown);
        assert_eq!(request(r#"{"cmd":"add","source":"s","out":"/d","extra":1}"#), Request::Add { source: "s".into(), out: PathBuf::from("/d") }, "what is not asked for is ignored");
    }

    #[test]
    fn a_request_that_is_not_understood_says_what_is_wrong() {
        for (line, wants) in [
            ("nonsense", "not a JSON object"),
            ("[]", "not a JSON object"),
            ("{}", "\"cmd\""),
            (r#"{"cmd":5}"#, "\"cmd\""),
            (r#"{"cmd":"fly"}"#, "no command \"fly\""),
            (r#"{"cmd":"add","out":"/d"}"#, "\"source\""),
            (r#"{"cmd":"add","source":"s"}"#, "\"out\""),
            (r#"{"cmd":"add","source":7,"out":"/d"}"#, "\"source\""),
            (r#"{"cmd":"status"}"#, "\"id\""),
            (r#"{"cmd":"remove"}"#, "\"id\""),
        ] {
            let error = parse_request(line).unwrap_err();
            assert!(error.contains(wants), "{}: {}", line, error);
        }
    }

    fn status(state: JobState) -> JobStatus {
        JobStatus {
            info_hash: [0xAB; 20],
            name: "a \"quoted\" name".to_string(),
            state,
            out_dir: PathBuf::from("/down loads"),
            snapshot: Snapshot { total_length: 1000, done_bytes: 250, down_rate: 1234.6, up_rate: 7.0, up_bytes: 99, active_peers: 3, ..Default::default() },
            log: (1..=15).map(|n| format!("line {}", n)).collect(),
        }
    }

    #[test]
    fn a_torrent_line_says_what_there_is_to_say_and_parses_back() {
        let line = json::parse_object(&torrent_line(&status(JobState::Downloading), false)).unwrap();
        assert_eq!(line["torrent"].as_str(), Some("ab".repeat(20).as_str()));
        assert_eq!((line["name"].as_str(), line["state"].as_str(), line["out"].as_str()), (Some("a \"quoted\" name"), Some("downloading"), Some("/down loads")));
        assert_eq!((line["size"].as_f64(), line["done"].as_f64(), line["uploaded"].as_f64(), line["peers"].as_f64()), (Some(1000.0), Some(250.0), Some(99.0), Some(3.0)));
        assert_eq!((line["progress"].as_f64(), line["down_rate"].as_f64(), line["up_rate"].as_f64()), (Some(0.25), Some(1235.0), Some(7.0)));
        assert_eq!(line["reason"], Value::Null);
        assert!(!line.contains_key("log"), "not unless asked for");
    }

    #[test]
    fn a_seeding_torrent_is_all_there_and_a_failed_one_says_why() {
        let seeding = json::parse_object(&torrent_line(&status(JobState::Seeding), false)).unwrap();
        assert_eq!(seeding["progress"].as_f64(), Some(1.0), "whatever the snapshot last said");
        let failed = json::parse_object(&torrent_line(&status(JobState::Failed("no peers".into())), false)).unwrap();
        assert_eq!((failed["state"].as_str(), failed["reason"].as_str()), (Some("failed"), Some("no peers")));
        let finished = json::parse_object(&torrent_line(&status(JobState::Finished("seed ratio 1.00 reached".into())), false)).unwrap();
        assert_eq!((finished["state"].as_str(), finished["reason"].as_str()), (Some("finished"), Some("seed ratio 1.00 reached")));
    }

    #[test]
    fn detail_adds_the_latest_lines_of_the_log_and_no_more() {
        let line = json::parse_object(&torrent_line(&status(JobState::Downloading), true)).unwrap();
        let log = line["log"].as_str().unwrap();
        assert_eq!(log.lines().count(), STATUS_LOG_LINES);
        assert!(log.starts_with("line 6") && log.ends_with("line 15"), "{}", log);
    }

    fn manager() -> (Arc<Manager>, Arc<SharedNetwork>) {
        let network = quiet_network(no_dht());
        (Manager::new(Arc::clone(&network), [9; 20], JobDefaults { lsd: None, ..Default::default() }, None), network)
    }

    /// The lines, read.
    fn read(lines: &[String]) -> Vec<Reply> {
        lines.iter().map(|l| json::parse_object(l).unwrap()).collect()
    }

    #[test]
    fn handling_requests_answers_with_torrent_lines_then_a_verdict() {
        let (manager, network) = manager();
        let stop = AtomicBool::new(false);

        let added = read(&handle(&manager, Request::Add { source: MAGNET.into(), out: PathBuf::from("/tmp") }, &stop));
        assert_eq!((added.len(), added[0]["torrent"].as_str(), added[1]["ok"].as_bool()), (2, Some("0123456789abcdef0123456789abcdef01234567"), Some(true)));

        let listed = read(&handle(&manager, Request::List, &stop));
        assert_eq!(listed.len(), 2, "the torrent and the verdict");
        let status = read(&handle(&manager, Request::Status { id: "0123".into() }, &stop));
        assert!(status[0].contains_key("log") && status[1]["ok"].as_bool() == Some(true), "a status has the log");

        let refused = read(&handle(&manager, Request::Status { id: "9999".into() }, &stop));
        assert_eq!((refused.len(), refused[0]["ok"].as_bool()), (1, Some(false)));
        assert!(refused[0]["error"].as_str().unwrap().contains("no torrent"));

        let removed = read(&handle(&manager, Request::Remove { id: "0123".into() }, &stop));
        assert_eq!((removed[0]["state"].as_str(), removed[1]["ok"].as_bool()), (Some("stopped"), Some(true)));
        assert_eq!(read(&handle(&manager, Request::List, &stop)).len(), 1, "an empty list is only the verdict");

        assert!(!stop.load(Ordering::SeqCst));
        assert_eq!(read(&handle(&manager, Request::Shutdown, &stop))[0]["ok"].as_bool(), Some(true));
        assert!(stop.load(Ordering::SeqCst), "and that is what shutdown does");
        manager.shutdown();
        network.shutdown();
    }

    /// A short path, as a Unix socket's must be.
    fn socket_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("bt-{}-{}.sock", name, std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn a_client_talks_to_the_daemon_over_the_socket() {
        let (manager, network) = manager();
        let stop = Arc::new(AtomicBool::new(false));
        let path = socket_path("talk");
        let server = Server::start(&path, Arc::clone(&manager), Arc::clone(&stop)).unwrap();

        let added = ask(&path, &format!(r#"{{"cmd":"add","source":"{}","out":"/tmp"}}"#, MAGNET)).unwrap();
        assert_eq!(added[0]["torrent"].as_str(), Some("0123456789abcdef0123456789abcdef01234567"));
        assert_eq!(ask(&path, r#"{"cmd":"list"}"#).unwrap().len(), 1);
        assert!(ask(&path, r#"{"cmd":"remove","id":"ffff"}"#).unwrap_err().contains("no torrent"), "a refusal is an Err with the reason");
        assert!(ask(&path, "garbage").unwrap_err().contains("not a JSON object"));

        assert!(!stop.load(Ordering::SeqCst));
        ask(&path, r#"{"cmd":"shutdown"}"#).unwrap();
        assert!(stop.load(Ordering::SeqCst));

        server.stop();
        assert!(!path.exists(), "the socket file goes with the server");
        assert!(ask(&path, r#"{"cmd":"list"}"#).unwrap_err().starts_with("no daemon"));
        server.stop();
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn a_connection_can_make_several_requests() {
        let (manager, network) = manager();
        let path = socket_path("several");
        let server = Server::start(&path, Arc::clone(&manager), Arc::new(AtomicBool::new(false))).unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        writeln!(stream, r#"{{"cmd":"list"}}"#).unwrap();
        writeln!(stream, "\n{{\"cmd\":\"list\"}}").unwrap(); // (blank lines are skipped)
        let mut lines = BufReader::new(stream).lines();
        for _ in 0..2 {
            assert_eq!(read(&[lines.next().unwrap().unwrap()])[0]["ok"].as_bool(), Some(true));
        }
        server.stop();
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn the_socket_is_the_owners_alone() {
        let (manager, network) = manager();
        let path = socket_path("perm");
        let server = Server::start(&path, Arc::clone(&manager), Arc::new(AtomicBool::new(false))).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        server.stop();
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn a_dead_daemons_socket_file_is_replaced_but_a_live_ones_is_not() {
        let (manager, network) = manager();
        let path = socket_path("stale");
        // A file left by a daemon that died: nothing answers on it.
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        let server = Server::start(&path, Arc::clone(&manager), Arc::new(AtomicBool::new(false))).expect("the stale one is replaced");

        let second = Server::start(&path, Arc::clone(&manager), Arc::new(AtomicBool::new(false)));
        assert_eq!(second.err().map(|e| e.kind()), Some(io::ErrorKind::AddrInUse), "one daemon at a time");
        assert!(ask(&path, r#"{"cmd":"list"}"#).is_ok(), "and the first is undisturbed");

        server.stop();
        manager.shutdown();
        network.shutdown();
    }

    #[test]
    fn a_request_that_is_far_too_long_is_refused_and_the_connection_closed() {
        let (manager, network) = manager();
        let path = socket_path("long");
        let server = Server::start(&path, Arc::clone(&manager), Arc::new(AtomicBool::new(false))).unwrap();
        let mut stream = UnixStream::connect(&path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let huge = format!("{{\"cmd\":\"add\",\"source\":\"{}\",\"out\":\"/d\"}}\n", "x".repeat(MAX_REQUEST as usize));
        let _ = stream.write_all(huge.as_bytes()); // (the daemon may hang up before it is all sent)
        let mut answer = String::new();
        let _ = BufReader::new(stream).read_line(&mut answer);
        assert!(answer.contains("too long"), "{:?}", answer);
        assert_eq!(manager.list().len(), 0, "and nothing was added");
        server.stop();
        manager.shutdown();
        network.shutdown();
    }
}
