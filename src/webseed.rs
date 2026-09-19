//! BEP 19 WebSeed (GetRight style): fetch pieces over HTTP(S) from the
//! torrent's `url-list`, in parallel with (or instead of) peers. A web
//! worker pops pieces from the same shared `WorkQueue`, fetches each via
//! ranged GET(s), and feeds the result into the identical
//! verify-write-record pipeline the peer workers use -- so hashing,
//! endgame, resume, and progress accounting all work unchanged, and a
//! torrent with a healthy web seed downloads even with zero peers.

use crate::downloader::file_writer::{write_piece, FileSpan};
use crate::downloader::queue::{PieceResult, WorkQueue};
use sha1::{Digest, Sha1};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Give up on a web seed after this many consecutive fetch failures
/// (dead mirror, no range support, persistent hash mismatch) so it stops
/// churning the queue.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

/// How a web worker's run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebEnd {
    /// The queue ran out of pieces.
    Drained,
    /// It was told to stop.
    Stopped,
    /// The mirror failed too many times in a row.
    Disabled,
    /// A verified piece could not be written to disk. Not the mirror's
    /// fault, and no other source can do better.
    DiskFailed(String),
}

/// One file's HTTP location plus its byte range in the torrent's
/// concatenated address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTarget {
    pub url: String,
    pub start: u64,
    pub end: u64,
}

/// Percent-encodes a single path segment (everything but the RFC 3986
/// unreserved set), leaving `/` to be added by the caller between
/// segments.
fn encode_segment(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for &b in seg.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Builds the per-file HTTP targets for a web-seed base URL, following
/// BEP 19's URL construction:
///
///  - single-file: if the base ends in `/`, the file URL is `base + name`;
///    otherwise the base *is* the file's direct URL.
///  - multi-file: the base is a directory; each file's URL is
///    `base[/] + name + '/' + path segments`.
///
/// `multi` is the torrent's form, not its file count: a multi-file torrent
/// with one entry still lives under its name.
pub fn build_targets(base_url: &str, name: &str, files: &[(Vec<String>, i64)], multi: bool) -> Vec<FileTarget> {
    let mut targets = Vec::with_capacity(files.len());
    let mut cursor = 0u64;

    for (parts, len) in files {
        let length = *len as u64;
        let url = if multi {
            let mut u = base_url.to_string();
            if !u.ends_with('/') {
                u.push('/');
            }
            u.push_str(&encode_segment(name));
            for seg in parts {
                u.push('/');
                u.push_str(&encode_segment(seg));
            }
            u
        } else if base_url.ends_with('/') {
            format!("{}{}", base_url, encode_segment(name))
        } else {
            base_url.to_string()
        };
        targets.push(FileTarget { url, start: cursor, end: cursor + length });
        cursor += length;
    }
    targets
}

/// The HTTP requests needed to fetch piece `piece_index`: `(url,
/// file_offset, length)` for each file the piece overlaps, in order. Pure
/// (no I/O) so the piece-to-file mapping is unit-testable.
pub fn piece_requests(targets: &[FileTarget], piece_index: u32, piece_length: u64, total_length: u64) -> Vec<(String, u64, u64)> {
    let ps = piece_index as u64 * piece_length;
    let pe = (ps + piece_length).min(total_length);
    let mut reqs = Vec::new();
    for t in targets {
        let seg_start = ps.max(t.start);
        let seg_end = pe.min(t.end);
        if seg_start >= seg_end {
            continue;
        }
        reqs.push((t.url.clone(), seg_start - t.start, seg_end - seg_start));
    }
    reqs
}

fn fetch_piece(agent: &ureq::Agent, targets: &[FileTarget], piece_index: u32, piece_length: u64, total_length: u64) -> Result<Vec<u8>, String> {
    let reqs = piece_requests(targets, piece_index, piece_length, total_length);
    let mut out = Vec::new();
    for (url, offset, len) in reqs {
        let range = format!("bytes={}-{}", offset, offset + len - 1);
        let resp = agent.get(&url).set("Range", &range).call().map_err(|e| format!("GET {}: {}", url, e))?;
        let status = resp.status();

        let mut buf = Vec::with_capacity(len as usize);
        // `take(len)` bounds memory even if a misbehaving server streams
        // more than the requested range.
        resp.into_reader().take(len).read_to_end(&mut buf).map_err(|e| format!("reading {}: {}", url, e))?;

        match status {
            206 => {
                if buf.len() as u64 != len {
                    return Err(format!("{} returned {} bytes for a {}-byte range", url, buf.len(), len));
                }
            }
            // 200 means the server ignored Range and sent the whole file.
            // Only acceptable if the "range" we wanted is the entire file.
            200 => {
                let whole_file = offset == 0 && len == targets.iter().find(|t| t.url == url).map(|t| t.end - t.start).unwrap_or(len);
                if !whole_file {
                    return Err(format!("{} ignored Range (HTTP 200); web seed can't serve partial pieces", url));
                }
                if buf.len() as u64 != len {
                    return Err(format!("{} returned {} bytes, expected {}", url, buf.len(), len));
                }
            }
            other => return Err(format!("{} returned HTTP {}", url, other)),
        }
        out.extend_from_slice(&buf);
    }
    Ok(out)
}

/// [`fetch_piece`] on a thread of its own, waited for in short slices so
/// that `stop` is noticed. An HTTP request cannot be cancelled from
/// outside, and a mirror that has stopped answering holds it for the whole
/// read timeout; without this, stopping the client waited that out.
/// Returns `None` if `stop` was set first, leaving the fetch to finish (or
/// time out) unwatched.
fn fetch_piece_or_stop(agent: &ureq::Agent, targets: &Arc<Vec<FileTarget>>, piece_index: u32, piece_length: u64, total_length: u64, stop: &AtomicBool) -> Option<Result<Vec<u8>, String>> {
    let (tx, rx) = mpsc::channel();
    let (agent, targets) = (agent.clone(), Arc::clone(targets));
    thread::spawn(move || {
        let _ = tx.send(fetch_piece(&agent, &targets, piece_index, piece_length, total_length));
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => return Some(result),
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::SeqCst) {
                    return None;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return Some(Err("the fetch thread died".to_string())),
        }
    }
}

/// Runs one web seed against the shared work queue until the queue drains,
/// the seed fails too many times, or `stop` is set, and says which. `log`
/// receives human-readable progress/errors (routed to the dashboard log).
#[allow(clippy::too_many_arguments)]
pub fn run_web_worker<L: Fn(String)>(
    base_url: &str,
    name: &str,
    files: &[(Vec<String>, i64)],
    multi_file: bool,
    limiter: Option<&crate::ratelimit::RateLimiter>,
    queue: &Arc<WorkQueue>,
    spans: &Arc<Vec<FileSpan>>,
    piece_length: u64,
    total_length: u64,
    results_tx: &Sender<PieceResult>,
    stop: &AtomicBool,
    log: L,
) -> WebEnd {
    let targets = Arc::new(build_targets(base_url, name, files, multi_file));
    let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout_read(Duration::from_secs(60)).build();
    let mut consecutive_failures = 0u32;

    while !stop.load(Ordering::SeqCst) {
        let Some(work) = queue.pop() else {
            return WebEnd::Drained;
        };
        let idx = work.index;
        if queue.is_done(idx) {
            continue; // finished elsewhere (endgame duplicate)
        }

        let Some(fetched) = fetch_piece_or_stop(&agent, &targets, idx, piece_length, total_length, stop) else {
            queue.push_back(work);
            return WebEnd::Stopped; // told to stop while waiting on the mirror
        };
        match fetched {
            Ok(data) => {
                if let Some(limiter) = limiter {
                    limiter.acquire_while(data.len(), || !stop.load(Ordering::SeqCst));
                    if stop.load(Ordering::SeqCst) {
                        queue.push_back(work);
                        return WebEnd::Stopped; // told to stop while held back by --max-down
                    }
                }
                let mut h = Sha1::new();
                h.update(&data);
                let got: [u8; 20] = h.finalize().into();
                if got != work.hash {
                    queue.push_back(work);
                    consecutive_failures += 1;
                    log(format!("web seed {}: piece {} failed hash check", base_url, idx));
                } else {
                    if let Err(e) = write_piece(spans, idx, piece_length, &data) {
                        queue.push_back(work);
                        log(format!("web seed {}: disk write failed on piece {}: {}", base_url, idx, e));
                        return WebEnd::DiskFailed(e.to_string());
                    }
                    // First copy wins (peers may be racing the same piece).
                    if queue.mark_done(idx) {
                        let _ = results_tx.send(PieceResult { index: idx, data });
                    }
                    consecutive_failures = 0;
                }
            }
            Err(e) => {
                queue.push_back(work);
                consecutive_failures += 1;
                log(format!("web seed {}: {}", base_url, e));
            }
        }

        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            log(format!("web seed {} disabled after {} consecutive failures", base_url, consecutive_failures));
            return WebEnd::Disabled;
        }
    }
    WebEnd::Stopped
}

/// A small HTTP server on loopback for tests of web-seed fetching, here so
/// that other modules' tests can use it too.
#[cfg(test)]
pub(crate) mod mirror {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    #[derive(Clone, Copy, PartialEq)]
    pub(crate) enum Mode {
        /// Honours Range with a 206.
        Serve,
        /// Sends the whole file with a 200 whatever the range.
        IgnoreRange,
        /// 404 for everything.
        NotFound,
        /// Range honoured, but every byte is wrong.
        Corrupt,
        /// Accepts the connection and never answers.
        Silent,
    }

    pub(crate) struct Mirror {
        /// `http://127.0.0.1:port/`
        pub(crate) base: String,
        pub(crate) requests: Arc<AtomicUsize>,
    }

    pub(crate) fn spawn_mirror(files: Vec<(&str, Vec<u8>)>, mode: Mode) -> Mirror {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let files: Vec<(String, Vec<u8>)> = files.into_iter().map(|(path, content)| (format!("/{}", path), content)).collect();
        thread::spawn(move || {
            let mut held = Vec::new(); // silent connections stay open
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                counted.fetch_add(1, Ordering::SeqCst);
                if mode == Mode::Silent {
                    held.push(stream);
                    continue;
                }
                let files = files.clone();
                thread::spawn(move || serve(stream, &files, mode));
            }
        });
        Mirror { base, requests }
    }

    fn serve(stream: TcpStream, files: &[(String, Vec<u8>)], mode: Mode) {
        let Ok(read_half) = stream.try_clone() else { return };
        let mut reader = BufReader::new(read_half);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        let path = request_line.split_whitespace().nth(1).unwrap_or("").to_string();
        let mut range = None;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            if let Some(spec) = line.to_ascii_lowercase().trim_end().strip_prefix("range: bytes=") {
                if let Some((from, to)) = spec.split_once('-') {
                    range = from.parse::<usize>().ok().zip(to.parse::<usize>().ok());
                }
            }
        }
        let mut stream = stream;
        let respond = |stream: &mut TcpStream, status: &str, extra: &str, body: &[u8]| {
            let head = format!("HTTP/1.1 {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n", status, body.len(), extra);
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        };
        let Some((_, content)) = files.iter().find(|(p, _)| *p == path) else {
            respond(&mut stream, "404 Not Found", "", b"");
            return;
        };
        match mode {
            Mode::NotFound => respond(&mut stream, "404 Not Found", "", b""),
            Mode::IgnoreRange => respond(&mut stream, "200 OK", "", content),
            Mode::Serve | Mode::Corrupt => {
                let (from, to) = range.unwrap_or((0, content.len() - 1));
                let mut body = content[from..=to.min(content.len() - 1)].to_vec();
                if mode == Mode::Corrupt {
                    body.iter_mut().for_each(|b| *b ^= 0xFF);
                }
                respond(&mut stream, "206 Partial Content", &format!("Content-Range: bytes {}-{}/{}\r\n", from, to, content.len()), &body);
            }
            Mode::Silent => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files_single() -> Vec<(Vec<String>, i64)> {
        vec![(vec!["movie.mkv".into()], 1000)]
    }
    // `TorrentFile.files` paths are relative to the torrent name (the name
    // is *not* a path component); build_targets prepends it per BEP 19.
    fn files_multi() -> Vec<(Vec<String>, i64)> {
        vec![(vec!["ep 1.mkv".into()], 600), (vec!["ep2.mkv".into()], 600)]
    }

    #[test]
    fn single_file_direct_url_when_base_has_no_trailing_slash() {
        let t = build_targets("http://mirror.test/movie.mkv", "movie.mkv", &files_single(), false);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].url, "http://mirror.test/movie.mkv");
        assert_eq!((t[0].start, t[0].end), (0, 1000));
    }

    #[test]
    fn single_file_appends_name_when_base_is_a_directory() {
        let t = build_targets("http://mirror.test/dir/", "movie.mkv", &files_single(), false);
        assert_eq!(t[0].url, "http://mirror.test/dir/movie.mkv");
    }

    #[test]
    fn multi_file_urls_include_name_and_encoded_path() {
        let t = build_targets("http://mirror.test/pub", "Show", &files_multi(), true);
        assert_eq!(t.len(), 2);
        // Note the space in "ep 1.mkv" is percent-encoded, and the base
        // gained a '/'.
        assert_eq!(t[0].url, "http://mirror.test/pub/Show/ep%201.mkv");
        assert_eq!(t[1].url, "http://mirror.test/pub/Show/ep2.mkv");
        assert_eq!((t[0].start, t[0].end), (0, 600));
        assert_eq!((t[1].start, t[1].end), (600, 1200));
    }

    #[test]
    fn piece_requests_map_within_a_single_file() {
        // single file 1000 bytes, piece_length 250 -> piece 1 = [250,500).
        let t = build_targets("http://m.test/f", "f", &files_single(), false);
        let reqs = piece_requests(&t, 1, 250, 1000);
        assert_eq!(reqs, vec![("http://m.test/f".to_string(), 250, 250)]);
    }

    #[test]
    fn piece_requests_split_across_a_file_boundary() {
        // multi: file0 [0,600), file1 [600,1200). piece_length 500 ->
        // piece 1 = [500,1000): 100 bytes from file0 (offset 500) + 400
        // from file1 (offset 0).
        let t = build_targets("http://m.test/", "Show", &files_multi(), true);
        let reqs = piece_requests(&t, 1, 500, 1200);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0], (t[0].url.clone(), 500, 100));
        assert_eq!(reqs[1], (t[1].url.clone(), 0, 400));
    }

    #[test]
    fn last_piece_is_clamped_to_total_length() {
        // single file 1000, piece_length 400 -> piece 2 = [800,1000) = 200B.
        let t = build_targets("http://m.test/f", "f", &files_single(), false);
        let reqs = piece_requests(&t, 2, 400, 1000);
        assert_eq!(reqs, vec![("http://m.test/f".to_string(), 800, 200)]);
    }

    #[test]
    fn encode_segment_escapes_reserved_and_keeps_unreserved() {
        assert_eq!(encode_segment("a b/c?"), "a%20b%2Fc%3F");
        assert_eq!(encode_segment("Ep.01-final_v2~"), "Ep.01-final_v2~");
    }

    #[test]
    fn a_multi_file_torrent_with_one_entry_is_still_under_its_name() {
        // BEP 19: the form decides, not the file count. Treating this as a
        // single-file torrent would ask the server for `base/file` instead
        // of `base/name/file`.
        let files = vec![(vec!["only.bin".to_string()], 500)];
        let t = build_targets("http://m.test/pub/", "Album", &files, true);
        assert_eq!(t[0].url, "http://m.test/pub/Album/only.bin");
        let as_single = build_targets("http://m.test/pub/", "only.bin", &files, false);
        assert_eq!(as_single[0].url, "http://m.test/pub/only.bin");
    }

    // ---- against an HTTP server on loopback ----

    use crate::downloader::file_writer::build_file_spans;
    use crate::downloader::piece_assembler::PieceWork;
    use crate::webseed::mirror::{spawn_mirror, Mode};
    use std::sync::Mutex;
    use std::time::Instant;

    fn sha1_of(data: &[u8]) -> [u8; 20] {
        Sha1::digest(data).into()
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-webseed-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A web worker's world: the queue of `data`'s pieces, spans on disk, and
    /// the channel results arrive on.
    struct Rig {
        data: Vec<u8>,
        piece_length: u64,
        queue: Arc<WorkQueue>,
        spans: Arc<Vec<FileSpan>>,
        dir: std::path::PathBuf,
        tx: Sender<PieceResult>,
        rx: mpsc::Receiver<PieceResult>,
        logs: Arc<Mutex<Vec<String>>>,
    }

    impl Rig {
        /// `files` in torrent order, as (path components, content).
        fn new(name: &str, files: &[(Vec<&str>, Vec<u8>)], piece_length: u64) -> Rig {
            let data: Vec<u8> = files.iter().flat_map(|(_, c)| c.iter().copied()).collect();
            let work = data.chunks(piece_length as usize).enumerate().map(|(i, chunk)| PieceWork { index: i as u32, hash: sha1_of(chunk), length: chunk.len() as u32 }).collect::<Vec<_>>();
            let piece_count = work.len();
            let dir = tmp_dir(name);
            let listed: Vec<(Vec<String>, i64)> = files.iter().map(|(path, c)| (path.iter().map(|p| p.to_string()).collect(), c.len() as i64)).collect();
            let spans = Arc::new(build_file_spans(&dir, &listed));
            let (tx, rx) = mpsc::channel();
            Rig { data, piece_length, queue: Arc::new(WorkQueue::new(work, piece_count)), spans, dir, tx, rx, logs: Arc::new(Mutex::new(Vec::new())) }
        }

        fn run(&self, base: &str, name: &str, files: &[(Vec<String>, i64)], multi: bool, limiter: Option<&crate::ratelimit::RateLimiter>, stop: &AtomicBool) -> WebEnd {
            let logs = Arc::clone(&self.logs);
            run_web_worker(base, name, files, multi, limiter, &self.queue, &self.spans, self.piece_length, self.data.len() as u64, &self.tx, stop, move |m| logs.lock().unwrap().push(m))
        }

        fn logged(&self, needle: &str) -> bool {
            self.logs.lock().unwrap().iter().any(|l| l.contains(needle))
        }

        fn completed(&self) -> Vec<u32> {
            let mut got: Vec<u32> = self.rx.try_iter().map(|r| r.index).collect();
            got.sort_unstable();
            got
        }
    }

    fn single(name: &str, len: usize) -> (Vec<(Vec<String>, i64)>, Vec<u8>) {
        let content: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13).wrapping_add(5)).collect();
        (vec![(vec![name.to_string()], len as i64)], content)
    }

    #[test]
    fn a_web_seed_serves_a_whole_torrent_through_the_normal_pipeline() {
        let (listed, content) = single("file.bin", 5000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Serve);
        let rig = Rig::new("serves", &[(vec!["file.bin"], content.clone())], 2048);

        let end = rig.run(&mirror.base, "file.bin", &listed, false, None, &AtomicBool::new(false));

        assert_eq!(end, WebEnd::Drained);
        assert_eq!(rig.completed(), vec![0, 1, 2]);
        assert!(rig.queue.is_empty());
        assert_eq!(std::fs::read(rig.dir.join("file.bin")).unwrap(), content, "written to disk, every byte");
        assert_eq!(mirror.requests.load(Ordering::SeqCst), 3, "one ranged request per piece");
    }

    #[test]
    fn a_piece_that_spans_two_files_is_fetched_from_both() {
        let (a, b) = ((0..1500).map(|i| i as u8).collect::<Vec<u8>>(), (0..2500).map(|i| (i as u8).wrapping_add(90)).collect::<Vec<u8>>());
        let mirror = spawn_mirror(vec![("pack/a.bin", a.clone()), ("pack/sub/b.bin", b.clone())], Mode::Serve);
        let rig = Rig::new("spans", &[(vec!["a.bin"], a.clone()), (vec!["sub", "b.bin"], b.clone())], 2048);
        let listed = vec![(vec!["a.bin".to_string()], 1500), (vec!["sub".to_string(), "b.bin".to_string()], 2500)];

        rig.run(&mirror.base, "pack", &listed, true, None, &AtomicBool::new(false));

        assert_eq!(rig.completed(), vec![0, 1]);
        assert_eq!(std::fs::read(rig.dir.join("a.bin")).unwrap(), a);
        assert_eq!(std::fs::read(rig.dir.join("sub/b.bin")).unwrap(), b);
        assert_eq!(mirror.requests.load(Ordering::SeqCst), 3, "piece 0 needed both files, piece 1 only the second");
    }

    #[test]
    fn a_server_that_ignores_range_is_fine_only_when_the_range_is_the_whole_file() {
        let (listed, content) = single("small.bin", 1000);
        let mirror = spawn_mirror(vec![("small.bin", content.clone())], Mode::IgnoreRange);
        // One piece, the whole file: a 200 with everything is what was asked for.
        let whole = Rig::new("ignore-whole", &[(vec!["small.bin"], content.clone())], 1024);
        whole.run(&mirror.base, "small.bin", &listed, false, None, &AtomicBool::new(false));
        assert_eq!(whole.completed(), vec![0]);

        // Several pieces: each needs part of the file, which this server cannot give.
        let (listed, content) = single("big.bin", 4000);
        let mirror = spawn_mirror(vec![("big.bin", content.clone())], Mode::IgnoreRange);
        let partial = Rig::new("ignore-partial", &[(vec!["big.bin"], content)], 1024);
        partial.run(&mirror.base, "big.bin", &listed, false, None, &AtomicBool::new(false));
        assert!(partial.logged("ignored Range"));
        assert!(partial.completed().is_empty());
        assert_eq!(partial.queue.len(), 4, "every piece went back for someone else");
    }

    #[test]
    fn a_mirror_that_serves_wrong_bytes_is_caught_by_the_hash_and_given_up_on() {
        let (listed, content) = single("file.bin", 3000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Corrupt);
        let rig = Rig::new("corrupt", &[(vec!["file.bin"], content)], 1024);

        let end = rig.run(&mirror.base, "file.bin", &listed, false, None, &AtomicBool::new(false));

        assert_eq!(end, WebEnd::Disabled);
        assert!(rig.logged("failed hash check"));
        assert!(rig.logged("disabled after 5 consecutive failures"));
        assert!(rig.completed().is_empty(), "nothing unverified was accepted");
        assert_eq!(rig.queue.len(), 3);
        assert!(!rig.dir.join("file.bin").exists() || std::fs::read(rig.dir.join("file.bin")).unwrap().iter().all(|&b| b == 0), "and nothing unverified was written");
    }

    #[test]
    fn a_mirror_that_says_not_found_is_given_up_on_after_five_tries() {
        let (listed, content) = single("file.bin", 3000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::NotFound);
        let rig = Rig::new("not-found", &[(vec!["file.bin"], content)], 1024);

        let end = rig.run(&mirror.base, "file.bin", &listed, false, None, &AtomicBool::new(false));

        assert_eq!(end, WebEnd::Disabled);
        assert!(rig.logged("404"));
        assert!(rig.logged("disabled after 5 consecutive failures"));
        assert_eq!(mirror.requests.load(Ordering::SeqCst), 5, "it stopped asking after the fifth failure");
        assert_eq!(rig.queue.len(), 3);
    }

    #[test]
    fn a_download_limit_holds_a_web_seed_back_but_not_what_it_delivers() {
        let (listed, content) = single("file.bin", 8000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Serve);
        let rig = Rig::new("limited", &[(vec!["file.bin"], content.clone())], 4000);
        // A second's worth in the bucket, so the other 4000 bytes cost a second.
        let limiter = crate::ratelimit::RateLimiter::new(4000);

        let started = Instant::now();
        rig.run(&mirror.base, "file.bin", &listed, false, Some(&limiter), &AtomicBool::new(false));
        let took = started.elapsed();

        assert_eq!(rig.completed(), vec![0, 1]);
        assert_eq!(std::fs::read(rig.dir.join("file.bin")).unwrap(), content);
        assert!(took >= Duration::from_millis(900), "8000 bytes at 4000 B/s with a 4000-byte burst: {:?}", took);
    }

    /// Runs a web worker on a thread and reports how long it took to return
    /// after `stop` was set 300 ms in, or `None` if it had not by five seconds.
    fn time_to_stop(rig: Rig, base: String, name: &'static str, files: Vec<(Vec<String>, i64)>, limiter: Option<crate::ratelimit::RateLimiter>) -> (Option<Duration>, Arc<WorkQueue>) {
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::clone(&rig.queue);
        let (done_tx, done_rx) = mpsc::channel();
        let worker_stop = Arc::clone(&stop);
        thread::spawn(move || {
            rig.run(&base, name, &files, false, limiter.as_ref(), &worker_stop);
            let _ = done_tx.send(());
        });
        thread::sleep(Duration::from_millis(300));
        let stopped_at = Instant::now();
        stop.store(true, Ordering::SeqCst);
        let returned = done_rx.recv_timeout(Duration::from_secs(5)).ok().map(|_| stopped_at.elapsed());
        (returned, queue)
    }

    #[test]
    fn stopping_does_not_wait_for_a_mirror_that_has_gone_silent() {
        let (listed, content) = single("file.bin", 3000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Silent);
        let rig = Rig::new("silent", &[(vec!["file.bin"], content)], 1024);

        let (returned, queue) = time_to_stop(rig, mirror.base.clone(), "file.bin", listed, None);

        let took = returned.expect("the worker must stop within seconds, not after the 60 s read timeout");
        assert!(took < Duration::from_secs(2), "{:?}", took);
        assert_eq!(queue.len(), 3, "the piece it was fetching went back");
    }

    #[test]
    fn stopping_does_not_wait_out_a_long_rate_limit_delay() {
        let (listed, content) = single("file.bin", 4000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Serve);
        let rig = Rig::new("limit-stop", &[(vec!["file.bin"], content)], 4000);
        // 10 B/s: the piece just fetched would have to be paid for over ~400 s.
        let limiter = crate::ratelimit::RateLimiter::new(10);

        let (returned, queue) = time_to_stop(rig, mirror.base.clone(), "file.bin", listed, Some(limiter));

        let took = returned.expect("the worker must stop within seconds, not sleep out its debt");
        assert!(took < Duration::from_secs(2), "{:?}", took);
        assert_eq!(queue.len(), 1, "the piece was not counted as done");
    }

    #[test]
    fn a_web_worker_that_cannot_write_says_the_disk_failed_and_gives_the_piece_back() {
        let (listed, content) = single("file.bin", 3000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Serve);
        let rig = Rig::new("disk-fails", &[(vec!["file.bin"], content)], 1024);
        std::fs::create_dir_all(rig.dir.join("file.bin")).unwrap(); // a directory where the file goes

        let end = rig.run(&mirror.base, "file.bin", &listed, false, None, &AtomicBool::new(false));

        assert!(matches!(end, WebEnd::DiskFailed(ref why) if !why.is_empty()), "{:?}", end);
        assert!(rig.logged("disk write failed"));
        assert_eq!(rig.queue.len(), 3, "the piece it could not write is back on the queue");
        assert_eq!(mirror.requests.load(Ordering::SeqCst), 1, "and it did not go on asking");
    }

    #[test]
    fn a_web_worker_told_to_stop_before_it_starts_says_it_stopped() {
        let (listed, content) = single("file.bin", 3000);
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Serve);
        let rig = Rig::new("stopped-end", &[(vec!["file.bin"], content)], 1024);

        let end = rig.run(&mirror.base, "file.bin", &listed, false, None, &AtomicBool::new(true));

        assert_eq!(end, WebEnd::Stopped);
        assert_eq!(mirror.requests.load(Ordering::SeqCst), 0);
    }
}
