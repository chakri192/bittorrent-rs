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
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

/// Give up on a web seed after this many consecutive fetch failures
/// (dead mirror, no range support, persistent hash mismatch) so it stops
/// churning the queue.
const MAX_CONSECUTIVE_FAILURES: u32 = 5;

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
pub fn build_targets(base_url: &str, name: &str, files: &[(Vec<String>, i64)]) -> Vec<FileTarget> {
    let multi = files.len() > 1;
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

/// Runs one web seed against the shared work queue until the queue drains,
/// the seed fails too many times, or `stop` is set. `log` receives
/// human-readable progress/errors (routed to the dashboard log).
#[allow(clippy::too_many_arguments)]
pub fn run_web_worker<L: Fn(String)>(
    base_url: &str,
    name: &str,
    files: &[(Vec<String>, i64)],
    queue: &Arc<WorkQueue>,
    spans: &Arc<Vec<FileSpan>>,
    piece_length: u64,
    total_length: u64,
    results_tx: &Sender<PieceResult>,
    stop: &AtomicBool,
    log: L,
) {
    let targets = build_targets(base_url, name, files);
    let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout_read(Duration::from_secs(60)).build();
    let mut consecutive_failures = 0u32;

    while !stop.load(Ordering::SeqCst) {
        let Some(work) = queue.pop() else {
            break; // queue fully drained
        };
        let idx = work.index;
        if queue.is_done(idx) {
            continue; // finished elsewhere (endgame duplicate)
        }

        match fetch_piece(&agent, &targets, idx, piece_length, total_length) {
            Ok(data) => {
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
                        return;
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
            return;
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
        let t = build_targets("http://mirror.test/movie.mkv", "movie.mkv", &files_single());
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].url, "http://mirror.test/movie.mkv");
        assert_eq!((t[0].start, t[0].end), (0, 1000));
    }

    #[test]
    fn single_file_appends_name_when_base_is_a_directory() {
        let t = build_targets("http://mirror.test/dir/", "movie.mkv", &files_single());
        assert_eq!(t[0].url, "http://mirror.test/dir/movie.mkv");
    }

    #[test]
    fn multi_file_urls_include_name_and_encoded_path() {
        let t = build_targets("http://mirror.test/pub", "Show", &files_multi());
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
        let t = build_targets("http://m.test/f", "f", &files_single());
        let reqs = piece_requests(&t, 1, 250, 1000);
        assert_eq!(reqs, vec![("http://m.test/f".to_string(), 250, 250)]);
    }

    #[test]
    fn piece_requests_split_across_a_file_boundary() {
        // multi: file0 [0,600), file1 [600,1200). piece_length 500 ->
        // piece 1 = [500,1000): 100 bytes from file0 (offset 500) + 400
        // from file1 (offset 0).
        let t = build_targets("http://m.test/", "Show", &files_multi());
        let reqs = piece_requests(&t, 1, 500, 1200);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0], (t[0].url.clone(), 500, 100));
        assert_eq!(reqs[1], (t[1].url.clone(), 0, 400));
    }

    #[test]
    fn last_piece_is_clamped_to_total_length() {
        // single file 1000, piece_length 400 -> piece 2 = [800,1000) = 200B.
        let t = build_targets("http://m.test/f", "f", &files_single());
        let reqs = piece_requests(&t, 2, 400, 1000);
        assert_eq!(reqs, vec![("http://m.test/f".to_string(), 800, 200)]);
    }

    #[test]
    fn encode_segment_escapes_reserved_and_keeps_unreserved() {
        assert_eq!(encode_segment("a b/c?"), "a%20b%2Fc%3F");
        assert_eq!(encode_segment("Ep.01-final_v2~"), "Ep.01-final_v2~");
    }
}
