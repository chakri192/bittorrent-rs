//! Shared UI primitives: human-readable formatters, the append-only file
//! `Logger` that captures the high-volume per-peer churn, and `Snapshot`
//! (the frame of live numbers the dashboard renders). The actual terminal
//! rendering lives in `tui`.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use crate::sync::lock;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Human-readable byte size, binary units (KiB/MiB/...).
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

/// Human-readable transfer rate.
pub fn format_rate(bytes_per_sec: f64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec.max(0.0) as u64))
}

/// Compact duration (e.g. `18m32s`, `2h04m`, `45s`).
pub fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{}h{:02}m", h, m)
    } else if m > 0 {
        format!("{}m{:02}s", m, s)
    } else {
        format!("{}s", s)
    }
}

/// Append-only, timestamped log sink shared across threads. `disabled()`
/// makes every `line` call a no-op, so callers never branch on whether
/// logging is on.
#[derive(Clone)]
pub struct Logger {
    inner: Option<Arc<Mutex<File>>>,
    start: Instant,
}

impl Logger {
    pub fn disabled() -> Self {
        Logger { inner: None, start: Instant::now() }
    }

    pub fn to_file(path: &Path) -> io::Result<Self> {
        let file = File::create(path)?;
        Ok(Logger { inner: Some(Arc::new(Mutex::new(file))), start: Instant::now() })
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Writes one `[+<elapsed>s] <msg>` line, flushed immediately so a
    /// killed process still leaves a complete log. Lock poisoning and IO
    /// errors are swallowed: logging must never take down a download.
    pub fn line(&self, msg: &str) {
        if let Some(file) = &self.inner {
            let mut f = lock(file);
            let _ = writeln!(f, "[+{:>8.2}s] {}", self.start.elapsed().as_secs_f64(), msg);
            let _ = f.flush();
        }
    }
}

/// A single frame's worth of numbers for the dashboard to render. The
/// caller rebuilds this each tick from its live state.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub total_length: u64,
    pub total_pieces: usize,
    pub verified: usize,
    /// Bytes verified on disk so far (resumed + this run).
    pub done_bytes: u64,
    pub down_rate: f64,
    pub up_bytes: u64,
    pub up_rate: f64,
    pub active_peers: usize,
    pub dialed_peers: usize,
    pub known_peers: usize,
    pub endgame: bool,
    pub trackers_ok: usize,
    pub trackers_total: usize,
    pub dht_nodes: usize,
    pub pex_total: usize,
    pub web_seeds: usize,
    pub eta_secs: Option<u64>,
    /// Seconds since the download phase started (for the header clock).
    pub elapsed_secs: u64,
    /// One-word phase: "connecting", "downloading", "waiting", ...
    pub status: &'static str,
    /// The connected peers, fastest first, for the dashboard's peer table.
    pub peers: Vec<crate::downloader::PeerRow>,
}

impl Snapshot {
    pub fn fraction(&self) -> f64 {
        if self.total_length > 0 {
            (self.done_bytes as f64 / self.total_length as f64).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_scales_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(23_346_250_742), "21.7 GiB");
    }

    #[test]
    fn format_rate_appends_per_second_and_clamps_negative() {
        assert_eq!(format_rate(0.0), "0 B/s");
        assert_eq!(format_rate(1024.0), "1.0 KiB/s");
        assert_eq!(format_rate(-5.0), "0 B/s");
    }

    #[test]
    fn format_duration_picks_granularity() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(92), "1m32s");
        assert_eq!(format_duration(3 * 3600 + 4 * 60), "3h04m");
    }

    #[test]
    fn fraction_is_clamped_and_safe_at_zero_length() {
        let s = Snapshot { total_length: 0, done_bytes: 10, ..Default::default() };
        assert_eq!(s.fraction(), 0.0);
        let s = Snapshot { total_length: 200, done_bytes: 50, ..Default::default() };
        assert_eq!(s.fraction(), 0.25);
        let s = Snapshot { total_length: 200, done_bytes: 999, ..Default::default() };
        assert_eq!(s.fraction(), 1.0);
    }

    #[test]
    fn disabled_logger_is_noop() {
        let log = Logger::disabled();
        assert!(!log.is_enabled());
        log.line("must not panic, goes nowhere");
    }

    #[test]
    fn logger_writes_timestamped_lines() {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-ui-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("run.log");
        let log = Logger::to_file(&path).unwrap();
        assert!(log.is_enabled());
        log.line("hello");
        log.line("world");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.matches('\n').count(), 2);
        assert!(contents.contains("hello") && contents.contains("world") && contents.contains("[+"));
    }
}
