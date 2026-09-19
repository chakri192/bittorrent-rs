//! Where a session reports what it is doing.

use crate::tui::Ui;
use crate::ui::Snapshot;

/// Everything a session tells the outside world: log lines, and the live
/// numbers behind the dashboard. The terminal dashboard implements it;
/// tests use a recording implementation, so a session can run with no
/// terminal at all.
pub trait ProgressSink: Send + Sync {
    fn log(&self, msg: String);
    /// The frame of numbers the dashboard shows now.
    fn set_snapshot(&self, snapshot: Snapshot);
    /// One point for the throughput sparklines, in bytes per second.
    fn push_rates(&self, down: u64, up: u64);
    /// Which pieces are on disk, for the piece-map heatmap.
    fn set_pieces(&self, have: Vec<bool>);
}

impl ProgressSink for Ui {
    fn log(&self, msg: String) {
        Ui::log(self, msg)
    }

    fn set_snapshot(&self, snapshot: Snapshot) {
        Ui::set_snapshot(self, snapshot)
    }

    fn push_rates(&self, down: u64, up: u64) {
        Ui::push_rates(self, down, up)
    }

    fn set_pieces(&self, have: Vec<bool>) {
        Ui::set_pieces(self, have)
    }
}

/// A sink that keeps everything it is told, for tests.
#[cfg(test)]
#[derive(Default)]
pub struct RecordingSink {
    pub lines: std::sync::Mutex<Vec<String>>,
    pub snapshots: std::sync::Mutex<Vec<Snapshot>>,
    pub rates: std::sync::Mutex<Vec<(u64, u64)>>,
    pub pieces: std::sync::Mutex<Vec<Vec<bool>>>,
}

#[cfg(test)]
impl RecordingSink {
    /// Whether any logged line contains `needle`.
    pub fn logged(&self, needle: &str) -> bool {
        self.lines.lock().unwrap().iter().any(|l| l.contains(needle))
    }

    /// The most recent snapshot.
    pub fn last_snapshot(&self) -> Snapshot {
        self.snapshots.lock().unwrap().last().cloned().expect("no snapshot was published")
    }
}

#[cfg(test)]
impl ProgressSink for RecordingSink {
    fn log(&self, msg: String) {
        self.lines.lock().unwrap().push(msg);
    }

    fn set_snapshot(&self, snapshot: Snapshot) {
        self.snapshots.lock().unwrap().push(snapshot);
    }

    fn push_rates(&self, down: u64, up: u64) {
        self.rates.lock().unwrap().push((down, up));
    }

    fn set_pieces(&self, have: Vec<bool>) {
        self.pieces.lock().unwrap().push(have);
    }
}
