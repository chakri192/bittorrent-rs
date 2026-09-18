//! Bookkeeping for pieces as they verify.

use crate::downloader::{PieceResult, ResumeWriter};
use crate::seeder::HaveMap;
use std::sync::Arc;

/// What a session has verified so far, and where it records it: the
/// count, the byte totals, the seeder-facing [`HaveMap`] and the resume
/// sidecar.
pub struct Progress {
    have: Arc<HaveMap>,
    resume: ResumeWriter,
    goal_pieces: usize,
    verified: usize,
    bytes_already_done: u64,
    bytes_this_run: u64,
}

impl Progress {
    /// `verified` and `bytes_already_done` describe the wanted pieces
    /// already on disk when the run starts (resumed ones); `goal_pieces`
    /// is how many the run needs in all.
    pub fn new(have: Arc<HaveMap>, resume: ResumeWriter, goal_pieces: usize, verified: usize, bytes_already_done: u64) -> Self {
        Progress { have, resume, goal_pieces, verified, bytes_already_done, bytes_this_run: 0 }
    }

    /// Takes in a piece a worker has verified and written to disk: counts
    /// it, advertises it to inbound peers, and records it so a later run
    /// can resume from it. A failure to record is reported through `log`
    /// but is not fatal, since the piece is on disk and the run continues.
    pub fn absorb(&mut self, piece: PieceResult, log: impl Fn(String)) {
        self.verified += 1;
        self.bytes_this_run += piece.data.len() as u64;
        self.have.set(piece.index);
        if let Err(e) = self.resume.record(piece.index) {
            log(format!("warning: failed to record resume progress for piece {}: {}", piece.index, e));
        }
        log(format!("piece {} verified ({}/{})", piece.index, self.verified, self.goal_pieces));
    }

    /// Wanted pieces verified: resumed ones plus this run's.
    pub fn verified(&self) -> usize {
        self.verified
    }

    /// Bytes fetched by this run alone.
    pub fn bytes_this_run(&self) -> u64 {
        self.bytes_this_run
    }

    /// Bytes of the wanted pieces on disk: resumed plus this run's.
    pub fn bytes_done(&self) -> u64 {
        self.bytes_already_done + self.bytes_this_run
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::progress_file_path;
    use std::cell::RefCell;
    use std::fs;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-progress-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn progress_in(dir: &std::path::Path, have: Arc<HaveMap>, goal: usize, verified: usize, already: u64) -> Progress {
        let writer = ResumeWriter::create(&progress_file_path(dir, &[0xAB; 20])).unwrap();
        Progress::new(have, writer, goal, verified, already)
    }

    fn sidecar(dir: &std::path::Path) -> String {
        fs::read_to_string(progress_file_path(dir, &[0xAB; 20])).unwrap()
    }

    #[test]
    fn a_new_progress_reports_only_what_was_resumed() {
        let dir = tmp_dir("new");
        let p = progress_in(&dir, Arc::new(HaveMap::new(4)), 4, 2, 512);
        assert_eq!(p.verified(), 2);
        assert_eq!(p.bytes_this_run(), 0);
        assert_eq!(p.bytes_done(), 512);
    }

    #[test]
    fn absorbing_a_piece_counts_advertises_and_records_it() {
        let dir = tmp_dir("absorb");
        let have = Arc::new(HaveMap::new(4));
        let mut p = progress_in(&dir, Arc::clone(&have), 4, 0, 0);

        p.absorb(PieceResult { index: 2, data: vec![0; 300] }, |_| {});

        assert_eq!(p.verified(), 1);
        assert_eq!(p.bytes_this_run(), 300);
        assert!(have.get(2) && !have.get(1), "only piece 2 is advertised to inbound peers");
        assert_eq!(sidecar(&dir).lines().collect::<Vec<_>>(), vec!["2"], "and it is on the resume sidecar");
    }

    #[test]
    fn bytes_done_adds_this_run_to_the_resumed_bytes() {
        let dir = tmp_dir("bytes");
        let mut p = progress_in(&dir, Arc::new(HaveMap::new(4)), 4, 1, 1000);
        p.absorb(PieceResult { index: 0, data: vec![0; 200] }, |_| {});
        p.absorb(PieceResult { index: 1, data: vec![0; 50] }, |_| {});
        assert_eq!((p.verified(), p.bytes_this_run(), p.bytes_done()), (3, 250, 1250));
    }

    #[test]
    fn the_log_line_counts_against_the_goal_not_the_total() {
        let dir = tmp_dir("log");
        // Selective run: 2 wanted pieces, 1 already resumed.
        let mut p = progress_in(&dir, Arc::new(HaveMap::new(9)), 2, 1, 0);
        let lines = RefCell::new(Vec::new());
        p.absorb(PieceResult { index: 7, data: vec![] }, |m| lines.borrow_mut().push(m));
        assert_eq!(lines.into_inner(), vec!["piece 7 verified (2/2)".to_string()]);
    }

    #[test]
    fn every_absorbed_piece_is_appended_to_the_sidecar_in_order() {
        let dir = tmp_dir("order");
        let mut p = progress_in(&dir, Arc::new(HaveMap::new(8)), 8, 0, 0);
        for index in [5, 1, 6] {
            p.absorb(PieceResult { index, data: vec![0; 1] }, |_| {});
        }
        assert_eq!(sidecar(&dir).lines().collect::<Vec<_>>(), vec!["5", "1", "6"]);
    }
}
