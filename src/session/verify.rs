//! `--verify`: check the files on disk against the torrent, and say which
//! are whole, which damaged and which missing. No network, no listener, no
//! resume file: it reads the files and hashes the pieces.

use crate::downloader::{build_file_spans, resume::piece_is_on_disk};
use crate::selection;
use crate::torrent::TorrentFile;
use std::path::Path;

/// How one file fares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    /// Every piece that covers it verifies (and it exists).
    Whole,
    /// It is not there.
    Missing,
    /// It is there but some of its pieces do not verify: wrong bytes, or
    /// too short.
    Damaged,
}

impl FileState {
    pub fn label(self) -> &'static str {
        match self {
            FileState::Whole => "ok",
            FileState::Missing => "missing",
            FileState::Damaged => "damaged",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStatus {
    pub path: String,
    pub bytes: u64,
    pub state: FileState,
}

/// What a check found. Pieces are counted over the wanted files only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Pieces that cover a wanted file.
    pub wanted_pieces: usize,
    pub verified_pieces: usize,
    /// Bytes in those pieces (piece-granular, so a piece shared with an
    /// unwanted file counts in full).
    pub wanted_bytes: u64,
    pub verified_bytes: u64,
    /// The wanted files, in torrent order.
    pub files: Vec<FileStatus>,
}

impl VerifyReport {
    /// Everything wanted is there and right.
    pub fn is_whole(&self) -> bool {
        self.verified_pieces == self.wanted_pieces && self.files.iter().all(|f| f.state == FileState::Whole)
    }

    /// The report as text: a summary line, then a line per file that is
    /// not whole (all of them, if `all_files`).
    pub fn describe(&self, torrent_name: &str, all_files: bool) -> String {
        let mut out = format!(
            "{}: {} of {} piece(s) verified ({} of {}), {} of {} file(s) whole",
            torrent_name,
            self.verified_pieces,
            self.wanted_pieces,
            crate::ui::format_bytes(self.verified_bytes),
            crate::ui::format_bytes(self.wanted_bytes),
            self.files.iter().filter(|f| f.state == FileState::Whole).count(),
            self.files.len()
        );
        for file in self.files.iter().filter(|f| all_files || f.state != FileState::Whole) {
            out.push_str(&format!("\n  [{}] {}", file.state.label(), file.path));
        }
        out
    }
}

/// Checks the wanted files of `torrent` (per `mask`, one entry per file) in
/// `base_dir` -- where its files go, that is, under the torrent's name for a
/// multi-file torrent. `progress(checked, of)` is called after each piece
/// and says whether to go on: a large torrent takes minutes to hash, and
/// stopping it must not have to wait for the end. `None` if it was stopped.
pub fn verify(torrent: &TorrentFile, mask: &[bool], base_dir: &Path, mut progress: impl FnMut(usize, usize) -> bool) -> Option<VerifyReport> {
    let spans = build_file_spans(base_dir, &torrent.files);
    let piece_length = torrent.piece_length as u64;
    let (wanted, wanted_bytes) = selection::selected_pieces(&torrent.files, piece_length, mask);

    let mut order: Vec<u32> = wanted.iter().copied().collect();
    order.sort_unstable();
    let mut verified = std::collections::HashSet::new();
    let mut verified_bytes = 0u64;
    for (done, &piece) in order.iter().enumerate() {
        if piece_is_on_disk(&spans, torrent, piece) {
            verified.insert(piece);
            verified_bytes += torrent.piece_len(piece as usize);
        }
        if !progress(done + 1, order.len()) {
            return None;
        }
    }

    let files = torrent
        .files
        .iter()
        .zip(&spans)
        .enumerate()
        .filter(|(index, _)| mask.get(*index).copied().unwrap_or(false))
        .map(|(_, ((parts, length), span))| {
            let path = selection::file_path(parts);
            let bytes = (*length).max(0) as u64;
            let exists = std::fs::metadata(&span.path).is_ok_and(|m| m.is_file());
            let state = if !exists {
                FileState::Missing
            } else if bytes == 0 {
                FileState::Whole
            } else {
                let (first, last) = (span.start / piece_length, (span.end - 1) / piece_length);
                if (first..=last).all(|p| verified.contains(&(p as u32))) {
                    FileState::Whole
                } else {
                    FileState::Damaged
                }
            };
            FileStatus { path, bytes, state }
        })
        .collect();

    Some(VerifyReport { wanted_pieces: order.len(), verified_pieces: verified.len(), wanted_bytes, verified_bytes, files })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::{create, CreateOptions};
    use crate::torrent::parse_torrent_file;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-verify-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bytes(len: usize, salt: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(salt)).collect()
    }

    /// A real torrent of three files (the middle one in a subdirectory), made
    /// by the creator from files it also leaves on disk under `<dir>/t`.
    /// Returns the torrent and the directory its files are in.
    fn three_file_torrent(name: &str) -> (TorrentFile, PathBuf) {
        let dir = tmp_dir(name);
        let root = dir.join("t");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("a.bin"), bytes(2048, 1)).unwrap(); // pieces 0-1
        fs::write(root.join("sub/b.bin"), bytes(2048, 2)).unwrap(); // pieces 2-3
        fs::write(root.join("z.bin"), bytes(900, 3)).unwrap(); // piece 4, a short one
        let created = create(&root, &CreateOptions { piece_length: Some(1024), ..Default::default() }, |_, _| {}).unwrap();
        (parse_torrent_file(&created.bytes).unwrap(), root)
    }

    fn states(report: &VerifyReport) -> Vec<(&str, FileState)> {
        report.files.iter().map(|f| (f.path.as_str(), f.state)).collect()
    }

    #[test]
    fn intact_files_verify_completely() {
        let (torrent, root) = three_file_torrent("intact");

        let report = verify(&torrent, &[true, true, true], &root, |_, _| true).unwrap();

        assert!(report.is_whole());
        assert_eq!((report.wanted_pieces, report.verified_pieces), (5, 5));
        assert_eq!((report.wanted_bytes, report.verified_bytes), (4996, 4996), "the last piece is 900 bytes, not 1024");
        assert_eq!(states(&report), vec![("a.bin", FileState::Whole), ("sub/b.bin", FileState::Whole), ("z.bin", FileState::Whole)]);
        assert!(report.describe("t", false).starts_with("t: 5 of 5 piece(s) verified (4.9 KiB of 4.9 KiB), 3 of 3 file(s) whole"));
        assert!(!report.describe("t", false).contains('['), "nothing to list when everything is whole");
        assert!(report.describe("t", true).contains("[ok] sub/b.bin"));
    }

    #[test]
    fn one_wrong_byte_damages_only_the_file_it_is_in() {
        let (torrent, root) = three_file_torrent("damaged");
        let mut b = fs::read(root.join("sub/b.bin")).unwrap();
        b[1500] ^= 0xFF; // in piece 3
        fs::write(root.join("sub/b.bin"), b).unwrap();

        let report = verify(&torrent, &[true, true, true], &root, |_, _| true).unwrap();

        assert!(!report.is_whole());
        assert_eq!((report.wanted_pieces, report.verified_pieces), (5, 4));
        assert_eq!(report.verified_bytes, 3 * 1024 + 900, "four pieces, one of them the short last one");
        assert_eq!(states(&report), vec![("a.bin", FileState::Whole), ("sub/b.bin", FileState::Damaged), ("z.bin", FileState::Whole)]);
        let text = report.describe("t", false);
        assert!(text.contains("[damaged] sub/b.bin") && !text.contains("a.bin") && !text.contains("z.bin"), "{}", text);
    }

    #[test]
    fn a_missing_file_is_missing_and_a_truncated_one_is_damaged() {
        let (torrent, root) = three_file_torrent("missing-truncated");
        fs::remove_file(root.join("a.bin")).unwrap();
        fs::write(root.join("z.bin"), &bytes(900, 3)[..400]).unwrap();

        let report = verify(&torrent, &[true, true, true], &root, |_, _| true).unwrap();

        assert_eq!(states(&report), vec![("a.bin", FileState::Missing), ("sub/b.bin", FileState::Whole), ("z.bin", FileState::Damaged)]);
        assert_eq!(report.verified_pieces, 2, "only b's pieces");
    }

    #[test]
    fn only_the_wanted_files_are_checked_and_counted() {
        let (torrent, root) = three_file_torrent("mask");
        fs::remove_file(root.join("a.bin")).unwrap(); // not wanted, so nobody minds

        let report = verify(&torrent, &[false, true, false], &root, |_, _| true).unwrap();

        assert!(report.is_whole());
        assert_eq!((report.wanted_pieces, report.verified_pieces, report.wanted_bytes), (2, 2, 2048));
        assert_eq!(states(&report), vec![("sub/b.bin", FileState::Whole)]);
    }

    #[test]
    fn progress_counts_up_over_the_wanted_pieces() {
        let (torrent, root) = three_file_torrent("progress");
        let mut seen = Vec::new();
        verify(&torrent, &[true, true, true], &root, |done, of| {
            seen.push((done, of));
            true
        })
        .unwrap();
        assert_eq!(seen, vec![(1, 5), (2, 5), (3, 5), (4, 5), (5, 5)]);
    }

    #[test]
    fn a_check_that_is_told_to_stop_stops_and_reports_nothing() {
        let (torrent, root) = three_file_torrent("stopped");
        let mut asked = 0;

        let report = verify(&torrent, &[true, true, true], &root, |done, _| {
            asked += 1;
            done < 2
        });

        assert!(report.is_none(), "an unfinished check has no report");
        assert_eq!(asked, 2, "and it did not go on hashing after being told to stop");
    }

    #[test]
    fn a_file_that_is_not_there_at_all_is_reported_for_every_file() {
        let (torrent, _) = three_file_torrent("nothing");
        let elsewhere = tmp_dir("nothing-else");

        let report = verify(&torrent, &[true, true, true], &elsewhere, |_, _| true).unwrap();

        assert_eq!(report.verified_pieces, 0);
        assert!(report.files.iter().all(|f| f.state == FileState::Missing));
        assert!(report.describe("t", false).contains("0 of 3 file(s) whole"));
    }

    #[test]
    fn empty_files_are_whole_if_they_exist_and_missing_if_not() {
        let dir = tmp_dir("empty-files");
        let root = dir.join("t");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.bin"), bytes(1500, 1)).unwrap();
        fs::write(root.join("keep"), b"").unwrap();
        let created = create(&root, &CreateOptions { piece_length: Some(1024), ..Default::default() }, |_, _| {}).unwrap();
        let torrent = parse_torrent_file(&created.bytes).unwrap();

        let whole = verify(&torrent, &[true, true], &root, |_, _| true).unwrap();
        assert_eq!(states(&whole), vec![("a.bin", FileState::Whole), ("keep", FileState::Whole)]);

        fs::remove_file(root.join("keep")).unwrap();
        let without = verify(&torrent, &[true, true], &root, |_, _| true).unwrap();
        assert_eq!(states(&without), vec![("a.bin", FileState::Whole), ("keep", FileState::Missing)]);
        assert_eq!(without.verified_pieces, without.wanted_pieces, "the pieces were fine; the empty file is what is missing");
        assert!(!without.is_whole());
    }
}
