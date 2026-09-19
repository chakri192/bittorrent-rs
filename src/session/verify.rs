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
    if torrent.is_v2_only() {
        return verify_v2(torrent, mask, base_dir, progress);
    }
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

/// [`verify`] for a torrent that is BitTorrent v2 only (BEP 52). Each file is
/// a tree of its own, so each is checked on its own, piece by piece against
/// the file's piece layer where the torrent carries one, and as a whole
/// against its root where it does not.
fn verify_v2(torrent: &TorrentFile, mask: &[bool], base_dir: &Path, mut progress: impl FnMut(usize, usize) -> bool) -> Option<VerifyReport> {
    use crate::v2::{expected_piece_hash, hash_file, piece_hash, V2File};
    use std::io::Read;

    let meta = torrent.v2.as_ref()?;
    let piece_length = torrent.piece_length as u64;
    let spans = build_file_spans(base_dir, &torrent.files);
    let wanted: Vec<usize> = (0..torrent.files.len()).filter(|&i| mask.get(i).copied().unwrap_or(false)).collect();
    let pieces_of = |file: &V2File| file.length.div_ceil(piece_length) as usize;
    let total: usize = wanted.iter().map(|&i| pieces_of(&meta.files[i])).sum();

    let (mut checked, mut verified, mut verified_bytes, mut wanted_bytes) = (0usize, 0usize, 0u64, 0u64);
    let mut files = Vec::new();
    for &index in &wanted {
        let file = &meta.files[index];
        let path = selection::file_path(&file.path);
        wanted_bytes += file.length;
        let pieces = pieces_of(file);
        let state = match std::fs::File::open(&spans[index].path) {
            Err(_) => FileState::Missing,
            Ok(_) if file.length == 0 => FileState::Whole,
            Ok(mut handle) => {
                let layer = meta.layer_of(file);
                let mut whole = true;
                if pieces > 1 && layer.is_none() {
                    // No piece layer to check against: the file stands or falls as a whole.
                    let ok = hash_file(&mut handle, file.length, piece_length as usize).is_ok_and(|hashes| hashes.root == file.root);
                    if ok {
                        verified += pieces;
                        verified_bytes += file.length;
                    }
                    whole = ok;
                    checked += pieces;
                    if !progress(checked, total) {
                        return None;
                    }
                } else {
                    let mut buf = vec![0u8; piece_length as usize];
                    for piece in 0..pieces {
                        let len = (file.length - piece as u64 * piece_length).min(piece_length) as usize;
                        let ok = handle.read_exact(&mut buf[..len]).is_ok() && {
                            let hash = if pieces == 1 { hash_file(&mut &buf[..len], len as u64, piece_length as usize).ok().and_then(|h| h.root) } else { Some(piece_hash(&buf[..len], piece_length as usize)) };
                            hash.is_some() && hash == expected_piece_hash(file, layer, piece)
                        };
                        if ok {
                            verified += 1;
                            verified_bytes += len as u64;
                        }
                        whole &= ok;
                        checked += 1;
                        if !progress(checked, total) {
                            return None;
                        }
                    }
                }
                if whole {
                    FileState::Whole
                } else {
                    FileState::Damaged
                }
            }
        };
        files.push(FileStatus { path, bytes: file.length, state });
    }
    Some(VerifyReport { wanted_pieces: total, verified_pieces: verified, wanted_bytes, verified_bytes, files })
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

    // ---- BitTorrent v2 ----

    /// A v2-only torrent of three files and an empty one, with piece length 16 KiB, made by
    /// the creator from files it also leaves on disk under `<dir>/t`.
    fn v2_torrent(name: &str) -> (TorrentFile, PathBuf) {
        let dir = tmp_dir(name);
        let root = dir.join("t");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("a.bin"), bytes(40_000, 1)).unwrap(); // three pieces, the last a short one
        fs::write(root.join("sub/b.bin"), bytes(5000, 2)).unwrap(); // one piece, and part of one
        fs::write(root.join("z.bin"), bytes(16_384 * 2, 3)).unwrap(); // exactly two pieces
        fs::write(root.join("empty"), b"").unwrap();
        let created = create(&root, &CreateOptions { piece_length: Some(16384), v2: true, ..Default::default() }, |_, _| {}).unwrap();
        let torrent = parse_torrent_file(&created.bytes).unwrap();
        assert!(torrent.is_v2_only());
        (torrent, root)
    }

    #[test]
    fn intact_v2_files_verify_completely_piece_by_piece() {
        let (torrent, root) = v2_torrent("v2-intact");
        let mask = vec![true; torrent.files.len()];

        let report = verify(&torrent, &mask, &root, |_, _| true).unwrap();

        assert!(report.is_whole(), "{}", report.describe("t", true));
        assert_eq!((report.wanted_pieces, report.verified_pieces), (3 + 1 + 2, 6), "no piece for the empty file");
        assert_eq!((report.wanted_bytes, report.verified_bytes), (40_000 + 5000 + 32_768, 40_000 + 5000 + 32_768));
        assert_eq!(states(&report), vec![("a.bin", FileState::Whole), ("empty", FileState::Whole), ("sub/b.bin", FileState::Whole), ("z.bin", FileState::Whole)]);
    }

    #[test]
    fn a_wrong_byte_in_a_v2_file_damages_that_file_and_only_its_piece_stops_counting() {
        let (torrent, root) = v2_torrent("v2-damaged");
        let mut a = fs::read(root.join("a.bin")).unwrap();
        a[20_000] ^= 0xFF; // in the second piece
        fs::write(root.join("a.bin"), a).unwrap();
        let mask = vec![true; torrent.files.len()];

        let report = verify(&torrent, &mask, &root, |_, _| true).unwrap();

        assert!(!report.is_whole());
        assert_eq!(states(&report)[0], ("a.bin", FileState::Damaged));
        assert_eq!(report.verified_pieces, 5, "the layer says which piece is wrong, so the other two of a.bin count");
        assert_eq!(report.verified_bytes, 16_384 + 40_000 - 32_768 + 5000 + 32_768, "the first piece and the short last one of a.bin");
    }

    #[test]
    fn missing_and_truncated_v2_files_are_told_apart() {
        let (torrent, root) = v2_torrent("v2-missing");
        fs::remove_file(root.join("z.bin")).unwrap();
        let b = fs::read(root.join("sub/b.bin")).unwrap();
        fs::write(root.join("sub/b.bin"), &b[..100]).unwrap();
        let a = fs::read(root.join("a.bin")).unwrap();
        fs::write(root.join("a.bin"), &a[..30_000]).unwrap(); // the second piece is cut short, and the third is not there

        let mask = vec![true; torrent.files.len()];
        let report = verify(&torrent, &mask, &root, |_, _| true).unwrap();

        assert_eq!(states(&report), vec![("a.bin", FileState::Damaged), ("empty", FileState::Whole), ("sub/b.bin", FileState::Damaged), ("z.bin", FileState::Missing)]);
        assert_eq!(report.verified_pieces, 1, "only a.bin's first piece: the rest of the file is short");
    }

    #[test]
    fn a_v2_torrent_without_its_layers_is_checked_a_file_at_a_time_against_the_root() {
        let (mut torrent, root) = v2_torrent("v2-nolayers");
        torrent.v2.as_mut().unwrap().layers.clear();
        let mask = vec![true; torrent.files.len()];
        assert!(verify(&torrent, &mask, &root, |_, _| true).unwrap().is_whole());

        let mut z = fs::read(root.join("z.bin")).unwrap();
        z[0] ^= 1;
        fs::write(root.join("z.bin"), z).unwrap();
        let report = verify(&torrent, &mask, &root, |_, _| true).unwrap();
        assert_eq!(states(&report)[3], ("z.bin", FileState::Damaged));
        assert_eq!(report.verified_pieces, 3 + 1, "z.bin's two pieces are all or nothing without a layer");
    }

    #[test]
    fn v2_verification_counts_only_the_wanted_files_and_can_be_stopped() {
        let (torrent, root) = v2_torrent("v2-mask");
        fs::remove_file(root.join("a.bin")).unwrap();
        let report = verify(&torrent, &[false, false, true, false], &root, |_, _| true).unwrap();
        assert!(report.is_whole());
        assert_eq!((report.wanted_pieces, report.wanted_bytes), (1, 5000));

        let mut calls = 0;
        let stopped = verify(&torrent, &[false, false, false, true], &root, |_, _| {
            calls += 1;
            false
        });
        assert!(stopped.is_none() && calls == 1, "stopped after the first piece: {}", calls);
    }

    #[test]
    fn a_small_v2_file_in_a_torrent_of_big_pieces_is_checked_by_its_own_short_tree() {
        // 20000 bytes is two blocks, so a two-leaf tree, in a torrent whose pieces are four blocks.
        let dir = tmp_dir("v2-bigpiece");
        let root = dir.join("t");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("small.bin"), bytes(20_000, 4)).unwrap();
        fs::write(root.join("big.bin"), bytes(150_000, 5)).unwrap();
        let created = create(&root, &CreateOptions { piece_length: Some(65_536), v2: true, ..Default::default() }, |_, _| {}).unwrap();
        let torrent = parse_torrent_file(&created.bytes).unwrap();

        let report = verify(&torrent, &[true, true], &root, |_, _| true).unwrap();

        assert!(report.is_whole(), "{}", report.describe("t", true));
        assert_eq!((report.wanted_pieces, report.verified_pieces), (1 + 3, 4));
    }
}
