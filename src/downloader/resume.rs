//! Resume support. A small sidecar file next to the download records
//! which piece indices were SHA-1-verified in a previous run. On
//! startup, those claims are **re-verified against the actual bytes on
//! disk** before being trusted -- a resume file surviving while the
//! downloaded data itself was deleted, truncated, or corrupted is
//! exactly the kind of thing this project's "verify everything, trust
//! nothing from outside this process" approach exists to catch.

use crate::downloader::file_writer::FileSpan;
use crate::torrent::{info_hash_hex, TorrentFile};
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Sidecar file path, keyed by InfoHash (not torrent name) so a renamed
/// or differently-labeled torrent with the same content still resumes
/// correctly, and so two different torrents that happen to share a name
/// never collide.
pub fn progress_file_path(out_dir: &Path, info_hash: &[u8; 20]) -> PathBuf {
    out_dir.join(format!(".{}.resume", info_hash_hex(info_hash)))
}

/// Reads whatever piece indices a previous run claimed as verified, then
/// re-reads each one's actual bytes off disk and re-hashes them --
/// only indices that still hash correctly are trusted. Missing files,
/// truncated files, or bytes that changed since the last run all
/// silently fall out of the returned set (meaning: re-download them),
/// rather than causing an error or writing corrupt data into the final
/// file.
pub fn load_and_verify(path: &Path, spans: &[FileSpan], torrent: &TorrentFile) -> HashSet<u32> {
    read_claimed_indices(path).into_iter().filter(|&index| piece_is_on_disk(spans, torrent, index)).collect()
}

/// Whether piece `index`'s bytes are on disk and hash to the torrent's
/// value for it. A missing file, a short file, or different bytes all just
/// mean "no": the piece will be fetched again.
pub fn piece_is_on_disk(spans: &[FileSpan], torrent: &TorrentFile, index: u32) -> bool {
    if index as usize >= torrent.pieces.len() {
        return false; // stale entry from a different torrent/layout
    }
    let piece_len = torrent.piece_len(index as usize);
    let Ok(data) = read_piece_bytes(spans, index, torrent.piece_length as u64, piece_len) else {
        return false; // file missing or shorter than expected -- not actually there
    };
    // A v2 piece is checked by its merkle tree; a v1 one by SHA-1.
    if let Some(piece) = torrent.v2_pieces.get(index as usize) {
        return crate::v2::merkle_matches(&data, piece.width as usize, &piece.root);
    }
    let hash: [u8; 20] = Sha1::digest(&data).into();
    hash == torrent.pieces[index as usize]
}

/// Whether any of the torrent's files already exists with some content.
pub fn any_data_on_disk(spans: &[FileSpan]) -> bool {
    spans.iter().any(|s| !s.padding && fs::metadata(&s.path).is_ok_and(|m| m.is_file() && m.len() > 0))
}

/// Hashes **every** piece of the torrent that is present on disk and
/// returns those that verify, without trusting any resume file. This is
/// what lets a finished download (whose resume file is deleted) be
/// checked and seeded again, and files that came from elsewhere be adopted.
///
/// `progress(done, total)` is called after each piece: a large torrent
/// takes minutes to hash, and the caller should say something.
pub fn scan_all(spans: &[FileSpan], torrent: &TorrentFile, mut progress: impl FnMut(usize, usize)) -> HashSet<u32> {
    let total = torrent.pieces.len();
    let mut confirmed = HashSet::new();
    for index in 0..total as u32 {
        if piece_is_on_disk(spans, torrent, index) {
            confirmed.insert(index);
        }
        progress(index as usize + 1, total);
    }
    confirmed
}

fn read_claimed_indices(path: &Path) -> HashSet<u32> {
    let Ok(content) = fs::read_to_string(path) else { return HashSet::new() };
    content.lines().filter_map(|l| l.trim().parse::<u32>().ok()).collect()
}

/// Reads exactly `piece_length` bytes for `piece_index` back out of the
/// on-disk file(s), following the same global-offset mapping
/// `write_at_global_offset` uses to write them -- the read-side mirror of
/// that function.
fn read_piece_bytes(spans: &[FileSpan], piece_index: u32, piece_stride: u64, piece_length: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; piece_length as usize];
    let mut filled = 0usize;
    let mut offset = piece_index as u64 * piece_stride;

    while filled < buf.len() {
        // A binary search, as in the writer: a scan of every file for every
        // piece made checking a torrent of many files quadratic.
        let span = crate::downloader::file_writer::span_at(spans, offset).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "offset outside known files"))?;
        let file_offset = offset - span.start;
        let available = (span.end - offset) as usize;
        let to_read = (buf.len() - filled).min(available);

        // Padding is zeros, which the buffer already is.
        if !span.padding {
            let mut f = File::open(&span.path)?;
            f.seek(SeekFrom::Start(file_offset))?;
            f.read_exact(&mut buf[filled..filled + to_read])?;
        }

        filled += to_read;
        offset += to_read as u64;
    }
    Ok(buf)
}

/// Overwrites the sidecar file with exactly `confirmed` -- called once at
/// startup after verification, so a resume file that was carrying stale
/// or unverifiable entries gets compacted down to only what's actually
/// trustworthy, instead of accumulating garbage indefinitely.
pub fn rewrite_compact(path: &Path, confirmed: &HashSet<u32>) -> io::Result<()> {
    let mut f = File::create(path)?; // truncates
    for idx in confirmed {
        writeln!(f, "{}", idx)?;
    }
    f.flush()
}

/// Appends newly-verified piece indices as the download progresses.
/// Append-only and flushed after every write so a crash mid-download
/// loses at most the not-yet-flushed write, never corrupts prior entries.
pub struct ResumeWriter {
    file: File,
}

impl ResumeWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        Ok(ResumeWriter { file: OpenOptions::new().create(true).append(true).open(path)? })
    }

    pub fn record(&mut self, index: u32) -> io::Result<()> {
        writeln!(self.file, "{}", index)?;
        self.file.flush()
    }
}

/// Deletes the sidecar file once a download completes -- nothing left to
/// resume, and no reason to leave a stale file behind for a future
/// unrelated run in the same output directory to trip over.
pub fn clear(path: &Path) {
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::file_writer::{build_file_spans, write_piece};
    use crate::torrent::parse_torrent_file;
    use std::fs as stdfs;

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-resume-test-{}-{}", name, std::process::id()));
        let _ = stdfs::remove_dir_all(&dir);
        stdfs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sha1_of(data: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize().into()
    }

    fn build_test_torrent(piece0: &[u8], piece1: &[u8]) -> TorrentFile {
        let mut pieces_concat = Vec::new();
        pieces_concat.extend_from_slice(&sha1_of(piece0));
        pieces_concat.extend_from_slice(&sha1_of(piece1));
        let bytes = format!(
            "d4:infod6:lengthi{}e4:name1:a12:piece lengthi{}e6:pieces{}:",
            piece0.len() + piece1.len(),
            piece0.len(),
            pieces_concat.len()
        )
        .into_bytes();
        let mut full = bytes;
        full.extend_from_slice(&pieces_concat);
        full.extend_from_slice(b"ee");
        parse_torrent_file(&full).unwrap()
    }

    #[test]
    fn confirms_piece_whose_disk_bytes_actually_match() {
        let piece0 = vec![0xAAu8; 50];
        let piece1 = vec![0xBBu8; 50];
        let torrent = build_test_torrent(&piece0, &piece1);

        let dir = tmp_dir("confirm");
        let spans = build_file_spans(&dir, &torrent.files);
        write_piece(&spans, 0, 50, &piece0).unwrap();

        let progress_path = progress_file_path(&dir, &torrent.info_hash);
        stdfs::write(&progress_path, "0\n").unwrap();

        let confirmed = load_and_verify(&progress_path, &spans, &torrent);
        assert_eq!(confirmed, HashSet::from([0]));
    }

    #[test]
    fn rejects_claimed_piece_whose_disk_bytes_dont_match() {
        let piece0 = vec![0xAAu8; 50];
        let piece1 = vec![0xBBu8; 50];
        let torrent = build_test_torrent(&piece0, &piece1);

        let dir = tmp_dir("reject-mismatch");
        let spans = build_file_spans(&dir, &torrent.files);
        // Write WRONG data for piece 0 (simulating corruption/truncation).
        write_piece(&spans, 0, 50, &[0xFFu8; 50]).unwrap();

        let progress_path = progress_file_path(&dir, &torrent.info_hash);
        stdfs::write(&progress_path, "0\n").unwrap();

        let confirmed = load_and_verify(&progress_path, &spans, &torrent);
        assert!(confirmed.is_empty(), "corrupted piece must not be trusted");
    }

    #[test]
    fn rejects_claimed_piece_whose_file_doesnt_exist_at_all() {
        let piece0 = vec![0xAAu8; 50];
        let piece1 = vec![0xBBu8; 50];
        let torrent = build_test_torrent(&piece0, &piece1);

        let dir = tmp_dir("reject-missing");
        let spans = build_file_spans(&dir, &torrent.files);
        // Never write anything to disk.

        let progress_path = progress_file_path(&dir, &torrent.info_hash);
        stdfs::write(&progress_path, "0\n1\n").unwrap();

        let confirmed = load_and_verify(&progress_path, &spans, &torrent);
        assert!(confirmed.is_empty());
    }

    #[test]
    fn ignores_out_of_range_stale_entries() {
        let piece0 = vec![0xAAu8; 50];
        let piece1 = vec![0xBBu8; 50];
        let torrent = build_test_torrent(&piece0, &piece1);
        let dir = tmp_dir("stale-entries");
        let spans = build_file_spans(&dir, &torrent.files);

        let progress_path = progress_file_path(&dir, &torrent.info_hash);
        stdfs::write(&progress_path, "999\nnot_a_number\n\n").unwrap();

        let confirmed = load_and_verify(&progress_path, &spans, &torrent);
        assert!(confirmed.is_empty());
    }

    #[test]
    fn missing_progress_file_yields_empty_set() {
        let piece0 = vec![0xAAu8; 50];
        let piece1 = vec![0xBBu8; 50];
        let torrent = build_test_torrent(&piece0, &piece1);
        let dir = tmp_dir("no-file");
        let spans = build_file_spans(&dir, &torrent.files);
        let progress_path = progress_file_path(&dir, &torrent.info_hash);

        let confirmed = load_and_verify(&progress_path, &spans, &torrent);
        assert!(confirmed.is_empty());
    }

    #[test]
    fn resume_writer_appends_and_rewrite_compact_replaces() {
        let dir = tmp_dir("writer");
        let path = dir.join("progress.resume");

        let mut w = ResumeWriter::create(&path).unwrap();
        w.record(3).unwrap();
        w.record(7).unwrap();
        drop(w);
        assert_eq!(read_claimed_indices(&path), HashSet::from([3, 7]));

        rewrite_compact(&path, &HashSet::from([3])).unwrap();
        assert_eq!(read_claimed_indices(&path), HashSet::from([3]));

        // Appending after a compact rewrite still works.
        let mut w2 = ResumeWriter::create(&path).unwrap();
        w2.record(9).unwrap();
        assert_eq!(read_claimed_indices(&path), HashSet::from([3, 9]));
    }

    #[test]
    fn clear_removes_the_file() {
        let dir = tmp_dir("clear");
        let path = dir.join("progress.resume");
        stdfs::write(&path, "1\n").unwrap();
        assert!(path.exists());
        clear(&path);
        assert!(!path.exists());
    }

    #[test]
    fn clear_on_nonexistent_file_does_not_panic() {
        let dir = tmp_dir("clear-missing");
        let path = dir.join("never-existed.resume");
        clear(&path); // must not panic
    }

    // ---- scan_all -----------------------------------------------------------

    fn write_single(dir: &std::path::Path, torrent: &TorrentFile, bytes: &[u8]) -> Vec<FileSpan> {
        let spans = build_file_spans(dir, &torrent.files);
        stdfs::write(&spans[0].path, bytes).unwrap();
        spans
    }

    #[test]
    fn a_scan_finds_every_piece_that_verifies_and_reports_progress() {
        let (p0, p1) = (vec![0xAAu8; 50], vec![0xBBu8; 50]);
        let torrent = build_test_torrent(&p0, &p1);
        let dir = tmp_dir("scan-all");
        let spans = write_single(&dir, &torrent, &[p0.clone(), p1.clone()].concat());

        let mut calls = Vec::new();
        let found = scan_all(&spans, &torrent, |done, total| calls.push((done, total)));

        assert_eq!(found, HashSet::from([0, 1]));
        assert_eq!(calls, vec![(1, 2), (2, 2)], "one report per piece, so a long scan can show progress");
    }

    #[test]
    fn a_scan_does_not_trust_a_piece_whose_bytes_changed() {
        let (p0, p1) = (vec![0xAAu8; 50], vec![0xBBu8; 50]);
        let torrent = build_test_torrent(&p0, &p1);
        let dir = tmp_dir("scan-corrupt");
        let mut bytes = [p0.clone(), p1.clone()].concat();
        bytes[60] ^= 0x01; // one bit in the second piece
        let spans = write_single(&dir, &torrent, &bytes);

        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0]));
    }

    #[test]
    fn a_scan_of_a_short_file_finds_only_the_pieces_that_are_all_there() {
        let (p0, p1) = (vec![0xAAu8; 50], vec![0xBBu8; 50]);
        let torrent = build_test_torrent(&p0, &p1);
        let dir = tmp_dir("scan-short");
        let spans = write_single(&dir, &torrent, &[p0.clone(), vec![0xBB; 20]].concat()); // second piece cut off

        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0]));
    }

    #[test]
    fn a_scan_with_no_files_finds_nothing_but_still_reports_every_piece() {
        let torrent = build_test_torrent(&[1; 50], &[2; 50]);
        let dir = tmp_dir("scan-missing");
        let spans = build_file_spans(&dir, &torrent.files);
        let mut reports = 0;

        assert!(scan_all(&spans, &torrent, |_, _| reports += 1).is_empty());
        assert_eq!(reports, 2);
    }

    #[test]
    fn a_scan_checks_a_piece_that_straddles_two_files() {
        // "abcdefghijkl" in pieces of 4, split across a="abcdef", b="ghijkl":
        // piece 1, "efgh", is the end of a and the start of b.
        let data = b"abcdefghijkl";
        let mut bytes = b"d4:infod5:filesld6:lengthi6e4:pathl1:aeed6:lengthi6e4:pathl1:beee4:name1:t12:piece lengthi4e6:pieces60:".to_vec();
        for chunk in data.chunks(4) {
            bytes.extend_from_slice(&sha1_of(chunk));
        }
        bytes.extend_from_slice(b"ee");
        let torrent = parse_torrent_file(&bytes).unwrap();
        let dir = tmp_dir("scan-straddle");
        let spans = build_file_spans(&dir, &torrent.files);
        stdfs::create_dir_all(spans[0].path.parent().unwrap()).unwrap();
        stdfs::write(&spans[0].path, b"abcdef").unwrap();
        stdfs::write(&spans[1].path, b"ghijkl").unwrap();
        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0, 1, 2]));

        stdfs::write(&spans[1].path, b"Xhijkl").unwrap(); // b's first byte, which is piece 1's last
        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0, 2]), "only the straddling piece fails");
    }

    #[test]
    fn any_data_on_disk_ignores_missing_and_empty_files() {
        let torrent = build_test_torrent(&[1; 50], &[2; 50]);
        let dir = tmp_dir("any-data");
        let spans = build_file_spans(&dir, &torrent.files);
        assert!(!any_data_on_disk(&spans), "no file at all");

        stdfs::write(&spans[0].path, b"").unwrap();
        assert!(!any_data_on_disk(&spans), "an empty file is not data");

        stdfs::write(&spans[0].path, b"x").unwrap();
        assert!(any_data_on_disk(&spans));
    }

    /// A v2-only torrent of two files (20000 and 100 bytes) in 16 KiB pieces, and the directory
    /// holding the files it was made from.
    fn v2_torrent(name: &str) -> (TorrentFile, std::path::PathBuf, Vec<Vec<u8>>) {
        use crate::create::{create, CreateOptions};
        let dir = tmp_dir(name);
        let root = dir.join("t");
        stdfs::create_dir_all(&root).unwrap();
        let (a, b) = ((0..20_000u32).map(|i| (i * 3) as u8).collect::<Vec<u8>>(), vec![7u8; 100]);
        stdfs::write(root.join("a"), &a).unwrap();
        stdfs::write(root.join("b"), &b).unwrap();
        let made = create(&root, &CreateOptions { piece_length: Some(16384), v2: true, ..Default::default() }, |_, _| {}).unwrap();
        let torrent = parse_torrent_file(&made.bytes).unwrap();
        (torrent, root, vec![a[..16384].to_vec(), a[16384..].to_vec(), b])
    }

    #[test]
    fn v2_pieces_are_confirmed_on_disk_by_their_merkle_trees() {
        let (torrent, root, pieces) = v2_torrent("resume-v2");
        let spans = torrent.file_spans(&root);
        assert!(torrent.v2_ready() && torrent.pieces.len() == 3);
        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0, 1, 2]), "every piece of what was made verifies, the short ones too");

        // One byte wrong in piece 1 (the short last piece of a): only that one falls out.
        let mut a = stdfs::read(root.join("a")).unwrap();
        a[17_000] ^= 1;
        stdfs::write(root.join("a"), a).unwrap();
        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0, 2]));
        assert!(!piece_is_on_disk(&spans, &torrent, 99), "a piece the torrent does not have");
        // And a resume file's claims are checked, not believed.
        let progress = progress_file_path(&root, &torrent.info_hash);
        stdfs::write(&progress, "0\n1\n2\n").unwrap();
        assert_eq!(load_and_verify(&progress, &spans, &torrent), HashSet::from([0, 2]));
        let _ = pieces;
    }

    #[test]
    fn a_v2_piece_that_is_not_all_there_is_not_confirmed() {
        let (torrent, root, _) = v2_torrent("resume-v2-short");
        let spans = torrent.file_spans(&root);
        let b = stdfs::read(root.join("b")).unwrap();
        stdfs::write(root.join("b"), &b[..50]).unwrap();
        stdfs::remove_file(root.join("a")).unwrap();
        assert!(scan_all(&spans, &torrent, |_, _| {}).is_empty());
    }

    #[test]
    fn the_pieces_of_a_padded_torrent_are_confirmed_from_the_real_files_alone() {
        use crate::torrent::padded_fixture as fx;
        let dir = tmp_dir("padded");
        let torrent = fx::torrent();
        let spans = torrent.file_spans(&dir);
        let (a, b) = fx::real_files();
        stdfs::write(dir.join("a.bin"), &a).unwrap();
        stdfs::write(dir.join("b.bin"), &b).unwrap();
        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0, 1, 2]), "piece 0 ends in padding, which hashes as the zeros it is");
        // Padding files that exist on disk hold nothing anyone reads.
        stdfs::create_dir_all(dir.join(".pad")).unwrap();
        stdfs::write(dir.join(".pad/1096"), vec![0xFFu8; 1096]).unwrap();
        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([0, 1, 2]), "whatever is in a padding file, the piece is what the torrent says");
        // A byte of a.bin changed: piece 0 falls out, the others do not.
        let mut damaged = a.clone();
        damaged[10] ^= 1;
        stdfs::write(dir.join("a.bin"), damaged).unwrap();
        assert_eq!(scan_all(&spans, &torrent, |_, _| {}), HashSet::from([1, 2]));
    }

    #[test]
    fn a_padding_file_on_disk_is_not_data() {
        use crate::torrent::padded_fixture as fx;
        let dir = tmp_dir("padded-data");
        let spans = fx::torrent().file_spans(&dir);
        stdfs::create_dir_all(dir.join(".pad")).unwrap();
        stdfs::write(dir.join(".pad/1096"), vec![0u8; 1096]).unwrap();
        assert!(!any_data_on_disk(&spans), "only a padding file: nothing of the torrent is there");
        stdfs::write(dir.join("a.bin"), b"x").unwrap();
        assert!(any_data_on_disk(&spans));
    }
}
