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
    let claimed = read_claimed_indices(path);
    let mut confirmed = HashSet::new();

    for index in claimed {
        if index as usize >= torrent.pieces.len() {
            continue; // stale entry from a different torrent/layout
        }
        let piece_len = torrent.piece_len(index as usize);
        let Ok(data) = read_piece_bytes(spans, index, torrent.piece_length as u64, piece_len) else {
            continue; // file missing or shorter than expected -- not actually there
        };
        let mut hasher = Sha1::new();
        hasher.update(&data);
        let hash: [u8; 20] = hasher.finalize().into();
        if hash == torrent.pieces[index as usize] {
            confirmed.insert(index);
        }
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
        let span = spans
            .iter()
            .find(|s| offset >= s.start && offset < s.end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "offset outside known files"))?;
        let file_offset = offset - span.start;
        let available = (span.end - offset) as usize;
        let to_read = (buf.len() - filled).min(available);

        let mut f = File::open(&span.path)?;
        f.seek(SeekFrom::Start(file_offset))?;
        f.read_exact(&mut buf[filled..filled + to_read])?;

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
}
