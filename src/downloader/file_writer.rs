//! Maps a torrent's flat byte-offset space (piece_index * piece_length +
//! begin) onto the actual files on disk, and writes verified piece data
//! to the right place -- including pieces that straddle a file boundary
//! in multi-file torrents.

use std::fs;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FileSpan {
    pub path: PathBuf,
    /// Global byte offset (inclusive) where this file begins in the
    /// torrent's concatenated byte space.
    pub start: u64,
    /// Global byte offset (exclusive) where this file ends.
    pub end: u64,
}

/// Builds the file-span table from `TorrentFile::files`, rooted at
/// `base_dir` (typically `base_dir/torrent.name/...` for multi-file
/// torrents, or `base_dir/torrent.name` for single-file -- both cases are
/// already expressed by `TorrentFile::files`' path components).
pub fn build_file_spans(base_dir: &Path, files: &[(Vec<String>, i64)]) -> Vec<FileSpan> {
    let mut spans = Vec::with_capacity(files.len());
    let mut cursor: u64 = 0;
    for (path_parts, length) in files {
        let path = path_parts.iter().fold(base_dir.to_path_buf(), |p, part| p.join(part));
        let len = *length as u64;
        spans.push(FileSpan { path, start: cursor, end: cursor + len });
        cursor += len;
    }
    spans
}

/// [`build_file_spans`] for a BitTorrent v2 torrent (BEP 52), in which each
/// file begins on a piece boundary of the torrent's flat byte space and the
/// space between the end of one file and the next piece boundary belongs to no
/// file. A piece never spans two files, so the gaps are never read or written.
pub fn build_file_spans_aligned(base_dir: &Path, files: &[(Vec<String>, i64)], piece_length: u64) -> Vec<FileSpan> {
    let mut spans = Vec::with_capacity(files.len());
    let mut cursor: u64 = 0;
    for (path_parts, length) in files {
        let path = path_parts.iter().fold(base_dir.to_path_buf(), |p, part| p.join(part));
        let len = *length as u64;
        spans.push(FileSpan { path, start: cursor, end: cursor + len });
        cursor = (cursor + len).next_multiple_of(piece_length.max(1));
    }
    spans
}

/// The file that holds byte `offset` of the torrent, if any. Spans are in
/// order and contiguous, so this is a binary search: a torrent of tens of
/// thousands of files would otherwise cost a scan of all of them for every
/// piece written. Empty files (start == end) hold no byte and are skipped.
pub(crate) fn span_at(spans: &[FileSpan], offset: u64) -> Option<&FileSpan> {
    let first_ending_after = spans.partition_point(|s| s.end <= offset);
    spans.get(first_ending_after).filter(|s| s.start <= offset)
}

/// Writes `data` starting at global offset `global_offset`, splitting
/// across file spans as needed. Creates parent directories and files on
/// demand; never truncates an existing file (uses `create + write`, seeks
/// to the exact offset for each chunk).
pub fn write_at_global_offset(spans: &[FileSpan], global_offset: u64, data: &[u8]) -> io::Result<()> {
    let mut offset = global_offset;
    let mut remaining = data;

    while !remaining.is_empty() {
        let span = span_at(spans, offset).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("offset {} is outside all known files", offset)))?;

        let file_offset = offset - span.start;
        let available_in_file = span.end - offset;
        let chunk_len = (remaining.len() as u64).min(available_in_file) as usize;

        if let Some(parent) = span.path.parent() {
            fs::create_dir_all(parent)?;
        }
        // truncate(false) is deliberate: we write specific byte ranges at
        // arbitrary offsets (pieces can arrive out of order), so
        // truncating on open would destroy data already written by a
        // previous piece to this same file.
        let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&span.path)?;
        f.seek(SeekFrom::Start(file_offset))?;
        f.write_all(&remaining[..chunk_len])?;

        offset += chunk_len as u64;
        remaining = &remaining[chunk_len..];
    }
    Ok(())
}

/// Creates the empty files among `spans` that `wanted` says are wanted
/// (with their directories). A file of no bytes is part of a torrent
/// (`.gitkeep`, `__init__.py`) but no piece holds any of it, so nothing
/// downloads it and nothing else would ever create it. An existing file is
/// left alone, whatever its size. Returns how many were created.
pub fn create_empty_files(spans: &[FileSpan], wanted: impl Fn(usize) -> bool) -> io::Result<usize> {
    let mut created = 0;
    for (index, span) in spans.iter().enumerate() {
        if span.start != span.end || !wanted(index) || span.path.exists() {
            continue;
        }
        if let Some(parent) = span.path.parent() {
            fs::create_dir_all(parent)?;
        }
        std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&span.path)?;
        created += 1;
    }
    Ok(created)
}

/// Convenience: writes a whole verified piece at `piece_index`.
pub fn write_piece(spans: &[FileSpan], piece_index: u32, piece_length: u64, data: &[u8]) -> io::Result<()> {
    let global_offset = piece_index as u64 * piece_length;
    write_at_global_offset(spans, global_offset, data)
}

/// Reads `len` bytes starting at global offset `global_offset`, stitching
/// across file spans as needed -- the exact inverse of
/// `write_at_global_offset`. Used by the seeder to serve `Request`s for
/// pieces already verified on disk. Errors if any covered file is missing
/// or shorter than the span demands (a piece we claim to have must be
/// fully readable; anything else is a bug or external file tampering).
pub fn read_at_global_offset(spans: &[FileSpan], global_offset: u64, len: usize) -> io::Result<Vec<u8>> {
    use std::io::Read;

    let mut out = Vec::with_capacity(len);
    let mut offset = global_offset;
    let mut remaining = len;

    while remaining > 0 {
        let span = span_at(spans, offset).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("offset {} is outside all known files", offset)))?;

        let file_offset = offset - span.start;
        let available_in_file = span.end - offset;
        let chunk_len = (remaining as u64).min(available_in_file) as usize;

        let mut f = fs::File::open(&span.path)?;
        f.seek(SeekFrom::Start(file_offset))?;
        let mut chunk = vec![0u8; chunk_len];
        f.read_exact(&mut chunk)?;
        out.extend_from_slice(&chunk);

        offset += chunk_len as u64;
        remaining -= chunk_len;
    }
    Ok(out)
}

/// Reads one block (`begin`..`begin+length` within piece `piece_index`)
/// for serving a peer's `Request`.
pub fn read_block(spans: &[FileSpan], piece_index: u32, piece_length: u64, begin: u32, length: u32) -> io::Result<Vec<u8>> {
    let global_offset = piece_index as u64 * piece_length + begin as u64;
    read_at_global_offset(spans, global_offset, length as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn single_file_span_covers_whole_range() {
        let files = vec![(vec!["movie.mkv".to_string()], 1000i64)];
        let spans = build_file_spans(Path::new("/base"), &files);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start, 0);
        assert_eq!(spans[0].end, 1000);
        assert_eq!(spans[0].path, Path::new("/base/movie.mkv"));
    }

    #[test]
    fn multi_file_spans_have_cumulative_offsets() {
        let files = vec![(vec!["a.txt".to_string()], 100i64), (vec!["dir".to_string(), "b.txt".to_string()], 200i64)];
        let spans = build_file_spans(Path::new("/base"), &files);
        assert_eq!((spans[0].start, spans[0].end), (0, 100));
        assert_eq!((spans[1].start, spans[1].end), (100, 300));
        assert_eq!(spans[1].path, Path::new("/base/dir/b.txt"));
    }

    #[test]
    fn writes_piece_fully_within_one_file() {
        let dir = tmp_dir("single");
        let files = vec![(vec!["out.bin".to_string()], 1000i64)];
        let spans = build_file_spans(&dir, &files);

        write_piece(&spans, 0, 100, &[0xAAu8; 100]).unwrap();
        write_piece(&spans, 1, 100, &[0xBBu8; 100]).unwrap();

        let mut buf = Vec::new();
        fs::File::open(dir.join("out.bin")).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(&buf[0..100], &vec![0xAAu8; 100][..]);
        assert_eq!(&buf[100..200], &vec![0xBBu8; 100][..]);
    }

    #[test]
    fn writes_piece_spanning_two_files() {
        let dir = tmp_dir("spanning");
        // file a: 0..150, file b: 150..300. A 100-byte piece at global
        // offset 100 covers bytes [100,150) of a and [150,200) of b.
        let files = vec![(vec!["a.bin".to_string()], 150i64), (vec!["b.bin".to_string()], 150i64)];
        let spans = build_file_spans(&dir, &files);

        let mut data = vec![1u8; 50];
        data.extend(vec![2u8; 50]);
        write_at_global_offset(&spans, 100, &data).unwrap();

        let mut a = Vec::new();
        fs::File::open(dir.join("a.bin")).unwrap().read_to_end(&mut a).unwrap();
        let mut b = Vec::new();
        fs::File::open(dir.join("b.bin")).unwrap().read_to_end(&mut b).unwrap();

        assert_eq!(&a[100..150], &vec![1u8; 50][..]);
        assert_eq!(&b[0..50], &vec![2u8; 50][..]);
    }

    #[test]
    fn creates_nested_directories_for_multi_file_torrents() {
        let dir = tmp_dir("nested");
        let files = vec![(vec!["deep".to_string(), "nested".to_string(), "file.txt".to_string()], 10i64)];
        let spans = build_file_spans(&dir, &files);
        write_piece(&spans, 0, 10, &[7u8; 10]).unwrap();
        assert!(dir.join("deep/nested/file.txt").exists());
    }

    #[test]
    fn rejects_offset_outside_all_files() {
        let files = vec![(vec!["a.bin".to_string()], 10i64)];
        let spans = build_file_spans(Path::new("/base"), &files);
        assert!(write_at_global_offset(&spans, 100, &[1, 2, 3]).is_err());
    }

    #[test]
    fn read_at_global_offset_round_trips_across_file_boundary() {
        let dir = tmp_dir("read-spanning");
        let files = vec![(vec!["a.bin".to_string()], 150i64), (vec!["b.bin".to_string()], 150i64)];
        let spans = build_file_spans(&dir, &files);

        let mut data = vec![7u8; 50];
        data.extend(vec![9u8; 50]);
        write_at_global_offset(&spans, 100, &data).unwrap();
        // b.bin only has 50 bytes written at its start; reading [100,200)
        // must return exactly what was written.
        let back = read_at_global_offset(&spans, 100, 100).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn read_block_maps_piece_coordinates_to_global_offset() {
        let dir = tmp_dir("read-block");
        let files = vec![(vec!["out.bin".to_string()], 300i64)];
        let spans = build_file_spans(&dir, &files);
        write_piece(&spans, 1, 100, &[5u8; 100]).unwrap();

        let block = read_block(&spans, 1, 100, 20, 30).unwrap();
        assert_eq!(block, vec![5u8; 30]);
    }

    #[test]
    fn read_of_missing_file_errors_instead_of_padding() {
        let dir = tmp_dir("read-missing");
        let files = vec![(vec!["never-written.bin".to_string()], 100i64)];
        let spans = build_file_spans(&dir, &files);
        assert!(read_at_global_offset(&spans, 0, 10).is_err());
    }

    #[test]
    fn out_of_order_piece_writes_do_not_clobber_each_other() {
        let dir = tmp_dir("out-of-order");
        let files = vec![(vec!["out.bin".to_string()], 300i64)];
        let spans = build_file_spans(&dir, &files);

        write_piece(&spans, 2, 100, &[3u8; 100]).unwrap(); // write piece 2 first
        write_piece(&spans, 0, 100, &[1u8; 100]).unwrap();
        write_piece(&spans, 1, 100, &[2u8; 100]).unwrap();

        let mut buf = Vec::new();
        fs::File::open(dir.join("out.bin")).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(&buf[0..100], &vec![1u8; 100][..]);
        assert_eq!(&buf[100..200], &vec![2u8; 100][..]);
        assert_eq!(&buf[200..300], &vec![3u8; 100][..]);
    }

    // ---- finding the file for an offset, and empty files ----

    /// Spans for files of the given lengths laid end to end.
    fn spans_of(lengths: &[u64]) -> Vec<FileSpan> {
        let mut cursor = 0;
        lengths
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                let span = FileSpan { path: std::path::PathBuf::from(format!("f{}", i)), start: cursor, end: cursor + len };
                cursor += len;
                span
            })
            .collect()
    }

    /// What span_at must agree with: the obvious scan.
    fn linear(spans: &[FileSpan], offset: u64) -> Option<usize> {
        spans.iter().position(|s| offset >= s.start && offset < s.end)
    }

    #[test]
    fn the_file_for_an_offset_is_found_however_the_files_are_laid_out() {
        // Empty files at the start, the middle (twice running) and the end.
        let spans = spans_of(&[0, 5, 0, 0, 7, 1, 0, 3, 0]);
        let total: u64 = 16;
        for offset in 0..total + 3 {
            let found = span_at(&spans, offset).map(|s| spans.iter().position(|o| o.path == s.path).unwrap());
            assert_eq!(found, linear(&spans, offset), "offset {}", offset);
        }
        assert!(span_at(&spans, total).is_none(), "one past the end");
        assert!(span_at(&[], 0).is_none(), "no files at all");
    }

    #[test]
    fn a_torrent_of_a_hundred_thousand_files_is_searched_in_no_time() {
        let spans = spans_of(&vec![10; 100_000]);
        let started = std::time::Instant::now();
        let mut checksum = 0usize;
        for piece in 0..100_000u64 {
            let span = span_at(&spans, piece * 10 + 3).unwrap();
            checksum += (span.start / 10) as usize;
        }
        assert_eq!(checksum, (0..100_000usize).sum::<usize>());
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "a scan of every file for each of them would take far longer: {:?}", started.elapsed());
    }

    #[test]
    fn empty_files_are_created_with_their_directories_and_only_the_wanted_ones() {
        let dir = tmp_dir("empty-files");
        let files = vec![(vec!["a.bin".to_string()], 4i64), (vec!["d".to_string(), "e".to_string(), ".keep".to_string()], 0), (vec!["skipped".to_string()], 0), (vec!["z.txt".to_string()], 0)];
        let spans = build_file_spans(&dir, &files);

        let made = create_empty_files(&spans, |file| file != 2).unwrap();

        assert_eq!(made, 2);
        assert!(dir.join("d/e/.keep").is_file() && fs::metadata(dir.join("d/e/.keep")).unwrap().len() == 0);
        assert!(dir.join("z.txt").is_file());
        assert!(!dir.join("skipped").exists(), "not wanted");
        assert!(!dir.join("a.bin").exists(), "a file with content is for the pieces to create");
    }

    #[test]
    fn an_empty_file_that_already_exists_is_left_as_it_is() {
        let dir = tmp_dir("empty-exists");
        fs::write(dir.join("keep.txt"), b"someone's data").unwrap();
        let spans = build_file_spans(&dir, &[(vec!["keep.txt".to_string()], 0i64)]);

        assert_eq!(create_empty_files(&spans, |_| true).unwrap(), 0);

        assert_eq!(fs::read(dir.join("keep.txt")).unwrap(), b"someone's data", "not truncated");
    }

    #[test]
    fn an_empty_file_that_cannot_be_created_is_an_error() {
        let dir = tmp_dir("empty-blocked");
        fs::write(dir.join("d"), b"a file where the directory must go").unwrap();
        let spans = build_file_spans(&dir, &[(vec!["d".to_string(), "x".to_string()], 0i64)]);

        assert!(create_empty_files(&spans, |_| true).is_err());
    }

    #[test]
    fn aligned_spans_start_every_file_on_a_piece_boundary_and_leave_the_gaps_to_nobody() {
        let files = vec![(vec!["a".to_string()], 100i64), (vec!["empty".to_string()], 0), (vec!["b".to_string()], 256), (vec!["c".to_string()], 1)];
        let spans = build_file_spans_aligned(Path::new("/base"), &files, 256);
        assert_eq!(spans.iter().map(|s| (s.start, s.end)).collect::<Vec<_>>(), vec![(0, 100), (256, 256), (256, 512), (512, 513)], "each file begins where the piece after the last one's end begins");
        assert!(span_at(&spans, 100).is_none() && span_at(&spans, 255).is_none(), "the gap holds no file");
        assert_eq!(span_at(&spans, 256).unwrap().path, Path::new("/base/b"));
        assert_eq!(span_at(&spans, 512).unwrap().path, Path::new("/base/c"));
        // Unaligned, the same files would run into one another.
        let plain = build_file_spans(Path::new("/base"), &files);
        assert_eq!(plain[2].start, 100);
    }

    #[test]
    fn a_v2_piece_is_written_and_read_back_at_its_place_in_the_aligned_space() {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-aligned-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let files = vec![(vec!["a".to_string()], 300i64), (vec!["b".to_string()], 100)];
        let spans = build_file_spans_aligned(&dir, &files, 256);
        // a: pieces 0 (256 bytes) and 1 (44); b: piece 2 (100).
        write_piece(&spans, 0, 256, &[1u8; 256]).unwrap();
        write_piece(&spans, 1, 256, &[2u8; 44]).unwrap();
        write_piece(&spans, 2, 256, &[3u8; 100]).unwrap();
        assert_eq!(fs::read(dir.join("a")).unwrap().len(), 300);
        assert_eq!(fs::read(dir.join("b")).unwrap(), vec![3u8; 100], "b begins with its own first byte, not at 44 into the padding");
        assert_eq!(read_at_global_offset(&spans, 512, 100).unwrap(), vec![3u8; 100]);
        let _ = fs::remove_dir_all(&dir);
    }
}
