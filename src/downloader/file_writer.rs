//! Maps a torrent's flat byte-offset space (piece_index * piece_length +
//! begin) onto the actual files on disk, and writes verified piece data
//! to the right place -- including pieces that straddle a file boundary
//! in multi-file torrents.

use std::fs::{self, OpenOptions};
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

/// Writes `data` starting at global offset `global_offset`, splitting
/// across file spans as needed. Creates parent directories and files on
/// demand; never truncates an existing file (uses `create + write`, seeks
/// to the exact offset for each chunk).
pub fn write_at_global_offset(spans: &[FileSpan], global_offset: u64, data: &[u8]) -> io::Result<()> {
    let mut offset = global_offset;
    let mut remaining = data;

    while !remaining.is_empty() {
        let span = spans
            .iter()
            .find(|s| offset >= s.start && offset < s.end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("offset {} is outside all known files", offset)))?;

        let file_offset = offset - span.start;
        let available_in_file = span.end - offset;
        let chunk_len = (remaining.len() as u64).min(available_in_file) as usize;

        if let Some(parent) = span.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = OpenOptions::new().create(true).write(true).open(&span.path)?;
        f.seek(SeekFrom::Start(file_offset))?;
        f.write_all(&remaining[..chunk_len])?;

        offset += chunk_len as u64;
        remaining = &remaining[chunk_len..];
    }
    Ok(())
}

/// Convenience: writes a whole verified piece at `piece_index`.
pub fn write_piece(spans: &[FileSpan], piece_index: u32, piece_length: u64, data: &[u8]) -> io::Result<()> {
    let global_offset = piece_index as u64 * piece_length;
    write_at_global_offset(spans, global_offset, data)
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

        write_piece(&spans, 0, 100, &vec![0xAAu8; 100]).unwrap();
        write_piece(&spans, 1, 100, &vec![0xBBu8; 100]).unwrap();

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
    fn out_of_order_piece_writes_do_not_clobber_each_other() {
        let dir = tmp_dir("out-of-order");
        let files = vec![(vec!["out.bin".to_string()], 300i64)];
        let spans = build_file_spans(&dir, &files);

        write_piece(&spans, 2, 100, &vec![3u8; 100]).unwrap(); // write piece 2 first
        write_piece(&spans, 0, 100, &vec![1u8; 100]).unwrap();
        write_piece(&spans, 1, 100, &vec![2u8; 100]).unwrap();

        let mut buf = Vec::new();
        fs::File::open(dir.join("out.bin")).unwrap().read_to_end(&mut buf).unwrap();
        assert_eq!(&buf[0..100], &vec![1u8; 100][..]);
        assert_eq!(&buf[100..200], &vec![2u8; 100][..]);
        assert_eq!(&buf[200..300], &vec![3u8; 100][..]);
    }
}
