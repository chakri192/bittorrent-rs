//! Making a `.torrent` from files on disk (`create_torrent`).
//!
//! The inverse of [`crate::torrent::parse_torrent_file`]: walk a file or a
//! directory, hash it in pieces, and describe it as the info dictionary
//! every client hashes to name the torrent. What comes out is
//! deterministic: files are listed in path order, and the same tree with
//! the same options (and creation date) gives the same bytes.
//!
//! Symbolic links are left out rather than followed, so a link cannot pull
//! data from outside the tree or loop. Empty directories are not
//! representable in a torrent and are dropped.

use crate::bencode::{self, Bencode};
use crate::torrent::{is_safe_component, MAX_PIECE_LENGTH};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// The smallest piece length chosen automatically.
pub const MIN_AUTO_PIECE_LENGTH: u64 = 16 * 1024;
/// The largest piece length chosen automatically.
pub const MAX_AUTO_PIECE_LENGTH: u64 = 16 * 1024 * 1024;
/// About how many pieces an automatic choice aims for: enough that a peer
/// can fetch from many sources at once, few enough that the piece list
/// (20 bytes each) stays small.
const TARGET_PIECES: u64 = 1500;
/// The smallest piece length that may be asked for explicitly.
pub const MIN_PIECE_LENGTH: u64 = 1024;
/// The most pieces a torrent made here may have (20 MB of hashes).
const MAX_PIECES: u64 = 1 << 20;
/// How much of a file is read at a time.
const READ_CHUNK: usize = 1 << 20;

/// What to put in the torrent besides the files.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CreateOptions {
    /// Bytes per piece: a power of two. `None` chooses one to suit the size.
    pub piece_length: Option<u64>,
    /// Tracker URLs in tiers (BEP 12), most preferred tier first.
    pub trackers: Vec<Vec<String>>,
    /// BEP 19 web seed URLs.
    pub web_seeds: Vec<String>,
    /// Set the `private` flag (BEP 27): no DHT or peer exchange.
    pub private: bool,
    pub comment: Option<String>,
    pub created_by: Option<String>,
    /// Seconds since the Unix epoch. `None` leaves the field out, which is
    /// what makes a torrent reproducible.
    pub creation_date: Option<u64>,
    /// The torrent's name; by default that of the file or directory.
    pub name: Option<String>,
}

/// A torrent that has been made.
#[derive(Debug, Clone, PartialEq)]
pub struct Created {
    /// The `.torrent` file's contents.
    pub bytes: Vec<u8>,
    pub info_hash: [u8; 20],
    pub name: String,
    pub total_length: u64,
    pub piece_length: u64,
    pub piece_count: usize,
    pub file_count: usize,
}

#[derive(Debug)]
pub enum CreateError {
    Io { path: PathBuf, source: io::Error },
    /// There are no bytes to make a torrent of.
    Empty,
    /// A path that is not UTF-8, which a torrent cannot name.
    NonUtf8Path(PathBuf),
    /// A name that cannot safely be a path component (`..`, or one with a
    /// separator in it): a client reading the torrent would refuse it.
    UnsafeName(String),
    BadPieceLength(String),
    /// A file changed size while it was being read.
    ChangedWhileReading(PathBuf),
    /// A torrent's info dictionary does not re-encode to the bytes its info
    /// hash was taken over.
    Unreproducible,
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateError::Io { path, source } => write!(f, "{}: {}", path.display(), source),
            CreateError::Empty => write!(f, "nothing to put in a torrent: no files, or only empty ones"),
            CreateError::NonUtf8Path(path) => write!(f, "{}: a torrent can only name files whose names are valid UTF-8", path.display()),
            CreateError::UnsafeName(name) => write!(f, "{:?} cannot be used as a file or torrent name", name),
            CreateError::BadPieceLength(why) => write!(f, "{}", why),
            CreateError::ChangedWhileReading(path) => write!(f, "{}: changed size while it was being read", path.display()),
            CreateError::Unreproducible => write!(f, "this torrent's info dictionary cannot be written back exactly as it was hashed"),
        }
    }
}

impl std::error::Error for CreateError {}

/// The piece length to use for `total` bytes: the smallest power of two
/// that keeps the torrent to about [`TARGET_PIECES`] pieces, within
/// [`MIN_AUTO_PIECE_LENGTH`] and [`MAX_AUTO_PIECE_LENGTH`].
pub fn auto_piece_length(total: u64) -> u64 {
    let wanted = total.div_ceil(TARGET_PIECES).max(1);
    wanted.next_power_of_two().clamp(MIN_AUTO_PIECE_LENGTH, MAX_AUTO_PIECE_LENGTH)
}

/// Parses a size such as `16K`, `256KiB` or `1M` (binary units) as given to
/// `--piece-length`. A bare number is bytes.
pub fn parse_size(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (number, suffix) = t.split_at(split);
    let value: u64 = number.parse().map_err(|_| format!("not a size: {:?} (try 256K or 1M)", text))?;
    let multiplier: u64 = match suffix.to_ascii_lowercase().trim_end_matches('b').trim_end_matches('i') {
        "" => 1,
        "k" => 1 << 10,
        "m" => 1 << 20,
        "g" => 1 << 30,
        _ => return Err(format!("unknown unit in {:?} (use K, M or G)", text)),
    };
    value.checked_mul(multiplier).ok_or_else(|| format!("that size is too large: {:?}", text))
}

struct Entry {
    path: Vec<String>,
    on_disk: PathBuf,
    length: u64,
}

/// Makes a torrent of `source`, a file or a directory. `progress` is
/// called as data is hashed, with the bytes done and the total.
pub fn create(source: &Path, options: &CreateOptions, mut progress: impl FnMut(u64, u64)) -> Result<Created, CreateError> {
    let io_err = |path: &Path| {
        let path = path.to_path_buf();
        move |source| CreateError::Io { path, source }
    };
    let meta = fs::metadata(source).map_err(io_err(source))?;

    let name = match &options.name {
        Some(name) => name.clone(),
        None => {
            // `.` and `..` have no name of their own; the real one is found
            // by resolving them.
            let resolved = source.canonicalize().map_err(io_err(source))?;
            let file_name = resolved.file_name().ok_or_else(|| CreateError::UnsafeName(source.display().to_string()))?;
            file_name.to_str().ok_or_else(|| CreateError::NonUtf8Path(resolved.clone()))?.to_string()
        }
    };
    if !is_safe_component(&name) {
        return Err(CreateError::UnsafeName(name));
    }

    let multi_file = meta.is_dir();
    let mut entries = Vec::new();
    if multi_file {
        collect(source, &mut Vec::new(), &mut entries)?;
        // Path order, so the same tree always makes the same torrent.
        entries.sort_by(|a, b| a.path.cmp(&b.path));
    } else {
        entries.push(Entry { path: vec![name.clone()], on_disk: source.to_path_buf(), length: meta.len() });
    }

    let total_length: u64 = entries.iter().map(|e| e.length).sum();
    if total_length == 0 {
        return Err(CreateError::Empty);
    }
    let piece_length = match options.piece_length {
        Some(len) => check_piece_length(len)?,
        None => auto_piece_length(total_length),
    };
    if total_length.div_ceil(piece_length) > MAX_PIECES {
        return Err(CreateError::BadPieceLength(format!("a piece length of {} would need more than {} pieces for {} bytes; use a larger one", piece_length, MAX_PIECES, total_length)));
    }

    let pieces = hash_pieces(&entries, piece_length, total_length, &mut progress)?;
    let piece_count = pieces.len() / 20;

    let mut info = BTreeMap::new();
    info.insert(b"name".to_vec(), text(&name));
    info.insert(b"piece length".to_vec(), Bencode::Int(piece_length as i64));
    info.insert(b"pieces".to_vec(), Bencode::Bytes(pieces));
    if options.private {
        info.insert(b"private".to_vec(), Bencode::Int(1));
    }
    if multi_file {
        let files = entries
            .iter()
            .map(|e| {
                let mut file = BTreeMap::new();
                file.insert(b"length".to_vec(), Bencode::Int(e.length as i64));
                file.insert(b"path".to_vec(), Bencode::List(e.path.iter().map(|part| text(part)).collect()));
                Bencode::Dict(file)
            })
            .collect();
        info.insert(b"files".to_vec(), Bencode::List(files));
    } else {
        info.insert(b"length".to_vec(), Bencode::Int(total_length as i64));
    }
    let info = Bencode::Dict(info);
    let info_hash: [u8; 20] = Sha1::digest(bencode::encode(&info)).into();

    let all_trackers: Vec<&String> = options.trackers.iter().flatten().collect();
    // BEP 12: a list of tiers, only worth writing when there is a choice.
    let announce_list = if all_trackers.len() > 1 { options.trackers.iter().filter(|tier| !tier.is_empty()).cloned().collect() } else { Vec::new() };
    let extras = Extras { comment: options.comment.as_deref(), created_by: options.created_by.as_deref(), creation_date: options.creation_date };
    let bytes = top_level(info, all_trackers.first().map(|url| url.as_str()), &announce_list, &options.web_seeds, &extras);

    Ok(Created { bytes, info_hash, name, total_length, piece_length, piece_count, file_count: entries.len() })
}

/// The optional descriptive fields of a torrent file.
struct Extras<'a> {
    comment: Option<&'a str>,
    created_by: Option<&'a str>,
    creation_date: Option<u64>,
}

/// The `.torrent` file around an info dictionary: where to announce, where
/// else to fetch from, and who made it.
fn top_level(info: Bencode, announce: Option<&str>, announce_list: &[Vec<String>], web_seeds: &[String], extras: &Extras) -> Vec<u8> {
    let mut top = BTreeMap::new();
    if let Some(url) = announce {
        top.insert(b"announce".to_vec(), text(url));
    }
    if !announce_list.is_empty() {
        let tiers = announce_list.iter().map(|tier| Bencode::List(tier.iter().map(|url| text(url)).collect())).collect();
        top.insert(b"announce-list".to_vec(), Bencode::List(tiers));
    }
    match web_seeds {
        [] => {}
        [one] => {
            top.insert(b"url-list".to_vec(), text(one));
        }
        many => {
            top.insert(b"url-list".to_vec(), Bencode::List(many.iter().map(|url| text(url)).collect()));
        }
    }
    if let Some(comment) = extras.comment {
        top.insert(b"comment".to_vec(), text(comment));
    }
    if let Some(created_by) = extras.created_by {
        top.insert(b"created by".to_vec(), text(created_by));
    }
    if let Some(date) = extras.creation_date {
        top.insert(b"creation date".to_vec(), Bencode::Int(date.min(i64::MAX as u64) as i64));
    }
    top.insert(b"info".to_vec(), info);
    bencode::encode(&Bencode::Dict(top))
}

/// The `.torrent` file for a torrent already in hand -- what a magnet link
/// resolved to -- so that it can be kept and used without the metadata
/// exchange next time. The info dictionary is written back exactly as it
/// was hashed; if it would not come out byte for byte (it always does for
/// anything the strict parser accepted) this refuses rather than write a
/// file whose info hash differs from the torrent's.
pub fn torrent_file_bytes(torrent: &crate::torrent::TorrentFile) -> Result<Vec<u8>, CreateError> {
    let info_bytes = bencode::encode(&torrent.info);
    let rehashed: [u8; 20] = Sha1::digest(&info_bytes).into();
    if rehashed != torrent.info_hash {
        return Err(CreateError::Unreproducible);
    }
    let extras = Extras { comment: None, created_by: None, creation_date: None };
    Ok(top_level(torrent.info.clone(), torrent.announce.as_deref(), &torrent.announce_list, &torrent.url_list, &extras))
}

/// Writes `torrent` to `path` as a `.torrent` file (see
/// [`torrent_file_bytes`]), replacing what is there. The file appears
/// whole or not at all: it is written beside the target and renamed into
/// place, so an interrupted run cannot leave half a torrent behind.
pub fn save_torrent(torrent: &crate::torrent::TorrentFile, path: &Path) -> Result<(), CreateError> {
    let bytes = torrent_file_bytes(torrent)?;
    let mut partial = path.as_os_str().to_owned();
    partial.push(".part");
    let partial = PathBuf::from(partial);
    let io_err = |path: &Path| {
        let path = path.to_path_buf();
        move |source| CreateError::Io { path, source }
    };
    fs::write(&partial, &bytes).map_err(io_err(&partial))?;
    fs::rename(&partial, path).map_err(|source| {
        let _ = fs::remove_file(&partial);
        CreateError::Io { path: path.to_path_buf(), source }
    })
}

fn text(s: &str) -> Bencode {
    Bencode::Bytes(s.as_bytes().to_vec())
}

fn check_piece_length(len: u64) -> Result<u64, CreateError> {
    if !len.is_power_of_two() {
        return Err(CreateError::BadPieceLength(format!("a piece length must be a power of two: {}", len)));
    }
    if len < MIN_PIECE_LENGTH {
        return Err(CreateError::BadPieceLength(format!("a piece length must be at least {} bytes: {}", MIN_PIECE_LENGTH, len)));
    }
    if len > MAX_PIECE_LENGTH as u64 {
        return Err(CreateError::BadPieceLength(format!("a piece length can be at most {} bytes: {}", MAX_PIECE_LENGTH, len)));
    }
    Ok(len)
}

/// Adds every regular file under `dir` to `out`, with its path relative to
/// the directory the walk began in (`prefix` holds the components so far).
fn collect(dir: &Path, prefix: &mut Vec<String>, out: &mut Vec<Entry>) -> Result<(), CreateError> {
    let read = fs::read_dir(dir).map_err(|source| CreateError::Io { path: dir.to_path_buf(), source })?;
    for entry in read {
        let entry = entry.map_err(|source| CreateError::Io { path: dir.to_path_buf(), source })?;
        let path = entry.path();
        // `symlink_metadata` so that a link is seen as a link, not as
        // whatever it points at.
        let meta = fs::symlink_metadata(&path).map_err(|source| CreateError::Io { path: path.clone(), source })?;
        let file_type = meta.file_type();
        if !file_type.is_dir() && !file_type.is_file() {
            continue; // a symbolic link, a socket, a device
        }
        let name = entry.file_name().into_string().map_err(|_| CreateError::NonUtf8Path(path.clone()))?;
        if !is_safe_component(&name) {
            return Err(CreateError::UnsafeName(name));
        }
        prefix.push(name);
        if file_type.is_dir() {
            collect(&path, prefix, out)?;
        } else {
            out.push(Entry { path: prefix.clone(), on_disk: path, length: meta.len() });
        }
        prefix.pop();
    }
    Ok(())
}

/// SHA-1 of each `piece_length` slice of the files' content taken back to
/// back, the last one shorter, concatenated.
fn hash_pieces(entries: &[Entry], piece_length: u64, total: u64, progress: &mut impl FnMut(u64, u64)) -> Result<Vec<u8>, CreateError> {
    let piece_length = piece_length as usize;
    let mut pieces = Vec::with_capacity(total.div_ceil(piece_length as u64) as usize * 20);
    let mut hasher = Sha1::new();
    let mut in_piece = 0usize;
    let mut done = 0u64;
    let mut buf = vec![0u8; READ_CHUNK];

    for entry in entries {
        let mut file = File::open(&entry.on_disk).map_err(|source| CreateError::Io { path: entry.on_disk.clone(), source })?;
        let mut read_from_file = 0u64;
        loop {
            let n = file.read(&mut buf).map_err(|source| CreateError::Io { path: entry.on_disk.clone(), source })?;
            if n == 0 {
                break;
            }
            read_from_file += n as u64;
            if read_from_file > entry.length {
                return Err(CreateError::ChangedWhileReading(entry.on_disk.clone()));
            }
            let mut chunk = &buf[..n];
            while !chunk.is_empty() {
                let take = (piece_length - in_piece).min(chunk.len());
                hasher.update(&chunk[..take]);
                in_piece += take;
                chunk = &chunk[take..];
                if in_piece == piece_length {
                    pieces.extend_from_slice(&hasher.finalize_reset());
                    in_piece = 0;
                }
            }
            done += n as u64;
            progress(done, total);
        }
        if read_from_file != entry.length {
            return Err(CreateError::ChangedWhileReading(entry.on_disk.clone()));
        }
    }
    if in_piece > 0 {
        pieces.extend_from_slice(&hasher.finalize());
    }
    Ok(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::torrent::{parse_torrent_file, TorrentFile};

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-create-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `len` bytes that differ from `salt` to `salt` and do not repeat
    /// within a piece, so hashes of misplaced bytes cannot match by luck.
    fn bytes(len: usize, salt: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(salt)).collect()
    }

    fn write(dir: &Path, relative: &str, content: &[u8]) {
        let path = dir.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn opts(piece_length: u64) -> CreateOptions {
        CreateOptions { piece_length: Some(piece_length), ..Default::default() }
    }

    fn make(source: &Path, options: &CreateOptions) -> (Created, TorrentFile) {
        let created = create(source, options, |_, _| {}).unwrap();
        let parsed = parse_torrent_file(&created.bytes).expect("the client's own parser accepts what was made");
        (created, parsed)
    }

    /// The SHA-1 of each `piece_length` slice of `data`.
    fn expected_pieces(data: &[u8], piece_length: usize) -> Vec<[u8; 20]> {
        data.chunks(piece_length).map(|chunk| Sha1::digest(chunk).into()).collect()
    }

    fn top(created: &Created) -> BTreeMap<Vec<u8>, Bencode> {
        match bencode::decode(&created.bytes).unwrap() {
            Bencode::Dict(d) => d,
            other => panic!("not a dict: {:?}", other),
        }
    }

    #[test]
    fn a_file_becomes_a_single_file_torrent_the_parser_reads_back() {
        let dir = tmp_dir("single");
        let content = bytes(5000, 3);
        write(&dir, "movie.bin", &content);

        let (created, parsed) = make(&dir.join("movie.bin"), &opts(2048));

        assert_eq!(parsed.name, "movie.bin");
        assert_eq!(parsed.files, vec![(vec!["movie.bin".to_string()], 5000)]);
        assert!(!parsed.multi_file);
        assert_eq!(parsed.piece_length, 2048);
        assert_eq!(parsed.pieces, expected_pieces(&content, 2048), "every piece hash, the short last one included");
        assert_eq!((created.total_length, created.piece_count, created.file_count), (5000, 3, 1));
        assert_eq!(created.info_hash, parsed.info_hash, "the hash of what was written is the hash the parser finds");
    }

    #[test]
    fn a_directory_becomes_a_multi_file_torrent_in_path_order_with_pieces_across_files() {
        let dir = tmp_dir("multi");
        let root = dir.join("album");
        let (b, inner, z, c) = (bytes(700, 1), bytes(900, 2), bytes(300, 3), bytes(2000, 4));
        write(&root, "b.txt", &b);
        write(&root, "a/z.bin", &z);
        write(&root, "a/inner.bin", &inner);
        write(&root, "c.bin", &c);

        let (created, parsed) = make(&root, &opts(1024));

        let listed: Vec<(Vec<&str>, i64)> = parsed.files.iter().map(|(path, len)| (path.iter().map(String::as_str).collect(), *len)).collect();
        assert_eq!(listed, vec![(vec!["a", "inner.bin"], 900), (vec!["a", "z.bin"], 300), (vec!["b.txt"], 700), (vec!["c.bin"], 2000)], "sorted by path, however the directory was read");
        assert!(parsed.multi_file);
        assert_eq!(parsed.name, "album");
        let all: Vec<u8> = [inner, z, b, c].concat();
        assert_eq!(parsed.pieces, expected_pieces(&all, 1024), "pieces run on across file boundaries");
        assert_eq!((created.total_length, created.file_count), (3900, 4));
    }

    #[test]
    fn a_directory_holding_one_file_is_still_a_multi_file_torrent() {
        let dir = tmp_dir("one-in-dir");
        write(&dir.join("pack"), "only.bin", &bytes(3000, 9));

        let (_, parsed) = make(&dir.join("pack"), &opts(1024));

        assert!(parsed.multi_file, "it was given a directory, so files go under its name");
        assert_eq!(parsed.files, vec![(vec!["only.bin".to_string()], 3000)]);
    }

    #[test]
    fn an_empty_file_beside_others_is_kept() {
        let dir = tmp_dir("empty-file");
        let root = dir.join("t");
        write(&root, "empty.txt", b"");
        write(&root, "full.bin", &bytes(1500, 5));

        let (_, parsed) = make(&root, &opts(1024));

        assert_eq!(parsed.files, vec![(vec!["empty.txt".to_string()], 0), (vec!["full.bin".to_string()], 1500)]);
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_links_are_left_out_rather_than_followed() {
        let dir = tmp_dir("symlink");
        let root = dir.join("t");
        write(&root, "real.bin", &bytes(2000, 1));
        write(&dir, "outside.bin", &bytes(4000, 2));
        std::os::unix::fs::symlink(dir.join("outside.bin"), root.join("link.bin")).unwrap();
        std::os::unix::fs::symlink(&root, root.join("loop")).unwrap();

        let (_, parsed) = make(&root, &opts(1024));

        assert_eq!(parsed.files, vec![(vec!["real.bin".to_string()], 2000)], "neither the file link nor the directory loop");
    }

    #[test]
    fn nothing_to_hash_is_an_error() {
        let dir = tmp_dir("empty");
        fs::create_dir_all(dir.join("hollow/inner")).unwrap();
        assert!(matches!(create(&dir.join("hollow"), &opts(1024), |_, _| {}), Err(CreateError::Empty)), "only empty directories");
        write(&dir, "zero.bin", b"");
        assert!(matches!(create(&dir.join("zero.bin"), &opts(1024), |_, _| {}), Err(CreateError::Empty)), "a file of no bytes");
    }

    #[test]
    fn a_missing_source_is_an_io_error_naming_it() {
        let dir = tmp_dir("missing");
        let err = create(&dir.join("nope"), &opts(1024), |_, _| {}).unwrap_err();
        assert!(matches!(err, CreateError::Io { .. }));
        assert!(err.to_string().contains("nope"), "{}", err);
    }

    #[test]
    fn the_same_tree_makes_the_same_bytes_and_a_changed_byte_changes_the_hash() {
        let dir = tmp_dir("deterministic");
        let root = dir.join("t");
        write(&root, "a.bin", &bytes(3000, 1));
        write(&root, "b.bin", &bytes(3000, 2));
        let options = CreateOptions { creation_date: Some(1_700_000_000), ..opts(1024) };

        let first = create(&root, &options, |_, _| {}).unwrap();
        let second = create(&root, &options, |_, _| {}).unwrap();
        assert_eq!(first.bytes, second.bytes);

        let mut changed = bytes(3000, 2);
        changed[1500] ^= 1;
        write(&root, "b.bin", &changed);
        let third = create(&root, &options, |_, _| {}).unwrap();
        assert_ne!(first.info_hash, third.info_hash);
    }

    #[test]
    fn the_piece_length_follows_the_size_within_bounds() {
        assert_eq!(auto_piece_length(1), MIN_AUTO_PIECE_LENGTH);
        assert_eq!(auto_piece_length(1500 * 16384), 16384, "exactly the target count at the minimum");
        assert_eq!(auto_piece_length(1500 * 16384 + 1), 32768, "one byte over needs the next size up");
        assert_eq!(auto_piece_length(3 << 30), 4 << 20, "3 GiB");
        assert_eq!(auto_piece_length(1 << 50), MAX_AUTO_PIECE_LENGTH);
        for total in [1u64, 1000, 1 << 20, 1 << 30, 1 << 40, u64::MAX / 2] {
            let len = auto_piece_length(total);
            assert!(len.is_power_of_two() && (MIN_AUTO_PIECE_LENGTH..=MAX_AUTO_PIECE_LENGTH).contains(&len), "{} -> {}", total, len);
        }
    }

    #[test]
    fn an_explicit_piece_length_must_be_a_sensible_one() {
        let dir = tmp_dir("piece-length");
        write(&dir, "f.bin", &bytes(5000, 1));
        let f = dir.join("f.bin");
        let refused = |len: u64| matches!(create(&f, &opts(len), |_, _| {}), Err(CreateError::BadPieceLength(_)));
        assert!(refused(3000), "not a power of two");
        assert!(refused(512), "below the minimum");
        assert!(refused(0));
        assert!(refused(MAX_PIECE_LENGTH as u64 * 2), "beyond what a client will accept");
        assert!(!refused(1024) && !refused(4096) && !refused(MAX_PIECE_LENGTH as u64));
    }

    #[test]
    fn a_piece_length_that_would_need_too_many_pieces_is_refused_before_any_hashing() {
        let dir = tmp_dir("too-many");
        let f = dir.join("sparse.bin");
        // Sparse: no disk is used, and nothing is read before the refusal.
        File::create(&f).unwrap().set_len(2 << 30).unwrap();
        let err = create(&f, &opts(1024), |_, _| panic!("nothing should be hashed")).unwrap_err();
        assert!(matches!(err, CreateError::BadPieceLength(_)), "{}", err);
    }

    #[test]
    fn trackers_web_seeds_and_the_private_flag_are_written_where_readers_look() {
        let dir = tmp_dir("metadata");
        write(&dir, "f.bin", &bytes(3000, 1));
        let f = dir.join("f.bin");

        let one = CreateOptions { trackers: vec![vec!["http://a/announce".into()]], web_seeds: vec!["http://mirror/f.bin".into()], ..opts(1024) };
        let (created, parsed) = make(&f, &one);
        assert_eq!(parsed.announce.as_deref(), Some("http://a/announce"));
        assert!(!top(&created).contains_key(b"announce-list".as_slice()), "one tracker needs no list");
        assert_eq!(parsed.url_list, vec!["http://mirror/f.bin".to_string()]);
        assert_eq!(top(&created)[b"url-list".as_slice()], Bencode::Bytes(b"http://mirror/f.bin".to_vec()), "one web seed is written as a bare string, the form every reader takes");
        assert!(!parsed.private);

        let tiers = CreateOptions {
            trackers: vec![vec!["http://a/announce".into(), "http://b/announce".into()], vec!["udp://c:1".into()]],
            web_seeds: vec!["http://m1/".into(), "http://m2/".into()],
            private: true,
            ..opts(1024)
        };
        let (created, parsed) = make(&f, &tiers);
        assert!(matches!(top(&created)[b"url-list".as_slice()], Bencode::List(_)), "several are a list");
        assert_eq!(parsed.announce.as_deref(), Some("http://a/announce"), "the first tracker of the first tier");
        assert_eq!(parsed.announce_list, vec![vec!["http://a/announce".to_string(), "http://b/announce".to_string()], vec!["udp://c:1".to_string()]]);
        assert_eq!(parsed.url_list, vec!["http://m1/".to_string(), "http://m2/".to_string()]);
        assert!(parsed.private);

        let (_, bare) = make(&f, &opts(1024));
        assert_eq!((bare.announce, bare.announce_list.len(), bare.url_list.len()), (None, 0, 0), "a torrent with no trackers is valid (DHT, magnet)");
    }

    #[test]
    fn the_private_flag_changes_the_info_hash() {
        let dir = tmp_dir("private-hash");
        write(&dir, "f.bin", &bytes(3000, 1));
        let f = dir.join("f.bin");
        let (public, _) = make(&f, &opts(1024));
        let (private, _) = make(&f, &CreateOptions { private: true, ..opts(1024) });
        assert_ne!(public.info_hash, private.info_hash, "it is part of the info dict, so a private torrent is a different torrent");
    }

    #[test]
    fn comment_creator_and_date_are_written_and_the_date_is_optional() {
        let dir = tmp_dir("comment");
        write(&dir, "f.bin", &bytes(3000, 1));
        let f = dir.join("f.bin");

        let with = CreateOptions { comment: Some("for you".into()), created_by: Some("me 1.0".into()), creation_date: Some(1_700_000_000), ..opts(1024) };
        let created = create(&f, &with, |_, _| {}).unwrap();
        let t = top(&created);
        assert_eq!(t[b"comment".as_slice()], Bencode::Bytes(b"for you".to_vec()));
        assert_eq!(t[b"created by".as_slice()], Bencode::Bytes(b"me 1.0".to_vec()));
        assert_eq!(t[b"creation date".as_slice()], Bencode::Int(1_700_000_000));

        let without = create(&f, &opts(1024), |_, _| {}).unwrap();
        assert!(!top(&without).contains_key(b"creation date".as_slice()), "left out unless asked for, so the same input gives the same file");
        assert_eq!(created.info_hash, without.info_hash, "none of it is part of the info dict");
    }

    #[test]
    fn the_name_defaults_to_the_source_and_can_be_overridden_but_never_unsafe() {
        let dir = tmp_dir("name");
        write(&dir.join("pack"), "sub/f.bin", &bytes(2000, 1));

        let (_, plain) = make(&dir.join("pack"), &opts(1024));
        assert_eq!(plain.name, "pack");
        let (_, dotted) = make(&dir.join("pack").join("sub").join(".."), &opts(1024));
        assert_eq!(dotted.name, "pack", "`..` is resolved to the real name");
        let (_, renamed) = make(&dir.join("pack"), &CreateOptions { name: Some("release".into()), ..opts(1024) });
        assert_eq!(renamed.name, "release");

        for bad in ["..", ".", "a/b", "a\\b", ""] {
            let err = create(&dir.join("pack"), &CreateOptions { name: Some(bad.into()), ..opts(1024) }, |_, _| {}).unwrap_err();
            assert!(matches!(err, CreateError::UnsafeName(_)), "{:?} gave {}", bad, err);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_file_name_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tmp_dir("non-utf8");
        let root = dir.join("t");
        fs::create_dir_all(&root).unwrap();
        let odd = root.join(std::ffi::OsStr::from_bytes(b"bad-\xff-name"));
        if fs::write(&odd, b"data").is_err() {
            return; // this file system will not hold such a name (macOS), so there is nothing to refuse
        }
        assert!(matches!(create(&root, &opts(1024), |_, _| {}), Err(CreateError::NonUtf8Path(_))));
    }

    #[test]
    fn progress_climbs_to_the_total() {
        let dir = tmp_dir("progress");
        write(&dir.join("t"), "a.bin", &bytes(2500, 1));
        write(&dir.join("t"), "b.bin", &bytes(1500, 2));
        let mut seen = Vec::new();

        create(&dir.join("t"), &opts(1024), |done, total| seen.push((done, total))).unwrap();

        assert!(seen.windows(2).all(|w| w[0].0 < w[1].0), "strictly increasing: {:?}", seen);
        assert_eq!(seen.last(), Some(&(4000, 4000)));
        assert!(seen.iter().all(|&(_, total)| total == 4000));
    }

    #[test]
    fn a_file_that_is_not_the_size_it_was_listed_as_is_an_error_not_a_bad_torrent() {
        let dir = tmp_dir("changed");
        write(&dir, "f.bin", &bytes(20, 1));
        let entry = |length| Entry { path: vec!["f.bin".into()], on_disk: dir.join("f.bin"), length };
        assert!(matches!(hash_pieces(&[entry(10)], 1024, 10, &mut |_, _| {}), Err(CreateError::ChangedWhileReading(_))), "it grew");
        assert!(matches!(hash_pieces(&[entry(30)], 1024, 30, &mut |_, _| {}), Err(CreateError::ChangedWhileReading(_))), "it shrank");
        assert!(hash_pieces(&[entry(20)], 1024, 20, &mut |_, _| {}).is_ok());
    }

    #[test]
    fn a_piece_boundary_that_falls_on_the_read_chunk_boundary_is_hashed_the_same() {
        // READ_CHUNK is a multiple of every piece length up to itself, so
        // exercise the other way round: pieces larger than a chunk.
        let dir = tmp_dir("chunks");
        let content = bytes(READ_CHUNK * 2 + 12345, 7);
        write(&dir, "big.bin", &content);

        let (_, parsed) = make(&dir.join("big.bin"), &opts(2 << 20));

        assert_eq!(parsed.pieces, expected_pieces(&content, 2 << 20));
    }

    #[test]
    fn sizes_parse_in_binary_units() {
        assert_eq!(parse_size("1024"), Ok(1024));
        assert_eq!(parse_size("16K"), Ok(16 * 1024));
        assert_eq!(parse_size("256KiB"), Ok(256 * 1024));
        assert_eq!(parse_size(" 2m "), Ok(2 << 20));
        assert_eq!(parse_size("1G"), Ok(1 << 30));
        for bad in ["", "K", "1.5M", "-1", "12x", "99999999999999999999", "18446744073709551615G"] {
            assert!(parse_size(bad).is_err(), "{:?} should be refused", bad);
        }
    }

    // ---- writing back a torrent that is already in hand ----

    #[test]
    fn a_parsed_torrent_is_written_back_byte_for_byte_when_it_carries_nothing_extra() {
        let dir = tmp_dir("write-back");
        let root = dir.join("pack");
        write(&root, "a.bin", &bytes(1500, 1));
        write(&root, "sub/b.bin", &bytes(2500, 2));
        let options = CreateOptions {
            trackers: vec![vec!["http://a/announce".into(), "http://b/announce".into()], vec!["udp://c:1".into()]],
            web_seeds: vec!["http://m1/".into(), "http://m2/".into()],
            private: true,
            ..opts(1024)
        };
        let (created, parsed) = make(&root, &options);

        let written = torrent_file_bytes(&parsed).unwrap();

        assert_eq!(written, created.bytes, "the same file comes back out");
    }

    #[test]
    fn a_torrent_from_a_magnet_link_can_be_saved_and_read_again() {
        let dir = tmp_dir("magnet-save");
        write(&dir, "f.bin", &bytes(3000, 4));
        let (created, parsed) = make(&dir.join("f.bin"), &opts(1024));
        let info = match bencode::decode(&created.bytes).unwrap() {
            Bencode::Dict(top) => bencode::encode(&top[b"info".as_slice()]),
            other => panic!("{:?}", other),
        };
        // What a magnet download holds: the info dict alone, and the trackers from the link.
        let from_magnet = crate::torrent::from_info_dict_bytes(&info, created.info_hash, Some("http://t/announce".into()), vec![vec!["http://t/announce".into()], vec!["http://u/announce".into()]]).unwrap();

        let saved = torrent_file_bytes(&from_magnet).unwrap();
        let reread = parse_torrent_file(&saved).expect("the saved file is a torrent");

        assert_eq!(reread.info_hash, parsed.info_hash, "the same torrent");
        assert_eq!(reread.announce.as_deref(), Some("http://t/announce"));
        assert_eq!(reread.announce_list, vec![vec!["http://t/announce".to_string()], vec!["http://u/announce".to_string()]]);
        assert_eq!(reread.pieces, parsed.pieces);
    }

    #[test]
    fn the_announce_url_is_kept_as_it_was_even_when_the_list_starts_elsewhere() {
        let dir = tmp_dir("announce-kept");
        write(&dir, "f.bin", &bytes(2000, 4));
        let (_, mut parsed) = make(&dir.join("f.bin"), &opts(1024));
        parsed.announce = Some("http://main/announce".into());
        parsed.announce_list = vec![vec!["http://other/announce".into()]];

        let reread = parse_torrent_file(&torrent_file_bytes(&parsed).unwrap()).unwrap();

        assert_eq!(reread.announce.as_deref(), Some("http://main/announce"));
        assert_eq!(reread.announce_list, vec![vec!["http://other/announce".to_string()]]);
    }

    #[test]
    fn a_torrent_with_no_trackers_is_saved_with_none() {
        let dir = tmp_dir("no-trackers-save");
        write(&dir, "f.bin", &bytes(2000, 4));
        let (_, parsed) = make(&dir.join("f.bin"), &opts(1024));

        let reread = parse_torrent_file(&torrent_file_bytes(&parsed).unwrap()).unwrap();

        assert_eq!((reread.announce, reread.announce_list.len(), reread.url_list.len()), (None, 0, 0));
    }

    #[test]
    fn an_info_dict_that_would_not_hash_the_same_is_refused_rather_than_saved() {
        let dir = tmp_dir("unreproducible");
        write(&dir, "f.bin", &bytes(2000, 4));
        let (_, mut parsed) = make(&dir.join("f.bin"), &opts(1024));
        if let Bencode::Dict(info) = &mut parsed.info {
            info.insert(b"name".to_vec(), text("something else"));
        }

        assert!(matches!(torrent_file_bytes(&parsed), Err(CreateError::Unreproducible)));
    }

    #[test]
    fn saving_writes_the_file_whole_and_replaces_an_old_one_without_leaving_a_partial() {
        let dir = tmp_dir("save");
        write(&dir, "f.bin", &bytes(2000, 4));
        let (created, parsed) = make(&dir.join("f.bin"), &opts(1024));
        let target = dir.join("kept.torrent");
        fs::write(&target, b"an older file").unwrap();

        save_torrent(&parsed, &target).unwrap();

        assert_eq!(fs::read(&target).unwrap(), created.bytes);
        assert!(!dir.join("kept.torrent.part").exists(), "nothing left beside it");
    }

    #[test]
    fn saving_where_it_cannot_is_an_error_naming_the_place_and_leaves_no_partial() {
        let dir = tmp_dir("save-fails");
        write(&dir, "f.bin", &bytes(2000, 4));
        let (_, parsed) = make(&dir.join("f.bin"), &opts(1024));
        let target = dir.join("no-such-dir").join("kept.torrent");

        let err = save_torrent(&parsed, &target).unwrap_err();

        assert!(matches!(err, CreateError::Io { .. }));
        assert!(err.to_string().contains("no-such-dir"), "{}", err);
        // A target that is itself a directory: the rename fails, and the partial is cleaned up.
        let as_dir = dir.join("a-directory");
        fs::create_dir_all(&as_dir).unwrap();
        assert!(save_torrent(&parsed, &as_dir).is_err());
        assert!(!dir.join("a-directory.part").exists(), "a failed rename does not leave the partial behind");
    }
}
