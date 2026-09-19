//! .torrent file parsing and InfoHash computation.

use crate::bencode::{self, Bencode, DecodeError, Decoder};
use sha1::{Digest, Sha1};

#[derive(Debug)]
pub struct TorrentFile {
    pub announce: Option<String>,
    pub announce_list: Vec<Vec<String>>,
    pub info: Bencode,
    pub info_hash: [u8; 20],
    pub piece_length: i64,
    pub pieces: Vec<[u8; 20]>,
    pub name: String,
    /// (path_components, length) for each file. Single-file torrents get
    /// one entry whose path is just [name].
    pub files: Vec<(Vec<String>, i64)>,
    /// Whether the info dict is in the multi-file form (a `files` list),
    /// in which case `name` is the directory the files go under, even if
    /// the list has only one entry. A single-file torrent's `name` is the
    /// file itself.
    pub multi_file: bool,
    /// BEP 19 web seeds (`url-list`): HTTP(S) base URLs the content can
    /// also be fetched from. Empty for magnet-derived torrents.
    pub url_list: Vec<String>,
    /// BEP 27 `private` flag. A private torrent's peers must come only
    /// from its tracker: no DHT, no PEX, no local discovery.
    pub private: bool,
    /// The BitTorrent v2 side of the metadata (BEP 52), for a v2 or hybrid
    /// torrent. For a torrent that is v2 only, `pieces` is empty and
    /// `info_hash` is the first 20 bytes of the SHA-256 one.
    pub v2: Option<crate::v2::V2Meta>,
    /// For a v2-only torrent whose piece layers are all present: its pieces,
    /// with what each must hash to. Empty otherwise.
    pub v2_pieces: Vec<crate::v2::V2Piece>,
}

#[derive(Debug)]
pub enum TorrentError {
    Decode(DecodeError),
    NotADict,
    MissingKey(&'static str),
    WrongType(&'static str),
    PiecesLengthNotMultipleOf20,
    InvalidLength(&'static str),
    InfoHashMismatch,
    /// A name or file path that is not a plain relative path: it could
    /// write outside the download directory.
    UnsafePath(String),
    /// The number of piece hashes does not match the torrent's length.
    PieceCountMismatch { pieces: usize, expected: u64 },
    /// A length beyond what is sane to handle (or that overflows).
    TooLarge(&'static str),
    /// The BitTorrent v2 part of the metadata (BEP 52) is malformed.
    V2(crate::v2::V2Error),
    /// A `meta version` this client does not know.
    UnsupportedVersion(i64),
}

impl From<DecodeError> for TorrentError {
    fn from(e: DecodeError) -> Self {
        TorrentError::Decode(e)
    }
}

impl std::fmt::Display for TorrentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorrentError::Decode(e) => write!(f, "bencode decode error: {}", e),
            TorrentError::NotADict => write!(f, "top-level value is not a dict"),
            TorrentError::MissingKey(k) => write!(f, "missing required key: {}", k),
            TorrentError::WrongType(k) => write!(f, "key has wrong type: {}", k),
            TorrentError::PiecesLengthNotMultipleOf20 => write!(f, "'pieces' length is not a multiple of 20"),
            TorrentError::InvalidLength(k) => write!(f, "'{}' must be a positive/non-negative integer", k),
            TorrentError::InfoHashMismatch => write!(f, "assembled info dict's SHA-1 does not match the expected InfoHash"),
            TorrentError::UnsafePath(p) => write!(f, "unsafe path in torrent ({:?}): it could write outside the download directory", p),
            TorrentError::PieceCountMismatch { pieces, expected } => write!(f, "torrent lists {} piece hashes but its length needs {}", pieces, expected),
            TorrentError::TooLarge(what) => write!(f, "'{}' is unreasonably large", what),
            TorrentError::V2(e) => write!(f, "BitTorrent v2 metadata: {}", e),
            TorrentError::UnsupportedVersion(v) => write!(f, "meta version {} is not supported", v),
        }
    }
}

impl std::error::Error for TorrentError {}

/// The largest piece length accepted, 128 MiB. Real torrents use 16 KiB to
/// 64 MiB, and the biggest common clients stop at 128 MiB. A whole piece
/// is held in memory by each worker while it downloads, so a larger claim
/// is a way to exhaust memory, and the length is carried as a `u32` below.
pub const MAX_PIECE_LENGTH: i64 = 128 << 20;

/// Whether `part` is exactly one ordinary path component: not empty, not
/// `.` or `..`, no separator of either kind, no NUL, and not absolute or a
/// drive prefix on the platform we are running on.
///
/// This is what stands between a hostile torrent and files written outside
/// the download directory: `PathBuf::join` with an absolute component
/// *replaces* the path, and `..` climbs out of it.
pub(crate) fn is_safe_component(part: &str) -> bool {
    if part.is_empty() || part.contains(['/', '\\', '\0']) {
        return false;
    }
    let mut components = std::path::Path::new(part).components();
    matches!((components.next(), components.next()), (Some(std::path::Component::Normal(_)), None))
}

/// Scans a top-level bencoded dict buffer for `key` and returns the byte
/// span `[value_start, value_end)` of its value, WITHOUT going through the
/// parsed `Bencode` tree. This is what lets us hash the info dict using its
/// *exact original bytes* rather than a re-serialization -- re-encoding a
/// parsed `BTreeMap` risks producing a different byte sequence than the
/// source in edge cases (e.g. a non-canonical but still-valid encode), which
/// would silently produce the wrong InfoHash.
fn find_key_span(data: &[u8], key: &[u8]) -> Result<(usize, usize), TorrentError> {
    if data.first() != Some(&b'd') {
        return Err(TorrentError::NotADict);
    }
    let mut pos = 1usize; // skip the leading 'd'
    loop {
        match data.get(pos) {
            Some(b'e') => return Err(TorrentError::MissingKey("info")),
            None => return Err(TorrentError::Decode(DecodeError::UnexpectedEof)),
            _ => {}
        }

        // Decode the key (must be a byte string) with span tracking.
        let mut kdec = Decoder::new(&data[pos..]);
        let (kval, kspan) = kdec.decode_value_with_span()?;
        let key_bytes = match kval {
            Bencode::Bytes(b) => b,
            _ => return Err(TorrentError::WrongType("dict key")),
        };
        let key_abs_end = pos + kspan.1;

        // Decode the value (any type) with span tracking.
        let mut vdec = Decoder::new(&data[key_abs_end..]);
        let (_vval, vspan) = vdec.decode_value_with_span()?;
        let value_start_abs = key_abs_end + vspan.0;
        let value_end_abs = key_abs_end + vspan.1;

        if key_bytes == key {
            return Ok((value_start_abs, value_end_abs));
        }

        pos = value_end_abs;
    }
}

pub fn parse_torrent_file(data: &[u8]) -> Result<TorrentFile, TorrentError> {
    let top = bencode::decode(data)?;
    let dict = top.as_dict().ok_or(TorrentError::NotADict)?;

    let info = dict.get(b"info".as_slice()).cloned().ok_or(TorrentError::MissingKey("info"))?;

    // Exact-byte InfoHash: locate the raw span of the "info" value in the
    // *original* buffer and SHA-1 it directly.
    let (info_start, info_end) = find_key_span(data, b"info")?;
    let raw_info = &data[info_start..info_end];

    let announce = dict
        .get(b"announce".as_slice())
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let announce_list = dict
        .get(b"announce-list".as_slice())
        .and_then(|v| v.as_list())
        .map(|tiers| {
            tiers
                .iter()
                .filter_map(Bencode::as_list)
                .map(|tier| tier.iter().filter_map(|u| u.as_str().map(str::to_string)).collect())
                .collect()
        })
        .unwrap_or_default();

    // BEP 19 `url-list`: either a single string or a list of strings.
    let url_list = match dict.get(b"url-list".as_slice()) {
        Some(v @ Bencode::Bytes(_)) => v.as_str().map(str::to_string).into_iter().collect(),
        Some(Bencode::List(l)) => l.iter().filter_map(|u| u.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    };

    build_torrent_from_info(info, raw_info, announce, announce_list, url_list, dict.get(b"piece layers".as_slice()))
}

/// Builds a `TorrentFile` from a magnet link's assembled+verified info
/// dict (BEP 9, Phase 4's `MetadataAssembler::assemble_and_verify` output).
/// `raw_info` here IS the whole buffer -- unlike `parse_torrent_file`,
/// there's no outer `.torrent` dict to find "info" inside; the metadata
/// exchange only ever transfers the info dict itself.
///
/// `expected_info_hash` is re-checked here (SHA-1 of `raw_info`) even
/// though the caller almost certainly already ran it through
/// `assemble_and_verify` -- cheap, and this function has no other way to
/// know the hash wasn't tampered with between that check and this call.
pub fn from_info_dict_bytes(raw_info: &[u8], expected_info_hash: [u8; 20], announce: Option<String>, announce_list: Vec<Vec<String>>) -> Result<TorrentFile, TorrentError> {
    let mut hasher = Sha1::new();
    hasher.update(raw_info);
    let actual: [u8; 20] = hasher.finalize().into();
    if actual != expected_info_hash {
        return Err(TorrentError::InfoHashMismatch);
    }

    let info = bencode::decode(raw_info)?;
    // Magnet metadata (BEP 9) transfers only the info dict, which never
    // contains `url-list`; web seeds, if any, would arrive via the magnet
    // `ws=` param (not currently parsed).
    build_torrent_from_info(info, raw_info, announce, announce_list, Vec::new(), None)
}

/// Shared construction logic: given a parsed info dict value and the raw
/// bytes it was decoded from (for the InfoHash), builds the rest of
/// `TorrentFile`'s fields identically regardless of whether the info dict
/// came from a `.torrent` file or a magnet metadata exchange.
fn build_torrent_from_info(info: Bencode, raw_info: &[u8], announce: Option<String>, announce_list: Vec<Vec<String>>, url_list: Vec<String>, layers: Option<&Bencode>) -> Result<TorrentFile, TorrentError> {
    // BitTorrent v2 (BEP 52): a torrent with a file tree and no v1 piece hashes
    // is v2 only; one with both is a hybrid, which this reads as v1.
    let version = info.get("meta version").and_then(Bencode::as_int);
    if let Some(version) = version.filter(|&v| v != 2) {
        return Err(TorrentError::UnsupportedVersion(version));
    }
    let file_tree = info.get("file tree").filter(|_| version == Some(2));
    if let (Some(tree), None) = (file_tree, info.get("pieces")) {
        return build_v2_only_torrent(info.clone(), tree, raw_info, announce, announce_list, url_list, layers);
    }
    let v2 = file_tree.and_then(|tree| v2_meta(&info, tree, raw_info, layers).ok());

    let mut hasher = Sha1::new();
    hasher.update(raw_info);
    let info_hash: [u8; 20] = hasher.finalize().into();

    let piece_length = info
        .get("piece length")
        .and_then(Bencode::as_int)
        .ok_or(TorrentError::MissingKey("piece length"))?;
    // Guard the numeric fields before they're cast to u64 elsewhere: a
    // non-positive piece length leads to division-by-zero in piece math, and
    // a negative file length would wrap to a gigantic u64 (huge allocation).
    if piece_length <= 0 {
        return Err(TorrentError::InvalidLength("piece length"));
    }

    let pieces_raw = info.get("pieces").and_then(Bencode::as_bytes).ok_or(TorrentError::MissingKey("pieces"))?;
    if pieces_raw.len() % 20 != 0 {
        return Err(TorrentError::PiecesLengthNotMultipleOf20);
    }
    // (No remainder: the length was checked to be a multiple of 20.)
    let pieces: Vec<[u8; 20]> = pieces_raw.as_chunks::<20>().0.to_vec();

    if piece_length > MAX_PIECE_LENGTH {
        return Err(TorrentError::TooLarge("piece length"));
    }

    let name = info.get("name").and_then(Bencode::as_str).ok_or(TorrentError::MissingKey("name"))?.to_string();
    // The name is the file's name, or the directory the files go under.
    if !is_safe_component(&name) {
        return Err(TorrentError::UnsafePath(name));
    }

    let multi_file = info.get("length").and_then(Bencode::as_int).is_none() && info.get("files").is_some();
    let files = if let Some(len) = info.get("length").and_then(Bencode::as_int) {
        // Single-file torrent.
        if len < 0 {
            return Err(TorrentError::InvalidLength("length"));
        }
        vec![(vec![name.clone()], len)]
    } else if let Some(file_list) = info.get("files").and_then(Bencode::as_list) {
        // Multi-file torrent.
        file_list
            .iter()
            .map(|f| {
                let length = f.get("length").and_then(Bencode::as_int).ok_or(TorrentError::MissingKey("length"))?;
                if length < 0 {
                    return Err(TorrentError::InvalidLength("length"));
                }
                let path: Vec<String> = f
                    .get("path")
                    .and_then(Bencode::as_list)
                    .ok_or(TorrentError::MissingKey("path"))?
                    .iter()
                    .filter_map(|p| p.as_str().map(str::to_string))
                    .collect();
                if path.is_empty() {
                    return Err(TorrentError::UnsafePath(String::new()));
                }
                if let Some(bad) = path.iter().find(|part| !is_safe_component(part)) {
                    return Err(TorrentError::UnsafePath(bad.clone()));
                }
                Ok::<_, TorrentError>((path, length))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        return Err(TorrentError::MissingKey("length|files"));
    };

    // The piece math trusts these numbers, so cross-check them here: the
    // total must not overflow, and the piece count must be what that total
    // needs (the last piece's length is `total - piece_length * (n - 1)`,
    // which underflows if there are more pieces than the data can fill).
    let total: u64 = files.iter().try_fold(0u64, |sum, (_, len)| sum.checked_add(*len as u64)).ok_or(TorrentError::TooLarge("total length"))?;
    let expected_pieces = total.div_ceil(piece_length as u64);
    if pieces.len() as u64 != expected_pieces {
        return Err(TorrentError::PieceCountMismatch { pieces: pieces.len(), expected: expected_pieces });
    }

    // BEP 27 specifies `private=1`, but libtorrent treats any non-zero
    // value as private. Erring toward private is the safe direction: the
    // cost of a false positive is a slower swarm, the cost of a false
    // negative is leaking a private tracker's peers into the public DHT.
    let private = info.get("private").and_then(Bencode::as_int).is_some_and(|v| v != 0);

    Ok(TorrentFile {
        announce,
        announce_list,
        info,
        info_hash,
        piece_length,
        pieces,
        name,
        files,
        multi_file,
        url_list,
        private,
        v2,
        v2_pieces: Vec::new(),
    })
}

/// The v2 metadata of an info dictionary: its files, the layers the
/// `.torrent` carries, and the SHA-256 of the dictionary. The layers are
/// checked against the files.
fn v2_meta(info: &Bencode, tree: &Bencode, raw_info: &[u8], layers: Option<&Bencode>) -> Result<crate::v2::V2Meta, TorrentError> {
    let files = crate::v2::parse_file_tree(tree).map_err(TorrentError::V2)?;
    let layers = crate::v2::parse_layers(layers).map_err(TorrentError::V2)?;
    let piece_length = info.get("piece length").and_then(Bencode::as_int).ok_or(TorrentError::MissingKey("piece length"))?;
    crate::v2::validate_layers(&files, &layers, piece_length).map_err(TorrentError::V2)?;
    Ok(crate::v2::V2Meta { files, layers, info_hash: crate::sha256::sha256(raw_info) })
}

/// A torrent that is BitTorrent v2 only. It has no piece hashes of the v1
/// kind, so `pieces` is empty; what a piece must hash to is in the layers.
fn build_v2_only_torrent(info: Bencode, tree: &Bencode, raw_info: &[u8], announce: Option<String>, announce_list: Vec<Vec<String>>, url_list: Vec<String>, layers: Option<&Bencode>) -> Result<TorrentFile, TorrentError> {
    let piece_length = info.get("piece length").and_then(Bencode::as_int).ok_or(TorrentError::MissingKey("piece length"))?;
    if !crate::v2::valid_piece_length(piece_length) {
        return Err(TorrentError::V2(crate::v2::V2Error::BadPieceLength));
    }
    if piece_length > MAX_PIECE_LENGTH {
        return Err(TorrentError::TooLarge("piece length"));
    }
    let name = info.get("name").and_then(Bencode::as_str).ok_or(TorrentError::MissingKey("name"))?.to_string();
    if !is_safe_component(&name) {
        return Err(TorrentError::UnsafePath(name));
    }
    let meta = v2_meta(&info, tree, raw_info, layers)?;
    let mut files = Vec::with_capacity(meta.files.len());
    let mut total = 0u64;
    for file in &meta.files {
        total = total.checked_add(file.length).ok_or(TorrentError::TooLarge("total length"))?;
        files.push((file.path.clone(), i64::try_from(file.length).map_err(|_| TorrentError::TooLarge("length"))?));
    }
    // A single file is a tree of one entry named as the torrent is.
    let multi_file = !(meta.files.len() == 1 && meta.files[0].path == [name.clone()]);
    let private = info.get("private").and_then(Bencode::as_int).is_some_and(|v| v != 0);
    let info_hash = meta.short_hash();
    // With the layers, every piece has something to be checked against and can be
    // fetched like a v1 piece (`pieces` then holds the first 20 bytes of each
    // expected hash, so that the counts everything works from are right).
    let v2_pieces = crate::v2::plan_pieces(&meta.files, &meta.layers, piece_length as u64).unwrap_or_default();
    let pieces = v2_pieces.iter().map(|p| <[u8; 20]>::try_from(&p.root[..20]).unwrap_or([0; 20])).collect();
    Ok(TorrentFile { announce, announce_list, info, info_hash, piece_length, pieces, name, files, multi_file, url_list, private, v2: Some(meta), v2_pieces })
}

pub fn info_hash_hex(hash: &[u8; 20]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

impl TorrentFile {
    /// Every tracker URL the torrent names, `announce` and every tier of
    /// `announce-list`, without duplicates.
    pub fn tracker_urls(&self) -> Vec<String> {
        let mut urls: Vec<String> = self.announce.iter().cloned().collect();
        for tier in &self.announce_list {
            urls.extend(tier.iter().cloned());
        }
        urls.sort();
        urls.dedup();
        urls
    }

    /// The trackers as BEP 12 has them: the tiers of `announce-list`, most preferred first (empty tiers left out),
    /// or, with no list, `announce` as a tier of its own. A torrent whose list does not include its `announce` gets
    /// that too, as a tier before the rest, since a client that ignored it would be ignoring a tracker the maker named.
    pub fn tracker_tiers(&self) -> Vec<Vec<String>> {
        let mut tiers: Vec<Vec<String>> = self.announce_list.iter().filter(|tier| !tier.is_empty()).cloned().collect();
        if let Some(announce) = &self.announce {
            if !tiers.iter().any(|tier| tier.contains(announce)) {
                tiers.insert(0, vec![announce.clone()]);
            }
        }
        tiers
    }

    /// Whether the torrent is BitTorrent v2 only (BEP 52), with no v1 piece
    /// hashes: it can be read, listed and verified, but not yet downloaded.
    pub fn is_v2_only(&self) -> bool {
        self.v2.is_some() && self.info.get("pieces").is_none()
    }

    /// Whether a v2-only torrent has what it takes to be downloaded: every piece
    /// has a hash to be checked against (the `.torrent` carried the piece layers).
    pub fn v2_ready(&self) -> bool {
        self.is_v2_only() && (!self.v2_pieces.is_empty() || self.total_length() == 0)
    }

    /// Where each file lies in the torrent's flat byte space, under `base_dir`.
    /// In a v2 torrent every file begins on a piece boundary, so the gaps
    /// between files hold no piece.
    pub fn file_spans(&self, base_dir: &std::path::Path) -> Vec<crate::downloader::file_writer::FileSpan> {
        if self.is_v2_only() {
            crate::downloader::file_writer::build_file_spans_aligned(base_dir, &self.files, self.piece_length as u64)
        } else {
            crate::downloader::file_writer::build_file_spans(base_dir, &self.files)
        }
    }

    /// Sum of every file's length -- the total number of bytes the torrent
    /// contains, which the last piece's length is derived from.
    pub fn total_length(&self) -> u64 {
        self.files.iter().map(|(_, len)| *len as u64).sum()
    }

    /// Length of piece `index` in bytes. Every piece is `piece_length`
    /// except the last, which is whatever remains
    /// (`total_length - piece_length * (num_pieces - 1)`).
    pub fn piece_len(&self, index: usize) -> u64 {
        // A v2 piece is part of one file, so a file's last piece is short.
        if !self.v2_pieces.is_empty() {
            return self.v2_pieces.get(index).map_or(0, |p| p.length as u64);
        }
        let num_pieces = self.pieces.len() as u64;
        let last_index = num_pieces.saturating_sub(1);
        if index as u64 == last_index {
            self.total_length() - self.piece_length as u64 * last_index
        } else {
            self.piece_length as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Single-file torrent, one 20-byte piece hash (all zero bytes as a stand-in).
    fn single_file_torrent_bytes() -> Vec<u8> {
        let mut piece_hash = [0u8; 20];
        piece_hash[0] = 0xAB;
        let mut s = Vec::new();
        s.extend_from_slice(b"d8:announce20:http://tracker.test/4:infod6:lengthi1024e4:name8:file.bin12:piece lengthi16384e6:pieces20:");
        s.extend_from_slice(&piece_hash);
        s.extend_from_slice(b"ee");
        s
    }

    /// Same shape as `single_file_torrent_bytes`, with `private_kv`
    /// appended to the info dict. Bencode keys must stay sorted and
    /// "private" sorts after "pieces", so appending is the valid spot.
    fn torrent_bytes_with_private(private_kv: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(b"d8:announce20:http://tracker.test/4:infod6:lengthi1024e4:name8:file.bin12:piece lengthi16384e6:pieces20:");
        s.extend_from_slice(&[0xAB; 20]);
        s.extend_from_slice(private_kv);
        s.extend_from_slice(b"ee");
        s
    }

    #[test]
    fn torrent_without_private_key_is_public() {
        assert!(!parse_torrent_file(&single_file_torrent_bytes()).unwrap().private);
    }

    #[test]
    fn private_one_marks_the_torrent_private() {
        assert!(parse_torrent_file(&torrent_bytes_with_private(b"7:privatei1e")).unwrap().private);
    }

    #[test]
    fn private_zero_is_public() {
        assert!(!parse_torrent_file(&torrent_bytes_with_private(b"7:privatei0e")).unwrap().private);
    }

    #[test]
    fn non_integer_private_value_is_treated_as_public() {
        assert!(!parse_torrent_file(&torrent_bytes_with_private(b"7:private3:yes")).unwrap().private);
    }

    #[test]
    fn private_flag_is_covered_by_the_info_hash() {
        // `private` lives inside the info dict, so it changes the hash --
        // which is exactly why a client can't be tricked into treating a
        // private torrent as public by editing outside the info dict.
        let public = parse_torrent_file(&single_file_torrent_bytes()).unwrap();
        let private = parse_torrent_file(&torrent_bytes_with_private(b"7:privatei1e")).unwrap();
        assert_ne!(public.info_hash, private.info_hash);
    }

    #[test]
    fn parses_single_file_torrent() {
        let bytes = single_file_torrent_bytes();
        let t = parse_torrent_file(&bytes).unwrap();
        assert_eq!(t.announce.as_deref(), Some("http://tracker.test/"));
        assert_eq!(t.name, "file.bin");
        assert_eq!(t.piece_length, 16384);
        assert_eq!(t.pieces.len(), 1);
        assert_eq!(t.files, vec![(vec!["file.bin".to_string()], 1024)]);
    }

    #[test]
    fn info_hash_matches_manual_sha1_of_info_span() {
        let bytes = single_file_torrent_bytes();
        let t = parse_torrent_file(&bytes).unwrap();

        // Manually locate "4:info" and hash everything from the 'd' right
        // after it up to (and including) its matching 'e', cross-checking
        // find_key_span's result independently.
        let marker = b"4:info";
        let marker_pos = bytes.windows(marker.len()).position(|w| w == marker).unwrap();
        let info_start = marker_pos + marker.len();
        assert_eq!(bytes[info_start], b'd');
        // The info dict in our fixture is the last thing before the final 'e'
        // of the top-level dict, so its end is len - 1.
        let info_end = bytes.len() - 1;
        let mut hasher = Sha1::new();
        hasher.update(&bytes[info_start..info_end]);
        let expected: [u8; 20] = hasher.finalize().into();

        assert_eq!(t.info_hash, expected);
    }

    #[test]
    fn multi_file_torrent_parses_files_list() {
        let bytes = b"d4:infod5:filesld6:lengthi100e4:pathl3:dir5:a.txteed6:lengthi200e4:pathl5:b.txteee4:name3:dir12:piece lengthi16384e6:pieces20:00000000000000000000ee".to_vec();
        let t = parse_torrent_file(&bytes).unwrap();
        assert_eq!(t.name, "dir");
        assert_eq!(
            t.files,
            vec![
                (vec!["dir".to_string(), "a.txt".to_string()], 100),
                (vec!["b.txt".to_string()], 200),
            ]
        );
    }

    #[test]
    fn parses_url_list_as_single_string() {
        // "http://mirror.test/f.bin" is 24 bytes. `url-list` sorts before
        // `info`, keeping the top-level dict keys canonically ordered.
        let mut s = Vec::new();
        s.extend_from_slice(b"d4:infod6:lengthi1024e4:name5:f.bin12:piece lengthi16384e6:pieces20:");
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(b"e8:url-list24:http://mirror.test/f.bine");
        let t = parse_torrent_file(&s).unwrap();
        assert_eq!(t.url_list, vec!["http://mirror.test/f.bin".to_string()]);
    }

    #[test]
    fn parses_url_list_as_list() {
        // "http://a.test/f.bin" is 19 bytes.
        let mut s = Vec::new();
        s.extend_from_slice(b"d4:infod6:lengthi1024e4:name5:f.bin12:piece lengthi16384e6:pieces20:");
        s.extend_from_slice(&[0u8; 20]);
        s.extend_from_slice(b"e8:url-listl19:http://a.test/f.bin19:http://b.test/f.binee");
        let t = parse_torrent_file(&s).unwrap();
        assert_eq!(t.url_list, vec!["http://a.test/f.bin".to_string(), "http://b.test/f.bin".to_string()]);
    }

    #[test]
    fn absent_url_list_is_empty() {
        let t = parse_torrent_file(&single_file_torrent_bytes()).unwrap();
        assert!(t.url_list.is_empty());
    }

    #[test]
    fn rejects_pieces_not_multiple_of_20() {
        let bytes = b"d4:infod6:lengthi1e4:name1:a12:piece lengthi1e6:pieces3:abcee".to_vec();
        assert!(matches!(parse_torrent_file(&bytes), Err(TorrentError::PiecesLengthNotMultipleOf20)));
    }

    #[test]
    fn info_hash_hex_formats_lowercase() {
        let mut h = [0u8; 20];
        h[0] = 0xDE;
        h[1] = 0xAD;
        assert!(info_hash_hex(&h).starts_with("dead"));
    }

    #[test]
    fn piece_len_returns_piece_length_for_all_but_last() {
        // 3 pieces, piece_length 16384, total 40000 -> last piece = 40000 - 32768 = 7232
        let bytes = b"d4:infod6:lengthi40000e4:name1:a12:piece lengthi16384e6:pieces60:000000000000000000001111111111111111111122222222222222222222ee".to_vec();
        let t = parse_torrent_file(&bytes).unwrap();
        assert_eq!(t.pieces.len(), 3);
        assert_eq!(t.piece_len(0), 16384);
        assert_eq!(t.piece_len(1), 16384);
        assert_eq!(t.piece_len(2), 40000 - 16384 * 2);
    }

    #[test]
    fn total_length_sums_multi_file_torrent() {
        let bytes = b"d4:infod5:filesld6:lengthi100e4:pathl3:dir5:a.txteed6:lengthi200e4:pathl5:b.txteee4:name3:dir12:piece lengthi16384e6:pieces20:00000000000000000000ee".to_vec();
        let t = parse_torrent_file(&bytes).unwrap();
        assert_eq!(t.total_length(), 300);
    }

    #[test]
    fn from_info_dict_bytes_matches_parse_torrent_file_for_the_same_info() {
        let full = single_file_torrent_bytes();
        let via_file = parse_torrent_file(&full).unwrap();

        // Extract just the raw info dict bytes the way a ut_metadata
        // exchange would deliver them (see metadata.rs / magnet_fetch.rs).
        let marker = b"4:info";
        let marker_pos = full.windows(marker.len()).position(|w| w == marker).unwrap();
        let info_start = marker_pos + marker.len();
        let info_end = full.len() - 1;
        let raw_info = &full[info_start..info_end];

        let via_magnet = from_info_dict_bytes(raw_info, via_file.info_hash, None, vec![]).unwrap();
        assert_eq!(via_magnet.info_hash, via_file.info_hash);
        assert_eq!(via_magnet.name, via_file.name);
        assert_eq!(via_magnet.pieces, via_file.pieces);
        assert_eq!(via_magnet.files, via_file.files);
    }

    #[test]
    fn from_info_dict_bytes_rejects_hash_mismatch() {
        let raw_info = b"d6:lengthi5e4:name1:a12:piece lengthi5e6:pieces20:00000000000000000000e";
        let wrong_hash = [0xFFu8; 20];
        assert!(matches!(from_info_dict_bytes(raw_info, wrong_hash, None, vec![]), Err(TorrentError::InfoHashMismatch)));
    }

    // ---- hostile torrents ------------------------------------------------

    /// A bencoded string.
    fn bstr(b: &[u8]) -> Vec<u8> {
        let mut v = format!("{}:", b.len()).into_bytes();
        v.extend_from_slice(b);
        v
    }

    /// A single-file `.torrent` with the given name, length, piece length
    /// and number of piece hashes.
    fn single(name: &[u8], length: i64, piece_length: i64, pieces: usize) -> Vec<u8> {
        let mut v = b"d4:infod".to_vec();
        v.extend_from_slice(format!("6:lengthi{}e4:name", length).as_bytes());
        v.extend_from_slice(&bstr(name));
        v.extend_from_slice(format!("12:piece lengthi{}e6:pieces{}:", piece_length, pieces * 20).as_bytes());
        v.extend_from_slice(&vec![0xAB; pieces * 20]);
        v.extend_from_slice(b"ee");
        v
    }

    /// A multi-file `.torrent`: `files` are (path components, length).
    fn multi(name: &[u8], files: &[(&[&[u8]], i64)], piece_length: i64, pieces: usize) -> Vec<u8> {
        let mut v = b"d4:infod5:filesl".to_vec();
        for (path, length) in files {
            v.extend_from_slice(format!("d6:lengthi{}e4:pathl", length).as_bytes());
            for part in *path {
                v.extend_from_slice(&bstr(part));
            }
            v.extend_from_slice(b"ee");
        }
        v.extend_from_slice(b"e4:name");
        v.extend_from_slice(&bstr(name));
        v.extend_from_slice(format!("12:piece lengthi{}e6:pieces{}:", piece_length, pieces * 20).as_bytes());
        v.extend_from_slice(&vec![0xAB; pieces * 20]);
        v.extend_from_slice(b"ee");
        v
    }

    fn is_unsafe(result: Result<TorrentFile, TorrentError>) -> bool {
        matches!(result, Err(TorrentError::UnsafePath(_)))
    }

    /// Names and path components that would escape the download directory
    /// or mean something other than one plain file or directory name.
    const HOSTILE: &[&[u8]] = &[b"..", b".", b"", b"a/b", b"a\\b", b"/etc/passwd", b"../x", b"..\\x", b"x\0y", b"/", b"a/../b"];

    #[test]
    fn a_single_file_torrent_named_to_escape_is_refused() {
        for name in HOSTILE {
            assert!(is_unsafe(parse_torrent_file(&single(name, 100, 16384, 1))), "name {:?} must be refused", String::from_utf8_lossy(name));
        }
    }

    #[test]
    fn a_multi_file_torrent_naming_its_directory_to_escape_is_refused() {
        let file: (&[&[u8]], i64) = (&[b"ok.bin"], 100);
        for name in HOSTILE {
            assert!(is_unsafe(parse_torrent_file(&multi(name, &[file], 16384, 1))), "directory {:?} must be refused", String::from_utf8_lossy(name));
        }
    }

    #[test]
    fn a_file_path_component_that_would_escape_is_refused() {
        for bad in HOSTILE {
            let path: &[&[u8]] = &[b"fine", bad, b"file.bin"];
            assert!(is_unsafe(parse_torrent_file(&multi(b"t", &[(path, 100)], 16384, 1))), "component {:?} must be refused", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_file_with_no_path_is_refused() {
        // It would be written to the download directory's own path.
        assert!(is_unsafe(parse_torrent_file(&multi(b"t", &[(&[], 100)], 16384, 1))));
    }

    #[test]
    fn a_path_of_only_undecodable_components_is_refused_too() {
        // Components that are not UTF-8 are dropped, leaving no path at all.
        assert!(is_unsafe(parse_torrent_file(&multi(b"t", &[(&[b"\xff\xfe"], 100)], 16384, 1))));
    }

    #[test]
    fn ordinary_names_and_nested_paths_are_accepted() {
        assert!(parse_torrent_file(&single(b"movie (2024).mkv", 100, 16384, 1)).is_ok());
        assert!(parse_torrent_file(&single(b".hidden", 100, 16384, 1)).is_ok());
        assert!(parse_torrent_file(&single("naïve café.txt".as_bytes(), 100, 16384, 1)).is_ok());
        let nested: &[&[u8]] = &[b"season 1", b"episode 01.mkv"];
        assert!(parse_torrent_file(&multi(b"show", &[(nested, 100)], 16384, 1)).is_ok());
    }

    #[test]
    fn metadata_fetched_for_a_magnet_link_is_checked_the_same_way() {
        // The info-hash only proves the metadata is what its creator
        // published; it says nothing about whether it is safe.
        let hostile = single(b"../../.ssh/authorized_keys", 100, 16384, 1);
        let start = hostile.windows(6).position(|w| w == b"4:info").unwrap() + 6;
        let raw_info = &hostile[start..hostile.len() - 1];
        let hash: [u8; 20] = Sha1::digest(raw_info).into();
        assert!(is_unsafe(from_info_dict_bytes(raw_info, hash, None, Vec::new())));
    }

    #[test]
    fn the_piece_count_must_match_the_length() {
        assert!(parse_torrent_file(&single(b"f", 40000, 16384, 3)).is_ok(), "40000 bytes in 16384s is 3 pieces");
        for wrong in [0, 1, 2, 4, 1000] {
            let result = parse_torrent_file(&single(b"f", 40000, 16384, wrong));
            assert!(matches!(result, Err(TorrentError::PieceCountMismatch { pieces, expected: 3 }) if pieces == wrong), "{} hashes: {:?}", wrong, result.err());
        }
        // The exact boundary: 32768 bytes is 2 pieces, one more byte is 3.
        assert!(parse_torrent_file(&single(b"f", 32768, 16384, 2)).is_ok());
        assert!(parse_torrent_file(&single(b"f", 32769, 16384, 3)).is_ok());
    }

    #[test]
    fn an_empty_torrent_has_no_pieces() {
        assert!(parse_torrent_file(&single(b"f", 0, 16384, 0)).is_ok());
        assert!(matches!(parse_torrent_file(&single(b"f", 0, 16384, 1)), Err(TorrentError::PieceCountMismatch { .. })));
    }

    #[test]
    fn more_pieces_than_the_data_can_fill_can_no_longer_underflow_the_last_piece() {
        // piece_len() computes total - piece_length * (n - 1) for the last
        // piece. With 1000 hashes for 10 bytes that used to be a u64
        // underflow: a panic in debug builds, a wrong length in release.
        assert!(parse_torrent_file(&single(b"f", 10, 16384, 1000)).is_err());
    }

    #[test]
    fn every_piece_of_an_accepted_torrent_has_a_length_that_fits() {
        let t = parse_torrent_file(&single(b"f", 40000, 16384, 3)).unwrap();
        let lengths: Vec<u64> = (0..t.pieces.len()).map(|i| t.piece_len(i)).collect();
        assert_eq!(lengths, vec![16384, 16384, 40000 - 2 * 16384]);
        assert_eq!(lengths.iter().sum::<u64>(), t.total_length());
    }

    #[test]
    fn an_absurd_piece_length_is_refused() {
        assert!(parse_torrent_file(&single(b"f", 100, MAX_PIECE_LENGTH, 1)).is_ok());
        assert!(matches!(parse_torrent_file(&single(b"f", 100, MAX_PIECE_LENGTH + 1, 1)), Err(TorrentError::TooLarge("piece length"))));
        assert!(matches!(parse_torrent_file(&single(b"f", 100, i64::MAX, 1)), Err(TorrentError::TooLarge("piece length"))));
    }

    #[test]
    fn file_lengths_that_overflow_when_added_are_refused() {
        let files: &[(&[&[u8]], i64)] = &[(&[b"a"], i64::MAX), (&[b"b"], i64::MAX), (&[b"c"], i64::MAX)];
        assert!(matches!(parse_torrent_file(&multi(b"t", files, 16384, 1)), Err(TorrentError::TooLarge("total length"))));
    }

    #[test]
    fn the_form_of_the_info_dict_is_recorded_not_guessed_from_the_file_count() {
        assert!(!parse_torrent_file(&single(b"f", 100, 16384, 1)).unwrap().multi_file, "a `length` key means a single file");
        let one: &[(&[&[u8]], i64)] = &[(&[b"only.bin"], 100)];
        let two: &[(&[&[u8]], i64)] = &[(&[b"a.bin"], 50), (&[b"b.bin"], 50)];
        assert!(parse_torrent_file(&multi(b"dir", two, 16384, 1)).unwrap().multi_file);
        assert!(
            parse_torrent_file(&multi(b"dir", one, 16384, 1)).unwrap().multi_file,
            "a `files` list with a single entry is still the multi-file form, and its name is a directory"
        );
    }

    // ---- BitTorrent v2 (BEP 52) ----
    // The torrents below were built by a Python script that shares nothing with this code.

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    const V2_ONLY: &str = "64383a616e6e6f756e636531383a687474703a2f2f742e6578616d706c652f61343a696e666f64393a66696c65207472656564353a662e62696e64303a64363a6c656e6774686934303030306531313a70696563657320726f6f7433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68265656531323a6d6574612076657273696f6e693265343a6e616d65353a662e62696e31323a7069656365206c656e677468693136333834656531323a7069656365206c61796572736433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68239363acfa57d60545ac82e09b63df067e2396f9377bac5311c3b159e50a61a2275876be25b78513a631bd38a5cc26875de9b787f1250a16ec6ad92f880fb37bfe5fa62eebf7c92de9855ef3886236a4378a7054258749ace85d10875991b9f13a6abab6565";
    const V2_ONLY_SHA256: &str = "73ec1349d7abba4a6808971cc642ddc3ed620191741baf40cb10f26bdcfbc1f7";
    const V2_ROOT: &str = "b01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa682";
    const HYBRID: &str = "64343a696e666f64393a66696c65207472656564353a662e62696e64303a64363a6c656e6774686934303030306531313a70696563657320726f6f7433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa682656565363a6c656e6774686934303030306531323a6d6574612076657273696f6e693265343a6e616d65353a662e62696e31323a7069656365206c656e67746869313633383465363a70696563657336303a6ab462cc165379d368dc9206fc25f8546e894131fd1d4adde2a16bf56c84129d6902e8d056d38311218898aa5c30e0ed9d2e1f9451b673dda2498a366531323a7069656365206c61796572736433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68239363acfa57d60545ac82e09b63df067e2396f9377bac5311c3b159e50a61a2275876be25b78513a631bd38a5cc26875de9b787f1250a16ec6ad92f880fb37bfe5fa62eebf7c92de9855ef3886236a4378a7054258749ace85d10875991b9f13a6abab6565";
    const HYBRID_SHA1: &str = "f7ad704f94c56d10621e59ff6e562e0cacb0f7f4";
    const HYBRID_SHA256: &str = "9d3ff85840fcbf09db7a59d6246a7d35118f4c5b732c40a506a06e5f5d343d70";
    const V2_TAMPERED_LAYER: &str = "64343a696e666f64393a66696c65207472656564353a662e62696e64303a64363a6c656e6774686934303030306531313a70696563657320726f6f7433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68265656531323a6d6574612076657273696f6e693265343a6e616d65353a662e62696e31323a7069656365206c656e677468693136333834656531323a7069656365206c61796572736433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68239363acea57d60545ac82e09b63df067e2396f9377bac5311c3b159e50a61a2275876be25b78513a631bd38a5cc26875de9b787f1250a16ec6ad92f880fb37bfe5fa62eebf7c92de9855ef3886236a4378a7054258749ace85d10875991b9f13a6abab6565";
    const META_VERSION_3: &str = "64343a696e666f64393a66696c65207472656564353a662e62696e64303a64363a6c656e6774686934303030306531313a70696563657320726f6f7433323ab01c2fe631bd8f28d2c5161725cc5630755231ea794c7d087f36f4161abfa68265656531323a6d6574612076657273696f6e693365343a6e616d65353a662e62696e31323a7069656365206c656e677468693136333834656565";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn a_v2_only_torrent_is_read_with_its_files_and_the_short_form_of_its_sha256_hash() {
        let t = parse_torrent_file(&unhex(V2_ONLY)).unwrap();
        assert!(t.is_v2_only());
        assert_eq!((t.name.as_str(), t.piece_length, t.multi_file), ("f.bin", 16384, false), "one file named as the torrent is: a single-file torrent");
        assert_eq!(t.files, vec![(vec!["f.bin".to_string()], 40_000)]);
        assert!(t.info.get("pieces").is_none(), "there are no v1 hashes");
        assert!(t.v2_ready());
        assert_eq!(t.v2_pieces.iter().map(|p| (p.file, p.offset, p.length)).collect::<Vec<_>>(), vec![(0, 0, 16384), (0, 16384, 16384), (0, 32768, 7232)], "three pieces, the last short");
        assert_eq!(t.pieces.len(), 3, "so the counts everything works from are right");
        assert_eq!(t.piece_len(2), 7232);
        assert_eq!(hex(&t.v2.as_ref().unwrap().info_hash), V2_ONLY_SHA256);
        assert_eq!(hex(&t.info_hash), &V2_ONLY_SHA256[..40], "what the handshake, trackers and the DHT know it by");
        assert_eq!(hex(&t.v2.as_ref().unwrap().files[0].root.unwrap()), V2_ROOT);
        assert_eq!(t.announce.as_deref(), Some("http://t.example/a"));
        assert_eq!(t.total_length(), 40_000);
    }

    #[test]
    fn a_hybrid_torrent_is_read_as_v1_and_also_carries_its_v2_side() {
        let t = parse_torrent_file(&unhex(HYBRID)).unwrap();
        assert!(!t.is_v2_only());
        assert_eq!(hex(&t.info_hash), HYBRID_SHA1, "the v1 hash, as before");
        assert_eq!(t.pieces.len(), 3);
        let v2 = t.v2.as_ref().expect("and the v2 side");
        assert_eq!(hex(&v2.info_hash), HYBRID_SHA256, "over the same info dictionary, with SHA-256");
        assert_eq!(hex(&v2.files[0].root.unwrap()), V2_ROOT);
    }

    #[test]
    fn a_v1_torrent_has_no_v2_side() {
        let t = parse_torrent_file(b"d4:infod6:lengthi10e4:name1:a12:piece lengthi16384e6:pieces20:00000000000000000000ee").unwrap();
        assert!(t.v2.is_none() && !t.is_v2_only());
    }

    #[test]
    fn a_v2_torrent_whose_layer_does_not_add_up_to_the_root_is_refused() {
        let err = parse_torrent_file(&unhex(V2_TAMPERED_LAYER)).unwrap_err();
        assert!(matches!(err, TorrentError::V2(crate::v2::V2Error::BadLayer)), "{:?}", err);
    }

    #[test]
    fn a_meta_version_this_client_does_not_know_is_refused_not_misread() {
        let err = parse_torrent_file(&unhex(META_VERSION_3)).unwrap_err();
        assert!(matches!(err, TorrentError::UnsupportedVersion(3)), "{:?}", err);
    }

    #[test]
    fn a_v2_torrent_without_its_layers_is_still_read_they_can_come_from_peers() {
        // The same torrent with the piece layers removed from the outer dictionary.
        let mut top = crate::bencode::decode(&unhex(V2_ONLY)).unwrap();
        if let Bencode::Dict(entries) = &mut top {
            entries.remove(b"piece layers".as_slice());
        }
        let bytes = crate::bencode::encode(&top);
        let t = parse_torrent_file(&bytes).unwrap();
        assert!(t.is_v2_only() && t.v2.as_ref().unwrap().layers.is_empty());
        assert_eq!(hex(&t.v2.as_ref().unwrap().info_hash), V2_ONLY_SHA256, "the info dictionary was not touched, so neither is its hash");
    }

    #[test]
    fn a_v2_torrent_with_an_unsafe_name_or_path_is_refused() {
        let mut top = crate::bencode::decode(&unhex(V2_ONLY)).unwrap();
        if let Bencode::Dict(entries) = &mut top {
            if let Some(Bencode::Dict(info)) = entries.get_mut(b"info".as_slice()) {
                info.insert(b"name".to_vec(), Bencode::Bytes(b"..".to_vec()));
            }
        }
        assert!(matches!(parse_torrent_file(&crate::bencode::encode(&top)).unwrap_err(), TorrentError::UnsafePath(_)));
    }

    #[test]
    fn a_v2_torrent_needs_a_valid_piece_length() {
        let mut top = crate::bencode::decode(&unhex(V2_ONLY)).unwrap();
        if let Bencode::Dict(entries) = &mut top {
            if let Some(Bencode::Dict(info)) = entries.get_mut(b"info".as_slice()) {
                info.insert(b"piece length".to_vec(), Bencode::Int(20_000));
            }
        }
        assert!(matches!(parse_torrent_file(&crate::bencode::encode(&top)).unwrap_err(), TorrentError::V2(crate::v2::V2Error::BadPieceLength)));
    }

    // ---- BEP 12 ------------------------------------------------------------

    fn with_trackers(announce: Option<&str>, list: &[&[&str]]) -> TorrentFile {
        let mut torrent = parse_torrent_file(b"d4:infod6:lengthi10e4:name1:f12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaaee").unwrap();
        torrent.announce = announce.map(str::to_string);
        torrent.announce_list = list.iter().map(|tier| tier.iter().map(|u| u.to_string()).collect()).collect();
        torrent
    }

    #[test]
    fn the_tiers_are_the_announce_list_and_announce_alone_is_a_tier_of_one() {
        assert_eq!(with_trackers(Some("http://a/"), &[]).tracker_tiers(), vec![vec!["http://a/".to_string()]]);
        assert!(with_trackers(None, &[]).tracker_tiers().is_empty());
        let both = with_trackers(Some("http://a/"), &[&["http://a/", "http://b/"], &["http://c/"]]);
        assert_eq!(both.tracker_tiers(), vec![vec!["http://a/".to_string(), "http://b/".to_string()], vec!["http://c/".to_string()]], "as listed, `announce` being in it already");
    }

    #[test]
    fn an_announce_the_list_leaves_out_is_a_tier_before_the_rest_and_empty_tiers_are_dropped() {
        let torrent = with_trackers(Some("http://main/"), &[&[], &["http://b/"], &[]]);
        assert_eq!(torrent.tracker_tiers(), vec![vec!["http://main/".to_string()], vec!["http://b/".to_string()]]);
    }
}
