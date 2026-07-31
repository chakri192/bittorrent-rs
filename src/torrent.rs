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
    /// BEP 19 web seeds (`url-list`): HTTP(S) base URLs the content can
    /// also be fetched from. Empty for magnet-derived torrents.
    pub url_list: Vec<String>,
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
        }
    }
}

impl std::error::Error for TorrentError {}

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

    build_torrent_from_info(info, raw_info, announce, announce_list, url_list)
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
    build_torrent_from_info(info, raw_info, announce, announce_list, Vec::new())
}

/// Shared construction logic: given a parsed info dict value and the raw
/// bytes it was decoded from (for the InfoHash), builds the rest of
/// `TorrentFile`'s fields identically regardless of whether the info dict
/// came from a `.torrent` file or a magnet metadata exchange.
fn build_torrent_from_info(info: Bencode, raw_info: &[u8], announce: Option<String>, announce_list: Vec<Vec<String>>, url_list: Vec<String>) -> Result<TorrentFile, TorrentError> {
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
    let pieces = pieces_raw
        .chunks_exact(20)
        .map(|c| {
            let mut h = [0u8; 20];
            h.copy_from_slice(c);
            h
        })
        .collect();

    let name = info.get("name").and_then(Bencode::as_str).ok_or(TorrentError::MissingKey("name"))?.to_string();

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
                let path = f
                    .get("path")
                    .and_then(Bencode::as_list)
                    .ok_or(TorrentError::MissingKey("path"))?
                    .iter()
                    .filter_map(|p| p.as_str().map(str::to_string))
                    .collect();
                Ok::<_, TorrentError>((path, length))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        return Err(TorrentError::MissingKey("length|files"));
    };

    Ok(TorrentFile {
        announce,
        announce_list,
        info,
        info_hash,
        piece_length,
        pieces,
        name,
        files,
        url_list,
    })
}

pub fn info_hash_hex(hash: &[u8; 20]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

impl TorrentFile {
    /// Sum of every file's length -- the total number of bytes the torrent
    /// contains, which the last piece's length is derived from.
    pub fn total_length(&self) -> u64 {
        self.files.iter().map(|(_, len)| *len as u64).sum()
    }

    /// Length of piece `index` in bytes. Every piece is `piece_length`
    /// except the last, which is whatever remains
    /// (`total_length - piece_length * (num_pieces - 1)`).
    pub fn piece_len(&self, index: usize) -> u64 {
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
}
