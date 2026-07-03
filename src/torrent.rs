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
}

#[derive(Debug)]
pub enum TorrentError {
    Decode(DecodeError),
    NotADict,
    MissingKey(&'static str),
    WrongType(&'static str),
    PiecesLengthNotMultipleOf20,
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
    let mut hasher = Sha1::new();
    hasher.update(raw_info);
    let info_hash: [u8; 20] = hasher.finalize().into();

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

    let piece_length = info
        .get("piece length")
        .and_then(Bencode::as_int)
        .ok_or(TorrentError::MissingKey("piece length"))?;

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
        vec![(vec![name.clone()], len)]
    } else if let Some(file_list) = info.get("files").and_then(Bencode::as_list) {
        // Multi-file torrent.
        file_list
            .iter()
            .map(|f| {
                let length = f.get("length").and_then(Bencode::as_int).ok_or(TorrentError::MissingKey("length"))?;
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
    })
}

pub fn info_hash_hex(hash: &[u8; 20]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
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
}
