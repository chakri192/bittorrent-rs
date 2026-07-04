//! Magnet URI parsing (BEP 9). Only the fields needed to bootstrap a
//! metadata exchange: `xt` (InfoHash, hex or base32), `dn` (display name),
//! `tr` (tracker URLs, repeatable).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetLink {
    pub info_hash: [u8; 20],
    pub display_name: Option<String>,
    pub trackers: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MagnetError {
    NotAMagnetUri,
    MissingInfoHash,
    BadInfoHashEncoding(String),
    BadInfoHashLength { expected_chars: &'static str, got: usize },
    InvalidBase32Char(char),
    InvalidHexChar(char),
    InvalidPercentEncoding,
}

impl std::fmt::Display for MagnetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MagnetError::NotAMagnetUri => write!(f, "uri does not start with \"magnet:?\""),
            MagnetError::MissingInfoHash => write!(f, "missing xt=urn:btih:... parameter"),
            MagnetError::BadInfoHashEncoding(s) => write!(f, "unsupported xt urn namespace: {}", s),
            MagnetError::BadInfoHashLength { expected_chars, got } => {
                write!(f, "info hash wrong length: expected {} chars, got {}", expected_chars, got)
            }
            MagnetError::InvalidBase32Char(c) => write!(f, "invalid base32 character: {:?}", c),
            MagnetError::InvalidHexChar(c) => write!(f, "invalid hex character: {:?}", c),
            MagnetError::InvalidPercentEncoding => write!(f, "invalid %XX percent-encoding"),
        }
    }
}

impl std::error::Error for MagnetError {}

pub fn parse_magnet_uri(uri: &str) -> Result<MagnetLink, MagnetError> {
    let query = uri.strip_prefix("magnet:?").ok_or(MagnetError::NotAMagnetUri)?;

    let mut info_hash: Option<[u8; 20]> = None;
    let mut display_name = None;
    let mut trackers = Vec::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(raw_value)?;

        match key {
            "xt" => {
                let hash_str = value.strip_prefix("urn:btih:").ok_or_else(|| MagnetError::BadInfoHashEncoding(value.clone()))?;
                info_hash = Some(decode_info_hash(hash_str)?);
            }
            "dn" => display_name = Some(value),
            "tr" => trackers.push(value),
            _ => {} // ignore unrecognized params (x.pe, kt, ws, as, xs, ...)
        }
    }

    Ok(MagnetLink {
        info_hash: info_hash.ok_or(MagnetError::MissingInfoHash)?,
        display_name,
        trackers,
    })
}

fn decode_info_hash(s: &str) -> Result<[u8; 20], MagnetError> {
    match s.len() {
        40 => decode_hex_20(s),
        32 => decode_base32_20(s),
        n => Err(MagnetError::BadInfoHashLength { expected_chars: "40 (hex) or 32 (base32)", got: n }),
    }
}

fn decode_hex_20(s: &str) -> Result<[u8; 20], MagnetError> {
    let mut out = [0u8; 20];
    let bytes = s.as_bytes();
    for i in 0..20 {
        let hi = hex_nibble(bytes[i * 2] as char)?;
        let lo = hex_nibble(bytes[i * 2 + 1] as char)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: char) -> Result<u8, MagnetError> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        other => Err(MagnetError::InvalidHexChar(other)),
    }
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 decode, no padding. 32 input chars * 5 bits = 160 bits
/// = exactly 20 bytes, which is why BEP 9 uses base32 for the 20-byte
/// InfoHash with no `=` padding needed.
fn decode_base32_20(s: &str) -> Result<[u8; 20], MagnetError> {
    let mut lut = [-1i8; 128];
    for (i, &c) in BASE32_ALPHABET.iter().enumerate() {
        lut[c as usize] = i as i8;
    }

    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::with_capacity(20);

    for c in s.chars().map(|c| c.to_ascii_uppercase()) {
        let idx = if c.is_ascii() { lut[c as usize] } else { -1 };
        if idx < 0 {
            return Err(MagnetError::InvalidBase32Char(c));
        }
        bit_buf = (bit_buf << 5) | (idx as u64);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bit_buf >> bit_count) & 0xFF) as u8);
        }
    }

    let mut fixed = [0u8; 20];
    fixed.copy_from_slice(&out[..20]);
    Ok(fixed)
}

/// Decodes `%XX` percent-encoding in a URI component. Unlike
/// `application/x-www-form-urlencoded`, `+` is left literal (magnet
/// tracker URLs can legitimately contain `+`).
fn percent_decode(s: &str) -> Result<String, MagnetError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(MagnetError::InvalidPercentEncoding);
            }
            let hi = hex_nibble(bytes[i + 1] as char).map_err(|_| MagnetError::InvalidPercentEncoding)?;
            let lo = hex_nibble(bytes[i + 2] as char).map_err(|_| MagnetError::InvalidPercentEncoding)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_info_hash() {
        let uri = "magnet:?xt=urn:btih:AABBCCDDEEFF00112233445566778899AABBCCDD";
        let m = parse_magnet_uri(uri).unwrap();
        assert_eq!(m.info_hash, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parses_lowercase_hex() {
        let uri = "magnet:?xt=urn:btih:aabbccddeeff00112233445566778899aabbccdd";
        let m = parse_magnet_uri(uri).unwrap();
        assert_eq!(m.info_hash[0], 0xAA);
    }

    #[test]
    fn base32_round_trips_against_known_hex_equivalent() {
        // 20 zero bytes in base32 is "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (32 'A's).
        let hash = decode_base32_20(&"A".repeat(32)).unwrap();
        assert_eq!(hash, [0u8; 20]);
    }

    #[test]
    fn base32_decodes_nonzero_pattern() {
        // 0xFF repeated: base32 of 20 0xFF bytes is 32 '7' chars
        // (0b11111 = 31 = '7', and 160 bits of all-1s is exactly 32 groups of 11111).
        let hash = decode_base32_20(&"7".repeat(32)).unwrap();
        assert_eq!(hash, [0xFFu8; 20]);
    }

    #[test]
    fn parses_display_name_and_trackers() {
        let uri = "magnet:?xt=urn:btih:AABBCCDDEEFF00112233445566778899AABBCCDD&dn=Some+File.iso&tr=http%3A%2F%2Ftracker.example.com%2Fannounce&tr=udp%3A%2F%2Ftracker2.example.com%3A6969";
        let m = parse_magnet_uri(uri).unwrap();
        // '+' is left literal (see percent_decode doc comment) -- dn shows it verbatim.
        assert_eq!(m.display_name.as_deref(), Some("Some+File.iso"));
        assert_eq!(m.trackers, vec!["http://tracker.example.com/announce", "udp://tracker2.example.com:6969"]);
    }

    #[test]
    fn rejects_non_magnet_uri() {
        assert_eq!(parse_magnet_uri("http://example.com"), Err(MagnetError::NotAMagnetUri));
    }

    #[test]
    fn rejects_missing_xt() {
        assert_eq!(parse_magnet_uri("magnet:?dn=foo"), Err(MagnetError::MissingInfoHash));
    }

    #[test]
    fn rejects_wrong_length_info_hash() {
        let err = parse_magnet_uri("magnet:?xt=urn:btih:AABB").unwrap_err();
        assert!(matches!(err, MagnetError::BadInfoHashLength { .. }));
    }

    #[test]
    fn rejects_non_btih_namespace() {
        let err = parse_magnet_uri("magnet:?xt=urn:sha1:AABBCCDDEEFF00112233445566778899AABBCCDD").unwrap_err();
        assert!(matches!(err, MagnetError::BadInfoHashEncoding(_)));
    }

    #[test]
    fn magnet_with_no_trackers_is_ok() {
        let m = parse_magnet_uri("magnet:?xt=urn:btih:AABBCCDDEEFF00112233445566778899AABBCCDD").unwrap();
        assert!(m.trackers.is_empty());
        assert!(m.display_name.is_none());
    }
}
