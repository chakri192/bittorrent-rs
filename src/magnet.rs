//! Magnet URI parsing (BEP 9). The fields needed to bootstrap a metadata
//! exchange: `xt` (the v1 InfoHash, hex or base32; a `urn:btmh:` beside it,
//! as in a hybrid v1/v2 link, is ignored), `dn` (display name), `tr`
//! (tracker URLs), `x.pe` (peers to try directly) and `ws` (BEP 19 web
//! seeds), each repeatable and each also accepted numbered (`tr.1`).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetLink {
    pub info_hash: [u8; 20],
    pub display_name: Option<String>,
    /// `tr` (or `tr.N`), each once, in the order given.
    pub trackers: Vec<String>,
    /// `x.pe` (or `x.pe.N`): addresses of peers to try directly (BEP 9),
    /// so a link with no tracker and no DHT still has somewhere to start.
    /// Only `ip:port` and `[ipv6]:port` forms; a hostname is not resolved.
    pub peers: Vec<std::net::SocketAddr>,
    /// `ws` (or `ws.N`): BEP 19 web seed URLs.
    pub web_seeds: Vec<String>,
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
    // An `xt` in some namespace other than BitTorrent v1's, seen while
    // looking for one (a hybrid link carries `urn:btmh:` beside `urn:btih:`).
    let mut other_xt: Option<String> = None;
    let mut display_name = None;
    let mut trackers: Vec<String> = Vec::new();
    let mut peers: Vec<std::net::SocketAddr> = Vec::new();
    let mut web_seeds: Vec<String> = Vec::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(raw_value)?;

        // Some links number repeated parameters: `tr.1=`, `x.pe.2=`.
        let base_key = key.rsplit_once('.').filter(|(_, n)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())).map_or(key, |(k, _)| k);

        match base_key {
            "xt" => {
                let lower = value.to_ascii_lowercase();
                match lower.strip_prefix("urn:btih:") {
                    // The first BitTorrent v1 hash is the one used.
                    Some(hash_str) if info_hash.is_none() => info_hash = Some(decode_info_hash(hash_str)?),
                    Some(_) => {}
                    None => other_xt = Some(value),
                }
            }
            "dn" => display_name = Some(value),
            "tr" => {
                if !trackers.contains(&value) {
                    trackers.push(value);
                }
            }
            "x.pe" => {
                if let Ok(addr) = value.parse::<std::net::SocketAddr>() {
                    if !peers.contains(&addr) {
                        peers.push(addr);
                    }
                }
            }
            "ws" if (value.starts_with("http://") || value.starts_with("https://")) && !web_seeds.contains(&value) => web_seeds.push(value),
            _ => {} // ignore unrecognized params (kt, as, xs, ...)
        }
    }

    let info_hash = match (info_hash, other_xt) {
        (Some(hash), _) => hash,
        // Only a hash this client cannot use (BitTorrent v2 alone).
        (None, Some(other)) => return Err(MagnetError::BadInfoHashEncoding(other)),
        (None, None) => return Err(MagnetError::MissingInfoHash),
    };
    Ok(MagnetLink { info_hash, display_name, trackers, peers, web_seeds })
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

    // ---- links as they turn up in the wild ----

    const HASH: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn a_hybrid_link_with_a_v2_hash_beside_the_v1_one_is_accepted() {
        let v2 = "1220aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        for uri in [format!("magnet:?xt=urn:btih:{}&xt=urn:btmh:{}&dn=x", HASH, v2), format!("magnet:?xt=urn:btmh:{}&xt=urn:btih:{}", v2, HASH)] {
            let link = parse_magnet_uri(&uri).expect(&uri);
            assert_eq!(link.info_hash[0], 0x01, "the v1 hash, whichever order they come in");
            assert_eq!(link.info_hash[19], 0x67);
        }
    }

    #[test]
    fn a_link_with_only_a_v2_hash_says_it_cannot_be_used_rather_than_that_it_has_no_hash() {
        let err = parse_magnet_uri("magnet:?xt=urn:btmh:1220aabb").unwrap_err();
        assert!(matches!(err, MagnetError::BadInfoHashEncoding(ref v) if v.contains("btmh")), "{:?}", err);
        assert_eq!(parse_magnet_uri("magnet:?dn=only-a-name").unwrap_err(), MagnetError::MissingInfoHash);
    }

    #[test]
    fn the_first_v1_hash_wins_and_the_scheme_is_case_insensitive() {
        let other = "f".repeat(40);
        let link = parse_magnet_uri(&format!("magnet:?xt=URN:BTIH:{}&xt=urn:btih:{}", HASH.to_uppercase(), other)).unwrap();
        assert_eq!(link.info_hash[0], 0x01);
    }

    #[test]
    fn trackers_are_kept_once_each_in_order_and_numbered_ones_count() {
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}&tr=udp%3A%2F%2Fa%3A1&tr.1=http%3A%2F%2Fb%2Fannounce&tr=udp%3A%2F%2Fa%3A1&tr.2=udp%3A%2F%2Fc%3A2", HASH)).unwrap();
        assert_eq!(link.trackers, vec!["udp://a:1", "http://b/announce", "udp://c:2"]);
    }

    #[test]
    fn peer_hints_are_read_as_socket_addresses_and_anything_else_is_skipped() {
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}&x.pe=10.0.0.1%3A6881&x.pe.1=%5B2001%3Adb8%3A%3A1%5D%3A51413&x.pe=10.0.0.1%3A6881&x.pe=some.host%3A6881&x.pe=not-an-address&x.pe=10.0.0.2", HASH)).unwrap();
        assert_eq!(link.peers, vec!["10.0.0.1:6881".parse().unwrap(), "[2001:db8::1]:51413".parse().unwrap()], "once each; a hostname, a non-address and a missing port are left out");
    }

    #[test]
    fn web_seeds_are_kept_when_they_are_http_urls() {
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}&ws=http%3A%2F%2Fm%2Ff.bin&ws.1=https%3A%2F%2Fn%2Ff.bin&ws=ftp%3A%2F%2Fx%2Ff&ws=http%3A%2F%2Fm%2Ff.bin", HASH)).unwrap();
        assert_eq!(link.web_seeds, vec!["http://m/f.bin", "https://n/f.bin"]);
    }

    #[test]
    fn a_link_with_none_of_the_extras_has_none() {
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}", HASH)).unwrap();
        assert!(link.trackers.is_empty() && link.peers.is_empty() && link.web_seeds.is_empty());
    }

    #[test]
    fn a_dotted_key_that_is_not_a_number_is_not_mistaken_for_a_repeat() {
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}&tr.extra=http%3A%2F%2Fx&x.pe.a=10.0.0.1%3A1&trx=http%3A%2F%2Fy", HASH)).unwrap();
        assert!(link.trackers.is_empty(), "tr.extra and trx are other parameters");
        assert!(link.peers.is_empty(), "x.pe.a is not a numbered x.pe");
    }
}
