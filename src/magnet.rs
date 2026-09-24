//! Magnet URI parsing (BEP 9). The fields needed to bootstrap a metadata
//! exchange: `xt` (the v1 InfoHash, hex or base32, or a BitTorrent v2 one as
//! `urn:btmh:` and a SHA-256 multihash; a link with both is a hybrid, and its
//! v1 hash is the one used), `dn` (display name), `tr`
//! (tracker URLs), `x.pe` (peers to try directly) and `ws` (BEP 19 web
//! seeds), each repeatable and each also accepted numbered (`tr.1`).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetLink {
    /// The hash peers and trackers are asked for: the v1 one, or for a link with only a v2 one that hash's first
    /// 20 bytes (BEP 52).
    pub info_hash: [u8; 20],
    /// The whole SHA-256 info hash, from a `urn:btmh:` in the link. The metadata found is checked against it.
    pub info_hash_v2: Option<[u8; 32]>,
    pub display_name: Option<String>,
    /// `tr` (or `tr.N`), each once, in the order given.
    pub trackers: Vec<String>,
    /// `x.pe` (or `x.pe.N`): addresses of peers to try directly (BEP 9),
    /// so a link with no tracker and no DHT still has somewhere to start.
    /// Only `ip:port` and `[ipv6]:port` forms; a hostname is not resolved.
    pub peers: Vec<std::net::SocketAddr>,
    /// `ws` (or `ws.N`): BEP 19 web seed URLs.
    pub web_seeds: Vec<String>,
    /// `so` (BEP 53): the files to fetch, as their 0-based indices in the torrent's file list, sorted and
    /// without repeats. Empty when the link does not say, which means all of them.
    pub select_only: Vec<usize>,
}

/// The most files an `so` parameter may name. A range such as `0-4294967295` would otherwise be an
/// instruction to allocate the address space; a link that names more than this has its `so` ignored, as
/// one that does not parse does.
const MAX_SELECTED_FILES: usize = 1 << 16;

/// The indices of BEP 53's `so` value: numbers and `first-last` ranges, comma-separated (`0,2,4-6`). `None` if
/// any part is not one of those, or the whole names too many files: a selection half understood would fetch
/// something other than what was asked for, and one that is not understood at all falls back to everything.
fn parse_select_only(value: &str) -> Option<Vec<usize>> {
    let mut indices = Vec::new();
    for part in value.split(',') {
        let (first, last) = match part.split_once('-') {
            Some((first, last)) => (first.parse::<usize>().ok()?, last.parse::<usize>().ok()?),
            None => {
                let index = part.parse::<usize>().ok()?;
                (index, index)
            }
        };
        // Before anything is allocated for it: a range may be as long as a usize is.
        if first > last || last - first >= MAX_SELECTED_FILES - indices.len() {
            return None;
        }
        indices.extend(first..=last);
    }
    indices.sort_unstable();
    indices.dedup();
    Some(indices)
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
    let mut info_hash_v2: Option<[u8; 32]> = None;
    let mut display_name = None;
    let mut trackers: Vec<String> = Vec::new();
    let mut peers: Vec<std::net::SocketAddr> = Vec::new();
    let mut web_seeds: Vec<String> = Vec::new();
    let mut select_only: Vec<usize> = Vec::new();

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
                    None => match lower.strip_prefix("urn:btmh:").and_then(decode_multihash_sha256) {
                        Some(hash) if info_hash_v2.is_none() => info_hash_v2 = Some(hash),
                        Some(_) => {}
                        None => other_xt = Some(value),
                    },
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
            // The first `so` that parses is the one used.
            "so" if select_only.is_empty() => select_only = parse_select_only(&value).unwrap_or_default(),
            _ => {} // ignore unrecognized params (kt, as, xs, ...)
        }
    }

    let info_hash = match (info_hash, info_hash_v2, other_xt) {
        (Some(hash), _, _) => hash,
        // BitTorrent v2 alone: peers know the torrent by the first 20 bytes of its SHA-256 hash.
        (None, Some(v2), _) => {
            let mut short = [0u8; 20];
            short.copy_from_slice(&v2[..20]);
            short
        }
        // Only a hash this client cannot use (BitTorrent v2 alone).
        (None, None, Some(other)) => return Err(MagnetError::BadInfoHashEncoding(other)),
        (None, None, None) => return Err(MagnetError::MissingInfoHash),
    };
    Ok(MagnetLink { info_hash, info_hash_v2, display_name, trackers, peers, web_seeds, select_only })
}

/// A SHA-256 multihash in hex: `1220` (SHA2-256, 32 bytes) and the 32 bytes of the hash.
fn decode_multihash_sha256(text: &str) -> Option<[u8; 32]> {
    let digits = text.strip_prefix("1220")?;
    if digits.len() != 64 || !digits.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
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

/// BEP 46: `xs=urn:btpk:<64 hex chars>` names a mutable DHT pointer to a torrent's current
/// version -- an ed25519 public key, with an optional hex `s`alt -- rather than a fixed info
/// hash. `magnet:?xs=urn:btpk:[Public Key (Hex)]&s=[Salt (Hex)]` is the link form the BEP gives.
/// A separate parse from [`parse_magnet_uri`], and not folded into [`MagnetLink`], because
/// resolving one needs a DHT round trip (`dht::Dht::get_item` on `dht::store::mutable_target`)
/// before there is an info hash to build an ordinary `MagnetLink` from at all -- the two have
/// different shapes for a reason, not by oversight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutablePointer {
    pub public_key: [u8; 32],
    /// `s`, hex-decoded. `None` when the link gives no salt at all; empty and absent are the
    /// same target either way (see `dht::store::mutable_target`).
    pub salt: Option<Vec<u8>>,
}

/// Parses a `magnet:?xs=urn:btpk:...` link. `None` for anything else: not a magnet URI at all,
/// no `xs` in the `urn:btpk:` namespace, a public key of the wrong length, or an `s` that is not
/// valid hex -- a malformed pointer is nothing to resolve, not a torrent to fall back to.
pub fn parse_mutable_pointer(uri: &str) -> Option<MutablePointer> {
    let query = uri.strip_prefix("magnet:?")?;
    let mut public_key: Option<[u8; 32]> = None;
    let mut salt: Option<Vec<u8>> = None;

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(raw_value).ok()?;
        match key {
            "xs" if public_key.is_none() => {
                let hex = value.to_ascii_lowercase();
                let digits = hex.strip_prefix("urn:btpk:")?;
                if digits.len() != 64 {
                    return None;
                }
                public_key = Some(decode_hex_32(digits)?);
            }
            "s" if salt.is_none() => salt = Some(decode_hex_bytes(&value)?),
            _ => {}
        }
    }
    Some(MutablePointer { public_key: public_key?, salt })
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex_bytes(s)?;
    bytes.try_into().ok()
}

// `is_multiple_of` needs a very recent stdlib; keep buildable on older toolchains (same stance
// as krpc.rs's parse_compact_nodes).
#[allow(clippy::manual_is_multiple_of)]
fn decode_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i] as char).ok()?;
        let lo = hex_nibble(bytes[i + 1] as char).ok()?;
        out.push((hi << 4) | lo);
    }
    Some(out)
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

    const LINK_HASH: &str = "xt=urn:btih:AABBCCDDEEFF00112233445566778899AABBCCDD";

    fn select_only(so: &str) -> Vec<usize> {
        parse_magnet_uri(&format!("magnet:?{}&so={}", LINK_HASH, so)).unwrap().select_only
    }

    #[test]
    fn so_names_files_by_number_and_range_from_zero() {
        assert_eq!(select_only("0"), vec![0]);
        assert_eq!(select_only("0,2,4-6"), vec![0, 2, 4, 5, 6], "BEP 53's own example");
        assert_eq!(select_only("6,2,2-3,0"), vec![0, 2, 3, 6], "sorted, and each once");
        assert_eq!(select_only("5-5"), vec![5]);
        assert_eq!(select_only("%30%2C2"), vec![0, 2], "percent-encoded, as some clients write the commas");
        assert!(parse_magnet_uri(&format!("magnet:?{}", LINK_HASH)).unwrap().select_only.is_empty(), "no `so`: no selection, which is everything");
    }

    #[test]
    fn an_so_that_is_not_understood_selects_nothing_rather_than_something_else() {
        for bad in ["", "a", "1,", ",1", "1,,2", "3-1", "-1", "1-", "1-2-3", "0x1", "-", "1;2", "99999999999999999999999"] {
            assert!(select_only(bad).is_empty(), "so={:?}", bad);
        }
        assert!(select_only("0-4294967295").is_empty(), "a range is not a licence to allocate");
        assert!(select_only("0-65535,65536").is_empty(), "nor is a list");
        assert_eq!(select_only("0-65535").len(), 65536, "the most it takes");
        // The first `so` that is understood is the one used.
        let two = parse_magnet_uri(&format!("magnet:?{}&so=x&so=1&so=2", LINK_HASH)).unwrap();
        assert_eq!(two.select_only, vec![1]);
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
            assert_eq!(link.info_hash_v2.map(|h| (h[0], h[31])), Some((0xaa, 0x99)), "and the whole v2 one is kept, to check the metadata against");
        }
    }

    #[test]
    fn a_link_with_only_a_v2_hash_is_known_to_peers_by_its_first_twenty_bytes() {
        let v2 = "1220aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let link = parse_magnet_uri(&format!("magnet:?xt=urn:btmh:{}&dn=v2", v2)).unwrap();
        assert_eq!(link.info_hash, <[u8; 20]>::try_from(&hex_bytes(&v2[4..44])[..]).unwrap());
        assert_eq!(link.info_hash_v2.unwrap()[..], hex_bytes(&v2[4..])[..]);
        assert!(parse_magnet_uri(&format!("magnet:?xt=urn:btmh:{}", v2.to_ascii_uppercase())).is_ok(), "in either case");
        assert_eq!(parse_magnet_uri(&format!("magnet:?xt=urn:btih:{}", HASH)).unwrap().info_hash_v2, None, "a v1 link has none");
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len() / 2).map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn a_link_with_a_multihash_that_is_not_a_sha256_of_thirty_two_bytes_says_it_cannot_be_used() {
        for bad in ["1220aabb", "1120aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899", "1220zzbbccddeeff00112233445566778899aabbccddeeff00112233445566778899", "1220aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899ff"] {
            let err = parse_magnet_uri(&format!("magnet:?xt=urn:btmh:{}", bad)).unwrap_err();
            assert!(matches!(err, MagnetError::BadInfoHashEncoding(ref v) if v.contains("btmh")), "{}: {:?}", bad, err);
        }
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

    // ---- BEP 46: mutable-pointer magnet links ----

    // BEP 46's own published test vectors (bittorrent.org/beps/bep_0046.html).
    const BEP46_PUBKEY: &str = "8543d3e6115f0f98c944077a4493dcd543e49c739fd998550a1f614ab36ed63e";

    #[test]
    fn a_mutable_pointer_link_without_salt_parses() {
        let uri = format!("magnet:?xs=urn:btpk:{}", BEP46_PUBKEY);
        let pointer = parse_mutable_pointer(&uri).unwrap();
        assert_eq!(pointer.public_key, decode_hex_32(BEP46_PUBKEY).unwrap());
        assert!(pointer.salt.is_none());
    }

    #[test]
    fn a_mutable_pointer_link_with_a_hex_salt_parses() {
        let uri = format!("magnet:?xs=urn:btpk:{}&s=6e", BEP46_PUBKEY);
        let pointer = parse_mutable_pointer(&uri).unwrap();
        assert_eq!(pointer.salt, Some(vec![0x6e]));
    }

    #[test]
    fn the_bep46_pubkey_and_salt_hash_to_the_beps_own_published_target_ids() {
        // These are the same target-ID vectors BEP 44's mutable_target is tested against
        // (BEP 46 reuses it wholesale); pinned here too since it is this parser's own field
        // that must feed the right bytes into it.
        let pk = decode_hex_32(BEP46_PUBKEY).unwrap();
        let without_salt = parse_mutable_pointer(&format!("magnet:?xs=urn:btpk:{}", BEP46_PUBKEY)).unwrap();
        assert_eq!(hex_20(crate::dht::store::mutable_target(&pk, without_salt.salt.as_deref())), "cc3f9d90b572172053626f9980ce261a850d050b");

        let with_salt = parse_mutable_pointer(&format!("magnet:?xs=urn:btpk:{}&s=6e", BEP46_PUBKEY)).unwrap();
        assert_eq!(hex_20(crate::dht::store::mutable_target(&pk, with_salt.salt.as_deref())), "59ee7c2cb9b4f7eb1986ee2d18fd2fdb8a56554f");
    }

    fn hex_20(bytes: [u8; 20]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn xs_in_a_different_namespace_is_not_a_mutable_pointer() {
        assert!(parse_mutable_pointer(&format!("magnet:?xt=urn:btih:{}&xs=http%3A%2F%2Fmirror%2Fx.torrent", HASH)).is_none());
    }

    #[test]
    fn a_public_key_of_the_wrong_length_is_refused() {
        assert!(parse_mutable_pointer("magnet:?xs=urn:btpk:aabb").is_none());
    }

    #[test]
    fn not_a_magnet_uri_at_all_is_refused() {
        assert!(parse_mutable_pointer("https://example.com/").is_none());
    }

    #[test]
    fn the_first_xs_and_first_s_win_when_repeated() {
        let other_key = "0".repeat(64);
        let uri = format!("magnet:?xs=urn:btpk:{}&xs=urn:btpk:{}&s=01&s=02", BEP46_PUBKEY, other_key);
        let pointer = parse_mutable_pointer(&uri).unwrap();
        assert_eq!(pointer.public_key, decode_hex_32(BEP46_PUBKEY).unwrap());
        assert_eq!(pointer.salt, Some(vec![0x01]));
    }
}
