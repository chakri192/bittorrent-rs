//! Asking a tracker how a torrent is doing without joining it (BEP 48 for HTTP, BEP 15 for UDP): how many
//! peers have all of it (seeders), how many do not (leechers), and how many times it has been finished.

use super::{percent_encode_bytes, TrackerError};
use crate::bencode::{self, Bencode};

/// What a tracker says of one torrent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrapeStats {
    /// Peers that have every piece (`complete`).
    pub complete: u32,
    /// How many times the torrent has been downloaded to the end (`downloaded`).
    pub downloaded: u32,
    /// Peers that do not have every piece (`incomplete`).
    pub incomplete: u32,
}

/// The URL to scrape for a tracker announced at `announce_url` (BEP 48): the last path segment of an announce URL that begins
/// with `announce` is changed to begin with `scrape` instead (`/announce.php` is `/scrape.php`), anything after it, a query
/// included, kept. A tracker whose announce URL does not look like that has no scrape.
pub fn scrape_url(announce_url: &str) -> Option<String> {
    let (path, query) = match announce_url.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (announce_url, None),
    };
    // Only what follows the authority is a path segment: `http://host` has none.
    let authority_end = path.find("://").map_or(0, |at| at + 3);
    let last_slash = path[authority_end..].rfind('/')? + authority_end;
    let segment = &path[last_slash + 1..];
    let rest = segment.strip_prefix("announce")?;
    let mut url = format!("{}/scrape{}", &path[..last_slash], rest);
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    Some(url)
}

/// The stats for `info_hash` in a scrape reply: `d5:filesd20:<hash>d8:completei_e10:downloadedi_e10:incompletei_eee e`.
fn parse_scrape_body(body: &[u8], info_hash: &[u8; 20]) -> Result<ScrapeStats, TrackerError> {
    let value = bencode::decode_lenient(body)?;
    let dict = value.as_dict().ok_or(TrackerError::MalformedResponse("scrape response is not a dict"))?;
    if let Some(reason) = dict.get(b"failure reason".as_slice()).and_then(Bencode::as_str) {
        return Err(TrackerError::TrackerFailure(reason.to_string()));
    }
    let files = value.get("files").and_then(Bencode::as_dict).ok_or(TrackerError::MalformedResponse("scrape response has no files"))?;
    let entry = files.get(info_hash.as_slice()).ok_or(TrackerError::MalformedResponse("the tracker does not know this torrent"))?;
    // A tracker that leaves a count out has none to say: 0.
    let count = |key: &str| entry.get(key).and_then(Bencode::as_int).map_or(0, |n| n.clamp(0, i64::from(u32::MAX)) as u32);
    Ok(ScrapeStats { complete: count("complete"), downloaded: count("downloaded"), incomplete: count("incomplete") })
}

/// Asks the tracker announced at `announce_url` (`http://`, `https://` or `udp://`) about `info_hash`.
pub fn scrape(announce_url: &str, info_hash: &[u8; 20]) -> Result<ScrapeStats, TrackerError> {
    if let Some(host_port) = announce_url.strip_prefix("udp://") {
        // As for announces: a path after the address means nothing to a UDP tracker.
        return super::udp::scrape(host_port.split('/').next().unwrap_or(host_port), info_hash);
    }
    if !announce_url.starts_with("http://") && !announce_url.starts_with("https://") {
        return Err(TrackerError::UnsupportedScheme(announce_url.split("://").next().unwrap_or(announce_url).to_string()));
    }
    let mut url = scrape_url(announce_url).ok_or_else(|| TrackerError::BadUrl(format!("{}: not an announce URL that has a scrape (BEP 48)", announce_url)))?;
    let query = format!("info_hash={}", percent_encode_bytes(info_hash));
    for _ in 0..=super::MAX_REDIRECTS {
        let body = if url.starts_with("https://") { super::https::get(&url, &query) } else { super::http::get(&url, &query) };
        match body {
            Err(TrackerError::Redirect(location)) => {
                let next = super::resolve_redirect(&url, &location)?;
                super::check_redirect_allowed(&url, &next)?;
                url = next;
            }
            other => return parse_scrape_body(&other?, info_hash),
        }
    }
    Err(TrackerError::TooManyRedirects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scrape_url_is_the_announce_url_with_its_last_segment_changed_as_bep_48_says() {
        for (announce, scrape) in [
            ("http://example.com/announce", "http://example.com/scrape"),
            ("http://example.com/x/announce", "http://example.com/x/scrape"),
            ("http://example.com/announce.php", "http://example.com/scrape.php"),
            ("http://example.com:6969/announce?passkey=abc", "http://example.com:6969/scrape?passkey=abc"),
            ("https://example.com/a/b/announce?k=one/two", "https://example.com/a/b/scrape?k=one/two"),
        ] {
            assert_eq!(scrape_url(announce).as_deref(), Some(scrape), "{}", announce);
        }
    }

    #[test]
    fn an_announce_url_not_shaped_like_that_has_no_scrape() {
        for announce in ["http://example.com/", "http://example.com", "http://example.com/tracker", "http://example.com/x/announce/y", "http://example.com/announce/", "http://example.com/scrape", "http://announce.example.com"] {
            assert_eq!(scrape_url(announce), None, "{}", announce);
        }
    }

    fn body(hash: &[u8; 20], entry: &str) -> Vec<u8> {
        let mut out = b"d5:filesd20:".to_vec();
        out.extend_from_slice(hash);
        out.extend_from_slice(entry.as_bytes());
        out.extend_from_slice(b"ee");
        out
    }

    #[test]
    fn the_counts_are_read_from_the_entry_of_the_hash_asked_about() {
        let hash = [0x11; 20];
        let stats = parse_scrape_body(&body(&hash, "d8:completei12e10:downloadedi345e10:incompletei6ee"), &hash).unwrap();
        assert_eq!(stats, ScrapeStats { complete: 12, downloaded: 345, incomplete: 6 });
        // Non-canonical key order is what trackers send.
        let stats = parse_scrape_body(&body(&hash, "d10:incompletei6e8:completei12ee"), &hash).unwrap();
        assert_eq!((stats.complete, stats.downloaded, stats.incomplete), (12, 0, 6), "a count left out is none");
    }

    #[test]
    fn a_tracker_that_does_not_know_the_torrent_or_fails_or_answers_nonsense_is_an_error_saying_so() {
        let hash = [0x11; 20];
        let other = [0x22; 20];
        assert!(matches!(parse_scrape_body(&body(&other, "d8:completei1ee"), &hash), Err(TrackerError::MalformedResponse(m)) if m.contains("does not know")));
        assert!(matches!(parse_scrape_body(b"d14:failure reason4:nopee", &hash), Err(TrackerError::TrackerFailure(r)) if r == "nope"));
        assert!(parse_scrape_body(b"de", &hash).is_err(), "no files");
        assert!(parse_scrape_body(b"not bencode", &hash).is_err());
        assert!(parse_scrape_body(&body(&hash, "i5e"), &hash).is_ok_and(|s| s == ScrapeStats { complete: 0, downloaded: 0, incomplete: 0 }), "an entry that is no dict has no counts, which is what it says");
    }

    #[test]
    fn counts_beyond_what_fits_are_clamped_not_wrapped() {
        let hash = [0x33; 20];
        let stats = parse_scrape_body(&body(&hash, "d8:completei99999999999e10:incompletei-4ee"), &hash).unwrap();
        assert_eq!((stats.complete, stats.incomplete), (u32::MAX, 0));
    }

    #[test]
    fn a_scheme_that_is_not_a_tracker_is_refused() {
        assert!(matches!(scrape("ftp://example.com/announce", &[0; 20]), Err(TrackerError::UnsupportedScheme(_))));
        assert!(matches!(scrape("http://127.0.0.1:1/tracker", &[0; 20]), Err(TrackerError::BadUrl(_))));
    }
}
