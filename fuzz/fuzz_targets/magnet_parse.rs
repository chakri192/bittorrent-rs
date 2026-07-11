//! Fuzzes `bittorrent_rs::magnet::parse_magnet_uri`. Magnet links come
//! straight from user input / clipboard / URLs clicked in a browser --
//! arbitrary untrusted text, including the base32/hex InfoHash decoder
//! and percent-decoding, both of which do manual byte-level parsing.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = bittorrent_rs::magnet::parse_magnet_uri(s);
    }
});
