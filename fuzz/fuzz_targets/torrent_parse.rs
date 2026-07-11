//! Fuzzes `bittorrent_rs::torrent::parse_torrent_file` end to end --
//! this is the actual entry point a user's downloaded .torrent file
//! hits, exercising bencode decoding, the hand-rolled `find_key_span`
//! byte-span scanner, and all the info-dict field extraction together
//! rather than bencode decoding in isolation.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bittorrent_rs::torrent::parse_torrent_file(data);
});
