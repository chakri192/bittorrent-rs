//! Fuzzes BEP 11 peer exchange payloads and compact peer lists.
//! It runs on untrusted input from arbitrary remote parties, so it must
//! never panic, overflow the stack or allocate without bound; a
//! `Result::Err` is the only acceptable failure mode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bittorrent_rs::peer::pex::parse_ut_pex(data);
    let _ = bittorrent_rs::tracker::parse_compact_peers(data);
    let _ = bittorrent_rs::tracker::parse_compact_peers_v6(data);
});
