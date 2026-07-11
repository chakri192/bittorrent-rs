//! Fuzzes `bittorrent_rs::bencode::decode` against arbitrary bytes. This
//! parser runs on untrusted input from every angle -- .torrent files,
//! tracker responses, and BEP 9 metadata pieces from arbitrary peers --
//! so it must never panic no matter what garbage it's handed; a
//! `Result::Err` is the only acceptable failure mode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bittorrent_rs::bencode::decode(data);
});
