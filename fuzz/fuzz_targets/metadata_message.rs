//! Fuzzes BEP 9 ut_metadata messages, sent by any peer during magnet resolution.
//! It runs on untrusted input from arbitrary remote parties, so it must
//! never panic, overflow the stack or allocate without bound; a
//! `Result::Err` is the only acceptable failure mode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bittorrent_rs::metadata::MetadataMessage::decode(data);
});
