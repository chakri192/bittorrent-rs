//! Fuzzes BEP 14 local service discovery announcements, which arrive from
//! anyone on the local network (or anyone who can send to the port). It must
//! never panic or allocate without bound; a `Result::Err` is the only
//! acceptable failure mode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bittorrent_rs::lsd::parse(data);
});
