//! Fuzzes peer wire messages: the framed messages any connected peer can send.
//! It runs on untrusted input from arbitrary remote parties, so it must
//! never panic, overflow the stack or allocate without bound; a
//! `Result::Err` is the only acceptable failure mode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = data;
    let _ = bittorrent_rs::peer::message::Message::read_from(&mut reader);
});
