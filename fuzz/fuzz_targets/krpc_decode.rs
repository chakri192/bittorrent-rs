//! Fuzzes Mainline DHT (KRPC) messages: every UDP datagram from any node, plus compact node lists.
//! It runs on untrusted input from arbitrary remote parties, so it must
//! never panic, overflow the stack or allocate without bound; a
//! `Result::Err` is the only acceptable failure mode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bittorrent_rs::dht::krpc::KrpcMessage::decode(data);
    let _ = bittorrent_rs::dht::krpc::parse_compact_nodes(data);
});
