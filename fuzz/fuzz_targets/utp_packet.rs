//! Fuzzes the uTP (BEP 29) packet parser and a connection fed whatever it
//! decodes: datagrams come from any host that can reach the UDP port. Nothing
//! may panic; a `Result::Err` is the only acceptable failure mode.
#![no_main]

use bittorrent_rs::utp::conn::Connection;
use bittorrent_rs::utp::packet::Packet;
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = Packet::decode(data) else { return };
    assert_eq!(Packet::decode(&packet.encode()).as_ref(), Ok(&packet));
    let start = Instant::now();
    let mut conn = Connection::connect(start, 1);
    conn.write(&[0u8; 4000]);
    for step in 1..5u64 {
        let now = start + Duration::from_millis(300 * step);
        conn.on_packet(now, &packet);
        conn.on_tick(now);
        let _ = conn.take_outgoing();
    }
});
