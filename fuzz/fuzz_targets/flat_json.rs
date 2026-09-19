//! Fuzzes the strict reader for flat JSON objects, which reads every line
//! a daemon client sends and every answer the daemon gives.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = bittorrent_rs::json::parse_object(text);
    }
});
