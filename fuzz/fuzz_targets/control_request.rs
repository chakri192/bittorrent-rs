//! Fuzzes the daemon's control-socket request parser. Whatever a client
//! sends down the socket is read by it, as text of any shape.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(request) = bittorrent_rs::daemon::control::parse_request(text) {
            // What it accepts, it can say again.
            assert_eq!(bittorrent_rs::daemon::control::parse_request(&request.to_line()), Ok(request));
        }
    }
});
