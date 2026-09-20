//! Fuzzes the reader of the daemon's state file: a file another program (or
//! a crash, or a person with an editor) may have left in any state.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let (entries, _warnings) = bittorrent_rs::daemon::state::parse_entries(text);
        for entry in entries {
            assert_eq!(bittorrent_rs::daemon::state::Entry::from_line(&entry.to_line()), Ok(entry));
        }
    }
});
