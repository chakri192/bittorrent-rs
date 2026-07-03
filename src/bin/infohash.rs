//! Usage: infohash <path-to.torrent>
//! Prints the InfoHash and basic metadata. Sanity-check tool for Phase 1.

use bittorrent_rs::torrent::{info_hash_hex, parse_torrent_file};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args();
    let _bin = args.next();
    let path = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: infohash <path-to.torrent>");
            return ExitCode::FAILURE;
        }
    };

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to read {}: {}", path, e);
            return ExitCode::FAILURE;
        }
    };

    match parse_torrent_file(&data) {
        Ok(t) => {
            println!("name:        {}", t.name);
            println!("info_hash:   {}", info_hash_hex(&t.info_hash));
            println!("announce:    {}", t.announce.as_deref().unwrap_or("-"));
            println!("piece_len:   {}", t.piece_length);
            println!("num_pieces:  {}", t.pieces.len());
            println!("files:");
            for (path, len) in &t.files {
                println!("  {} ({} bytes)", path.join("/"), len);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to parse torrent: {}", e);
            ExitCode::FAILURE
        }
    }
}
