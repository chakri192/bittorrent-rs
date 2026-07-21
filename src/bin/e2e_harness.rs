//! Not part of the client itself -- a self-contained sanity check that
//! proves the compiled `download` binary works end-to-end without needing
//! a real tracker or real peers on the internet. Everything here runs on
//! `127.0.0.1`: a fake HTTP tracker (hand-rolled, not `bittorrent_rs`'s
//! tracker code -- this plays the *other side* of that conversation) and
//! a fake peer (plays the other side of the wire protocol), both serving
//! data from an in-memory buffer. The real `download` binary is then
//! spawned as a subprocess exactly as a user would run it, and its output
//! file is diffed byte-for-byte against the original.
//!
//! Run with: `cargo run --bin e2e_harness`

use bittorrent_rs::peer::handshake::Handshake;
use bittorrent_rs::peer::message::Message;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::process::Command;
use std::thread;

fn main() {
    let data = b"hello bittorrent world, this is the e2e harness payload.\n".repeat(30); // a few pieces' worth
    let piece_len: usize = 256;

    let mut pieces_hashes: Vec<[u8; 20]> = Vec::new();
    let mut pieces_concat = Vec::new();
    for chunk in data.chunks(piece_len) {
        let mut h = Sha1::new();
        h.update(chunk);
        let hash: [u8; 20] = h.finalize().into();
        pieces_concat.extend_from_slice(&hash);
        pieces_hashes.push(hash);
    }

    let info_bytes = {
        let mut v = Vec::new();
        v.extend_from_slice(b"d");
        v.extend_from_slice(format!("6:lengthi{}e", data.len()).as_bytes());
        v.extend_from_slice(b"4:name7:e2e.bin");
        v.extend_from_slice(format!("12:piece lengthi{}e", piece_len).as_bytes());
        v.extend_from_slice(format!("6:pieces{}:", pieces_concat.len()).as_bytes());
        v.extend_from_slice(&pieces_concat);
        v.extend_from_slice(b"e");
        v
    };
    let info_hash: [u8; 20] = {
        let mut h = Sha1::new();
        h.update(&info_bytes);
        h.finalize().into()
    };

    let tracker_listener = TcpListener::bind("127.0.0.1:0").expect("bind fake tracker");
    let tracker_addr = tracker_listener.local_addr().unwrap();
    let peer_listener = TcpListener::bind("127.0.0.1:0").expect("bind fake peer");
    let peer_addr = peer_listener.local_addr().unwrap();

    let announce_url = format!("http://{}/announce", tracker_addr);
    let torrent_bytes = {
        let mut v = Vec::new();
        v.extend_from_slice(b"d");
        v.extend_from_slice(format!("8:announce{}:{}", announce_url.len(), announce_url).as_bytes());
        v.extend_from_slice(b"4:info");
        v.extend_from_slice(&info_bytes);
        v.extend_from_slice(b"e");
        v
    };
    let torrent_path = std::env::temp_dir().join("e2e_harness.torrent");
    fs::write(&torrent_path, &torrent_bytes).expect("write torrent file");

    // Fake tracker: answers exactly one HTTP GET with a compact peer list
    // pointing at the fake peer below.
    thread::spawn(move || {
        let Ok((mut stream, _)) = tracker_listener.accept() else { return };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf); // drain the request; we don't need its contents

        let peer_port = peer_addr.port();
        let ip_octets = match peer_addr.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!("loopback bind is always v4 here"),
        };
        let mut peers_bin = Vec::new();
        peers_bin.extend_from_slice(&ip_octets);
        peers_bin.extend_from_slice(&peer_port.to_be_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(b"d8:intervali1800e5:peers");
        body.extend_from_slice(format!("{}:", peers_bin.len()).as_bytes());
        body.extend_from_slice(&peers_bin);
        body.push(b'e');

        let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = stream.write_all(headers.as_bytes());
        let _ = stream.write_all(&body);
    });

    // Fake peer: real handshake, announces every piece via bitfield,
    // unchokes immediately, serves whatever blocks are requested.
    let peer_data = data.clone();
    thread::spawn(move || {
        let Ok((mut stream, _)) = peer_listener.accept() else { return };

        let mut hs_buf = [0u8; 68];
        if stream.read_exact(&mut hs_buf).is_err() {
            return;
        }
        let Ok(their_hs) = Handshake::from_bytes(&hs_buf) else { return };
        if their_hs.info_hash != info_hash {
            return;
        }
        let our_hs = Handshake::new(info_hash, [0x99; 20], false);
        if stream.write_all(&our_hs.to_bytes()).is_err() {
            return;
        }

        let num_pieces = pieces_hashes.len();
        let mut bits = vec![0u8; num_pieces.div_ceil(8)];
        for i in 0..num_pieces {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
        if Message::Bitfield(bits).write_to(&mut stream).is_err() {
            return;
        }
        if Message::Unchoke.write_to(&mut stream).is_err() {
            return;
        }

        loop {
            match Message::read_from(&mut stream) {
                Ok(Message::Request { index, begin, length }) => {
                    let piece_start = index as usize * piece_len;
                    let piece_end = (piece_start + piece_len).min(peer_data.len());
                    let piece = &peer_data[piece_start..piece_end];
                    let block = piece[begin as usize..(begin + length) as usize].to_vec();
                    if (Message::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                        return;
                    }
                }
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    });

    let out_dir = std::env::temp_dir().join("e2e_harness_out");
    let _ = fs::remove_dir_all(&out_dir);

    let download_bin = std::env::current_exe().expect("current exe").parent().expect("exe dir").join("download");

    let status = Command::new(&download_bin)
        .arg(&torrent_path)
        .arg("--out")
        .arg(&out_dir)
        .arg("--peers")
        .arg("1")
        // No DHT in the harness: everything must stay on 127.0.0.1 (CI
        // has no business resolving bootstrap routers), and the run
        // should exercise exactly the fake tracker + fake peer.
        .arg("--no-dht")
        // Plain output + no logfile: keep the harness deterministic and
        // free of the interactive dashboard / stray log artifacts.
        .arg("--no-tui")
        .arg("--no-log")
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {:?}: {}", download_bin, e));

    if !status.success() {
        eprintln!("FAIL: download binary exited with {:?}", status.code());
        std::process::exit(1);
    }

    let downloaded_path = out_dir.join("e2e.bin");
    let downloaded = fs::read(&downloaded_path).unwrap_or_else(|e| panic!("reading {:?}: {}", downloaded_path, e));

    if downloaded == data {
        println!("PASS: {} bytes downloaded via fake tracker+peer match the source exactly", data.len());
    } else {
        eprintln!("FAIL: downloaded {} bytes, expected {}, content differs", downloaded.len(), data.len());
        std::process::exit(1);
    }
}
