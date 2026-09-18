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
//! Each [`Scenario`] is one such run with a different torrent or flag
//! set, and adds its own assertions on top of the byte-for-byte check
//! (what the client advertised to the peer, what it logged).
//!
//! Run with: `cargo run --bin e2e_harness`

use bittorrent_rs::peer::handshake::Handshake;
use bittorrent_rs::peer::message::Message;
use bittorrent_rs::peer::ExtendedHandshake;
use sha1::{Digest, Sha1};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

struct Scenario {
    name: &'static str,
    /// Sets BEP 27 `private=1` in the info dict. The client must then
    /// leave the DHT off and withhold `ut_pex`, even though this scenario
    /// deliberately does *not* pass `--no-dht`.
    private: bool,
}

const SCENARIOS: &[Scenario] = &[Scenario { name: "public", private: false }, Scenario { name: "private", private: true }];

fn main() {
    let mut failed = false;
    for scenario in SCENARIOS {
        match run_scenario(scenario) {
            Ok(summary) => println!("PASS [{}]: {}", scenario.name, summary),
            Err(reason) => {
                eprintln!("FAIL [{}]: {}", scenario.name, reason);
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}

fn run_scenario(scenario: &Scenario) -> Result<String, String> {
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
        // Keys must stay sorted: "private" comes after "pieces".
        if scenario.private {
            v.extend_from_slice(b"7:privatei1e");
        }
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
    let tmp = std::env::temp_dir();
    let torrent_path = tmp.join(format!("e2e_harness_{}.torrent", scenario.name));
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

    // Fake peer: real handshake (with the BEP 10 bit set so the client
    // sends its extended handshake), announces every piece via bitfield,
    // unchokes immediately, serves whatever blocks are requested. Records
    // whether the client's extended handshake offered `ut_pex`.
    let pex_offered: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let pex_offered_peer = Arc::clone(&pex_offered);
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
        let our_hs = Handshake::new(info_hash, [0x99; 20], true);
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
                Ok(Message::Extended { id: 0, payload }) => {
                    if let Ok(hs) = ExtendedHandshake::parse(&payload) {
                        *pex_offered_peer.lock().unwrap() = Some(hs.peer_ut_pex_id().is_some());
                    }
                }
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    });

    let out_dir = tmp.join(format!("e2e_harness_{}_out", scenario.name));
    let log_path = tmp.join(format!("e2e_harness_{}.log", scenario.name));
    let _ = fs::remove_dir_all(&out_dir);
    let _ = fs::remove_file(&log_path);

    let download_bin = std::env::current_exe().expect("current exe").parent().expect("exe dir").join("download");

    let mut cmd = Command::new(&download_bin);
    cmd.arg(&torrent_path).arg("--out").arg(&out_dir).arg("--peers").arg("1");
    // Don't let a developer's ~/.config/bittorrent-rs.toml change what
    // this run does.
    cmd.arg("--no-config");
    if scenario.private {
        // DHT stays *on*: the point is that the client turns it off
        // itself. Were that to regress, the client would try to reach the
        // public bootstrap routers, so the log assertion below is what
        // catches it.
        cmd.arg("--dht");
    } else {
        // No DHT: everything must stay on 127.0.0.1 (CI has no business
        // resolving bootstrap routers), and the run should exercise
        // exactly the fake tracker + fake peer.
        cmd.arg("--no-dht");
    }
    // Plain output, but a logfile: the assertions below read what the
    // client says about its own decisions (DHT started or not).
    cmd.arg("--no-tui").arg("--log").arg(&log_path);

    let status = cmd.status().map_err(|e| format!("failed to spawn {:?}: {}", download_bin, e))?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }

    let downloaded_path = out_dir.join("e2e.bin");
    let downloaded = fs::read(&downloaded_path).map_err(|e| format!("reading {:?}: {}", downloaded_path, e))?;
    if downloaded != data {
        return Err(format!("downloaded {} bytes, expected {}, content differs", downloaded.len(), data.len()));
    }

    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    let dht_started = log.contains("DHT node running");
    let said_private = log.contains("private torrent");
    if dht_started {
        // Only reachable in the private scenario: the public one passes
        // --no-dht.
        return Err("client started a DHT node for a private torrent".to_string());
    }
    if said_private != scenario.private {
        return Err(format!("client log {} a private-torrent notice (private = {})", if said_private { "has" } else { "lacks" }, scenario.private));
    }

    let offered = *pex_offered.lock().unwrap();
    if offered != Some(!scenario.private) {
        return Err(format!("client's extended handshake offered ut_pex = {:?}, expected {}", offered, !scenario.private));
    }

    Ok(format!("{} bytes downloaded via fake tracker+peer match the source exactly", data.len()))
}
