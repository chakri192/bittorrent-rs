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
//! Each [`Scenario`] is one such story, with assertions on top of the
//! byte-for-byte check about what the client said to the peer, what it
//! asked the peer for, and what it logged.
//!
//! Run with: `cargo run --bin e2e_harness`

use bittorrent_rs::downloader::progress_file_path;
use bittorrent_rs::peer::handshake::Handshake;
use bittorrent_rs::peer::message::Message;
use bittorrent_rs::peer::ExtendedHandshake;
use sha1::{Digest, Sha1};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How long a client run may take before the harness gives up and kills
/// it. A hung client should fail the harness, not hang CI.
const RUN_LIMIT: Duration = Duration::from_secs(60);

enum Kind {
    /// Download the whole torrent from one well-behaved peer.
    Download {
        /// Sets BEP 27 `private=1` in the info dict. The client must then
        /// leave the DHT off and withhold `ut_pex`, even though the run
        /// deliberately does *not* pass `--no-dht`.
        private: bool,
    },
    /// Kill the client partway through, then start it again on the same
    /// output directory: it must resume rather than start over.
    ResumeAfterKill,
}

struct Scenario {
    name: &'static str,
    kind: Kind,
}

const SCENARIOS: &[Scenario] = &[
    Scenario { name: "public", kind: Kind::Download { private: false } },
    Scenario { name: "private", kind: Kind::Download { private: true } },
    Scenario { name: "resume-after-kill", kind: Kind::ResumeAfterKill },
];

fn main() {
    let mut failed = false;
    for scenario in SCENARIOS {
        let outcome = match scenario.kind {
            Kind::Download { private } => run_download(scenario.name, private),
            Kind::ResumeAfterKill => run_resume_after_kill(scenario.name),
        };
        match outcome {
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

// ---- the torrent -----------------------------------------------------

/// A small synthetic torrent: its content, and the info dict describing it.
struct Fixture {
    data: Vec<u8>,
    piece_len: usize,
    piece_count: usize,
    info_bytes: Vec<u8>,
    info_hash: [u8; 20],
}

impl Fixture {
    fn new(private: bool) -> Self {
        let data = b"hello bittorrent world, this is the e2e harness payload.\n".repeat(30); // a few pieces' worth
        let piece_len: usize = 256;

        let mut pieces_concat = Vec::new();
        for chunk in data.chunks(piece_len) {
            let mut h = Sha1::new();
            h.update(chunk);
            pieces_concat.extend_from_slice(&h.finalize());
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
            if private {
                v.extend_from_slice(b"7:privatei1e");
            }
            v.extend_from_slice(b"e");
            v
        };
        let info_hash: [u8; 20] = Sha1::digest(&info_bytes).into();

        Fixture { piece_count: pieces_concat.len() / 20, data, piece_len, info_bytes, info_hash }
    }

    /// The `.torrent` bytes announcing to `tracker_addr`. Only the
    /// announce URL differs between runs; the info hash never does.
    fn torrent_bytes(&self, tracker_addr: SocketAddr) -> Vec<u8> {
        let announce_url = format!("http://{}/announce", tracker_addr);
        let mut v = Vec::new();
        v.extend_from_slice(b"d");
        v.extend_from_slice(format!("8:announce{}:{}", announce_url.len(), announce_url).as_bytes());
        v.extend_from_slice(b"4:info");
        v.extend_from_slice(&self.info_bytes);
        v.extend_from_slice(b"e");
        v
    }
}

// ---- the fake swarm --------------------------------------------------

/// What the fake peer observed of the client.
#[derive(Default)]
struct PeerLog {
    /// Whether the client's extended handshake offered `ut_pex`.
    pex_offered: Option<bool>,
    /// Every piece index the client asked for, in order (repeats included).
    requested: Vec<u32>,
    /// Pieces the peer actually sent.
    served: BTreeSet<u32>,
}

struct Swarm {
    tracker_addr: SocketAddr,
    log: Arc<Mutex<PeerLog>>,
}

/// Starts a fake tracker (answers one announce, pointing at the fake peer)
/// and a fake peer on loopback.
///
/// The peer does a real handshake (with the BEP 10 bit set so the client
/// sends its extended handshake), announces every piece via bitfield,
/// unchokes immediately and serves the blocks it is asked for. With
/// `serve_limit = Some(n)` it stops answering requests for new pieces
/// once it has served `n` distinct ones -- it stays connected but goes
/// silent, which is a client mid-download as far as the client can tell.
fn spawn_swarm(fx: &Fixture, serve_limit: Option<usize>) -> Swarm {
    let tracker_listener = TcpListener::bind("127.0.0.1:0").expect("bind fake tracker");
    let tracker_addr = tracker_listener.local_addr().unwrap();
    let peer_listener = TcpListener::bind("127.0.0.1:0").expect("bind fake peer");
    let peer_addr = peer_listener.local_addr().unwrap();

    thread::spawn(move || {
        let Ok((mut stream, _)) = tracker_listener.accept() else { return };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf); // drain the request; we don't need its contents

        let ip_octets = match peer_addr.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!("loopback bind is always v4 here"),
        };
        let mut peers_bin = Vec::new();
        peers_bin.extend_from_slice(&ip_octets);
        peers_bin.extend_from_slice(&peer_addr.port().to_be_bytes());

        let mut body = Vec::new();
        body.extend_from_slice(b"d8:intervali1800e5:peers");
        body.extend_from_slice(format!("{}:", peers_bin.len()).as_bytes());
        body.extend_from_slice(&peers_bin);
        body.push(b'e');

        let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = stream.write_all(headers.as_bytes());
        let _ = stream.write_all(&body);
    });

    let log = Arc::new(Mutex::new(PeerLog::default()));
    let peer_log = Arc::clone(&log);
    let data = fx.data.clone();
    let (info_hash, piece_len, piece_count) = (fx.info_hash, fx.piece_len, fx.piece_count);
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

        let mut bits = vec![0u8; piece_count.div_ceil(8)];
        for i in 0..piece_count {
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
                    {
                        let mut log = peer_log.lock().unwrap();
                        log.requested.push(index);
                        if serve_limit.is_some_and(|limit| log.served.len() >= limit && !log.served.contains(&index)) {
                            continue; // stalled: read the request, never answer it
                        }
                        log.served.insert(index);
                    }
                    let piece_start = index as usize * piece_len;
                    let piece_end = (piece_start + piece_len).min(data.len());
                    let piece = &data[piece_start..piece_end];
                    let block = piece[begin as usize..(begin + length) as usize].to_vec();
                    if (Message::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                        return;
                    }
                }
                Ok(Message::Extended { id: 0, payload }) => {
                    if let Ok(hs) = ExtendedHandshake::parse(&payload) {
                        peer_log.lock().unwrap().pex_offered = Some(hs.peer_ut_pex_id().is_some());
                    }
                }
                Ok(_) => continue,
                Err(_) => return,
            }
        }
    });

    Swarm { tracker_addr, log }
}

// ---- running the client ----------------------------------------------

/// A fresh scratch directory for one scenario.
fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("e2e_harness_{}", name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// The client invoked as a user would, with the flags every scenario
/// shares. The caller adds the DHT choice.
fn client_command(torrent: &Path, out_dir: &Path, log: &Path) -> Command {
    let download_bin = std::env::current_exe().expect("current exe").parent().expect("exe dir").join("download");
    let mut cmd = Command::new(download_bin);
    cmd.arg(torrent).arg("--out").arg(out_dir).arg("--peers").arg("1");
    // Don't let a developer's ~/.config/bittorrent-rs.toml change what
    // this run does.
    cmd.arg("--no-config");
    // Nothing here should leave loopback. Port mapping talks to the LAN
    // gateway, and a client killed mid-run can't remove the mapping it
    // made, which would leave it on a real router.
    cmd.arg("--no-portmap");
    // Plain output, but a logfile: assertions read what the client says
    // about its own decisions (DHT started or not, pieces resumed).
    cmd.arg("--no-tui").arg("--log").arg(log);
    cmd
}

/// Waits for `child` to exit, killing it if it outlives `limit`.
fn wait_or_kill(child: &mut Child, limit: Duration) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| format!("waiting for the client: {}", e))? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("client had not exited after {:?}; killed it", limit));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Piece indices listed in the client's resume sidecar (one per line).
fn read_recorded(sidecar: &Path) -> BTreeSet<u32> {
    fs::read_to_string(sidecar).unwrap_or_default().lines().filter_map(|l| l.trim().parse().ok()).collect()
}

fn check_downloaded(fx: &Fixture, out_dir: &Path) -> Result<(), String> {
    let path = out_dir.join("e2e.bin");
    let downloaded = fs::read(&path).map_err(|e| format!("reading {:?}: {}", path, e))?;
    if downloaded != fx.data {
        return Err(format!("downloaded {} bytes, expected {}, content differs", downloaded.len(), fx.data.len()));
    }
    Ok(())
}

// ---- scenarios -------------------------------------------------------

fn run_download(name: &str, private: bool) -> Result<String, String> {
    let fx = Fixture::new(private);
    let swarm = spawn_swarm(&fx, None);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut cmd = client_command(&torrent, &out_dir, &log_path);
    if private {
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
    let mut child = cmd.spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    if log.contains("DHT node running") {
        // Only reachable in the private scenario: the public one passes
        // --no-dht.
        return Err("client started a DHT node for a private torrent".to_string());
    }
    let said_private = log.contains("private torrent");
    if said_private != private {
        return Err(format!("client log {} a private-torrent notice (private = {})", if said_private { "has" } else { "lacks" }, private));
    }

    let offered = swarm.log.lock().unwrap().pex_offered;
    if offered != Some(!private) {
        return Err(format!("client's extended handshake offered ut_pex = {:?}, expected {}", offered, !private));
    }

    Ok(format!("{} bytes downloaded via fake tracker+peer match the source exactly", fx.data.len()))
}

/// Kill the client mid-download, run it again on the same output
/// directory, and check it fetches only what it was missing.
fn run_resume_after_kill(name: &str) -> Result<String, String> {
    const STALL_AFTER: usize = 3;
    let fx = Fixture::new(false);
    let dir = scratch_dir(name);
    let out_dir = dir.join("out");
    let sidecar = progress_file_path(&out_dir, &fx.info_hash);

    // Run 1: the peer serves STALL_AFTER pieces and then goes silent.
    // Once the client has recorded them, kill it -- SIGKILL, no chance to
    // tidy up, which is the case resume exists for.
    let swarm1 = spawn_swarm(&fx, Some(STALL_AFTER));
    let torrent1 = dir.join("run1.torrent");
    fs::write(&torrent1, fx.torrent_bytes(swarm1.tracker_addr)).expect("write torrent file");
    let mut child = client_command(&torrent1, &out_dir, &dir.join("run1.log"))
        .arg("--no-dht")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;

    let deadline = Instant::now() + Duration::from_secs(20);
    while read_recorded(&sidecar).len() < STALL_AFTER {
        let died = child.try_wait().ok().flatten();
        if died.is_some() || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("run 1: client recorded {} of {} pieces before {}", read_recorded(&sidecar).len(), STALL_AFTER, if died.is_some() { "exiting" } else { "the timeout" }));
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.kill().map_err(|e| format!("killing the client: {}", e))?;
    let _ = child.wait();

    let recorded = read_recorded(&sidecar);
    let served = swarm1.log.lock().unwrap().served.clone();
    if recorded != served {
        return Err(format!("run 1: client recorded pieces {:?} but the peer served {:?}", recorded, served));
    }

    // Run 2: a fresh peer and tracker, same output directory. Only the
    // announce URL in the .torrent differs; the sidecar is keyed by info
    // hash, so this is still the same download.
    let swarm2 = spawn_swarm(&fx, None);
    let torrent2 = dir.join("run2.torrent");
    let log2 = dir.join("run2.log");
    fs::write(&torrent2, fx.torrent_bytes(swarm2.tracker_addr)).expect("write torrent file");
    let mut child = client_command(&torrent2, &out_dir, &log2).arg("--no-dht").spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("run 2: download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir).map_err(|e| format!("run 2: {}", e))?;

    let requested: BTreeSet<u32> = swarm2.log.lock().unwrap().requested.iter().copied().collect();
    let missing: BTreeSet<u32> = (0..fx.piece_count as u32).filter(|i| !recorded.contains(i)).collect();
    if requested != missing {
        return Err(format!("run 2 asked the peer for pieces {:?}; expected exactly the {:?} that weren't recorded before the kill (recorded: {:?})", requested, missing, recorded));
    }

    let log = fs::read_to_string(&log2).map_err(|e| format!("reading client log {:?}: {}", log2, e))?;
    let notice = format!("resuming: {} piece(s) already verified on disk", recorded.len());
    if !log.contains(&notice) {
        return Err(format!("run 2's log lacks {:?}", notice));
    }

    Ok(format!("killed with {} of {} pieces on disk; the resumed run fetched only the other {}", recorded.len(), fx.piece_count, missing.len()))
}
