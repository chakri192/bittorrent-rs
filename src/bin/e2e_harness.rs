//! Not part of the client itself -- a self-contained sanity check that
//! proves the compiled `download` binary works end-to-end without needing
//! a real tracker or real peers on the internet. Everything here runs on
//! `127.0.0.1`: a fake HTTP tracker (hand-rolled, not `bittorrent_rs`'s
//! tracker code -- this plays the *other side* of that conversation) and
//! fake peers (they play the other side of the wire protocol), all
//! serving data from an in-memory buffer. The real `download` binary is
//! then spawned as a subprocess exactly as a user would run it, and its
//! output is diffed byte-for-byte against the original.
//!
//! Each [`Scenario`] is one such story, with assertions on top of the
//! byte-for-byte check about what the client said to the peers, what it
//! asked them for, and what it logged.
//!
//! Run with: `cargo run --bin e2e_harness`

use bittorrent_rs::downloader::progress_file_path;
use bittorrent_rs::metadata::{MetadataMessage, METADATA_PIECE_SIZE};
use bittorrent_rs::peer::handshake::Handshake;
use bittorrent_rs::peer::message::Message;
use bittorrent_rs::peer::ExtendedHandshake;
use sha1::{Digest, Sha1};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex};
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
    /// A three-file torrent downloaded with `--only` on the middle file:
    /// only the pieces that file touches may be fetched.
    SelectiveMultiFile,
    /// A peer that hangs up halfway through a piece: the piece must go
    /// back on the queue and be finished by someone else.
    DropMidPiece,
    /// `--timeout` against a peer that goes silent: the client must give
    /// up, say the download is incomplete, and keep what it has for a
    /// later resume.
    TimeoutIncomplete,
    /// `--seed`: after downloading, the client must stay up and serve the
    /// finished torrent to a peer that connects to it.
    SeedAfterDownload,
    /// The client is given only a magnet link: it must find a peer through
    /// the tracker, fetch and verify the metadata from it (BEP 9), and then
    /// download the content.
    MagnetDownload,
    /// A torrent whose file paths would write outside the download
    /// directory: the client must refuse it and write nothing.
    HostileTorrent,
    /// The only peer hangs up on the first connection: the client must
    /// dial it again and finish.
    ReconnectAfterDrop,
    /// A peer that sends corrupt data beside an honest one: the download
    /// must be correct and the liar must be banned, not retried.
    BanCorruptPeer,
    /// A finished download run again: everything on disk verifies, so
    /// nothing may be fetched.
    RerunAfterComplete,
    /// A finished download with one damaged piece: exactly that piece must
    /// be fetched again.
    RepairCorruptedFile,
    /// `--max-down`: the download must take as long as the limit says.
    LimitDownload,
    /// `--max-up`: so must serving the finished torrent to a leecher.
    LimitUpload,
}

struct Scenario {
    name: &'static str,
    kind: Kind,
}

const SCENARIOS: &[Scenario] = &[
    Scenario { name: "public", kind: Kind::Download { private: false } },
    Scenario { name: "private", kind: Kind::Download { private: true } },
    Scenario { name: "resume-after-kill", kind: Kind::ResumeAfterKill },
    Scenario { name: "selective-multi-file", kind: Kind::SelectiveMultiFile },
    Scenario { name: "drop-mid-piece", kind: Kind::DropMidPiece },
    Scenario { name: "timeout-incomplete", kind: Kind::TimeoutIncomplete },
    Scenario { name: "seed-after-download", kind: Kind::SeedAfterDownload },
    Scenario { name: "magnet-download", kind: Kind::MagnetDownload },
    Scenario { name: "hostile-torrent", kind: Kind::HostileTorrent },
    Scenario { name: "reconnect-after-drop", kind: Kind::ReconnectAfterDrop },
    Scenario { name: "ban-corrupt-peer", kind: Kind::BanCorruptPeer },
    Scenario { name: "rerun-after-complete", kind: Kind::RerunAfterComplete },
    Scenario { name: "repair-corrupted-file", kind: Kind::RepairCorruptedFile },
    Scenario { name: "limit-download", kind: Kind::LimitDownload },
    Scenario { name: "limit-upload", kind: Kind::LimitUpload },
];

fn main() {
    let mut failed = false;
    for scenario in SCENARIOS {
        let outcome = match scenario.kind {
            Kind::Download { private } => run_download(scenario.name, private),
            Kind::ResumeAfterKill => run_resume_after_kill(scenario.name),
            Kind::SelectiveMultiFile => run_selective_multi_file(scenario.name),
            Kind::DropMidPiece => run_drop_mid_piece(scenario.name),
            Kind::TimeoutIncomplete => run_timeout_incomplete(scenario.name),
            Kind::SeedAfterDownload => run_seed_after_download(scenario.name),
            Kind::MagnetDownload => run_magnet_download(scenario.name),
            Kind::HostileTorrent => run_hostile_torrent(scenario.name),
            Kind::ReconnectAfterDrop => run_reconnect_after_drop(scenario.name),
            Kind::BanCorruptPeer => run_ban_corrupt_peer(scenario.name),
            Kind::RerunAfterComplete => run_rerun(scenario.name, None),
            Kind::RepairCorruptedFile => run_rerun(scenario.name, Some(3)),
            Kind::LimitDownload => run_limit_download(scenario.name),
            Kind::LimitUpload => run_limit_upload(scenario.name),
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
    /// Every file, in torrent order: its path relative to the client's
    /// output directory, and its content.
    files: Vec<(String, Vec<u8>)>,
    /// All the files' content back to back: the address space pieces cover.
    data: Vec<u8>,
    piece_len: usize,
    piece_count: usize,
    info_bytes: Vec<u8>,
    info_hash: [u8; 20],
}

/// `len` bytes that differ from `salt` to `salt` and don't repeat within a
/// piece, so a byte landing in the wrong file or place can't go unnoticed.
fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt)).collect()
}

impl Fixture {
    /// The plain fixture: one small text file in 256-byte pieces, so every
    /// piece is a single block.
    fn new(private: bool) -> Self {
        let data = b"hello bittorrent world, this is the e2e harness payload.\n".repeat(30); // a few pieces' worth
        Self::build("e2e.bin", &[("e2e.bin", data)], 256, private)
    }

    /// One file is a single-file torrent named after it; several make a
    /// multi-file torrent named `name`, with the files under `name/`.
    fn build(name: &str, files: &[(&str, Vec<u8>)], piece_len: usize, private: bool) -> Self {
        let files: Vec<(Vec<&str>, Vec<u8>)> = files.iter().map(|(fname, content)| (vec![*fname], content.clone())).collect();
        Self::build_paths(name, &files, piece_len, private, files.len() > 1)
    }

    /// As [`build`](Self::build), with each file's path given as its
    /// components, and `multi` forcing the multi-file form even for one file.
    fn build_paths(name: &str, files: &[(Vec<&str>, Vec<u8>)], piece_len: usize, private: bool, multi: bool) -> Self {
        let single = !multi;
        let data: Vec<u8> = files.iter().flat_map(|(_, content)| content.iter().copied()).collect();

        let mut pieces_concat = Vec::new();
        for chunk in data.chunks(piece_len) {
            pieces_concat.extend_from_slice(&Sha1::digest(chunk));
        }

        // Bencode keys must stay sorted: files < name < piece length <
        // pieces < private (and length < name for a single file).
        let mut v = Vec::new();
        v.extend_from_slice(b"d");
        if single {
            v.extend_from_slice(format!("6:lengthi{}e", data.len()).as_bytes());
        } else {
            v.extend_from_slice(b"5:filesl");
            for (path, content) in files {
                v.extend_from_slice(format!("d6:lengthi{}e4:pathl", content.len()).as_bytes());
                for part in path {
                    v.extend_from_slice(format!("{}:{}", part.len(), part).as_bytes());
                }
                v.extend_from_slice(b"ee");
            }
            v.extend_from_slice(b"e");
        }
        v.extend_from_slice(format!("4:name{}:{}", name.len(), name).as_bytes());
        v.extend_from_slice(format!("12:piece lengthi{}e", piece_len).as_bytes());
        v.extend_from_slice(format!("6:pieces{}:", pieces_concat.len()).as_bytes());
        v.extend_from_slice(&pieces_concat);
        if private {
            v.extend_from_slice(b"7:privatei1e");
        }
        v.extend_from_slice(b"e");
        let info_hash: [u8; 20] = Sha1::digest(&v).into();

        let files = files
            .iter()
            .map(|(path, content)| (if single { path.join("/") } else { format!("{}/{}", name, path.join("/")) }, content.clone()))
            .collect();
        Fixture { files, piece_count: pieces_concat.len() / 20, data, piece_len, info_bytes: v, info_hash }
    }

    /// A magnet link for this torrent naming the tracker at `tracker_addr`.
    fn magnet_uri(&self, tracker_addr: SocketAddr) -> String {
        let hash: String = self.info_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let tracker = format!("http://{}/announce", tracker_addr).replace(':', "%3A").replace('/', "%2F");
        format!("magnet:?xt=urn:btih:{}&dn=e2e.bin&tr={}", hash, tracker)
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

/// What one fake peer observed of the client.
#[derive(Default)]
struct PeerLog {
    /// Whether the client's extended handshake offered `ut_pex`.
    pex_offered: Option<bool>,
    /// Every piece index the client asked for, in order (repeats included).
    requested: Vec<u32>,
    /// Pieces the peer sent in full.
    served: BTreeSet<u32>,
    /// The piece the peer hung up in the middle of, if it did.
    dropped_piece: Option<u32>,
    /// ut_metadata pieces (BEP 9) the peer sent to a client that asked.
    metadata_pieces_served: usize,
    /// Connections the peer has accepted and handshaken.
    connections: usize,
}

/// A latch one fake peer can open for another to wait on, to force an
/// order of events between them.
struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
}

/// A stuck scenario must fail on its own assertions, not hang: waiting
/// on a gate gives up after this long.
const GATE_LIMIT: Duration = Duration::from_secs(30);

impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Gate { open: Mutex::new(false), opened: Condvar::new() })
    }

    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }

    fn wait(&self, limit: Duration) {
        let guard = self.open.lock().unwrap();
        let _ = self.opened.wait_timeout_while(guard, limit, |open| !*open);
    }
}

/// How a fake peer conducts itself. Every kind does a real handshake (with
/// the BEP 10 bit set, so the client sends its extended handshake),
/// announces every piece via bitfield and, sooner or later, unchokes.
enum Behavior {
    /// Serves every block it is asked for.
    Serve,
    /// Serves `n` distinct pieces, then goes silent: it stays connected
    /// but never answers another request, which is a client mid-download
    /// as far as the client can tell.
    StallAfter(usize),
    /// Serves `after_pieces` pieces in full, then on the next piece sends
    /// only the first block and hangs up. Opens `dropped` as it does.
    DropMidPiece { after_pieces: usize, dropped: Arc<Gate> },
    /// Serves normally, but keeps the client choked until `gate` opens.
    ChokedUntil(Arc<Gate>),
    /// Serves normally, but only unchokes the client after this long.
    UnchokeAfter(Duration),
    /// Hangs up on the first connection's first request, then serves.
    DropFirstConnection,
    /// Sends every block corrupted, so no piece ever verifies.
    Corrupt,
}

struct Swarm {
    tracker_addr: SocketAddr,
    /// One log per peer, in the order the tracker lists them.
    logs: Vec<Arc<Mutex<PeerLog>>>,
    /// The request line of every announce the tracker received, in order:
    /// `GET /announce?info_hash=...&port=...&event=started ... HTTP/1.1`.
    announces: Arc<Mutex<Vec<String>>>,
}

/// One query parameter of an announce request line.
fn announce_param(request_line: &str, key: &str) -> Option<String> {
    let query = request_line.split_once('?')?.1.split(' ').next()?;
    query.split('&').find_map(|pair| pair.strip_prefix(key)?.strip_prefix('=')).map(str::to_string)
}

/// What a fake peer needs to know about the torrent it serves.
struct PeerContext {
    data: Vec<u8>,
    /// The bencoded info dict, served to clients that ask for it (BEP 9).
    info_bytes: Vec<u8>,
    info_hash: [u8; 20],
    piece_len: usize,
    piece_count: usize,
}

/// Starts a fake tracker (answers every announce with the full peer list,
/// and records it) and one fake peer per entry of `behaviors`, all on
/// loopback.
fn spawn_swarm(fx: &Fixture, behaviors: Vec<Behavior>) -> Swarm {
    let tracker_listener = TcpListener::bind("127.0.0.1:0").expect("bind fake tracker");
    let tracker_addr = tracker_listener.local_addr().unwrap();

    let mut peer_addrs = Vec::new();
    let mut logs = Vec::new();
    for behavior in behaviors {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake peer");
        peer_addrs.push(listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(PeerLog::default()));
        logs.push(Arc::clone(&log));
        let cx = PeerContext { data: fx.data.clone(), info_bytes: fx.info_bytes.clone(), info_hash: fx.info_hash, piece_len: fx.piece_len, piece_count: fx.piece_count };
        thread::spawn(move || run_fake_peer(listener, cx, behavior, log));
    }

    let announces = Arc::new(Mutex::new(Vec::new()));
    let tracker_announces = Arc::clone(&announces);
    thread::spawn(move || {
        let mut peers_bin = Vec::new();
        for addr in &peer_addrs {
            let IpAddr::V4(ip) = addr.ip() else { unreachable!("loopback bind is always v4 here") };
            peers_bin.extend_from_slice(&ip.octets());
            peers_bin.extend_from_slice(&addr.port().to_be_bytes());
        }

        let mut body = Vec::new();
        body.extend_from_slice(b"d8:intervali1800e5:peers");
        body.extend_from_slice(format!("{}:", peers_bin.len()).as_bytes());
        body.extend_from_slice(&peers_bin);
        body.push(b'e');
        let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());

        // Runs until the harness exits; each announce is a fresh connection.
        for stream in tracker_listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            tracker_announces.lock().unwrap().push(request.lines().next().unwrap_or("").to_string());
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(&body);
        }
    });

    Swarm { tracker_addr, logs, announces }
}

/// The extended-message id the fake peer uses for ut_metadata. Deliberately
/// not the id the client picks, so the client has to use the one it is told.
const PEER_UT_METADATA_ID: u8 = 7;

/// One fake peer: accepts connections for as long as the harness runs, and
/// plays `behavior` on each. (A magnet download connects twice: once to
/// fetch the metadata, once to download.)
fn run_fake_peer(listener: TcpListener, cx: PeerContext, behavior: Behavior, log: Arc<Mutex<PeerLog>>) {
    let (cx, behavior) = (Arc::new(cx), Arc::new(behavior));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let (cx, behavior, log) = (Arc::clone(&cx), Arc::clone(&behavior), Arc::clone(&log));
        thread::spawn(move || serve_connection(stream, &cx, &behavior, &log));
    }
}

fn serve_connection(mut stream: TcpStream, cx: &PeerContext, behavior: &Behavior, log: &Mutex<PeerLog>) {
    let mut hs_buf = [0u8; 68];
    if stream.read_exact(&mut hs_buf).is_err() {
        return;
    }
    let Ok(their_hs) = Handshake::from_bytes(&hs_buf) else { return };
    if their_hs.info_hash != cx.info_hash {
        return;
    }
    let our_hs = Handshake::new(cx.info_hash, [0x99; 20], true);
    if stream.write_all(&our_hs.to_bytes()).is_err() {
        return;
    }

    let mut bits = vec![0u8; cx.piece_count.div_ceil(8)];
    for i in 0..cx.piece_count {
        bits[i / 8] |= 1 << (7 - (i % 8));
    }
    if Message::Bitfield(bits).write_to(&mut stream).is_err() {
        return;
    }
    let nth_connection = {
        let mut log = log.lock().unwrap();
        log.connections += 1;
        log.connections
    };
    if let Behavior::ChokedUntil(gate) = behavior {
        gate.wait(GATE_LIMIT);
    }
    if let Behavior::UnchokeAfter(delay) = behavior {
        thread::sleep(*delay);
    }
    if Message::Unchoke.write_to(&mut stream).is_err() {
        return;
    }

    // The piece a `DropMidPiece` peer has decided to hang up in.
    let mut doomed: Option<u32> = None;
    // The id the client gave ut_metadata in its extended handshake.
    let mut client_ut_metadata_id: Option<u8> = None;
    loop {
        match Message::read_from(&mut stream) {
            Ok(Message::Request { index, begin, length }) => {
                let piece_start = index as usize * cx.piece_len;
                let piece_end = (piece_start + cx.piece_len).min(cx.data.len());
                let hang_up = {
                    let mut log = log.lock().unwrap();
                    log.requested.push(index);
                    match behavior {
                        Behavior::StallAfter(limit) if log.served.len() >= *limit && !log.served.contains(&index) => continue, // read it, never answer
                        Behavior::DropMidPiece { after_pieces, .. } => {
                            if doomed.is_none() && log.served.len() >= *after_pieces && !log.served.contains(&index) {
                                doomed = Some(index);
                            }
                            if doomed == Some(index) && begin > 0 {
                                log.dropped_piece = Some(index);
                            }
                        }
                        _ => {}
                    }
                    // The piece counts as served once its last block is
                    // sent -- recorded *before* the send, so it is never
                    // behind what the client can have received.
                    if log.dropped_piece != Some(index) && (begin + length) as usize == piece_end - piece_start {
                        log.served.insert(index);
                    }
                    log.dropped_piece == Some(index)
                };
                if hang_up {
                    if let Behavior::DropMidPiece { dropped, .. } = behavior {
                        dropped.open();
                    }
                    return; // the stream closes with the piece half-sent
                }
                if matches!(behavior, Behavior::DropFirstConnection) && nth_connection == 1 {
                    return; // hang up on the request
                }
                let mut block = cx.data[piece_start..piece_end][begin as usize..(begin + length) as usize].to_vec();
                if matches!(behavior, Behavior::Corrupt) {
                    block.iter_mut().for_each(|b| *b ^= 0xFF);
                }
                if (Message::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                    return;
                }
            }
            Ok(Message::Extended { id: 0, payload }) => {
                if let Ok(hs) = ExtendedHandshake::parse(&payload) {
                    log.lock().unwrap().pex_offered = Some(hs.peer_ut_pex_id().is_some());
                    // A peer that has the whole torrent answers an extended
                    // handshake with its own, so a client that started from a
                    // magnet link can ask it for the info dict.
                    client_ut_metadata_id = hs.peer_ut_metadata_id();
                    let reply = ExtendedHandshake::build(PEER_UT_METADATA_ID, Some(cx.info_bytes.len() as i64));
                    if (Message::Extended { id: 0, payload: reply }).write_to(&mut stream).is_err() {
                        return;
                    }
                }
            }
            Ok(Message::Extended { id, payload }) if id == PEER_UT_METADATA_ID => {
                let (Some(reply_id), Ok(MetadataMessage::Request { piece })) = (client_ut_metadata_id, MetadataMessage::decode(&payload)) else { continue };
                let start = piece as usize * METADATA_PIECE_SIZE;
                let end = (start + METADATA_PIECE_SIZE).min(cx.info_bytes.len());
                let data = MetadataMessage::Data { piece, total_size: cx.info_bytes.len() as u32, data: cx.info_bytes[start..end].to_vec() };
                log.lock().unwrap().metadata_pieces_served += 1;
                if (Message::Extended { id: reply_id, payload: data.encode() }).write_to(&mut stream).is_err() {
                    return;
                }
            }
            Ok(_) => continue,
            Err(_) => return,
        }
    }
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
fn client_command(source: impl AsRef<std::ffi::OsStr>, out_dir: &Path, log: &Path, max_peers: usize) -> Command {
    let download_bin = std::env::current_exe().expect("current exe").parent().expect("exe dir").join("download");
    let mut cmd = Command::new(download_bin);
    cmd.arg(source).arg("--out").arg(out_dir).arg("--peers").arg(max_peers.to_string());
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

/// Checks one downloaded file against the content it should have.
fn check_file(out_dir: &Path, relative: &str, expected: &[u8]) -> Result<(), String> {
    let path = out_dir.join(relative);
    let downloaded = fs::read(&path).map_err(|e| format!("reading {:?}: {}", path, e))?;
    if downloaded != expected {
        return Err(format!("{}: downloaded {} bytes, expected {}, content differs", relative, downloaded.len(), expected.len()));
    }
    Ok(())
}

/// Checks every file of the torrent.
fn check_downloaded(fx: &Fixture, out_dir: &Path) -> Result<(), String> {
    fx.files.iter().try_for_each(|(relative, content)| check_file(out_dir, relative, content))
}

/// Piece indices `requested` as a set, for comparing with what a run
/// should have asked for.
fn requested_set(log: &Mutex<PeerLog>) -> BTreeSet<u32> {
    log.lock().unwrap().requested.iter().copied().collect()
}

// ---- scenarios -------------------------------------------------------

fn run_download(name: &str, private: bool) -> Result<String, String> {
    let fx = Fixture::new(private);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut cmd = client_command(&torrent, &out_dir, &log_path, 1);
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

    let offered = swarm.logs[0].lock().unwrap().pex_offered;
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
    let swarm1 = spawn_swarm(&fx, vec![Behavior::StallAfter(STALL_AFTER)]);
    let torrent1 = dir.join("run1.torrent");
    fs::write(&torrent1, fx.torrent_bytes(swarm1.tracker_addr)).expect("write torrent file");
    let mut child = client_command(&torrent1, &out_dir, &dir.join("run1.log"), 1)
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
    let served = swarm1.logs[0].lock().unwrap().served.clone();
    if recorded != served {
        return Err(format!("run 1: client recorded pieces {:?} but the peer served {:?}", recorded, served));
    }

    // Run 2: a fresh peer and tracker, same output directory. Only the
    // announce URL in the .torrent differs; the sidecar is keyed by info
    // hash, so this is still the same download.
    let swarm2 = spawn_swarm(&fx, vec![Behavior::Serve]);
    let torrent2 = dir.join("run2.torrent");
    let log2 = dir.join("run2.log");
    fs::write(&torrent2, fx.torrent_bytes(swarm2.tracker_addr)).expect("write torrent file");
    let mut child = client_command(&torrent2, &out_dir, &log2, 1).arg("--no-dht").spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("run 2: download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir).map_err(|e| format!("run 2: {}", e))?;

    let requested = requested_set(&swarm2.logs[0]);
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

/// `--only` on the middle file of three: the client may fetch only the
/// pieces that file touches, and both of those are shared with a neighbour.
fn run_selective_multi_file(name: &str) -> Result<String, String> {
    // Three 300-byte files in 256-byte pieces, 900 bytes, 4 pieces:
    //   a.bin  bytes   0..300  -> pieces 0, 1
    //   b.bin  bytes 300..600  -> pieces 1, 2
    //   c.bin  bytes 600..900  -> pieces 2, 3
    // Piece 1 is the end of a.bin plus the start of b.bin; piece 2 is the
    // end of b.bin plus the start of c.bin. Wanting b.bin means wanting
    // pieces 1 and 2, and pieces 0 and 3 must never be asked for.
    const WANTED: [u32; 2] = [1, 2];
    let fx = Fixture::build("multi", &[("a.bin", pattern(300, 1)), ("b.bin", pattern(300, 2)), ("c.bin", pattern(300, 3))], 256, false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("multi.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .args(["--only", "b.bin"])
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }

    let requested = requested_set(&swarm.logs[0]);
    let wanted: BTreeSet<u32> = WANTED.into_iter().collect();
    if requested != wanted {
        return Err(format!("client asked the peer for pieces {:?}; expected exactly {:?}, the ones b.bin touches", requested, wanted));
    }

    let (b_path, b_content) = &fx.files[1];
    check_file(&out_dir, b_path, b_content)?;
    // Pieces 0 and 3 were never fetched, so neither neighbour can be whole.
    for (path, content) in [&fx.files[0], &fx.files[2]] {
        if fs::read(out_dir.join(path)).is_ok_and(|on_disk| on_disk == *content) {
            return Err(format!("{} is complete on disk although it wasn't selected", path));
        }
    }

    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    let notice = "selective download: 1 of 3 file(s), 2 piece(s)";
    if !log.contains(notice) {
        return Err(format!("client log lacks {:?}", notice));
    }

    Ok(format!("--only b.bin fetched pieces {:?} of 4; b.bin matches, a.bin and c.bin left incomplete", requested))
}

/// One peer hangs up halfway through a piece while a second is choked;
/// the second must then be asked for exactly what the first never finished.
fn run_drop_mid_piece(name: &str) -> Result<String, String> {
    // Pieces of two 16 KiB blocks (the last one a full block and a bit),
    // so a peer can send one block of a piece and leave.
    const CLEAN_PIECES_BEFORE_DROP: usize = 1;
    let fx = Fixture::build("e2e.bin", &[("e2e.bin", pattern(5 * 32768 + 20000, 9))], 32768, false);
    assert_eq!(fx.piece_count, 6);

    // The healthy peer stays choked until the flaky one has dropped, so
    // the flaky one is certain to be handed a piece first, and to lose it.
    let dropped = Gate::new();
    let swarm = spawn_swarm(&fx, vec![Behavior::DropMidPiece { after_pieces: CLEAN_PIECES_BEFORE_DROP, dropped: Arc::clone(&dropped) }, Behavior::ChokedUntil(dropped)]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 2).arg("--no-dht").spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    let (flaky, healthy) = (&swarm.logs[0], &swarm.logs[1]);
    let (served_by_flaky, dropped_piece) = {
        let flaky = flaky.lock().unwrap();
        let Some(dropped_piece) = flaky.dropped_piece else {
            return Err("the flaky peer never hung up mid-piece, so this run tested nothing".to_string());
        };
        (flaky.served.clone(), dropped_piece)
    };
    if served_by_flaky.len() != CLEAN_PIECES_BEFORE_DROP {
        return Err(format!("the flaky peer served {:?} in full; expected {} piece(s) before the drop", served_by_flaky, CLEAN_PIECES_BEFORE_DROP));
    }

    // Everything the flaky peer didn't complete must have come from the
    // healthy one -- the dropped piece included.
    let expected: BTreeSet<u32> = (0..fx.piece_count as u32).filter(|i| !served_by_flaky.contains(i)).collect();
    let asked_of_healthy = requested_set(healthy);
    if asked_of_healthy != expected {
        return Err(format!("the healthy peer was asked for pieces {:?}; expected exactly the {:?} the flaky peer never completed (it hung up on piece {})", asked_of_healthy, expected, dropped_piece));
    }

    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    if !log.contains("disconnected") {
        return Err("client log doesn't mention the dropped peer".to_string());
    }

    Ok(format!("peer hung up mid-piece {}; the other peer supplied the remaining {} pieces and the file matches", dropped_piece, expected.len()))
}

/// `--timeout` with a peer that stops answering partway: the run must end
/// on its own, report an incomplete download and fail, and leave its
/// progress recorded so the same command can resume.
fn run_timeout_incomplete(name: &str) -> Result<String, String> {
    const STALL_AFTER: usize = 3;
    const TIMEOUT: Duration = Duration::from_secs(3);
    // After the timeout the client waits for its workers, and one is
    // blocked reading from the silent peer until its read timeout (10s)
    // expires. Allow that and some slack, but not an indefinite hang.
    const LONGEST_EXPECTED: Duration = Duration::from_secs(30);

    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::StallAfter(STALL_AFTER)]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path, stderr_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"), dir.join("stderr.txt"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let started = Instant::now();
    let mut child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .arg("--timeout")
        .arg(TIMEOUT.as_secs().to_string())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&stderr_path).expect("create stderr file"))
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    let elapsed = started.elapsed();

    if status.code() != Some(1) {
        return Err(format!("client exited with {:?}; an incomplete download must exit with 1", status.code()));
    }
    if elapsed < TIMEOUT {
        return Err(format!("client gave up after {:?}, before its --timeout of {:?}", elapsed, TIMEOUT));
    }
    if elapsed > LONGEST_EXPECTED {
        return Err(format!("client took {:?} to stop after a {:?} timeout", elapsed, TIMEOUT));
    }

    // The peer must have got as far as going silent, or nothing was tested.
    let served = swarm.logs[0].lock().unwrap().served.clone();
    if served.len() != STALL_AFTER {
        return Err(format!("the peer served {:?} before the timeout; expected {} pieces, so the client never reached the stall", served, STALL_AFTER));
    }
    let remaining = fx.piece_count - STALL_AFTER;

    let stderr = fs::read_to_string(&stderr_path).map_err(|e| format!("reading {:?}: {}", stderr_path, e))?;
    let reason = format!("error: incomplete: {} piece(s) never downloaded (1 peer(s) dialed) -- rerun the same command to resume", remaining);
    if !stderr.contains(&reason) {
        return Err(format!("stderr lacks {:?}; it says {:?}", reason, stderr.trim()));
    }

    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    let notice = format!("--timeout of {}s reached with {} piece(s) remaining", TIMEOUT.as_secs(), remaining);
    if !log.contains(&notice) {
        return Err(format!("client log lacks {:?}", notice));
    }

    // Progress is kept for a resume: the pieces the peer sent are recorded,
    // and the resume file is not cleared as it would be on completion.
    let recorded = read_recorded(&progress_file_path(&out_dir, &fx.info_hash));
    if recorded != served {
        return Err(format!("resume file lists {:?}; expected the pieces the peer served, {:?}", recorded, served));
    }
    if fs::read(out_dir.join("e2e.bin")).is_ok_and(|on_disk| on_disk == fx.data) {
        return Err("the output file is complete although the download was reported incomplete".to_string());
    }

    Ok(format!("stopped {:.0?} after a {}s --timeout with {} of {} pieces; exited 1, reported incomplete, resume file kept", elapsed, TIMEOUT.as_secs(), STALL_AFTER, fx.piece_count))
}

/// Checks one announce request line against what the client should have
/// reported: its event and transfer counters.
fn check_announce(line: &str, event: &str, downloaded: &str, left: &str) -> Result<(), String> {
    for (key, want) in [("event", event), ("downloaded", downloaded), ("left", left)] {
        let got = announce_param(line, key);
        if got.as_deref() != Some(want) {
            return Err(format!("{} announce has {}={:?}, expected {:?}: {}", event, key, got, want, line));
        }
    }
    Ok(())
}

/// Kills the client when dropped, so a scenario that leaves it running on
/// purpose can't leak it on an early return.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits until the client's log contains `needle`, failing if the client
/// exits first or `limit` passes.
fn wait_for_log(path: &Path, needle: &str, limit: Duration, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    loop {
        if fs::read_to_string(path).is_ok_and(|log| log.contains(needle)) {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(|e| format!("waiting for the client: {}", e))? {
            return Err(format!("client exited ({:?}) before logging {:?}", status.code(), needle));
        }
        if Instant::now() >= deadline {
            return Err(format!("client had not logged {:?} after {:?}", needle, limit));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Plays a leecher against the client's listener: connects, handshakes,
/// checks the client advertises every piece, and downloads them all,
/// comparing each against the source.
fn leech_everything(fx: &Fixture, port: u16) -> Result<(), String> {
    let wire = |what: &str, e: bittorrent_rs::peer::message::WireError| format!("{}: {:?}", what, e);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connecting to the client's listener on port {}: {}", port, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;

    let ours = Handshake::new(fx.info_hash, [0x77; 20], false);
    stream.write_all(&ours.to_bytes()).map_err(|e| format!("sending the handshake: {}", e))?;
    let mut hs_buf = [0u8; 68];
    stream.read_exact(&mut hs_buf).map_err(|e| format!("reading the client's handshake: {}", e))?;
    let theirs = Handshake::from_bytes(&hs_buf).map_err(|e| format!("the client's handshake: {:?}", e))?;
    if theirs.info_hash != fx.info_hash {
        return Err("the client answered with a different info hash".to_string());
    }

    let bitfield = loop {
        match Message::read_from(&mut stream).map_err(|e| wire("waiting for the bitfield", e))? {
            Message::Bitfield(bits) => break bits,
            _ => continue,
        }
    };
    let advertised = (0..fx.piece_count).filter(|i| bitfield.get(i / 8).is_some_and(|byte| byte & (1 << (7 - (i % 8))) != 0)).count();
    if advertised != fx.piece_count {
        return Err(format!("the client advertised {} of {} pieces after finishing", advertised, fx.piece_count));
    }

    Message::Interested.write_to(&mut stream).map_err(|e| wire("sending interested", e))?;
    loop {
        match Message::read_from(&mut stream).map_err(|e| wire("waiting for the unchoke", e))? {
            Message::Unchoke => break,
            _ => continue,
        }
    }

    for index in 0..fx.piece_count {
        let start = index * fx.piece_len;
        let end = (start + fx.piece_len).min(fx.data.len());
        Message::Request { index: index as u32, begin: 0, length: (end - start) as u32 }.write_to(&mut stream).map_err(|e| wire("requesting a piece", e))?;
        let block = loop {
            match Message::read_from(&mut stream).map_err(|e| wire(&format!("waiting for piece {}", index), e))? {
                Message::Piece { index: got, begin: 0, block } if got as usize == index => break block,
                _ => continue,
            }
        };
        if block != fx.data[start..end] {
            return Err(format!("piece {} served by the client differs from the source", index));
        }
    }
    Ok(())
}

/// `--seed`: once the download is done the client keeps running and serves
/// the torrent to whoever connects.
///
/// It cannot test the graceful stop. In plain (non-TTY) mode nothing ever
/// sets the client's stop flag -- only the dashboard's `q` does, and there
/// is no signal handler -- so the harness can only kill it.
fn run_seed_after_download(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    // Port 0: let the OS pick, so this can't collide with a real client on
    // 6881. What matters is that the client announces the port it really
    // listens on.
    let child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .arg("--seed")
        .args(["--port", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);

    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    check_downloaded(&fx, &out_dir)?;
    if client.0.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Err("the client exited once the download finished; --seed should keep it running".to_string());
    }
    if progress_file_path(&out_dir, &fx.info_hash).exists() {
        return Err("the resume file is still there after the download completed".to_string());
    }

    // Both tracker announces the client owes: started, then completed.
    let announces = swarm.announces.lock().unwrap().clone();
    let [started, completed] = announces.as_slice() else {
        return Err(format!("the tracker saw {} announces, expected started and completed: {:?}", announces.len(), announces));
    };
    let total = fx.data.len().to_string();
    check_announce(started, "started", "0", &total)?;
    check_announce(completed, "completed", &total, "0")?;

    // Connect to the port the client told the tracker about and leech.
    let port: u16 = announce_param(started, "port").and_then(|p| p.parse().ok()).ok_or_else(|| format!("no port in the announce: {}", started))?;
    leech_everything(&fx, port)?;

    if client.0.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Err("the client exited while seeding".to_string());
    }
    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    if !log.contains("download complete") {
        return Err("client log lacks \"download complete\"".to_string());
    }

    Ok(format!("finished, announced started+completed, kept running, and served all {} pieces to a leecher on port {}", fx.piece_count, port))
}

/// The client starts from a magnet link and nothing else: the tracker in the
/// link gives it a peer, it fetches the info dict from that peer over
/// BEP 9 and checks it against the link's hash, and then it downloads.
fn run_magnet_download(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (out_dir, log_path) = (dir.join("out"), dir.join("client.log"));

    let mut child = client_command(fx.magnet_uri(swarm.tracker_addr), &out_dir, &log_path, 1)
        .arg("--no-dht")
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    for notice in ["querying 1 tracker(s) to bootstrap peer list", "metadata received and verified against magnet InfoHash"] {
        if !log.contains(notice) {
            return Err(format!("client log lacks {:?}", notice));
        }
    }
    let served = swarm.logs[0].lock().unwrap().metadata_pieces_served;
    if served == 0 {
        return Err("the peer was never asked for the metadata".to_string());
    }

    // Three announces: the bootstrap one, made before the size is known
    // (left=1, so the tracker sees a leecher); the real one once the
    // metadata has arrived; and completed.
    let announces = swarm.announces.lock().unwrap().clone();
    let [bootstrap, started, completed] = announces.as_slice() else {
        return Err(format!("the tracker saw {} announces, expected bootstrap, started and completed: {:?}", announces.len(), announces));
    };
    let total = fx.data.len().to_string();
    check_announce(bootstrap, "started", "0", "1")?;
    check_announce(started, "started", "0", &total)?;
    check_announce(completed, "completed", &total, "0")?;

    Ok(format!("magnet link -> metadata ({} piece) -> {} bytes, all matching; announced bootstrap, started, completed", served, fx.data.len()))
}

/// A torrent whose paths would escape the download directory, with correct
/// piece hashes and a peer that would happily serve it, so that if the
/// client did not refuse it the download would succeed and write outside.
/// It must fail cleanly, before contacting anyone, and write nothing.
fn run_hostile_torrent(name: &str) -> Result<String, String> {
    // Canary files where the hostile paths would put their data. The output
    // directory is <tmp>/e2e_harness_<name>/out/<torrent name>, so three
    // `..` land in <tmp>; watching the directory above it as well means a
    // change to where files go cannot hide an escape.
    let tmp = std::env::temp_dir();
    let above_tmp = tmp.parent().map(Path::to_path_buf).unwrap_or_else(|| tmp.clone());
    let escape_canaries = [tmp.join("e2e_hostile_escape.bin"), above_tmp.join("e2e_hostile_escape.bin")];
    let absolute_canary = tmp.join("e2e_hostile_absolute.bin");
    for canary in escape_canaries.iter().chain([&absolute_canary]) {
        let _ = fs::remove_file(canary);
    }
    let absolute = absolute_canary.to_string_lossy().to_string();

    let cases: [(&str, Vec<&str>, Vec<&PathBuf>); 2] = [
        ("parent-directory traversal", vec!["..", "..", "..", "e2e_hostile_escape.bin"], escape_canaries.iter().collect()),
        ("absolute path", vec![absolute.as_str()], vec![&absolute_canary]),
    ];

    for (label, path, canaries) in cases {
        let fx = Fixture::build_paths("multi", &[(path, pattern(512, 7))], 256, false, true);
        let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
        let dir = scratch_dir(&format!("{}-{}", name, label.replace(' ', "-")));
        let (torrent, out_dir, log_path, stderr_path) = (dir.join("hostile.torrent"), dir.join("out"), dir.join("client.log"), dir.join("stderr.txt"));
        fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

        let mut child = client_command(&torrent, &out_dir, &log_path, 1)
            .arg("--no-dht")
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr_path).expect("create stderr file"))
            .spawn()
            .map_err(|e| format!("failed to spawn the client: {}", e))?;
        let status = wait_or_kill(&mut child, RUN_LIMIT)?;

        if let Some(written) = canaries.iter().find(|c| c.exists()) {
            let _ = fs::remove_file(written);
            return Err(format!("{}: the client wrote {:?}, outside the download directory", label, written));
        }
        if status.code() != Some(1) {
            return Err(format!("{}: client exited with {:?}; a hostile torrent must be refused with status 1", label, status.code()));
        }
        let stderr = fs::read_to_string(&stderr_path).map_err(|e| format!("reading {:?}: {}", stderr_path, e))?;
        if !stderr.contains("unsafe path in torrent") {
            return Err(format!("{}: stderr should say why; it says {:?}", label, stderr.trim()));
        }
        if !swarm.announces.lock().unwrap().is_empty() || !swarm.logs[0].lock().unwrap().requested.is_empty() {
            return Err(format!("{}: the client contacted the swarm before refusing the torrent", label));
        }
    }

    Ok("parent-traversal and absolute paths were refused with status 1 before any network use, and nothing was written outside".to_string())
}

/// The only peer hangs up on the first connection. The client used to dial
/// each address once, so that ended the download; it must now wait out a
/// short delay, dial again, and finish.
fn run_reconnect_after_drop(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::DropFirstConnection]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .args(["--retry-delay", "1"])
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}; it should have reconnected and finished", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    let connections = swarm.logs[0].lock().unwrap().connections;
    if connections != 2 {
        return Err(format!("the peer saw {} connections; expected the dropped one and one retry", connections));
    }
    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    if !log.contains("disconnected") {
        return Err("client log does not mention the dropped connection".to_string());
    }
    Ok("the only peer dropped the first connection; the client dialed it again and the file matches".to_string())
}

/// A peer that sends corrupt data, beside an honest one that is slow to
/// unchoke. The download must be correct, and the liar dialed exactly once:
/// the honest peer's delay makes the run longer than the retry delay, so a
/// client that merely retried it would show up as a second connection.
fn run_ban_corrupt_peer(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Corrupt, Behavior::UnchokeAfter(Duration::from_millis(2500))]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 2)
        .arg("--no-dht")
        .args(["--retry-delay", "1"])
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    let liar_connections = swarm.logs[0].lock().unwrap().connections;
    if liar_connections != 1 {
        return Err(format!("the corrupt peer was dialed {} times; a peer that sends bad data must be banned after the first", liar_connections));
    }
    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    if !log.contains("banned: it sent a piece that failed verification") {
        return Err("client log does not say the corrupt peer was banned".to_string());
    }
    Ok("the corrupt peer was banned after one bad piece and never redialed; the honest peer supplied a byte-identical file".to_string())
}

/// Downloads the torrent, then runs the client again over the finished
/// files. The first run deletes its resume file on completion, so the
/// second has only the data on disk to go on. With `damage_piece`, one byte
/// of that piece is flipped in between.
fn run_rerun(name: &str, damage_piece: Option<usize>) -> Result<String, String> {
    let fx = Fixture::new(false);
    let dir = scratch_dir(name);
    let out_dir = dir.join("out");

    // First run: an ordinary complete download.
    let swarm1 = spawn_swarm(&fx, vec![Behavior::Serve]);
    let torrent1 = dir.join("run1.torrent");
    fs::write(&torrent1, fx.torrent_bytes(swarm1.tracker_addr)).expect("write torrent file");
    let mut child = client_command(&torrent1, &out_dir, &dir.join("run1.log"), 1).arg("--no-dht").stdout(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    if !wait_or_kill(&mut child, RUN_LIMIT)?.success() {
        return Err("run 1 did not complete".to_string());
    }
    check_downloaded(&fx, &out_dir).map_err(|e| format!("run 1: {}", e))?;
    if progress_file_path(&out_dir, &fx.info_hash).exists() {
        return Err("run 1 left its resume file behind".to_string());
    }

    if let Some(piece) = damage_piece {
        let path = out_dir.join("e2e.bin");
        let mut bytes = fs::read(&path).map_err(|e| e.to_string())?;
        bytes[piece * fx.piece_len + 7] ^= 0xFF;
        fs::write(&path, bytes).map_err(|e| e.to_string())?;
    }

    // Second run, against a fresh swarm that would serve every piece.
    let swarm2 = spawn_swarm(&fx, vec![Behavior::Serve]);
    let torrent2 = dir.join("run2.torrent");
    let log2 = dir.join("run2.log");
    fs::write(&torrent2, fx.torrent_bytes(swarm2.tracker_addr)).expect("write torrent file");
    let mut child = client_command(&torrent2, &out_dir, &log2, 1).arg("--no-dht").stdout(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("run 2 exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir).map_err(|e| format!("run 2: {}", e))?;

    let requested = requested_set(&swarm2.logs[0]);
    let expected: BTreeSet<u32> = damage_piece.map(|p| p as u32).into_iter().collect();
    if requested != expected {
        return Err(format!("run 2 asked the peer for pieces {:?}; expected {:?}", requested, expected));
    }
    let log = fs::read_to_string(&log2).map_err(|e| format!("reading client log {:?}: {}", log2, e))?;
    let checked = format!("checking the files on disk against the torrent ({} pieces)", fx.piece_count);
    if !log.contains(&checked) {
        return Err(format!("run 2's log lacks {:?}", checked));
    }
    let good = fx.piece_count - expected.len();
    if good > 0 && !log.contains(&format!("resuming: {} piece(s) already verified on disk", good)) {
        return Err(format!("run 2's log does not report {} pieces resumed", good));
    }

    Ok(match damage_piece {
        None => format!("the finished download was verified in place ({} pieces) and nothing was fetched", fx.piece_count),
        Some(p) => format!("one damaged piece ({}) was found among {} and only it was fetched; the file matches", p, fx.piece_count),
    })
}

/// `--max-down 500` on a 1710-byte torrent: a full second's worth (500
/// bytes) is free, the other 1210 take 2.4s at 500 B/s. Unlimited, the same
/// download takes a few hundredths of a second.
fn run_limit_download(name: &str) -> Result<String, String> {
    const RATE: u64 = 500;
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let started = Instant::now();
    let mut child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .args(["--max-down", &RATE.to_string()])
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    let elapsed = started.elapsed();
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    let floor = Duration::from_secs_f64((fx.data.len() as f64 - RATE as f64) / RATE as f64 * 0.85);
    if elapsed < floor {
        return Err(format!("{} bytes at --max-down {} took only {:?}; at least {:?} was expected", fx.data.len(), RATE, elapsed, floor));
    }
    Ok(format!("{} bytes at --max-down {} took {:.1?} (at least {:.1?}), and match exactly", fx.data.len(), RATE, elapsed, floor))
}

/// `--max-up 600`: a leecher pulling all 1710 bytes from the seeding
/// client gets the first 600 free and waits for the rest.
fn run_limit_upload(name: &str) -> Result<String, String> {
    const RATE: u64 = 600;
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .arg("--seed")
        .args(["--port", "0"])
        .args(["--max-up", &RATE.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;

    let announces = swarm.announces.lock().unwrap().clone();
    let port: u16 = announces.first().and_then(|line| announce_param(line, "port")).and_then(|p| p.parse().ok()).ok_or("no port in the client's first announce")?;
    let started = Instant::now();
    leech_everything(&fx, port)?; // checks every byte too
    let elapsed = started.elapsed();

    let floor = Duration::from_secs_f64((fx.data.len() as f64 - RATE as f64) / RATE as f64 * 0.85);
    if elapsed < floor {
        return Err(format!("serving {} bytes at --max-up {} took only {:?}; at least {:?} was expected", fx.data.len(), RATE, elapsed, floor));
    }
    Ok(format!("a leecher took {:.1?} (at least {:.1?}) to pull {} bytes at --max-up {}, every byte correct", elapsed, floor, fx.data.len(), RATE))
}
