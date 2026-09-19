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
//! Run with: `cargo run --bin e2e_harness`, or with scenario names after
//! `--` to run only those.

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
    /// SIGINT while seeding, with no terminal: a clean exit, status 0.
    SigintWhileSeeding,
    /// SIGTERM mid-download, with the only peer silent: a prompt, clean exit
    /// that keeps the resume file.
    SigtermMidDownload,
    /// A torrent's empty files exist after the download, though no piece
    /// contains a byte of them; with `--only`, only the selected ones do.
    EmptyFiles,
    /// `--verify` checks files on disk against the torrent with no network,
    /// and its exit status says whether they are whole.
    Verify,
    /// A finished client serves its info dictionary to a peer that asks for
    /// it (BEP 9) and says it is a seed (BEP 21).
    ServeMetadata,
    /// A magnet link with no tracker, only an `x.pe` peer hint (and a v2
    /// hash beside the v1 one, as a hybrid link has): it still downloads.
    MagnetPeerHint,
    /// A tracker that redirects every announce: the client follows it, and
    /// the download is unaffected.
    TrackerRedirect,
    /// `--encryption`: an encrypted connection is made and used where the
    /// peer will, a plain one where it will not (unless required), and
    /// incoming connections are taken either way (unless required).
    Encryption,
    /// Local service discovery (BEP 14): a torrent with no tracker and no
    /// DHT finds its only peer from a datagram on the local network, and
    /// announces itself the way the BEP describes. Kept on loopback with
    /// unicast addresses in place of the multicast group.
    LocalDiscovery,
    /// The Fast Extension (BEP 6): the client downloads what a peer allows
    /// while still choked, and as a seeder tells a fast peer what it has
    /// with `have all`, allows it pieces and serves them before any unchoke.
    FastExtension,
    /// A disk that cannot be written to ends the run at once with a message
    /// saying so, instead of dialing the same peers over and over.
    DiskFailure,
    /// `--prefer`: the pieces of the preferred file are requested first;
    /// a pattern that matches nothing is refused before any download.
    PreferFiles,
    /// `--json`: stdout is nothing but JSON events, in a sensible order,
    /// for a download, a failure, a `--list` and an interruption.
    JsonEvents,
    /// `create_torrent` makes what an independently written builder makes,
    /// and the client downloads from it.
    CreateTorrent,
    /// Two peers that each have only part of the torrent between them: the
    /// download completes, and each is asked only for what it has.
    PartialPeers,
    /// A leecher connected to the client's listener during the download is
    /// told of each piece as it is verified.
    HaveBroadcast,
    /// `--seed-ratio`: seeding ends by itself once that much has been
    /// uploaded, and not before.
    SeedRatio,
    /// `--seed-time`: seeding ends by itself after that long.
    SeedTime,
    /// A tracker that never answers the `stopped` announce delays the exit
    /// by a few seconds and no more.
    StoppedAnnounceIsBounded,
    /// A second signal during that wait exits at once with status 130.
    SecondSignalForcesExit,
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
    Scenario { name: "sigint-while-seeding", kind: Kind::SigintWhileSeeding },
    Scenario { name: "sigterm-mid-download", kind: Kind::SigtermMidDownload },
    Scenario { name: "empty-files", kind: Kind::EmptyFiles },
    Scenario { name: "verify", kind: Kind::Verify },
    Scenario { name: "serve-metadata", kind: Kind::ServeMetadata },
    Scenario { name: "magnet-peer-hint", kind: Kind::MagnetPeerHint },
    Scenario { name: "tracker-redirect", kind: Kind::TrackerRedirect },
    Scenario { name: "encryption", kind: Kind::Encryption },
    Scenario { name: "local-discovery", kind: Kind::LocalDiscovery },
    Scenario { name: "fast-extension", kind: Kind::FastExtension },
    Scenario { name: "disk-failure", kind: Kind::DiskFailure },
    Scenario { name: "prefer-files", kind: Kind::PreferFiles },
    Scenario { name: "json-events", kind: Kind::JsonEvents },
    Scenario { name: "create-torrent", kind: Kind::CreateTorrent },
    Scenario { name: "partial-peers", kind: Kind::PartialPeers },
    Scenario { name: "have-broadcast", kind: Kind::HaveBroadcast },
    Scenario { name: "seed-ratio-ends-seeding", kind: Kind::SeedRatio },
    Scenario { name: "seed-time-ends-seeding", kind: Kind::SeedTime },
    Scenario { name: "stopped-announce-is-bounded", kind: Kind::StoppedAnnounceIsBounded },
    Scenario { name: "second-signal-forces-exit", kind: Kind::SecondSignalForcesExit },
];

fn main() {
    // Scenario names on the command line select just those; none runs all.
    let wanted: Vec<String> = std::env::args().skip(1).collect();
    if let Some(unknown) = wanted.iter().find(|name| !SCENARIOS.iter().any(|s| s.name == name.as_str())) {
        eprintln!("no scenario called {:?}; they are: {}", unknown, SCENARIOS.iter().map(|s| s.name).collect::<Vec<_>>().join(", "));
        std::process::exit(2);
    }
    let mut failed = false;
    for scenario in SCENARIOS.iter().filter(|s| wanted.is_empty() || wanted.iter().any(|name| name == s.name)) {
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
            Kind::SigintWhileSeeding => run_sigint_while_seeding(scenario.name),
            Kind::SigtermMidDownload => run_sigterm_mid_download(scenario.name),
            Kind::EmptyFiles => run_empty_files(scenario.name),
            Kind::Verify => run_verify(scenario.name),
            Kind::ServeMetadata => run_serve_metadata(scenario.name),
            Kind::MagnetPeerHint => run_magnet_peer_hint(scenario.name),
            Kind::TrackerRedirect => run_tracker_redirect(scenario.name),
            Kind::Encryption => run_encryption(scenario.name),
            Kind::LocalDiscovery => run_local_discovery(scenario.name),
            Kind::FastExtension => run_fast_extension(scenario.name),
            Kind::DiskFailure => run_disk_failure(scenario.name),
            Kind::PreferFiles => run_prefer_files(scenario.name),
            Kind::JsonEvents => run_json_events(scenario.name),
            Kind::CreateTorrent => run_create_torrent(scenario.name),
            Kind::PartialPeers => run_partial_peers(scenario.name),
            Kind::HaveBroadcast => run_have_broadcast(scenario.name),
            Kind::SeedRatio => run_seed_ratio(scenario.name),
            Kind::SeedTime => run_seed_time(scenario.name),
            Kind::StoppedAnnounceIsBounded => run_stopped_announce_is_bounded(scenario.name),
            Kind::SecondSignalForcesExit => run_second_signal_forces_exit(scenario.name),
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
    /// Connections that turned out to be encrypted (MSE) and plain.
    encrypted_connections: usize,
    plain_connections: usize,
    /// Whether the client's extended handshake offered `ut_pex`.
    pex_offered: Option<bool>,
    /// Whether the client's handshake had the Fast Extension bit.
    fast_offered: Option<bool>,
    /// Requests a `Fast` peer turned away because it had the client choked.
    refused_while_choked: usize,
    /// Every piece index the client asked for, in order (repeats included).
    requested: Vec<u32>,
    /// Every block requested as (piece, offset within the piece), in order.
    requested_blocks: Vec<(u32, u32)>,
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
    /// Serves normally but has only these pieces, and says so in its
    /// bitfield: what a mid-download peer in a real swarm looks like.
    Partial(BTreeSet<u32>),
    /// Speaks the Fast Extension: `have all`, then `allowed fast` for these
    /// pieces, and no unchoke until they have all been served. A request for
    /// any other piece while choked is refused with `reject request`.
    Fast(BTreeSet<u32>),
}

/// How the fake tracker treats the client's announces.
#[derive(Clone, Copy, PartialEq)]
enum TrackerMode {
    /// Answers every announce.
    Answer,
    /// Answers all but `event=stopped`, which it receives and then leaves
    /// hanging with the connection open: the client's exit has to cope with
    /// a tracker that never replies.
    IgnoreStopped,
    /// Answers every announce to `/announce` with a 302 to `/announce2`,
    /// which answers normally.
    Redirect,
}

struct Swarm {
    tracker_addr: SocketAddr,
    /// Where each fake peer listens, in the order of `logs`.
    peer_addrs: Vec<SocketAddr>,
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
    /// Whether this peer takes encrypted (MSE) connections, and plain ones.
    encryption: bittorrent_rs::peer::Encryption,
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
    spawn_swarm_with_tracker(fx, behaviors, TrackerMode::Answer)
}

/// [`spawn_swarm`] with a chosen way for the tracker to behave.
fn spawn_swarm_with_tracker(fx: &Fixture, behaviors: Vec<Behavior>, mode: TrackerMode) -> Swarm {
    spawn_swarm_full(fx, behaviors, mode, bittorrent_rs::peer::Encryption::Off)
}

/// [`spawn_swarm_with_tracker`] with the peers taking encrypted connections
/// too, if `encryption` says so.
fn spawn_swarm_full(fx: &Fixture, behaviors: Vec<Behavior>, mode: TrackerMode, encryption: bittorrent_rs::peer::Encryption) -> Swarm {
    let tracker_listener = TcpListener::bind("127.0.0.1:0").expect("bind fake tracker");
    let tracker_addr = tracker_listener.local_addr().unwrap();

    let mut peer_addrs = Vec::new();
    let mut logs = Vec::new();
    for behavior in behaviors {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake peer");
        peer_addrs.push(listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(PeerLog::default()));
        logs.push(Arc::clone(&log));
        let cx = PeerContext { encryption, data: fx.data.clone(), info_bytes: fx.info_bytes.clone(), info_hash: fx.info_hash, piece_len: fx.piece_len, piece_count: fx.piece_count };
        thread::spawn(move || run_fake_peer(listener, cx, behavior, log));
    }

    let peer_addrs_for_swarm = peer_addrs.clone();
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

        // Connections left unanswered stay open until the harness exits.
        let mut hung = Vec::new();
        // Runs until the harness exits; each announce is a fresh connection.
        for stream in tracker_listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let request_line = request.lines().next().unwrap_or("").to_string();
            let ignored = mode == TrackerMode::IgnoreStopped && announce_param(&request_line, "event").as_deref() == Some("stopped");
            let redirected = mode == TrackerMode::Redirect && request_line.starts_with("GET /announce?");
            tracker_announces.lock().unwrap().push(request_line);
            if ignored {
                hung.push(stream);
                continue;
            }
            if redirected {
                let _ = stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /announce2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                continue;
            }
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(&body);
        }
    });

    Swarm { tracker_addr, peer_addrs: peer_addrs_for_swarm, logs, announces }
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

fn serve_connection(tcp: TcpStream, cx: &PeerContext, behavior: &Behavior, log: &Mutex<PeerLog>) {
    // Plain or encrypted, whichever the client begins with (as far as this
    // peer is set to take).
    let Ok((mut stream, encrypted)) = bittorrent_rs::peer::mse::accept(Box::new(tcp), &[cx.info_hash], cx.encryption) else { return };
    let mut hs_buf = [0u8; 68];
    if stream.read_exact(&mut hs_buf).is_err() {
        return;
    }
    let Ok(their_hs) = Handshake::from_bytes(&hs_buf) else { return };
    if their_hs.info_hash != cx.info_hash {
        return;
    }
    let fast = matches!(behavior, Behavior::Fast(_));
    let our_hs = Handshake::new(cx.info_hash, [0x99; 20], true).with_fast(fast);
    if stream.write_all(&our_hs.to_bytes()).is_err() {
        return;
    }
    {
        let mut log = log.lock().unwrap();
        log.fast_offered = Some(their_hs.supports_fast());
        if encrypted {
            log.encrypted_connections += 1;
        } else {
            log.plain_connections += 1;
        }
    }

    let mut bits = vec![0u8; cx.piece_count.div_ceil(8)];
    for i in 0..cx.piece_count {
        if !matches!(behavior, Behavior::Partial(has) if !has.contains(&(i as u32))) {
            bits[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    if let Behavior::Fast(allowed) = behavior {
        if Message::HaveAll.write_to(&mut stream).is_err() || allowed.iter().any(|&piece_index| Message::AllowedFast { piece_index }.write_to(&mut stream).is_err()) {
            return;
        }
    } else if Message::Bitfield(bits).write_to(&mut stream).is_err() {
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
    // A `Fast` peer holds the client choked until it has served what it allowed.
    let mut choking = matches!(behavior, Behavior::Fast(_));
    if !choking && Message::Unchoke.write_to(&mut stream).is_err() {
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
                if let (Behavior::Fast(allowed), true) = (behavior, choking) {
                    if !allowed.contains(&index) {
                        let mut log = log.lock().unwrap();
                        log.requested.push(index);
                        log.refused_while_choked += 1;
                        drop(log);
                        if (Message::RejectRequest { index, begin, length }).write_to(&mut stream).is_err() {
                            return;
                        }
                        continue;
                    }
                }
                let hang_up = {
                    let mut log = log.lock().unwrap();
                    log.requested.push(index);
                    log.requested_blocks.push((index, begin));
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
                if let Behavior::Fast(allowed) = behavior {
                    if choking && allowed.is_subset(&log.lock().unwrap().served) {
                        choking = false;
                        if Message::Unchoke.write_to(&mut stream).is_err() {
                            return;
                        }
                    }
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
    // And local discovery would announce on the real network's multicast group.
    cmd.arg("--no-lsd");
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

    // The flaky peer delivered the first block of the piece it dropped, and
    // the client kept it: the healthy peer is asked only for the second.
    let asked_for_dropped: Vec<u32> = healthy.lock().unwrap().requested_blocks.iter().filter(|&&(piece, _)| piece == dropped_piece).map(|&(_, begin)| begin).collect();
    if asked_for_dropped != [16384] {
        return Err(format!("the healthy peer was asked for blocks {:?} of piece {}; the first block had already arrived, so only the block at 16384 was needed", asked_for_dropped, dropped_piece));
    }

    let log = fs::read_to_string(&log_path).map_err(|e| format!("reading client log {:?}: {}", log_path, e))?;
    if !log.contains("disconnected") {
        return Err("client log doesn't mention the dropped peer".to_string());
    }

    Ok(format!("peer hung up mid-piece {}; the other peer supplied the remaining {} pieces, fetching only the block of piece {} that had not arrived, and the file matches", dropped_piece, expected.len(), dropped_piece))
}

/// `--timeout` with a peer that stops answering partway: the run must end
/// on its own, report an incomplete download and fail, and leave its
/// progress recorded so the same command can resume.
fn run_timeout_incomplete(name: &str) -> Result<String, String> {
    const STALL_AFTER: usize = 3;
    const TIMEOUT: Duration = Duration::from_secs(3);
    // The client used to wait out the silent peer's read timeout (10 s)
    // after the deadline; now it stops within a UI tick or two. Leave
    // room for a loaded machine, but well under that old wait.
    const LONGEST_EXPECTED: Duration = Duration::from_secs(3 + 5);

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

    // It told the tracker it was leaving, and what was still missing.
    let got = bytes_of_pieces(&fx, &served);
    check_stopped_last(&swarm, got, fx.data.len() - got)?;

    Ok(format!("stopped {:.0?} after a {}s --timeout with {} of {} pieces; exited 1, reported incomplete, resume file kept, tracker told", elapsed, TIMEOUT.as_secs(), STALL_AFTER, fx.piece_count))
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

/// How many bytes the given pieces of the fixture's data add up to.
fn bytes_of_pieces(fx: &Fixture, pieces: &BTreeSet<u32>) -> usize {
    pieces.iter().map(|&p| (fx.data.len() - p as usize * fx.piece_len).min(fx.piece_len)).sum()
}

/// Checks that the last thing the tracker heard was a `stopped` announce
/// for a client that had downloaded `downloaded` bytes and still lacked `left`.
fn check_stopped_last(swarm: &Swarm, downloaded: usize, left: usize) -> Result<(), String> {
    let announces = swarm.announces.lock().unwrap().clone();
    let last = announces.last().ok_or("the tracker heard nothing")?;
    check_announce(last, "stopped", &downloaded.to_string(), &left.to_string())
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
    leech_pieces(fx, port, 0..fx.piece_count)
}

/// [`leech_everything`], but downloading only the pieces in `wanted`.
fn leech_pieces(fx: &Fixture, port: u16, wanted: std::ops::Range<usize>) -> Result<(), String> {
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

    for index in wanted {
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
/// The harness ends the client by killing it; the stop itself is covered by
/// the signal scenarios.
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
    let (out_dir, log_path, saved_path) = (dir.join("out"), dir.join("client.log"), dir.join("saved.torrent"));

    let mut child = client_command(fx.magnet_uri(swarm.tracker_addr), &out_dir, &log_path, 1)
        .arg("--no-dht")
        .arg("--save-torrent")
        .arg(&saved_path)
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

    // Four announces: the bootstrap one, made before the size is known
    // (left=1, so the tracker sees a leecher); the real one once the
    // metadata has arrived; completed; and stopped as it exits.
    let announces = swarm.announces.lock().unwrap().clone();
    let [bootstrap, started, completed, stopped] = announces.as_slice() else {
        return Err(format!("the tracker saw {} announces, expected bootstrap, started, completed and stopped: {:?}", announces.len(), announces));
    };
    let total = fx.data.len().to_string();
    check_announce(bootstrap, "started", "0", "1")?;
    check_announce(started, "started", "0", &total)?;
    check_announce(completed, "completed", &total, "0")?;
    check_announce(stopped, "stopped", &total, "0")?;

    // --save-torrent kept what the magnet link resolved to, as a torrent
    // anyone can use: the same info hash, and the tracker from the link.
    let saved = fs::read(&saved_path).map_err(|e| format!("--save-torrent wrote nothing: {}", e))?;
    let parsed = bittorrent_rs::torrent::parse_torrent_file(&saved).map_err(|e| format!("the saved torrent cannot be read: {}", e))?;
    if parsed.info_hash != fx.info_hash {
        return Err("the saved torrent has a different info hash".to_string());
    }
    let tracker = format!("http://{}/announce", swarm.tracker_addr);
    if parsed.announce.as_deref() != Some(tracker.as_str()) {
        return Err(format!("the saved torrent's announce is {:?}, expected {}", parsed.announce, tracker));
    }
    if saved_path.with_extension("torrent.part").exists() {
        return Err("a .part file was left beside the saved torrent".to_string());
    }

    Ok(format!("magnet link -> metadata ({} piece) -> {} bytes, all matching; announced bootstrap, started, completed, stopped; --save-torrent kept a torrent with the same info hash", served, fx.data.len()))
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

/// Sends `signal` ("INT", "TERM") to the client, as a user or a service
/// manager would.
fn send_signal(child: &Child, signal: &str) -> Result<(), String> {
    let status = Command::new("kill").args(["-s", signal, &child.id().to_string()]).status().map_err(|e| format!("running kill: {}", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("kill -s {} {} failed", signal, child.id()))
    }
}

/// SIGINT to a seeding client with no terminal. Before signal handling the
/// process was simply killed: no cleanup, no message, and the router's port
/// mapping left behind. Now it must stop the way the dashboard's `q` does.
fn run_sigint_while_seeding(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path, stdout_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"), dir.join("stdout.txt"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .arg("--seed")
        .args(["--port", "0"])
        .stdout(fs::File::create(&stdout_path).expect("create stdout file"))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;

    let signalled = Instant::now();
    send_signal(&client.0, "INT")?;
    let status = wait_or_kill(&mut client.0, Duration::from_secs(10))?;
    let took = signalled.elapsed();

    if status.code() != Some(0) {
        return Err(format!("the client exited with {:?} after SIGINT; a clean stop is status 0", status.code()));
    }
    let stdout = fs::read_to_string(&stdout_path).map_err(|e| e.to_string())?;
    if !stdout.contains("stopped") {
        return Err(format!("stdout should say the client stopped; it says {:?}", stdout.trim()));
    }
    // Its last word to the tracker: leaving, having finished everything.
    let announces = swarm.announces.lock().unwrap().clone();
    let events: Vec<_> = announces.iter().map(|line| announce_param(line, "event").unwrap_or_default()).collect();
    if events != ["started", "completed", "stopped"] {
        return Err(format!("the tracker should hear started, completed, stopped; it heard {:?}", events));
    }
    check_stopped_last(&swarm, fx.data.len(), 0)?;
    Ok(format!("SIGINT stopped a seeding client cleanly in {:.1?}: status 0, a \"stopped\" message, and a stopped announce to the tracker", took))
}

/// SIGTERM while downloading from a peer that has gone silent. The client
/// used to wait out that peer's read timeout (10 s) before it could stop;
/// it must now stop promptly, with the pieces already downloaded kept.
fn run_sigterm_mid_download(name: &str) -> Result<String, String> {
    const STALL_AFTER: usize = 3;
    // Comfortably under the 10 s read timeout it used to wait for, and
    // generous for a loaded machine: the stop itself takes a few hundred ms.
    const PROMPT: Duration = Duration::from_secs(4);
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::StallAfter(STALL_AFTER)]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, stdout_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("stdout.txt"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
    let sidecar = progress_file_path(&out_dir, &fx.info_hash);

    let child = client_command(&torrent, &out_dir, &dir.join("client.log"), 1)
        .arg("--no-dht")
        .stdout(fs::File::create(&stdout_path).expect("create stdout file"))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    let deadline = Instant::now() + Duration::from_secs(20);
    while read_recorded(&sidecar).len() < STALL_AFTER {
        if Instant::now() >= deadline || client.0.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Err(format!("the client recorded only {} of {} pieces", read_recorded(&sidecar).len(), STALL_AFTER));
        }
        thread::sleep(Duration::from_millis(20));
    }

    send_signal(&client.0, "TERM")?;
    let signalled = Instant::now();
    let status = wait_or_kill(&mut client.0, Duration::from_secs(25))?;
    let took = signalled.elapsed();
    if took > PROMPT {
        return Err(format!("the client took {:?} to stop after SIGTERM; it should not wait on a silent peer", took));
    }
    if status.code() != Some(0) {
        return Err(format!("the client exited with {:?} after SIGTERM; a clean stop is status 0", status.code()));
    }
    let stdout = fs::read_to_string(&stdout_path).map_err(|e| e.to_string())?;
    if !stdout.contains("stopped") {
        return Err(format!("stdout should say the client stopped; it says {:?}", stdout.trim()));
    }
    let recorded = read_recorded(&sidecar);
    if recorded.len() != STALL_AFTER {
        return Err(format!("the resume file should keep the {} pieces downloaded; it lists {:?}", STALL_AFTER, recorded));
    }
    let got = bytes_of_pieces(&fx, &recorded);
    check_stopped_last(&swarm, got, fx.data.len() - got)?;
    Ok(format!("SIGTERM mid-download stopped the client cleanly after {:.1?}: status 0, a \"stopped\" message, {} pieces kept for a resume, tracker told what was left", took, STALL_AFTER))
}

/// A tracker that takes the `stopped` announce and never replies. The client
/// must still finish, having waited a few seconds for it -- not the 15 s of
/// the request's own timeout, and not forever.
fn run_stopped_announce_is_bounded(name: &str) -> Result<String, String> {
    const AT_LEAST: Duration = Duration::from_millis(2500);
    const AT_MOST: Duration = Duration::from_secs(8);
    let fx = Fixture::new(false);
    let swarm = spawn_swarm_with_tracker(&fx, vec![Behavior::Serve], TrackerMode::IgnoreStopped);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let started = Instant::now();
    let mut child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    let took = started.elapsed();

    if status.code() != Some(0) {
        return Err(format!("the client exited with {:?}; the unanswered stop must not fail the run", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;
    let announces = swarm.announces.lock().unwrap().clone();
    if announces.last().is_none_or(|line| announce_param(line, "event").as_deref() != Some("stopped")) {
        return Err(format!("the tracker never got a stopped announce: {:?}", announces));
    }
    if took < AT_LEAST {
        return Err(format!("the client exited after {:?}, so it did not wait for the tracker to answer stopped", took));
    }
    if took > AT_MOST {
        return Err(format!("the client took {:?}; an unanswered stopped announce must not hold up the exit that long", took));
    }
    Ok(format!("a tracker that ignored the stopped announce delayed the exit to {:.1?}; the download was complete and the exit status 0", took))
}

/// While the client waits on a tracker that will not answer `stopped`, a
/// second signal must end it at once with status 130.
fn run_second_signal_forces_exit(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm_with_tracker(&fx, vec![Behavior::Serve], TrackerMode::IgnoreStopped);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

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

    send_signal(&client.0, "INT")?;
    // The first signal starts a graceful stop, which ends up waiting for the
    // tracker: wait until the tracker has been told, then check it is
    // still waiting rather than gone.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !swarm.announces.lock().unwrap().iter().any(|line| announce_param(line, "event").as_deref() == Some("stopped")) {
        if Instant::now() >= deadline {
            return Err("the client never sent the stopped announce after the first signal".to_string());
        }
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(300));
    if client.0.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Err("the client had already exited, so there was no slow shutdown for a second signal to cut short".to_string());
    }

    let again = Instant::now();
    send_signal(&client.0, "INT")?;
    let status = wait_or_kill(&mut client.0, Duration::from_secs(2))?;
    if status.code() != Some(130) {
        return Err(format!("a second signal should exit with status 130; got {:?}", status.code()));
    }
    Ok(format!("a second signal cut short the wait on a silent tracker: status 130, {:.1?} later", again.elapsed()))
}

/// `--seed-ratio 1` on its own turns seeding on. Half the torrent uploaded
/// is not enough; all of it is, and then the client stops by itself, tells
/// the tracker, and exits with status 0.
fn run_seed_ratio(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path, stdout_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"), dir.join("stdout.txt"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .args(["--seed-ratio", "1"])
        .args(["--port", "0"])
        .stdout(fs::File::create(&stdout_path).expect("create stdout file"))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    let announces = swarm.announces.lock().unwrap().clone();
    let port: u16 = announces.first().and_then(|line| announce_param(line, "port")).and_then(|p| p.parse().ok()).ok_or("no port in the client's first announce")?;

    // Half the torrent: the ratio is 0.5, so the client must carry on.
    leech_pieces(&fx, port, 0..fx.piece_count / 2)?;
    thread::sleep(Duration::from_millis(800));
    if client.0.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Err("the client stopped seeding at about half the ratio".to_string());
    }

    // The rest brings it to 1.0.
    leech_pieces(&fx, port, fx.piece_count / 2..fx.piece_count)?;
    let status = wait_or_kill(&mut client.0, Duration::from_secs(10))?;
    if status.code() != Some(0) {
        return Err(format!("the client exited with {:?} at its seed ratio; that is a success, status 0", status.code()));
    }
    let stdout = fs::read_to_string(&stdout_path).map_err(|e| e.to_string())?;
    if !stdout.contains("seed ratio 1.00 reached") {
        return Err(format!("stdout should say the seed ratio was reached; it says {:?}", stdout.trim()));
    }
    let log = fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    if !log.contains("will stop seeding at ratio 1.00") {
        return Err("the log does not say when seeding will stop".to_string());
    }
    check_stopped_last(&swarm, fx.data.len(), 0)?;
    Ok(format!("--seed-ratio 1 kept seeding at half the ratio, then stopped by itself once all {} bytes had been uploaded: status 0, tracker told", fx.data.len()))
}

/// `--seed-time 2s`: the client seeds for about that long, then stops by
/// itself with status 0.
fn run_seed_time(name: &str) -> Result<String, String> {
    const SEED_FOR: Duration = Duration::from_secs(2);
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path, stdout_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"), dir.join("stdout.txt"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .args(["--seed-time", &SEED_FOR.as_secs().to_string()])
        .args(["--port", "0"])
        .stdout(fs::File::create(&stdout_path).expect("create stdout file"))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    let seeding_since = Instant::now();

    let status = wait_or_kill(&mut client.0, Duration::from_secs(15))?;
    let seeded_for = seeding_since.elapsed();
    if status.code() != Some(0) {
        return Err(format!("the client exited with {:?} when its seed time was up; that is a success, status 0", status.code()));
    }
    // A little slack below: the log line is read some milliseconds after it is written.
    if seeded_for < SEED_FOR - Duration::from_millis(300) {
        return Err(format!("the client stopped after seeding for only {:?} of {:?}", seeded_for, SEED_FOR));
    }
    if seeded_for > SEED_FOR + Duration::from_secs(5) {
        return Err(format!("the client seeded for {:?}, well past its {:?} limit", seeded_for, SEED_FOR));
    }
    let stdout = fs::read_to_string(&stdout_path).map_err(|e| e.to_string())?;
    if !stdout.contains("seed time of 2s reached") {
        return Err(format!("stdout should say the seed time was reached; it says {:?}", stdout.trim()));
    }
    check_downloaded(&fx, &out_dir)?;
    check_stopped_last(&swarm, fx.data.len(), 0)?;
    Ok(format!("--seed-time {}s stopped a seeding client by itself after {:.1?}: status 0, tracker told", SEED_FOR.as_secs(), seeded_for))
}

/// The client serves what it has while it is still downloading. A leecher
/// that connects to its listener at the start, when it has nothing, must
/// hear about every piece as the client verifies it -- exactly once each --
/// or it would have no way to know there was anything to ask for.
fn run_have_broadcast(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let gate = Gate::new();
    let swarm = spawn_swarm(&fx, vec![Behavior::ChokedUntil(Arc::clone(&gate))]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    // `--seed` keeps the client running once the download is done: a peer
    // is told of a new piece within half a second, which a client that
    // exits the moment it finishes might not stay alive for.
    let child = client_command(&torrent, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .arg("--seed")
        .args(["--port", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);

    // The client announces the port it listens on; the only peer keeps it
    // choked, so nothing is downloaded until the gate opens.
    let deadline = Instant::now() + Duration::from_secs(20);
    let port: u16 = loop {
        let port = swarm.announces.lock().unwrap().first().and_then(|line| announce_param(line, "port")).and_then(|p| p.parse().ok());
        if let Some(port) = port {
            break port;
        }
        if Instant::now() >= deadline || client.0.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Err("the client never announced".to_string());
        }
        thread::sleep(Duration::from_millis(20));
    };

    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(e) if Instant::now() >= deadline => return Err(format!("connecting to the client's listener on port {}: {}", port, e)),
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    stream.write_all(&Handshake::new(fx.info_hash, [0x77; 20], false).to_bytes()).map_err(|e| format!("sending the handshake: {}", e))?;
    let mut hs_buf = [0u8; 68];
    stream.read_exact(&mut hs_buf).map_err(|e| format!("reading the client's handshake: {}", e))?;
    let bitfield = loop {
        match Message::read_from(&mut stream).map_err(|e| format!("waiting for the bitfield: {:?}", e))? {
            Message::Bitfield(bits) => break bits,
            _ => continue,
        }
    };
    if bitfield.iter().any(|&byte| byte != 0) {
        return Err(format!("the client claimed pieces before downloading any: {:?}", bitfield));
    }

    gate.open();
    let mut told = Vec::new();
    while told.len() < fx.piece_count {
        match Message::read_from(&mut stream).map_err(|e| format!("after {} Have message(s) ({:?}): {:?}", told.len(), told, e))? {
            Message::Have { piece_index } => told.push(piece_index),
            _ => continue,
        }
    }
    let mut sorted = told.clone();
    sorted.sort_unstable();
    let expected: Vec<u32> = (0..fx.piece_count as u32).collect();
    if sorted != expected {
        return Err(format!("the leecher was told of pieces {:?}; expected each of {:?} exactly once", told, expected));
    }

    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    check_downloaded(&fx, &out_dir)?;
    Ok(format!("a leecher connected before the download began was told of all {} pieces as they were verified, each once", fx.piece_count))
}

/// The `create_torrent` binary, run on a directory the harness wrote, must
/// produce the info dict this harness builds independently (byte for byte,
/// so the same info hash) -- and a torrent the client can download from.
fn run_create_torrent(name: &str) -> Result<String, String> {
    const PIECE_LEN: usize = 1024;
    // Sizes that put piece boundaries in the middle of files, and a file
    // in a subdirectory whose path sorts between the others.
    let files = [(vec!["a.bin"], pattern(1500, 1)), (vec!["sub", "b.bin"], pattern(2200, 2)), (vec!["z.bin"], pattern(900, 3))];
    let fx = Fixture::build_paths("pack", &files, PIECE_LEN, false, true);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);

    let source = dir.join("src");
    for (relative, content) in &fx.files {
        let path = source.join(relative);
        fs::create_dir_all(path.parent().ok_or("a file with no directory")?).map_err(|e| e.to_string())?;
        fs::write(&path, content).map_err(|e| format!("writing {:?}: {}", path, e))?;
    }
    let torrent_path = dir.join("made.torrent");
    let tracker = format!("http://{}/announce", swarm.tracker_addr);
    let create_bin = std::env::current_exe().map_err(|e| e.to_string())?.parent().ok_or("no exe dir")?.join("create_torrent");
    let run = |extra: &[&str]| {
        Command::new(&create_bin)
            .arg(source.join("pack"))
            .arg("--out")
            .arg(&torrent_path)
            .args(["--announce", &tracker, "--piece-length", "1K", "--no-date", "--quiet"])
            .args(extra)
            .output()
            .map_err(|e| format!("running create_torrent: {}", e))
    };

    let made = run(&[])?;
    if !made.status.success() {
        return Err(format!("create_torrent failed: {}", String::from_utf8_lossy(&made.stderr).trim()));
    }
    let bytes = fs::read(&torrent_path).map_err(|e| format!("reading the torrent it wrote: {}", e))?;
    let parsed = bittorrent_rs::torrent::parse_torrent_file(&bytes).map_err(|e| format!("the client cannot read what create_torrent wrote: {}", e))?;
    if parsed.info_hash != fx.info_hash {
        return Err(format!("info hash {} differs from the independently built {}", bittorrent_rs::torrent::info_hash_hex(&parsed.info_hash), bittorrent_rs::torrent::info_hash_hex(&fx.info_hash)));
    }
    if parsed.announce.as_deref() != Some(tracker.as_str()) {
        return Err(format!("announce is {:?}, expected {:?}", parsed.announce, tracker));
    }

    // It will not silently replace a torrent that is already there.
    let again = run(&[])?;
    if again.status.success() || !String::from_utf8_lossy(&again.stderr).contains("already exists") {
        return Err(format!("a second run should refuse to overwrite; it exited {:?} saying {:?}", again.status.code(), String::from_utf8_lossy(&again.stderr).trim()));
    }
    if fs::read(&torrent_path).map_err(|e| e.to_string())? != bytes {
        return Err("the refused run changed the file anyway".to_string());
    }
    if !run(&["--force"])?.status.success() {
        return Err("--force should replace the file".to_string());
    }

    // And the client downloads from the torrent that was made.
    let (out_dir, log_path) = (dir.join("out"), dir.join("client.log"));
    let mut child = client_command(&torrent_path, &out_dir, &log_path, 1)
        .arg("--no-dht")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if status.code() != Some(0) {
        return Err(format!("the client exited with {:?} downloading the created torrent", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;
    Ok(format!("create_torrent made the same info hash ({}) as the independent builder: {} pieces across 3 files, refused to overwrite, and the client downloaded it byte for byte", &bittorrent_rs::torrent::info_hash_hex(&parsed.info_hash)[..8], fx.piece_count))
}

/// Each of two peers has part of the torrent and they overlap on one
/// piece; neither could supply a whole file. The client must combine them,
/// and must ask each only for pieces it said it has.
fn run_partial_peers(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    if fx.piece_count != 7 {
        return Err(format!("this scenario assumes 7 pieces; the fixture has {}", fx.piece_count));
    }
    let first: BTreeSet<u32> = (0..=3).collect();
    let second: BTreeSet<u32> = (3..=6).collect();
    let swarm = spawn_swarm(&fx, vec![Behavior::Partial(first.clone()), Behavior::Partial(second.clone())]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 2)
        .arg("--no-dht")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    for (label, log, offered) in [("first", &swarm.logs[0], &first), ("second", &swarm.logs[1], &second)] {
        let log = log.lock().unwrap();
        let asked: BTreeSet<u32> = log.requested.iter().copied().collect();
        if let Some(stray) = asked.difference(offered).next() {
            return Err(format!("the {} peer has only {:?} but was asked for piece {}", label, offered, stray));
        }
        if log.served.is_empty() {
            return Err(format!("the {} peer supplied nothing; the download should have needed it", label));
        }
    }
    let served_by_first = swarm.logs[0].lock().unwrap().served.clone();
    let served_by_second = swarm.logs[1].lock().unwrap().served.clone();
    Ok(format!("two partial peers ({:?} and {:?}) together supplied the whole file: {} pieces from the first, {} from the second, none requested that a peer lacked", first, second, served_by_first.len(), served_by_second.len()))
}

/// Every line of `stdout` as a flat JSON object, or the first line that is
/// not one.
fn json_lines(stdout: &str) -> Result<Vec<std::collections::BTreeMap<String, bittorrent_rs::json::Value>>, String> {
    stdout.lines().map(|line| bittorrent_rs::json::parse_object(line).map_err(|e| format!("stdout has a line that is not JSON ({}): {:?}", e, line))).collect()
}

fn event_kinds(events: &[std::collections::BTreeMap<String, bittorrent_rs::json::Value>]) -> Vec<String> {
    events.iter().map(|e| e.get("event").and_then(|v| v.as_str()).unwrap_or("?").to_string()).collect()
}

/// `--json` writes JSON lines and nothing else to stdout, whatever happens.
fn run_json_events(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir) = (dir.join("e2e.torrent"), dir.join("out"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    // 1. A download that succeeds.
    let output = client_command(&torrent, &out_dir, &dir.join("client.log"), 1)
        .arg("--no-dht")
        .arg("--json")
        .output()
        .map_err(|e| format!("running the client: {}", e))?;
    if !output.status.success() {
        return Err(format!("--json download exited with {:?}: {}", output.status.code(), String::from_utf8_lossy(&output.stderr).trim()));
    }
    let events = json_lines(&String::from_utf8_lossy(&output.stdout))?;
    let kinds = event_kinds(&events);
    if kinds.first().map(String::as_str) != Some("torrent") || kinds.last().map(String::as_str) != Some("done") || kinds.iter().filter(|k| *k == "torrent" || *k == "done").count() != 2 {
        return Err(format!("expected torrent first and done last, once each; got {:?}", kinds));
    }
    if let Some(odd) = kinds.iter().find(|k| !["torrent", "progress", "done"].contains(&k.as_str())) {
        return Err(format!("unexpected event {:?} in {:?}", odd, kinds));
    }
    let torrent_event = &events[0];
    let want_hash = bittorrent_rs::torrent::info_hash_hex(&fx.info_hash);
    if torrent_event["info_hash"].as_str() != Some(want_hash.as_str()) || torrent_event["pieces"].as_f64() != Some(fx.piece_count as f64) || torrent_event["total_bytes"].as_f64() != Some(fx.data.len() as f64) {
        return Err(format!("the torrent event is wrong: {:?}", torrent_event));
    }
    let last_progress = events.iter().rev().find(|e| e["event"].as_str() == Some("progress")).ok_or("no progress event")?;
    if last_progress["verified_pieces"].as_f64() != Some(fx.piece_count as f64) || last_progress["percent"].as_f64() != Some(100.0) {
        return Err(format!("the last progress event does not show a finished download: {:?}", last_progress));
    }
    check_downloaded(&fx, &out_dir)?;

    // 2. A failure: a torrent that is not there. The error is an event, and stdout has nothing else.
    let failed = client_command(dir.join("missing.torrent"), &out_dir, &dir.join("client2.log"), 1).arg("--json").output().map_err(|e| format!("running the client: {}", e))?;
    let failure_events = json_lines(&String::from_utf8_lossy(&failed.stdout))?;
    if failed.status.success() || event_kinds(&failure_events) != ["error"] {
        return Err(format!("a missing torrent should exit non-zero with a single error event; exit {:?}, events {:?}", failed.status.code(), event_kinds(&failure_events)));
    }
    let message = failure_events[0]["message"].as_str().unwrap_or("");
    if !message.contains("missing.torrent") {
        return Err(format!("the error does not name the file: {:?}", message));
    }

    // 3. --list: a file event each, and done.
    let multi = Fixture::build_paths("pack", &[(vec!["a.bin"], pattern(700, 1)), (vec!["sub", "we\"ird.bin"], pattern(900, 2))], 256, false, true);
    let multi_torrent = dir.join("multi.torrent");
    fs::write(&multi_torrent, multi.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
    let listed = client_command(&multi_torrent, &out_dir, &dir.join("client3.log"), 1).args(["--no-dht", "--json", "--list", "--only", "ird"]).output().map_err(|e| format!("running the client: {}", e))?;
    let list_events = json_lines(&String::from_utf8_lossy(&listed.stdout))?;
    if !listed.status.success() || event_kinds(&list_events) != ["file", "file", "done"] {
        return Err(format!("--list --json should give two file events then done; exit {:?}, events {:?}", listed.status.code(), event_kinds(&list_events)));
    }
    if list_events[0]["path"].as_str() != Some("a.bin") || list_events[0]["selected"].as_bool() != Some(false) || list_events[1]["path"].as_str() != Some("sub/we\"ird.bin") || list_events[1]["selected"].as_bool() != Some(true) || list_events[1]["bytes"].as_f64() != Some(900.0) {
        return Err(format!("the file events are wrong: {:?}", list_events));
    }

    // 4. Interrupted while seeding: the last event is `stopped`.
    let seed_out = dir.join("seed-out");
    let seed_log = dir.join("seed.log");
    let child = client_command(&torrent, &seed_out, &seed_log, 1)
        .args(["--no-dht", "--json", "--seed", "--port", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&seed_log, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    send_signal(&client.0, "INT")?;
    let mut stdout = String::new();
    if let Some(mut pipe) = client.0.stdout.take() {
        pipe.read_to_string(&mut stdout).map_err(|e| e.to_string())?;
    }
    let status = wait_or_kill(&mut client.0, Duration::from_secs(10))?;
    let seed_events = json_lines(&stdout)?;
    let seed_kinds = event_kinds(&seed_events);
    if status.code() != Some(0) || seed_kinds.last().map(String::as_str) != Some("stopped") || seed_kinds.iter().any(|k| k == "done" || k == "error") {
        return Err(format!("an interrupted --json run should exit 0 ending in a stopped event; exit {:?}, events {:?}", status.code(), seed_kinds));
    }

    Ok(format!("--json: {} events for a download (torrent, progress, done), a lone error for a missing torrent, file events for --list, and a final stopped after SIGINT; stdout was JSON throughout", events.len()))
}

/// A torrent of two files, the second of which is preferred: its pieces are
/// requested before the first file's, and the whole download still
/// completes. A `--prefer` that matches no file fails before any download.
fn run_prefer_files(name: &str) -> Result<String, String> {
    // 1500 + 1500 bytes in 256-byte pieces: 12 pieces, and the second file
    // starts inside piece 5, so it covers pieces 5 through 11.
    let fx = Fixture::build("pack", &[("a.bin", pattern(1500, 1)), ("b.bin", pattern(1500, 2))], 256, false);
    assert_eq!(fx.piece_count, 12);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 1)
        .args(["--no-dht", "--prefer", "B.BIN"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;
    let asked = swarm.logs[0].lock().unwrap().requested.clone();
    let expected: Vec<u32> = (5..12).chain(0..5).collect();
    if asked != expected {
        return Err(format!("pieces were requested in the order {:?}; expected the preferred file's pieces first: {:?}", asked, expected));
    }

    // A pattern that matches nothing is a typo, and is refused up front.
    let typo_swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let typo_torrent = dir.join("typo.torrent");
    fs::write(&typo_torrent, fx.torrent_bytes(typo_swarm.tracker_addr)).expect("write torrent file");
    let refused = client_command(&typo_torrent, &dir.join("typo-out"), &dir.join("typo.log"), 1).args(["--no-dht", "--prefer", "nosuchfile"]).output().map_err(|e| format!("running the client: {}", e))?;
    let stderr = String::from_utf8_lossy(&refused.stderr);
    if refused.status.success() || !stderr.contains("matched no file") {
        return Err(format!("a --prefer that matches nothing should fail saying so; exit {:?}, stderr {:?}", refused.status.code(), stderr.trim()));
    }
    if !typo_swarm.logs[0].lock().unwrap().requested.is_empty() {
        return Err("the client asked for pieces despite refusing the flag".to_string());
    }

    Ok("--prefer b.bin requested its 7 pieces (5..11) before the other 5, and the whole torrent downloaded; a pattern matching nothing was refused before any request".to_string())
}

/// The place the file must go holds a directory, so no piece can be
/// written. With peers ready to serve, the client must not sit dialing
/// them: it stops within seconds, exits non-zero, and says the disk is
/// the problem (not "incomplete", which would blame the swarm).
fn run_disk_failure(name: &str) -> Result<String, String> {
    const LIMIT: Duration = Duration::from_secs(15);
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve, Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path, stderr_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"), dir.join("stderr.txt"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
    fs::create_dir_all(out_dir.join("e2e.bin")).map_err(|e| e.to_string())?;

    let started = Instant::now();
    let mut child = client_command(&torrent, &out_dir, &log_path, 2)
        .arg("--no-dht")
        .stdout(Stdio::null())
        .stderr(fs::File::create(&stderr_path).expect("create stderr file"))
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, LIMIT)?;
    let took = started.elapsed();

    if status.code() != Some(1) {
        return Err(format!("exit status {:?}; an unwritable disk is a failure, status 1", status.code()));
    }
    let stderr = fs::read_to_string(&stderr_path).map_err(|e| e.to_string())?;
    if !stderr.contains("cannot write to disk") || stderr.contains("incomplete:") {
        return Err(format!("stderr should blame the disk, not the swarm: {:?}", stderr.trim()));
    }
    let log = fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    if !log.contains("cannot write to disk") {
        return Err("the log does not say why the run ended".to_string());
    }
    Ok(format!("a directory in the way of the file ended the run in {:.1?} with status 1 and \"cannot write to disk\", with two peers ready to serve", took))
}

/// Empty files (`.gitkeep`, `__init__.py`) are part of a torrent but no
/// piece holds a byte of them, so nothing downloads them: the client has to
/// create them itself.
fn run_empty_files(name: &str) -> Result<String, String> {
    let files = [
        (vec!["a.bin"], pattern(600, 1)),
        (vec!["empty.txt"], Vec::new()),
        (vec!["sub", "deeper", ".gitkeep"], Vec::new()),
        (vec!["sub", "b.bin"], pattern(500, 2)),
        (vec!["zzz-empty"], Vec::new()),
    ];
    let fx = Fixture::build_paths("pack", &files, 256, false, true);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 1).arg("--no-dht").stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    // check_downloaded reads every file, the empty ones included, so a
    // missing one is an error.
    check_downloaded(&fx, &out_dir)?;
    for empty in ["pack/empty.txt", "pack/sub/deeper/.gitkeep", "pack/zzz-empty"] {
        let meta = fs::metadata(out_dir.join(empty)).map_err(|e| format!("{} was not created: {}", empty, e))?;
        if !meta.is_file() || meta.len() != 0 {
            return Err(format!("{} should be an empty file", empty));
        }
    }

    // With --only, an empty file that was not selected is not created.
    let only_swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let only_torrent = dir.join("only.torrent");
    fs::write(&only_torrent, fx.torrent_bytes(only_swarm.tracker_addr)).expect("write torrent file");
    let only_out = dir.join("only-out");
    let mut child = client_command(&only_torrent, &only_out, &dir.join("only.log"), 1).args(["--no-dht", "--only", "b.bin", "--only", "empty.txt"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("--only run exited with {:?}", status.code()));
    }
    if !only_out.join("pack/empty.txt").is_file() {
        return Err("--only selected empty.txt, which should have been created".to_string());
    }
    for unselected in ["pack/sub/deeper/.gitkeep", "pack/zzz-empty"] {
        if only_out.join(unselected).exists() {
            return Err(format!("{} was not selected but was created", unselected));
        }
    }
    Ok("three empty files (one three directories deep) exist after the download, and under --only just the selected one".to_string())
}

/// The tracker answers every announce with a redirect. Before the client
/// followed redirects, that was an error, no peer was found, and the
/// download never started.
fn run_tracker_redirect(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm_with_tracker(&fx, vec![Behavior::Serve], TrackerMode::Redirect);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let mut child = client_command(&torrent, &out_dir, &log_path, 1).arg("--no-dht").stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;

    // Every announce went first to /announce and then, redirected, to
    // /announce2, with the same event.
    let announces = swarm.announces.lock().unwrap().clone();
    if announces.is_empty() || announces.chunks(2).any(|pair| pair.len() != 2) {
        return Err(format!("expected announces in pairs, got {}: {:?}", announces.len(), announces));
    }
    for pair in announces.chunks(2) {
        let (first, second) = (&pair[0], &pair[1]);
        if !first.starts_with("GET /announce?") || !second.starts_with("GET /announce2?") || announce_param(first, "event") != announce_param(second, "event") {
            return Err(format!("an announce was not followed to its redirect: {:?} then {:?}", first, second));
        }
    }
    Ok(format!("{} announces, each redirected from /announce to /announce2 and followed, and the file matches", announces.len() / 2))
}

/// A hybrid magnet link (a v2 hash beside the v1 one) with no tracker, only
/// an `x.pe` hint naming the peer, and DHT off: the hint is the only way to
/// find anyone, and the v2 hash must not make the link unreadable.
fn run_magnet_peer_hint(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (out_dir, log_path) = (dir.join("out"), dir.join("client.log"));
    let hash = bittorrent_rs::torrent::info_hash_hex(&fx.info_hash);
    let link = format!("magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}&x.pe={}&dn=e2e.bin", hash, "ab".repeat(32), swarm.peer_addrs[0]);

    let mut child = client_command(&link, &out_dir, &log_path, 1).arg("--no-dht").stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("download binary exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;
    let log = fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    if !log.contains("names 1 peer(s) to try directly") {
        return Err("the log does not say the link's peer hint was used".to_string());
    }
    if swarm.logs[0].lock().unwrap().metadata_pieces_served == 0 {
        return Err("the peer was never asked for the metadata".to_string());
    }
    if !swarm.announces.lock().unwrap().is_empty() {
        return Err("a tracker was contacted although the link and the torrent name none".to_string());
    }
    Ok("a hybrid link with a v2 hash and only an x.pe hint fetched its metadata from that peer and downloaded the file, with no tracker involved".to_string())
}

/// A client that has finished and is seeding is also a source for the info
/// dictionary: a peer holding only a magnet link connects, asks, and gets it
/// byte for byte (checked against the harness's own copy), and is told the
/// client is a seed.
fn run_serve_metadata(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");

    let child = client_command(&torrent, &out_dir, &log_path, 1).args(["--no-dht", "--seed", "--port", "0"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    let port: u16 = swarm.announces.lock().unwrap().first().and_then(|line| announce_param(line, "port")).and_then(|p| p.parse().ok()).ok_or("no port in the client's first announce")?;

    let wire = |what: &str, e: bittorrent_rs::peer::message::WireError| format!("{}: {:?}", what, e);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connecting to the listener: {}", e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    stream.write_all(&Handshake::new(fx.info_hash, [0x55; 20], true).to_bytes()).map_err(|e| e.to_string())?;
    let mut hs_buf = [0u8; 68];
    stream.read_exact(&mut hs_buf).map_err(|e| format!("reading the handshake: {}", e))?;
    let theirs = Handshake::from_bytes(&hs_buf).map_err(|e| format!("the handshake: {:?}", e))?;
    if !theirs.supports_extensions() {
        return Err("the client does not advertise the extension protocol".to_string());
    }
    // Ask for replies under id 9, and read the client's own handshake.
    Message::Extended { id: 0, payload: ExtendedHandshake::build(9, None) }.write_to(&mut stream).map_err(|e| wire("sending our extended handshake", e))?;
    let hello = loop {
        match Message::read_from(&mut stream).map_err(|e| wire("waiting for the extended handshake", e))? {
            Message::Extended { id: 0, payload } => break ExtendedHandshake::parse(&payload).map_err(|e| format!("its extended handshake: {}", e))?,
            _ => continue,
        }
    };
    if !hello.upload_only {
        return Err("a finished client should say upload_only (BEP 21)".to_string());
    }
    if hello.metadata_size != Some(fx.info_bytes.len() as i64) {
        return Err(format!("it says the metadata is {:?} bytes; it is {}", hello.metadata_size, fx.info_bytes.len()));
    }
    let its_id = hello.peer_ut_metadata_id().ok_or("it offers no ut_metadata")?;

    Message::Extended { id: its_id, payload: MetadataMessage::Request { piece: 0 }.encode() }.write_to(&mut stream).map_err(|e| wire("asking for the metadata", e))?;
    let served = loop {
        match Message::read_from(&mut stream).map_err(|e| wire("waiting for the metadata", e))? {
            Message::Extended { id: 9, payload } => break MetadataMessage::decode(&payload).map_err(|e| format!("its reply: {}", e))?,
            _ => continue,
        }
    };
    match served {
        MetadataMessage::Data { piece: 0, total_size, data } if data == fx.info_bytes && total_size as usize == fx.info_bytes.len() => {}
        other => return Err(format!("expected the info dict as piece 0, got {:?}", other)),
    }
    Ok(format!("a peer holding only the info hash got the {}-byte info dictionary from the seeding client, byte for byte, and was told it is a seed", fx.info_bytes.len()))
}

/// Local service discovery (BEP 14). The torrent names no tracker and the DHT
/// is off, so the fake peer can be found only through a datagram from the
/// "local network" -- here the harness, writing the announcement by hand.
/// The client's own announcement, which the harness receives, must be what
/// the BEP shows: the request line, the info hash in hex, and the port the
/// client is really listening on. A neighbour announcing a different torrent
/// must not be dialed.
fn run_local_discovery(name: &str) -> Result<String, String> {
    use std::net::UdpSocket;
    let fx = Fixture::new(false);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir, log_path) = (dir.join("e2e.torrent"), dir.join("out"), dir.join("client.log"));
    // No `announce` at all.
    let mut bytes = b"d4:info".to_vec();
    bytes.extend_from_slice(&fx.info_bytes);
    bytes.push(b'e');
    fs::write(&torrent, bytes).expect("write torrent file");

    // Where the client will hear from its neighbours, and where it will announce to.
    let listens_on = {
        let probe = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        probe.local_addr().map_err(|e| e.to_string())?
    };
    let network = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    network.set_read_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
    let network_addr = network.local_addr().map_err(|e| e.to_string())?;

    let mut child = client_command(&torrent, &out_dir, &log_path, 1)
        .args(["--no-dht", "--lsd", "--timeout", "40"])
        .env("BITTORRENT_RS_LSD_LISTEN", listens_on.to_string())
        .env("BITTORRENT_RS_LSD_SEND_TO", network_addr.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;

    // Its announcement, as the network sees it.
    let mut buf = [0u8; 2048];
    let (len, _) = network.recv_from(&mut buf).map_err(|e| format!("the client announced nothing on the local network: {}", e))?;
    let heard = String::from_utf8_lossy(&buf[..len]).to_string();
    let lines: Vec<&str> = heard.split("\r\n").collect();
    let hash_hex = bittorrent_rs::torrent::info_hash_hex(&fx.info_hash);
    if lines.first() != Some(&"BT-SEARCH * HTTP/1.1") {
        let _ = child.kill();
        return Err(format!("the announcement does not begin with BEP 14's request line: {:?}", heard));
    }
    if !lines.iter().any(|l| l.eq_ignore_ascii_case(&format!("Infohash: {}", hash_hex))) {
        let _ = child.kill();
        return Err(format!("the announcement does not carry the info hash {}: {:?}", hash_hex, heard));
    }
    let announced_port: u16 = lines.iter().find_map(|l| l.strip_prefix("Port: ")).and_then(|p| p.parse().ok()).ok_or("the announcement has no Port header")?;
    if !heard.ends_with("\r\n\r\n") || !lines.iter().any(|l| l.starts_with("cookie: ")) {
        let _ = child.kill();
        return Err(format!("the announcement lacks its cookie or its blank-line ending: {:?}", heard));
    }

    // Neighbours. One has a different torrent (and nothing listening where it says).
    let decoy = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    decoy.set_nonblocking(true).map_err(|e| e.to_string())?;
    let neighbour = |port: u16, hash: &str| format!("BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: {}\r\nInfohash: {}\r\ncookie: the-harness\r\n\r\n\r\n", port, hash);
    network.send_to(neighbour(decoy.local_addr().map_err(|e| e.to_string())?.port(), &"cd".repeat(20)).as_bytes(), listens_on).map_err(|e| e.to_string())?;
    network.send_to(neighbour(swarm.peer_addrs[0].port(), &hash_hex).as_bytes(), listens_on).map_err(|e| e.to_string())?;

    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("the client exited with {:?}; its log: {}", status.code(), fs::read_to_string(&log_path).unwrap_or_default().lines().rev().take(8).collect::<Vec<_>>().join(" | ")));
    }
    check_downloaded(&fx, &out_dir)?;
    let log = fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    if !log.contains("LSD: 1 new peer address(es)") {
        return Err("the log does not say the peer came from local discovery".to_string());
    }
    if !log.contains(&format!("listening for inbound peers on port {}", announced_port)) {
        return Err(format!("it announced port {}, which is not the one it says it listens on", announced_port));
    }
    if !swarm.announces.lock().unwrap().is_empty() {
        return Err("a tracker was contacted although the torrent names none".to_string());
    }
    if decoy.accept().is_ok() {
        return Err("the client dialed a neighbour that announced a different torrent".to_string());
    }
    Ok(format!("a trackerless torrent with no DHT found its peer from a local announcement, announced itself with the right hash and port ({}), and ignored a neighbour with another torrent", announced_port))
}

/// The Fast Extension (BEP 6), both ways round.
///
/// As a downloader: the peer says `have all`, allows one piece and keeps the
/// client choked until it has been given that piece, so the download can only
/// finish if the client asks for it while choked -- and it must not ask for
/// any other piece before the unchoke. As a seeder: a peer that offers the
/// extension is told `have all` rather than sent a bitfield, is allowed the
/// pieces BEP 6 says for its address, gets one of them without ever being
/// unchoked, and has a request for another piece refused, not ignored.
fn run_fast_extension(name: &str) -> Result<String, String> {
    let fx = Fixture::new(false);
    let dir = scratch_dir(name);

    // The client downloading.
    const ALLOWED: u32 = 5;
    let swarm = spawn_swarm(&fx, vec![Behavior::Fast(BTreeSet::from([ALLOWED]))]);
    let torrent = dir.join("e2e.torrent");
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
    let out_dir = dir.join("out");
    let mut child = client_command(&torrent, &out_dir, &dir.join("client.log"), 1).arg("--no-dht").spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let status = wait_or_kill(&mut child, RUN_LIMIT)?;
    if !status.success() {
        return Err(format!("the client exited with {:?}", status.code()));
    }
    check_downloaded(&fx, &out_dir)?;
    {
        let seen = swarm.logs[0].lock().unwrap();
        if seen.fast_offered != Some(true) {
            return Err(format!("the client's handshake should offer the Fast Extension, and said {:?}", seen.fast_offered));
        }
        if seen.requested.first() != Some(&ALLOWED) {
            return Err(format!("with only piece {} allowed while choked, that should be the first asked for; the requests were {:?}", ALLOWED, seen.requested));
        }
        if seen.refused_while_choked != 0 {
            return Err(format!("the client asked for {} piece(s) the peer had not allowed while it had the client choked", seen.refused_while_choked));
        }
    }

    // The client seeding.
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let torrent = dir.join("seed.torrent");
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
    let log_path = dir.join("seed.log");
    let child = client_command(&torrent, &dir.join("seed-out"), &log_path, 1).args(["--no-dht", "--seed", "--port", "0"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    let port: u16 = swarm.announces.lock().unwrap().first().and_then(|line| announce_param(line, "port")).and_then(|p| p.parse().ok()).ok_or("no port in the client's first announce")?;

    let wire = |what: &str, e: bittorrent_rs::peer::message::WireError| format!("{}: {:?}", what, e);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connecting to the listener: {}", e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    stream.write_all(&Handshake::new(fx.info_hash, [0x58; 20], false).with_fast(true).to_bytes()).map_err(|e| e.to_string())?;
    let mut hs_buf = [0u8; 68];
    stream.read_exact(&mut hs_buf).map_err(|e| format!("reading the handshake: {}", e))?;
    if !Handshake::from_bytes(&hs_buf).map_err(|e| format!("the handshake: {:?}", e))?.supports_fast() {
        return Err("the seeding client does not offer the Fast Extension".to_string());
    }

    // Its opening: `have all`, and the allowed pieces, in whatever order, and no bitfield. Nothing else
    // need come, so read until we have both `have all` and a quiet moment.
    let (mut have_all, mut allowed) = (false, Vec::new());
    stream.set_read_timeout(Some(Duration::from_millis(700))).map_err(|e| e.to_string())?;
    loop {
        match Message::read_from(&mut stream) {
            Ok(Message::HaveAll) => have_all = true,
            Ok(Message::AllowedFast { piece_index }) => allowed.push(piece_index),
            Ok(Message::Bitfield(_)) => return Err("a fast peer should be sent have-all, not a bitfield, by a client with every piece".to_string()),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    if !have_all {
        return Err("the seeding client did not send have-all".to_string());
    }
    let mut expected = bittorrent_rs::peer::fast::allowed_fast_set(std::net::Ipv4Addr::LOCALHOST, &fx.info_hash, fx.piece_count as u32, 5);
    expected.sort_unstable();
    allowed.sort_unstable();
    if allowed != expected {
        return Err(format!("allowed fast pieces {:?}, where BEP 6's recipe for 127.0.0.1 gives {:?}", allowed, expected));
    }

    // An allowed piece, asked for without ever having said `interested`.
    let index = allowed[0] as usize;
    let (start, end) = (index * fx.piece_len, ((index + 1) * fx.piece_len).min(fx.data.len()));
    Message::Request { index: index as u32, begin: 0, length: (end - start) as u32 }.write_to(&mut stream).map_err(|e| wire("requesting an allowed piece", e))?;
    let block = loop {
        match Message::read_from(&mut stream).map_err(|e| wire("waiting for the allowed piece", e))? {
            Message::Piece { index: got, block, .. } if got as usize == index => break block,
            Message::RejectRequest { .. } => return Err("the client refused a piece it had allowed".to_string()),
            _ => continue,
        }
    };
    if block != fx.data[start..end] {
        return Err(format!("the allowed piece {} came back different from the source", index));
    }

    // One it did not allow: refused, not left unanswered.
    let other = (0..fx.piece_count as u32).find(|piece| !allowed.contains(piece)).ok_or("every piece was allowed; the fixture is too small for this check")?;
    let length = (fx.piece_len).min(fx.data.len() - other as usize * fx.piece_len) as u32;
    Message::Request { index: other, begin: 0, length }.write_to(&mut stream).map_err(|e| wire("requesting a piece not allowed", e))?;
    loop {
        match Message::read_from(&mut stream).map_err(|e| wire("waiting for the refusal", e))? {
            Message::RejectRequest { index: got, .. } if got == other => break,
            Message::Piece { .. } => return Err("a choked fast peer was sent a piece it had not been allowed".to_string()),
            _ => continue,
        }
    }

    Ok(format!("downloaded from a peer that kept it choked until the allowed piece {} was served; as a seeder said have-all, allowed {:?}, served piece {} choked and refused piece {}", ALLOWED, allowed, index, other))
}

/// `--verify` on files written by the harness itself: whole ones pass with
/// status 0; a damaged, a truncated and a missing file each fail with
/// status 1 and are named; and no tracker or peer is contacted.
fn run_verify(name: &str) -> Result<String, String> {
    let files = [(vec!["a.bin"], pattern(1500, 1)), (vec!["sub", "b.bin"], pattern(2200, 2)), (vec!["z.bin"], pattern(900, 3))];
    let fx = Fixture::build_paths("pack", &files, 1024, false, true);
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let dir = scratch_dir(name);
    let (torrent, out_dir) = (dir.join("e2e.torrent"), dir.join("out"));
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
    let write_all = || -> Result<(), String> {
        for (relative, content) in &fx.files {
            let path = out_dir.join(relative);
            fs::create_dir_all(path.parent().ok_or("no parent")?).map_err(|e| e.to_string())?;
            fs::write(&path, content).map_err(|e| format!("writing {:?}: {}", path, e))?;
        }
        Ok(())
    };
    let run = |extra: &[&str]| client_command(&torrent, &out_dir, &dir.join("client.log"), 1).arg("--no-dht").arg("--verify").args(extra).output().map_err(|e| format!("running the client: {}", e));

    // 1. Everything there and right.
    write_all()?;
    let whole = run(&[])?;
    let text = String::from_utf8_lossy(&whole.stdout).to_string();
    if !whole.status.success() || !text.contains("5 of 5 piece(s) verified") || !text.contains("3 of 3 file(s) whole") {
        return Err(format!("intact files should verify with status 0; exit {:?}, stdout {:?}, stderr {:?}", whole.status.code(), text.trim(), String::from_utf8_lossy(&whole.stderr).trim()));
    }

    // 2. One byte wrong in the middle file.
    let b_path = out_dir.join("pack/sub/b.bin");
    let mut b = fs::read(&b_path).map_err(|e| e.to_string())?;
    b[1500] ^= 0xFF;
    fs::write(&b_path, b).map_err(|e| e.to_string())?;
    let damaged = run(&[])?;
    let stderr = String::from_utf8_lossy(&damaged.stderr).to_string();
    if damaged.status.code() != Some(1) || !stderr.contains("[damaged] sub/b.bin") || stderr.contains("a.bin") || stderr.contains("z.bin") {
        return Err(format!("a damaged file should be named and nothing else, with status 1; exit {:?}, stderr {:?}", damaged.status.code(), stderr.trim()));
    }

    // 3. A file missing and one truncated.
    write_all()?;
    fs::remove_file(out_dir.join("pack/a.bin")).map_err(|e| e.to_string())?;
    fs::write(out_dir.join("pack/z.bin"), &fx.files[2].1[..100]).map_err(|e| e.to_string())?;
    let broken = run(&[])?;
    let stderr = String::from_utf8_lossy(&broken.stderr).to_string();
    if broken.status.code() != Some(1) || !stderr.contains("[missing] a.bin") || !stderr.contains("[damaged] z.bin") {
        return Err(format!("expected a.bin missing and z.bin damaged with status 1; exit {:?}, stderr {:?}", broken.status.code(), stderr.trim()));
    }

    // 4. With --only, what is not wanted is not checked. a.bin is damaged in
    // its first piece, which z.bin (the last piece) has nothing to do with.
    write_all()?;
    let a_path = out_dir.join("pack/a.bin");
    let mut a = fs::read(&a_path).map_err(|e| e.to_string())?;
    a[10] ^= 0xFF;
    fs::write(&a_path, a).map_err(|e| e.to_string())?;
    if run(&[])?.status.success() {
        return Err("a.bin is damaged, so checking everything should fail".to_string());
    }
    let only = run(&["--only", "z.bin"])?;
    if !only.status.success() {
        return Err(format!("--only z.bin should not care about a.bin; exit {:?}, stderr {:?}", only.status.code(), String::from_utf8_lossy(&only.stderr).trim()));
    }

    if !swarm.announces.lock().unwrap().is_empty() || !swarm.logs[0].lock().unwrap().requested.is_empty() {
        return Err("--verify touched the network".to_string());
    }
    Ok("intact files pass with status 0; a wrong byte, a truncated file and a missing one each fail with status 1 and are named; --only ignores the rest; no tracker or peer was contacted".to_string())
}

/// Message stream encryption through the real binary, both directions.
fn run_encryption(name: &str) -> Result<String, String> {
    use bittorrent_rs::peer::mse;
    use bittorrent_rs::peer::Encryption;
    let fx = Fixture::new(false);
    let dir = scratch_dir(name);
    let run_download = |label: &str, peer_takes: Encryption, flag: &str| -> Result<(std::process::ExitStatus, Arc<Mutex<PeerLog>>), String> {
        let swarm = spawn_swarm_full(&fx, vec![Behavior::Serve], TrackerMode::Answer, peer_takes);
        let torrent = dir.join(format!("{}.torrent", label));
        fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
        let mut child = client_command(&torrent, &dir.join(format!("{}-out", label)), &dir.join(format!("{}.log", label)), 1)
            .args(["--no-dht", "--retry-delay", "1", "--encryption", flag, "--timeout", "12"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to spawn the client: {}", e))?;
        let status = wait_or_kill(&mut child, RUN_LIMIT)?;
        Ok((status, Arc::clone(&swarm.logs[0])))
    };

    // 1. --encryption require, against a peer that does MSE: encrypted, and the file arrives.
    let (status, log) = run_download("require", Encryption::Prefer, "require")?;
    check_downloaded(&fx, &dir.join("require-out"))?;
    let seen = log.lock().unwrap();
    if !status.success() || seen.encrypted_connections == 0 || seen.plain_connections != 0 {
        return Err(format!("--encryption require: exit {:?}, {} encrypted and {} plain connections", status.code(), seen.encrypted_connections, seen.plain_connections));
    }
    drop(seen);

    // 2. --encryption prefer, against a peer that only speaks plain: falls back and finishes.
    let (status, log) = run_download("prefer", Encryption::Off, "prefer")?;
    check_downloaded(&fx, &dir.join("prefer-out"))?;
    let seen = log.lock().unwrap();
    if !status.success() || seen.plain_connections == 0 || seen.encrypted_connections != 0 {
        return Err(format!("--encryption prefer against a plain peer: exit {:?}, {} encrypted and {} plain", status.code(), seen.encrypted_connections, seen.plain_connections));
    }
    drop(seen);

    // 3. --encryption require, against a peer that only speaks plain: never falls back.
    let (status, log) = run_download("refused", Encryption::Off, "require")?;
    let seen = log.lock().unwrap();
    if status.success() || seen.plain_connections != 0 {
        return Err(format!("--encryption require must not use a plain peer: exit {:?}, {} plain connections", status.code(), seen.plain_connections));
    }
    drop(seen);

    // 4. Incoming: a client that requires encryption serves an encrypted leecher and turns a plain one away.
    let swarm = spawn_swarm(&fx, vec![Behavior::Serve]);
    let torrent = dir.join("inbound.torrent");
    fs::write(&torrent, fx.torrent_bytes(swarm.tracker_addr)).expect("write torrent file");
    let log_path = dir.join("inbound.log");
    let child = client_command(&torrent, &dir.join("inbound-out"), &log_path, 1)
        .args(["--no-dht", "--seed", "--port", "0", "--encryption", "prefer"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut client = KillOnDrop(child);
    wait_for_log(&log_path, "seeding e2e.bin on port", Duration::from_secs(20), &mut client.0)?;
    let port: u16 = swarm.announces.lock().unwrap().first().and_then(|line| announce_param(line, "port")).and_then(|p| p.parse().ok()).ok_or("no port in the client's first announce")?;

    let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    let mut stream = mse::initiate(Box::new(tcp), &fx.info_hash, false, &Handshake::new(fx.info_hash, [0x66; 20], false).to_bytes()).map_err(|e| format!("the client would not take an encrypted connection: {}", e))?;
    let mut hs = [0u8; 68];
    stream.read_exact(&mut hs).map_err(|e| format!("reading its handshake: {}", e))?;
    Message::Interested.write_to(&mut stream).map_err(|e| format!("{:?}", e))?;
    loop {
        if matches!(Message::read_from(&mut stream).map_err(|e| format!("waiting for the unchoke: {:?}", e))?, Message::Unchoke) {
            break;
        }
    }
    let piece_len = fx.piece_len.min(fx.data.len());
    Message::Request { index: 0, begin: 0, length: piece_len as u32 }.write_to(&mut stream).map_err(|e| format!("{:?}", e))?;
    let block = loop {
        if let Message::Piece { block, .. } = Message::read_from(&mut stream).map_err(|e| format!("waiting for the block: {:?}", e))? {
            break block;
        }
    };
    if block != fx.data[..piece_len] {
        return Err("the block served over the encrypted connection is wrong".to_string());
    }

    // A client set to `require` refuses plain, which the default `prefer` above did not.
    let strict_log = dir.join("strict.log");
    // Its own peer must do MSE, or the client could not download to have anything to serve.
    let strict_swarm = spawn_swarm_full(&fx, vec![Behavior::Serve], TrackerMode::Answer, Encryption::Prefer);
    let strict_torrent = dir.join("strict.torrent");
    fs::write(&strict_torrent, fx.torrent_bytes(strict_swarm.tracker_addr)).expect("write torrent file");
    let child = client_command(&strict_torrent, &dir.join("strict-out"), &strict_log, 1)
        .args(["--no-dht", "--seed", "--port", "0", "--encryption", "require"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn the client: {}", e))?;
    let mut strict = KillOnDrop(child);
    wait_for_log(&strict_log, "seeding e2e.bin on port", Duration::from_secs(20), &mut strict.0)?;
    let strict_port: u16 = strict_swarm.announces.lock().unwrap().first().and_then(|line| announce_param(line, "port")).and_then(|p| p.parse().ok()).ok_or("no port in the strict client's announce")?;
    let mut plain = TcpStream::connect(("127.0.0.1", strict_port)).map_err(|e| e.to_string())?;
    plain.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    plain.write_all(&Handshake::new(fx.info_hash, [0x66; 20], false).to_bytes()).map_err(|e| e.to_string())?;
    let mut reply = [0u8; 68];
    if plain.read_exact(&mut reply).is_ok() {
        return Err("a client set to require encryption answered a plain handshake".to_string());
    }

    Ok("require encrypted a download from an MSE peer; prefer fell back to plain for a plain-only peer; require refused it; an encrypted leecher was served by the client, and a require-client turned a plain one away".to_string())
}
