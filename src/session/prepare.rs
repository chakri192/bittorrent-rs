//! Everything between "the torrent is known" and "the download can run":
//! the file selection, resuming from disk, the listener and port mapping,
//! the first tracker announce, and the workers.

use crate::downloader::{any_data_on_disk, create_empty_files, load_and_verify, progress_file_path, rewrite_compact, scan_all, Order, ResumeWriter, WorkQueue, WorkerConfig};
use crate::ratelimit::RateLimiter;
use crate::seeder::{self, HaveMap};
use crate::session::peer_pool::RetryPolicy;
use crate::session::{Announcer, DownloadPlan, Log, Outstanding, PeerPool, Progress, ProgressSink, Services, Session, Setup, Workers};
use crate::torrent::TorrentFile;
use crate::tracker_discovery::TransferTotals;
use crate::ui::format_bytes;
use sha1::{Digest, Sha1};
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Whether to dial IPv6 peers. `Auto` probes for a local IPv6 route once
/// at startup and enables v6 only if one exists -- dialing v6 addresses
/// on a v4-only host just burns connect timeouts on guaranteed
/// `NetworkUnreachable`/`HostUnreachable` failures (the dominant failure
/// mode observed in the wild).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Mode {
    Auto,
    Always,
    Never,
}

/// Probes for outbound IPv6 connectivity without sending a single packet:
/// a UDP `connect` only resolves a route and fixes the default
/// destination. No route (v4-only host) fails immediately with
/// `NetworkUnreachable`, so this is a cheap, side-effect-free egress test.
pub fn has_ipv6_egress() -> bool {
    match UdpSocket::bind("[::]:0") {
        // 2001:4860:4860::8888 is a well-known global v6 address (Google
        // DNS); we never talk to it, only ask the kernel if it's routable.
        Ok(sock) => sock.connect("[2001:4860:4860::8888]:53").is_ok(),
        Err(_) => false,
    }
}

/// Why a BitTorrent v2 torrent that carries no piece layers is not downloaded.
pub const NO_PIECE_LAYERS: &str = "this torrent is BitTorrent v2 only (BEP 52) and does not carry its piece layers, which are what its pieces are checked against; fetching them from peers is not implemented. It can be listed (--list) and verified (--verify)";

/// How a session is set up. Everything the command line decides, and the
/// two protocol constants the workers need.
pub struct Options {
    pub out_dir: PathBuf,
    /// Preferred TCP port for the listener (an ephemeral one is used if it
    /// is taken).
    pub port: u16,
    /// Peer connections to keep going at once.
    pub max_peers: usize,
    /// `--reannounce`: a fixed announce interval.
    pub reannounce_override: Option<Duration>,
    pub ipv6: Ipv6Mode,
    pub no_portmap: bool,
    pub no_webseed: bool,
    /// Announce on the local network and listen for others (BEP 14): where
    /// to, or `None` for not at all. Never done for a private torrent.
    pub lsd: Option<crate::lsd::LsdConfig>,
    /// Give up after this long (`--timeout`).
    pub timeout: Option<Duration>,
    /// Limit on the bytes downloaded per second across every connection
    /// (`--max-down`).
    pub max_down: Option<u64>,
    /// Limit on the bytes uploaded per second across every peer
    /// (`--max-up`).
    pub max_up: Option<u64>,
    /// Check every piece against the files on disk instead of trusting the
    /// resume file (`--recheck`). This happens by itself when there is data
    /// on disk but no resume file, such as after a completed download or
    /// files copied in from elsewhere.
    pub recheck: bool,
    /// How outgoing connections are made, and whether uTP is taken on the
    /// listening side (`--transport`). A mode that wants uTP without a running
    /// uTP socket falls back to TCP, and says so.
    pub transport: crate::peer::TransportMode,
    /// Message stream encryption (`--encryption`). `None` is the default:
    /// outgoing connections are plain, incoming ones may be either.
    pub encryption: Option<crate::peer::Encryption>,
    /// Fetch pieces in order instead of rarest first (`--sequential`).
    pub sequential: bool,
    /// Files whose pieces are fetched before the others (`--prefer`), as a
    /// per-file mask; empty for none.
    pub prefer: Vec<bool>,
    /// The first delay before retrying a peer that failed; later retries
    /// wait longer (see [`RetryPolicy`]).
    pub retry_delay: Duration,
    /// Outstanding block requests per piece.
    pub pipeline_depth: usize,
    pub connect_timeout: Duration,
}

/// What the caller needs to know about a run beyond the session itself.
#[derive(Debug, Clone)]
pub struct RunInfo {
    /// Where the files are written: the output directory, plus the
    /// torrent's name when it has several files.
    pub base_dir: PathBuf,
    /// The resume sidecar, to be cleared once the download completes.
    pub progress_path: PathBuf,
    /// Only some of the files were selected.
    pub selective: bool,
    /// The torrent's true length.
    pub total_length: u64,
    /// Bytes in the wanted pieces: what the progress display counts.
    pub display_total: u64,
    /// The TCP port announced to trackers: the listener's if it started.
    pub announce_port: u16,
}

/// A session ready to run. Holds no borrow of [`Services`], so the caller
/// can keep using them around the session.
pub struct Prepared {
    queue: Arc<WorkQueue>,
    workers: Workers,
    announcer: Announcer,
    progress: Progress,
    pool: PeerPool,
    display_total: u64,
    goal_pieces: usize,
    timeout: Option<Duration>,
    pub info: RunInfo,
}

impl Prepared {
    /// Builds the session that will run the download, reporting to `sink`.
    pub fn into_session<'a>(self, sink: &'a dyn ProgressSink, services: &'a Services) -> Session<'a> {
        Session::new(Setup {
            sink,
            services,
            queue: self.queue,
            workers: self.workers,
            announcer: self.announcer,
            progress: self.progress,
            pool: self.pool,
            display_total: self.display_total,
            goal_pieces: self.goal_pieces,
            timeout: self.timeout,
        })
    }
}

/// A logging function the worker threads can share.
fn shared_log(sink: &Arc<dyn ProgressSink>) -> Log {
    let sink = Arc::clone(sink);
    Arc::new(move |m: String| sink.log(m))
}

/// Sets a download up: plans it from `mask` (which files are wanted),
/// resumes what is already on disk, starts the listener and port mapping
/// in `services`, makes the first tracker announce, and creates the
/// workers. `bootstrap_peers` are addresses already known, such as those
/// gathered while resolving a magnet link.
///
/// Fails, with a reason for the user, if the output directory or resume
/// file cannot be used, or if there is nowhere at all to get peers from.
pub fn prepare(torrent: &TorrentFile, mask: &[bool], bootstrap_peers: Vec<SocketAddr>, our_peer_id: [u8; 20], options: &Options, services: &mut Services, sink: &Arc<dyn ProgressSink>) -> Result<Prepared, String> {
    if torrent.is_v2_only() && !torrent.v2_ready() {
        return Err(NO_PIECE_LAYERS.to_string());
    }
    let total_pieces = torrent.pieces.len();
    let total_length = torrent.total_length();
    let piece_length = torrent.piece_length as u64;

    // `display_total` / `goal_pieces` drive the progress UI for the
    // selected subset. The *true* torrent length still governs on-disk
    // piece math (spans, seeder), so those stay `total_length`.
    let plan = DownloadPlan::new(torrent, mask);
    let (selective, display_total, goal_pieces) = (plan.is_selective(), plan.display_total(), plan.goal_pieces());
    if selective {
        sink.log(format!("selective download: {} of {} file(s), {} piece(s), {}", mask.iter().filter(|&&b| b).count(), torrent.files.len(), goal_pieces, format_bytes(display_total)));
    }

    let tracker_urls = torrent.tracker_urls();
    // A multi-file torrent's name is the directory its files go under,
    // however many files it lists (one is legal and common).
    let base_dir = if torrent.multi_file { options.out_dir.join(&torrent.name) } else { options.out_dir.clone() };
    let spans = Arc::new(torrent.file_spans(&base_dir));
    // Empty files are in no piece, so nothing would ever create them.
    create_empty_files(&spans, |file| mask.get(file).copied().unwrap_or(false)).map_err(|e| format!("creating an empty file under {}: {}", base_dir.display(), e))?;

    // Resume: work out which pieces are already on disk. Normally that is
    // the pieces a previous run recorded as complete, each re-verified
    // against its actual bytes before it is trusted. With no resume file
    // but data present (a finished download, whose resume file is deleted,
    // or files from elsewhere) or on request, every piece is checked.
    fs::create_dir_all(&options.out_dir).map_err(|e| format!("creating output directory {}: {}", options.out_dir.display(), e))?;
    let progress_path = progress_file_path(&options.out_dir, &torrent.info_hash);
    let full_scan = options.recheck || (!progress_path.exists() && any_data_on_disk(&spans));
    let confirmed_resumed = if full_scan {
        sink.log(format!("checking the files on disk against the torrent ({} pieces)", total_pieces));
        let mut next_report = 10;
        scan_all(&spans, torrent, |done, total| {
            // Big torrents take a while to hash; small ones do not need a running commentary.
            if total >= 20 && done * 100 / total >= next_report {
                sink.log(format!("checked {}% of the pieces", next_report));
                next_report += 10;
            }
        })
    } else {
        load_and_verify(&progress_path, &spans, torrent)
    };
    if !confirmed_resumed.is_empty() {
        sink.log(format!("resuming: {} piece(s) already verified on disk", confirmed_resumed.len()));
        rewrite_compact(&progress_path, &confirmed_resumed).map_err(|e| format!("writing resume file: {}", e))?;
    }
    let resume_writer = ResumeWriter::create(&progress_path).map_err(|e| format!("opening resume file: {}", e))?;

    // Upload side: serve verified pieces to inbound peers for the whole
    // run. A bind failure downgrades to download-only with a warning.
    let have = Arc::new(HaveMap::new(total_pieces));
    for &idx in &confirmed_resumed {
        have.set(idx);
    }
    let up_limit = options.max_up.map(|rate| Arc::new(RateLimiter::new(rate)));
    let down_limit = options.max_down.map(|rate| Arc::new(RateLimiter::new(rate)));
    // The info dictionary is offered to peers that have only a magnet link
    // (BEP 9), but only if it re-encodes to what the hash was taken over.
    let info_bytes = crate::bencode::encode(&torrent.info);
    let metadata = (Sha1::digest(&info_bytes).as_slice() == torrent.info_hash).then(|| Arc::new(info_bytes));
    let piece_lengths = (!torrent.v2_pieces.is_empty()).then(|| Arc::new(torrent.v2_pieces.iter().map(|p| p.length).collect::<Vec<u32>>()));
    let seeder_options = seeder::SeederOptions { metadata, encryption: options.encryption.unwrap_or(crate::peer::Encryption::Prefer), utp: services.utp(), piece_lengths, ..Default::default() };
    match seeder::start_with(options.port, torrent.info_hash, our_peer_id, Arc::clone(&spans), piece_length, total_length, Arc::clone(&have), up_limit, seeder_options) {
        Ok(handle) => {
            sink.log(format!("listening for inbound peers on port {}", handle.port));
            if let Some(utp) = services.utp() {
                let udp_port = utp.local_addr().map(|a| a.port()).unwrap_or(0);
                if udp_port != handle.port {
                    sink.log(format!("warning: uTP is on UDP port {} but TCP is on {}; peers will dial uTP at the port announced, so inbound uTP will not reach us", udp_port, handle.port));
                }
            }
            services.attach_seeder(handle);
        }
        Err(e) => sink.log(format!("warning: could not start listener (download-only): {}", e)),
    }
    let announce_port = services.announce_port(options.port);

    // Local service discovery announces the info hash to the whole network,
    // which a private torrent must not do; and it announces the listener's
    // port, so it needs a listener.
    if let (Some(config), false, true) = (&options.lsd, torrent.private, services.has_seeder()) {
        let log = shared_log(sink);
        services.start_lsd(config.clone(), torrent.info_hash, announce_port, move |m| log(m));
    }

    // Best-effort port forwarding (UPnP/NAT-PMP) so inbound peers and DHT
    // queries reach us behind a home router. Runs on its own thread and
    // never blocks; silently no-ops if the router doesn't cooperate.
    if !options.no_portmap {
        let log = shared_log(sink);
        services.start_portmap(move |m| log(m));
    }

    // Only wanted pieces enter the queue and the progress totals; already-
    // verified wanted pieces count as done from the start. (Resumed
    // *unwanted* pieces from a prior full run stay advertised for seeding
    // via `have` above, but don't count toward this run's goal.)
    let Outstanding { work, pieces_done, bytes_done: bytes_already_done } = plan.outstanding(torrent, &confirmed_resumed);
    let preferred = if options.prefer.iter().any(|&p| p) { crate::selection::selected_pieces_of(torrent, &options.prefer).0 } else { Default::default() };
    let queue = Arc::new(WorkQueue::new(work, total_pieces).with_order(if options.sequential { Order::Sequential } else { Order::RarestFirst }).with_preferred(preferred));

    let allow_ipv6 = match options.ipv6 {
        Ipv6Mode::Always => true,
        Ipv6Mode::Never => false,
        Ipv6Mode::Auto => has_ipv6_egress(),
    };
    sink.log(if allow_ipv6 {
        "IPv6 peers enabled".to_string()
    } else {
        format!("IPv6 peers disabled ({})", if options.ipv6 == Ipv6Mode::Never { "--no-ipv6" } else { "no local IPv6 route" })
    });
    let mut pool = PeerPool::with_policy(allow_ipv6, RetryPolicy::with_base(options.retry_delay));
    pool.add(bootstrap_peers);

    // First real announce, now that the true size is known.
    let mut announcer = Announcer::new(tracker_urls, torrent.info_hash, our_peer_id, announce_port, options.reannounce_override, Instant::now());
    let first_totals = TransferTotals { uploaded: services.uploaded_counter().map_or(0, |c| c.load(std::sync::atomic::Ordering::Relaxed)), downloaded: 0, left: display_total.saturating_sub(bytes_already_done) };
    pool.add(announcer.start(Instant::now(), first_totals, |m| sink.log(m)));

    // BEP 19 web seeds (from the torrent's url-list). These can carry the
    // whole download even with zero peers, so their presence keeps the run
    // alive.
    // Web seeds serve v1 pieces, which a v2-only torrent has none of.
    let web_seeds: Vec<String> = if options.no_webseed || torrent.is_v2_only() { Vec::new() } else { torrent.url_list.clone() };

    if pool.known_count() == 0 && services.dht().is_none() && services.lsd().is_none() && web_seeds.is_empty() {
        return Err("no peers found from any tracker (and DHT, local discovery + web seeds unavailable)".to_string());
    }
    sink.log(format!("{} peer(s) known; dialing up to {} concurrently", pool.known_count(), options.max_peers));
    if pool.skipped_ipv6() > 0 {
        sink.log(format!("skipped {} IPv6 peer(s) with no local route (pass --ipv6 to force)", pool.skipped_ipv6()));
    }

    let transport = match (options.transport.wants_utp(), services.utp()) {
        (true, Some(utp)) => crate::peer::Transport { mode: options.transport, utp: Some(utp) },
        (true, None) => {
            sink.log("uTP is not running; connections will be made over TCP".to_string());
            crate::peer::Transport::default()
        }
        (false, _) => crate::peer::Transport::default(),
    };
    let config = Arc::new(WorkerConfig { info_hash: torrent.info_hash, our_peer_id, pipeline_depth: options.pipeline_depth, connect_timeout: options.connect_timeout, down_limit, interrupt: Default::default(), peers: Default::default(), encryption: options.encryption.unwrap_or_default(), transport: transport.clone() });
    let mut workers = Workers::new(Arc::clone(&queue), Arc::clone(&spans), config, piece_length, options.max_peers, torrent.private, shared_log(sink));

    // Web-seed workers: one thread per url-list entry, draining the same
    // shared queue into the same verify-write-record pipeline as peers.
    if !web_seeds.is_empty() {
        sink.log(format!("web seed: {} url(s) from the torrent's url-list", web_seeds.len()));
        workers.start_web_seeds(&web_seeds, &torrent.name, &torrent.files, torrent.multi_file, total_length);
    }

    let progress = Progress::new(have, resume_writer, goal_pieces, pieces_done, bytes_already_done);
    Ok(Prepared { queue, workers, announcer, progress, pool, display_total, goal_pieces, timeout: options.timeout, info: RunInfo { base_dir, progress_path, selective, total_length, display_total, announce_port } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::sink::RecordingSink;
    use crate::session::testing::{dead_addr, tracker};
    use crate::torrent::parse_torrent_file;
    use sha1::{Digest, Sha1};
    use std::sync::atomic::AtomicBool;

    const PIECE_LEN: usize = 256;

    /// Two 300-byte files, `a` then `b`, in 256-byte pieces: 600 bytes, 3
    /// pieces (256 / 256 / 88). Piece 1 straddles both files.
    fn data() -> Vec<u8> {
        (0..600).map(|i| (i as u8).wrapping_mul(13)).collect()
    }

    /// The `.torrent` for `data()`, with optional extras.
    fn torrent_bytes(announce: Option<&str>, url_list: Option<&str>, private: bool) -> Vec<u8> {
        let mut b = b"d".to_vec();
        if let Some(a) = announce {
            b.extend_from_slice(format!("8:announce{}:{}", a.len(), a).as_bytes());
        }
        b.extend_from_slice(b"4:infod5:filesld6:lengthi300e4:pathl1:aeed6:lengthi300e4:pathl1:beee4:name1:t12:piece lengthi256e6:pieces60:");
        for chunk in data().chunks(PIECE_LEN) {
            b.extend_from_slice(&Sha1::digest(chunk));
        }
        if private {
            b.extend_from_slice(b"7:privatei1e");
        }
        b.push(b'e');
        if let Some(u) = url_list {
            b.extend_from_slice(format!("8:url-list{}:{}", u.len(), u).as_bytes());
        }
        b.push(b'e');
        b
    }

    fn torrent() -> TorrentFile {
        parse_torrent_file(&torrent_bytes(None, None, false)).unwrap()
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-prepare-test-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn options(out_dir: &std::path::Path) -> Options {
        Options {
            out_dir: out_dir.to_path_buf(),
            port: 0,
            max_peers: 4,
            reannounce_override: None,
            ipv6: Ipv6Mode::Never,
            no_portmap: true, // nothing here may touch the LAN gateway
            no_webseed: false,
            lsd: None,
            timeout: None,
            max_down: None,
            max_up: None,
            recheck: false,
            sequential: false,
            encryption: None,
            transport: Default::default(),
            prefer: Vec::new(),
            retry_delay: Duration::from_secs(15),
            pipeline_depth: 5,
            connect_timeout: Duration::from_secs(1),
        }
    }

    /// The sink to pass in, and the same recorder to read back.
    fn sink() -> (Arc<dyn ProgressSink>, Arc<RecordingSink>) {
        let recorder = Arc::new(RecordingSink::default());
        (recorder.clone(), recorder)
    }

    fn run_prepare(t: &TorrentFile, mask: &[bool], peers: Vec<SocketAddr>, opts: &Options, services: &mut Services) -> (Result<Prepared, String>, Arc<RecordingSink>) {
        let (sink, recorder) = sink();
        (prepare(t, mask, peers, [2; 20], opts, services, &sink), recorder)
    }

    fn sidecar(dir: &std::path::Path) -> String {
        fs::read_to_string(progress_file_path(dir, &torrent().info_hash)).unwrap_or_default()
    }

    #[test]
    fn a_fresh_prepare_queues_every_piece_and_starts_listening() {
        let dir = tmp_dir("fresh");
        let mut services = Services::new();

        let (prepared, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        let prepared = prepared.expect("one known peer is enough to start");

        assert_eq!(prepared.queue.len(), 3);
        assert!(services.has_seeder(), "the listener is up");
        assert_ne!(prepared.info.announce_port, 0);
        assert_eq!(prepared.info.announce_port, services.announce_port(0), "the port announced is the one bound");
        assert_eq!((prepared.info.total_length, prepared.info.display_total, prepared.info.selective), (600, 600, false));
        assert_eq!(prepared.info.base_dir, dir.join("t"), "several files go under the torrent's name");
        assert!(progress_file_path(&dir, &torrent().info_hash).exists(), "the resume file is open for appending");
        for line in ["listening for inbound peers on port", "IPv6 peers disabled (--no-ipv6)", "1 peer(s) known; dialing up to 4 concurrently"] {
            assert!(log.logged(line), "log lacks {:?}: {:?}", line, log.lines.lock().unwrap());
        }
    }

    #[test]
    fn a_single_file_torrent_writes_straight_into_the_output_directory() {
        let dir = tmp_dir("single");
        let single = parse_torrent_file(b"d4:infod6:lengthi10e4:name1:f12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaaee").unwrap();
        let mut services = Services::new();

        let (prepared, _) = run_prepare(&single, &[true], vec![dead_addr()], &options(&dir), &mut services);

        assert_eq!(prepared.unwrap().info.base_dir, dir);
    }

    #[test]
    fn pieces_that_verify_on_disk_are_resumed_and_the_rest_are_queued() {
        let dir = tmp_dir("resume");
        // Piece 0 is on disk (a.bin's first 256 bytes); the sidecar also
        // claims 1 and 2, which are not.
        fs::create_dir_all(dir.join("t")).unwrap();
        fs::write(dir.join("t/a"), &data()[..PIECE_LEN]).unwrap();
        fs::write(progress_file_path(&dir, &torrent().info_hash), "0\n1\n2\n").unwrap();
        let mut services = Services::new();

        let (prepared, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        let prepared = prepared.unwrap();

        assert_eq!(prepared.progress.verified(), 1, "only the piece that verified against the disk counts");
        assert_eq!(prepared.progress.bytes_done(), PIECE_LEN as u64);
        assert_eq!(prepared.queue.len(), 2);
        assert!(log.logged("resuming: 1 piece(s) already verified on disk"));
        assert_eq!(sidecar(&dir).trim(), "0", "and the sidecar is rewritten to what is actually there");
    }

    #[test]
    fn a_selective_mask_narrows_the_goal_to_the_pieces_those_files_touch() {
        let dir = tmp_dir("selective");
        let mut services = Services::new();

        let (prepared, log) = run_prepare(&torrent(), &[true, false], vec![dead_addr()], &options(&dir), &mut services);
        let prepared = prepared.unwrap();

        // File a covers bytes 0..300: pieces 0 and 1, in full, so 512 bytes.
        assert!(prepared.info.selective);
        assert_eq!((prepared.info.display_total, prepared.info.total_length), (512, 600));
        assert_eq!((prepared.goal_pieces, prepared.queue.len()), (2, 2));
        assert!(log.logged("selective download: 1 of 2 file(s), 2 piece(s), 512 B"));
    }

    #[test]
    fn with_no_peers_and_nowhere_to_look_it_fails_and_says_so() {
        let dir = tmp_dir("nopeers");
        let mut services = Services::new();
        let (result, _) = run_prepare(&torrent(), &[true, true], Vec::new(), &options(&dir), &mut services);
        assert_eq!(result.err().as_deref(), Some("no peers found from any tracker (and DHT, local discovery + web seeds unavailable)"));
    }

    #[test]
    fn a_web_seed_alone_is_enough_unless_web_seeds_are_switched_off() {
        let dir = tmp_dir("webseed");
        let with_seed = parse_torrent_file(&torrent_bytes(None, Some(&format!("http://{}/", dead_addr())), false)).unwrap();

        let mut services = Services::new();
        let (prepared, log) = run_prepare(&with_seed, &[true, true], Vec::new(), &options(&dir), &mut services);
        assert!(prepared.is_ok(), "a web seed can carry the whole download");
        assert!(log.logged("web seed: 1 url(s) from the torrent's url-list"));

        let mut off = options(&dir);
        off.no_webseed = true;
        let mut services = Services::new();
        let (result, _) = run_prepare(&with_seed, &[true, true], Vec::new(), &off, &mut services);
        assert!(result.is_err(), "--no-webseed leaves nothing to fetch from");
    }

    #[test]
    fn ipv6_peers_are_dropped_and_counted_when_ipv6_is_off_and_kept_when_it_is_forced() {
        let dir = tmp_dir("ipv6");
        let peers = vec!["10.0.0.1:6881".parse().unwrap(), "[2001:db8::1]:6881".parse().unwrap()];

        let mut services = Services::new();
        let (prepared, log) = run_prepare(&torrent(), &[true, true], peers.clone(), &options(&dir), &mut services);
        assert_eq!((prepared.unwrap().pool.known_count(), log.logged("skipped 1 IPv6 peer(s) with no local route (pass --ipv6 to force)")), (1, true));

        let mut always = options(&dir);
        always.ipv6 = Ipv6Mode::Always;
        let mut services = Services::new();
        let (prepared, log) = run_prepare(&torrent(), &[true, true], peers, &always, &mut services);
        assert_eq!(prepared.unwrap().pool.known_count(), 2);
        assert!(log.logged("IPv6 peers enabled"));
    }

    #[test]
    fn the_first_announce_reports_what_is_left_and_the_port_it_listens_on() {
        let dir = tmp_dir("announce");
        // Piece 0 is already on disk, so 600 - 256 = 344 bytes are left.
        fs::create_dir_all(dir.join("t")).unwrap();
        fs::write(dir.join("t/a"), &data()[..PIECE_LEN]).unwrap();
        fs::write(progress_file_path(&dir, &torrent().info_hash), "0\n").unwrap();
        let tracked_peer = dead_addr();
        let (url, requests) = tracker(tracked_peer);
        let t = parse_torrent_file(&torrent_bytes(Some(&url), None, false)).unwrap();
        let mut services = Services::new();

        let (prepared, _) = run_prepare(&t, &[true, true], Vec::new(), &options(&dir), &mut services);
        let prepared = prepared.expect("the tracker supplied a peer");

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].contains("event=started") && requests[0].contains("left=344&"), "{}", requests[0]);
        assert!(requests[0].contains(&format!("port={}&", prepared.info.announce_port)), "{}", requests[0]);
        assert_eq!(prepared.pool.known_count(), 1, "and the peer it returned is queued for dialing");
    }

    #[test]
    fn an_unusable_output_directory_is_an_error_naming_it() {
        let dir = tmp_dir("baddir");
        let blocker = dir.join("file");
        fs::write(&blocker, b"in the way").unwrap();
        let mut opts = options(&dir);
        opts.out_dir = blocker.join("sub"); // a directory cannot be made under a file
        let mut services = Services::new();

        let (result, _) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &opts, &mut services);

        assert!(result.err().is_some_and(|e| e.starts_with("creating output directory ")));
    }

    #[test]
    fn a_private_torrents_workers_get_no_pex_channel() {
        let dir = tmp_dir("private");
        let private = parse_torrent_file(&torrent_bytes(None, None, true)).unwrap();
        let mut services = Services::new();
        let (prepared, _) = run_prepare(&private, &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        assert!(!prepared.unwrap().workers.pex_enabled(), "BEP 27");

        let mut services = Services::new();
        let (prepared, _) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        assert!(prepared.unwrap().workers.pex_enabled());
    }

    /// Local discovery on loopback, as a test can have it.
    fn lsd_options(dir: &std::path::Path) -> Options {
        let mut with = options(dir);
        with.lsd = Some(crate::lsd::LsdConfig { send_to: SocketAddr::from(([127, 0, 0, 1], 9)), listen: SocketAddr::from(([127, 0, 0, 1], 0)), join: None, share_port: false, interval: Duration::from_secs(3600) });
        with
    }

    #[test]
    fn local_discovery_announces_the_port_the_listener_really_has() {
        let dir = tmp_dir("lsd");
        let mut services = Services::new();
        let (prepared, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &lsd_options(&dir), &mut services);
        assert!(prepared.is_ok());
        let port = services.announce_port(0);
        assert!(services.lsd().is_some());
        assert!(log.logged(&format!("local service discovery running (announcing port {})", port)), "{:?}", log.lines.lock().unwrap());
    }

    #[test]
    fn local_discovery_is_left_off_when_not_asked_for_and_for_a_private_torrent() {
        let dir = tmp_dir("lsd-off");
        let mut services = Services::new();
        run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services).0.unwrap();
        assert!(services.lsd().is_none(), "not asked for");

        let private = parse_torrent_file(&torrent_bytes(None, None, true)).unwrap();
        let mut services = Services::new();
        run_prepare(&private, &[true, true], vec![dead_addr()], &lsd_options(&dir), &mut services).0.unwrap();
        assert!(services.lsd().is_none(), "a private torrent's info hash is not shouted at the local network (BEP 27)");
    }

    #[test]
    fn local_discovery_alone_is_reason_enough_to_wait_for_peers() {
        let dir = tmp_dir("lsd-alone");
        let mut services = Services::new();
        let (prepared, _) = run_prepare(&torrent(), &[true, true], Vec::new(), &lsd_options(&dir), &mut services);
        assert!(prepared.is_ok(), "no tracker, no DHT, no address -- but the local network may yet turn one up");
    }

    #[test]
    fn with_a_utp_socket_the_listener_takes_utp_connections_too_and_warns_when_the_ports_differ() {
        let dir = tmp_dir("utp");
        let mut services = Services::new();
        services.start_utp(0, |_| {});
        let utp = services.utp().expect("running");
        let mut with_utp = options(&dir);
        with_utp.transport = crate::peer::TransportMode::Both;

        let (prepared, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &with_utp, &mut services);
        assert_eq!(prepared.unwrap().workers.transport_mode(), crate::peer::TransportMode::Both, "and the workers dial the way it says");

        // A uTP peer connects and completes the BitTorrent handshake.
        let client = crate::utp::UtpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let mut stream = client.connect(SocketAddr::from(([127, 0, 0, 1], utp.local_addr().unwrap().port())), Duration::from_secs(5)).expect("the listener takes uTP");
        crate::peer::PeerStream::set_read_timeout(&stream, Some(Duration::from_secs(5))).unwrap();
        std::io::Write::write_all(&mut stream, &crate::peer::Handshake::new(torrent().info_hash, [7; 20], false).to_bytes()).unwrap();
        let mut answer = [0u8; crate::peer::handshake::HANDSHAKE_LEN];
        std::io::Read::read_exact(&mut stream, &mut answer).unwrap();
        assert_eq!(crate::peer::Handshake::from_bytes(&answer).unwrap().info_hash, torrent().info_hash);

        // Both ports were left to be chosen, so they differ, and that is said.
        assert!(log.logged("warning: uTP is on UDP port"), "{:?}", log.lines.lock().unwrap());
    }

    #[test]
    fn a_transport_that_wants_utp_falls_back_to_tcp_when_there_is_no_socket() {
        let dir = tmp_dir("utp-missing");
        let mut services = Services::new();
        let mut wants = options(&dir);
        wants.transport = crate::peer::TransportMode::Utp;
        let (prepared, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &wants, &mut services);
        assert_eq!(prepared.unwrap().workers.transport_mode(), crate::peer::TransportMode::Tcp, "it still runs, over TCP");
        assert!(log.logged("uTP is not running; connections will be made over TCP"));

        let mut services = Services::new();
        let (_, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        assert!(!log.logged("uTP is not running"), "and says nothing when TCP was asked for");
    }

    /// A v2-only torrent of two files, made by the creator (piece length 16 KiB), with its layers or without.
    fn v2_torrent(with_layers: bool) -> TorrentFile {
        // A directory for each, since tests run side by side.
        let dir = tmp_dir(if with_layers { "v2-source-with" } else { "v2-source-without" });
        fs::create_dir_all(dir.join("t")).unwrap();
        fs::write(dir.join("t/a.bin"), vec![1u8; 40_000]).unwrap();
        fs::write(dir.join("t/empty"), b"").unwrap();
        fs::write(dir.join("t/b.bin"), vec![2u8; 100]).unwrap();
        let made = crate::create::create(&dir.join("t"), &crate::create::CreateOptions { piece_length: Some(16384), v2: true, web_seeds: vec![format!("http://{}/", dead_addr())], ..Default::default() }, |_, _| {}).unwrap();
        let mut bytes = made.bytes;
        if !with_layers {
            let mut top = crate::bencode::decode(&bytes).unwrap();
            if let crate::bencode::Bencode::Dict(entries) = &mut top {
                entries.remove(b"piece layers".as_slice());
            }
            bytes = crate::bencode::encode(&top);
        }
        parse_torrent_file(&bytes).unwrap()
    }

    #[test]
    fn a_v2_torrent_is_prepared_over_its_aligned_layout() {
        let dir = tmp_dir("v2-prepare");
        let t = v2_torrent(true);
        let mut services = Services::new();

        let (prepared, log) = run_prepare(&t, &[true, true, true], vec![dead_addr()], &options(&dir), &mut services);
        let prepared = prepared.expect("a v2 torrent with its layers can be downloaded");

        assert_eq!(prepared.goal_pieces, 4, "a.bin's three pieces and b.bin's one");
        assert_eq!(prepared.queue.len(), 4);
        assert_eq!(prepared.display_total, 40_100);
        assert!(dir.join("t/empty").exists(), "the empty file is made, as for any torrent");
        assert!(t.url_list.len() == 1 && !log.logged("web seed:"), "the torrent names a web seed, but a v2 torrent has no v1 pieces for it to serve");
    }

    #[test]
    fn a_v2_torrent_without_its_layers_is_not_prepared_and_the_reason_is_given() {
        let dir = tmp_dir("v2-prepare-bare");
        let t = v2_torrent(false);
        assert!(t.is_v2_only() && !t.v2_ready());
        let mut services = Services::new();
        let (result, _) = run_prepare(&t, &[true, true, true], vec![dead_addr()], &options(&dir), &mut services);
        assert_eq!(result.err().as_deref(), Some(NO_PIECE_LAYERS));
    }

    #[test]
    fn a_prepared_download_turns_into_a_session_that_runs() {
        let dir = tmp_dir("session");
        let mut services = Services::new();
        let (sink, recorder) = sink();
        let prepared = prepare(&torrent(), &[true, true], vec![dead_addr()], [2; 20], &options(&dir), &mut services, &sink).unwrap();

        let mut session = prepared.into_session(&*sink, &services);
        let report = session.run(&AtomicBool::new(true)); // asked to stop before it starts

        assert!(!report.complete);
        assert_eq!(report.remaining, 3);
        assert!(recorder.snapshots.lock().unwrap().iter().all(|s| s.total_length == 600));
    }

    #[test]
    fn a_multi_file_torrent_with_one_entry_still_goes_under_its_name() {
        // Deciding by the file count would write `only.bin` straight into
        // the output directory and lose the torrent's own folder.
        let mut bytes = b"d4:infod5:filesld6:lengthi300e4:pathl8:only.bineee4:name5:Album12:piece lengthi256e6:pieces40:".to_vec();
        bytes.extend_from_slice(&[0xAB; 40]);
        bytes.extend_from_slice(b"ee");
        let one_file = parse_torrent_file(&bytes).unwrap();
        assert!(one_file.multi_file && one_file.files.len() == 1);
        let dir = tmp_dir("onefile");
        let mut services = Services::new();

        let (prepared, _) = run_prepare(&one_file, &[true], vec![dead_addr()], &options(&dir), &mut services);

        assert_eq!(prepared.unwrap().info.base_dir, dir.join("Album"));
    }

    // ---- adopting data that is already on disk --------------------------

    /// The whole torrent's data, written where the download would put it.
    fn write_all_data(dir: &std::path::Path) {
        fs::create_dir_all(dir.join("t")).unwrap();
        fs::write(dir.join("t/a"), &data()[..300]).unwrap();
        fs::write(dir.join("t/b"), &data()[300..]).unwrap();
    }

    #[test]
    fn a_finished_download_run_again_is_verified_not_fetched_again() {
        // The resume file is deleted on completion, so the second run has
        // nothing to trust; it used to fetch every piece a second time.
        let dir = tmp_dir("adopt");
        write_all_data(&dir);
        let mut services = Services::new();

        let (prepared, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        let prepared = prepared.unwrap();

        assert_eq!(prepared.queue.len(), 0, "every piece checks out, so there is nothing to fetch");
        assert_eq!(prepared.progress.verified(), 3);
        assert_eq!(prepared.progress.bytes_done(), 600);
        assert!(log.logged("checking the files on disk against the torrent (3 pieces)"));
        assert!(log.logged("resuming: 3 piece(s) already verified on disk"));
        assert_eq!(sidecar(&dir).lines().count(), 3, "and the resume file is rebuilt from what was found");
    }

    #[test]
    fn a_corrupted_piece_in_existing_data_is_found_and_only_it_is_fetched() {
        let dir = tmp_dir("adopt-corrupt");
        write_all_data(&dir);
        // Piece 2 is the last 88 bytes, all in file b: damage one of them.
        let mut b = fs::read(dir.join("t/b")).unwrap();
        b[250] ^= 0xFF;
        fs::write(dir.join("t/b"), b).unwrap();
        let mut services = Services::new();

        let (prepared, _) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        let prepared = prepared.unwrap();

        assert_eq!(prepared.queue.len(), 1);
        assert_eq!(prepared.progress.verified(), 2);
        assert_eq!(prepared.progress.bytes_done(), 512);
    }

    #[test]
    fn with_a_resume_file_only_its_claims_are_checked_unless_a_recheck_is_asked_for() {
        let dir = tmp_dir("recheck");
        write_all_data(&dir);
        fs::write(progress_file_path(&dir, &torrent().info_hash), "0\n").unwrap(); // claims only piece 0

        let mut services = Services::new();
        let (trusting, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        assert_eq!(trusting.unwrap().progress.verified(), 1, "the other two are valid on disk but nobody said so");
        assert!(!log.logged("checking the files on disk"), "no full scan: a resume file exists");

        let mut recheck = options(&dir);
        recheck.recheck = true;
        let mut services = Services::new();
        let (scanning, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &recheck, &mut services);
        assert_eq!(scanning.unwrap().progress.verified(), 3, "--recheck finds them");
        assert!(log.logged("checking the files on disk"));
    }

    #[test]
    fn an_empty_output_directory_is_not_scanned_at_all() {
        let dir = tmp_dir("no-scan");
        let mut services = Services::new();
        let (prepared, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        assert_eq!(prepared.unwrap().queue.len(), 3);
        assert!(!log.logged("checking the files on disk"), "nothing to check");
    }

    #[test]
    fn a_long_scan_reports_every_ten_percent_and_a_short_one_stays_quiet() {
        // 40 pieces of 16 bytes: long enough to be worth a running commentary.
        let content: Vec<u8> = (0..640).map(|i| (i as u8).wrapping_mul(3)).collect();
        let mut bytes = b"d4:infod6:lengthi640e4:name1:f12:piece lengthi16e6:pieces800:".to_vec();
        for chunk in content.chunks(16) {
            bytes.extend_from_slice(&Sha1::digest(chunk));
        }
        bytes.extend_from_slice(b"ee");
        let long = parse_torrent_file(&bytes).unwrap();
        let dir = tmp_dir("progress-long");
        fs::write(dir.join("f"), &content).unwrap();
        let mut services = Services::new();

        let (prepared, log) = run_prepare(&long, &[true], vec![dead_addr()], &options(&dir), &mut services);

        assert_eq!(prepared.unwrap().progress.verified(), 40);
        let reports: Vec<String> = log.lines.lock().unwrap().iter().filter(|l| l.starts_with("checked ")).cloned().collect();
        assert_eq!(reports.len(), 10, "{:?}", reports);
        assert_eq!((reports.first().map(String::as_str), reports.last().map(String::as_str)), (Some("checked 10% of the pieces"), Some("checked 100% of the pieces")));

        // The 3-piece torrent used elsewhere in these tests says nothing.
        let dir = tmp_dir("progress-short");
        write_all_data(&dir);
        let mut services = Services::new();
        let (_, log) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &options(&dir), &mut services);
        assert!(!log.logged("checked "));
    }

    #[test]
    fn the_queue_is_rarest_first_unless_sequential_is_asked_for() {
        let dir = tmp_dir("sequential");
        let first_taken = |sequential: bool| {
            let mut opts = options(&dir);
            opts.sequential = sequential;
            let mut services = Services::new();
            let (prepared, _) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &opts, &mut services);
            let prepared = prepared.unwrap();
            // The swarm has been seen with pieces 0 and 1 but not 2.
            prepared.queue.note_have(0);
            prepared.queue.note_have(1);
            match prepared.queue.take_for(|_| true) {
                crate::downloader::Take::Piece(work) => work.index,
                other => panic!("expected a piece, got {:?}", other),
            }
        };

        assert_eq!(first_taken(false), 2, "rarest first: the piece nobody has been seen with");
        assert_eq!(first_taken(true), 0, "--sequential: the lowest index");
    }

    #[test]
    fn preferred_files_make_their_pieces_come_out_of_the_queue_first() {
        let dir = tmp_dir("prefer");
        let first_taken = |prefer: Vec<bool>| {
            let mut opts = options(&dir);
            opts.prefer = prefer;
            let mut services = Services::new();
            let (prepared, _) = run_prepare(&torrent(), &[true, true], vec![dead_addr()], &opts, &mut services);
            match prepared.unwrap().queue.take_for(|_| true) {
                crate::downloader::Take::Piece(work) => work.index,
                other => panic!("expected a piece, got {:?}", other),
            }
        };

        assert_eq!(first_taken(Vec::new()), 0, "no preference: the lowest index among equals");
        // The torrent's second file (bytes 256..600) is pieces 1 and 2.
        assert_eq!(first_taken(vec![false, true]), 1, "preferring it brings its first piece out ahead of piece 0");
    }
}
