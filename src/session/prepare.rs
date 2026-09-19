//! Everything between "the torrent is known" and "the download can run":
//! the file selection, resuming from disk, the listener and port mapping,
//! the first tracker announce, and the workers.

use crate::downloader::{any_data_on_disk, build_file_spans, load_and_verify, progress_file_path, rewrite_compact, scan_all, ResumeWriter, WorkQueue, WorkerConfig};
use crate::ratelimit::RateLimiter;
use crate::seeder::{self, HaveMap};
use crate::session::peer_pool::RetryPolicy;
use crate::session::{Announcer, DownloadPlan, Log, Outstanding, PeerPool, Progress, ProgressSink, Services, Session, Setup, Workers};
use crate::torrent::TorrentFile;
use crate::tracker_discovery::TransferTotals;
use crate::ui::format_bytes;
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
    let spans = Arc::new(build_file_spans(&base_dir, &torrent.files));

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
    match seeder::start(options.port, torrent.info_hash, our_peer_id, Arc::clone(&spans), piece_length, total_length, Arc::clone(&have), up_limit) {
        Ok(handle) => {
            sink.log(format!("listening for inbound peers on port {}", handle.port));
            services.attach_seeder(handle);
        }
        Err(e) => sink.log(format!("warning: could not start listener (download-only): {}", e)),
    }
    let announce_port = services.announce_port(options.port);

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
    let queue = Arc::new(WorkQueue::new(work, total_pieces));

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
    let web_seeds: Vec<String> = if options.no_webseed { Vec::new() } else { torrent.url_list.clone() };

    if pool.known_count() == 0 && services.dht().is_none() && web_seeds.is_empty() {
        return Err("no peers found from any tracker (and DHT + web seeds unavailable)".to_string());
    }
    sink.log(format!("{} peer(s) known; dialing up to {} concurrently", pool.known_count(), options.max_peers));
    if pool.skipped_ipv6() > 0 {
        sink.log(format!("skipped {} IPv6 peer(s) with no local route (pass --ipv6 to force)", pool.skipped_ipv6()));
    }

    let config = Arc::new(WorkerConfig { info_hash: torrent.info_hash, our_peer_id, pipeline_depth: options.pipeline_depth, connect_timeout: options.connect_timeout, down_limit });
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
            timeout: None,
            max_down: None,
            max_up: None,
            recheck: false,
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
        assert_eq!(result.err().as_deref(), Some("no peers found from any tracker (and DHT + web seeds unavailable)"));
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
}
