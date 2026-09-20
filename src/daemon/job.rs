//! One torrent of the daemon, from where it comes from to seeding it, on a thread of its own.
//! Every job runs on the daemon's [`SharedNetwork`]: the port, the DHT node, the uTP socket and
//! the rate limits are everyone's.

use crate::lsd::LsdConfig;
use crate::magnet::parse_magnet_uri;
use crate::peer::{Encryption, Transport, TransportMode};
use crate::session::{prepare, resolve_magnet, Ipv6Mode, MetadataConfig, Options, ProgressSink, SeedLimits, Services, SharedNetwork};
use crate::sync::lock;
use crate::torrent::{self, info_hash_hex, TorrentFile};
use crate::ui::Snapshot;
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// How many of a job's latest log lines are kept, to show what it has been doing.
const LOG_LINES: usize = 50;

/// Where a torrent comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A magnet link: the torrent is fetched from peers first.
    Magnet(String),
    /// A `.torrent` file.
    File(PathBuf),
}

/// Where a job has got to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    /// Waiting for the torrent's metadata, from a magnet link.
    Resolving,
    /// Checking what is already on disk, and starting up.
    Checking,
    Downloading,
    Seeding,
    /// Was seeding until a limit (ratio, time) was reached: which one.
    Finished(String),
    /// Ended, and why.
    Failed(String),
    /// Ended by being asked to.
    Stopped,
    /// Set aside to be started again: nothing runs, and nothing is served, until it is resumed.
    Paused,
}

impl JobState {
    /// One word for it.
    pub fn name(&self) -> &'static str {
        match self {
            JobState::Resolving => "resolving",
            JobState::Checking => "checking",
            JobState::Downloading => "downloading",
            JobState::Seeding => "seeding",
            JobState::Finished(_) => "finished",
            JobState::Failed(_) => "failed",
            JobState::Stopped => "stopped",
            JobState::Paused => "paused",
        }
    }

    /// Whether nothing is running for the job any more.
    pub fn is_over(&self) -> bool {
        matches!(self, JobState::Finished(_) | JobState::Failed(_) | JobState::Stopped | JobState::Paused)
    }
}

/// How every job is run: what the daemon's command line decides, for all of them.
#[derive(Debug, Clone)]
pub struct JobDefaults {
    pub max_peers: usize,
    pub ipv6: Ipv6Mode,
    pub no_webseed: bool,
    /// Where local discovery goes, or `None` for not at all.
    pub lsd: Option<LsdConfig>,
    pub encryption: Option<Encryption>,
    pub transport: TransportMode,
    pub tracker_mode: crate::tracker_discovery::TrackerMode,
    pub retry_delay: Duration,
    pub pipeline_depth: usize,
    pub connect_timeout: Duration,
    /// How long a magnet link is given to find its metadata.
    pub metadata_budget: Duration,
    /// When to stop seeding a torrent; without a limit it is seeded until removed.
    pub seed_limits: SeedLimits,
}

impl Default for JobDefaults {
    fn default() -> Self {
        JobDefaults {
            max_peers: 30,
            ipv6: Ipv6Mode::Auto,
            no_webseed: false,
            lsd: Some(LsdConfig::multicast()),
            encryption: None,
            transport: TransportMode::Tcp,
            tracker_mode: Default::default(),
            retry_delay: Duration::from_secs(15),
            pipeline_depth: 5,
            connect_timeout: Duration::from_secs(10),
            metadata_budget: Duration::from_secs(120),
            seed_limits: SeedLimits::default(),
        }
    }
}

/// What is asked of one torrent beyond where it goes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobOptions {
    /// Only the files with these numbers, counted from 1 as `--list` shows them, and those `only` matches;
    /// all of them if neither says. A magnet link's `so` (BEP 53) is put here when the link is added.
    pub files: Vec<usize>,
    /// Only the files whose path contains one of these (case-insensitive); all of them if empty.
    pub only: Vec<String>,
    /// Files whose pieces are fetched before the others.
    pub prefer: Vec<String>,
    /// Fetch pieces in order instead of rarest first.
    pub sequential: bool,
    /// This torrent's own limits, which hold as well as the daemon's (bytes per second).
    pub max_up: Option<u64>,
    pub max_down: Option<u64>,
}

/// What a job tells the daemon around it when it has finished, and why.
pub type FinishedHook = Box<dyn Fn(&[u8; 20], &str) + Send + Sync>;

/// What a job needs from the daemon around it.
pub struct JobContext {
    pub network: Arc<SharedNetwork>,
    pub peer_id: [u8; 20],
    pub defaults: JobDefaults,
    /// Told the torrent once it is known (a magnet link's arrives after a while), to keep it.
    pub on_resolved: Box<dyn Fn(&TorrentFile) + Send + Sync>,
    /// Told when a torrent has been seeded up to a limit, and why, to keep that.
    pub on_finished: FinishedHook,
}

/// What a job is told to do.
#[derive(Debug, Clone)]
pub struct JobSpec {
    pub info_hash: [u8; 20],
    pub source: Source,
    pub out_dir: PathBuf,
    pub options: JobOptions,
}

/// What can be seen of a job at any moment.
#[derive(Debug, Clone)]
pub struct JobStatus {
    pub info_hash: [u8; 20],
    /// The torrent's name; the info hash until it is known.
    pub name: String,
    pub state: JobState,
    pub out_dir: PathBuf,
    pub snapshot: Snapshot,
    /// The latest of what the job logged.
    pub log: Vec<String>,
}

impl JobStatus {
    /// Fraction done, 0 to 1.
    pub fn progress(&self) -> f64 {
        match self.state {
            JobState::Seeding | JobState::Finished(_) => 1.0,
            _ => self.snapshot.fraction(),
        }
    }
}

/// The part of a job that its thread and everyone watching it share; and what the session reports to.
struct JobShared {
    name: Mutex<String>,
    state: Mutex<JobState>,
    snapshot: Mutex<Snapshot>,
    log: Mutex<VecDeque<String>>,
    stop: AtomicBool,
}

impl JobShared {
    fn set_state(&self, state: JobState) {
        *lock(&self.state) = state;
    }
}

impl ProgressSink for JobShared {
    fn log(&self, msg: String) {
        let mut log = lock(&self.log);
        if log.len() == LOG_LINES {
            log.pop_front();
        }
        log.push_back(msg);
    }

    fn set_snapshot(&self, snapshot: Snapshot) {
        *lock(&self.snapshot) = snapshot;
    }

    fn push_rates(&self, _down: u64, _up: u64) {}

    fn set_pieces(&self, _have: Vec<bool>) {}
}

/// A torrent being downloaded and then seeded.
pub struct Job {
    spec: JobSpec,
    shared: Arc<JobShared>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl Job {
    /// Starts the job on a thread of its own.
    pub fn start(spec: JobSpec, context: Arc<JobContext>) -> Job {
        let shared = Arc::new(JobShared { name: Mutex::new(info_hash_hex(&spec.info_hash)), state: Mutex::new(JobState::Checking), snapshot: Mutex::new(Snapshot::default()), log: Mutex::new(VecDeque::new()), stop: AtomicBool::new(false) });
        let thread = {
            let (shared, spec) = (Arc::clone(&shared), spec.clone());
            thread::spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&shared, &spec, &context)));
                let end = outcome.unwrap_or_else(|_| Err("internal error".to_string()));
                match end {
                    Ok(state) => {
                        shared.set_state(state.clone());
                        if let JobState::Finished(reason) = &state {
                            (context.on_finished)(&spec.info_hash, reason);
                        }
                    }
                    // Whatever came of being told to stop -- a magnet link that was not resolved, say -- is not a failure.
                    Err(_) if shared.stop.load(Ordering::SeqCst) => shared.set_state(JobState::Stopped),
                    Err(reason) => {
                        shared.log(format!("failed: {}", reason));
                        shared.set_state(JobState::Failed(reason));
                    }
                }
            })
        };
        Job { spec, shared, thread: Mutex::new(Some(thread)) }
    }

    /// A job with nothing running, in `state` (paused, or finished): what there is to show of a
    /// torrent that is not being worked on. It is started by making a new [`Job::start`].
    pub fn dormant(spec: JobSpec, state: JobState) -> Job {
        // Its name and size, if they are to be had without asking anyone.
        let (name, size) = match &spec.source {
            Source::File(path) => fs::read(path).ok().and_then(|bytes| torrent::parse_torrent_file(&bytes).ok()).map(|t| (Some(t.name.clone()), t.total_length())).unwrap_or((None, 0)),
            Source::Magnet(uri) => (parse_magnet_uri(uri).ok().and_then(|m| m.display_name), 0),
        };
        let shared = Arc::new(JobShared {
            name: Mutex::new(name.unwrap_or_else(|| info_hash_hex(&spec.info_hash))),
            state: Mutex::new(state),
            snapshot: Mutex::new(Snapshot { total_length: size, ..Default::default() }),
            log: Mutex::new(VecDeque::new()),
            stop: AtomicBool::new(true),
        });
        Job { spec, shared, thread: Mutex::new(None) }
    }

    pub fn spec(&self) -> &JobSpec {
        &self.spec
    }

    pub fn info_hash(&self) -> [u8; 20] {
        self.spec.info_hash
    }

    pub fn status(&self) -> JobStatus {
        JobStatus {
            info_hash: self.spec.info_hash,
            name: lock(&self.shared.name).clone(),
            state: lock(&self.shared.state).clone(),
            out_dir: self.spec.out_dir.clone(),
            snapshot: lock(&self.shared.snapshot).clone(),
            log: lock(&self.shared.log).iter().cloned().collect(),
        }
    }

    /// Tells the job to end, without waiting for it to.
    pub fn signal_stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }

    /// Ends the job and waits for it to be over: its peers let go, its place on the shared port
    /// given up, the trackers told. What was downloaded stays on disk.
    pub fn stop(&self) {
        self.signal_stop();
        if let Some(thread) = lock(&self.thread).take() {
            let _ = thread.join();
        }
    }
}

/// The job, from start to end. `Err` is a reason it failed; `Ok` how it ended otherwise.
fn run(shared: &Arc<JobShared>, spec: &JobSpec, context: &JobContext) -> Result<JobState, String> {
    let stop = &shared.stop;
    let sink: Arc<dyn ProgressSink> = shared.clone();
    let defaults = &context.defaults;
    // Dropping this, on any way out, takes the torrent off the shared port and the DHT.
    let mut services = Services::shared(Arc::clone(&context.network));

    let (torrent, bootstrap_peers) = match &spec.source {
        Source::Magnet(uri) => {
            let magnet = parse_magnet_uri(uri).map_err(|e| format!("parsing the magnet link: {}", e))?;
            shared.set_state(JobState::Resolving);
            if let Some(name) = &magnet.display_name {
                *lock(&shared.name) = name.clone();
            }
            services.start_dht(0, magnet.info_hash, false, Vec::new(), |m| sink.log(m));
            if magnet.trackers.is_empty() && magnet.peers.is_empty() && services.dht().is_none() {
                return Err("the magnet link has no trackers or peers, and there is no DHT: no way to find any peer".to_string());
            }
            let transport = Transport { mode: if services.utp().is_some() { defaults.transport } else { TransportMode::Tcp }, utp: services.utp() };
            let metadata = MetadataConfig { budget: defaults.metadata_budget, parallelism: 20, connect_timeout: defaults.connect_timeout, encryption: defaults.encryption.unwrap_or_default(), transport };
            let (torrent, peers) = resolve_magnet(&magnet, context.peer_id, context.network.port, services.dht(), &metadata, &*sink, stop)?;
            // The DHT was needed to find the metadata, which is what says whether the torrent is private.
            if torrent.private {
                services.stop_dht();
            }
            (torrent, peers)
        }
        Source::File(path) => {
            let bytes = fs::read(path).map_err(|e| format!("reading {}: {}", path.display(), e))?;
            let torrent = torrent::parse_torrent_file(&bytes).map_err(|e| format!("parsing {}: {}", path.display(), e))?;
            if !torrent.private {
                services.start_dht(0, torrent.info_hash, false, Vec::new(), |m| sink.log(m));
            }
            (torrent, Vec::new())
        }
    };
    if stop.load(Ordering::SeqCst) {
        return Ok(JobState::Stopped);
    }
    let mut torrent = torrent;
    if torrent.info_hash != spec.info_hash {
        return Err(format!("the torrent's info hash is {}, not the {} it was added as", info_hash_hex(&torrent.info_hash), info_hash_hex(&spec.info_hash)));
    }
    // A v2 torrent that lacks its piece layers (a magnet link's does) gets them from peers before it is kept or run.
    if torrent.is_v2_only() && !torrent.v2_ready() {
        let transport = Transport { mode: if services.utp().is_some() { defaults.transport } else { TransportMode::Tcp }, utp: services.utp() };
        let config = crate::session::layers::LayerConfig { our_peer_id: context.peer_id, timeout: defaults.connect_timeout, encryption: defaults.encryption.unwrap_or_default(), transport };
        let discovery = crate::session::layers::Discovery { bootstrap: bootstrap_peers.clone(), dht: services.dht(), trackers: torrent.tracker_tiers(), announce_port: context.network.port };
        crate::session::layers::complete_torrent(&mut torrent, discovery, &config, crate::session::layers::LAYER_BUDGET, stop, &|m| sink.log(m))?;
    }
    (context.on_resolved)(&torrent);
    *lock(&shared.name) = torrent.name.clone();
    sink.log(format!("torrent: {} ({}, {} pieces)", torrent.name, crate::ui::format_bytes(torrent.total_length()), torrent.pieces.len()));
    if torrent.private {
        sink.log("private torrent (BEP 27): DHT and peer exchange disabled, peers come from the tracker only".to_string());
    }

    shared.set_state(JobState::Checking);
    let (options, mask) = session_options(spec, &torrent, defaults, context.network.port)?;
    let prepared = prepare(&torrent, &mask, bootstrap_peers, context.peer_id, &options, &mut services, &sink)?;
    let info = prepared.info.clone();
    let mut session = prepared.into_session(&*sink, &services);

    shared.set_state(JobState::Downloading);
    let report = session.run(stop);
    let end = if report.complete {
        crate::downloader::resume::clear(&info.progress_path);
        session.announce_completed();
        sink.log("download complete".to_string());
        shared.set_state(JobState::Seeding);
        let ended = session.seed(&torrent.name, info.announce_port, stop, defaults.seed_limits);
        Ok(ended.map_or(JobState::Stopped, |limit| JobState::Finished(limit.to_string())))
    } else if let Some(why) = &report.aborted {
        Err(format!("cannot write to disk: {} -- {} piece(s) not downloaded", why, report.remaining))
    } else if stop.load(Ordering::SeqCst) {
        Ok(JobState::Stopped)
    } else {
        Err(format!("incomplete: {} piece(s) never downloaded ({} peer(s) dialed)", report.remaining, report.dialed))
    };
    session.announce_stopped();
    services.shutdown();
    end
}

/// How the session for `spec` is set up, and which of the torrent's files it is to fetch. The
/// daemon's network does the port mapping and holds the daemon-wide limits; what is the torrent's
/// own comes from `spec`.
fn session_options(spec: &JobSpec, torrent: &TorrentFile, defaults: &JobDefaults, port: u16) -> Result<(Options, Vec<bool>), String> {
    let mask = crate::selection::build_mask_for(torrent, &spec.options.files, &spec.options.only)?;
    let prefer = if spec.options.prefer.is_empty() { Vec::new() } else { crate::selection::build_prefer_mask_for(torrent, &spec.options.prefer)? };
    let options = Options {
        out_dir: spec.out_dir.clone(),
        port,
        max_peers: defaults.max_peers,
        reannounce_override: None,
        ipv6: defaults.ipv6,
        no_portmap: true, // the network has done it
        no_webseed: defaults.no_webseed,
        lsd: defaults.lsd.clone(),
        timeout: None,
        max_down: spec.options.max_down, // as well as the network's
        max_up: spec.options.max_up,
        recheck: false,
        transport: defaults.transport,
        tracker_mode: defaults.tracker_mode,
        encryption: defaults.encryption,
        sequential: spec.options.sequential,
        prefer,
        retry_delay: defaults.retry_delay,
        pipeline_depth: defaults.pipeline_depth,
        connect_timeout: defaults.connect_timeout,
    };
    Ok((options, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn torrent() -> TorrentFile {
        // Two files of 100 bytes each, in pieces of 64.
        let mut bytes = b"d4:infod5:filesld6:lengthi100e4:pathl5:a.mkveed6:lengthi100e4:pathl5:b.nfoeee4:name3:dir12:piece lengthi64e6:pieces80:".to_vec();
        bytes.extend_from_slice(&[7u8; 80]);
        bytes.extend_from_slice(b"ee");
        torrent::parse_torrent_file(&bytes).unwrap()
    }

    fn spec(options: JobOptions) -> JobSpec {
        JobSpec { info_hash: [1; 20], source: Source::Magnet("m".into()), out_dir: PathBuf::from("/out"), options }
    }

    #[test]
    fn a_torrent_with_no_options_is_fetched_whole_with_the_daemons_defaults() {
        let defaults = JobDefaults { max_peers: 12, no_webseed: true, ipv6: Ipv6Mode::Never, ..Default::default() };
        let (options, mask) = session_options(&spec(JobOptions::default()), &torrent(), &defaults, 6999).unwrap();
        assert_eq!(mask, vec![true, true]);
        assert_eq!((options.port, options.max_peers, options.no_webseed, options.ipv6, options.out_dir), (6999, 12, true, Ipv6Mode::Never, PathBuf::from("/out")));
        assert!(options.no_portmap, "the network maps the ports");
        assert_eq!((options.max_up, options.max_down, options.sequential, options.prefer), (None, None, false, Vec::new()));
    }

    #[test]
    fn a_torrents_own_options_reach_its_session() {
        let own = JobOptions { files: Vec::new(), only: vec![".MKV".into()], prefer: vec!["nfo".into()], sequential: true, max_up: Some(10), max_down: Some(20) };
        let (options, mask) = session_options(&spec(own), &torrent(), &JobDefaults::default(), 1).unwrap();
        assert_eq!(mask, vec![true, false], "only the file that matches, whatever the case");
        assert_eq!(options.prefer, vec![false, true]);
        assert_eq!((options.sequential, options.max_up, options.max_down), (true, Some(10), Some(20)));
    }

    #[test]
    fn file_numbers_select_files_as_list_numbers_them_and_add_to_what_the_patterns_match() {
        let numbered = JobOptions { files: vec![2], ..Default::default() };
        assert_eq!(session_options(&spec(numbered), &torrent(), &JobDefaults::default(), 1).unwrap().1, vec![false, true]);
        let both = JobOptions { files: vec![2], only: vec!["mkv".into()], ..Default::default() };
        assert_eq!(session_options(&spec(both), &torrent(), &JobDefaults::default(), 1).unwrap().1, vec![true, true]);
        let past_the_end = JobOptions { files: vec![3], ..Default::default() };
        assert!(session_options(&spec(past_the_end), &torrent(), &JobDefaults::default(), 1).is_err(), "there are two files");
    }

    #[test]
    fn a_pattern_that_matches_no_file_is_refused() {
        let only = JobOptions { only: vec!["nothing".into()], ..Default::default() };
        assert!(session_options(&spec(only), &torrent(), &JobDefaults::default(), 1).is_err());
        let prefer = JobOptions { prefer: vec!["nothing".into()], ..Default::default() };
        assert!(session_options(&spec(prefer), &torrent(), &JobDefaults::default(), 1).is_err());
    }

    #[test]
    fn a_dormant_job_shows_what_is_known_of_the_torrent_and_runs_nothing() {
        let job = Job::dormant(spec(JobOptions::default()), JobState::Paused);
        let status = job.status();
        assert_eq!((status.state, status.name.len()), (JobState::Paused, 40), "named by its hash while nothing else is known");
        job.stop(); // there is no thread to wait for
        job.stop();

        let magnet = JobSpec { source: Source::Magnet("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Some%20Name".into()), ..spec(JobOptions::default()) };
        assert_eq!(Job::dormant(magnet, JobState::Paused).status().name, "Some Name");

        let dir = std::env::temp_dir().join(format!("bt-dormant-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut bytes = b"d4:infod5:filesld6:lengthi100e4:pathl5:a.mkveed6:lengthi100e4:pathl5:b.nfoeee4:name3:dir12:piece lengthi64e6:pieces80:".to_vec();
        bytes.extend_from_slice(&[7u8; 80]);
        bytes.extend_from_slice(b"ee");
        std::fs::write(dir.join("t.torrent"), &bytes).unwrap();
        let from_file = JobSpec { source: Source::File(dir.join("t.torrent")), ..spec(JobOptions::default()) };
        let status = Job::dormant(from_file, JobState::Finished("done".into())).status();
        assert_eq!((status.name.as_str(), status.snapshot.total_length), ("dir", 200), "name and size from the kept file");
    }

    #[test]
    fn only_a_job_that_has_nothing_running_is_over() {
        for over in [JobState::Finished("r".into()), JobState::Failed("r".into()), JobState::Stopped, JobState::Paused] {
            assert!(over.is_over(), "{:?}", over);
        }
        for running in [JobState::Resolving, JobState::Checking, JobState::Downloading, JobState::Seeding] {
            assert!(!running.is_over(), "{:?}", running);
        }
        assert_eq!(JobState::Paused.name(), "paused");
    }
}
