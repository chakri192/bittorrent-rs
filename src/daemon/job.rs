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
        }
    }

    /// Whether the job has ended.
    pub fn is_over(&self) -> bool {
        matches!(self, JobState::Finished(_) | JobState::Failed(_) | JobState::Stopped)
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
            retry_delay: Duration::from_secs(15),
            pipeline_depth: 5,
            connect_timeout: Duration::from_secs(10),
            metadata_budget: Duration::from_secs(120),
            seed_limits: SeedLimits::default(),
        }
    }
}

/// What a job needs from the daemon around it.
pub struct JobContext {
    pub network: Arc<SharedNetwork>,
    pub peer_id: [u8; 20],
    pub defaults: JobDefaults,
    /// Told the torrent once it is known (a magnet link's arrives after a while), to keep it.
    pub on_resolved: Box<dyn Fn(&TorrentFile) + Send + Sync>,
}

/// What a job is told to do.
#[derive(Debug, Clone)]
pub struct JobSpec {
    pub info_hash: [u8; 20],
    pub source: Source,
    pub out_dir: PathBuf,
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
                    Ok(state) => shared.set_state(state),
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
    if torrent.info_hash != spec.info_hash {
        return Err(format!("the torrent's info hash is {}, not the {} it was added as", info_hash_hex(&torrent.info_hash), info_hash_hex(&spec.info_hash)));
    }
    (context.on_resolved)(&torrent);
    *lock(&shared.name) = torrent.name.clone();
    sink.log(format!("torrent: {} ({}, {} pieces)", torrent.name, crate::ui::format_bytes(torrent.total_length()), torrent.pieces.len()));
    if torrent.private {
        sink.log("private torrent (BEP 27): DHT and peer exchange disabled, peers come from the tracker only".to_string());
    }

    shared.set_state(JobState::Checking);
    let options = Options {
        out_dir: spec.out_dir.clone(),
        port: context.network.port,
        max_peers: defaults.max_peers,
        reannounce_override: None,
        ipv6: defaults.ipv6,
        no_portmap: true, // the network has done it
        no_webseed: defaults.no_webseed,
        lsd: defaults.lsd.clone(),
        timeout: None,
        max_down: None, // the network's limits apply
        max_up: None,
        recheck: false,
        transport: defaults.transport,
        encryption: defaults.encryption,
        sequential: false,
        prefer: Vec::new(),
        retry_delay: defaults.retry_delay,
        pipeline_depth: defaults.pipeline_depth,
        connect_timeout: defaults.connect_timeout,
    };
    let mask = vec![true; torrent.files.len()];
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
