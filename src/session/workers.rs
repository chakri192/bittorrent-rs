//! The threads that fetch pieces: one per connected peer, one per web
//! seed, all draining the same work queue.

use crate::downloader::{run_worker, FileSpan, PexSender, PieceResult, WorkQueue, WorkerConfig, WorkerError};
use crate::session::peer_pool::Outcome;
use crate::session::PeerPool;
use crate::sync::lock;
use crate::webseed::{run_web_worker, WebEnd};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Where the workers' progress and failure messages go. Shared by every
/// worker thread, hence the `Arc`.
pub type Log = Arc<dyn Fn(String) + Send + Sync>;

/// How a worker's run against one peer ended, in the pool's terms.
pub fn classify(result: &Result<(), WorkerError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Finished,
        Err(WorkerError::PieceHashMismatch) => Outcome::BadData,
        Err(WorkerError::Connection { stage: "connect_and_handshake", .. }) => Outcome::Unreachable,
        // Our disk failed; the peer did nothing wrong.
        Err(WorkerError::Connection { stage: "write_piece_to_disk", .. }) => Outcome::Local,
        Err(WorkerError::Connection { .. }) => Outcome::Dropped,
    }
}

/// The running download workers and the channels they report on.
pub struct Workers {
    queue: Arc<WorkQueue>,
    spans: Arc<Vec<FileSpan>>,
    config: Arc<WorkerConfig>,
    piece_length: u64,
    max_peers: usize,
    log: Log,
    results_tx: Sender<PieceResult>,
    results_rx: Receiver<PieceResult>,
    /// Handed to each peer worker so it can report addresses it learns
    /// through peer exchange. `None` for a private torrent (BEP 27): a
    /// worker with no channel neither advertises `ut_pex` nor forwards
    /// what it hears.
    pex_tx: Option<PexSender>,
    pex_rx: Receiver<Vec<SocketAddr>>,
    /// How each peer worker's run ended, for the pool to act on.
    outcomes_tx: Sender<(SocketAddr, Outcome)>,
    outcomes_rx: Receiver<(SocketAddr, Outcome)>,
    peers: Vec<JoinHandle<()>>,
    web_seeds: Vec<JoinHandle<()>>,
    web_stop: Arc<AtomicBool>,
    /// Why writing to disk failed, once it has: with nothing to write to,
    /// no peer can help, and the run cannot go on.
    disk_failure: Arc<Mutex<Option<String>>>,
}

impl Workers {
    /// The limit the downloads are held to, for tests to see whose it is.
    #[cfg(test)]
    pub(crate) fn down_limit(&self) -> Option<Arc<crate::ratelimit::RateLimiter>> {
        self.config.down_limit.clone()
    }

    /// A worker set that will keep at most `max_peers` peer connections
    /// going. Nothing runs until [`spawn_peers`](Self::spawn_peers) or
    /// [`start_web_seeds`](Self::start_web_seeds).
    pub fn new(queue: Arc<WorkQueue>, spans: Arc<Vec<FileSpan>>, config: Arc<WorkerConfig>, piece_length: u64, max_peers: usize, private: bool, log: Log) -> Self {
        let (results_tx, results_rx) = mpsc::channel();
        let (pex_tx, pex_rx) = mpsc::channel();
        let (outcomes_tx, outcomes_rx) = mpsc::channel();
        Workers { queue, spans, config, piece_length, max_peers, log, results_tx, results_rx, pex_tx: (!private).then_some(pex_tx), pex_rx, outcomes_tx, outcomes_rx, peers: Vec::new(), web_seeds: Vec::new(), web_stop: Arc::new(AtomicBool::new(false)), disk_failure: Arc::new(Mutex::new(None)) }
    }

    /// Starts one worker per BEP 19 web seed, each dialing nobody: they
    /// fetch ranges over HTTP into the same queue.
    pub fn start_web_seeds(&mut self, urls: &[String], name: &str, files: &[(Vec<String>, i64)], multi_file: bool, total_length: u64) {
        let files = Arc::new(files.to_vec());
        for url in urls {
            let (url, name, files) = (url.clone(), name.to_string(), Arc::clone(&files));
            let (queue, spans, tx, stop, log) = (Arc::clone(&self.queue), Arc::clone(&self.spans), self.results_tx.clone(), Arc::clone(&self.web_stop), Arc::clone(&self.log));
            let limiter = self.config.down_limit.clone();
            let piece_length = self.piece_length;
            let disk_failure = Arc::clone(&self.disk_failure);
            self.web_seeds.push(thread::spawn(move || {
                let end = run_web_worker(&url, &name, &files, multi_file, limiter.as_deref(), &queue, &spans, piece_length, total_length, &tx, &stop, move |m| log(m));
                if let WebEnd::DiskFailed(why) = end {
                    lock(&disk_failure).get_or_insert(why);
                }
            }));
        }
    }

    /// Dials peers from `pool` (as of `now`, which decides whether a
    /// waiting retry is due) until `max_peers` are connected or there is
    /// nothing left to dial or fetch.
    pub fn spawn_peers(&mut self, pool: &mut PeerPool, now: Instant) {
        while self.peers.len() < self.max_peers && !self.queue.is_empty() {
            let Some(addr) = pool.next_to_dial(now) else { break };
            let (queue, spans, config) = (Arc::clone(&self.queue), Arc::clone(&self.spans), Arc::clone(&self.config));
            let (tx, pex_tx, log) = (self.results_tx.clone(), self.pex_tx.clone(), Arc::clone(&self.log));
            let outcomes = self.outcomes_tx.clone();
            let disk_failure = Arc::clone(&self.disk_failure);
            let piece_length = self.piece_length;
            self.peers.push(thread::spawn(move || {
                let result = run_worker(addr, &config, &queue, &spans, piece_length, &tx, pex_tx.as_ref());
                if let Err(e) = &result {
                    log(format!("peer {} disconnected: {:?}", addr, e));
                    if let WorkerError::Connection { stage: "write_piece_to_disk", error } = e {
                        lock(&disk_failure).get_or_insert(error.to_string());
                    }
                }
                let _ = outcomes.send((addr, classify(&result)));
            }));
        }
    }

    /// Forgets peer workers whose threads have ended, freeing their slots.
    pub fn reap(&mut self) {
        self.peers.retain(|h| !h.is_finished());
    }

    /// Peer connections currently held (as of the last [`reap`](Self::reap)).
    /// How connections to peers are opened.
    pub fn transport_mode(&self) -> crate::peer::TransportMode {
        self.config.transport.mode
    }

    pub fn active_peers(&self) -> usize {
        self.peers.len()
    }

    /// Web seed workers still running.
    pub fn web_running(&self) -> usize {
        self.web_seeds.iter().filter(|h| !h.is_finished()).count()
    }

    pub fn web_active(&self) -> bool {
        self.web_running() > 0
    }

    /// The next verified-and-written piece, waiting up to `timeout`.
    pub fn recv_result(&self, timeout: Duration) -> Result<PieceResult, RecvTimeoutError> {
        self.results_rx.recv_timeout(timeout)
    }

    /// The connected peers and what each is doing, fastest first. Reading
    /// advances each peer's rate, so this is for one call per refresh.
    pub fn peer_rows(&self, now: Instant) -> Vec<crate::downloader::PeerRow> {
        self.config.peers.rows(now)
    }

    /// Why the disk could not be written to, if that has happened.
    pub fn disk_failure(&self) -> Option<String> {
        lock(&self.disk_failure).clone()
    }

    /// How each peer worker that has ended since the last call ended.
    pub fn take_outcomes(&self) -> Vec<(SocketAddr, Outcome)> {
        self.outcomes_rx.try_iter().collect()
    }

    /// Batches of peer addresses learned through PEX since the last call.
    pub fn pex_batches(&self) -> impl Iterator<Item = Vec<SocketAddr>> + '_ {
        self.pex_rx.try_iter()
    }

    /// Whether peer workers get a PEX channel: false for a private torrent.
    #[cfg(test)]
    pub(crate) fn pex_enabled(&self) -> bool {
        self.pex_tx.is_some()
    }

    /// Puts a result on the channel as a finished worker would, for tests
    /// of what happens to results nobody has collected yet.
    #[cfg(test)]
    pub(crate) fn inject_result(&self, result: PieceResult) {
        self.results_tx.send(result).unwrap();
    }

    /// Stops the web seeds, waits for every worker to finish, and returns
    /// the pieces they completed that nobody had collected yet.
    pub fn shutdown(&mut self) -> Vec<PieceResult> {
        self.web_stop.store(true, Ordering::SeqCst);
        // Workers blocked on a silent peer would otherwise be waited for
        // until their read timeout.
        self.config.interrupt.trigger();
        self.pex_tx = None;
        for h in self.peers.drain(..).chain(self.web_seeds.drain(..)) {
            let _ = h.join();
        }
        self.results_rx.try_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::PieceWork;
    use crate::session::testing::dead_addr;
    use std::sync::Mutex;
    use std::time::Instant;

    fn queue_with(pieces: usize) -> Arc<WorkQueue> {
        let work = (0..pieces).map(|i| PieceWork { index: i as u32, hash: [0; 20], length: 16, merkle: None }).collect();
        Arc::new(WorkQueue::new(work, pieces))
    }

    fn recording_log() -> (Log, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        (Arc::new(move |m| sink.lock().unwrap().push(m)), lines)
    }

    fn workers(queue: Arc<WorkQueue>, max_peers: usize, private: bool, log: Log) -> Workers {
        let config = Arc::new(WorkerConfig { info_hash: [1; 20], our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default() });
        Workers::new(queue, Arc::new(Vec::new()), config, 16, max_peers, private, log)
    }

    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {}", what);
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn spawn_peers_stops_at_the_cap_and_takes_addresses_from_the_pool() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(1), 2, false, log);
        let mut pool = PeerPool::new(true);
        pool.add((0..5).map(|_| dead_addr()));

        w.spawn_peers(&mut pool, Instant::now());

        assert_eq!(w.active_peers(), 2);
        assert_eq!(pool.dialed(), 2, "only the two dialed addresses left the pool");
        w.shutdown();
    }

    #[test]
    fn nothing_is_dialed_when_there_is_no_work_left() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(0), 4, false, log);
        let mut pool = PeerPool::new(true);
        pool.add([dead_addr()]);

        w.spawn_peers(&mut pool, Instant::now());

        assert_eq!(w.active_peers(), 0);
        assert_eq!(pool.dialed(), 0);
    }

    #[test]
    fn a_peer_that_cannot_be_reached_is_logged_and_its_slot_freed() {
        let (log, lines) = recording_log();
        let mut w = workers(queue_with(1), 1, false, log);
        let mut pool = PeerPool::new(true);
        let addr = dead_addr();
        pool.add([addr]);
        w.spawn_peers(&mut pool, Instant::now());
        assert_eq!(w.active_peers(), 1);

        wait_until("the worker to give up", || w.peers.iter().all(|h| h.is_finished()));
        w.reap();

        assert_eq!(w.active_peers(), 0, "the slot is free again");
        let lines = lines.lock().unwrap();
        assert!(lines.iter().any(|l| l.contains(&format!("peer {} disconnected", addr))), "got {:?}", *lines);
    }

    #[test]
    fn shutdown_returns_pieces_nobody_had_collected() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(1), 1, false, log);
        w.results_tx.send(PieceResult { index: 3, data: vec![9; 4] }).unwrap();

        let left = w.shutdown();

        assert_eq!(left.len(), 1);
        assert_eq!((left[0].index, left[0].data.len()), (3, 4));
        assert!(w.shutdown().is_empty(), "and a second shutdown has nothing left to give");
    }

    #[test]
    fn recv_result_delivers_a_piece_and_times_out_when_there_is_none() {
        let (log, _) = recording_log();
        let w = workers(queue_with(1), 1, false, log);
        assert!(matches!(w.recv_result(Duration::from_millis(10)), Err(RecvTimeoutError::Timeout)));

        w.results_tx.send(PieceResult { index: 1, data: vec![] }).unwrap();
        assert_eq!(w.recv_result(Duration::from_millis(10)).unwrap().index, 1);
    }

    #[test]
    fn a_private_torrent_gets_no_pex_channel_and_a_public_one_does() {
        let (log, _) = recording_log();
        assert!(workers(queue_with(1), 1, true, Arc::clone(&log)).pex_tx.is_none(), "BEP 27");
        assert!(workers(queue_with(1), 1, false, log).pex_tx.is_some());
    }

    #[test]
    fn addresses_workers_learn_through_pex_come_out_as_batches() {
        let (log, _) = recording_log();
        let w = workers(queue_with(1), 1, false, log);
        let found: SocketAddr = "10.1.2.3:4567".parse().unwrap();
        w.pex_tx.as_ref().unwrap().send(vec![found]).unwrap();

        assert_eq!(w.pex_batches().collect::<Vec<_>>(), vec![vec![found]]);
        assert_eq!(w.pex_batches().count(), 0, "each batch comes out once");
    }

    #[test]
    fn a_web_seed_that_keeps_failing_logs_it_and_gives_up() {
        let (log, lines) = recording_log();
        let mut w = workers(queue_with(1), 1, false, log);
        let url = format!("http://{}/", dead_addr());
        let files = vec![(vec!["a.bin".to_string()], 16)];

        w.start_web_seeds(&[url], "t", &files, false, 16);
        wait_until("the web seed to give up", || !w.web_active());
        w.shutdown();

        let lines = lines.lock().unwrap();
        assert!(lines.iter().any(|l| l.contains("disabled after")), "got {:?}", *lines);
    }

    fn connection_error(stage: &'static str) -> WorkerError {
        WorkerError::Connection { stage, error: crate::peer::ConnectionError::InfoHashMismatch }
    }

    #[test]
    fn a_workers_end_is_classified_for_the_pool() {
        assert_eq!(classify(&Ok(())), Outcome::Finished);
        assert_eq!(classify(&Err(WorkerError::PieceHashMismatch)), Outcome::BadData, "a corrupt piece is the peer's doing");
        assert_eq!(classify(&Err(connection_error("connect_and_handshake"))), Outcome::Unreachable);
        assert_eq!(classify(&Err(connection_error("write_piece_to_disk"))), Outcome::Local, "our disk, not the peer");
        for stage in ["wait_for_unchoke", "read_message_during_piece_download", "peer_never_unchoked", "peer_has_no_needed_pieces", "send_request"] {
            assert_eq!(classify(&Err(connection_error(stage))), Outcome::Dropped, "{}", stage);
        }
    }

    #[test]
    fn a_worker_reports_how_it_ended_to_the_coordinator() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(1), 1, false, log);
        let mut pool = PeerPool::new(true);
        let addr = dead_addr();
        pool.add([addr]);

        w.spawn_peers(&mut pool, Instant::now());
        let mut outcomes = Vec::new();
        wait_until("the worker to report", || {
            outcomes.extend(w.take_outcomes());
            !outcomes.is_empty()
        });

        assert_eq!(outcomes, vec![(addr, Outcome::Unreachable)]);
        assert!(w.take_outcomes().is_empty(), "each outcome is delivered once");
    }

    #[test]
    fn a_web_seed_that_cannot_write_to_disk_is_reported_as_a_disk_failure() {
        use crate::downloader::build_file_spans;
        use crate::webseed::mirror::{spawn_mirror, Mode};
        use sha1::{Digest, Sha1};

        let content: Vec<u8> = (0..3000).map(|i| (i as u8).wrapping_mul(3)).collect();
        let mirror = spawn_mirror(vec![("file.bin", content.clone())], Mode::Serve);
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-workers-disk-failure-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("file.bin")).unwrap(); // a directory where the file goes
        let work = content.chunks(1024).enumerate().map(|(i, c)| PieceWork { index: i as u32, hash: Sha1::digest(c).into(), length: c.len() as u32, merkle: None }).collect();
        let queue = Arc::new(WorkQueue::new(work, 3));
        let files = vec![(vec!["file.bin".to_string()], 3000i64)];
        let spans = Arc::new(build_file_spans(&dir, &files));
        let config = Arc::new(WorkerConfig { info_hash: [1; 20], our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default() });
        let (log, _) = recording_log();
        let mut w = Workers::new(queue, spans, config, 1024, 1, false, log);
        assert_eq!(w.disk_failure(), None, "nothing has failed yet");

        w.start_web_seeds(std::slice::from_ref(&mirror.base), "file.bin", &files, false, 3000);

        wait_until("the disk failure to be reported", || w.disk_failure().is_some());
        w.shutdown();
    }
}
