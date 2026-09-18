//! The threads that fetch pieces: one per connected peer, one per web
//! seed, all draining the same work queue.

use crate::downloader::{run_worker, FileSpan, PexSender, PieceResult, WorkQueue, WorkerConfig};
use crate::session::PeerPool;
use crate::webseed::run_web_worker;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Where the workers' progress and failure messages go. Shared by every
/// worker thread, hence the `Arc`.
pub type Log = Arc<dyn Fn(String) + Send + Sync>;

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
    peers: Vec<JoinHandle<()>>,
    web_seeds: Vec<JoinHandle<()>>,
    web_stop: Arc<AtomicBool>,
}

impl Workers {
    /// A worker set that will keep at most `max_peers` peer connections
    /// going. Nothing runs until [`spawn_peers`](Self::spawn_peers) or
    /// [`start_web_seeds`](Self::start_web_seeds).
    pub fn new(queue: Arc<WorkQueue>, spans: Arc<Vec<FileSpan>>, config: Arc<WorkerConfig>, piece_length: u64, max_peers: usize, private: bool, log: Log) -> Self {
        let (results_tx, results_rx) = mpsc::channel();
        let (pex_tx, pex_rx) = mpsc::channel();
        Workers { queue, spans, config, piece_length, max_peers, log, results_tx, results_rx, pex_tx: (!private).then_some(pex_tx), pex_rx, peers: Vec::new(), web_seeds: Vec::new(), web_stop: Arc::new(AtomicBool::new(false)) }
    }

    /// Starts one worker per BEP 19 web seed, each dialing nobody: they
    /// fetch ranges over HTTP into the same queue.
    pub fn start_web_seeds(&mut self, urls: &[String], name: &str, files: &[(Vec<String>, i64)], total_length: u64) {
        let files = Arc::new(files.to_vec());
        for url in urls {
            let (url, name, files) = (url.clone(), name.to_string(), Arc::clone(&files));
            let (queue, spans, tx, stop, log) = (Arc::clone(&self.queue), Arc::clone(&self.spans), self.results_tx.clone(), Arc::clone(&self.web_stop), Arc::clone(&self.log));
            let piece_length = self.piece_length;
            self.web_seeds.push(thread::spawn(move || {
                run_web_worker(&url, &name, &files, &queue, &spans, piece_length, total_length, &tx, &stop, move |m| log(m));
            }));
        }
    }

    /// Dials peers from `pool` until `max_peers` are connected or there is
    /// nothing left to dial or fetch.
    pub fn spawn_peers(&mut self, pool: &mut PeerPool) {
        while self.peers.len() < self.max_peers && !self.queue.is_empty() {
            let Some(addr) = pool.next_to_dial() else { break };
            let (queue, spans, config) = (Arc::clone(&self.queue), Arc::clone(&self.spans), Arc::clone(&self.config));
            let (tx, pex_tx, log) = (self.results_tx.clone(), self.pex_tx.clone(), Arc::clone(&self.log));
            let piece_length = self.piece_length;
            self.peers.push(thread::spawn(move || {
                if let Err(e) = run_worker(addr, &config, &queue, &spans, piece_length, &tx, pex_tx.as_ref()) {
                    log(format!("peer {} disconnected: {:?}", addr, e));
                }
            }));
        }
    }

    /// Forgets peer workers whose threads have ended, freeing their slots.
    pub fn reap(&mut self) {
        self.peers.retain(|h| !h.is_finished());
    }

    /// Peer connections currently held (as of the last [`reap`](Self::reap)).
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

    /// Batches of peer addresses learned through PEX since the last call.
    pub fn pex_batches(&self) -> impl Iterator<Item = Vec<SocketAddr>> + '_ {
        self.pex_rx.try_iter()
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
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::time::Instant;

    /// A loopback address nothing is listening on: connecting is refused
    /// straight away, so a worker dialing it fails fast.
    fn dead_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
    }

    fn queue_with(pieces: usize) -> Arc<WorkQueue> {
        let work = (0..pieces).map(|i| PieceWork { index: i as u32, hash: [0; 20], length: 16 }).collect();
        Arc::new(WorkQueue::new(work, pieces))
    }

    fn recording_log() -> (Log, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        (Arc::new(move |m| sink.lock().unwrap().push(m)), lines)
    }

    fn workers(queue: Arc<WorkQueue>, max_peers: usize, private: bool, log: Log) -> Workers {
        let config = Arc::new(WorkerConfig { info_hash: [1; 20], our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2) });
        Workers::new(queue, Arc::new(Vec::new()), config, 16, max_peers, private, log)
    }

    fn wait_until(what: &str, cond: impl Fn() -> bool) {
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

        w.spawn_peers(&mut pool);

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

        w.spawn_peers(&mut pool);

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
        w.spawn_peers(&mut pool);
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

        w.start_web_seeds(&[url], "t", &files, 16);
        wait_until("the web seed to give up", || !w.web_active());
        w.shutdown();

        let lines = lines.lock().unwrap();
        assert!(lines.iter().any(|l| l.contains("disabled after")), "got {:?}", *lines);
    }
}
