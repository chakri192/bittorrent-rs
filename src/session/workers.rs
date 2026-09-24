//! The threads that fetch pieces: one per connected peer, one per web
//! seed, all draining the same work queue.

use crate::downloader::{run_adopted, run_worker, Adopted, Adoption, FileSpan, PexSender, PieceResult, WorkQueue, WorkerConfig, WorkerError};
use crate::seeder::Adopter;
use crate::session::peer_pool::Outcome;
use crate::session::PeerPool;
use crate::sync::lock;
use crate::webseed::{run_web_worker, WebEnd};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// Takes the connections that peers made to us and that turn out to be of use to the download: it asks the peer's pieces of the queue, and
/// hands the connection over to [`Workers::take_adopted`] on a channel.
struct Adoptions {
    queue: Arc<WorkQueue>,
    tx: Mutex<Sender<Adopted>>,
    /// Adopted connections that are running, and the most there are to be.
    running: AtomicUsize,
    max: usize,
    /// Set when the workers are stopped: nothing more is taken.
    closed: AtomicBool,
    /// Addresses whose connections gave data that failed its hash. An address that dialed us has no port to remember it by, as one we
    /// dialed does, so it is the address: such a peer is still served, but not downloaded from again.
    banned: Mutex<std::collections::HashSet<std::net::IpAddr>>,
}

/// Whether a connection that ended this way is one whose peer is not to be downloaded from again: it sent what did not match its hash.
fn is_to_be_banned(result: &Result<(), WorkerError>) -> bool {
    matches!(result, Err(WorkerError::PieceHashMismatch))
}

impl Adopter for Adoptions {
    fn wants(&self, peer: std::net::IpAddr, has: &[bool]) -> bool {
        !self.closed.load(Ordering::SeqCst) && self.running.load(Ordering::SeqCst) < self.max && !lock(&self.banned).contains(&peer) && self.queue.any_wanted_in(has)
    }

    fn adopt(&self, connection: Adopted) {
        self.running.fetch_add(1, Ordering::SeqCst);
        if lock(&self.tx).send(connection).is_err() {
            self.running.fetch_sub(1, Ordering::SeqCst); // the workers are gone: the connection closes
        }
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
    /// Connections that peers made and the download is to take over, and where they wait to be started.
    adoptions: Arc<Adoptions>,
    adopted_rx: Receiver<Adopted>,
}

impl Workers {
    /// How connections are made and what is said on them: what a peer dialed for any other reason is dialed with.
    pub fn config(&self) -> &Arc<WorkerConfig> {
        &self.config
    }

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
        let (adopted_tx, adopted_rx) = mpsc::channel();
        let adoptions = Arc::new(Adoptions { queue: Arc::clone(&queue), tx: Mutex::new(adopted_tx), running: AtomicUsize::new(0), max: max_peers, closed: AtomicBool::new(false), banned: Mutex::new(Default::default()) });
        Workers { queue, spans, config, piece_length, max_peers, log, results_tx, results_rx, pex_tx: (!private).then_some(pex_tx), pex_rx, outcomes_tx, outcomes_rx, peers: Vec::new(), web_seeds: Vec::new(), web_stop: Arc::new(AtomicBool::new(false)), disk_failure: Arc::new(Mutex::new(None)), adoptions, adopted_rx }
    }

    /// What lets the listener give this download the connections of peers that have pieces it lacks (see [`crate::seeder::SeederHandle::set_adopter`]).
    pub fn adopter(&self) -> Arc<dyn Adopter> {
        Arc::clone(&self.adoptions) as Arc<dyn Adopter>
    }

    /// Starts a worker on each connection that has been adopted since the last call. What a worker does with one that has nothing
    /// more to give is to serve it on, on a thread of its own, so that its slot is free for a peer that has.
    pub fn take_adopted(&mut self) {
        let adopted: Vec<Adopted> = self.adopted_rx.try_iter().collect();
        for connection in adopted {
            let (queue, spans, config) = (Arc::clone(&self.queue), Arc::clone(&self.spans), Arc::clone(&self.config));
            let (tx, pex_tx, log) = (self.results_tx.clone(), self.pex_tx.clone(), Arc::clone(&self.log));
            let disk_failure = Arc::clone(&self.disk_failure);
            let (adoptions, piece_length) = (Arc::clone(&self.adoptions), self.piece_length);
            self.peers.push(thread::spawn(move || {
                let peer = connection.peer;
                let result = match run_adopted(connection, &config, &queue, &spans, piece_length, &tx, pex_tx.as_ref()) {
                    Adoption::ServeOn(stream, serving) => {
                        if let Some(upload) = config.upload.clone() {
                            thread::spawn(move || {
                                let _ = crate::seeder::serve_adopted(stream, serving, &upload);
                            });
                        }
                        Ok(())
                    }
                    Adoption::Ended(result) => result,
                };
                adoptions.running.fetch_sub(1, Ordering::SeqCst);
                if is_to_be_banned(&result) {
                    lock(&adoptions.banned).insert(peer.ip());
                }
                if let Err(e) = &result {
                    log(format!("peer {} (connected to us) disconnected: {:?}", peer, e));
                    if let WorkerError::Connection { stage: "write_piece_to_disk", error } = e {
                        lock(&disk_failure).get_or_insert(error.to_string());
                    }
                }
            }));
        }
    }

    /// Starts one worker per BEP 19 web seed, each dialing nobody: they
    /// fetch ranges over HTTP into the same queue.
    pub fn start_web_seeds(&mut self, urls: &[String], name: &str, files: &[(Vec<String>, i64)], multi_file: bool, total_length: u64, v2_pieces: Option<Arc<Vec<crate::v2::V2Piece>>>) {
        let files = Arc::new(files.to_vec());
        for url in urls {
            let (url, name, files, v2_pieces) = (url.clone(), name.to_string(), Arc::clone(&files), v2_pieces.clone());
            let (queue, spans, tx, stop, log) = (Arc::clone(&self.queue), Arc::clone(&self.spans), self.results_tx.clone(), Arc::clone(&self.web_stop), Arc::clone(&self.log));
            let limiter = self.config.down_limit.clone();
            let piece_length = self.piece_length;
            let disk_failure = Arc::clone(&self.disk_failure);
            self.web_seeds.push(thread::spawn(move || {
                let end = run_web_worker(&url, &name, &files, multi_file, limiter.as_deref(), &queue, &spans, piece_length, total_length, v2_pieces.as_deref().map(Vec::as_slice), &tx, &stop, move |m| log(m));
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
        self.take_adopted();
        self.spawn_holepunch_dials();
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
                let outcome = classify(&result);
                // BEP 55: a peer we could not reach directly may still be reachable through a
                // connection we already have -- ask any one of them, if any advertised the
                // extension, to introduce us. Best-effort: nothing is lost if none can.
                if outcome == Outcome::Unreachable {
                    if let Some(relay) = config.holepunch.any_supporting(addr) {
                        config.holepunch.relay(relay, crate::peer::HolepunchMessage::Rendezvous { target: addr });
                    }
                }
                let _ = outcomes.send((addr, outcome));
            }));
        }
    }

    /// Starts a worker, over uTP specifically, for every address a BEP 55 `connect` message has
    /// named since the last call (see [`crate::peer::holepunch`]): the peer or address family may
    /// have no matching uTP socket, in which case that target is silently given up on, consistent
    /// with the rest of this client's best-effort treatment of uTP. Held to the same `max_peers`
    /// cap as [`Self::spawn_peers`], since a swarm that keeps sending `connect` should not be able
    /// to grow the connection count past it.
    pub fn spawn_holepunch_dials(&mut self) {
        for addr in self.config.holepunch.take_dial_targets() {
            if self.peers.len() >= self.max_peers {
                continue; // dropped, not queued: a reactive dial that comes too late is stale anyway
            }
            let socket = match addr {
                SocketAddr::V4(_) => self.config.transport.utp.clone(),
                SocketAddr::V6(_) => self.config.utp6.clone(),
            };
            let Some(socket) = socket else { continue };
            let transport = crate::peer::Transport { mode: crate::peer::TransportMode::Utp, utp: Some(socket) };
            let (queue, spans, config) = (Arc::clone(&self.queue), Arc::clone(&self.spans), Arc::clone(&self.config));
            let (tx, pex_tx, log) = (self.results_tx.clone(), self.pex_tx.clone(), Arc::clone(&self.log));
            let outcomes = self.outcomes_tx.clone();
            let disk_failure = Arc::clone(&self.disk_failure);
            let piece_length = self.piece_length;
            self.peers.push(thread::spawn(move || {
                let result = crate::downloader::run_worker_via(addr, &transport, &config, &queue, &spans, piece_length, &tx, pex_tx.as_ref());
                if let Err(e) = &result {
                    log(format!("peer {} (holepunch) disconnected: {:?}", addr, e));
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
        self.adoptions.closed.store(true, Ordering::SeqCst);
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
        let config = Arc::new(WorkerConfig { info_hash: [1; 20], our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None });
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
    fn holepunch_dials_with_no_matching_utp_socket_are_dropped_silently() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(1), 4, false, log);
        w.config().holepunch.request_dial(dead_addr()); // no uTP socket configured at all
        w.spawn_holepunch_dials();
        assert_eq!(w.active_peers(), 0, "nothing to dial with, so nothing was spawned");
        w.shutdown();
    }

    #[test]
    fn holepunch_dials_respect_the_max_peers_cap() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(1), 1, false, log);
        let mut pool = PeerPool::new(true);
        pool.add([dead_addr()]);
        w.spawn_peers(&mut pool, Instant::now()); // fills the one slot
        assert_eq!(w.active_peers(), 1);

        w.config().holepunch.request_dial(dead_addr());
        w.spawn_holepunch_dials();

        assert_eq!(w.active_peers(), 1, "the cap held: the reactive dial was dropped, not queued");
        w.shutdown();
    }

    #[test]
    fn a_holepunch_dial_with_a_real_matching_socket_is_still_capped() {
        use crate::utp::UtpSocket;
        let v4_server = Arc::new(UtpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());
        v4_server.listen();
        let v4_addr = SocketAddr::from(([127, 0, 0, 1], v4_server.local_addr().unwrap().port()));
        let v4_client = Arc::new(UtpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());

        let (log, _) = recording_log();
        let config = Arc::new(WorkerConfig {
            info_hash: [1; 20],
            our_peer_id: [2; 20],
            pipeline_depth: 5,
            connect_timeout: Duration::from_secs(2),
            down_limit: None,
            interrupt: Default::default(),
            peers: Default::default(),
            encryption: Default::default(),
            transport: crate::peer::Transport { mode: crate::peer::TransportMode::Utp, utp: Some(v4_client) },
            upload: None,
            holepunch: Default::default(),
            utp6: None,
        });
        let mut w = Workers::new(queue_with(1), Arc::new(Vec::new()), config, 16, 1, false, log);
        let mut pool = PeerPool::new(true);
        pool.add([dead_addr()]);
        w.spawn_peers(&mut pool, Instant::now()); // fills the one slot
        assert_eq!(w.active_peers(), 1);

        w.config().holepunch.request_dial(v4_addr);
        w.spawn_holepunch_dials();

        assert!(v4_server.accept(Duration::from_millis(300)).is_none(), "a socket existed for it, but the cap still held");
        w.shutdown();
    }

    #[test]
    fn holepunch_dials_pick_the_utp_socket_matching_the_targets_family() {
        use crate::utp::UtpSocket;
        let v4_server = Arc::new(UtpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());
        v4_server.listen();
        let v4_addr = SocketAddr::from(([127, 0, 0, 1], v4_server.local_addr().unwrap().port()));
        let v4_client = Arc::new(UtpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap());

        let (log, _) = recording_log();
        let config = Arc::new(WorkerConfig {
            info_hash: [1; 20],
            our_peer_id: [2; 20],
            pipeline_depth: 5,
            connect_timeout: Duration::from_secs(2),
            down_limit: None,
            interrupt: Default::default(),
            peers: Default::default(),
            encryption: Default::default(),
            transport: crate::peer::Transport { mode: crate::peer::TransportMode::Utp, utp: Some(v4_client) },
            upload: None,
            holepunch: Default::default(),
            utp6: None,
        });
        let mut w = Workers::new(queue_with(1), Arc::new(Vec::new()), config, 16, 4, false, log);

        w.config().holepunch.request_dial(v4_addr);
        w.spawn_holepunch_dials();

        assert!(v4_server.accept(Duration::from_secs(5)).is_some(), "the v4 target was dialed on the v4 socket");
        w.shutdown();
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

        w.start_web_seeds(&[url], "t", &files, false, 16, None);
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
    fn a_peer_dialed_unreachable_is_asked_of_a_holepunch_capable_connection() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(1), 1, false, log);
        let relay: SocketAddr = "10.9.9.9:1".parse().unwrap();
        let config = Arc::clone(w.config());
        let (entry, rx) = config.holepunch.enter(relay);
        entry.supports.store(true, Ordering::Relaxed);

        let mut pool = PeerPool::new(true);
        let target = dead_addr();
        pool.add([target]);
        w.spawn_peers(&mut pool, Instant::now());
        wait_until("the dial to fail and a rendezvous to be relayed", || rx.try_recv().is_ok_and(|m| m == crate::peer::HolepunchMessage::Rendezvous { target }));
        drop(entry);
    }

    #[test]
    fn a_peer_dialed_unreachable_with_nobody_capable_connected_asks_no_one_and_still_reports_its_outcome() {
        let (log, _) = recording_log();
        let mut w = workers(queue_with(1), 1, false, log);
        let mut pool = PeerPool::new(true);
        let target = dead_addr();
        pool.add([target]);
        w.spawn_peers(&mut pool, Instant::now());
        let mut outcomes = Vec::new();
        wait_until("the worker to report", || {
            outcomes.extend(w.take_outcomes());
            !outcomes.is_empty()
        });
        assert_eq!(outcomes, vec![(target, Outcome::Unreachable)], "the relay lookup finding nobody does not change the outcome reported");
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
        let config = Arc::new(WorkerConfig { info_hash: [1; 20], our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None });
        let (log, _) = recording_log();
        let mut w = Workers::new(queue, spans, config, 1024, 1, false, log);
        assert_eq!(w.disk_failure(), None, "nothing has failed yet");

        w.start_web_seeds(std::slice::from_ref(&mirror.base), "file.bin", &files, false, 3000, None);

        wait_until("the disk failure to be reported", || w.disk_failure().is_some());
        w.shutdown();
    }

    // ---- connections peers made ----

    const LOCAL: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn adoptions_for(pieces: usize, max: usize) -> (Workers, Arc<dyn Adopter>) {
        let workers = Workers::new(queue_with(pieces), Arc::new(Vec::new()), Arc::new(WorkerConfig { info_hash: [1; 20], our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(2), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: None , holepunch: Default::default(), utp6: None }), 16, max, false, recording_log().0);
        let adopter = workers.adopter();
        (workers, adopter)
    }

    #[test]
    fn a_peer_is_wanted_when_it_has_a_piece_still_to_fetch_and_only_then() {
        let (_workers, adopter) = adoptions_for(3, 4);
        assert!(adopter.wants(LOCAL, &[false, false, true]));
        assert!(adopter.wants(LOCAL, &[true, false, false]));
        assert!(!adopter.wants(LOCAL, &[false, false, false]), "it has nothing");
        assert!(!adopter.wants(LOCAL, &[]), "it has said nothing");
        assert!(!adopter.wants(LOCAL, &[false, false, false, true]), "a piece the torrent does not have is nothing to want");
    }

    #[test]
    fn a_piece_that_has_been_fetched_is_no_reason_to_want_a_peer() {
        let (workers, adopter) = adoptions_for(2, 4);
        let (a, b) = (workers.queue.pop().unwrap(), workers.queue.pop().unwrap());
        // Both are claimed by workers, not yet done: the peer might yet be the one to give them.
        assert!(adopter.wants(LOCAL, &[true, true]));
        workers.queue.mark_done(a.index);
        workers.queue.mark_done(b.index);
        assert!(!adopter.wants(LOCAL, &[true, true]), "the download has everything");
    }

    #[test]
    fn no_more_connections_are_taken_than_the_limit_and_none_once_the_workers_are_stopped() {
        let (mut workers, adopter) = adoptions_for(3, 1);
        assert!(adopter.wants(LOCAL, &[true, true, true]));
        workers.adoptions.running.store(1, Ordering::SeqCst);
        assert!(!adopter.wants(LOCAL, &[true, true, true]), "the one allowed is running");
        workers.adoptions.running.store(0, Ordering::SeqCst);
        assert!(adopter.wants(LOCAL, &[true, true, true]));
        workers.shutdown();
        assert!(!adopter.wants(LOCAL, &[true, true, true]), "nothing is taken by workers that are stopping");
    }

    #[test]
    fn only_a_hash_mismatch_gets_a_peer_banned_and_a_ban_is_by_address() {
        assert!(is_to_be_banned(&Err(WorkerError::PieceHashMismatch)));
        assert!(!is_to_be_banned(&Ok(())));
        assert!(!is_to_be_banned(&Err(WorkerError::Connection { stage: "serve_peer", error: crate::peer::ConnectionError::Io(std::io::Error::other("x")) })), "a connection that failed is not one that lied");
        let (workers, adopter) = adoptions_for(3, 4);
        let other: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        assert!(adopter.wants(LOCAL, &[true, true, true]) && adopter.wants(other, &[true, true, true]));
        lock(&workers.adoptions.banned).insert(other);
        assert!(!adopter.wants(other, &[true, true, true]), "that address is not wanted again");
        assert!(adopter.wants(LOCAL, &[true, true, true]), "and the others still are");
    }

    #[test]
    fn a_peer_that_connected_and_sent_a_piece_that_fails_its_hash_is_not_adopted_again() {
        use sha1::Digest;
        use std::io::{Read, Write};
        let info_hash = [0x5C; 20];
        let good = vec![0x11u8; 16384];
        let dir = std::env::temp_dir().join(format!("bt-adopt-ban-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A torrent of one piece that we lack, and a listener to serve from.
        let spans = Arc::new(crate::downloader::build_file_spans(&dir, &[(vec!["f.bin".to_string()], 16384)]));
        let have = Arc::new(crate::seeder::HaveMap::new(1));
        let mut seeder = crate::seeder::start(0, info_hash, [7; 20], Arc::clone(&spans), 16384, 16384, have, None).unwrap();
        let hash: [u8; 20] = sha1::Sha1::digest(&good).into();
        let queue = Arc::new(WorkQueue::new(vec![PieceWork { index: 0, hash, length: 16384, merkle: None }], 1));
        let config = Arc::new(WorkerConfig { info_hash, our_peer_id: [2; 20], pipeline_depth: 2, connect_timeout: Duration::from_secs(2), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default(), transport: Default::default(), upload: Some(seeder.upload()) , holepunch: Default::default(), utp6: None });
        let mut workers = Workers::new(Arc::clone(&queue), spans, config, 16384, 4, false, recording_log().0);
        seeder.set_adopter(Some(workers.adopter()));

        // A peer connects, says it has the piece, unchokes us, and sends the piece with the wrong bytes.
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", seeder.port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(&crate::peer::handshake::Handshake::new(info_hash, [9; 20], false).to_bytes()).unwrap();
        let mut hs = [0u8; 68];
        stream.read_exact(&mut hs).unwrap();
        // (Short reads from here: the loop below starts the worker as soon as the connection has been handed over.)
        stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        crate::peer::message::Message::Bitfield(vec![0x80]).write_to(&mut stream).unwrap();
        crate::peer::message::Message::Unchoke.write_to(&mut stream).unwrap();
        let bad = vec![0x22u8; 16384];
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut sent = false;
        while Instant::now() < deadline && !sent {
            workers.take_adopted();
            match crate::peer::message::Message::read_from(&mut stream) {
                Ok(crate::peer::message::Message::Request { index: 0, begin, length }) => {
                    crate::peer::message::Message::Piece { index: 0, begin, block: bad[begin as usize..(begin + length) as usize].to_vec() }.write_to(&mut stream).unwrap();
                    sent = true;
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        assert!(sent, "the worker asked for the piece over the connection the peer made");
        // Once the worker has judged it, that address is not wanted again.
        let adopter = workers.adopter();
        let banned_by = Instant::now() + Duration::from_secs(5);
        while adopter.wants(LOCAL, &[true]) && Instant::now() < banned_by {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!adopter.wants(LOCAL, &[true]), "a peer that sent a bad piece is not downloaded from again");
        assert!(queue.is_wanted(0), "and the piece is still to be fetched");
        drop(stream);
        workers.shutdown();
        seeder.stop();
    }
}
