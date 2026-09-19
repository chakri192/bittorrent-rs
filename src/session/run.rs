//! One download, from the first dial to the last piece, and the seeding
//! that can follow it.

use crate::downloader::WorkQueue;
use crate::session::peer_pool::Decision;
use crate::session::{Announcer, PeerPool, ProgressSink, Progress, RateSampler, SeedEnd, SeedLimits, Services, Workers};
use crate::ui::format_bytes;
use crate::tracker_discovery::TransferTotals;
use crate::ui::Snapshot;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Main-loop cadence: also the dashboard refresh interval.
pub const UI_TICK: Duration = Duration::from_millis(250);

/// Give up only after this many consecutive re-announce rounds where NO
/// discovery source produced a single new address *and* nothing is
/// running -- bounds "retry forever" against a genuinely dead swarm.
pub const MAX_FRUITLESS_ROUNDS: u32 = 5;

/// How long quitting waits for trackers to take the `stopped` announce.
/// It is a courtesy (their peer lists would drop this client eventually),
/// so it may not hold up the exit for long.
pub const STOP_ANNOUNCE_DEADLINE: Duration = Duration::from_secs(3);

/// Everything a [`Session`] is built from. The setup that produces these
/// (resolving the torrent, resuming, starting the services) stays with the
/// caller.
pub struct Setup<'a> {
    pub sink: &'a dyn ProgressSink,
    pub services: &'a Services,
    pub queue: Arc<WorkQueue>,
    pub workers: Workers,
    pub announcer: Announcer,
    pub progress: Progress,
    pub pool: PeerPool,
    /// Bytes in the wanted pieces: the progress total shown.
    pub display_total: u64,
    /// Pieces this run must verify to be complete.
    pub goal_pieces: usize,
    /// Give up after this long (`--timeout`), if set.
    pub timeout: Option<Duration>,
}

/// How a [`Session::run`] ended.
#[derive(Debug)]
pub struct Report {
    /// Every wanted piece is verified.
    pub complete: bool,
    /// Pieces still missing.
    pub remaining: usize,
    /// Peers dialed over the run.
    pub dialed: usize,
    pub elapsed: Duration,
    /// Bytes fetched by this run (resumed pieces don't count).
    pub bytes_this_run: u64,
    /// Why the run was ended early and not by finishing, the timeout or a
    /// stop: the disk could not be written to. No peer can help with that,
    /// so retrying would only spin.
    pub aborted: Option<String>,
}

/// A running download: the workers fetching pieces, the dial queue, the
/// tracker schedule, and the progress numbers, driven by [`run`](Self::run).
pub struct Session<'a> {
    sink: &'a dyn ProgressSink,
    services: &'a Services,
    queue: Arc<WorkQueue>,
    workers: Workers,
    announcer: Announcer,
    progress: Progress,
    pool: PeerPool,
    rates: RateSampler,
    uploaded: Option<Arc<AtomicU64>>,
    display_total: u64,
    goal_pieces: usize,
    timeout: Option<Duration>,
    run_start: Instant,
    pex_total: usize,
    fresh_since_announce: usize,
    fruitless_rounds: u32,
    endgame_announced: bool,
}

impl<'a> Session<'a> {
    pub fn new(setup: Setup<'a>) -> Self {
        let uploaded = setup.services.uploaded_counter();
        let up_now = uploaded.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
        // Rate sampling starts from what is already counted, so resumed
        // bytes don't read as a burst of throughput.
        let rates = RateSampler::new(Instant::now(), setup.progress.bytes_done(), up_now);
        Session {
            sink: setup.sink,
            services: setup.services,
            queue: setup.queue,
            workers: setup.workers,
            announcer: setup.announcer,
            progress: setup.progress,
            pool: setup.pool,
            rates,
            uploaded,
            display_total: setup.display_total,
            goal_pieces: setup.goal_pieces,
            timeout: setup.timeout,
            run_start: Instant::now(),
            pex_total: 0,
            fresh_since_announce: 0,
            fruitless_rounds: 0,
            endgame_announced: false,
        }
    }

    /// Bytes uploaded to inbound peers so far.
    pub fn uploaded_bytes(&self) -> u64 {
        self.uploaded.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)
    }

    /// Downloads until every wanted piece is verified, `stop` is set, the
    /// timeout passes, or the swarm proves dead. Stops the workers before
    /// returning, so a piece one of them finished on its way out is counted.
    pub fn run(&mut self, stop: &AtomicBool) -> Report {
        let sink = self.sink;
        self.run_start = Instant::now();
        self.workers.spawn_peers(&mut self.pool, Instant::now());
        self.publish();
        let mut aborted = None;

        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            if let Some(why) = self.workers.disk_failure() {
                sink.log(format!("cannot write to disk: {}", why));
                aborted = Some(why);
                break;
            }
            if let Some(timeout) = self.timeout {
                if self.run_start.elapsed() >= timeout {
                    sink.log(format!("--timeout of {}s reached with {} piece(s) remaining", timeout.as_secs(), self.queue.len()));
                    break;
                }
            }

            match self.workers.recv_result(UI_TICK) {
                Ok(result) => self.progress.absorb(result, |m| sink.log(m)),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }

            if self.queue.is_empty() {
                break;
            }

            self.workers.reap();
            self.settle_peers();
            self.poll_discovery();
            self.workers.spawn_peers(&mut self.pool, Instant::now());

            if !self.endgame_announced && self.queue.in_endgame() {
                self.endgame_announced = true;
                sink.log(format!("endgame: {} piece(s) left, requesting duplicates from every capable peer", self.queue.len()));
            }

            self.publish();

            if !self.reannounce_if_due() {
                continue;
            }
            self.workers.spawn_peers(&mut self.pool, Instant::now());
            if self.round_was_fruitless_and_final() {
                break;
            }
        }

        for result in self.workers.shutdown() {
            self.progress.absorb(result, |m| sink.log(m));
        }
        // What the loop last published predates the pieces absorbed above,
        // so without this the final numbers shown -- and, in `--json`, the
        // last progress event -- describe a download that was not quite done.
        self.publish();

        Report { complete: self.queue.is_empty(), remaining: self.queue.len(), dialed: self.pool.dialed(), elapsed: self.run_start.elapsed(), bytes_this_run: self.progress.bytes_this_run(), aborted }
    }

    /// Tells the pool how each peer worker that has ended ended, so it can
    /// schedule a retry or a ban, and says what it decided about the ones
    /// that matter. (The worker's own log line already says why it ended.)
    fn settle_peers(&mut self) {
        let now = Instant::now();
        for (addr, outcome) in self.workers.take_outcomes() {
            match self.pool.record_outcome(addr, outcome, now) {
                Decision::Banned => self.sink.log(format!("peer {} banned: it sent a piece that failed verification", addr)),
                Decision::GiveUp => self.sink.log(format!("peer {}: giving up on it after repeated failures", addr)),
                Decision::RetryIn(_) | Decision::NoRetry => {}
            }
        }
    }

    /// Feeds the dial queue from the passive discovery sources: peer
    /// exchange, the DHT and the local network.
    fn poll_discovery(&mut self) {
        let sink = self.sink;
        let pex_fresh: usize = self.workers.pex_batches().map(|batch| self.pool.add(batch)).sum();
        if pex_fresh > 0 {
            self.pex_total += pex_fresh;
            sink.log(format!("PEX: {} new peer address(es) from connected peers", pex_fresh));
        }
        self.fresh_since_announce += pex_fresh;
        if let Some(dht) = self.services.dht() {
            let dht_fresh: usize = dht.peers_rx.try_iter().map(|batch| self.pool.add(batch)).sum();
            if dht_fresh > 0 {
                sink.log(format!("DHT: {} new peer address(es)", dht_fresh));
            }
            self.fresh_since_announce += dht_fresh;
        }
        if let Some(lsd) = self.services.lsd() {
            let lsd_fresh: usize = lsd.peers_rx.try_iter().map(|batch| self.pool.add(batch)).sum();
            if lsd_fresh > 0 {
                sink.log(format!("LSD: {} new peer address(es) on the local network", lsd_fresh));
            }
            self.fresh_since_announce += lsd_fresh;
        }
    }

    /// Re-announces to the trackers if the schedule says it is time.
    /// Returns whether it did.
    fn reannounce_if_due(&mut self) -> bool {
        let sink = self.sink;
        let starved = self.workers.active_peers() == 0 && self.pool.reserve_is_empty();
        if !self.announcer.is_due(Instant::now(), starved) {
            return false;
        }
        if self.announcer.has_trackers() {
            sink.log(format!("{} piece(s) remaining, re-announcing to trackers", self.queue.len()));
        }
        let totals = TransferTotals { uploaded: self.uploaded_bytes(), downloaded: self.progress.bytes_this_run(), left: self.display_total.saturating_sub(self.progress.bytes_done()) };
        self.fresh_since_announce += self.pool.add(self.announcer.reannounce(Instant::now(), totals, |m| sink.log(m)));
        true
    }

    /// Ends an announce round: counts it as fruitless when no source found
    /// a new address and nothing is running or left to dial, and returns
    /// whether that has now happened [`MAX_FRUITLESS_ROUNDS`] times in a row.
    fn round_was_fruitless_and_final(&mut self) -> bool {
        // A run isn't fruitless while a web seed is still pulling pieces --
        // it can finish the whole download with no peers at all.
        let fruitless = self.fresh_since_announce == 0 && self.workers.active_peers() == 0 && self.pool.reserve_is_empty() && !self.workers.web_active();
        self.fresh_since_announce = 0;
        if !fruitless {
            self.fruitless_rounds = 0;
            return false;
        }
        self.fruitless_rounds += 1;
        self.sink.log(format!("no new peers from any source ({}/{} fruitless rounds)", self.fruitless_rounds, MAX_FRUITLESS_ROUNDS));
        self.fruitless_rounds >= MAX_FRUITLESS_ROUNDS
    }

    /// Pushes the current numbers to the sink.
    fn publish(&mut self) {
        let done = self.progress.bytes_done();
        let up = self.uploaded_bytes();
        if self.rates.sample(Instant::now(), done, up) {
            self.sink.push_rates(self.rates.down_rate() as u64, self.rates.up_rate() as u64);
            self.sink.set_pieces(self.progress.have_snapshot()); // drives the piece-map heatmap
        }
        let remaining = self.display_total.saturating_sub(done);
        let eta_secs = if self.rates.down_rate() > 1.0 { Some((remaining as f64 / self.rates.down_rate()) as u64) } else { None };
        let web_active = self.workers.web_active();
        let status = if self.queue.is_empty() {
            "complete"
        } else if self.queue.in_endgame() {
            "endgame"
        } else if self.progress.bytes_this_run() > 0 || web_active {
            "downloading"
        } else if self.workers.active_peers() == 0 && self.pool.reserve_is_empty() {
            "waiting"
        } else {
            "connecting"
        };
        self.sink.set_snapshot(Snapshot {
            total_length: self.display_total,
            total_pieces: self.goal_pieces,
            verified: self.progress.verified(),
            done_bytes: done,
            down_rate: self.rates.down_rate(),
            up_bytes: up,
            up_rate: self.rates.up_rate(),
            active_peers: self.workers.active_peers(),
            dialed_peers: self.pool.dialed(),
            known_peers: self.pool.known_count(),
            endgame: self.queue.in_endgame(),
            trackers_ok: self.announcer.trackers_ok(),
            trackers_total: self.announcer.tracker_count(),
            dht_nodes: self.services.dht().map(|d| d.nodes.load(Ordering::SeqCst)).unwrap_or(0),
            pex_total: self.pex_total,
            web_seeds: self.workers.web_running(),
            eta_secs,
            elapsed_secs: self.run_start.elapsed().as_secs(),
            status,
            peers: self.workers.peer_rows(Instant::now()),
        });
    }

    /// Tells the trackers the download completed, if this run fetched
    /// anything. A run that only resumed finished pieces has nothing to
    /// report.
    pub fn announce_completed(&mut self) {
        if self.progress.bytes_this_run() > 0 {
            let totals = TransferTotals { uploaded: self.uploaded_bytes(), downloaded: self.progress.bytes_this_run(), left: 0 };
            self.announcer.completed(Instant::now(), totals);
        }
    }

    /// Tells the trackers this client is leaving (BEP 3 `stopped`), with
    /// what the session moved and what was still missing. Waits at most
    /// [`STOP_ANNOUNCE_DEADLINE`].
    pub fn announce_stopped(&mut self) {
        let totals = TransferTotals { uploaded: self.uploaded_bytes(), downloaded: self.progress.bytes_this_run(), left: self.display_total.saturating_sub(self.progress.bytes_done()) };
        self.announcer.stopped(totals, STOP_ANNOUNCE_DEADLINE);
    }

    /// Post-completion seeding: keep the listener and DHT alive,
    /// re-announce with `left = 0` on the tracker interval, publish upload
    /// stats. Returns when `stop` is set (user quit), with `None`, or when
    /// one of `limits` is reached, with which.
    pub fn seed(&mut self, name: &str, port: u16, stop: &AtomicBool, limits: SeedLimits) -> Option<SeedEnd> {
        let sink = self.sink;
        sink.log(format!("seeding {} on port {} -- press q to stop", name, port));
        if limits.is_set() {
            sink.log(format!("will stop seeding at {}", limits));
        }
        let seeding_since = Instant::now();

        // Seeding has its own cadence: count the interval from here.
        self.announcer.restart_clock(Instant::now());
        // Seeding downloads nothing, so the down total stays at 0.
        let mut rates = RateSampler::new(Instant::now(), 0, self.uploaded_bytes());

        while !stop.load(Ordering::SeqCst) {
            if rates.sample(Instant::now(), 0, self.uploaded_bytes()) {
                sink.push_rates(0, rates.up_rate() as u64);
            }
            // The totals are those of the selected subset, all of it done.
            sink.set_snapshot(Snapshot {
                total_length: self.display_total,
                total_pieces: self.goal_pieces,
                verified: self.goal_pieces,
                done_bytes: self.display_total,
                down_rate: 0.0,
                up_bytes: self.uploaded_bytes(),
                up_rate: rates.up_rate(),
                endgame: false,
                status: "seeding",
                ..Default::default()
            });

            if let Some(end) = limits.reached(self.uploaded_bytes(), self.display_total, seeding_since.elapsed()) {
                sink.log(format!("{}: uploaded {} of a {} torrent, stopping", end, format_bytes(self.uploaded_bytes()), format_bytes(self.display_total)));
                return Some(end);
            }

            if self.announcer.has_trackers() && self.announcer.is_due(Instant::now(), false) {
                let totals = TransferTotals { uploaded: self.uploaded_bytes(), downloaded: self.progress.bytes_this_run(), left: 0 };
                let _ = self.announcer.reannounce(Instant::now(), totals, |m| sink.log(m));
            }
            thread::sleep(UI_TICK);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downloader::{build_file_spans, progress_file_path, PieceWork, ResumeWriter, WorkerConfig};
    use crate::peer::handshake::Handshake;
    use crate::peer::message::Message;
    use crate::seeder::{self, HaveMap};
    use crate::session::sink::RecordingSink;
    use crate::session::testing::dead_addr;
    use crate::session::Log;
    use sha1::{Digest, Sha1};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};

    const INFO_HASH: [u8; 20] = [7; 20];
    const PIECE_LEN: usize = 256;
    const PIECES: usize = 4;

    fn data() -> Vec<u8> {
        (0..PIECE_LEN * PIECES).map(|i| (i as u8).wrapping_mul(7)).collect()
    }

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bittorrent-rs-session-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A peer on loopback that has every piece and unchokes at once. With
    /// `serve` false it never answers a request, which is a peer that has
    /// gone silent.
    fn fake_peer(serve: bool) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let data = data();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut hs = [0u8; 68];
            if stream.read_exact(&mut hs).is_err() || stream.write_all(&Handshake::new(INFO_HASH, [9; 20], false).to_bytes()).is_err() {
                return;
            }
            let mut bits = vec![0u8; PIECES.div_ceil(8)];
            for i in 0..PIECES {
                bits[i / 8] |= 1 << (7 - i % 8);
            }
            if Message::Bitfield(bits).write_to(&mut stream).is_err() || Message::Unchoke.write_to(&mut stream).is_err() {
                return;
            }
            while let Ok(msg) = Message::read_from(&mut stream) {
                if let (true, Message::Request { index, begin, length }) = (serve, msg) {
                    let start = index as usize * PIECE_LEN;
                    let block = data[start..start + PIECE_LEN][begin as usize..(begin + length) as usize].to_vec();
                    if (Message::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                        return;
                    }
                }
            }
        });
        addr
    }

    /// A session over the 4-piece test torrent, wired to `sink` and to the
    /// given peers, writing into `dir`.
    fn session<'a>(sink: &'a Arc<RecordingSink>, services: &'a Services, dir: &Path, peers: &[SocketAddr], timeout: Option<Duration>) -> Session<'a> {
        session_with_floor(sink, services, dir, peers, timeout, crate::session::announce::MIN_REANNOUNCE)
    }

    /// As [`session`], with the announce floor lowered, so the paths that
    /// wait on it (a starved swarm) run in milliseconds.
    fn session_with_floor<'a>(sink: &'a Arc<RecordingSink>, services: &'a Services, dir: &Path, peers: &[SocketAddr], timeout: Option<Duration>, floor: Duration) -> Session<'a> {
        session_with_retries(sink, services, dir, peers, timeout, floor, Duration::from_secs(15))
    }

    /// As [`session_with_floor`], with the first retry delay chosen too.
    fn session_with_retries<'a>(sink: &'a Arc<RecordingSink>, services: &'a Services, dir: &Path, peers: &[SocketAddr], timeout: Option<Duration>, floor: Duration, retry_base: Duration) -> Session<'a> {
        session_with_policy(sink, services, dir, peers, timeout, floor, crate::session::peer_pool::RetryPolicy::with_base(retry_base))
    }

    /// As [`session_with_floor`], with the whole retry policy chosen.
    fn session_with_policy<'a>(sink: &'a Arc<RecordingSink>, services: &'a Services, dir: &Path, peers: &[SocketAddr], timeout: Option<Duration>, floor: Duration, policy: crate::session::peer_pool::RetryPolicy) -> Session<'a> {
        let data = data();
        let work = data.chunks(PIECE_LEN).enumerate().map(|(i, c)| PieceWork { index: i as u32, hash: Sha1::digest(c).into(), length: c.len() as u32 }).collect();
        let queue = Arc::new(WorkQueue::new(work, PIECES));
        let spans = Arc::new(build_file_spans(dir, &[(vec!["f.bin".to_string()], data.len() as i64)]));
        let config = Arc::new(WorkerConfig { info_hash: INFO_HASH, our_peer_id: [2; 20], pipeline_depth: 5, connect_timeout: Duration::from_secs(1), down_limit: None, interrupt: Default::default(), peers: Default::default(), encryption: Default::default() });
        let log: Log = {
            let sink = Arc::clone(sink);
            Arc::new(move |m| sink.log(m))
        };
        let workers = Workers::new(Arc::clone(&queue), spans, config, PIECE_LEN as u64, 4, false, log);
        let progress = Progress::new(Arc::new(HaveMap::new(PIECES)), ResumeWriter::create(&progress_file_path(dir, &INFO_HASH)).unwrap(), PIECES, 0, 0);
        let mut pool = PeerPool::with_policy(true, policy);
        pool.add(peers.iter().copied());
        Session::new(Setup {
            sink: &**sink,
            services,
            queue,
            workers,
            announcer: Announcer::new(Vec::new(), INFO_HASH, [2; 20], 6881, None, Instant::now()).with_floor(floor),
            progress,
            pool,
            display_total: data.len() as u64,
            goal_pieces: PIECES,
            timeout,
        })
    }

    #[test]
    fn a_run_downloads_every_piece_from_a_peer_and_reports_it_complete() {
        let dir = tmp_dir("complete");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[fake_peer(true)], None);

        let report = s.run(&AtomicBool::new(false));

        assert!(report.complete);
        assert_eq!((report.remaining, report.dialed, report.bytes_this_run), (0, 1, data().len() as u64));
        assert_eq!(std::fs::read(dir.join("f.bin")).unwrap(), data(), "every piece verified and on disk");
        for piece in 0..PIECES {
            assert!(sink.lines.lock().unwrap().iter().any(|l| l.starts_with(&format!("piece {} verified (", piece))), "piece {} was reported", piece);
        }
        assert!(sink.snapshots.lock().unwrap().iter().any(|snap| snap.status == "downloading"), "and the dashboard saw it downloading");
    }

    #[test]
    fn a_run_whose_disk_cannot_be_written_ends_at_once_saying_so_instead_of_spinning() {
        let dir = tmp_dir("disk-failure");
        // A directory where the file must go: opening it for writing fails.
        std::fs::create_dir_all(dir.join("f.bin")).unwrap();
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        // Safety net: without the abort this would wait out the timeout.
        let mut s = session(&sink, &services, &dir, &[fake_peer(true), fake_peer(true)], Some(Duration::from_secs(20)));

        let report = s.run(&AtomicBool::new(false));

        assert!(!report.complete);
        let why = report.aborted.expect("the run was aborted for the disk, not left to time out");
        assert!(!why.is_empty());
        assert!(report.elapsed < Duration::from_secs(10), "at once, not after {:?}", report.elapsed);
        assert!(sink.logged("cannot write to disk"), "the log says so");
        assert_eq!(report.remaining, PIECES, "nothing was written");
    }

    #[test]
    fn a_run_that_ends_any_other_way_is_not_marked_aborted() {
        let dir = tmp_dir("not-aborted");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[fake_peer(true)], None);

        assert!(s.run(&AtomicBool::new(false)).aborted.is_none());
    }

    #[test]
    fn a_connected_peer_is_listed_in_what_the_run_publishes() {
        let dir = tmp_dir("peer-rows");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        // A peer that unchokes us and then never answers a request: the worker is on the table, downloading nothing.
        let mut s = session(&sink, &services, &dir, &[fake_peer(false)], Some(Duration::from_millis(1200)));

        s.run(&AtomicBool::new(false));

        let listed: Vec<_> = sink.snapshots.lock().unwrap().iter().flat_map(|snap| snap.peers.clone()).collect();
        assert!(!listed.is_empty(), "the peer was on the table in some snapshot");
        assert!(listed.iter().any(|row| row.activity == "downloading"), "and, once it had unchoked us, as downloading: {:?}", listed);
        assert!(listed.iter().all(|row| row.addr.starts_with("127.0.0.1:") && matches!(row.activity, "connecting" | "downloading") && row.bytes == 0), "{:?}", listed);
        assert!(sink.last_snapshot().peers.is_empty(), "and gone once the run had stopped its workers");
    }

    #[test]
    fn the_last_thing_a_finished_run_publishes_is_that_it_is_finished() {
        let dir = tmp_dir("final-snapshot");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[fake_peer(true)], None);

        s.run(&AtomicBool::new(false));

        let last = sink.last_snapshot();
        assert_eq!((last.verified, last.total_pieces), (PIECES, PIECES), "every piece counted, not the count as it stood a tick earlier");
        assert_eq!(last.done_bytes, data().len() as u64);
        assert!(!last.endgame, "and no longer in endgame");
        assert_eq!(last.status, "complete");
        assert_eq!(last.fraction(), 1.0);
    }

    #[test]
    fn a_run_against_a_silent_peer_ends_at_the_timeout_incomplete() {
        let dir = tmp_dir("timeout");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[fake_peer(false)], Some(Duration::from_secs(1)));

        let report = s.run(&AtomicBool::new(false));

        assert!(!report.complete);
        assert_eq!(report.remaining, PIECES);
        assert!(report.elapsed >= Duration::from_secs(1));
        assert!(sink.logged(&format!("--timeout of 1s reached with {} piece(s) remaining", PIECES)));
    }

    #[test]
    fn a_stop_request_ends_the_run_at_once_incomplete() {
        let dir = tmp_dir("stop");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[], None);

        let report = s.run(&AtomicBool::new(true));

        assert!(!report.complete);
        assert_eq!((report.remaining, report.dialed, report.bytes_this_run), (PIECES, 0, 0));
        assert!(report.elapsed < Duration::from_secs(1));
    }

    /// A web seed that accepts the connection and then says nothing, so
    /// its worker stays busy for as long as the test needs.
    fn stalled_web_seed() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let _held = listener.accept();
            thread::sleep(Duration::from_secs(30));
        });
        format!("http://{}/", addr)
    }

    #[test]
    fn a_dead_swarm_ends_the_run_after_the_fruitless_rounds() {
        let dir = tmp_dir("dead");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        // One peer that refuses connections, no trackers, no DHT, no web
        // seed: nothing will ever be found. No stop request, so the way out
        // is the swarm being declared dead; the timeout is only a net so a
        // regression there fails this test instead of hanging it.
        let mut s = session_with_policy(&sink, &services, &dir, &[dead_addr()], Some(Duration::from_secs(15)), Duration::from_millis(1), crate::session::peer_pool::RetryPolicy::none());

        let report = s.run(&AtomicBool::new(false));

        assert!(!report.complete);
        assert_eq!((report.remaining, report.dialed, report.bytes_this_run), (PIECES, 1, 0));
        for round in 1..=MAX_FRUITLESS_ROUNDS {
            assert!(sink.logged(&format!("no new peers from any source ({}/{} fruitless rounds)", round, MAX_FRUITLESS_ROUNDS)), "round {} was announced", round);
        }
        assert!(!sink.logged("--timeout"), "it ended by declaring the swarm dead, not by the safety timeout");
        assert!(report.elapsed < Duration::from_secs(15), "and promptly: {:?}", report.elapsed);
    }

    #[test]
    fn a_run_does_not_give_up_while_a_peer_is_still_connected() {
        let dir = tmp_dir("connected");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        // A peer that connects, unchokes and never answers. Its worker gives
        // up when its 1s read timeout expires; until then the swarm is not
        // dead, however many announce rounds come and go.
        let mut s = session_with_policy(&sink, &services, &dir, &[fake_peer(false)], Some(Duration::from_secs(15)), Duration::from_millis(1), crate::session::peer_pool::RetryPolicy::none()); // the timeout is only a net

        let report = s.run(&AtomicBool::new(false));

        assert!(!report.complete);
        assert!(!sink.logged("--timeout"), "it ended by declaring the swarm dead, not by the safety timeout");
        assert!(report.elapsed >= Duration::from_secs(1), "the run outlasted the peer's read timeout: {:?}", report.elapsed);
        let first_fruitless = sink.lines.lock().unwrap().iter().position(|l| l.contains("(1/5 fruitless rounds)")).expect("it did give up in the end");
        let peer_gone = sink.lines.lock().unwrap().iter().position(|l| l.contains("disconnected")).expect("the peer's worker logged its exit");
        assert!(peer_gone < first_fruitless, "no round was fruitless before the peer went away");
    }

    #[test]
    fn a_round_counts_as_fruitless_only_when_nothing_is_running_found_or_left_to_dial() {
        let dir = tmp_dir("rounds");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[], None);

        for round in 1..MAX_FRUITLESS_ROUNDS {
            assert!(!s.round_was_fruitless_and_final(), "round {} is not yet the last", round);
            assert_eq!(s.fruitless_rounds, round);
        }
        assert!(s.round_was_fruitless_and_final(), "the fifth in a row ends the run");
        assert!(sink.logged("(5/5 fruitless rounds)"));
    }

    #[test]
    fn finding_new_addresses_resets_the_fruitless_count() {
        let dir = tmp_dir("fresh");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[], None);
        s.fruitless_rounds = MAX_FRUITLESS_ROUNDS - 1;
        s.fresh_since_announce = 2;

        assert!(!s.round_was_fruitless_and_final(), "a round that found peers is never the last");
        assert_eq!(s.fruitless_rounds, 0);
        assert_eq!(s.fresh_since_announce, 0, "and the next round starts counting from nothing");
    }

    #[test]
    fn a_peer_waiting_to_be_dialed_keeps_the_swarm_alive() {
        let dir = tmp_dir("reserve");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[dead_addr()], None); // known, not yet dialed
        s.fruitless_rounds = MAX_FRUITLESS_ROUNDS - 1;

        assert!(!s.round_was_fruitless_and_final());
        assert_eq!(s.fruitless_rounds, 0);
    }

    #[test]
    fn a_connected_peer_keeps_the_swarm_alive() {
        let dir = tmp_dir("active");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[fake_peer(false)], None);
        s.workers.spawn_peers(&mut s.pool, Instant::now());
        assert_eq!(s.workers.active_peers(), 1);
        s.fruitless_rounds = MAX_FRUITLESS_ROUNDS - 1;

        assert!(!s.round_was_fruitless_and_final());
        assert_eq!(s.fruitless_rounds, 0);
    }

    #[test]
    fn a_web_seed_still_working_keeps_the_swarm_alive() {
        // A web seed can finish the whole download with no peers at all.
        let dir = tmp_dir("web");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[], None);
        let len = data().len() as i64;
        s.workers.start_web_seeds(&[stalled_web_seed()], "t", &[(vec!["f.bin".to_string()], len)], false, len as u64);
        assert!(s.workers.web_active());
        s.fruitless_rounds = MAX_FRUITLESS_ROUNDS - 1;

        assert!(!s.round_was_fruitless_and_final());
        assert_eq!(s.fruitless_rounds, 0);
    }

    #[test]
    fn a_result_still_in_the_channel_when_the_run_ends_is_counted() {
        // A worker marks a piece done *before* sending its result, so the
        // loop can see the queue empty a moment before the last result
        // arrives. That piece must still be counted, recorded and
        // advertised, or the resume file and the have-map lose it.
        let dir = tmp_dir("drain");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[], None);
        s.workers.inject_result(crate::downloader::PieceResult { index: 2, data: vec![0; PIECE_LEN] });

        let report = s.run(&AtomicBool::new(true)); // ends before the loop reads the channel

        assert_eq!(report.bytes_this_run, PIECE_LEN as u64);
        assert!(sink.logged("piece 2 verified (1/4)"));
        assert_eq!(std::fs::read_to_string(progress_file_path(&dir, &INFO_HASH)).unwrap().trim(), "2", "and it is in the resume file");
    }

    #[test]
    fn the_snapshot_says_waiting_with_nobody_to_dial_and_connecting_with_someone() {
        let dir = tmp_dir("status");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();

        let mut alone = session(&sink, &services, &dir, &[], None);
        alone.publish();
        let snap = sink.last_snapshot();
        assert_eq!((snap.status, snap.known_peers, snap.trackers_total), ("waiting", 0, 0));
        assert_eq!((snap.total_length, snap.total_pieces, snap.verified), (data().len() as u64, PIECES, 0));

        let mut with_peer = session(&sink, &services, &dir, &["127.0.0.1:9".parse().unwrap()], None);
        with_peer.publish();
        let snap = sink.last_snapshot();
        assert_eq!((snap.status, snap.known_peers, snap.dialed_peers), ("connecting", 1, 0));
    }

    #[test]
    fn seeding_reports_everything_done_until_told_to_stop() {
        let dir = tmp_dir("seed");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let mut s = session(&sink, &services, &dir, &[], None);
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(400));
                stop.store(true, Ordering::SeqCst);
            })
        };

        assert_eq!(s.seed("f.bin", 6881, &stop, SeedLimits::default()), None, "stopped by the flag, not by a limit");
        stopper.join().unwrap();

        assert!(sink.logged("seeding f.bin on port 6881 -- press q to stop"));
        let snap = sink.last_snapshot();
        assert_eq!(snap.status, "seeding");
        assert_eq!((snap.verified, snap.total_pieces, snap.done_bytes, snap.total_length), (PIECES, PIECES, data().len() as u64, data().len() as u64));
        assert!(!sink.rates.lock().unwrap().is_empty(), "upload rate was sampled while seeding");
    }

    /// A session with a seeder whose upload counter reads `uploaded`, and a
    /// stop flag that sets itself after `stop_after` so that a seed which
    /// ignores its limits fails rather than hangs.
    fn seed_with(name: &str, uploaded: u64, limits: SeedLimits, stop_after: Duration) -> (Option<SeedEnd>, Duration, Arc<RecordingSink>) {
        let dir = tmp_dir(name);
        let sink = Arc::new(RecordingSink::default());
        let mut services = Services::new();
        services.attach_seeder(seeder::start(0, INFO_HASH, [2; 20], Arc::new(Vec::new()), PIECE_LEN as u64, 0, Arc::new(HaveMap::new(0)), None).unwrap());
        services.uploaded_counter().unwrap().store(uploaded, Ordering::SeqCst);
        let mut s = session(&sink, &services, &dir, &[], None);
        let stop = Arc::new(AtomicBool::new(false));
        // Left to finish its sleep on its own: joining it would make every
        // test that ends early wait out `stop_after`.
        let flag = Arc::clone(&stop);
        thread::spawn(move || {
            thread::sleep(stop_after);
            flag.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let end = s.seed("f.bin", 6881, &stop, limits);
        (end, started.elapsed(), sink)
    }

    #[test]
    fn seeding_ends_by_itself_once_the_ratio_is_reached() {
        let size = data().len() as u64;
        let limits = SeedLimits { ratio: Some(1.0), time: None };

        let (end, took, sink) = seed_with("seed-ratio-reached", size, limits, Duration::from_secs(20));

        assert_eq!(end, Some(SeedEnd::Ratio(1.0)));
        assert!(took < Duration::from_secs(5), "it stopped on its own, not when the flag was set: {:?}", took);
        assert!(sink.logged("will stop seeding at ratio 1.00"));
        assert!(sink.logged("seed ratio 1.00 reached: uploaded"), "the log says why it stopped");
    }

    #[test]
    fn seeding_below_the_ratio_carries_on_until_told_to_stop() {
        let size = data().len() as u64;
        let limits = SeedLimits { ratio: Some(1.0), time: None };

        let (end, took, _) = seed_with("seed-ratio-short", size - 1, limits, Duration::from_millis(700));

        assert_eq!(end, None, "one byte short of the ratio");
        assert!(took >= Duration::from_millis(600), "it ran until the flag: {:?}", took);
    }

    #[test]
    fn seeding_ends_by_itself_once_the_time_is_up() {
        let limits = SeedLimits { ratio: None, time: Some(Duration::from_millis(600)) };

        let (end, took, sink) = seed_with("seed-time-up", 0, limits, Duration::from_secs(20));

        assert_eq!(end, Some(SeedEnd::Time(Duration::from_millis(600))));
        assert!(took >= Duration::from_millis(600), "not before the time: {:?}", took);
        assert!(took < Duration::from_secs(5), "and then promptly: {:?}", took);
        assert!(sink.logged("seed time of 0s reached: uploaded"), "the log says why it stopped");
    }

    #[test]
    fn upload_bytes_come_from_the_seeders_counter() {
        let dir = tmp_dir("uploaded");
        let sink = Arc::new(RecordingSink::default());
        let mut services = Services::new();
        services.attach_seeder(seeder::start(0, INFO_HASH, [2; 20], Arc::new(Vec::new()), PIECE_LEN as u64, 0, Arc::new(HaveMap::new(0)), None).unwrap());
        services.uploaded_counter().unwrap().store(42, Ordering::SeqCst);
        let mut s = session(&sink, &services, &dir, &[], None);

        assert_eq!(s.uploaded_bytes(), 42);
        s.publish();
        assert_eq!(sink.last_snapshot().up_bytes, 42);
    }

    #[test]
    fn a_session_without_a_seeder_has_uploaded_nothing() {
        let dir = tmp_dir("noseeder");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        assert_eq!(session(&sink, &services, &dir, &[], None).uploaded_bytes(), 0);
    }

    // ---- peers that fail --------------------------------------------------

    #[derive(Clone, Copy)]
    enum Flaw {
        /// Hangs up on the first connection's first request, serves later ones.
        DropsOnce,
        /// Hangs up on every connection's first request.
        AlwaysDrops,
        /// Serves every block corrupted.
        Corrupt,
    }

    /// A peer with the given flaw that accepts any number of connections.
    /// Returns its address and how many connections it has accepted.
    fn flawed_peer(flaw: Flaw) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = Arc::clone(&connections);
        let data = data();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let nth = count.fetch_add(1, Ordering::SeqCst) + 1;
                let data = data.clone();
                thread::spawn(move || {
                    let mut hs = [0u8; 68];
                    if stream.read_exact(&mut hs).is_err() || stream.write_all(&Handshake::new(INFO_HASH, [9; 20], false).to_bytes()).is_err() {
                        return;
                    }
                    let mut bits = vec![0u8; PIECES.div_ceil(8)];
                    for i in 0..PIECES {
                        bits[i / 8] |= 1 << (7 - i % 8);
                    }
                    if Message::Bitfield(bits).write_to(&mut stream).is_err() || Message::Unchoke.write_to(&mut stream).is_err() {
                        return;
                    }
                    while let Ok(msg) = Message::read_from(&mut stream) {
                        let Message::Request { index, begin, length } = msg else { continue };
                        if matches!(flaw, Flaw::AlwaysDrops) || (matches!(flaw, Flaw::DropsOnce) && nth == 1) {
                            return; // hang up
                        }
                        let start = index as usize * PIECE_LEN;
                        let mut block = data[start..start + PIECE_LEN][begin as usize..(begin + length) as usize].to_vec();
                        if matches!(flaw, Flaw::Corrupt) {
                            block.iter_mut().for_each(|b| *b ^= 0xFF);
                        }
                        if (Message::Piece { index, begin, block }).write_to(&mut stream).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, connections)
    }

    const SAFETY: Duration = Duration::from_secs(20); // only a net: a regression fails instead of hanging

    #[test]
    fn a_peer_heard_of_on_the_local_network_is_news_to_the_round_it_arrives_in() {
        // A round that found nobody is fruitless, and enough of them end the run; one that heard of a peer is not.
        let dir = tmp_dir("lsd-fresh");
        let sink = Arc::new(RecordingSink::default());
        let mut services = Services::new();
        let listen = SocketAddr::from(([127, 0, 0, 1], 0));
        services.start_lsd(crate::lsd::LsdConfig { send_to: SocketAddr::from(([127, 0, 0, 1], 9)), listen, join: None, share_port: false, interval: Duration::from_secs(3600) }, INFO_HASH, 6881, |_| {});
        let heard_at = services.lsd().expect("the service started").listen_addr;
        let neighbour = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        neighbour.send_to(&crate::lsd::announcement(heard_at, 5555, &INFO_HASH, "the-neighbour"), heard_at).unwrap();
        let mut s = session(&sink, &services, &dir, &[], None);
        let until = Instant::now() + Duration::from_secs(5);
        while s.fresh_since_announce == 0 && Instant::now() < until {
            s.poll_discovery();
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(s.fresh_since_announce, 1);
    }

    #[test]
    fn a_peer_found_on_the_local_network_is_dialed_and_the_download_finishes() {
        // No tracker, no DHT and no address to begin with: the only way to the
        // peer is a datagram from the local network, as LSD would deliver it.
        let dir = tmp_dir("lsd");
        let sink = Arc::new(RecordingSink::default());
        let mut services = Services::new();
        let listen = SocketAddr::from(([127, 0, 0, 1], 0));
        let config = crate::lsd::LsdConfig { send_to: SocketAddr::from(([127, 0, 0, 1], 9)), listen, join: None, share_port: false, interval: Duration::from_secs(3600) };
        services.start_lsd(config, INFO_HASH, 6881, |_| {});
        let heard_at = services.lsd().expect("the service started").listen_addr;
        let peer = fake_peer(true);
        let neighbour = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        neighbour.send_to(&crate::lsd::announcement(heard_at, peer.port(), &INFO_HASH, "the-neighbour"), heard_at).unwrap();
        let mut s = session(&sink, &services, &dir, &[], Some(SAFETY));

        let report = s.run(&AtomicBool::new(false));

        assert!(report.complete, "{:?}", sink.lines.lock().unwrap());
        assert!(sink.logged("LSD: 1 new peer address(es) on the local network"));
        assert_eq!(std::fs::read(dir.join("f.bin")).unwrap(), data());
    }

    #[test]
    fn a_peer_that_drops_us_once_is_dialed_again_and_the_download_finishes() {
        // The pool used to dial each address exactly once, so one dropped
        // connection to the only peer ended the download.
        let dir = tmp_dir("dropsonce");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let (peer, connections) = flawed_peer(Flaw::DropsOnce);
        let mut s = session_with_retries(&sink, &services, &dir, &[peer], Some(SAFETY), crate::session::announce::MIN_REANNOUNCE, Duration::from_millis(100));

        let report = s.run(&AtomicBool::new(false));

        assert!(report.complete, "it should finish on the second connection: {:?}", sink.lines.lock().unwrap());
        assert_eq!(connections.load(Ordering::SeqCst), 2, "one connection dropped, one retried");
        assert_eq!(std::fs::read(dir.join("f.bin")).unwrap(), data());
        assert_eq!(report.dialed, 1, "one distinct peer");
    }

    #[test]
    fn a_peer_that_always_hangs_up_is_retried_a_bounded_number_of_times_then_given_up() {
        let dir = tmp_dir("alwaysdrops");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let (peer, connections) = flawed_peer(Flaw::AlwaysDrops);
        // Retry delays of 20, 60 and 180 ms: the first connection and three retries.
        let mut s = session_with_retries(&sink, &services, &dir, &[peer], Some(SAFETY), Duration::from_millis(1), Duration::from_millis(20));

        let report = s.run(&AtomicBool::new(false));

        assert!(!report.complete);
        assert_eq!(connections.load(Ordering::SeqCst), 4, "the first attempt and three retries, no more");
        assert!(sink.logged(&format!("peer {}: giving up on it after repeated failures", peer)));
        assert!(!sink.logged("--timeout"), "it ended because the peer was given up on, not by the safety timeout");
    }

    #[test]
    fn a_peer_that_sends_corrupt_data_is_banned_and_never_dialed_again() {
        let dir = tmp_dir("corrupt");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let (peer, connections) = flawed_peer(Flaw::Corrupt);
        let mut s = session_with_retries(&sink, &services, &dir, &[peer], Some(SAFETY), Duration::from_millis(1), Duration::from_millis(20));

        let report = s.run(&AtomicBool::new(false));

        assert!(!report.complete, "the only peer is a liar");
        assert_eq!(connections.load(Ordering::SeqCst), 1, "banned after its first bad piece, however short the retry delay");
        assert!(sink.logged(&format!("peer {} banned: it sent a piece that failed verification", peer)));
        assert!(s.pool.is_banned(&peer));
        assert_eq!(std::fs::metadata(dir.join("f.bin")).map(|m| m.len()).unwrap_or(0), 0, "nothing corrupt was written");
    }

    #[test]
    fn a_liar_is_banned_while_an_honest_peer_finishes_the_download() {
        let dir = tmp_dir("liarandhonest");
        let sink = Arc::new(RecordingSink::default());
        let services = Services::new();
        let (liar, liar_connections) = flawed_peer(Flaw::Corrupt);
        let honest = fake_peer(true);
        let mut s = session_with_retries(&sink, &services, &dir, &[liar, honest], Some(SAFETY), crate::session::announce::MIN_REANNOUNCE, Duration::from_millis(20));

        let report = s.run(&AtomicBool::new(false));

        assert!(report.complete);
        assert_eq!(std::fs::read(dir.join("f.bin")).unwrap(), data(), "every byte is the honest peer's");
        assert_eq!(liar_connections.load(Ordering::SeqCst), 1);
    }
}
