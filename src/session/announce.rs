//! Talking to a torrent's trackers over the life of a session: the first
//! announce, the periodic re-announces, and the final "completed".

use crate::tracker::{AnnounceRequest, Event};
use crate::tracker_discovery::{announce_to_all, announce_to_all_within, build_request, walk_tiers, TrackerAttempt, TrackerMode, TransferTotals, TIERED_TRACKER_DEADLINE};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Floor on re-announce spacing whatever a tracker asks for, and the
/// wait used when nothing is connected and nothing is left to dial.
pub const MIN_REANNOUNCE: Duration = Duration::from_secs(30);

/// Spacing until a tracker says otherwise.
pub const DEFAULT_REANNOUNCE: Duration = Duration::from_secs(120);

/// One announce round across a list of trackers: the peers found, the
/// trackers that failed, and the re-announce interval to honour.
pub type Round = (Vec<SocketAddr>, Vec<TrackerAttempt>, Option<u32>);

/// Where announces actually go. The network implementation is
/// [`NetworkTrackers`]; tests script the replies instead.
pub trait TrackerClient {
    fn announce(&self, urls: &[String], req: &AnnounceRequest) -> Round;

    /// Like [`announce`](Self::announce), but giving up on trackers that
    /// have not answered within `deadline`. The default ignores the
    /// deadline, which suits a client that answers at once.
    fn announce_within(&self, urls: &[String], req: &AnnounceRequest, _deadline: Duration) -> Round {
        self.announce(urls, req)
    }
}

/// Announces over HTTP, HTTPS and UDP, all trackers concurrently.
pub struct NetworkTrackers;

impl TrackerClient for NetworkTrackers {
    fn announce(&self, urls: &[String], req: &AnnounceRequest) -> Round {
        announce_to_all(urls, req)
    }

    fn announce_within(&self, urls: &[String], req: &AnnounceRequest, deadline: Duration) -> Round {
        announce_to_all_within(urls, req, deadline)
    }
}

/// Announce schedule and bookkeeping for one torrent.
///
/// With no trackers every announce is a no-op that finds nothing, but the
/// schedule still runs: a DHT-only or web-seed-only session paces its own
/// housekeeping off the same clock.
pub struct Announcer<C: TrackerClient = NetworkTrackers> {
    client: C,
    /// The trackers, in tiers (BEP 12). A list with no tiers to it is one tier, asked all at once.
    tiers: Vec<Vec<String>>,
    mode: TrackerMode,
    /// In tiered mode, the tracker that answered last: the one told of completion and of leaving.
    active: Option<String>,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    /// `--reannounce`: an interval that wins over whatever trackers ask.
    fixed_interval: Option<Duration>,
    /// The shortest wait ever used: [`MIN_REANNOUNCE`] in real use. Only
    /// tests lower it, so they need not sit through 30-second waits.
    floor: Duration,
    wait: Duration,
    last_at: Instant,
    trackers_ok: usize,
}

impl Announcer {
    /// An announcer for a flat list of trackers, all asked at once.
    pub fn new(urls: Vec<String>, info_hash: [u8; 20], peer_id: [u8; 20], port: u16, fixed_interval: Option<Duration>, now: Instant) -> Self {
        Announcer::with_client(NetworkTrackers, urls, info_hash, peer_id, port, fixed_interval, now)
    }

    /// An announcer for trackers in `tiers`, asked as `mode` says.
    pub fn tiered(tiers: Vec<Vec<String>>, mode: TrackerMode, info_hash: [u8; 20], peer_id: [u8; 20], port: u16, fixed_interval: Option<Duration>, now: Instant) -> Self {
        Announcer::with_client_tiers(NetworkTrackers, tiers, mode, info_hash, peer_id, port, fixed_interval, now)
    }
}

impl<C: TrackerClient> Announcer<C> {
    pub fn with_client(client: C, urls: Vec<String>, info_hash: [u8; 20], peer_id: [u8; 20], port: u16, fixed_interval: Option<Duration>, now: Instant) -> Self {
        Announcer::with_client_tiers(client, if urls.is_empty() { Vec::new() } else { vec![urls] }, TrackerMode::Concurrent, info_hash, peer_id, port, fixed_interval, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_client_tiers(client: C, tiers: Vec<Vec<String>>, mode: TrackerMode, info_hash: [u8; 20], peer_id: [u8; 20], port: u16, fixed_interval: Option<Duration>, now: Instant) -> Self {
        Announcer {
            client,
            tiers: tiers.into_iter().filter(|tier| !tier.is_empty()).collect(),
            mode,
            active: None,
            info_hash,
            peer_id,
            port,
            fixed_interval,
            floor: MIN_REANNOUNCE,
            wait: fixed_interval.map_or(DEFAULT_REANNOUNCE, |d| d.max(MIN_REANNOUNCE)),
            last_at: now,
            trackers_ok: 0,
        }
    }

    /// Lowers the floor under every wait to `floor`.
    #[cfg(test)]
    pub(crate) fn with_floor(mut self, floor: Duration) -> Self {
        self.floor = floor;
        self.wait = self.fixed_interval.map_or(DEFAULT_REANNOUNCE, |d| d.max(floor));
        self
    }

    pub fn has_trackers(&self) -> bool {
        !self.tiers.is_empty()
    }

    pub fn tracker_count(&self) -> usize {
        self.all_urls().len()
    }

    /// Every tracker, whatever its tier, each once.
    fn all_urls(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.tiers.iter().flatten().filter(|url| seen.insert(url.as_str())).cloned().collect()
    }

    /// The trackers to tell of an event that is not a request for peers: all of them, or in tiered mode the one
    /// that has been answering.
    fn to_tell(&self) -> Vec<String> {
        match (self.mode, &self.active) {
            (TrackerMode::Concurrent, _) => self.all_urls(),
            (TrackerMode::Tiered, Some(active)) => vec![active.clone()],
            (TrackerMode::Tiered, None) => Vec::new(),
        }
    }

    /// Trackers that answered the most recent round.
    pub fn trackers_ok(&self) -> usize {
        self.trackers_ok
    }

    /// The `started` announce. Returns the peers found.
    pub fn start(&mut self, now: Instant, totals: TransferTotals, log: impl Fn(String)) -> Vec<SocketAddr> {
        self.round(now, totals, Some(Event::Started), log)
    }

    /// Whether a periodic re-announce is due. `starved` (nothing connected
    /// and nothing left to dial) shortens the wait to [`MIN_REANNOUNCE`],
    /// since fresh peers are the only way forward.
    pub fn is_due(&self, now: Instant, starved: bool) -> bool {
        let wait = if starved { self.floor } else { self.wait };
        now.saturating_duration_since(self.last_at) >= wait
    }

    /// A periodic re-announce. Restarts the schedule whether or not there
    /// are trackers to ask. Returns the peers found.
    pub fn reannounce(&mut self, now: Instant, totals: TransferTotals, log: impl Fn(String)) -> Vec<SocketAddr> {
        self.round(now, totals, None, log)
    }

    /// The `completed` announce. Best effort: the reply is not used.
    pub fn completed(&mut self, now: Instant, totals: TransferTotals) {
        self.last_at = now;
        let urls = self.to_tell();
        if urls.is_empty() {
            return;
        }
        let req = build_request(self.info_hash, self.peer_id, self.port, totals, Some(Event::Completed));
        let _ = self.client.announce(&urls, &req);
    }

    /// The `stopped` announce (BEP 3), sent as the client exits so trackers
    /// drop it from their peer lists at once rather than when it times
    /// out. Best effort, and bounded: trackers that have not answered
    /// within `deadline` are left behind, since a dead tracker must not
    /// hold up quitting.
    pub fn stopped(&mut self, totals: TransferTotals, deadline: Duration) {
        let urls = self.to_tell();
        if urls.is_empty() {
            return;
        }
        let req = build_request(self.info_hash, self.peer_id, self.port, totals, Some(Event::Stopped));
        let _ = self.client.announce_within(&urls, &req, deadline);
    }

    /// Restarts the re-announce clock without announcing, for when a
    /// session enters a new phase (seeding) with its own cadence.
    pub fn restart_clock(&mut self, now: Instant) {
        self.last_at = now;
    }

    fn round(&mut self, now: Instant, totals: TransferTotals, event: Option<Event>, log: impl Fn(String)) -> Vec<SocketAddr> {
        self.last_at = now;
        if self.tiers.is_empty() {
            return Vec::new();
        }
        let req = build_request(self.info_hash, self.peer_id, self.port, totals, event);
        let (peers, failures, interval) = match self.mode {
            TrackerMode::Concurrent => {
                let round = self.client.announce(&self.all_urls(), &req);
                self.trackers_ok = self.tracker_count().saturating_sub(round.1.len());
                round
            }
            TrackerMode::Tiered => {
                let client = &self.client;
                let (found, failures) = walk_tiers(&mut self.tiers, |url| {
                    let (peers, failed, interval) = client.announce_within(&[url.to_string()], &req, TIERED_TRACKER_DEADLINE);
                    match failed.into_iter().next() {
                        Some(failure) => Err(failure.error),
                        None => Ok((peers, interval)),
                    }
                });
                self.active = found.as_ref().map(|(url, _)| url.clone());
                self.trackers_ok = usize::from(found.is_some());
                let (peers, interval) = found.map(|(_, answer)| answer).unwrap_or_default();
                (peers, failures, interval)
            }
        };
        for f in &failures {
            log(format!("tracker {} failed: {}", f.url, f.error));
        }
        // Adopt the tracker's interval unless the user fixed one, but never
        // go below the floor: announcing faster than asked is how clients
        // get rate-limited.
        if self.fixed_interval.is_none() {
            if let Some(secs) = interval {
                self.wait = Duration::from_secs(secs as u64).max(self.floor);
            }
        }
        peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Replays canned rounds and records every request it is sent.
    #[derive(Default)]
    struct Scripted {
        replies: RefCell<VecDeque<Round>>,
        seen: RefCell<Vec<AnnounceRequest>>,
        /// The deadline of each announce that was given one.
        deadlines: RefCell<Vec<Duration>>,
    }

    impl Scripted {
        fn reply(&self, peers: &[&str], failed: &[&str], interval: Option<u32>) {
            let peers = peers.iter().map(|p| p.parse().unwrap()).collect();
            let failed = failed.iter().map(|u| TrackerAttempt { url: u.to_string(), error: "boom".to_string() }).collect();
            self.replies.borrow_mut().push_back((peers, failed, interval));
        }
    }

    impl TrackerClient for &Scripted {
        fn announce(&self, _urls: &[String], req: &AnnounceRequest) -> Round {
            self.seen.borrow_mut().push(req.clone());
            self.replies.borrow_mut().pop_front().unwrap_or_default()
        }

        fn announce_within(&self, urls: &[String], req: &AnnounceRequest, deadline: Duration) -> Round {
            self.deadlines.borrow_mut().push(deadline);
            self.announce(urls, req)
        }
    }

    fn urls(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("http://t{}/announce", i)).collect()
    }

    fn announcer(client: &Scripted, n_urls: usize, fixed: Option<u64>, now: Instant) -> Announcer<&Scripted> {
        Announcer::with_client(client, urls(n_urls), [1; 20], [2; 20], 6881, fixed.map(Duration::from_secs), now)
    }

    fn totals() -> TransferTotals {
        TransferTotals { uploaded: 10, downloaded: 20, left: 30 }
    }

    fn secs(t0: Instant, s: u64) -> Instant {
        t0 + Duration::from_secs(s)
    }

    #[test]
    fn start_returns_the_peers_and_counts_the_trackers_that_answered() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&["10.0.0.1:6881", "10.0.0.2:6881"], &["http://t1/announce"], Some(600));
        let mut a = announcer(&client, 3, None, t0);

        let peers = a.start(t0, totals(), |_| {});

        assert_eq!(peers.len(), 2);
        assert_eq!(a.trackers_ok(), 2, "3 trackers, 1 failed");
        assert_eq!(client.seen.borrow()[0].event, Some(Event::Started));
        assert_eq!((client.seen.borrow()[0].uploaded, client.seen.borrow()[0].downloaded, client.seen.borrow()[0].left), (10, 20, 30));
    }

    #[test]
    fn stopped_tells_every_tracker_within_the_deadline_what_the_session_moved() {
        let t0 = Instant::now();
        let client = Scripted::default();
        let mut a = announcer(&client, 2, None, t0);

        a.stopped(totals(), Duration::from_secs(3));

        let seen = client.seen.borrow();
        assert_eq!(seen.len(), 1, "one round, which reaches all trackers");
        assert_eq!(seen[0].event, Some(Event::Stopped));
        assert_eq!((seen[0].uploaded, seen[0].downloaded, seen[0].left), (10, 20, 30));
        assert_eq!(*client.deadlines.borrow(), vec![Duration::from_secs(3)], "a dead tracker must not hold up quitting");
    }

    #[test]
    fn stopped_with_no_trackers_sends_nothing() {
        let client = Scripted::default();
        let mut a = announcer(&client, 0, None, Instant::now());
        a.stopped(totals(), Duration::from_secs(3));
        assert!(client.seen.borrow().is_empty());
    }

    #[test]
    fn failures_are_logged_with_the_tracker_url() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&[], &["http://t0/announce"], None);
        let mut a = announcer(&client, 1, None, t0);
        let lines = RefCell::new(Vec::new());

        a.start(t0, totals(), |m| lines.borrow_mut().push(m));

        assert_eq!(lines.into_inner(), vec!["tracker http://t0/announce failed: boom".to_string()]);
    }

    #[test]
    fn until_a_tracker_says_otherwise_the_default_interval_applies() {
        let t0 = Instant::now();
        let client = Scripted::default();
        let a = announcer(&client, 1, None, t0);
        assert!(!a.is_due(secs(t0, 119), false));
        assert!(a.is_due(secs(t0, 120), false));
    }

    #[test]
    fn the_trackers_interval_is_adopted() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&[], &[], Some(600));
        let mut a = announcer(&client, 1, None, t0);
        a.start(t0, totals(), |_| {});
        assert!(!a.is_due(secs(t0, 599), false));
        assert!(a.is_due(secs(t0, 600), false));
    }

    #[test]
    fn an_interval_below_the_floor_is_raised_to_it() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&[], &[], Some(5));
        let mut a = announcer(&client, 1, None, t0);
        a.start(t0, totals(), |_| {});
        assert!(!a.is_due(secs(t0, 29), false));
        assert!(a.is_due(secs(t0, 30), false));
    }

    #[test]
    fn a_fixed_interval_beats_the_trackers_on_start_and_on_reannounce() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&[], &[], Some(600));
        client.reply(&[], &[], Some(900));
        let mut a = announcer(&client, 1, Some(45), t0);

        assert!(a.is_due(secs(t0, 45), false), "fixed before anything is announced");
        a.start(t0, totals(), |_| {});
        assert!(a.is_due(secs(t0, 45), false), "start's reply doesn't override it");
        a.reannounce(secs(t0, 45), totals(), |_| {});
        assert!(!a.is_due(secs(t0, 45 + 44), false));
        assert!(a.is_due(secs(t0, 45 + 45), false), "nor does a later reply");
    }

    #[test]
    fn a_fixed_interval_below_the_floor_is_raised_to_it() {
        let t0 = Instant::now();
        let client = Scripted::default();
        let a = announcer(&client, 1, Some(3), t0);
        assert!(!a.is_due(secs(t0, 29), false));
        assert!(a.is_due(secs(t0, 30), false));
    }

    #[test]
    fn a_starved_session_reannounces_at_the_floor_whatever_the_interval() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&[], &[], Some(900));
        let mut a = announcer(&client, 1, None, t0);
        a.start(t0, totals(), |_| {});
        assert!(!a.is_due(secs(t0, 30), false));
        assert!(a.is_due(secs(t0, 30), true));
    }

    #[test]
    fn a_reannounce_sends_no_event_restarts_the_clock_and_updates_the_count() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&[], &[], None);
        client.reply(&["10.0.0.9:1"], &["http://t0/announce", "http://t1/announce"], Some(60));
        let mut a = announcer(&client, 2, None, t0);
        a.start(t0, totals(), |_| {});
        assert_eq!(a.trackers_ok(), 2);

        let peers = a.reannounce(secs(t0, 200), totals(), |_| {});

        assert_eq!(peers.len(), 1);
        assert_eq!(client.seen.borrow()[1].event, None);
        assert_eq!(a.trackers_ok(), 0);
        assert!(!a.is_due(secs(t0, 200 + 59), false));
        assert!(a.is_due(secs(t0, 200 + 60), false), "the schedule restarted at the reannounce and took the new interval");
    }

    #[test]
    fn with_no_trackers_nothing_is_sent_but_the_clock_still_runs() {
        let t0 = Instant::now();
        let client = Scripted::default();
        let mut a = announcer(&client, 0, None, t0);
        assert!(!a.has_trackers());

        assert!(a.start(t0, totals(), |_| {}).is_empty());
        assert!(a.is_due(secs(t0, 120), false));
        assert!(a.reannounce(secs(t0, 120), totals(), |_| {}).is_empty());
        a.completed(secs(t0, 121), totals());

        assert!(client.seen.borrow().is_empty(), "no request without a tracker");
        assert!(!a.is_due(secs(t0, 121 + 119), false));
        assert!(a.is_due(secs(t0, 121 + 120), false), "each call restarted the clock");
    }

    #[test]
    fn completed_sends_the_event_ignores_the_reply_and_restarts_the_clock() {
        let t0 = Instant::now();
        let client = Scripted::default();
        client.reply(&["10.0.0.1:1"], &["http://t0/announce"], Some(900));
        let mut a = announcer(&client, 1, None, t0);

        a.completed(secs(t0, 100), TransferTotals { uploaded: 5, downloaded: 6, left: 0 });

        let seen = client.seen.borrow();
        assert_eq!((seen[0].event, seen[0].left), (Some(Event::Completed), 0));
        assert_eq!(a.trackers_ok(), 0, "the reply is not used");
        assert!(a.is_due(secs(t0, 100 + 120), false), "and its interval isn't adopted");
        assert!(!a.is_due(secs(t0, 100 + 119), false));
    }

    #[test]
    fn a_lowered_floor_applies_to_starvation_adopted_and_fixed_intervals() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let client = Scripted::default();
        client.reply(&[], &[], Some(0));

        // Starved: the wait is the floor itself.
        let mut a = announcer(&client, 1, None, t0).with_floor(ms(50));
        assert!(!a.is_due(t0 + ms(49), true));
        assert!(a.is_due(t0 + ms(50), true));

        // A tracker interval below the floor is raised to the (lowered) floor.
        a.start(t0, totals(), |_| {});
        assert!(!a.is_due(t0 + ms(49), false));
        assert!(a.is_due(t0 + ms(50), false));

        // So is a fixed one.
        let b = announcer(&client, 1, Some(0), t0).with_floor(ms(70));
        assert!(!b.is_due(t0 + ms(69), false));
        assert!(b.is_due(t0 + ms(70), false));
    }

    #[test]
    fn restart_clock_moves_the_next_due_time() {
        let t0 = Instant::now();
        let client = Scripted::default();
        let mut a = announcer(&client, 1, None, t0);
        a.restart_clock(secs(t0, 500));
        assert!(!a.is_due(secs(t0, 500 + 119), false));
        assert!(a.is_due(secs(t0, 500 + 120), false));
    }

    #[test]
    fn requests_carry_the_torrent_identity_and_port() {
        let t0 = Instant::now();
        let client = Scripted::default();
        let mut a = announcer(&client, 1, None, t0);
        a.start(t0, totals(), |_| {});
        let seen = client.seen.borrow();
        assert_eq!((seen[0].info_hash, seen[0].peer_id, seen[0].port), ([1; 20], [2; 20], 6881));
    }

    // ---- tiers (BEP 12) ----------------------------------------------------

    /// A client that answers for the trackers it is told are up, recording each announce it gets in order.
    #[derive(Default)]
    struct UpDown {
        up: RefCell<Vec<String>>,
        asked: RefCell<Vec<(Vec<String>, Option<Event>)>>,
    }

    impl UpDown {
        fn with_up(up: &[&str]) -> UpDown {
            UpDown { up: RefCell::new(up.iter().map(|u| u.to_string()).collect()), ..Default::default() }
        }

        fn asked_urls(&self) -> Vec<Vec<String>> {
            self.asked.borrow().iter().map(|(urls, _)| urls.clone()).collect()
        }
    }

    impl TrackerClient for &UpDown {
        fn announce(&self, urls: &[String], req: &AnnounceRequest) -> Round {
            self.asked.borrow_mut().push((urls.to_vec(), req.event));
            let (mut peers, mut failed) = (Vec::new(), Vec::new());
            for url in urls {
                if self.up.borrow().contains(url) {
                    peers.push(format!("10.0.0.{}:6881", url.len()).parse().unwrap());
                } else {
                    failed.push(TrackerAttempt { url: url.clone(), error: "down".to_string() });
                }
            }
            (peers, failed, Some(900))
        }
    }

    fn tiered<'a>(client: &'a UpDown, tiers: &[&[&str]], mode: TrackerMode, now: Instant) -> Announcer<&'a UpDown> {
        let tiers = tiers.iter().map(|tier| tier.iter().map(|u| u.to_string()).collect()).collect();
        Announcer::with_client_tiers(client, tiers, mode, [1; 20], [2; 20], 6881, None, now)
    }

    #[test]
    fn a_tiered_announcer_asks_one_tracker_and_no_more_when_the_first_answers() {
        let t0 = Instant::now();
        let client = UpDown::with_up(&["http://a/", "http://b/", "http://c/"]);
        let mut a = tiered(&client, &[&["http://a/", "http://b/"], &["http://c/"]], TrackerMode::Tiered, t0);

        let peers = a.start(t0, totals(), |_| {});

        assert_eq!(client.asked_urls(), vec![vec!["http://a/".to_string()]], "one tracker, not the second of its tier, not the next tier");
        assert_eq!(peers.len(), 1);
        assert_eq!((a.trackers_ok(), a.tracker_count()), (1, 3));
    }

    #[test]
    fn a_tracker_that_fails_is_passed_over_and_the_one_that_answered_is_asked_first_from_then_on() {
        let t0 = Instant::now();
        let client = UpDown::with_up(&["http://b/"]);
        let mut a = tiered(&client, &[&["http://a/", "http://b/"]], TrackerMode::Tiered, t0);
        let log = std::cell::RefCell::new(Vec::new());

        a.start(t0, totals(), |m| log.borrow_mut().push(m));
        a.reannounce(secs(t0, 200), totals(), |_| {});

        assert_eq!(client.asked_urls(), vec![vec!["http://a/".to_string()], vec!["http://b/".to_string()], vec!["http://b/".to_string()]], "a, then b; and next time b at once");
        assert!(log.borrow().iter().any(|m| m.contains("http://a/") && m.contains("down")), "the failure is reported: {:?}", log.borrow());
    }

    #[test]
    fn the_next_tier_is_asked_only_when_the_whole_tier_before_it_failed() {
        let t0 = Instant::now();
        let client = UpDown::with_up(&["http://c/"]);
        let mut a = tiered(&client, &[&["http://a/", "http://b/"], &["http://c/"]], TrackerMode::Tiered, t0);
        let peers = a.start(t0, totals(), |_| {});
        assert_eq!(client.asked_urls().concat(), vec!["http://a/", "http://b/", "http://c/"]);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn with_no_tracker_answering_nothing_is_found_and_none_is_ok() {
        let t0 = Instant::now();
        let client = UpDown::with_up(&[]);
        let mut a = tiered(&client, &[&["http://a/"], &["http://b/"]], TrackerMode::Tiered, t0);
        assert!(a.start(t0, totals(), |_| {}).is_empty());
        assert_eq!(a.trackers_ok(), 0);
    }

    #[test]
    fn a_tiered_announcer_tells_only_the_tracker_that_answered_of_completion_and_leaving() {
        let t0 = Instant::now();
        let client = UpDown::with_up(&["http://b/"]);
        let mut a = tiered(&client, &[&["http://a/", "http://b/"], &["http://c/"]], TrackerMode::Tiered, t0);
        // Before any has answered there is nobody to tell.
        a.stopped(totals(), Duration::from_secs(1));
        a.completed(t0, totals());
        assert!(client.asked.borrow().is_empty());

        a.start(t0, totals(), |_| {});
        client.asked.borrow_mut().clear();
        a.completed(secs(t0, 5), totals());
        a.stopped(totals(), Duration::from_secs(1));

        let asked = client.asked.borrow();
        assert_eq!(*asked, vec![(vec!["http://b/".to_string()], Some(Event::Completed)), (vec!["http://b/".to_string()], Some(Event::Stopped))]);
    }

    #[test]
    fn a_concurrent_announcer_asks_every_tracker_of_every_tier_once_in_one_round_and_tells_them_all() {
        let t0 = Instant::now();
        let client = UpDown::with_up(&["http://a/", "http://c/"]);
        let mut a = tiered(&client, &[&["http://a/", "http://b/"], &["http://c/", "http://a/"]], TrackerMode::Concurrent, t0);
        assert_eq!(a.tracker_count(), 3, "a tracker in two tiers is one tracker");

        let peers = a.start(t0, totals(), |_| {});
        a.stopped(totals(), Duration::from_secs(1));

        assert_eq!(client.asked_urls(), vec![vec!["http://a/", "http://b/", "http://c/"], vec!["http://a/", "http://b/", "http://c/"]], "all at once, both times");
        assert_eq!((peers.len(), a.trackers_ok()), (2, 2));
    }

    #[test]
    fn empty_tiers_are_no_trackers() {
        let client = UpDown::default();
        let a = tiered(&client, &[&[], &[]], TrackerMode::Tiered, Instant::now());
        assert!(!a.has_trackers());
        assert_eq!(a.tracker_count(), 0);
    }
}
