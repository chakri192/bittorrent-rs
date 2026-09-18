//! Talking to a torrent's trackers over the life of a session: the first
//! announce, the periodic re-announces, and the final "completed".

use crate::tracker::{AnnounceRequest, Event};
use crate::tracker_discovery::{announce_to_all, build_request, TrackerAttempt, TransferTotals};
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
}

/// Announces over HTTP, HTTPS and UDP, all trackers concurrently.
pub struct NetworkTrackers;

impl TrackerClient for NetworkTrackers {
    fn announce(&self, urls: &[String], req: &AnnounceRequest) -> Round {
        announce_to_all(urls, req)
    }
}

/// Announce schedule and bookkeeping for one torrent.
///
/// With no trackers every announce is a no-op that finds nothing, but the
/// schedule still runs: a DHT-only or web-seed-only session paces its own
/// housekeeping off the same clock.
pub struct Announcer<C: TrackerClient = NetworkTrackers> {
    client: C,
    urls: Vec<String>,
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
    pub fn new(urls: Vec<String>, info_hash: [u8; 20], peer_id: [u8; 20], port: u16, fixed_interval: Option<Duration>, now: Instant) -> Self {
        Announcer::with_client(NetworkTrackers, urls, info_hash, peer_id, port, fixed_interval, now)
    }
}

impl<C: TrackerClient> Announcer<C> {
    pub fn with_client(client: C, urls: Vec<String>, info_hash: [u8; 20], peer_id: [u8; 20], port: u16, fixed_interval: Option<Duration>, now: Instant) -> Self {
        Announcer {
            client,
            urls,
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
        !self.urls.is_empty()
    }

    pub fn tracker_count(&self) -> usize {
        self.urls.len()
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
        if self.urls.is_empty() {
            return;
        }
        let req = build_request(self.info_hash, self.peer_id, self.port, totals, Some(Event::Completed));
        let _ = self.client.announce(&self.urls, &req);
    }

    /// Restarts the re-announce clock without announcing, for when a
    /// session enters a new phase (seeding) with its own cadence.
    pub fn restart_clock(&mut self, now: Instant) {
        self.last_at = now;
    }

    fn round(&mut self, now: Instant, totals: TransferTotals, event: Option<Event>, log: impl Fn(String)) -> Vec<SocketAddr> {
        self.last_at = now;
        if self.urls.is_empty() {
            return Vec::new();
        }
        let req = build_request(self.info_hash, self.peer_id, self.port, totals, event);
        let (peers, failures, interval) = self.client.announce(&self.urls, &req);
        self.trackers_ok = self.urls.len().saturating_sub(failures.len());
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
}
