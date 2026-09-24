//! What each connected peer is doing, for the dashboard's peer table.
//!
//! Every peer worker registers here for as long as its connection lasts and
//! keeps a few numbers current: what it is doing, and how many bytes it has
//! received. The session reads them once a tick. Nothing here affects the
//! download; it is a window onto it.

use crate::sync::lock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// What a peer's worker is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// Dialing, handshaking, waiting to be unchoked for the first time.
    Connecting,
    /// Unchoked and fetching, or about to.
    Downloading,
    /// The peer has us choked.
    Choked,
    /// Connected and unchoked, but with nothing we still need.
    Idle,
}

impl Activity {
    pub fn label(self) -> &'static str {
        match self {
            Activity::Connecting => "connecting",
            Activity::Downloading => "downloading",
            Activity::Choked => "choked",
            Activity::Idle => "idle",
        }
    }

    fn from_u8(n: u8) -> Activity {
        match n {
            1 => Activity::Downloading,
            2 => Activity::Choked,
            3 => Activity::Idle,
            _ => Activity::Connecting,
        }
    }
}

/// One peer's numbers. Written by its worker, read by the session.
#[derive(Debug)]
pub struct PeerStat {
    activity: AtomicU8,
    bytes: AtomicU64,
    /// (bytes at the last reading, when, smoothed rate) for `rows`.
    sample: Mutex<(u64, Instant, f64)>,
}

impl PeerStat {
    fn new(now: Instant) -> Self {
        PeerStat { activity: AtomicU8::new(0), bytes: AtomicU64::new(0), sample: Mutex::new((0, now, 0.0)) }
    }

    pub fn set(&self, activity: Activity) {
        self.activity.store(activity as u8, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, n: usize) {
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// One line of the peer table.
#[derive(Debug, Clone, PartialEq)]
pub struct PeerRow {
    pub addr: String,
    pub activity: &'static str,
    /// Bytes per second, smoothed over the last few readings.
    pub rate: f64,
    /// Bytes received from it on this connection.
    pub bytes: u64,
}

/// The connected peers, by address.
#[derive(Debug, Default)]
pub struct PeerRegistry {
    peers: Mutex<HashMap<SocketAddr, Arc<PeerStat>>>,
}

/// A peer's entry, removed when dropped.
pub struct PeerEntry<'a> {
    registry: &'a PeerRegistry,
    addr: SocketAddr,
    pub stat: Arc<PeerStat>,
}

impl Drop for PeerEntry<'_> {
    fn drop(&mut self) {
        let mut peers = lock(&self.registry.peers);
        // Only if it is still this entry: an address is dialed again after
        // a retry, and the new connection must not lose its row to the
        // old one's cleanup.
        if peers.get(&self.addr).is_some_and(|current| Arc::ptr_eq(current, &self.stat)) {
            peers.remove(&self.addr);
        }
    }
}

impl PeerRegistry {
    /// Registers a connection to `addr`, connecting.
    pub fn enter(&self, addr: SocketAddr, now: Instant) -> PeerEntry<'_> {
        let stat = Arc::new(PeerStat::new(now));
        lock(&self.peers).insert(addr, Arc::clone(&stat));
        PeerEntry { registry: self, addr, stat }
    }

    /// The table as of `now`, fastest first (then by address, so the order
    /// is steady). Reading advances each peer's rate sample, so call it
    /// about once per refresh.
    pub fn rows(&self, now: Instant) -> Vec<PeerRow> {
        let peers = lock(&self.peers);
        let mut rows: Vec<PeerRow> = peers
            .iter()
            .map(|(addr, stat)| {
                let bytes = stat.bytes.load(Ordering::Relaxed);
                let mut sample = lock(&stat.sample);
                let elapsed = now.saturating_duration_since(sample.1).as_secs_f64();
                if elapsed > 0.0 {
                    let instant_rate = bytes.saturating_sub(sample.0) as f64 / elapsed;
                    // Half old, half new: steady enough to read, quick
                    // enough to follow a peer that has stopped.
                    sample.2 = if sample.0 == 0 && sample.2 == 0.0 { instant_rate } else { 0.5 * sample.2 + 0.5 * instant_rate };
                    *sample = (bytes, now, sample.2);
                }
                PeerRow { addr: addr.to_string(), activity: Activity::from_u8(stat.activity.load(Ordering::Relaxed)).label(), rate: sample.2, bytes }
            })
            .collect();
        rows.sort_by(|a, b| b.rate.total_cmp(&a.rate).then_with(|| a.addr.cmp(&b.addr)));
        rows
    }

    pub fn len(&self) -> usize {
        lock(&self.peers).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether a connection to `addr` is currently registered.
    pub fn contains(&self, addr: &SocketAddr) -> bool {
        lock(&self.peers).contains_key(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn addr(last: u8) -> SocketAddr {
        format!("10.0.0.{}:6881", last).parse().unwrap()
    }

    #[test]
    fn a_registered_peer_appears_as_connecting_and_leaves_when_its_entry_is_dropped() {
        let registry = PeerRegistry::default();
        let t0 = Instant::now();
        assert!(registry.is_empty());

        let entry = registry.enter(addr(1), t0);
        let rows = registry.rows(t0);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].addr.as_str(), rows[0].activity, rows[0].bytes), ("10.0.0.1:6881", "connecting", 0));
        assert!(registry.contains(&addr(1)));
        assert!(!registry.contains(&addr(2)));

        drop(entry);
        assert!(registry.is_empty(), "the connection ended, so does its row");
        assert!(!registry.contains(&addr(1)));
    }

    #[test]
    fn the_activity_and_the_bytes_are_what_the_worker_last_said() {
        let registry = PeerRegistry::default();
        let t0 = Instant::now();
        let entry = registry.enter(addr(1), t0);

        entry.stat.set(Activity::Downloading);
        entry.stat.add_bytes(16384);
        entry.stat.add_bytes(16384);
        let rows = registry.rows(t0 + Duration::from_secs(1));
        assert_eq!((rows[0].activity, rows[0].bytes), ("downloading", 32768));

        entry.stat.set(Activity::Choked);
        assert_eq!(registry.rows(t0 + Duration::from_secs(2))[0].activity, "choked");
        entry.stat.set(Activity::Idle);
        assert_eq!(registry.rows(t0 + Duration::from_secs(3))[0].activity, "idle");
    }

    #[test]
    fn the_rate_is_bytes_since_the_last_reading_over_the_time_between_and_smoothed() {
        let registry = PeerRegistry::default();
        let t0 = Instant::now();
        let entry = registry.enter(addr(1), t0);

        entry.stat.add_bytes(1000);
        let first = registry.rows(t0 + Duration::from_secs(1))[0].rate;
        assert_eq!(first, 1000.0, "the first reading is taken as it is");

        // Nothing more arrives for a second: the rate halves, not drops to zero.
        let second = registry.rows(t0 + Duration::from_secs(2))[0].rate;
        assert_eq!(second, 500.0);
        entry.stat.add_bytes(3000);
        let third = registry.rows(t0 + Duration::from_secs(3))[0].rate;
        assert_eq!(third, 0.5 * 500.0 + 0.5 * 3000.0);
    }

    #[test]
    fn reading_twice_at_the_same_instant_changes_nothing() {
        let registry = PeerRegistry::default();
        let t0 = Instant::now();
        let entry = registry.enter(addr(1), t0);
        entry.stat.add_bytes(500);
        let at = t0 + Duration::from_secs(1);
        assert_eq!(registry.rows(at)[0].rate, registry.rows(at)[0].rate);
    }

    #[test]
    fn rows_come_fastest_first_and_ties_by_address() {
        let registry = PeerRegistry::default();
        let t0 = Instant::now();
        let slow = registry.enter(addr(3), t0);
        let fast = registry.enter(addr(2), t0);
        let idle_b = registry.enter(addr(9), t0);
        let idle_a = registry.enter(addr(1), t0);
        slow.stat.add_bytes(100);
        fast.stat.add_bytes(9000);

        let rows = registry.rows(t0 + Duration::from_secs(1));

        let order: Vec<&str> = rows.iter().map(|r| r.addr.as_str()).collect();
        assert_eq!(order, vec!["10.0.0.2:6881", "10.0.0.3:6881", "10.0.0.1:6881", "10.0.0.9:6881"]);
        drop((idle_a, idle_b));
    }

    #[test]
    fn a_reconnection_to_the_same_address_is_not_removed_by_the_old_ones_cleanup() {
        let registry = PeerRegistry::default();
        let t0 = Instant::now();
        let old = registry.enter(addr(1), t0);
        let new = registry.enter(addr(1), t0); // the address dialed again before the old thread finished
        new.stat.set(Activity::Downloading);

        drop(old);

        let rows = registry.rows(t0);
        assert_eq!(rows.len(), 1, "the new connection keeps its row");
        assert_eq!(rows[0].activity, "downloading");
        drop(new);
        assert!(registry.is_empty());
    }
}
