//! The set of peer addresses a session knows about, the queue of the ones
//! not yet dialed, and what became of the ones that were.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How a connection to a peer ended, as far as the pool is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The worker finished cleanly (the queue drained). Nothing to hold
    /// against the peer, nothing to retry.
    Finished,
    /// The connection could not be made.
    Unreachable,
    /// It connected and then failed: dropped, timed out, or gave nothing
    /// useful. Often transient.
    Dropped,
    /// The peer sent a piece that failed verification.
    BadData,
    /// Our own fault (a disk error): says nothing about the peer.
    Local,
}

/// How long to wait before each retry of a peer, by how many times it has
/// failed. Growing delays keep a peer that is down from being hammered,
/// and running out of them gives it up.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Delays before the 1st, 2nd, ... retry of a peer that connected and
    /// then dropped us.
    pub after_drop: Vec<Duration>,
    /// The same for a peer we could not connect to at all (usually behind
    /// a NAT or gone, so fewer tries).
    pub after_unreachable: Vec<Duration>,
}

impl RetryPolicy {
    /// The standard schedule with `base` as the first delay: `base`, 3x,
    /// 9x for a drop; `base`, 3x for an unreachable peer.
    pub fn with_base(base: Duration) -> Self {
        RetryPolicy { after_drop: vec![base, base * 3, base * 9], after_unreachable: vec![base, base * 3] }
    }

    /// Never retry anyone.
    pub fn none() -> Self {
        RetryPolicy { after_drop: Vec::new(), after_unreachable: Vec::new() }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::with_base(Duration::from_secs(15))
    }
}

/// What the pool has learned about one peer.
#[derive(Default)]
struct Record {
    drops: usize,
    unreachable: usize,
    banned: bool,
}

/// One dial queue fed by every discovery source (tracker, DHT, PEX,
/// magnet bootstrap). It remembers every address ever seen, so a peer that
/// is announced again is not queued twice, and holds the ones not yet
/// dialed in arrival order. A peer that fails is retried after a growing
/// delay, up to a limit; one that sends bad data is banned for the session.
pub struct PeerPool {
    known: HashSet<SocketAddr>,
    reserve: VecDeque<SocketAddr>,
    /// Peers waiting out a delay before their next attempt.
    retry: Vec<(SocketAddr, Instant)>,
    records: HashMap<SocketAddr, Record>,
    policy: RetryPolicy,
    /// When false, IPv6 peer addresses are dropped on arrival rather than
    /// wasting a dial slot on an unroutable host.
    allow_ipv6: bool,
    /// Count of IPv6 addresses dropped for lack of a route (diagnostics).
    skipped_ipv6: usize,
}

impl PeerPool {
    pub fn new(allow_ipv6: bool) -> Self {
        Self::with_policy(allow_ipv6, RetryPolicy::default())
    }

    pub fn with_policy(allow_ipv6: bool, policy: RetryPolicy) -> Self {
        PeerPool { known: HashSet::new(), reserve: VecDeque::new(), retry: Vec::new(), records: HashMap::new(), policy, allow_ipv6, skipped_ipv6: 0 }
    }

    /// Queues every address not seen before and returns how many were new.
    /// Port 0 is never dialable; IPv6 is dropped unless allowed.
    pub fn add(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) -> usize {
        let mut fresh = 0;
        for addr in addrs {
            if addr.port() == 0 {
                continue;
            }
            if addr.is_ipv6() && !self.allow_ipv6 {
                self.skipped_ipv6 += 1;
                continue;
            }
            if self.known.insert(addr) {
                self.reserve.push_back(addr);
                fresh += 1;
            }
        }
        fresh
    }

    /// The next peer to dial at `now`: a never-dialed one if any, else one
    /// whose retry delay has passed.
    pub fn next_to_dial(&mut self, now: Instant) -> Option<SocketAddr> {
        if let Some(addr) = self.reserve.pop_front() {
            return Some(addr);
        }
        let due = self.retry.iter().position(|&(_, at)| at <= now)?;
        Some(self.retry.swap_remove(due).0)
    }

    /// Records how a connection to `addr` ended, at `now`, and schedules a
    /// retry or a ban accordingly. Returns what was decided.
    pub fn record_outcome(&mut self, addr: SocketAddr, outcome: Outcome, now: Instant) -> Decision {
        let record = self.records.entry(addr).or_default();
        let (failures, delays) = match outcome {
            Outcome::Finished | Outcome::Local => return Decision::NoRetry,
            Outcome::BadData => {
                record.banned = true;
                self.retry.retain(|&(a, _)| a != addr);
                return Decision::Banned;
            }
            Outcome::Dropped => {
                record.drops += 1;
                (record.drops, &self.policy.after_drop)
            }
            Outcome::Unreachable => {
                record.unreachable += 1;
                (record.unreachable, &self.policy.after_unreachable)
            }
        };
        match delays.get(failures - 1) {
            Some(&delay) if !record.banned => {
                self.retry.push((addr, now + delay));
                Decision::RetryIn(delay)
            }
            _ => Decision::GiveUp,
        }
    }

    /// Whether nothing is waiting to be dialed, now or after a delay. A
    /// peer waiting out a retry keeps the swarm alive: it is not dead yet.
    pub fn reserve_is_empty(&self) -> bool {
        self.reserve.is_empty() && self.retry.is_empty()
    }

    /// Peers banned for sending bad data.
    pub fn banned_count(&self) -> usize {
        self.records.values().filter(|r| r.banned).count()
    }

    /// Whether `addr` is banned.
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        self.records.get(addr).is_some_and(|r| r.banned)
    }

    /// Distinct peers dialed at least once: known, and no longer waiting
    /// for a first dial.
    pub fn dialed(&self) -> usize {
        self.known.len() - self.reserve.len()
    }

    /// Distinct addresses accepted so far, dialed or not.
    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    /// IPv6 addresses dropped because `allow_ipv6` was false.
    pub fn skipped_ipv6(&self) -> usize {
        self.skipped_ipv6
    }
}

/// What the pool decided about a peer after an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Nothing to do: not a failure, or not the peer's fault.
    NoRetry,
    /// It will be dialed again after this delay.
    RetryIn(Duration),
    /// It has failed too often; it will not be dialed again.
    GiveUp,
    /// It sent bad data and is banned for the session.
    Banned,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pool_dedups_and_skips_port_zero() {
        let mut pool = PeerPool::new(true);
        let added = pool.add([v4("10.0.0.1:6881"), v4("10.0.0.1:6881"), v4("10.0.0.2:0")]);
        assert_eq!(added, 1, "duplicate collapses, port-0 is dropped");
        assert_eq!(pool.dialed(), 0);
        assert_eq!(pool.next_to_dial(Instant::now()), Some(v4("10.0.0.1:6881")));
        assert_eq!(pool.dialed(), 1);
        assert!(pool.reserve_is_empty());
    }

    #[test]
    fn pool_drops_ipv6_when_disallowed_and_counts_it() {
        let mut pool = PeerPool::new(false);
        let added = pool.add([v4("10.0.0.1:6881"), v6("[2001:db8::1]:6881"), v6("[2001:db8::2]:51413")]);
        assert_eq!(added, 1, "only the v4 peer is queued");
        assert_eq!(pool.skipped_ipv6(), 2);
        assert_eq!(pool.next_to_dial(Instant::now()), Some(v4("10.0.0.1:6881")));
        assert!(pool.reserve_is_empty());
    }

    #[test]
    fn pool_keeps_ipv6_when_allowed() {
        let mut pool = PeerPool::new(true);
        let added = pool.add([v6("[2001:db8::1]:6881")]);
        assert_eq!(added, 1);
        assert_eq!(pool.skipped_ipv6(), 0);
    }

    #[test]
    fn an_address_dialed_once_is_never_queued_again() {
        let mut pool = PeerPool::new(true);
        pool.add([v4("10.0.0.1:6881")]);
        assert_eq!(pool.next_to_dial(Instant::now()), Some(v4("10.0.0.1:6881")));
        assert_eq!(pool.add([v4("10.0.0.1:6881")]), 0, "a re-announce of a dialed peer is not new");
        assert!(pool.reserve_is_empty());
        assert_eq!(pool.known_count(), 1);
    }

    #[test]
    fn peers_are_dialed_in_arrival_order() {
        let mut pool = PeerPool::new(true);
        pool.add([v4("10.0.0.3:1"), v4("10.0.0.1:1"), v4("10.0.0.2:1")]);
        let order: Vec<_> = std::iter::from_fn(|| pool.next_to_dial(Instant::now())).collect();
        assert_eq!(order, vec![v4("10.0.0.3:1"), v4("10.0.0.1:1"), v4("10.0.0.2:1")]);
    }

    // ---- retry and ban ---------------------------------------------------

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn policy() -> RetryPolicy {
        RetryPolicy::with_base(secs(10)) // drop: 10, 30, 90; unreachable: 10, 30
    }

    /// A pool with one peer already dialed, so it is the only candidate.
    fn pool_with_dialed_peer() -> (PeerPool, SocketAddr, Instant) {
        let mut pool = PeerPool::with_policy(true, policy());
        let addr = v4("10.0.0.1:6881");
        pool.add([addr]);
        let t0 = Instant::now();
        assert_eq!(pool.next_to_dial(t0), Some(addr));
        (pool, addr, t0)
    }

    #[test]
    fn a_peer_that_dropped_us_is_dialed_again_only_after_its_delay() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();

        assert_eq!(pool.record_outcome(addr, Outcome::Dropped, t0), Decision::RetryIn(secs(10)));

        assert_eq!(pool.next_to_dial(t0), None, "not yet");
        assert_eq!(pool.next_to_dial(t0 + secs(9)), None);
        assert_eq!(pool.next_to_dial(t0 + secs(10)), Some(addr), "the delay has passed");
        assert_eq!(pool.next_to_dial(t0 + secs(10)), None, "and it is out of the queue while it is being dialed");
    }

    #[test]
    fn the_delays_grow_and_then_run_out() {
        let (mut pool, addr, mut now) = pool_with_dialed_peer();
        for expected in [10, 30, 90] {
            assert_eq!(pool.record_outcome(addr, Outcome::Dropped, now), Decision::RetryIn(secs(expected)));
            now += secs(expected);
            assert_eq!(pool.next_to_dial(now), Some(addr));
        }
        assert_eq!(pool.record_outcome(addr, Outcome::Dropped, now), Decision::GiveUp, "a fourth drop is the last");
        assert_eq!(pool.next_to_dial(now + secs(10_000)), None);
    }

    #[test]
    fn an_unreachable_peer_gets_fewer_tries_than_one_that_dropped() {
        let (mut pool, addr, mut now) = pool_with_dialed_peer();
        for expected in [10, 30] {
            assert_eq!(pool.record_outcome(addr, Outcome::Unreachable, now), Decision::RetryIn(secs(expected)));
            now += secs(expected);
            assert_eq!(pool.next_to_dial(now), Some(addr));
        }
        assert_eq!(pool.record_outcome(addr, Outcome::Unreachable, now), Decision::GiveUp);
    }

    #[test]
    fn bad_data_bans_the_peer_for_good() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();

        assert_eq!(pool.record_outcome(addr, Outcome::BadData, t0), Decision::Banned);

        assert!(pool.is_banned(&addr));
        assert_eq!(pool.banned_count(), 1);
        assert_eq!(pool.next_to_dial(t0 + secs(1_000_000)), None, "never redialed");
        assert_eq!(pool.add([addr]), 0, "and announcing it again does not bring it back");
        assert_eq!(pool.next_to_dial(t0 + secs(1_000_000)), None);
    }

    #[test]
    fn a_ban_cancels_a_retry_already_waiting() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();
        pool.record_outcome(addr, Outcome::Dropped, t0);
        // Another connection to the same peer turns out to send bad data.
        pool.record_outcome(addr, Outcome::BadData, t0 + secs(1));
        assert_eq!(pool.next_to_dial(t0 + secs(1000)), None);
        assert!(pool.reserve_is_empty());
    }

    #[test]
    fn a_banned_peer_that_reports_another_failure_is_not_scheduled_again() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();
        pool.record_outcome(addr, Outcome::BadData, t0);
        assert_eq!(pool.record_outcome(addr, Outcome::Dropped, t0), Decision::GiveUp);
        assert_eq!(pool.next_to_dial(t0 + secs(1000)), None);
    }

    #[test]
    fn finishing_or_a_local_error_is_neither_retried_nor_held_against_the_peer() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();
        assert_eq!(pool.record_outcome(addr, Outcome::Finished, t0), Decision::NoRetry);
        assert_eq!(pool.record_outcome(addr, Outcome::Local, t0), Decision::NoRetry);
        assert_eq!(pool.next_to_dial(t0 + secs(1000)), None);
        assert!(!pool.is_banned(&addr));
    }

    #[test]
    fn a_peer_waiting_on_a_retry_keeps_the_swarm_alive_until_it_is_given_up() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();
        assert!(pool.reserve_is_empty(), "nothing waiting yet");

        pool.record_outcome(addr, Outcome::Dropped, t0);
        assert!(!pool.reserve_is_empty(), "a retry is pending, so the swarm is not dead");

        assert_eq!(pool.next_to_dial(t0 + secs(10)), Some(addr));
        assert!(pool.reserve_is_empty(), "it is being dialed, not waiting");

        let mut now = t0 + secs(10);
        for _ in 0..3 {
            pool.record_outcome(addr, Outcome::Dropped, now);
            now += secs(1000);
            let _ = pool.next_to_dial(now);
        }
        assert!(pool.reserve_is_empty(), "given up: nothing is coming");
    }

    #[test]
    fn a_never_dialed_peer_goes_before_one_that_is_due_for_a_retry() {
        let (mut pool, old, t0) = pool_with_dialed_peer();
        pool.record_outcome(old, Outcome::Dropped, t0);
        let fresh = v4("10.0.0.2:6881");
        pool.add([fresh]);

        assert_eq!(pool.next_to_dial(t0 + secs(100)), Some(fresh));
        assert_eq!(pool.next_to_dial(t0 + secs(100)), Some(old));
    }

    #[test]
    fn a_peer_announced_again_while_it_waits_is_not_queued_twice() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();
        pool.record_outcome(addr, Outcome::Dropped, t0);
        assert_eq!(pool.add([addr]), 0, "the tracker mentions it again: already known");
        assert_eq!(pool.next_to_dial(t0 + secs(10)), Some(addr));
        assert_eq!(pool.next_to_dial(t0 + secs(10)), None, "dialed once, not twice");
    }

    #[test]
    fn failures_are_counted_per_peer() {
        let mut pool = PeerPool::with_policy(true, policy());
        let (a, b) = (v4("10.0.0.1:1"), v4("10.0.0.2:1"));
        pool.add([a, b]);
        let t0 = Instant::now();
        pool.next_to_dial(t0);
        pool.next_to_dial(t0);
        pool.record_outcome(a, Outcome::Dropped, t0);
        pool.record_outcome(a, Outcome::Dropped, t0);
        assert_eq!(pool.record_outcome(b, Outcome::Dropped, t0), Decision::RetryIn(secs(10)), "b is on its first failure, whatever a has done");
    }

    #[test]
    fn a_policy_of_none_never_retries() {
        let mut pool = PeerPool::with_policy(true, RetryPolicy::none());
        let addr = v4("10.0.0.1:1");
        pool.add([addr]);
        let t0 = Instant::now();
        pool.next_to_dial(t0);
        assert_eq!(pool.record_outcome(addr, Outcome::Dropped, t0), Decision::GiveUp);
        assert_eq!(pool.record_outcome(addr, Outcome::Unreachable, t0), Decision::GiveUp);
    }

    #[test]
    fn a_retried_peer_still_counts_as_dialed_once() {
        let (mut pool, addr, t0) = pool_with_dialed_peer();
        assert_eq!(pool.dialed(), 1);
        pool.record_outcome(addr, Outcome::Dropped, t0);
        assert_eq!(pool.dialed(), 1);
        assert_eq!(pool.known_count(), 1);
    }
}
