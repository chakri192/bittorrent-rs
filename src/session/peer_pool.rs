//! The set of peer addresses a session knows about, and the queue of the
//! ones not yet dialed.

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;

/// One dial queue fed by every discovery source (tracker, DHT, PEX,
/// magnet bootstrap). It remembers every address ever seen so a peer is
/// dialed at most once, and holds the ones not yet dialed in arrival
/// order.
pub struct PeerPool {
    known: HashSet<SocketAddr>,
    reserve: VecDeque<SocketAddr>,
    /// When false, IPv6 peer addresses are dropped on arrival rather than
    /// wasting a dial slot on an unroutable host.
    allow_ipv6: bool,
    /// Count of IPv6 addresses dropped for lack of a route (diagnostics).
    skipped_ipv6: usize,
}

impl PeerPool {
    pub fn new(allow_ipv6: bool) -> Self {
        PeerPool { known: HashSet::new(), reserve: VecDeque::new(), allow_ipv6, skipped_ipv6: 0 }
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

    pub fn next_to_dial(&mut self) -> Option<SocketAddr> {
        self.reserve.pop_front()
    }

    pub fn reserve_is_empty(&self) -> bool {
        self.reserve.is_empty()
    }

    /// Addresses handed out by `next_to_dial` so far.
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
        assert_eq!(pool.next_to_dial(), Some(v4("10.0.0.1:6881")));
        assert_eq!(pool.dialed(), 1);
        assert!(pool.reserve_is_empty());
    }

    #[test]
    fn pool_drops_ipv6_when_disallowed_and_counts_it() {
        let mut pool = PeerPool::new(false);
        let added = pool.add([v4("10.0.0.1:6881"), v6("[2001:db8::1]:6881"), v6("[2001:db8::2]:51413")]);
        assert_eq!(added, 1, "only the v4 peer is queued");
        assert_eq!(pool.skipped_ipv6(), 2);
        assert_eq!(pool.next_to_dial(), Some(v4("10.0.0.1:6881")));
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
        assert_eq!(pool.next_to_dial(), Some(v4("10.0.0.1:6881")));
        assert_eq!(pool.add([v4("10.0.0.1:6881")]), 0, "a re-announce of a dialed peer is not new");
        assert!(pool.reserve_is_empty());
        assert_eq!(pool.known_count(), 1);
    }

    #[test]
    fn peers_are_dialed_in_arrival_order() {
        let mut pool = PeerPool::new(true);
        pool.add([v4("10.0.0.3:1"), v4("10.0.0.1:1"), v4("10.0.0.2:1")]);
        let order: Vec<_> = std::iter::from_fn(|| pool.next_to_dial()).collect();
        assert_eq!(order, vec![v4("10.0.0.3:1"), v4("10.0.0.1:1"), v4("10.0.0.2:1")]);
    }
}
