//! Kademlia-style routing table (BEP 5): nodes bucketed by the length of
//! their common id-prefix with ours, k=8 per bucket.
//!
//! Simplifications vs. a full mainline implementation, chosen because
//! this table only ever ingests nodes that just *responded* to us (we
//! never insert hearsay nodes from other nodes' `nodes` lists without
//! contact), which keeps it naturally fresh:
//!  - fixed 160 buckets indexed by common-prefix length, rather than a
//!    dynamically-splitting bucket tree (same lookup behavior, simpler
//!    structure);
//!  - a full bucket evicts its least-recently-seen member instead of
//!    ping-testing it first (the evicted node earns its way back in by
//!    answering a future query).

use crate::dht::krpc::{CompactNode, NodeId};
use std::net::SocketAddr;
use std::time::Instant;

pub const K: usize = 8;

/// XOR metric (Kademlia): distance between two ids, byte-wise.
pub fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Index of the bucket a node with `other` belongs to, relative to
/// `self_id`: the number of leading bits the two ids share (0..=159).
/// `None` when the ids are identical (a node never stores itself).
pub fn bucket_index(self_id: &NodeId, other: &NodeId) -> Option<usize> {
    let d = xor_distance(self_id, other);
    for (byte_idx, byte) in d.iter().enumerate() {
        if *byte != 0 {
            return Some(byte_idx * 8 + byte.leading_zeros() as usize);
        }
    }
    None
}

#[derive(Debug, Clone)]
struct Entry {
    node: CompactNode,
    last_seen: Instant,
}

pub struct RoutingTable {
    self_id: NodeId,
    buckets: Vec<Vec<Entry>>,
}

impl RoutingTable {
    pub fn new(self_id: NodeId) -> Self {
        RoutingTable { self_id, buckets: vec![Vec::new(); 160] }
    }

    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records a node that just responded to (or validly queried) us.
    /// Re-inserting an existing id refreshes its address and timestamp.
    pub fn insert(&mut self, id: NodeId, addr: SocketAddr) {
        let Some(idx) = bucket_index(&self.self_id, &id) else {
            return; // our own id
        };
        let bucket = &mut self.buckets[idx];
        if let Some(existing) = bucket.iter_mut().find(|e| e.node.id == id) {
            existing.node.addr = addr;
            existing.last_seen = Instant::now();
            return;
        }
        let entry = Entry { node: CompactNode { id, addr }, last_seen: Instant::now() };
        if bucket.len() < K {
            bucket.push(entry);
            return;
        }
        // Full: evict the least-recently-seen occupant.
        if let Some(oldest) = bucket.iter_mut().min_by_key(|e| e.last_seen) {
            *oldest = entry;
        }
    }

    /// The up-to-`n` known nodes closest (XOR metric) to `target`.
    pub fn closest(&self, target: &NodeId, n: usize) -> Vec<CompactNode> {
        let mut all: Vec<&Entry> = self.buckets.iter().flatten().collect();
        all.sort_by_key(|e| xor_distance(&e.node.id, target));
        all.into_iter().take(n).map(|e| e.node.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(first: u8) -> NodeId {
        let mut id = [0u8; 20];
        id[0] = first;
        id
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], port))
    }

    #[test]
    fn xor_distance_is_zero_for_identical_and_symmetric() {
        let a = nid(0xAB);
        let b = nid(0x13);
        assert_eq!(xor_distance(&a, &a), [0u8; 20]);
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn bucket_index_counts_shared_prefix_bits() {
        let me = [0u8; 20];
        assert_eq!(bucket_index(&me, &nid(0b1000_0000)), Some(0)); // differ at bit 0
        assert_eq!(bucket_index(&me, &nid(0b0000_0001)), Some(7)); // differ at bit 7
        let mut far = [0u8; 20];
        far[19] = 1;
        assert_eq!(bucket_index(&me, &far), Some(159)); // differ at the very last bit
        assert_eq!(bucket_index(&me, &me), None);
    }

    #[test]
    fn insert_refreshes_existing_node_instead_of_duplicating() {
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(nid(1), addr(1000));
        rt.insert(nid(1), addr(2000)); // same id, new address
        assert_eq!(rt.len(), 1);
        let got = rt.closest(&nid(1), 1);
        assert_eq!(got[0].addr, addr(2000));
    }

    #[test]
    fn full_bucket_evicts_least_recently_seen() {
        let mut rt = RoutingTable::new([0u8; 20]);
        // All these share bucket 7 (first byte 0b0000_0001 pattern varies
        // in later bytes): construct K+1 ids differing only in byte 1,
        // all with first byte 0x01 -> same common-prefix length 7.
        for i in 0..=K as u8 {
            let mut id = [0u8; 20];
            id[0] = 0x01;
            id[1] = i;
            rt.insert(id, addr(1000 + i as u16));
            std::thread::sleep(std::time::Duration::from_millis(2)); // strictly ordered last_seen
        }
        // K+1 inserts into one bucket -> still K entries, and the very
        // first inserted (oldest) is the one gone.
        assert_eq!(rt.len(), K);
        let survivors = rt.closest(&[0u8; 20], K + 1);
        assert!(!survivors.iter().any(|n| n.addr == addr(1000)), "oldest entry should have been evicted");
    }

    #[test]
    fn closest_orders_by_xor_distance_to_target() {
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(nid(0x10), addr(1));
        rt.insert(nid(0x11), addr(2));
        rt.insert(nid(0xF0), addr(3));
        let target = nid(0x11);
        let got = rt.closest(&target, 3);
        assert_eq!(got[0].id, nid(0x11)); // exact match first
        assert_eq!(got[1].id, nid(0x10)); // 1 bit off
        assert_eq!(got[2].id, nid(0xF0)); // way off
    }

    #[test]
    fn never_stores_our_own_id() {
        let me = nid(0x42);
        let mut rt = RoutingTable::new(me);
        rt.insert(me, addr(1));
        assert!(rt.is_empty());
    }

    #[test]
    fn ipv6_nodes_are_kept_like_any_other_and_found_by_distance() {
        let mut rt = RoutingTable::new([0u8; 20]);
        let a: SocketAddr = "[2001:db8::1]:6881".parse().unwrap();
        let b: SocketAddr = "[2001:db8::2]:6881".parse().unwrap();
        rt.insert(nid(0x10), a);
        rt.insert(nid(0xF0), b);
        let got = rt.closest(&nid(0x11), 2);
        assert_eq!((got[0].addr, got[1].addr), (a, b));
        rt.insert(nid(0x10), b); // the same id, from a new address
        assert_eq!(rt.len(), 2);
        assert_eq!(rt.closest(&nid(0x10), 1)[0].addr, b);
    }
}
