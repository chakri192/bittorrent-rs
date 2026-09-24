//! The client side of the DHT: bootstrapping a routing table, finding the
//! peers for a torrent with an iterative Kademlia lookup, and announcing
//! ourselves to the nodes that hold its tokens.

use super::krpc::{CompactNode, NodeId, Query};
use super::routing::{xor_distance, K};
use super::store;
use super::{Dht, Transport, RECV_TICK};
use crate::bencode;
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Parallelism of the iterative lookup (Kademlia's alpha).
const ALPHA: usize = 3;
/// Hard cap on queries per lookup, so one lookup can't spray the network
/// indefinitely even against an adversarial node graph.
const MAX_LOOKUP_QUERIES: usize = 64;

/// Everything a completed lookup learned: actual peers for the torrent,
/// plus the closest nodes that handed us announce tokens.
#[derive(Debug, Default)]
pub struct LookupResult {
    pub peers: Vec<SocketAddr>,
    pub tokens: Vec<(CompactNode, Vec<u8>)>,
}

impl<T: Transport> Dht<T> {
    /// Sends `find_node(self)` to each bootstrap address, then runs a
    /// full iterative lookup toward our own id -- the canonical way to
    /// populate a fresh routing table with nodes near us.
    pub fn bootstrap(&mut self, routers: &[String], stop: &AtomicBool) {
        // A router name may resolve to both families; this node uses its own.
        let mut router_addrs: Vec<SocketAddr> = Vec::new();
        for r in routers {
            if let Ok(resolved) = r.to_socket_addrs() {
                router_addrs.extend(resolved.filter(|a| self.is_our_family(a)));
            }
        }
        let self_id = self.node_id;
        self.iterative_lookup(&self_id, &router_addrs, false, Duration::from_secs(8), stop);
    }

    /// Iterative `get_peers` for a torrent. Call after `bootstrap`.
    pub fn get_peers(&mut self, info_hash: &NodeId, deadline: Duration, stop: &AtomicBool) -> LookupResult {
        self.iterative_lookup(info_hash, &[], true, deadline, stop)
    }

    /// The Kademlia iterative lookup shared by bootstrap (`find_node`
    /// flavor) and peer search (`get_peers` flavor). Maintains a
    /// shortlist of candidates sorted by XOR distance to `target`,
    /// keeps up to `ALPHA` queries in flight toward the closest
    /// unqueried candidates, and terminates when the K closest known
    /// candidates have all been queried (or on deadline/query-budget).
    fn iterative_lookup(&mut self, target: &NodeId, extra_seeds: &[SocketAddr], want_peers: bool, deadline: Duration, stop: &AtomicBool) -> LookupResult {
        let mut result = LookupResult::default();
        let end = Instant::now() + deadline;

        // Shortlist: distance-sorted candidates. Seeded from the routing
        // table plus any explicit seed addresses (bootstrap routers get a
        // zero id -- never inserted into the table, only queried).
        let mut candidates: Vec<CompactNode> = self.table.closest(target, K * 2);
        candidates.extend(extra_seeds.iter().map(|&addr| CompactNode { id: [0u8; 20], addr }));

        let mut queried: HashSet<SocketAddr> = HashSet::new();
        let mut seen_peers: HashSet<SocketAddr> = HashSet::new();
        let mut pending: HashMap<Vec<u8>, CompactNode> = HashMap::new();
        let mut queries_sent = 0usize;

        loop {
            if Instant::now() >= end || stop.load(Ordering::SeqCst) {
                break;
            }

            candidates.sort_by_key(|n| xor_distance(&n.id, target));
            candidates.dedup_by_key(|n| n.addr);

            // Termination: the K closest candidates are all queried and
            // nothing is still in flight -- no closer node is coming.
            let frontier_exhausted = candidates.iter().take(K).all(|n| queried.contains(&n.addr));
            if pending.is_empty() && (frontier_exhausted || candidates.is_empty()) {
                break;
            }

            // Keep ALPHA queries in flight toward the closest unqueried.
            if queries_sent < MAX_LOOKUP_QUERIES {
                let to_query: Vec<CompactNode> = candidates.iter().filter(|n| !queried.contains(&n.addr)).take(ALPHA.saturating_sub(pending.len())).cloned().collect();
                for node in to_query {
                    let q = if want_peers { Query::GetPeers { id: self.node_id, info_hash: *target } } else { Query::FindNode { id: self.node_id, target: *target } };
                    if let Ok(t) = self.send_query(q, node.addr) {
                        queried.insert(node.addr);
                        pending.insert(t, node);
                        queries_sent += 1;
                    } else {
                        queried.insert(node.addr); // unsendable address: never retry it
                    }
                }
            } else if pending.is_empty() {
                break; // budget spent and nothing left in flight
            }

            match self.transport.recv(RECV_TICK) {
                Ok(Some((data, from))) => {
                    let Some((t, response, from)) = self.handle_inbound(&data, from) else {
                        continue; // was a query (answered inline) or noise
                    };
                    let Some(asked) = pending.remove(&t) else {
                        // Response to a long-forgotten transaction; still
                        // proof of liveness.
                        self.table.insert(response.id, from);
                        continue;
                    };
                    // Responders earn a routing-table slot. Use the id
                    // *they* report with their observed address, not the
                    // (possibly zero / hearsay) id we sent to.
                    let _ = asked;
                    self.table.insert(response.id, from);

                    for peer in &response.values {
                        if seen_peers.insert(*peer) {
                            result.peers.push(*peer);
                        }
                    }
                    if let Some(token) = response.token {
                        result.tokens.push((CompactNode { id: response.id, addr: from }, token));
                    }
                    for node in response.nodes {
                        // (A node may list both families; only ours is reachable from here.)
                        if !queried.contains(&node.addr) && self.is_our_family(&node.addr) {
                            candidates.push(node);
                        }
                    }
                }
                Ok(None) => {
                    // Timeout tick. In-flight queries against dead nodes
                    // would hold `pending` forever; a tick with nothing
                    // received is the signal to stop waiting on them.
                    // (Coarse -- a real client tracks per-query timeouts
                    // -- but convergence only needs "eventually give up
                    // on silence", and RECV_TICK bounds the wait.)
                    pending.clear();
                }
                Err(_) => break,
            }
        }

        // Tokens closest to the target first (that's who announce_peer
        // should go to, per BEP 5).
        result.tokens.sort_by_key(|(n, _)| xor_distance(&n.id, target));
        result
    }

    /// `announce_peer` to the (up to) K closest token-holding nodes from
    /// a lookup: tells the DHT "I'm serving `info_hash` on `port`".
    /// Fire-and-forget: replies (or bad-token errors) arrive during
    /// subsequent `serve_for` ticks and need no handling.
    pub fn announce(&mut self, info_hash: &NodeId, port: u16, lookup: &LookupResult) {
        let targets: Vec<(SocketAddr, Vec<u8>)> = lookup.tokens.iter().take(K).map(|(n, tok)| (n.addr, tok.clone())).collect();
        for (addr, token) in targets {
            let q = Query::AnnouncePeer { id: self.node_id, info_hash: *info_hash, port, token, implied_port: false };
            let _ = self.send_query(q, addr);
        }
    }

    /// Iterative BEP 44 `get`: finds the value stored under `target` (an immutable item's
    /// content hash, or a mutable item's `sha1(k + salt)`). `salt` is needed only to verify a
    /// mutable item's signature -- BEP 44 never echoes it back in a `get` response, so a caller
    /// resolving a mutable pointer must already know it (it went into computing `target` in the
    /// first place). Every candidate answer is independently verified against `target` (an
    /// immutable one by hash, a mutable one by both its signature and that its key actually
    /// hashes to the target asked for) before being trusted; among verified mutable answers the
    /// one with the highest sequence number wins, and later queries in the same lookup ask for
    /// only a strictly newer one (BEP 44's own `seq` filter), saving bandwidth once something
    /// has already been confirmed. An unverifiable or malformed answer is silently discarded,
    /// never trusted and never grown the result with -- a hostile node can at worst waste this
    /// lookup's time, not feed it a forged value.
    pub fn get_item(&mut self, target: &NodeId, salt: Option<&[u8]>, deadline: Duration, stop: &AtomicBool) -> Option<store::StoredItem> {
        let mut best: Option<store::StoredItem> = None;
        let end = Instant::now() + deadline;

        let mut candidates: Vec<CompactNode> = self.table.closest(target, K * 2);
        let mut queried: HashSet<SocketAddr> = HashSet::new();
        let mut pending: HashMap<Vec<u8>, CompactNode> = HashMap::new();
        let mut queries_sent = 0usize;

        loop {
            if Instant::now() >= end || stop.load(Ordering::SeqCst) {
                break;
            }

            candidates.sort_by_key(|n| xor_distance(&n.id, target));
            candidates.dedup_by_key(|n| n.addr);

            let frontier_exhausted = candidates.iter().take(K).all(|n| queried.contains(&n.addr));
            if pending.is_empty() && (frontier_exhausted || candidates.is_empty()) {
                break;
            }

            if queries_sent < MAX_LOOKUP_QUERIES {
                let to_query: Vec<CompactNode> = candidates.iter().filter(|n| !queried.contains(&n.addr)).take(ALPHA.saturating_sub(pending.len())).cloned().collect();
                let known_seq = best.as_ref().and_then(|b| b.mutable).map(|(_, seq, _)| seq);
                for node in to_query {
                    let q = Query::Get { id: self.node_id, target: *target, seq: known_seq };
                    if let Ok(t) = self.send_query(q, node.addr) {
                        queried.insert(node.addr);
                        pending.insert(t, node);
                        queries_sent += 1;
                    } else {
                        queried.insert(node.addr);
                    }
                }
            } else if pending.is_empty() {
                break;
            }

            match self.transport.recv(RECV_TICK) {
                Ok(Some((data, from))) => {
                    let Some((t, response, from)) = self.handle_inbound(&data, from) else { continue };
                    let Some(_) = pending.remove(&t) else {
                        self.table.insert(response.id, from);
                        continue;
                    };
                    self.table.insert(response.id, from);
                    for node in response.nodes {
                        if !queried.contains(&node.addr) && self.is_our_family(&node.addr) {
                            candidates.push(node);
                        }
                    }

                    let Some(v) = response.v else { continue };
                    let bencoded = bencode::encode(&v);
                    let accepted = match (response.k, response.seq, response.sig) {
                        (Some(k), Some(seq), Some(sig)) => {
                            (store::mutable_target(&k, salt) == *target && store::verify_mutable(&k, salt, seq, &bencoded, &sig)).then_some(store::StoredItem { v, mutable: Some((k, seq, sig)) })
                        }
                        (None, None, None) => (store::immutable_target(&bencoded) == *target).then_some(store::StoredItem { v, mutable: None }),
                        _ => None, // a malformed mix of mutable fields: not something a well-formed answer sends
                    };
                    if let Some(candidate) = accepted {
                        let better = match (&best, candidate.mutable) {
                            (Some(current), Some((_, seq, _))) => current.mutable.is_none_or(|(_, current_seq, _)| seq > current_seq),
                            (None, _) => true,
                            (Some(_), None) => false, // an immutable answer never displaces one already accepted
                        };
                        if better {
                            best = Some(candidate);
                        }
                    }
                }
                Ok(None) => pending.clear(),
                Err(_) => break,
            }
        }

        best
    }

    /// BEP 46: resolves a mutable pointer -- an ed25519 public key, plus the optional salt that
    /// went into its target (see [`crate::magnet::parse_mutable_pointer`] for reading one out of
    /// a `magnet:?xs=urn:btpk:...` link) -- to the info hash it currently names, if the DHT
    /// holds a published, signature-verified value for it and that value is BEP 46's own shape
    /// (`{"ih": <20-byte infohash>}`). `None` either for nothing found or for something found
    /// that is not usable -- a caller has nothing different to do either way.
    pub fn resolve_torrent_pointer(&mut self, public_key: &[u8; 32], salt: Option<&[u8]>, deadline: Duration, stop: &AtomicBool) -> Option<[u8; 20]> {
        let target = store::mutable_target(public_key, salt);
        let item = self.get_item(&target, salt, deadline, stop)?;
        let dict = item.v.as_dict()?;
        let ih = dict.get(b"ih".as_slice())?.as_bytes()?;
        ih.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::krpc::KrpcMessage;
    use crate::dht::testing::{v4, MockTransport, ScriptedNode};

    #[test]
    fn lookup_walks_node_chain_and_collects_peers_and_tokens() {
        let transport = MockTransport::new();
        let node_b = CompactNode { id: [0xBB; 20], addr: v4("10.0.0.2:6881") };
        let the_peer = v4("203.0.113.9:51413");

        // A knows about B; B has actual peers + a token.
        transport.script_node(v4("10.0.0.1:6881"), ScriptedNode { id: [0xAA; 20], nodes: vec![node_b.clone()], values: vec![], token: None , item: None });
        transport.script_node(node_b.addr, ScriptedNode { id: node_b.id, nodes: vec![], values: vec![the_peer], token: Some(b"tok-b".to_vec()) , item: None });

        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], v4("10.0.0.1:6881"));

        let info_hash = [0x99; 20];
        let stop = AtomicBool::new(false);
        let result = dht.get_peers(&info_hash, Duration::from_secs(5), &stop);

        assert_eq!(result.peers, vec![the_peer]);
        assert_eq!(result.tokens.len(), 1);
        assert_eq!(result.tokens[0].0.addr, node_b.addr);
        assert_eq!(result.tokens[0].1, b"tok-b".to_vec());
        // Both responders got inserted into the routing table.
        assert_eq!(dht.table_len(), 2);
    }

    #[test]
    fn announce_sends_announce_peer_with_the_lookup_token() {
        let transport = MockTransport::new();
        let node_b = CompactNode { id: [0xBB; 20], addr: v4("10.0.0.2:6881") };
        transport.script_node(node_b.addr, ScriptedNode { id: node_b.id, nodes: vec![], values: vec![v4("203.0.113.9:51413")], token: Some(b"tok-b".to_vec()) , item: None });

        let mut dht = Dht::new(&transport);
        dht.seed_node(node_b.id, node_b.addr);
        let info_hash = [0x99; 20];
        let stop = AtomicBool::new(false);
        let result = dht.get_peers(&info_hash, Duration::from_secs(5), &stop);
        dht.announce(&info_hash, 6889, &result);

        let to_b = transport.sent_to(node_b.addr);
        let announce = to_b
            .iter()
            .filter_map(|d| match KrpcMessage::decode(d) {
                Ok(KrpcMessage::Query { query: q @ Query::AnnouncePeer { .. }, .. }) => Some(q),
                _ => None,
            })
            .next()
            .expect("an announce_peer query must have been sent to the token holder");
        match announce {
            Query::AnnouncePeer { info_hash: ih, port, token, .. } => {
                assert_eq!(ih, info_hash);
                assert_eq!(port, 6889);
                assert_eq!(token, b"tok-b".to_vec());
            }
            _ => unreachable!(),
        }
    }

    // ---- BEP 32 ----

    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_ipv6_lookup_walks_ipv6_nodes_and_collects_ipv6_peers_and_never_queries_an_ipv4_node() {
        let transport = MockTransport::new_v6();
        let (a, b) = (v6("[2001:db8::1]:6881"), v6("[2001:db8::2]:6881"));
        let stray = v4("10.0.0.7:6881");
        let node_b = CompactNode { id: [0xBB; 20], addr: b };
        let peer = v6("[2001:db8::99]:51413");
        // A lists B and, in the same answer, an IPv4 node.
        transport.script_node(a, ScriptedNode { id: [0xAA; 20], nodes: vec![node_b.clone(), CompactNode { id: [0xCC; 20], addr: stray }], values: vec![], token: None, item: None });
        transport.script_node(b, ScriptedNode { id: node_b.id, nodes: vec![], values: vec![peer, v4("203.0.113.1:1")], token: Some(b"tok".to_vec()) , item: None });

        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], a);
        let result = dht.get_peers(&[0x99; 20], Duration::from_secs(5), &AtomicBool::new(false));

        assert_eq!(result.peers, vec![peer, v4("203.0.113.1:1")], "what the node said is passed on as it said it");
        assert!(transport.sent_to(stray).is_empty(), "an IPv4 node is not queried from an IPv6 socket");
        assert_eq!(dht.table_len(), 2);
    }

    #[test]
    fn an_ipv4_lookup_does_not_query_the_ipv6_nodes_an_answer_lists() {
        let transport = MockTransport::new();
        let a = v4("10.0.0.1:6881");
        let stray = v6("[2001:db8::7]:6881");
        transport.script_node(a, ScriptedNode { id: [0xAA; 20], nodes: vec![CompactNode { id: [0xCC; 20], addr: stray }], values: vec![], token: None, item: None });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], a);
        dht.get_peers(&[0x99; 20], Duration::from_secs(5), &AtomicBool::new(false));
        assert!(transport.sent_to(stray).is_empty());
    }

    #[test]
    fn bootstrap_starts_from_the_routers_of_this_nodes_own_family_only() {
        let routers = vec!["[::1]:4001".to_string(), "127.0.0.1:4002".to_string(), "[::1]:4003".to_string()];
        let v6_transport = MockTransport::new_v6();
        let mut dht = Dht::new(&v6_transport);
        dht.bootstrap(&routers, &AtomicBool::new(false));
        assert!(!v6_transport.sent_to(v6("[::1]:4001")).is_empty() && !v6_transport.sent_to(v6("[::1]:4003")).is_empty());
        assert!(v6_transport.sent_to(v4("127.0.0.1:4002")).is_empty(), "an IPv6 node does not try an IPv4 router");

        let v4_transport = MockTransport::new();
        let mut dht = Dht::new(&v4_transport);
        dht.bootstrap(&routers, &AtomicBool::new(false));
        assert!(!v4_transport.sent_to(v4("127.0.0.1:4002")).is_empty());
        assert!(v4_transport.sent_to(v6("[::1]:4001")).is_empty());
    }

    #[test]
    fn announcing_over_ipv6_goes_to_the_ipv6_token_holders() {
        let transport = MockTransport::new_v6();
        let holder = v6("[2001:db8::2]:6881");
        transport.script_node(holder, ScriptedNode { id: [0xBB; 20], nodes: vec![], values: vec![], token: Some(b"tk6".to_vec()) , item: None });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xBB; 20], holder);
        let result = dht.get_peers(&[0x99; 20], Duration::from_secs(5), &AtomicBool::new(false));
        dht.announce(&[0x99; 20], 6889, &result);
        let announced = transport.sent_to(holder).iter().any(|d| matches!(KrpcMessage::decode(d), Ok(KrpcMessage::Query { query: Query::AnnouncePeer { port: 6889, .. }, .. })));
        assert!(announced);
    }

    // ---- BEP 44: get_item ----

    use super::store::StoredItem;
    use crate::bencode::Bencode;
    use ed25519_dalek::SigningKey;

    fn immutable(bytes: &[u8]) -> StoredItem {
        StoredItem { v: Bencode::Bytes(bytes.to_vec()), mutable: None }
    }

    fn mutable(key: &SigningKey, seq: i64, bytes: &[u8]) -> StoredItem {
        let v = Bencode::Bytes(bytes.to_vec());
        let sig = super::store::sign_mutable(key, None, seq, &bencode::encode(&v));
        StoredItem { v, mutable: Some((key.verifying_key().to_bytes(), seq, sig)) }
    }

    #[test]
    fn get_item_finds_an_immutable_value_from_the_closest_node_that_has_it() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        let item = immutable(b"Hello World!");
        let target = super::store::immutable_target(&bencode::encode(&item.v));
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], item: Some(item.clone()), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);

        let found = dht.get_item(&target, None, Duration::from_secs(5), &AtomicBool::new(false));
        assert_eq!(found, Some(item));
    }

    #[test]
    fn get_item_rejects_an_immutable_answer_that_does_not_hash_to_the_target_asked_for() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        // A dishonest node claims to have the value for a target it does not match.
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], item: Some(immutable(b"not the right value")), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);

        let honest_target = super::store::immutable_target(&bencode::encode(&Bencode::Bytes(b"Hello World!".to_vec())));
        assert!(dht.get_item(&honest_target, None, Duration::from_secs(5), &AtomicBool::new(false)).is_none());
    }

    #[test]
    fn get_item_finds_a_mutable_value_and_returns_its_verified_key_seq_and_signature() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let item = mutable(&key, 3, b"current");
        let target = super::store::mutable_target(&key.verifying_key().to_bytes(), None);
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], item: Some(item.clone()), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);

        let found = dht.get_item(&target, None, Duration::from_secs(5), &AtomicBool::new(false));
        assert_eq!(found, Some(item));
    }

    #[test]
    fn get_item_rejects_a_mutable_answer_with_a_signature_that_does_not_verify() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let mut item = mutable(&key, 3, b"current");
        if let Some((_, _, sig)) = &mut item.mutable {
            sig[0] ^= 0xff;
        }
        let target = super::store::mutable_target(&key.verifying_key().to_bytes(), None);
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], item: Some(item), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);

        assert!(dht.get_item(&target, None, Duration::from_secs(5), &AtomicBool::new(false)).is_none());
    }

    #[test]
    fn get_item_prefers_the_higher_sequence_number_among_several_answers() {
        let transport = MockTransport::new();
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let target = super::store::mutable_target(&key.verifying_key().to_bytes(), None);
        let (older, newer) = (v4("10.0.0.1:6881"), v4("10.0.0.2:6881"));
        transport.script_node(older, ScriptedNode { id: [0xAA; 20], item: Some(mutable(&key, 1, b"old")), ..Default::default() });
        transport.script_node(newer, ScriptedNode { id: [0xBB; 20], item: Some(mutable(&key, 9, b"new")), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], older);
        dht.seed_node([0xBB; 20], newer);

        let found = dht.get_item(&target, None, Duration::from_secs(5), &AtomicBool::new(false)).expect("something was found");
        assert_eq!(found.v, Bencode::Bytes(b"new".to_vec()));
        assert_eq!(found.mutable.map(|(_, seq, _)| seq), Some(9));
    }

    #[test]
    fn get_item_finds_nothing_when_nobody_has_it() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);
        assert!(dht.get_item(&[0x99; 20], None, Duration::from_secs(5), &AtomicBool::new(false)).is_none());
    }

    #[test]
    fn resolve_torrent_pointer_finds_the_infohash_a_bep46_item_names() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        let key = SigningKey::from_bytes(&[0x66; 32]);
        let ih = [0x42; 20];
        let v = Bencode::Dict(std::collections::BTreeMap::from([(b"ih".to_vec(), Bencode::Bytes(ih.to_vec()))]));
        let sig = super::store::sign_mutable(&key, None, 1, &bencode::encode(&v));
        let item = StoredItem { v, mutable: Some((key.verifying_key().to_bytes(), 1, sig)) };
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], item: Some(item), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);

        let resolved = dht.resolve_torrent_pointer(&key.verifying_key().to_bytes(), None, Duration::from_secs(5), &AtomicBool::new(false));
        assert_eq!(resolved, Some(ih));
    }

    #[test]
    fn resolve_torrent_pointer_is_none_for_a_value_that_is_not_bep46_shaped() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        let key = SigningKey::from_bytes(&[0x66; 32]);
        // A mutable item that verifies fine but is not `{"ih": ...}` -- some other application's data.
        let item = mutable(&key, 1, b"not a torrent pointer");
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], item: Some(item), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);

        assert!(dht.resolve_torrent_pointer(&key.verifying_key().to_bytes(), None, Duration::from_secs(5), &AtomicBool::new(false)).is_none());
    }

    #[test]
    fn a_mutable_lookup_with_a_salt_verifies_against_that_salt() {
        let transport = MockTransport::new();
        let node = v4("10.0.0.1:6881");
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let v = Bencode::Bytes(b"salted".to_vec());
        let sig = super::store::sign_mutable(&key, Some(b"s"), 1, &bencode::encode(&v));
        let item = StoredItem { v: v.clone(), mutable: Some((key.verifying_key().to_bytes(), 1, sig)) };
        let target = super::store::mutable_target(&key.verifying_key().to_bytes(), Some(b"s"));
        transport.script_node(node, ScriptedNode { id: [0xAA; 20], item: Some(item), ..Default::default() });
        let mut dht = Dht::new(&transport);
        dht.seed_node([0xAA; 20], node);

        assert!(dht.get_item(&target, None, Duration::from_secs(5), &AtomicBool::new(false)).is_none(), "verifying without the salt must fail");
        assert_eq!(dht.get_item(&target, Some(b"s"), Duration::from_secs(5), &AtomicBool::new(false)).map(|i| i.v), Some(v));
    }
}
