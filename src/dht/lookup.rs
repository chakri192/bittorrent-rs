//! The client side of the DHT: bootstrapping a routing table, finding the
//! peers for a torrent with an iterative Kademlia lookup, and announcing
//! ourselves to the nodes that hold its tokens.

use super::krpc::{CompactNode, NodeId, Query};
use super::routing::{xor_distance, K};
use super::{Dht, Transport, RECV_TICK};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
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
    pub peers: Vec<SocketAddrV4>,
    pub tokens: Vec<(CompactNode, Vec<u8>)>,
}

impl<T: Transport> Dht<T> {
    /// Sends `find_node(self)` to each bootstrap address, then runs a
    /// full iterative lookup toward our own id -- the canonical way to
    /// populate a fresh routing table with nodes near us.
    pub fn bootstrap(&mut self, routers: &[String], stop: &AtomicBool) {
        let mut router_addrs: Vec<SocketAddrV4> = Vec::new();
        for r in routers {
            if let Ok(resolved) = r.to_socket_addrs() {
                router_addrs.extend(resolved.filter_map(|a| match a {
                    SocketAddr::V4(v4) => Some(v4),
                    SocketAddr::V6(_) => None,
                }));
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
    fn iterative_lookup(&mut self, target: &NodeId, extra_seeds: &[SocketAddrV4], want_peers: bool, deadline: Duration, stop: &AtomicBool) -> LookupResult {
        let mut result = LookupResult::default();
        let end = Instant::now() + deadline;

        // Shortlist: distance-sorted candidates. Seeded from the routing
        // table plus any explicit seed addresses (bootstrap routers get a
        // zero id -- never inserted into the table, only queried).
        let mut candidates: Vec<CompactNode> = self.table.closest(target, K * 2);
        candidates.extend(extra_seeds.iter().map(|&addr| CompactNode { id: [0u8; 20], addr }));

        let mut queried: HashSet<SocketAddrV4> = HashSet::new();
        let mut seen_peers: HashSet<SocketAddrV4> = HashSet::new();
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
                    let Some((t, response, from_v4)) = self.handle_inbound(&data, from) else {
                        continue; // was a query (answered inline) or noise
                    };
                    let Some(asked) = pending.remove(&t) else {
                        // Response to a long-forgotten transaction; still
                        // proof of liveness.
                        self.table.insert(response.id, from_v4);
                        continue;
                    };
                    // Responders earn a routing-table slot. Use the id
                    // *they* report with their observed address, not the
                    // (possibly zero / hearsay) id we sent to.
                    let _ = asked;
                    self.table.insert(response.id, from_v4);

                    for peer in &response.values {
                        if seen_peers.insert(*peer) {
                            result.peers.push(*peer);
                        }
                    }
                    if let Some(token) = response.token {
                        result.tokens.push((CompactNode { id: response.id, addr: from_v4 }, token));
                    }
                    for node in response.nodes {
                        if !queried.contains(&node.addr) {
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
        let targets: Vec<(SocketAddrV4, Vec<u8>)> = lookup.tokens.iter().take(K).map(|(n, tok)| (n.addr, tok.clone())).collect();
        for (addr, token) in targets {
            let q = Query::AnnouncePeer { id: self.node_id, info_hash: *info_hash, port, token, implied_port: false };
            let _ = self.send_query(q, addr);
        }
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
        transport.script_node(v4("10.0.0.1:6881"), ScriptedNode { id: [0xAA; 20], nodes: vec![node_b.clone()], values: vec![], token: None });
        transport.script_node(node_b.addr, ScriptedNode { id: node_b.id, nodes: vec![], values: vec![the_peer], token: Some(b"tok-b".to_vec()) });

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
        transport.script_node(node_b.addr, ScriptedNode { id: node_b.id, nodes: vec![], values: vec![v4("203.0.113.9:51413")], token: Some(b"tok-b".to_vec()) });

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
}
