//! Mainline DHT (BEP 5): trackerless peer discovery over a Kademlia
//! overlay. This client participates as a (mostly) well-behaved node:
//! it answers inbound `ping`/`find_node`/`get_peers`/`announce_peer`
//! queries and runs iterative `get_peers` lookups + `announce_peer` for
//! the torrents it downloads.
//!
//! Networking is behind the `Transport` trait so the lookup/responder
//! state machines are unit-testable with a scripted in-memory transport
//! -- real DHT nodes aren't reachable from this repo's CI sandbox.

pub mod krpc;
pub mod routing;

use krpc::{CompactNode, KrpcMessage, NodeId, Query, Response};
use routing::{xor_distance, RoutingTable, K};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Well-known bootstrap routers (not regular nodes: they answer
/// `find_node` but shouldn't be inserted into routing tables; their
/// responses lead us to real nodes, which earn insertion by responding).
pub const DEFAULT_BOOTSTRAP: &[&str] = &["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "router.utorrent.com:6881", "dht.libtorrent.org:25401"];

/// Parallelism of the iterative lookup (Kademlia's alpha).
const ALPHA: usize = 3;
/// Hard cap on queries per lookup, so one lookup can't spray the network
/// indefinitely even against an adversarial node graph.
const MAX_LOOKUP_QUERIES: usize = 64;
/// Per-recv poll granularity inside lookups and idle serving.
const RECV_TICK: Duration = Duration::from_millis(300);

pub trait Transport: Send {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()>;
    /// Blocks up to `timeout`; `Ok(None)` on timeout (not an error).
    fn recv(&self, timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>>;
}

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Binds `0.0.0.0:port`, falling back to an ephemeral port if taken.
    pub fn bind(port: u16) -> io::Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", port)).or_else(|_| UdpSocket::bind(("0.0.0.0", 0)))?;
        Ok(UdpTransport { socket })
    }

    pub fn local_port(&self) -> u16 {
        self.socket.local_addr().map(|a| a.port()).unwrap_or(0)
    }
}

impl Transport for UdpTransport {
    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_to(data, addr).map(|_| ())
    }

    fn recv(&self, timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        self.socket.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; 2048]; // KRPC messages are far smaller than one MTU in practice
        match self.socket.recv_from(&mut buf) {
            Ok((n, from)) => Ok(Some((buf[..n].to_vec(), from))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Everything a completed lookup learned: actual peers for the torrent,
/// plus the closest nodes that handed us announce tokens.
#[derive(Debug, Default)]
pub struct LookupResult {
    pub peers: Vec<SocketAddrV4>,
    pub tokens: Vec<(CompactNode, Vec<u8>)>,
}

pub fn random_node_id() -> NodeId {
    // The peer_id generator already mixes an atomic counter, wall clock,
    // and OS entropy; hashing its output makes the bits uniform across
    // the whole id space (peer_ids carry a fixed ASCII prefix).
    let mut h = Sha1::new();
    h.update(crate::tracker::generate_peer_id());
    h.finalize().into()
}

/// How often the announce-token secret is replaced. BEP 5 leaves the
/// schedule to the implementation but requires a token to stay valid for
/// a while after it is issued; mainline rotates every 5 minutes and
/// accepts the previous generation too, so a token is good for 5-10.
const TOKEN_ROTATION: Duration = Duration::from_secs(300);

/// The secrets announce tokens are derived from: the current one, plus
/// the one before it so a token handed out just before a rotation still
/// verifies. Anything older is rejected, which is the point -- a token
/// harvested once cannot be replayed indefinitely.
struct TokenSecrets {
    current: [u8; 20],
    previous: Option<[u8; 20]>,
    rotated_at: Instant,
}

impl TokenSecrets {
    fn new(now: Instant) -> Self {
        TokenSecrets { current: random_node_id(), previous: None, rotated_at: now }
    }

    fn rotate(&mut self, now: Instant) {
        self.previous = Some(std::mem::replace(&mut self.current, random_node_id()));
        self.rotated_at = now;
    }

    fn rotate_if_due(&mut self, now: Instant) {
        if now.saturating_duration_since(self.rotated_at) >= TOKEN_ROTATION {
            self.rotate(now);
        }
    }

    fn accepts(&self, ip: &std::net::Ipv4Addr, token: &[u8]) -> bool {
        token_for(&self.current, ip) == token || self.previous.is_some_and(|prev| token_for(&prev, ip) == token)
    }
}

/// Announce token for `ip` under `secret`: the first 8 bytes of
/// sha1(secret || ip). Opaque to the receiver (BEP 5), verifiable by us.
fn token_for(secret: &[u8; 20], ip: &std::net::Ipv4Addr) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(secret);
    h.update(ip.octets());
    h.finalize()[..8].to_vec()
}

pub struct Dht<T: Transport> {
    node_id: NodeId,
    table: RoutingTable,
    transport: T,
    txid_counter: u16,
    tokens: TokenSecrets,
    /// info_hash -> peers other nodes announced to us. Bounded per hash;
    /// this client is a downloader first, storage node second.
    peer_store: HashMap<NodeId, Vec<SocketAddrV4>>,
}

const MAX_STORED_PEERS_PER_HASH: usize = 100;

impl<T: Transport> Dht<T> {
    pub fn new(transport: T) -> Self {
        let node_id = random_node_id();
        Dht {
            node_id,
            table: RoutingTable::new(node_id),
            transport,
            txid_counter: 0,
            tokens: TokenSecrets::new(Instant::now()),
            peer_store: HashMap::new(),
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    /// Directly seeds the routing table (tests, cached-nodes files).
    pub fn seed_node(&mut self, id: NodeId, addr: SocketAddrV4) {
        self.table.insert(id, addr);
    }

    fn next_txid(&mut self) -> Vec<u8> {
        self.txid_counter = self.txid_counter.wrapping_add(1);
        self.txid_counter.to_be_bytes().to_vec()
    }

    fn send_query(&mut self, query: Query, addr: SocketAddrV4) -> io::Result<Vec<u8>> {
        let t = self.next_txid();
        let msg = KrpcMessage::Query { t: t.clone(), query };
        self.transport.send_to(&msg.encode(), SocketAddr::V4(addr))?;
        Ok(t)
    }

    fn make_token(&self, ip: &std::net::Ipv4Addr) -> Vec<u8> {
        token_for(&self.tokens.current, ip)
    }

    /// Handles one inbound datagram. Queries get answered on the spot;
    /// responses are returned to the caller for transaction correlation.
    fn handle_inbound(&mut self, data: &[u8], from: SocketAddr) -> Option<(Vec<u8>, Response, SocketAddrV4)> {
        let SocketAddr::V4(from_v4) = from else {
            return None; // BEP 32 (IPv6) out of scope
        };
        let msg = KrpcMessage::decode(data).ok()?; // garbage from strangers: drop silently

        match msg {
            KrpcMessage::Query { t, query } => {
                self.tokens.rotate_if_due(Instant::now());
                // A node that queries us is alive at that address --
                // exactly the freshness signal the routing table wants.
                self.table.insert(*query.sender_id(), from_v4);
                let reply = match &query {
                    Query::Ping { .. } => Response { id: self.node_id, ..Default::default() },
                    Query::FindNode { target, .. } => Response { id: self.node_id, nodes: self.table.closest(target, K), ..Default::default() },
                    Query::GetPeers { info_hash, .. } => {
                        let token = Some(self.make_token(from_v4.ip()));
                        match self.peer_store.get(info_hash) {
                            Some(peers) if !peers.is_empty() => Response { id: self.node_id, values: peers.clone(), token, ..Default::default() },
                            _ => Response { id: self.node_id, nodes: self.table.closest(info_hash, K), token, ..Default::default() },
                        }
                    }
                    Query::AnnouncePeer { info_hash, port, token, implied_port, .. } => {
                        if !self.tokens.accepts(from_v4.ip(), token) {
                            let err = KrpcMessage::Error { t, code: 203, message: "bad token".to_string() };
                            let _ = self.transport.send_to(&err.encode(), from);
                            return None;
                        }
                        let peer_port = if *implied_port { from_v4.port() } else { *port };
                        let peers = self.peer_store.entry(*info_hash).or_default();
                        let peer = SocketAddrV4::new(*from_v4.ip(), peer_port);
                        if !peers.contains(&peer) && peers.len() < MAX_STORED_PEERS_PER_HASH {
                            peers.push(peer);
                        }
                        Response { id: self.node_id, ..Default::default() }
                    }
                };
                let _ = self.transport.send_to(&KrpcMessage::Response { t, response: reply }.encode(), from);
                None
            }
            KrpcMessage::Response { t, response } => Some((t, response, from_v4)),
            KrpcMessage::Error { .. } => None, // errors just mean that txid never resolves
        }
    }

    /// Serves inbound queries for up to `duration` (idle keep-warm
    /// between lookups). Responses arriving here (stragglers from past
    /// lookups) still refresh the routing table.
    pub fn serve_for(&mut self, duration: Duration, stop: &AtomicBool) {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
            match self.transport.recv(RECV_TICK) {
                Ok(Some((data, from))) => {
                    if let Some((_t, response, from_v4)) = self.handle_inbound(&data, from) {
                        self.table.insert(response.id, from_v4);
                    }
                }
                Ok(None) => {}
                Err(_) => return, // socket died; service loop will notice
            }
        }
    }

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

/// Handle to the background DHT service thread `download.rs` runs: it
/// bootstraps, then alternates `get_peers` lookups (results pushed
/// through `peers_rx`) with serving inbound queries, re-announcing our
/// listen port after each lookup.
pub struct DhtService {
    pub peers_rx: Receiver<Vec<SocketAddr>>,
    pub port: u16,
    /// Live routing-table size, updated by the service thread each round
    /// -- a cheap "is the DHT healthy?" signal for the UI.
    pub nodes: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl DhtService {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Interval between repeat lookups once the first one has run. Long
/// enough to be polite; short enough that a swarm's churn keeps showing
/// up in the dial queue.
const RELOOKUP_INTERVAL: Duration = Duration::from_secs(180);

/// `announce_port` is read fresh before each announce round: `0` means
/// "don't announce yet". This lets the downloader spawn the DHT early
/// (a magnet with no trackers needs DHT peers before it can even fetch
/// metadata) and fill the port in later, once the TCP listener is up.
pub fn spawn_service(bind_port: u16, bootstrap_nodes: Vec<String>, info_hash: [u8; 20], announce_port: Arc<AtomicU16>) -> io::Result<DhtService> {
    let transport = UdpTransport::bind(bind_port)?;
    let port = transport.local_port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let nodes = Arc::new(AtomicUsize::new(0));
    let nodes_thread = Arc::clone(&nodes);
    let (tx, peers_rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let mut dht = Dht::new(transport);
        dht.bootstrap(&bootstrap_nodes, &stop_thread);
        nodes_thread.store(dht.table_len(), Ordering::SeqCst);

        while !stop_thread.load(Ordering::SeqCst) {
            let found = dht.get_peers(&info_hash, Duration::from_secs(10), &stop_thread);
            if !found.peers.is_empty() {
                let as_socket_addrs: Vec<SocketAddr> = found.peers.iter().map(|p| SocketAddr::V4(*p)).collect();
                if tx.send(as_socket_addrs).is_err() {
                    return; // downloader gone; nothing left to do
                }
            }
            let p = announce_port.load(Ordering::SeqCst);
            if p != 0 {
                dht.announce(&info_hash, p, &found);
            }
            nodes_thread.store(dht.table_len(), Ordering::SeqCst);
            dht.serve_for(RELOOKUP_INTERVAL, &stop_thread);
            nodes_thread.store(dht.table_len(), Ordering::SeqCst);
        }
    });

    Ok(DhtService { peers_rx, port, nodes, stop, handle: Some(handle) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// Scripted in-memory transport: `send_to` records every outgoing
    /// datagram and, if the destination is scripted, synthesizes that
    /// node's reply into the inbox (echoing the transaction id, as a
    /// real node would).
    struct MockTransport {
        inbox: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        script: Mutex<HashMap<SocketAddr, ScriptedNode>>,
    }

    #[derive(Clone)]
    struct ScriptedNode {
        id: NodeId,
        nodes: Vec<CompactNode>,
        values: Vec<SocketAddrV4>,
        token: Option<Vec<u8>>,
    }

    impl MockTransport {
        fn new() -> Self {
            MockTransport { inbox: Mutex::new(VecDeque::new()), sent: Mutex::new(Vec::new()), script: Mutex::new(HashMap::new()) }
        }

        fn script_node(&self, addr: SocketAddrV4, node: ScriptedNode) {
            self.script.lock().unwrap().insert(SocketAddr::V4(addr), node);
        }

        fn push_inbound(&self, data: Vec<u8>, from: SocketAddrV4) {
            self.inbox.lock().unwrap().push_back((data, SocketAddr::V4(from)));
        }

        fn sent_to(&self, addr: SocketAddrV4) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().iter().filter(|(_, a)| *a == SocketAddr::V4(addr)).map(|(d, _)| d.clone()).collect()
        }
    }

    impl Transport for &MockTransport {
        fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
            self.sent.lock().unwrap().push((data.to_vec(), addr));
            if let Some(node) = self.script.lock().unwrap().get(&addr).cloned() {
                if let Ok(KrpcMessage::Query { t, query }) = KrpcMessage::decode(data) {
                    let response = match query {
                        Query::GetPeers { .. } => Response { id: node.id, nodes: node.nodes.clone(), values: node.values.clone(), token: node.token.clone() },
                        Query::FindNode { .. } => Response { id: node.id, nodes: node.nodes.clone(), ..Default::default() },
                        _ => Response { id: node.id, ..Default::default() },
                    };
                    let reply = KrpcMessage::Response { t, response };
                    self.inbox.lock().unwrap().push_back((reply.encode(), addr));
                }
            }
            Ok(())
        }

        fn recv(&self, _timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
            Ok(self.inbox.lock().unwrap().pop_front())
        }
    }

    fn v4(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

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

    #[test]
    fn responds_to_inbound_ping_with_our_id_and_same_txid() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let our_id = *dht.node_id();

        let asker = v4("10.9.9.9:1234");
        let ping = KrpcMessage::Query { t: b"xy".to_vec(), query: Query::Ping { id: [0x01; 20] } };
        transport.push_inbound(ping.encode(), asker);

        let stop = AtomicBool::new(false);
        dht.serve_for(Duration::from_millis(1), &stop);

        let replies = transport.sent_to(asker);
        assert_eq!(replies.len(), 1);
        match KrpcMessage::decode(&replies[0]).unwrap() {
            KrpcMessage::Response { t, response } => {
                assert_eq!(t, b"xy".to_vec());
                assert_eq!(response.id, our_id);
            }
            other => panic!("expected response, got {:?}", other),
        }
        // The asker is now in our routing table.
        assert_eq!(dht.table_len(), 1);
    }

    #[test]
    fn get_peers_token_round_trips_through_announce_peer_and_is_stored() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let stop = AtomicBool::new(false);
        let info_hash = [0x77; 20];
        let asker = v4("10.5.5.5:7000");

        // 1) get_peers -> harvest the token we hand out.
        let q = KrpcMessage::Query { t: b"t1".to_vec(), query: Query::GetPeers { id: [0x02; 20], info_hash } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        let token = match KrpcMessage::decode(&transport.sent_to(asker)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => response.token.expect("get_peers response must carry a token"),
            other => panic!("expected response, got {:?}", other),
        };

        // 2) announce_peer with that token -> accepted + stored.
        let q = KrpcMessage::Query { t: b"t2".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 9999, token, implied_port: false } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);

        // 3) a *different* node's get_peers now receives that peer as a value.
        let other = v4("10.6.6.6:7001");
        let q = KrpcMessage::Query { t: b"t3".to_vec(), query: Query::GetPeers { id: [0x03; 20], info_hash } };
        transport.push_inbound(q.encode(), other);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(&transport.sent_to(other)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => {
                assert_eq!(response.values, vec![v4("10.5.5.5:9999")]);
            }
            other => panic!("expected response, got {:?}", other),
        }
    }

    #[test]
    fn announce_peer_with_bad_token_gets_error_203_and_is_not_stored() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let stop = AtomicBool::new(false);
        let info_hash = [0x77; 20];
        let asker = v4("10.5.5.5:7000");

        let q = KrpcMessage::Query { t: b"t9".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 9999, token: b"forged".to_vec(), implied_port: false } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);

        match KrpcMessage::decode(&transport.sent_to(asker)[0]).unwrap() {
            KrpcMessage::Error { code, .. } => assert_eq!(code, 203),
            other => panic!("expected error 203, got {:?}", other),
        }

        // And a get_peers for that hash returns no values.
        let other = v4("10.6.6.6:7001");
        let q = KrpcMessage::Query { t: b"ta".to_vec(), query: Query::GetPeers { id: [0x03; 20], info_hash } };
        transport.push_inbound(q.encode(), other);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(&transport.sent_to(other)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => assert!(response.values.is_empty()),
            other => panic!("expected response, got {:?}", other),
        }
    }

    #[test]
    fn implied_port_uses_the_udp_source_port() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let stop = AtomicBool::new(false);
        let info_hash = [0x70; 20];
        let asker = v4("10.5.5.5:7070");

        // Harvest a token first.
        let q = KrpcMessage::Query { t: b"t1".to_vec(), query: Query::GetPeers { id: [0x02; 20], info_hash } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        let token = match KrpcMessage::decode(&transport.sent_to(asker)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => response.token.unwrap(),
            _ => unreachable!(),
        };

        let q = KrpcMessage::Query { t: b"t2".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 1, token, implied_port: true } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);

        let other = v4("10.6.6.6:7001");
        let q = KrpcMessage::Query { t: b"t3".to_vec(), query: Query::GetPeers { id: [0x03; 20], info_hash } };
        transport.push_inbound(q.encode(), other);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(&transport.sent_to(other)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => assert_eq!(response.values, vec![v4("10.5.5.5:7070")], "implied_port=1 must use the UDP source port, not the port field"),
            _ => unreachable!(),
        }
    }
    /// Sends `get_peers` from `asker` and returns the token in the reply.
    fn harvest_token(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddrV4, info_hash: [u8; 20]) -> Vec<u8> {
        let stop = AtomicBool::new(false);
        let q = KrpcMessage::Query { t: b"g".to_vec(), query: Query::GetPeers { id: [0x02; 20], info_hash } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Response { response, .. } => response.token.expect("get_peers response must carry a token"),
            other => panic!("expected response, got {:?}", other),
        }
    }

    /// Sends `announce_peer` with `token` and reports whether it was
    /// accepted (a plain response) or refused (error 203).
    fn announce_accepted(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddrV4, info_hash: [u8; 20], token: Vec<u8>) -> bool {
        let stop = AtomicBool::new(false);
        let q = KrpcMessage::Query { t: b"a".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 9999, token, implied_port: false } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Response { .. } => true,
            KrpcMessage::Error { code: 203, .. } => false,
            other => panic!("unexpected reply {:?}", other),
        }
    }

    #[test]
    fn token_issued_before_one_rotation_is_still_accepted() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("10.5.5.5:7000");
        let token = harvest_token(&mut dht, &transport, asker, [0x77; 20]);

        dht.tokens.rotate(Instant::now());

        assert!(announce_accepted(&mut dht, &transport, asker, [0x77; 20], token), "one generation back must still verify");
    }

    #[test]
    fn token_issued_before_two_rotations_is_rejected() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("10.5.5.5:7000");
        let token = harvest_token(&mut dht, &transport, asker, [0x77; 20]);

        dht.tokens.rotate(Instant::now());
        dht.tokens.rotate(Instant::now());

        assert!(!announce_accepted(&mut dht, &transport, asker, [0x77; 20], token), "a stale token must not be replayable");
    }

    #[test]
    fn rotation_happens_only_once_the_interval_has_elapsed() {
        let start = Instant::now();
        let mut secrets = TokenSecrets::new(start);
        let original = secrets.current;

        secrets.rotate_if_due(start + TOKEN_ROTATION - Duration::from_secs(1));
        assert_eq!(secrets.current, original, "must not rotate early");
        assert!(secrets.previous.is_none());

        secrets.rotate_if_due(start + TOKEN_ROTATION);
        assert_ne!(secrets.current, original, "must rotate at the interval");
        assert_eq!(secrets.previous, Some(original), "the old secret is kept for one more generation");
    }

    #[test]
    fn tokens_are_bound_to_the_requesters_ip() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let token = harvest_token(&mut dht, &transport, v4("10.5.5.5:7000"), [0x77; 20]);

        assert!(!announce_accepted(&mut dht, &transport, v4("10.6.6.6:7000"), [0x77; 20], token), "a token must not work from a different address");
    }
}
