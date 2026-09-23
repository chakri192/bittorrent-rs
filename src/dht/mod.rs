//! Mainline DHT (BEP 5): trackerless peer discovery over a Kademlia
//! overlay. This client participates as a (mostly) well-behaved node:
//! it answers inbound `ping`/`find_node`/`get_peers`/`announce_peer`
//! queries and runs iterative `get_peers` lookups + `announce_peer` for
//! the torrents it downloads.
//!
//! Networking is behind the `Transport` trait so the lookup/responder
//! state machines are unit-testable with a scripted in-memory transport
//! -- real DHT nodes aren't reachable from this repo's CI sandbox.
//!
//! The node itself, [`Dht`], is defined here; its behaviour is spread over
//! the modules by role:
//!
//! - `transport`: the UDP socket behind the [`Transport`] trait
//! - `token`: announce-token secrets and their rotation
//! - `responder`: answering inbound queries, storing announced peers
//! - `lookup`: bootstrap, iterative `get_peers`, `announce_peer`
//! - `service`: the background thread the downloader runs
//!
//! Every public item keeps its `bittorrent_rs::dht::...` path:
//!
//! ```
//! use bittorrent_rs::dht::{random_node_id, spawn_service, Dht, DhtService, LookupResult, Transport, UdpTransport, DEFAULT_BOOTSTRAP};
//! ```

pub mod krpc;
pub mod routing;
pub mod secure_id;

mod lookup;
mod responder;
mod service;
#[cfg(test)]
mod testing;
mod token;
mod transport;

pub use lookup::LookupResult;
pub use service::{spawn_service, spawn_service_on, DhtNode, DhtService, DEFAULT_BOOTSTRAP};
pub use transport::{SharedTransport, Transport, UdpTransport};

use krpc::{KrpcMessage, NodeId, Query};
use routing::RoutingTable;
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use token::TokenSecrets;

/// Per-recv poll granularity inside lookups and idle serving.
const RECV_TICK: Duration = Duration::from_millis(300);

/// How many different nodes must say they see this node at the same address (BEP 42) before it believes it: one node can lie, or be
/// wrong; several that share nothing but a query to us are hard to line up.
const ADDRESS_REPORTS_NEEDED: usize = 5;

/// The most different addresses nodes may say we are at that are kept while the votes are counted.
const MAX_ADDRESS_CANDIDATES: usize = 32;

pub fn random_node_id() -> NodeId {
    // The peer_id generator already mixes an atomic counter, wall clock,
    // and OS entropy; hashing its output makes the bits uniform across
    // the whole id space (peer_ids carry a fixed ASCII prefix).
    let mut h = Sha1::new();
    h.update(crate::tracker::generate_peer_id());
    h.finalize().into()
}

pub struct Dht<T: Transport> {
    node_id: NodeId,
    table: RoutingTable,
    transport: T,
    /// Whether this node lives on IPv6 (BEP 32), and so only knows IPv6 nodes.
    ipv6: bool,
    txid_counter: u16,
    tokens: TokenSecrets,
    /// info_hash -> peers other nodes announced to us. Bounded per hash;
    /// this client is a downloader first, storage node second.
    peer_store: HashMap<NodeId, Vec<SocketAddr>>,
    /// BEP 43: this node asks, and does not answer, and asks the nodes it asks not to remember it.
    read_only: bool,
    /// The address nodes agree they see this one at (BEP 42), once they have, which the node id is made from.
    external_ip: Option<IpAddr>,
    /// Who has said this node is at which address, until one is believed.
    address_reports: HashMap<IpAddr, HashSet<IpAddr>>,
}

impl<T: Transport> Dht<T> {
    pub fn new(transport: T) -> Self {
        let node_id = random_node_id();
        Dht {
            node_id,
            table: RoutingTable::new(node_id),
            ipv6: transport.ipv6(),
            transport,
            txid_counter: 0,
            tokens: TokenSecrets::new(Instant::now()),
            peer_store: HashMap::new(),
            read_only: false,
            external_ip: None,
            address_reports: HashMap::new(),
        }
    }

    /// Makes this node read-only (BEP 43), as one that cannot be reached from outside should be: its queries say so, so that no one
    /// puts it in a routing table, and it answers none.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    /// The address nodes have told this one it is at (BEP 42), if enough have agreed.
    pub fn external_ip(&self) -> Option<IpAddr> {
        self.external_ip
    }

    /// A node has answered saying it sees this one at `reported` (BEP 42). Once [`ADDRESS_REPORTS_NEEDED`] different nodes agree,
    /// the node's id is made anew from that address, so that it is one that others can check and will accept, and its routing
    /// table is centred on it. An address that is not the internet's (a loopback answer, one from a node on the same network)
    /// says nothing of where this node is on it, and is not counted.
    pub(crate) fn note_reported_address(&mut self, reporter: IpAddr, reported: IpAddr) {
        if reported.is_ipv6() != self.ipv6 || secure_id::is_local(reported) || self.external_ip == Some(reported) {
            return;
        }
        if !self.address_reports.contains_key(&reported) && self.address_reports.len() >= MAX_ADDRESS_CANDIDATES {
            self.address_reports.clear(); // a flood of made-up addresses is not to be kept
        }
        let count = {
            let reporters = self.address_reports.entry(reported).or_default();
            reporters.insert(reporter);
            reporters.len()
        };
        // The first address that enough nodes agree on: a rival that has not got there first has fewer.
        if count >= ADDRESS_REPORTS_NEEDED {
            let mut rand = [0u8; 1];
            let _ = getrandom::getrandom(&mut rand);
            self.node_id = secure_id::node_id_for(reported, rand[0], random_node_id());
            self.table.recentre(self.node_id);
            self.external_ip = Some(reported);
            self.address_reports.clear();
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    /// Directly seeds the routing table (tests, cached-nodes files).
    pub fn seed_node(&mut self, id: NodeId, addr: SocketAddr) {
        if self.is_our_family(&addr) {
            self.table.insert(id, addr);
        }
    }

    fn next_txid(&mut self) -> Vec<u8> {
        self.txid_counter = self.txid_counter.wrapping_add(1);
        self.txid_counter.to_be_bytes().to_vec()
    }

    /// Whether `addr` is of the family this node lives on. A node of the other
    /// family cannot be reached from this socket, so it is not to be remembered.
    fn is_our_family(&self, addr: &SocketAddr) -> bool {
        addr.is_ipv6() == self.ipv6
    }

    fn send_query(&mut self, query: Query, addr: SocketAddr) -> io::Result<Vec<u8>> {
        let t = self.next_txid();
        let msg = KrpcMessage::Query { t: t.clone(), query };
        self.transport.send_to(&msg.encode_with(self.read_only), addr)?;
        Ok(t)
    }
}
