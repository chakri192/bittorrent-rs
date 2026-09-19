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
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use token::TokenSecrets;

/// Per-recv poll granularity inside lookups and idle serving.
const RECV_TICK: Duration = Duration::from_millis(300);

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
        self.transport.send_to(&msg.encode(), addr)?;
        Ok(t)
    }
}
