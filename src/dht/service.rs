//! The DHT as a background thread: bootstrap, look up peers for one
//! torrent on a schedule, announce our port, and answer other nodes in
//! between.

use super::{Dht, UdpTransport};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Well-known bootstrap routers (not regular nodes: they answer
/// `find_node` but shouldn't be inserted into routing tables; their
/// responses lead us to real nodes, which earn insertion by responding).
pub const DEFAULT_BOOTSTRAP: &[&str] = &["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "router.utorrent.com:6881", "dht.libtorrent.org:25401"];

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
