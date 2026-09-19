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
    spawn_service_on(transport, port, bootstrap_nodes, info_hash, announce_port)
}

/// [`spawn_service`] on a transport already made -- one shared with uTP, say --
/// which listens on UDP `port`.
pub fn spawn_service_on<T: super::Transport + 'static>(transport: T, port: u16, bootstrap_nodes: Vec<String>, info_hash: [u8; 20], announce_port: Arc<AtomicU16>) -> io::Result<DhtService> {
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
    use crate::dht::krpc::{KrpcMessage, Query, Response};
    use std::net::{SocketAddrV4, UdpSocket};
    use std::sync::Mutex;
    use std::time::Instant;

    const INFO_HASH: [u8; 20] = [0x42; 20];
    const NODE_ID: [u8; 20] = [0xCC; 20];

    /// Every `announce_peer` a node received: the port and the token.
    type Announces = Arc<Mutex<Vec<(u16, Vec<u8>)>>>;

    /// A DHT node on loopback: answers `find_node` with nothing, `get_peers`
    /// with one peer and a token, and records every `announce_peer`.
    struct FakeNode {
        port: u16,
        announces: Announces,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl FakeNode {
        fn start(peer: SocketAddrV4) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let port = socket.local_addr().unwrap().port();
            let announces = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (log, halt) = (Arc::clone(&announces), Arc::clone(&stop));
            let thread = thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !halt.load(Ordering::SeqCst) {
                    let Ok((n, from)) = socket.recv_from(&mut buf) else { continue };
                    let Ok(KrpcMessage::Query { t, query }) = KrpcMessage::decode(&buf[..n]) else { continue };
                    let response = match query {
                        Query::GetPeers { .. } => Response { id: NODE_ID, values: vec![peer], token: Some(b"tk".to_vec()), ..Default::default() },
                        Query::AnnouncePeer { port, token, .. } => {
                            log.lock().unwrap().push((port, token));
                            Response { id: NODE_ID, ..Default::default() }
                        }
                        _ => Response { id: NODE_ID, ..Default::default() },
                    };
                    let _ = socket.send_to(&KrpcMessage::Response { t, response }.encode(), from);
                }
            });
            FakeNode { port, announces, stop, thread: Some(thread) }
        }

        fn router(&self) -> String {
            format!("127.0.0.1:{}", self.port)
        }
    }

    impl Drop for FakeNode {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {}", what);
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn peer() -> SocketAddrV4 {
        "203.0.113.9:51413".parse().unwrap()
    }

    #[test]
    fn the_service_finds_peers_through_a_bootstrap_node_and_announces_our_port() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(6881))).unwrap();

        let found = service.peers_rx.recv_timeout(Duration::from_secs(10)).expect("the lookup delivers the peer the node knows");
        assert_eq!(found, vec![SocketAddr::V4(peer())]);

        wait_until("the announce_peer", || !node.announces.lock().unwrap().is_empty());
        assert_eq!(node.announces.lock().unwrap()[0], (6881, b"tk".to_vec()), "our port, with the token the node handed out");
        assert!(service.nodes.load(Ordering::SeqCst) >= 1, "the node that answered is in the routing table");

        service.stop(); // returns only once the thread has ended
    }

    #[test]
    fn a_zero_announce_port_means_not_yet_and_nothing_is_announced() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0))).unwrap();

        service.peers_rx.recv_timeout(Duration::from_secs(10)).expect("peers are still delivered");
        // The announce, had there been one, follows the delivery within
        // microseconds; give it far longer than that.
        thread::sleep(Duration::from_millis(500));

        assert!(node.announces.lock().unwrap().is_empty());
        service.stop();
    }

    #[test]
    fn the_service_reports_the_udp_port_it_bound() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0))).unwrap();
        assert_ne!(service.port, 0);
        service.stop();
    }

    #[test]
    fn a_stopped_service_can_be_stopped_again() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0))).unwrap();
        service.stop();
        service.stop();
    }

    #[test]
    fn the_default_bootstrap_routers_are_host_port_pairs() {
        assert!(!DEFAULT_BOOTSTRAP.is_empty());
        for router in DEFAULT_BOOTSTRAP {
            let (host, port) = router.rsplit_once(':').unwrap_or_else(|| panic!("{} has no port", router));
            assert!(!host.is_empty() && port.parse::<u16>().is_ok(), "{}", router);
        }
    }

    #[test]
    fn the_service_answers_a_ping_that_reaches_it_through_the_port_utp_shares() {
        let (tx, rx) = mpsc::channel();
        let socket = Arc::new(crate::utp::UtpSocket::with_socket(UdpSocket::bind("127.0.0.1:0").unwrap(), Some(tx)).unwrap());
        let transport = crate::dht::SharedTransport::new(Arc::clone(&socket), rx);
        let port = transport.local_port();
        let mut service = spawn_service_on(transport, port, Vec::new(), INFO_HASH, Arc::new(AtomicU16::new(0))).unwrap();
        assert_eq!(service.port, port, "it says it is on the shared port");

        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.send_to(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe", ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 512];
        let (n, from) = peer.recv_from(&mut buf).expect("the DHT node answers");
        assert_eq!(from.port(), port, "from the shared port");
        assert!(buf[..n].windows(4).any(|w| w == b"1:rd"), "a KRPC response: {:?}", String::from_utf8_lossy(&buf[..n]));
        service.stop();
    }
}
