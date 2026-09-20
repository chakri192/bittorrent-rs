//! The DHT as a background thread: bootstrap, look up peers for one
//! torrent on a schedule, announce our port, and answer other nodes in
//! between.

use super::{Dht, UdpTransport};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Well-known bootstrap routers (not regular nodes: they answer
/// `find_node` but shouldn't be inserted into routing tables; their
/// responses lead us to real nodes, which earn insertion by responding).
pub const DEFAULT_BOOTSTRAP: &[&str] = &["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "router.utorrent.com:6881", "dht.libtorrent.org:25401"];

/// Interval between repeat lookups of a torrent once its first has run. Long
/// enough to be polite; short enough that a swarm's churn keeps showing
/// up in the dial queue.
const RELOOKUP_INTERVAL: Duration = Duration::from_secs(180);

/// How long one lookup is given when a node has a single torrent to look for; with more, each is given a share of it, so
/// that a network that does not answer holds up every torrent's turn for about this long in all, not this long each.
const LOOKUP_BUDGET: Duration = Duration::from_secs(10);

/// How often the node looks up whether there is something to do: a torrent added, a lookup
/// due, or (before the listener is up) a port to announce that it did not have.
const ANNOUNCE_POLL: Duration = Duration::from_millis(500);

/// What a node is told to do.
enum Command {
    Add { info_hash: [u8; 20], announce_port: Arc<AtomicU16>, tx: mpsc::Sender<Vec<SocketAddr>> },
    Remove { info_hash: [u8; 20] },
}

/// A DHT node -- one on IPv4 and, if wanted, one on IPv6 (BEP 32), each with a
/// routing table of its own -- that looks up and announces any number of
/// torrents, added and removed while it runs. Dropping it does not stop it.
pub struct DhtNode {
    /// The UDP port of the IPv4 node.
    pub port: u16,
    /// The UDP port of the IPv6 node, if one runs.
    pub port6: Option<u16>,
    /// Live routing-table size of the IPv4 node, updated by its thread each
    /// round -- a cheap "is the DHT healthy?" signal for the UI.
    pub nodes: Arc<AtomicUsize>,
    /// The same for the IPv6 node, if one runs.
    pub nodes6: Arc<AtomicUsize>,
    commands: Vec<mpsc::Sender<Command>>,
    stop: Arc<AtomicBool>,
    handles: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl DhtNode {
    /// Starts a node on UDP `bind_port` (an ephemeral one if it is taken), and with `ipv6` a
    /// second on an IPv6 socket, on the same port number if it can. If the machine has no
    /// IPv6 the second node is simply not there. `bootstrap_nodes` are `host:port` routers.
    pub fn start(bind_port: u16, bootstrap_nodes: Vec<String>, ipv6: bool) -> io::Result<DhtNode> {
        let transport = UdpTransport::bind(bind_port)?;
        let port = transport.local_port();
        DhtNode::start_on(transport, port, bootstrap_nodes, ipv6)
    }

    /// [`start`](Self::start) on a transport already made -- one shared with uTP, say --
    /// which listens on UDP `port`.
    pub fn start_on<T: super::Transport + 'static>(transport: T, port: u16, bootstrap_nodes: Vec<String>, ipv6: bool) -> io::Result<DhtNode> {
        DhtNode::start_every(transport, port, bootstrap_nodes, ipv6, RELOOKUP_INTERVAL, LOOKUP_BUDGET)
    }

    /// [`start_on`](Self::start_on), looking each torrent up again every `relookup`, and giving one lookup at most `budget`
    /// (less, shared out between the torrents, when there are several).
    fn start_every<T: super::Transport + 'static>(transport: T, port: u16, bootstrap_nodes: Vec<String>, ipv6: bool, relookup: Duration, budget: Duration) -> io::Result<DhtNode> {
        let stop = Arc::new(AtomicBool::new(false));
        let (nodes, nodes6) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let mut commands = Vec::new();
        let mut handles = Vec::new();
        let mut spawn = |transport: Box<dyn super::Transport>, table_size: Arc<AtomicUsize>, bootstrap: Vec<String>| {
            let (tx, rx) = mpsc::channel();
            commands.push(tx);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || run_node(Dht::new(transport), bootstrap, rx, table_size, stop, relookup, budget)));
        };
        spawn(Box::new(transport), Arc::clone(&nodes), bootstrap_nodes.clone());
        let mut port6 = None;
        if ipv6 {
            // The IPv6 node prefers the same port number, as peers expect one number to do for both.
            if let Ok(transport6) = UdpTransport::bind_v6(port) {
                port6 = Some(transport6.local_port());
                spawn(Box::new(transport6), Arc::clone(&nodes6), bootstrap_nodes);
            }
        }
        Ok(DhtNode { port, port6, nodes, nodes6, commands, stop, handles: Mutex::new(handles) })
    }

    /// Nodes known, over both families.
    pub fn node_count(&self) -> usize {
        self.nodes.load(Ordering::SeqCst) + self.nodes6.load(Ordering::SeqCst)
    }

    /// Starts looking up `info_hash` and announcing `announce_port` for it. `announce_port` is
    /// read afresh each round: `0` means "not yet", which lets a torrent be added before its
    /// listener is up. What is found arrives on the returned handle.
    pub fn add_torrent(self: &Arc<Self>, info_hash: [u8; 20], announce_port: Arc<AtomicU16>) -> DhtService {
        let (tx, peers_rx) = mpsc::channel();
        for commands in &self.commands {
            let _ = commands.send(Command::Add { info_hash, announce_port: Arc::clone(&announce_port), tx: tx.clone() });
        }
        DhtService { peers_rx, port: self.port, nodes: Arc::clone(&self.nodes), nodes6: Arc::clone(&self.nodes6), port6: self.port6, info_hash, node: Arc::clone(self), owned: false }
    }

    /// Stops the node and its threads, and with them every torrent's lookups. Safe to call twice.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let handles: Vec<_> = crate::sync::lock(&self.handles).drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

/// How long one lookup may take when the node has `torrents` of them: the whole `budget` for one, and for more a share
/// of it, but never less than a fifth: what a lookup finds arrives in the first moments, and one that has to be cut
/// short is one the network was not answering.
fn lookup_deadline(budget: Duration, torrents: usize) -> Duration {
    (budget / torrents.max(1) as u32).max(budget / 5)
}

/// One torrent being looked up on a node.
struct Tracked {
    info_hash: [u8; 20],
    announce_port: Arc<AtomicU16>,
    tx: mpsc::Sender<Vec<SocketAddr>>,
    next_lookup: Instant,
    /// What the last lookup found, for the announce that follows it.
    found: Option<super::LookupResult>,
    announced: bool,
}

/// One DHT node, of whichever family its transport is, on a thread of its own: it serves the
/// network, and between times looks up and announces each torrent it has been given.
fn run_node<T: super::Transport>(mut dht: Dht<T>, bootstrap: Vec<String>, commands: mpsc::Receiver<Command>, table_size: Arc<AtomicUsize>, stop: Arc<AtomicBool>, relookup: Duration, budget: Duration) {
    dht.bootstrap(&bootstrap, &stop);
    table_size.store(dht.table_len(), Ordering::SeqCst);
    let mut torrents: Vec<Tracked> = Vec::new();

    while !stop.load(Ordering::SeqCst) {
        while let Ok(command) = commands.try_recv() {
            match command {
                Command::Add { info_hash, announce_port, tx } => {
                    torrents.retain(|t| t.info_hash != info_hash);
                    torrents.push(Tracked { info_hash, announce_port, tx, next_lookup: Instant::now(), found: None, announced: false });
                }
                Command::Remove { info_hash } => torrents.retain(|t| t.info_hash != info_hash),
            }
        }

        let now = Instant::now();
        // The one most overdue, so that none goes without for want of the ones before it in the list.
        if let Some(index) = (0..torrents.len()).filter(|&i| torrents[i].next_lookup <= now).min_by_key(|&i| torrents[i].next_lookup) {
            let found = dht.get_peers(&torrents[index].info_hash, lookup_deadline(budget, torrents.len()), &stop);
            let torrent = &mut torrents[index];
            if !found.peers.is_empty() && torrent.tx.send(found.peers.clone()).is_err() {
                torrents.remove(index); // nobody wants it any more
                continue;
            }
            torrent.found = Some(found);
            torrent.announced = false;
            torrent.next_lookup = Instant::now() + relookup;
        }

        // The announce needs our port, which may not be known yet (the DHT starts before the
        // listener); rather than leave it to the next round, it is looked for every so often, and
        // made with the tokens the lookup won.
        for torrent in torrents.iter_mut().filter(|t| !t.announced) {
            let port = torrent.announce_port.load(Ordering::SeqCst);
            if let (true, Some(found)) = (port != 0, &torrent.found) {
                dht.announce(&torrent.info_hash, port, found);
                torrent.announced = true;
            }
        }

        table_size.store(dht.table_len(), Ordering::SeqCst);
        // Serving, until there is something else to do.
        let wait = torrents.iter().map(|t| t.next_lookup.saturating_duration_since(Instant::now())).min().map_or(ANNOUNCE_POLL, |due| due.min(ANNOUNCE_POLL));
        dht.serve_for(wait.max(Duration::from_millis(10)), &stop);
    }
}

/// The handle a torrent holds on a DHT node: what is found for it, and the way to stop looking.
pub struct DhtService {
    pub peers_rx: Receiver<Vec<SocketAddr>>,
    pub port: u16,
    /// Live routing-table size of the IPv4 node -- a cheap "is the DHT healthy?" signal for the UI.
    pub nodes: Arc<AtomicUsize>,
    /// The same for the IPv6 node (BEP 32), if one runs.
    pub nodes6: Arc<AtomicUsize>,
    /// The UDP port of the IPv6 node, if one runs.
    pub port6: Option<u16>,
    info_hash: [u8; 20],
    node: Arc<DhtNode>,
    /// Whether the node is this handle's alone, and ends with it.
    owned: bool,
}

impl DhtService {
    /// Nodes known, over both families.
    pub fn node_count(&self) -> usize {
        self.nodes.load(Ordering::SeqCst) + self.nodes6.load(Ordering::SeqCst)
    }

    /// Stops looking up this torrent; and, if the node was made for it alone, ends the node.
    pub fn stop(&mut self) {
        if self.owned {
            self.node.stop();
        } else {
            for commands in &self.node.commands {
                let _ = commands.send(Command::Remove { info_hash: self.info_hash });
            }
        }
    }
}

/// `announce_port` is read fresh before each announce round: `0` means
/// "don't announce yet". This lets the downloader spawn the DHT early
/// (a magnet with no trackers needs DHT peers before it can even fetch
/// metadata) and fill the port in later, once the TCP listener is up.
///
/// With `ipv6`, a second node runs on an IPv6 socket of its own (BEP 32), with
/// a routing table of its own, and what it finds arrives on the same channel.
/// If the machine has no IPv6 the second node is simply not there.
///
/// A node for one torrent; [`DhtNode`] serves many.
pub fn spawn_service(bind_port: u16, bootstrap_nodes: Vec<String>, info_hash: [u8; 20], announce_port: Arc<AtomicU16>, ipv6: bool) -> io::Result<DhtService> {
    let node = Arc::new(DhtNode::start(bind_port, bootstrap_nodes, ipv6)?);
    Ok(owned(node, info_hash, announce_port))
}

/// [`spawn_service`] on a transport already made -- one shared with uTP, say --
/// which listens on UDP `port`.
pub fn spawn_service_on<T: super::Transport + 'static>(transport: T, port: u16, bootstrap_nodes: Vec<String>, info_hash: [u8; 20], announce_port: Arc<AtomicU16>, ipv6: bool) -> io::Result<DhtService> {
    let node = Arc::new(DhtNode::start_on(transport, port, bootstrap_nodes, ipv6)?);
    Ok(owned(node, info_hash, announce_port))
}

fn owned(node: Arc<DhtNode>, info_hash: [u8; 20], announce_port: Arc<AtomicU16>) -> DhtService {
    let mut service = node.add_torrent(info_hash, announce_port);
    service.owned = true;
    service
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::krpc::{KrpcMessage, Query, Response};
    use std::net::UdpSocket;
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
        /// The info hash of every `get_peers` and of every `announce_peer`, in order.
        asked: Arc<Mutex<Vec<[u8; 20]>>>,
        announced: Arc<Mutex<Vec<[u8; 20]>>>,
        stop: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl FakeNode {
        fn start(peer: SocketAddr) -> Self {
            FakeNode::start_on("127.0.0.1:0", peer)
        }

        fn start_on(bind: &str, peer: SocketAddr) -> Self {
            FakeNode::start_with(bind, Some(peer))
        }

        /// One that answers each info hash with a peer of its own, `peer_for` it.
        fn start_by_hash() -> Self {
            FakeNode::start_with("127.0.0.1:0", None)
        }

        fn start_with(bind: &str, peer: Option<SocketAddr>) -> Self {
            let socket = UdpSocket::bind(bind).unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let port = socket.local_addr().unwrap().port();
            let announces = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let (log, halt) = (Arc::clone(&announces), Arc::clone(&stop));
            let (asked, announced) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(Vec::new())));
            let (asked_log, announced_log) = (Arc::clone(&asked), Arc::clone(&announced));
            let thread = thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !halt.load(Ordering::SeqCst) {
                    let Ok((n, from)) = socket.recv_from(&mut buf) else { continue };
                    let Ok(KrpcMessage::Query { t, query }) = KrpcMessage::decode(&buf[..n]) else { continue };
                    let response = match query {
                        Query::GetPeers { info_hash, .. } => {
                            asked_log.lock().unwrap().push(info_hash);
                            Response { id: NODE_ID, values: vec![peer.unwrap_or_else(|| peer_for(&info_hash))], token: Some(b"tk".to_vec()), ..Default::default() }
                        }
                        Query::AnnouncePeer { port, token, info_hash, .. } => {
                            announced_log.lock().unwrap().push(info_hash);
                            log.lock().unwrap().push((port, token));
                            Response { id: NODE_ID, ..Default::default() }
                        }
                        _ => Response { id: NODE_ID, ..Default::default() },
                    };
                    let _ = socket.send_to(&KrpcMessage::Response { t, response }.encode(), from);
                }
            });
            FakeNode { port, announces, asked, announced, stop, thread: Some(thread) }
        }

        fn router(&self) -> String {
            format!("127.0.0.1:{}", self.port)
        }

        fn router6(&self) -> String {
            format!("[::1]:{}", self.port)
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

    fn peer() -> SocketAddr {
        "203.0.113.9:51413".parse().unwrap()
    }

    /// The peer a by-hash node hands out for a torrent: the first byte of the hash says which.
    fn peer_for(info_hash: &[u8; 20]) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, info_hash[0]], 51413))
    }

    fn started(bootstrap: String, ipv6: bool) -> Arc<DhtNode> {
        Arc::new(DhtNode::start(0, vec![bootstrap], ipv6).unwrap())
    }

    #[test]
    fn the_service_finds_peers_through_a_bootstrap_node_and_announces_our_port() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(6881)), false).unwrap();

        let found = service.peers_rx.recv_timeout(Duration::from_secs(10)).expect("the lookup delivers the peer the node knows");
        assert_eq!(found, vec![peer()]);

        wait_until("the announce_peer", || !node.announces.lock().unwrap().is_empty());
        assert_eq!(node.announces.lock().unwrap()[0], (6881, b"tk".to_vec()), "our port, with the token the node handed out");
        assert!(service.nodes.load(Ordering::SeqCst) >= 1, "the node that answered is in the routing table");

        service.stop(); // returns only once the thread has ended
    }

    #[test]
    fn a_zero_announce_port_means_not_yet_and_nothing_is_announced() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0)), false).unwrap();

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
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0)), false).unwrap();
        assert_ne!(service.port, 0);
        service.stop();
    }

    #[test]
    fn a_stopped_service_can_be_stopped_again() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0)), false).unwrap();
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
        let mut service = spawn_service_on(transport, port, Vec::new(), INFO_HASH, Arc::new(AtomicU16::new(0)), false).unwrap();
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

    #[test]
    fn with_ipv6_a_second_node_finds_ipv6_peers_through_an_ipv6_router_and_announces_to_it() {
        if UdpSocket::bind("[::1]:0").is_err() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        let peer6: SocketAddr = "[2001:db8::99]:51413".parse().unwrap();
        let node = FakeNode::start_on("[::1]:0", peer6);
        // Only an IPv6 router is named: the IPv4 node has nowhere to start from.
        let mut service = spawn_service(0, vec![node.router6()], INFO_HASH, Arc::new(AtomicU16::new(6881)), true).unwrap();
        assert!(service.port6.is_some(), "the IPv6 node runs");

        let found = service.peers_rx.recv_timeout(Duration::from_secs(10)).expect("the IPv6 node delivers what it found");
        assert_eq!(found, vec![peer6]);
        wait_until("the announce_peer", || !node.announces.lock().unwrap().is_empty());
        assert_eq!(node.announces.lock().unwrap()[0], (6881, b"tk".to_vec()));
        wait_until("the routing table to show it", || service.node_count() >= 1);
        assert!(service.nodes6.load(Ordering::SeqCst) >= 1 && service.nodes.load(Ordering::SeqCst) == 0, "in the IPv6 node's table, not the IPv4 one's");
        service.stop();
    }

    #[test]
    fn both_nodes_report_what_they_find_on_the_one_channel() {
        if UdpSocket::bind("[::1]:0").is_err() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        let (peer4, peer6): (SocketAddr, SocketAddr) = ("203.0.113.9:51413".parse().unwrap(), "[2001:db8::99]:51413".parse().unwrap());
        let (node4, node6) = (FakeNode::start(peer4), FakeNode::start_on("[::1]:0", peer6));
        let mut service = spawn_service(0, vec![node4.router(), node6.router6()], INFO_HASH, Arc::new(AtomicU16::new(0)), true).unwrap();

        let mut found = Vec::new();
        while found.len() < 2 {
            found.extend(service.peers_rx.recv_timeout(Duration::from_secs(10)).expect("both families deliver"));
        }
        found.sort();
        assert_eq!(found, vec![peer4, peer6]);
        service.stop();
    }

    #[test]
    fn without_ipv6_asked_for_there_is_no_ipv6_node() {
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0)), false).unwrap();
        assert!(service.port6.is_none());
        service.stop();
    }

    #[test]
    fn stopping_stops_both_nodes() {
        if UdpSocket::bind("[::1]:0").is_err() {
            return;
        }
        let node = FakeNode::start(peer());
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::new(AtomicU16::new(0)), true).unwrap();
        let (port, port6) = (service.port, service.port6.expect("the IPv6 node runs"));
        let started = Instant::now();
        service.stop();
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        service.stop();
        // Both threads have ended and let go of their sockets, not just the first.
        assert!(UdpSocket::bind(("0.0.0.0", port)).is_ok() && UdpSocket::bind(("::", port6)).is_ok());
    }

    #[test]
    fn a_port_that_becomes_known_after_the_first_lookup_is_announced_at_once_not_a_round_later() {
        let node = FakeNode::start(peer());
        let port = Arc::new(AtomicU16::new(0));
        let mut service = spawn_service(0, vec![node.router()], INFO_HASH, Arc::clone(&port), false).unwrap();
        service.peers_rx.recv_timeout(Duration::from_secs(10)).expect("the first lookup is done");
        thread::sleep(Duration::from_millis(300));
        assert!(node.announces.lock().unwrap().is_empty(), "no port yet, so nothing announced");

        port.store(6889, Ordering::SeqCst); // the listener comes up

        wait_until("the announce_peer, well inside the three minutes to the next round", || !node.announces.lock().unwrap().is_empty());
        assert_eq!(node.announces.lock().unwrap()[0], (6889, b"tk".to_vec()), "with the token the first lookup won");
        service.stop();
    }

    #[test]
    fn one_node_looks_up_and_announces_each_torrent_it_is_given() {
        let router = FakeNode::start_by_hash();
        let node = started(router.router(), false);
        let (first, second) = ([1u8; 20], [2u8; 20]);
        let mut a = node.add_torrent(first, Arc::new(AtomicU16::new(6881)));
        let mut b = node.add_torrent(second, Arc::new(AtomicU16::new(6882)));

        // Each hears of the peer for its own torrent and of no other.
        assert_eq!(a.peers_rx.recv_timeout(Duration::from_secs(10)).unwrap(), vec![peer_for(&first)]);
        assert_eq!(b.peers_rx.recv_timeout(Duration::from_secs(10)).unwrap(), vec![peer_for(&second)]);
        wait_until("both announces", || router.announced.lock().unwrap().len() >= 2);
        let ports: Vec<u16> = router.announces.lock().unwrap().iter().map(|(port, _)| *port).collect();
        let hashes = router.announced.lock().unwrap().clone();
        for (hash, port) in hashes.iter().zip(&ports) {
            assert_eq!(*port, if *hash == first { 6881 } else { 6882 }, "each torrent announces its own port");
        }
        assert!(hashes.contains(&first) && hashes.contains(&second));
        assert_eq!(a.port, b.port, "over one socket");

        a.stop();
        b.stop();
        node.stop();
    }

    #[test]
    fn a_torrent_added_while_the_node_runs_is_looked_up_at_once() {
        let router = FakeNode::start_by_hash();
        let node = started(router.router(), false);
        let mut early = node.add_torrent([1; 20], Arc::new(AtomicU16::new(0)));
        early.peers_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        // Long before the early torrent's next lookup, which is minutes off.
        let mut late = node.add_torrent([7; 20], Arc::new(AtomicU16::new(6881)));
        assert_eq!(late.peers_rx.recv_timeout(Duration::from_secs(10)).expect("looked up without waiting for a round"), vec![peer_for(&[7; 20])]);
        early.stop();
        late.stop();
        node.stop();
    }

    #[test]
    fn stopping_one_torrent_leaves_the_node_and_the_others_running() {
        let router = FakeNode::start_by_hash();
        let node = started(router.router(), false);
        let mut gone = node.add_torrent([1; 20], Arc::new(AtomicU16::new(0)));
        gone.peers_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        gone.stop();

        let mut kept = node.add_torrent([2; 20], Arc::new(AtomicU16::new(6881)));
        assert_eq!(kept.peers_rx.recv_timeout(Duration::from_secs(10)).expect("the node still works"), vec![peer_for(&[2; 20])]);
        wait_until("the announce", || router.announced.lock().unwrap().contains(&[2; 20]));
        assert!(!node.stop.load(Ordering::SeqCst), "stopping a torrent is not stopping the node");
        kept.stop();
        node.stop();
    }

    #[test]
    fn a_torrent_removed_is_not_looked_up_or_announced_again() {
        let router = FakeNode::start_by_hash();
        let node = started(router.router(), false);
        // Its port unknown, it would be announced as soon as the port is; but it is removed first.
        let port = Arc::new(AtomicU16::new(0));
        let mut removed = node.add_torrent([1; 20], Arc::clone(&port));
        removed.peers_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        removed.stop();
        let mut other = node.add_torrent([2; 20], Arc::new(AtomicU16::new(0)));
        other.peers_rx.recv_timeout(Duration::from_secs(10)).unwrap(); // the removal has been read by now

        port.store(6881, Ordering::SeqCst);
        thread::sleep(Duration::from_secs(1));
        assert!(!router.announced.lock().unwrap().contains(&[1; 20]), "nothing is announced for a torrent that is gone");
        other.stop();
        node.stop();
    }

    #[test]
    fn the_handle_of_a_service_made_for_one_torrent_ends_the_node_with_it() {
        let router = FakeNode::start_by_hash();
        let mut service = spawn_service(0, vec![router.router()], [3; 20], Arc::new(AtomicU16::new(0)), false).unwrap();
        service.peers_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        service.stop();
        assert!(service.node.stop.load(Ordering::SeqCst), "the node it made goes with it");
    }

    #[test]
    fn each_torrent_is_looked_up_and_announced_again_every_round() {
        let router = FakeNode::start_by_hash();
        let transport = UdpTransport::bind(0).unwrap();
        let port = transport.local_port();
        let node = Arc::new(DhtNode::start_every(transport, port, vec![router.router()], false, Duration::from_millis(300), LOOKUP_BUDGET).unwrap());
        let mut service = node.add_torrent([1; 20], Arc::new(AtomicU16::new(6881)));
        let mut other = node.add_torrent([2; 20], Arc::new(AtomicU16::new(6882)));

        let count = |hash: [u8; 20]| router.announced.lock().unwrap().iter().filter(|h| **h == hash).count();
        wait_until("both to be announced a second time", || count([1; 20]) >= 2 && count([2; 20]) >= 2);
        service.stop();
        other.stop();
        node.stop();
    }

    #[test]
    fn a_torrent_nobody_is_listening_for_is_dropped_by_the_node() {
        let router = FakeNode::start_by_hash();
        let node = started(router.router(), false);
        let service = node.add_torrent([1; 20], Arc::new(AtomicU16::new(6881)));
        drop(service.peers_rx); // the receiving end goes away, as when a session ends
        wait_until("the first lookup", || !router.asked.lock().unwrap().is_empty());
        thread::sleep(Duration::from_millis(500));
        assert!(router.announced.lock().unwrap().is_empty(), "having found nobody to tell, the node lets the torrent go, and does not announce it");
        node.stop();
    }

    #[test]
    fn a_lookup_is_given_the_whole_budget_alone_and_a_share_with_company_but_never_under_a_fifth() {
        let budget = Duration::from_secs(10);
        assert_eq!(lookup_deadline(budget, 0), budget, "no torrents is treated as one");
        assert_eq!(lookup_deadline(budget, 1), budget);
        assert_eq!(lookup_deadline(budget, 2), Duration::from_secs(5));
        assert_eq!(lookup_deadline(budget, 4), Duration::from_millis(2500));
        assert_eq!(lookup_deadline(budget, 5), Duration::from_secs(2));
        assert_eq!(lookup_deadline(budget, 500), Duration::from_secs(2), "the floor");
    }
}
