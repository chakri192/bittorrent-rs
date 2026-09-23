//! The background services a session runs alongside the download proper:
//! the DHT node, local service discovery, the inbound-peer listener (seeder)
//! and the router port mapping. One owner, so they start in a sensible order and always stop
//! together.

use crate::dht::{self, DhtService, SharedTransport};
use crate::lsd::{LsdConfig, LsdService};
use crate::portmap::{self, PortMap};
use crate::seeder::SeederHandle;
use crate::session::network::SharedNetwork;
use crate::utp::socket::Foreign;
use crate::utp::UtpSocket;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;

/// Owns the DHT service, local discovery, the seeder and the port mapping.
///
/// With [`Services::shared`] the listener, the DHT node, the uTP socket and the port mapping
/// are not its own but a [`SharedNetwork`]'s, which serves other torrents too; what it owns
/// then is this torrent's place on them, and stopping it takes the torrent off them and leaves
/// them running.
///
/// Dropping it stops all three, so a session that bails out early (no
/// peers, a bad torrent) cannot leave a port mapping on the user's router
/// or a listener running. The individual handles do *not* stop on drop:
/// `SeederHandle` documents as much.
#[derive(Default)]
pub struct Services {
    dht: Option<DhtService>,
    lsd: Option<LsdService>,
    /// The uTP socket (BEP 29), which the DHT shares if there is one.
    utp: Option<Arc<UtpSocket>>,
    /// Its IPv6 counterpart, if there is one: inbound connections only (see [`super::network::open_utp`]).
    utp6: Option<Arc<UtpSocket>>,
    /// The datagrams on that socket that are not uTP, until the DHT takes them.
    utp_foreign: Option<std::sync::mpsc::Receiver<Foreign>>,
    seeder: Option<SeederHandle>,
    portmap: Option<PortMap>,
    /// The TCP port the DHT service announces for us. Shared with its
    /// thread, and `0` until the seeder's listener is up (the DHT starts
    /// first, since a magnet link may need it before anything else).
    dht_announce_port: Arc<AtomicU16>,
    /// What is shared with other torrents, if this is one of several.
    network: Option<Arc<SharedNetwork>>,
}

impl Services {
    pub fn new() -> Self {
        Self::default()
    }

    /// Services for one torrent among several, on `network`'s ports and sockets.
    pub fn shared(network: Arc<SharedNetwork>) -> Self {
        let mut services = Self::default();
        services.network = Some(network);
        services
    }

    /// The network this torrent shares with others, if it does.
    pub fn network(&self) -> Option<&Arc<SharedNetwork>> {
        self.network.as_ref()
    }

    /// Starts the DHT node on UDP `port` for `info_hash`. Failure to bind
    /// is not fatal: `log` says so and the session goes on without one.
    ///
    /// With `ipv6` a second node runs on an IPv6 socket (BEP 32). `bootstrap`
    /// names the routers to start from as `host:port`; empty means the public
    /// ones.
    pub fn start_dht(&mut self, port: u16, info_hash: [u8; 20], ipv6: bool, bootstrap: Vec<String>, log: impl Fn(String)) {
        // On a shared network the node is already running (or is not wanted); this torrent is given to it.
        if let Some(network) = &self.network {
            if let Some(node) = network.dht() {
                self.dht = Some(node.add_torrent(info_hash, Arc::clone(&self.dht_announce_port)));
            }
            return;
        }
        let bootstrap = if bootstrap.is_empty() { dht::DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()).collect() } else { bootstrap };
        // With a uTP socket, the DHT uses its port, as peers expect one port to do both.
        let started = match self.shared_dht_transport() {
            Some((transport, udp_port)) => dht::spawn_service_on(transport, udp_port, bootstrap, info_hash, Arc::clone(&self.dht_announce_port), ipv6),
            None => dht::spawn_service(port, bootstrap, info_hash, Arc::clone(&self.dht_announce_port), ipv6),
        };
        match started {
            Ok(service) => {
                log(match service.port6 {
                    Some(port6) => format!("DHT nodes running on UDP port {} (IPv4) and {} (IPv6)", service.port, port6),
                    None => format!("DHT node running on UDP port {}", service.port),
                });
                self.dht = Some(service);
            }
            Err(e) => log(format!("DHT disabled (couldn't bind UDP socket): {}", e)),
        }
    }

    /// Opens the UDP port for uTP connections (BEP 29), `port` if it is free. With `ipv6`, a second
    /// socket takes inbound uTP connections from IPv6 peers too (outbound uTP dialing stays IPv4 alone).
    /// Failure is not fatal: `log` says so and connections are made over TCP.
    pub fn start_utp(&mut self, port: u16, ipv6: bool, log: impl Fn(String)) {
        if self.network.is_some() {
            return; // the network's
        }
        match super::network::open_utp(port, ipv6) {
            Ok((socket, rx, socket6)) => {
                log(format!("uTP running on UDP port {}{}", socket.local_addr().map(|a| a.port()).unwrap_or(0), if socket6.is_some() { " (IPv4 and IPv6)" } else { "" }));
                self.utp = Some(socket);
                self.utp6 = socket6;
                self.utp_foreign = Some(rx);
            }
            Err(e) => log(format!("uTP disabled (couldn't bind UDP socket): {}", e)),
        }
    }

    /// The DHT's way of using the uTP socket's port, and that port, if there
    /// is a socket and the DHT has not already taken it.
    fn shared_dht_transport(&mut self) -> Option<(SharedTransport, u16)> {
        let (utp, foreign) = (self.utp.as_ref()?, self.utp_foreign.take()?);
        let transport = SharedTransport::new(Arc::clone(utp), foreign);
        let port = transport.local_port();
        Some((transport, port))
    }

    /// The uTP socket, if one is running.
    pub fn utp(&self) -> Option<Arc<UtpSocket>> {
        self.utp.clone().or_else(|| self.network.as_ref().and_then(|n| n.utp()))
    }

    /// Its IPv6 counterpart, if one joined.
    pub fn utp6(&self) -> Option<Arc<UtpSocket>> {
        self.utp6.clone().or_else(|| self.network.as_ref().and_then(|n| n.utp6()))
    }

    /// Starts announcing the torrent on the local network (BEP 14) and
    /// listening for others doing the same. Failure to set up the socket
    /// (no multicast route, say) is not fatal: `log` says so and the session
    /// goes on without it.
    pub fn start_lsd(&mut self, config: LsdConfig, info_hash: [u8; 20], tcp_port: u16, log: impl Fn(String)) {
        match LsdService::start(config, info_hash, tcp_port) {
            Ok(service) => {
                log(format!("local service discovery running (announcing port {}{})", tcp_port, if service.ipv6_joined { ", IPv4 and IPv6" } else { "" }));
                self.lsd = Some(service);
            }
            Err(e) => log(format!("local service discovery disabled: {}", e)),
        }
    }

    /// The running local-discovery service, if there is one.
    pub fn lsd(&self) -> Option<&LsdService> {
        self.lsd.as_ref()
    }

    /// The running DHT node, if there is one.
    pub fn dht(&self) -> Option<&DhtService> {
        self.dht.as_ref()
    }

    /// Stops and discards the DHT node. Used once a magnet link turns out
    /// to name a private torrent, which must not touch the DHT.
    pub fn stop_dht(&mut self) {
        if let Some(mut d) = self.dht.take() {
            d.stop();
        }
    }

    /// Takes ownership of a started seeder and tells the DHT which port to
    /// announce for us.
    pub fn attach_seeder(&mut self, seeder: SeederHandle) {
        self.dht_announce_port.store(seeder.port, Ordering::SeqCst);
        self.seeder = Some(seeder);
    }

    /// The seeder this torrent is served by, if there is one.
    pub fn seeder(&self) -> Option<&SeederHandle> {
        self.seeder.as_ref()
    }

    pub fn has_seeder(&self) -> bool {
        self.seeder.is_some()
    }

    /// The TCP port to announce to trackers: the seeder's, else `fallback`.
    pub fn announce_port(&self, fallback: u16) -> u16 {
        self.seeder.as_ref().map(|s| s.port).unwrap_or(fallback)
    }

    /// The limit the seeder's uploads are held to, for tests to see whose it is.
    #[cfg(test)]
    pub(crate) fn seeder_up_limit(&self) -> Option<Arc<crate::ratelimit::RateLimiter>> {
        self.seeder.as_ref().and_then(|s| s.up_limit())
    }

    /// Bytes uploaded so far, as a counter that stays readable after the
    /// seeder is stopped. `None` without a seeder.
    pub fn uploaded_counter(&self) -> Option<Arc<AtomicU64>> {
        self.seeder.as_ref().map(|s| Arc::clone(&s.uploaded))
    }

    /// Asks the router to forward the seeder's TCP port and the DHT's UDP
    /// port (UPnP/NAT-PMP), best effort and off-thread. Does nothing
    /// without a seeder: with nothing listening there is nothing to forward.
    pub fn start_portmap(&mut self, log: impl Fn(String) + Send + 'static) {
        if self.network.is_some() {
            return; // mapped once, for all the torrents, when the network started
        }
        let Some(seeder) = &self.seeder else { return };
        let tcp = seeder.port;
        let udp = self.dht.as_ref().map(|d| d.port).or_else(|| self.utp.as_ref().and_then(|u| u.local_addr().ok()).map(|a| a.port())).unwrap_or(tcp);
        self.portmap = portmap::map_ports(tcp, udp, log);
    }

    /// Stops everything: port mapping first (so the mapping is removed
    /// while the ports still answer), then the listener, then the DHT.
    /// Safe to call more than once.
    pub fn shutdown(&mut self) {
        if let Some(mut p) = self.portmap.take() {
            p.stop();
        }
        if let Some(mut s) = self.seeder.take() {
            s.stop();
        }
        if let Some(mut l) = self.lsd.take() {
            l.stop();
        }
        if let Some(mut d) = self.dht.take() {
            d.stop();
        }
        if let Some(utp) = self.utp.take() {
            utp.shutdown();
        }
        if let Some(utp6) = self.utp6.take() {
            utp6.shutdown();
        }
    }
}

impl Drop for Services {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seeder::{self, HaveMap};
    use std::net::{TcpStream, UdpSocket};

    /// A real seeder on an ephemeral loopback-reachable port, serving nothing.
    fn idle_seeder() -> SeederHandle {
        seeder::start(0, [0x11; 20], [0x22; 20], Arc::new(Vec::new()), 16384, 0, Arc::new(HaveMap::new(0)), None).expect("start seeder")
    }

    #[test]
    fn a_fresh_services_has_nothing_running() {
        let s = Services::new();
        assert!(s.dht().is_none());
        assert!(!s.has_seeder());
        assert!(s.uploaded_counter().is_none());
        assert_eq!(s.announce_port(6881), 6881, "without a seeder the fallback port is announced");
    }

    #[test]
    fn shutdown_with_nothing_running_is_harmless_and_repeatable() {
        let mut s = Services::new();
        s.shutdown();
        s.shutdown();
        s.stop_dht();
    }

    #[test]
    fn attaching_a_seeder_sets_the_announce_ports() {
        let mut s = Services::new();
        let seeder = idle_seeder();
        let port = seeder.port;
        s.attach_seeder(seeder);

        assert!(s.has_seeder());
        assert_eq!(s.announce_port(1), port, "trackers are told the port actually bound");
        assert_eq!(s.dht_announce_port.load(Ordering::SeqCst), port, "and so is the DHT service");
        assert!(s.uploaded_counter().is_some());
    }

    #[test]
    fn the_uploaded_counter_outlives_shutdown() {
        let mut s = Services::new();
        s.attach_seeder(idle_seeder());
        let counter = s.uploaded_counter().unwrap();
        counter.store(42, Ordering::SeqCst);
        s.shutdown();
        assert_eq!(counter.load(Ordering::SeqCst), 42, "the final summary reads it after the seeder is gone");
    }

    #[test]
    fn dropping_services_stops_the_listener() {
        let mut s = Services::new();
        s.attach_seeder(idle_seeder());
        let port = s.announce_port(0);
        assert!(TcpStream::connect(("127.0.0.1", port)).is_ok(), "the listener is up beforehand");

        drop(s); // what an early `return Err(..)` in the session does

        assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "stop joins the accept thread, closing the socket");
    }

    #[test]
    fn shutdown_takes_the_port_mapping_off_the_router_while_the_listener_still_answers() {
        let mut s = Services::new();
        s.attach_seeder(idle_seeder());
        let port = s.announce_port(0);
        let removed_while_listening = Arc::new(std::sync::Mutex::new(None));
        let seen = Arc::clone(&removed_while_listening);
        s.portmap = Some(PortMap::fake(move || *seen.lock().unwrap() = Some(TcpStream::connect(("127.0.0.1", port)).is_ok())));

        s.shutdown();

        assert_eq!(*removed_while_listening.lock().unwrap(), Some(true));
    }

    #[test]
    fn port_mapping_is_not_attempted_without_a_seeder() {
        let mut s = Services::new();
        s.start_portmap(|_| {});
        assert!(s.portmap.is_none());
    }

    fn loopback_lsd(listen_port: u16) -> LsdConfig {
        LsdConfig { send_to: std::net::SocketAddr::from(([127, 0, 0, 1], 9)), listen: std::net::SocketAddr::from(([127, 0, 0, 1], listen_port)), join: None, share_port: false, interval: std::time::Duration::from_secs(3600), reply_interval: std::time::Duration::from_secs(3600), ipv6: false }
    }

    #[test]
    fn local_discovery_is_running_once_started_and_gone_after_shutdown() {
        let mut s = Services::new();
        assert!(s.lsd().is_none());
        let logged = std::sync::Mutex::new(Vec::new());
        s.start_lsd(loopback_lsd(0), [0x11; 20], 6881, |m| logged.lock().unwrap().push(m));
        let addr = s.lsd().expect("started").listen_addr;
        assert!(logged.lock().unwrap()[0].contains("6881"), "it says which port it announces: {:?}", logged.lock().unwrap());
        assert!(std::net::UdpSocket::bind(addr).is_err(), "and holds its socket");

        s.shutdown();

        assert!(s.lsd().is_none());
        assert!(std::net::UdpSocket::bind(addr).is_ok(), "shutdown released the socket");
    }

    #[cfg(unix)]
    #[test]
    fn the_log_says_when_ipv6_is_joined_too() {
        let mut s = Services::new();
        let logged = std::sync::Mutex::new(Vec::new());
        s.start_lsd(loopback_lsd(0), [0x11; 20], 6881, |m| logged.lock().unwrap().push(m));
        assert!(!logged.lock().unwrap()[0].contains("IPv6"), "not asked for, not mentioned: {:?}", logged.lock().unwrap());
        s.shutdown();

        let logged6 = std::sync::Mutex::new(Vec::new());
        let config = crate::lsd::LsdConfig { ipv6: true, share_port: true, ..loopback_lsd(0) };
        s.start_lsd(config, [0x11; 20], 6882, |m| logged6.lock().unwrap().push(m));
        assert!(logged6.lock().unwrap()[0].contains("IPv4 and IPv6"), "asked for, and this machine can join it: {:?}", logged6.lock().unwrap());
        s.shutdown();
    }

    #[test]
    fn local_discovery_that_cannot_start_is_reported_and_the_session_goes_on_without_it() {
        // The address is taken, and this config does not share.
        let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut s = Services::new();
        let logged = std::sync::Mutex::new(Vec::new());
        s.start_lsd(loopback_lsd(taken.local_addr().unwrap().port()), [0x11; 20], 6881, |m| logged.lock().unwrap().push(m));
        assert!(s.lsd().is_none());
        assert!(logged.lock().unwrap()[0].contains("disabled"), "{:?}", logged.lock().unwrap());
    }

    #[test]
    fn a_utp_socket_is_running_once_started_and_gone_after_shutdown() {
        let mut s = Services::new();
        assert!(s.utp().is_none());
        let logged = std::sync::Mutex::new(Vec::new());
        s.start_utp(0, false, |m| logged.lock().unwrap().push(m));
        let utp = s.utp().expect("started");
        let port = utp.local_addr().unwrap().port();
        assert!(logged.lock().unwrap()[0].contains(&port.to_string()), "it says which port: {:?}", logged.lock().unwrap());

        s.shutdown();
        drop(utp);

        assert!(s.utp().is_none());
        assert!(std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok(), "the port is free again");
    }

    #[test]
    fn a_utp_socket_that_cannot_take_the_preferred_port_takes_another() {
        let taken = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let taken_port = taken.local_addr().unwrap().port();
        let mut s = Services::new();
        s.start_utp(taken_port, false, |_| {});
        let port = s.utp().expect("still started").local_addr().unwrap().port();
        assert_ne!(port, taken_port);
    }

    #[test]
    fn asking_for_ipv6_gives_a_second_utp_socket_and_the_log_says_so() {
        if std::net::UdpSocket::bind("[::1]:0").is_err() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        let mut s = Services::new();
        assert!(s.utp6().is_none());
        let logged = std::sync::Mutex::new(Vec::new());
        s.start_utp(0, true, |m| logged.lock().unwrap().push(m));
        assert!(s.utp().is_some(), "the IPv4 socket still runs");
        assert!(s.utp6().is_some(), "and now the IPv6 one too");
        assert!(logged.lock().unwrap()[0].contains("IPv4 and IPv6"), "{:?}", logged.lock().unwrap());
        s.shutdown();
        assert!(s.utp6().is_none());
    }

    #[test]
    fn without_ipv6_asked_for_there_is_no_second_utp_socket_and_the_log_does_not_mention_it() {
        let mut s = Services::new();
        let logged = std::sync::Mutex::new(Vec::new());
        s.start_utp(0, false, |m| logged.lock().unwrap().push(m));
        assert!(s.utp6().is_none());
        assert!(!logged.lock().unwrap()[0].contains("IPv6"), "{:?}", logged.lock().unwrap());
    }

    #[test]
    fn the_dht_takes_the_utp_sockets_port_once_and_only_when_there_is_a_socket() {
        let mut s = Services::new();
        assert!(s.shared_dht_transport().is_none(), "no socket, nothing to share");
        s.start_utp(0, false, |_| {});
        let port = s.utp().unwrap().local_addr().unwrap().port();
        let (_, shared_port) = s.shared_dht_transport().expect("the DHT can have it");
        assert_eq!(shared_port, port, "the same port, so one number serves TCP peers' uTP and the DHT");
        assert!(s.shared_dht_transport().is_none(), "but only one DHT can");
    }

    use crate::session::network::tests::{handshake, no_dht, quiet_network};
    use crate::session::network::NetworkConfig;

    fn on_network(network: &Arc<SharedNetwork>, info_hash: [u8; 20]) -> Services {
        let mut services = Services::shared(Arc::clone(network));
        let handle = network.register(info_hash, [7; 20], Arc::new(Vec::new()), 16384, 0, Arc::new(HaveMap::new(0)), network.up_limit(), Default::default());
        services.attach_seeder(handle);
        services
    }

    #[test]
    fn a_torrent_stopping_takes_it_off_the_shared_port_and_leaves_the_port_open_for_the_others() {
        let network = quiet_network(no_dht());
        let (a, b) = ([0xAA; 20], [0xBB; 20]);
        let (mut first, second) = (on_network(&network, a), on_network(&network, b));
        assert_eq!(first.announce_port(0), network.port, "each announces the shared port");
        assert_eq!(second.announce_port(0), network.port);

        first.shutdown();

        assert_eq!(handshake(network.port, a), None);
        assert_eq!(handshake(network.port, b), Some(b), "the port stayed open");
        drop(second);
        assert_eq!(network.torrent_count(), 0, "and dropping the last takes it off too");
        assert!(std::net::TcpStream::connect(("127.0.0.1", network.port)).is_ok(), "though the listener is the network's, and still listens");
        network.shutdown();
    }

    #[test]
    fn shared_services_give_their_torrent_to_the_networks_dht_node_and_leave_it_running() {
        let network = quiet_network(NetworkConfig { dht: true, dht_bootstrap: vec!["127.0.0.1:9".to_string()], ..no_dht() });
        let node_port = network.dht().unwrap().port;
        let (mut first, mut second) = (Services::shared(Arc::clone(&network)), Services::shared(Arc::clone(&network)));
        first.start_dht(0, [1; 20], false, Vec::new(), |_| {});
        second.start_dht(0, [2; 20], false, Vec::new(), |_| {});
        assert_eq!((first.dht().map(|d| d.port), second.dht().map(|d| d.port)), (Some(node_port), Some(node_port)), "both are on the one node");

        first.shutdown();

        assert!(UdpSocket::bind(("0.0.0.0", node_port)).is_err(), "the node is still there, holding its port");
        second.stop_dht();
        assert!(UdpSocket::bind(("0.0.0.0", node_port)).is_err(), "and still, with no torrent on it");
        network.shutdown();
    }

    #[test]
    fn shared_services_start_no_dht_when_the_network_has_none() {
        let network = quiet_network(no_dht());
        let mut services = Services::shared(Arc::clone(&network));
        services.start_dht(0, [1; 20], false, Vec::new(), |_| {});
        assert!(services.dht().is_none(), "nor open a socket of their own for one");
        network.shutdown();
    }

    #[test]
    fn shared_services_use_the_networks_utp_socket_and_do_not_open_or_close_one() {
        let network = quiet_network(NetworkConfig { transport: crate::peer::TransportMode::Both, ..no_dht() });
        let mut services = Services::shared(Arc::clone(&network));
        services.start_utp(0, false, |_| panic!("no socket of its own to log about"));
        let socket = services.utp().expect("the network's");
        assert!(Arc::ptr_eq(&socket, &network.utp().unwrap()));
        let port = socket.local_addr().unwrap().port();

        services.shutdown();

        assert!(network.utp().unwrap().is_running(), "the socket is still running for the other torrents");
        assert!(UdpSocket::bind(("0.0.0.0", port)).is_err(), "and open");
        network.shutdown();
        assert!(!socket.is_running(), "until the network ends it");
    }

    #[test]
    fn shared_services_use_the_networks_ipv6_utp_socket_too() {
        if std::net::UdpSocket::bind("[::1]:0").is_err() {
            eprintln!("no IPv6 here; skipped");
            return;
        }
        let network = quiet_network(NetworkConfig { transport: crate::peer::TransportMode::Both, ipv6: true, ..no_dht() });
        let services = Services::shared(Arc::clone(&network));
        let socket6 = services.utp6().expect("the network's IPv6 socket");
        assert!(Arc::ptr_eq(&socket6, &network.utp6().unwrap()));
        network.shutdown();
    }

    #[test]
    fn shared_services_leave_port_mapping_to_the_network() {
        let network = quiet_network(no_dht());
        let mut services = on_network(&network, [1; 20]);
        services.start_portmap(|_| panic!("a torrent maps no ports of its own"));
        assert!(services.portmap.is_none());
        network.shutdown();
    }
}
