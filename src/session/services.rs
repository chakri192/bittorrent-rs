//! The background services a session runs alongside the download proper:
//! the DHT node, local service discovery, the inbound-peer listener (seeder)
//! and the router port mapping. One owner, so they start in a sensible order and always stop
//! together.

use crate::dht::{self, DhtService, SharedTransport};
use crate::lsd::{LsdConfig, LsdService};
use crate::portmap::{self, PortMap};
use crate::seeder::SeederHandle;
use crate::utp::socket::Foreign;
use crate::utp::UtpSocket;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;

/// Owns the DHT service, local discovery, the seeder and the port mapping.
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
    /// The datagrams on that socket that are not uTP, until the DHT takes them.
    utp_foreign: Option<std::sync::mpsc::Receiver<Foreign>>,
    seeder: Option<SeederHandle>,
    portmap: Option<PortMap>,
    /// The TCP port the DHT service announces for us. Shared with its
    /// thread, and `0` until the seeder's listener is up (the DHT starts
    /// first, since a magnet link may need it before anything else).
    dht_announce_port: Arc<AtomicU16>,
}

impl Services {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts the DHT node on UDP `port` for `info_hash`. Failure to bind
    /// is not fatal: `log` says so and the session goes on without one.
    pub fn start_dht(&mut self, port: u16, info_hash: [u8; 20], log: impl Fn(String)) {
        let bootstrap = dht::DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()).collect();
        // With a uTP socket, the DHT uses its port, as peers expect one port to do both.
        let started = match self.shared_dht_transport() {
            Some((transport, udp_port)) => dht::spawn_service_on(transport, udp_port, bootstrap, info_hash, Arc::clone(&self.dht_announce_port)),
            None => dht::spawn_service(port, bootstrap, info_hash, Arc::clone(&self.dht_announce_port)),
        };
        match started {
            Ok(service) => {
                log(format!("DHT node running on UDP port {}", service.port));
                self.dht = Some(service);
            }
            Err(e) => log(format!("DHT disabled (couldn't bind UDP socket): {}", e)),
        }
    }

    /// Opens the UDP port for uTP connections (BEP 29), `port` if it is free.
    /// Failure is not fatal: `log` says so and connections are made over TCP.
    pub fn start_utp(&mut self, port: u16, log: impl Fn(String)) {
        let bound = UdpSocket::bind(("0.0.0.0", port)).or_else(|_| UdpSocket::bind(("0.0.0.0", 0)));
        let (tx, rx) = std::sync::mpsc::channel();
        match bound.and_then(|socket| UtpSocket::with_socket(socket, Some(tx))) {
            Ok(socket) => {
                log(format!("uTP running on UDP port {}", socket.local_addr().map(|a| a.port()).unwrap_or(0)));
                self.utp = Some(Arc::new(socket));
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
        self.utp.clone()
    }

    /// Starts announcing the torrent on the local network (BEP 14) and
    /// listening for others doing the same. Failure to set up the socket
    /// (no multicast route, say) is not fatal: `log` says so and the session
    /// goes on without it.
    pub fn start_lsd(&mut self, config: LsdConfig, info_hash: [u8; 20], tcp_port: u16, log: impl Fn(String)) {
        match LsdService::start(config, info_hash, tcp_port) {
            Ok(service) => {
                log(format!("local service discovery running (announcing port {})", tcp_port));
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

    pub fn has_seeder(&self) -> bool {
        self.seeder.is_some()
    }

    /// The TCP port to announce to trackers: the seeder's, else `fallback`.
    pub fn announce_port(&self, fallback: u16) -> u16 {
        self.seeder.as_ref().map(|s| s.port).unwrap_or(fallback)
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
    use std::net::TcpStream;

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
    fn port_mapping_is_not_attempted_without_a_seeder() {
        let mut s = Services::new();
        s.start_portmap(|_| {});
        assert!(s.portmap.is_none());
    }

    fn loopback_lsd(listen_port: u16) -> LsdConfig {
        LsdConfig { send_to: std::net::SocketAddr::from(([127, 0, 0, 1], 9)), listen: std::net::SocketAddr::from(([127, 0, 0, 1], listen_port)), join: None, share_port: false, interval: std::time::Duration::from_secs(3600) }
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
        s.start_utp(0, |m| logged.lock().unwrap().push(m));
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
        s.start_utp(taken_port, |_| {});
        let port = s.utp().expect("still started").local_addr().unwrap().port();
        assert_ne!(port, taken_port);
    }

    #[test]
    fn the_dht_takes_the_utp_sockets_port_once_and_only_when_there_is_a_socket() {
        let mut s = Services::new();
        assert!(s.shared_dht_transport().is_none(), "no socket, nothing to share");
        s.start_utp(0, |_| {});
        let port = s.utp().unwrap().local_addr().unwrap().port();
        let (_, shared_port) = s.shared_dht_transport().expect("the DHT can have it");
        assert_eq!(shared_port, port, "the same port, so one number serves TCP peers' uTP and the DHT");
        assert!(s.shared_dht_transport().is_none(), "but only one DHT can");
    }
}
