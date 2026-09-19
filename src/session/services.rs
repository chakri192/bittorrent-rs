//! The background services a session runs alongside the download proper:
//! the DHT node, the inbound-peer listener (seeder) and the router port
//! mapping. One owner, so they start in a sensible order and always stop
//! together.

use crate::dht::{self, DhtService};
use crate::portmap::{self, PortMap};
use crate::seeder::SeederHandle;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;

/// Owns the DHT service, the seeder and the port mapping.
///
/// Dropping it stops all three, so a session that bails out early (no
/// peers, a bad torrent) cannot leave a port mapping on the user's router
/// or a listener running. The individual handles do *not* stop on drop:
/// `SeederHandle` documents as much.
#[derive(Default)]
pub struct Services {
    dht: Option<DhtService>,
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
        match dht::spawn_service(port, bootstrap, info_hash, Arc::clone(&self.dht_announce_port)) {
            Ok(service) => {
                log(format!("DHT node running on UDP port {}", service.port));
                self.dht = Some(service);
            }
            Err(e) => log(format!("DHT disabled (couldn't bind UDP socket): {}", e)),
        }
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
        let udp = self.dht.as_ref().map(|d| d.port).unwrap_or(tcp);
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
        if let Some(mut d) = self.dht.take() {
            d.stop();
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
}
