//! What every torrent of a daemon shares: one port that takes inbound peers for all of them,
//! one DHT node per address family, one uTP socket, one port mapping on the router, and the
//! rate limits. A client with a single torrent has these too, but to itself (see [`Services`]);
//! here they belong to the process and the torrents come and go on them.
//!
//! [`Services`]: super::Services

use crate::dht::{self, DhtNode, SharedTransport};
use crate::peer::{Encryption, TransportMode};
use crate::portmap::{self, PortMap};
use crate::ratelimit::RateLimiter;
use crate::seeder::{HaveMap, Listener, ListenerOptions, SeederHandle, SeederOptions};
use crate::sync::lock;
use crate::downloader::FileSpan;
use crate::utp::UtpSocket;
use std::io;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};

/// How the shared network is set up.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Preferred port, TCP and UDP; others are used if it is taken.
    pub port: u16,
    /// Whether uTP (BEP 29) is running: a socket for it, taking inbound connections.
    pub transport: TransportMode,
    /// Message stream encryption for what the listener takes; `None` takes either kind.
    pub encryption: Option<Encryption>,
    /// Whether a DHT node runs, and the routers it starts from (`host:port`; the public ones if empty).
    pub dht: bool,
    pub dht_bootstrap: Vec<String>,
    /// Whether the listener and the DHT take IPv6 as well (BEP 32).
    pub ipv6: bool,
    /// Whether the router is asked to forward the ports (UPnP, NAT-PMP).
    pub portmap: bool,
    /// Limits on the bytes per second over every torrent together.
    pub max_up: Option<u64>,
    pub max_down: Option<u64>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig { port: 6881, transport: TransportMode::Tcp, encryption: None, dht: true, dht_bootstrap: Vec::new(), ipv6: false, portmap: true, max_up: None, max_down: None }
    }
}

/// The ports, sockets and limits shared by all the torrents of a process.
pub struct SharedNetwork {
    /// The TCP port peers connect to.
    pub port: u16,
    /// Whether IPv6 connections are taken too, on the same port.
    pub ipv6: bool,
    listener: Mutex<Listener>,
    utp: Option<Arc<UtpSocket>>,
    dht: Option<Arc<DhtNode>>,
    portmap: Mutex<Option<PortMap>>,
    up_limit: Option<Arc<RateLimiter>>,
    down_limit: Option<Arc<RateLimiter>>,
}

impl SharedNetwork {
    /// Opens the ports. The listener must open, as there is nothing to be without it; a uTP
    /// socket or a DHT node that cannot is reported to `log` and left out.
    pub fn start(config: &NetworkConfig, log: impl Fn(String) + Send + Sync + 'static) -> io::Result<SharedNetwork> {
        let log = Arc::new(log);

        let mut utp_rx = None;
        let utp = if config.transport.wants_utp() {
            match open_utp(config.port) {
                Ok((socket, foreign)) => {
                    log(format!("uTP running on UDP port {}", socket.local_addr().map(|a| a.port()).unwrap_or(0)));
                    utp_rx = Some(foreign);
                    Some(socket)
                }
                Err(e) => {
                    log(format!("uTP disabled (couldn't bind UDP socket): {}", e));
                    None
                }
            }
        } else {
            None
        };

        let dht = if config.dht {
            let bootstrap = if config.dht_bootstrap.is_empty() { dht::DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()).collect() } else { config.dht_bootstrap.clone() };
            // With a uTP socket the DHT takes its port, as peers expect one number to do for both.
            let started = match (&utp, utp_rx.take()) {
                (Some(socket), Some(foreign)) => {
                    let transport = SharedTransport::new(Arc::clone(socket), foreign);
                    let port = transport.local_port();
                    DhtNode::start_on(transport, port, bootstrap, config.ipv6)
                }
                _ => DhtNode::start(config.port, bootstrap, config.ipv6),
            };
            match started {
                Ok(node) => {
                    log(match node.port6 {
                        Some(port6) => format!("DHT nodes running on UDP port {} (IPv4) and {} (IPv6)", node.port, port6),
                        None => format!("DHT node running on UDP port {}", node.port),
                    });
                    Some(Arc::new(node))
                }
                Err(e) => {
                    log(format!("DHT disabled (couldn't bind UDP socket): {}", e));
                    None
                }
            }
        } else {
            None
        };

        let listener = match Listener::start(config.port, ListenerOptions { encryption: config.encryption.unwrap_or(Encryption::Prefer), ipv6: config.ipv6, utp: utp.clone() }) {
            Ok(listener) => listener,
            Err(e) => {
                // Not left running with nobody to serve.
                if let Some(dht) = &dht {
                    dht.stop();
                }
                if let Some(utp) = &utp {
                    utp.shutdown();
                }
                return Err(e);
            }
        };
        let port = listener.port;
        let ipv6 = listener.ipv6;
        log(format!("listening for inbound peers on port {}{}", port, if ipv6 { " (IPv4 and IPv6)" } else { "" }));

        let portmap = if config.portmap {
            let udp = dht.as_ref().map(|d| d.port).or_else(|| utp.as_ref().and_then(|u| u.local_addr().ok()).map(|a| a.port())).unwrap_or(port);
            let log = Arc::clone(&log);
            portmap::map_ports(port, udp, move |m| log(m))
        } else {
            None
        };
        Ok(SharedNetwork { port, ipv6, listener: Mutex::new(listener), utp, dht, portmap: Mutex::new(portmap), up_limit: config.max_up.map(|rate| Arc::new(RateLimiter::new(rate))), down_limit: config.max_down.map(|rate| Arc::new(RateLimiter::new(rate))) })
    }

    /// The uTP socket, if one is running.
    pub fn utp(&self) -> Option<Arc<UtpSocket>> {
        self.utp.clone()
    }

    /// The DHT node, if one is running.
    pub fn dht(&self) -> Option<&Arc<DhtNode>> {
        self.dht.as_ref()
    }

    /// The limit on uploading over every torrent, if there is one.
    pub fn up_limit(&self) -> Option<Arc<RateLimiter>> {
        self.up_limit.clone()
    }

    /// The limit on downloading over every torrent, if there is one.
    pub fn down_limit(&self) -> Option<Arc<RateLimiter>> {
        self.down_limit.clone()
    }

    /// How many torrents peers can connect to.
    pub fn torrent_count(&self) -> usize {
        lock(&self.listener).torrent_count()
    }

    /// Starts serving a torrent on the shared port.
    #[allow(clippy::too_many_arguments)]
    pub fn register(&self, info_hash: [u8; 20], our_peer_id: [u8; 20], spans: Arc<Vec<FileSpan>>, piece_length: u64, total_length: u64, have: Arc<HaveMap>, options: SeederOptions) -> SeederHandle {
        lock(&self.listener).register(info_hash, our_peer_id, spans, piece_length, total_length, have, self.up_limit(), options)
    }

    /// Stops everything: the port mapping first (so it is removed while the ports still answer),
    /// then the listener, the DHT and uTP. Safe to call twice.
    pub fn shutdown(&self) {
        if let Some(mut mapping) = lock(&self.portmap).take() {
            mapping.stop();
        }
        lock(&self.listener).stop();
        if let Some(dht) = &self.dht {
            dht.stop();
        }
        if let Some(utp) = &self.utp {
            utp.shutdown();
        }
    }
}

/// Opens the UDP socket for uTP, `port` if it is free, with the channel the datagrams that are
/// not uTP arrive on.
pub(super) fn open_utp(port: u16) -> io::Result<(Arc<UtpSocket>, std::sync::mpsc::Receiver<crate::utp::socket::Foreign>)> {
    let socket = UdpSocket::bind(("0.0.0.0", port)).or_else(|_| UdpSocket::bind(("0.0.0.0", 0)))?;
    let (tx, rx) = std::sync::mpsc::channel();
    Ok((Arc::new(UtpSocket::with_socket(socket, Some(tx))?), rx))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    /// A configuration that reaches nowhere beyond the machine: no DHT, no port mapping.
    pub(crate) fn no_dht() -> NetworkConfig {
        NetworkConfig { dht: false, portmap: false, ..Default::default() }
    }

    /// A network on loopback-reachable ports of its own, with nothing that reaches beyond the machine.
    pub(crate) fn quiet_network(config: NetworkConfig) -> Arc<SharedNetwork> {
        Arc::new(SharedNetwork::start(&NetworkConfig { port: 0, portmap: false, ..config }, |_| {}).expect("the network starts"))
    }

    /// Connects to `port` and shakes hands asking for `info_hash`: the info hash the answer names,
    /// or `None` if the other end hangs up instead.
    pub(crate) fn handshake(port: u16, info_hash: [u8; 20]) -> Option<[u8; 20]> {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut hello = vec![19u8];
        hello.extend_from_slice(b"BitTorrent protocol");
        hello.extend_from_slice(&[0u8; 8]);
        hello.extend_from_slice(&info_hash);
        hello.extend_from_slice(&[9u8; 20]);
        stream.write_all(&hello).ok()?;
        let mut reply = [0u8; 68];
        stream.read_exact(&mut reply).ok()?;
        reply[28..48].try_into().ok()
    }

    fn idle(network: &SharedNetwork, info_hash: [u8; 20]) -> SeederHandle {
        network.register(info_hash, [7; 20], Arc::new(Vec::new()), 16384, 0, Arc::new(HaveMap::new(0)), SeederOptions::default())
    }

    #[test]
    fn one_port_serves_every_torrent_registered_on_it() {
        let network = quiet_network(no_dht());
        let (a, b) = ([0xAA; 20], [0xBB; 20]);
        let (mut first, mut second) = (idle(&network, a), idle(&network, b));
        assert_eq!((first.port, second.port), (network.port, network.port));
        assert_eq!(network.torrent_count(), 2);

        assert_eq!(handshake(network.port, a), Some(a));
        assert_eq!(handshake(network.port, b), Some(b));
        assert_eq!(handshake(network.port, [0xCC; 20]), None, "and one that is not served is refused");

        first.stop();
        assert_eq!(handshake(network.port, a), None, "a torrent taken off it is no longer served");
        assert_eq!(handshake(network.port, b), Some(b), "and the other one is");
        second.stop();
        network.shutdown();
    }

    #[test]
    fn the_limits_are_one_limiter_for_every_torrent() {
        let network = quiet_network(NetworkConfig { max_up: Some(1000), max_down: Some(2000), ..no_dht() });
        assert!(Arc::ptr_eq(&network.up_limit().unwrap(), &network.up_limit().unwrap()), "the same one each time");
        assert!(network.down_limit().is_some());
        network.shutdown();
        assert!(quiet_network(no_dht()).up_limit().is_none(), "none unless asked for");
    }

    #[test]
    fn every_torrent_registered_is_held_to_the_networks_upload_limit() {
        let network = quiet_network(NetworkConfig { max_up: Some(1000), ..no_dht() });
        let (mut a, mut b) = (idle(&network, [1; 20]), idle(&network, [2; 20]));
        let shared = network.up_limit().unwrap();
        assert!(Arc::ptr_eq(&a.up_limit().unwrap(), &shared) && Arc::ptr_eq(&b.up_limit().unwrap(), &shared), "one limit, not one each");
        a.stop();
        b.stop();
        network.shutdown();

        let unlimited = quiet_network(no_dht());
        assert!(idle(&unlimited, [1; 20]).up_limit().is_none());
        unlimited.shutdown();
    }

    #[test]
    fn shutdown_frees_the_port_and_can_be_repeated() {
        let network = quiet_network(no_dht());
        let port = network.port;
        assert!(handshake(port, [1; 20]).is_none() && TcpStream::connect(("127.0.0.1", port)).is_ok(), "listening");
        network.shutdown();
        network.shutdown();
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "no longer");
    }

    #[test]
    fn the_dht_shares_the_utp_sockets_port_and_both_are_the_networks() {
        let network = quiet_network(NetworkConfig { transport: TransportMode::Both, dht: true, dht_bootstrap: vec!["127.0.0.1:9".to_string()], ..no_dht() });
        let utp = network.utp().expect("uTP is running");
        let dht = network.dht().expect("and the DHT");
        assert_eq!(utp.local_addr().unwrap().port(), dht.port, "one UDP port for both");
        let port = dht.port;
        network.shutdown();
        drop((utp, network));
        assert!(UdpSocket::bind(("0.0.0.0", port)).is_ok(), "released");
    }

    #[test]
    fn without_them_asked_for_neither_utp_nor_the_dht_runs() {
        let network = quiet_network(no_dht());
        assert!(network.utp().is_none() && network.dht().is_none());
        network.shutdown();
    }
}
