//! Best-effort automatic port forwarding so inbound peers and DHT queries
//! can reach this client behind a home router. Two mechanisms, tried in
//! order:
//!
//!  1. **NAT-PMP** (RFC 6886) -- hand-rolled here: a tiny fixed-layout UDP
//!     request to the gateway on port 5351. Fast, and the packet codec is
//!     unit-tested. The gateway address is guessed from the LAN IP (the
//!     `.1`/`.254` of the local /24), which covers the overwhelming
//!     majority of consumer routers without a routing-table dependency.
//!  2. **UPnP IGD** -- via the `igd-next` crate, which finds the gateway
//!     by SSDP multicast (no address guess needed).
//!
//! Everything is best-effort and runs on a background thread: mapping
//! never blocks startup, and if no gateway cooperates the client simply
//! stays outbound-only (exactly its prior behaviour). A lease-refresh
//! loop renews the mapping until `stop`, which then tears it down.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const NATPMP_PORT: u16 = 5351;
const NATPMP_OP_UDP: u8 = 1;
const NATPMP_OP_TCP: u8 = 2;
/// Requested lease. Routers may grant less; we refresh at half this.
const LEASE_SECS: u32 = 3600;
const DESC: &str = "bittorrent-rs";
const RPC_TIMEOUT: Duration = Duration::from_millis(300);

#[derive(Debug)]
pub enum NatpmpError {
    ShortResponse,
    BadVersion(u8),
    NotAResponse(u8),
    ResultCode(u16),
}

impl std::fmt::Display for NatpmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatpmpError::ShortResponse => write!(f, "NAT-PMP response too short"),
            NatpmpError::BadVersion(v) => write!(f, "NAT-PMP unexpected version {}", v),
            NatpmpError::NotAResponse(op) => write!(f, "NAT-PMP op {} is not a response", op),
            NatpmpError::ResultCode(c) => write!(f, "NAT-PMP result code {}", c),
        }
    }
}

/// A NAT-PMP map response (`op` is the request op + 128).
#[derive(Debug, PartialEq, Eq)]
pub struct MapResponse {
    pub result: u16,
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime: u32,
}

/// Builds a NAT-PMP map request: 12 fixed bytes.
fn encode_map_request(op: u8, internal_port: u16, suggested_external: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = 0; // version
    b[1] = op;
    // b[2..4] reserved (zero)
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

/// Parses a NAT-PMP map response (16 bytes), validating version, op, and
/// result code.
fn parse_map_response(buf: &[u8]) -> Result<MapResponse, NatpmpError> {
    if buf.len() < 16 {
        return Err(NatpmpError::ShortResponse);
    }
    if buf[0] != 0 {
        return Err(NatpmpError::BadVersion(buf[0]));
    }
    if buf[1] < 128 {
        return Err(NatpmpError::NotAResponse(buf[1]));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    if result != 0 {
        return Err(NatpmpError::ResultCode(result));
    }
    Ok(MapResponse {
        result,
        internal_port: u16::from_be_bytes([buf[8], buf[9]]),
        external_port: u16::from_be_bytes([buf[10], buf[11]]),
        lifetime: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
    })
}

/// The "external address" request (2 bytes) and its response parser (12
/// bytes: version, op, result, epoch, 4-byte IPv4).
fn encode_extaddr_request() -> [u8; 2] {
    [0, 0]
}

fn parse_extaddr_response(buf: &[u8]) -> Result<Ipv4Addr, NatpmpError> {
    if buf.len() < 12 {
        return Err(NatpmpError::ShortResponse);
    }
    if buf[0] != 0 {
        return Err(NatpmpError::BadVersion(buf[0]));
    }
    if buf[1] < 128 {
        return Err(NatpmpError::NotAResponse(buf[1]));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    if result != 0 {
        return Err(NatpmpError::ResultCode(result));
    }
    Ok(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

/// The client's own LAN IPv4, discovered without sending a packet (a UDP
/// `connect` only fixes the route/source address).
fn local_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Likely gateway addresses for a LAN IP: `.1` and `.254` of its /24.
fn gateway_candidates(local: Ipv4Addr) -> Vec<Ipv4Addr> {
    let o = local.octets();
    let one = Ipv4Addr::new(o[0], o[1], o[2], 1);
    let high = Ipv4Addr::new(o[0], o[1], o[2], 254);
    if local == one {
        vec![high]
    } else {
        vec![one, high]
    }
}

/// Sends one NAT-PMP request to `gateway:5351` and returns the response,
/// ignoring datagrams from anywhere else.
fn natpmp_rpc(gateway: Ipv4Addr, req: &[u8], resp_len: usize) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(RPC_TIMEOUT)).ok()?;
    sock.send_to(req, (gateway, NATPMP_PORT)).ok()?;
    let mut buf = vec![0u8; resp_len];
    let (n, from) = sock.recv_from(&mut buf).ok()?;
    if from.ip() != IpAddr::V4(gateway) {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

struct Mapped {
    method: &'static str,
    gateway: Option<Ipv4Addr>, // Some for NAT-PMP (needed to refresh/teardown)
    external_ip: Option<IpAddr>,
    tcp_external: u16,
    udp_external: u16,
}

/// Attempts a NAT-PMP mapping of both ports against `gateway`. `lifetime
/// = 0` deletes the mapping (used at teardown).
fn try_natpmp(gateway: Ipv4Addr, tcp: u16, udp: u16, lifetime: u32) -> Option<Mapped> {
    let ext_ip = natpmp_rpc(gateway, &encode_extaddr_request(), 12).and_then(|r| parse_extaddr_response(&r).ok());

    let tcp_resp = natpmp_rpc(gateway, &encode_map_request(NATPMP_OP_TCP, tcp, tcp, lifetime), 16)?;
    let tcp_map = parse_map_response(&tcp_resp).ok()?;

    // UDP is best-effort on top of a successful TCP map.
    let udp_ext = natpmp_rpc(gateway, &encode_map_request(NATPMP_OP_UDP, udp, udp, lifetime), 16)
        .and_then(|r| parse_map_response(&r).ok())
        .map(|m| m.external_port)
        .unwrap_or(udp);

    Some(Mapped { method: "NAT-PMP", gateway: Some(gateway), external_ip: ext_ip.map(IpAddr::V4), tcp_external: tcp_map.external_port, udp_external: udp_ext })
}

fn upnp_search() -> Option<igd_next::Gateway> {
    // `SearchOptions::default()` (rather than a struct literal) avoids any
    // dependence on the crate's exact field set. The default SSDP timeout
    // only applies on this background thread, so it never stalls startup.
    igd_next::search_gateway(igd_next::SearchOptions::default()).ok()
}

/// Attempts a UPnP IGD mapping of both ports.
fn try_upnp(local: Ipv4Addr, tcp: u16, udp: u16, lifetime: u32) -> Option<Mapped> {
    let gw = upnp_search()?;
    let ext_ip = gw.get_external_ip().ok();
    let tcp_addr = SocketAddr::new(IpAddr::V4(local), tcp);
    let udp_addr = SocketAddr::new(IpAddr::V4(local), udp);
    gw.add_port(igd_next::PortMappingProtocol::TCP, tcp, tcp_addr, lifetime, DESC).ok()?;
    let _ = gw.add_port(igd_next::PortMappingProtocol::UDP, udp, udp_addr, lifetime, DESC);
    Some(Mapped { method: "UPnP", gateway: None, external_ip: ext_ip, tcp_external: tcp, udp_external: udp })
}

fn map_once(local: Ipv4Addr, tcp: u16, udp: u16, lifetime: u32) -> Option<Mapped> {
    gateway_candidates(local).into_iter().find_map(|gw| try_natpmp(gw, tcp, udp, lifetime)).or_else(|| try_upnp(local, tcp, udp, lifetime))
}

fn teardown(mapped: &Mapped, tcp: u16, udp: u16) {
    match mapped.gateway {
        Some(gw) => {
            let _ = try_natpmp(gw, tcp, udp, 0); // lifetime 0 = delete
        }
        None => {
            if let Some(gw) = upnp_search() {
                let _ = gw.remove_port(igd_next::PortMappingProtocol::TCP, mapped.tcp_external);
                let _ = gw.remove_port(igd_next::PortMappingProtocol::UDP, mapped.udp_external);
            }
        }
    }
}

/// Handle to the background mapping thread. `stop` (idempotent) renews
/// nothing further and removes the mapping.
pub struct PortMap {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl PortMap {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawns the mapping thread and returns immediately (discovery can take a
/// few seconds and must not stall startup). `log` receives human-readable
/// progress/results. Returns `None` only if there's no usable LAN IPv4 at
/// all; a router that simply doesn't support mapping still returns a
/// handle (the thread logs that it fell back to outbound-only).
pub fn map_ports<L>(tcp: u16, udp: u16, log: L) -> Option<PortMap>
where
    L: Fn(String) + Send + 'static,
{
    let local = local_ipv4()?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        let Some(mapped) = map_once(local, tcp, udp, LEASE_SECS) else {
            log("no UPnP/NAT-PMP gateway found; staying outbound-only (inbound peers may be limited)".to_string());
            return;
        };
        match mapped.external_ip {
            Some(ip) => log(format!("port mapping via {}: external {} tcp:{} udp:{}", mapped.method, ip, mapped.tcp_external, mapped.udp_external)),
            None => log(format!("port mapping via {}: tcp:{} udp:{} forwarded", mapped.method, mapped.tcp_external, mapped.udp_external)),
        }
        if mapped.tcp_external != tcp {
            log(format!("note: router assigned external TCP port {} (announcing {}); forward {} manually for best results", mapped.tcp_external, tcp, mapped.tcp_external));
        }

        // Refresh at half the lease, reacting to `stop` promptly.
        let refresh_every = Duration::from_secs((LEASE_SECS / 2) as u64);
        loop {
            let mut slept = Duration::ZERO;
            while slept < refresh_every && !stop_thread.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(250));
                slept += Duration::from_millis(250);
            }
            if stop_thread.load(Ordering::SeqCst) {
                break;
            }
            let _ = map_once(local, tcp, udp, LEASE_SECS);
        }

        teardown(&mapped, tcp, udp);
    });

    Some(PortMap { stop, handle: Some(handle) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_request_has_canonical_layout() {
        // TCP map: internal 6881, suggested 6881, lease 3600.
        let req = encode_map_request(NATPMP_OP_TCP, 6881, 6881, 3600);
        assert_eq!(req[0], 0); // version
        assert_eq!(req[1], 2); // TCP op
        assert_eq!(&req[2..4], &[0, 0]); // reserved
        assert_eq!(u16::from_be_bytes([req[4], req[5]]), 6881);
        assert_eq!(u16::from_be_bytes([req[6], req[7]]), 6881);
        assert_eq!(u32::from_be_bytes([req[8], req[9], req[10], req[11]]), 3600);
    }

    #[test]
    fn parses_successful_map_response() {
        let mut buf = [0u8; 16];
        buf[1] = 128 + 2; // TCP response
        buf[8..10].copy_from_slice(&6881u16.to_be_bytes()); // internal
        buf[10..12].copy_from_slice(&6881u16.to_be_bytes()); // external
        buf[12..16].copy_from_slice(&1800u32.to_be_bytes()); // granted lifetime
        let resp = parse_map_response(&buf).unwrap();
        assert_eq!(resp, MapResponse { result: 0, internal_port: 6881, external_port: 6881, lifetime: 1800 });
    }

    #[test]
    fn rejects_nonzero_result_code() {
        let mut buf = [0u8; 16];
        buf[1] = 128 + 2;
        buf[2..4].copy_from_slice(&3u16.to_be_bytes()); // e.g. "network failure"
        assert!(matches!(parse_map_response(&buf), Err(NatpmpError::ResultCode(3))));
    }

    #[test]
    fn rejects_short_and_malformed_responses() {
        assert!(matches!(parse_map_response(&[0u8; 8]), Err(NatpmpError::ShortResponse)));
        let mut bad_ver = [0u8; 16];
        bad_ver[0] = 9;
        bad_ver[1] = 130;
        assert!(matches!(parse_map_response(&bad_ver), Err(NatpmpError::BadVersion(9))));
        let mut not_resp = [0u8; 16];
        not_resp[1] = 2; // a request op, not a response
        assert!(matches!(parse_map_response(&not_resp), Err(NatpmpError::NotAResponse(2))));
    }

    #[test]
    fn parses_external_address_response() {
        let mut buf = [0u8; 12];
        buf[1] = 128; // external-address response op
        buf[8..12].copy_from_slice(&[203, 0, 113, 7]);
        assert_eq!(parse_extaddr_response(&buf).unwrap(), Ipv4Addr::new(203, 0, 113, 7));
    }

    #[test]
    fn extaddr_request_is_two_zero_bytes() {
        assert_eq!(encode_extaddr_request(), [0, 0]);
    }

    #[test]
    fn gateway_candidates_are_dot_one_and_dot_254() {
        assert_eq!(gateway_candidates(Ipv4Addr::new(192, 168, 7, 42)), vec![Ipv4Addr::new(192, 168, 7, 1), Ipv4Addr::new(192, 168, 7, 254)]);
        // If we *are* .1, don't list ourselves.
        assert_eq!(gateway_candidates(Ipv4Addr::new(10, 0, 0, 1)), vec![Ipv4Addr::new(10, 0, 0, 254)]);
    }
}
