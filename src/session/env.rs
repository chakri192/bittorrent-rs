//! What the environment says, where it is for the end-to-end tests to keep a client on loopback.

/// Where local service discovery listens and announces: BEP 14's multicast
/// group, unless both `BITTORRENT_RS_LSD_LISTEN` and `BITTORRENT_RS_LSD_SEND_TO`
/// name unicast addresses, which is how the end-to-end tests keep it on
/// loopback.
pub fn lsd_config() -> crate::lsd::LsdConfig {
    let address = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<std::net::SocketAddr>().ok());
    match (address("BITTORRENT_RS_LSD_LISTEN"), address("BITTORRENT_RS_LSD_SEND_TO")) {
        (Some(listen), Some(send_to)) => crate::lsd::LsdConfig { listen, send_to, join: None, share_port: false, ..crate::lsd::LsdConfig::multicast() },
        _ => crate::lsd::LsdConfig::multicast(),
    }
}

/// The DHT's routers to start from: the public ones, unless
/// `BITTORRENT_RS_DHT_BOOTSTRAP` lists others (`host:port`, separated by
/// commas), which is how the end-to-end tests keep it on loopback.
pub fn dht_bootstrap() -> Vec<String> {
    std::env::var("BITTORRENT_RS_DHT_BOOTSTRAP").map(|list| list.split(',').map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_discovery_uses_the_multicast_group_unless_the_test_hooks_name_both_addresses() {
        let group = crate::lsd::LsdConfig::multicast();
        std::env::remove_var("BITTORRENT_RS_LSD_LISTEN");
        std::env::remove_var("BITTORRENT_RS_LSD_SEND_TO");
        assert_eq!(lsd_config().send_to, group.send_to);
        std::env::set_var("BITTORRENT_RS_LSD_LISTEN", "127.0.0.1:4001");
        assert_eq!(lsd_config().send_to, group.send_to, "one of the two is not enough");
        std::env::set_var("BITTORRENT_RS_LSD_SEND_TO", "127.0.0.1:4002");
        let hooked = lsd_config();
        assert_eq!((hooked.listen.port(), hooked.send_to.port(), hooked.join, hooked.share_port), (4001, 4002, None, false));
        std::env::set_var("BITTORRENT_RS_LSD_SEND_TO", "not an address");
        assert_eq!(lsd_config().send_to, group.send_to, "an unusable one is ignored, not obeyed");
        std::env::remove_var("BITTORRENT_RS_LSD_LISTEN");
        std::env::remove_var("BITTORRENT_RS_LSD_SEND_TO");
    }

    #[test]
    fn the_dht_routers_are_the_public_ones_unless_the_test_hook_lists_others() {
        std::env::remove_var("BITTORRENT_RS_DHT_BOOTSTRAP");
        assert!(dht_bootstrap().is_empty(), "empty means the public ones");
        std::env::set_var("BITTORRENT_RS_DHT_BOOTSTRAP", " 127.0.0.1:4001 ,[::1]:4002,, ");
        assert_eq!(dht_bootstrap(), vec!["127.0.0.1:4001".to_string(), "[::1]:4002".to_string()]);
        std::env::remove_var("BITTORRENT_RS_DHT_BOOTSTRAP");
    }
}
