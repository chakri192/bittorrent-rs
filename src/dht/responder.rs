//! The server side of the DHT: answering the queries other nodes send us,
//! and remembering the peers they announce.

use super::krpc::{KrpcMessage, Query, Response};
use super::routing::K;
use super::{Dht, Transport, RECV_TICK};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Peers remembered per info-hash. This client is a downloader first, a
/// storage node second.
const MAX_STORED_PEERS_PER_HASH: usize = 100;

/// Info-hashes remembered in total. A token is bound only to the sender's
/// address, so without a limit here one `get_peers` buys the right to make
/// this node remember an unbounded number of info-hashes.
const MAX_STORED_INFOHASHES: usize = 1000;

impl<T: Transport> Dht<T> {
    /// Handles one inbound datagram. Queries get answered on the spot;
    /// responses are returned to the caller for transaction correlation.
    pub(super) fn handle_inbound(&mut self, data: &[u8], from: SocketAddr) -> Option<(Vec<u8>, Response, SocketAddr)> {
        if !self.is_our_family(&from) {
            return None; // not something this socket can have received; ignore it
        }
        let msg = KrpcMessage::decode(data).ok()?; // garbage from strangers: drop silently

        match msg {
            KrpcMessage::Query { t, query } => {
                self.tokens.rotate_if_due(Instant::now());
                // A node that queries us is alive at that address --
                // exactly the freshness signal the routing table wants.
                self.table.insert(*query.sender_id(), from);
                let reply = match &query {
                    Query::Ping { .. } => Response { id: self.node_id, ..Default::default() },
                    Query::FindNode { target, .. } => Response { id: self.node_id, nodes: self.table.closest(target, K), ..Default::default() },
                    Query::GetPeers { info_hash, .. } => {
                        let token = Some(self.tokens.issue(&from.ip()));
                        match self.peer_store.get(info_hash) {
                            Some(peers) if !peers.is_empty() => Response { id: self.node_id, values: peers.clone(), token, ..Default::default() },
                            _ => Response { id: self.node_id, nodes: self.table.closest(info_hash, K), token, ..Default::default() },
                        }
                    }
                    Query::AnnouncePeer { info_hash, port, token, implied_port, .. } => {
                        if !self.tokens.accepts(&from.ip(), token) {
                            let err = KrpcMessage::Error { t, code: 203, message: "bad token".to_string() };
                            let _ = self.transport.send_to(&err.encode(), from);
                            return None;
                        }
                        let peer_port = if *implied_port { from.port() } else { *port };
                        // At capacity we still answer "ok" but only add peers to
                        // info-hashes we already hold.
                        if self.peer_store.contains_key(info_hash) || self.peer_store.len() < MAX_STORED_INFOHASHES {
                            let peers = self.peer_store.entry(*info_hash).or_default();
                            let peer = SocketAddr::new(from.ip(), peer_port);
                            if !peers.contains(&peer) && peers.len() < MAX_STORED_PEERS_PER_HASH {
                                peers.push(peer);
                            }
                        }
                        Response { id: self.node_id, ..Default::default() }
                    }
                };
                let _ = self.transport.send_to(&KrpcMessage::Response { t, response: reply }.encode(), from);
                None
            }
            KrpcMessage::Response { t, response } => Some((t, response, from)),
            KrpcMessage::Error { .. } => None, // errors just mean that txid never resolves
        }
    }

    /// Serves inbound queries for up to `duration` (idle keep-warm
    /// between lookups). Responses arriving here (stragglers from past
    /// lookups) still refresh the routing table.
    pub fn serve_for(&mut self, duration: Duration, stop: &AtomicBool) {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
            match self.transport.recv(RECV_TICK) {
                Ok(Some((data, from))) => {
                    if let Some((_t, response, from)) = self.handle_inbound(&data, from) {
                        self.table.insert(response.id, from);
                    }
                }
                Ok(None) => {}
                Err(_) => return, // socket died; service loop will notice
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dht::testing::{v4, MockTransport};

    #[test]
    fn responds_to_inbound_ping_with_our_id_and_same_txid() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let our_id = *dht.node_id();

        let asker = v4("10.9.9.9:1234");
        let ping = KrpcMessage::Query { t: b"xy".to_vec(), query: Query::Ping { id: [0x01; 20] } };
        transport.push_inbound(ping.encode(), asker);

        let stop = AtomicBool::new(false);
        dht.serve_for(Duration::from_millis(1), &stop);

        let replies = transport.sent_to(asker);
        assert_eq!(replies.len(), 1);
        match KrpcMessage::decode(&replies[0]).unwrap() {
            KrpcMessage::Response { t, response } => {
                assert_eq!(t, b"xy".to_vec());
                assert_eq!(response.id, our_id);
            }
            other => panic!("expected response, got {:?}", other),
        }
        // The asker is now in our routing table.
        assert_eq!(dht.table_len(), 1);
    }

    #[test]
    fn get_peers_token_round_trips_through_announce_peer_and_is_stored() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let stop = AtomicBool::new(false);
        let info_hash = [0x77; 20];
        let asker = v4("10.5.5.5:7000");

        // 1) get_peers -> harvest the token we hand out.
        let q = KrpcMessage::Query { t: b"t1".to_vec(), query: Query::GetPeers { id: [0x02; 20], info_hash } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        let token = match KrpcMessage::decode(&transport.sent_to(asker)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => response.token.expect("get_peers response must carry a token"),
            other => panic!("expected response, got {:?}", other),
        };

        // 2) announce_peer with that token -> accepted + stored.
        let q = KrpcMessage::Query { t: b"t2".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 9999, token, implied_port: false } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);

        // 3) a *different* node's get_peers now receives that peer as a value.
        let other = v4("10.6.6.6:7001");
        let q = KrpcMessage::Query { t: b"t3".to_vec(), query: Query::GetPeers { id: [0x03; 20], info_hash } };
        transport.push_inbound(q.encode(), other);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(&transport.sent_to(other)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => {
                assert_eq!(response.values, vec![v4("10.5.5.5:9999")]);
            }
            other => panic!("expected response, got {:?}", other),
        }
    }

    #[test]
    fn announce_peer_with_bad_token_gets_error_203_and_is_not_stored() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let stop = AtomicBool::new(false);
        let info_hash = [0x77; 20];
        let asker = v4("10.5.5.5:7000");

        let q = KrpcMessage::Query { t: b"t9".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 9999, token: b"forged".to_vec(), implied_port: false } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);

        match KrpcMessage::decode(&transport.sent_to(asker)[0]).unwrap() {
            KrpcMessage::Error { code, .. } => assert_eq!(code, 203),
            other => panic!("expected error 203, got {:?}", other),
        }

        // And a get_peers for that hash returns no values.
        let other = v4("10.6.6.6:7001");
        let q = KrpcMessage::Query { t: b"ta".to_vec(), query: Query::GetPeers { id: [0x03; 20], info_hash } };
        transport.push_inbound(q.encode(), other);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(&transport.sent_to(other)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => assert!(response.values.is_empty()),
            other => panic!("expected response, got {:?}", other),
        }
    }

    #[test]
    fn implied_port_uses_the_udp_source_port() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let stop = AtomicBool::new(false);
        let info_hash = [0x70; 20];
        let asker = v4("10.5.5.5:7070");

        // Harvest a token first.
        let q = KrpcMessage::Query { t: b"t1".to_vec(), query: Query::GetPeers { id: [0x02; 20], info_hash } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        let token = match KrpcMessage::decode(&transport.sent_to(asker)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => response.token.unwrap(),
            _ => unreachable!(),
        };

        let q = KrpcMessage::Query { t: b"t2".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 1, token, implied_port: true } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);

        let other = v4("10.6.6.6:7001");
        let q = KrpcMessage::Query { t: b"t3".to_vec(), query: Query::GetPeers { id: [0x03; 20], info_hash } };
        transport.push_inbound(q.encode(), other);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(&transport.sent_to(other)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => assert_eq!(response.values, vec![v4("10.5.5.5:7070")], "implied_port=1 must use the UDP source port, not the port field"),
            _ => unreachable!(),
        }
    }

    /// Sends `get_peers` from `asker` and returns the token in the reply.
    fn harvest_token(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddr, info_hash: [u8; 20]) -> Vec<u8> {
        let stop = AtomicBool::new(false);
        let q = KrpcMessage::Query { t: b"g".to_vec(), query: Query::GetPeers { id: [0x02; 20], info_hash } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Response { response, .. } => response.token.expect("get_peers response must carry a token"),
            other => panic!("expected response, got {:?}", other),
        }
    }

    /// Sends `announce_peer` with `token` and reports whether it was
    /// accepted (a plain response) or refused (error 203).
    fn announce_accepted(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddr, info_hash: [u8; 20], token: Vec<u8>) -> bool {
        let stop = AtomicBool::new(false);
        let q = KrpcMessage::Query { t: b"a".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 9999, token, implied_port: false } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Response { .. } => true,
            KrpcMessage::Error { code: 203, .. } => false,
            other => panic!("unexpected reply {:?}", other),
        }
    }

    #[test]
    fn token_issued_before_one_rotation_is_still_accepted() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("10.5.5.5:7000");
        let token = harvest_token(&mut dht, &transport, asker, [0x77; 20]);

        dht.tokens.rotate(Instant::now());

        assert!(announce_accepted(&mut dht, &transport, asker, [0x77; 20], token), "one generation back must still verify");
    }

    #[test]
    fn token_issued_before_two_rotations_is_rejected() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("10.5.5.5:7000");
        let token = harvest_token(&mut dht, &transport, asker, [0x77; 20]);

        dht.tokens.rotate(Instant::now());
        dht.tokens.rotate(Instant::now());

        assert!(!announce_accepted(&mut dht, &transport, asker, [0x77; 20], token), "a stale token must not be replayable");
    }

    #[test]
    fn tokens_are_bound_to_the_requesters_ip() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let token = harvest_token(&mut dht, &transport, v4("10.5.5.5:7000"), [0x77; 20]);

        assert!(!announce_accepted(&mut dht, &transport, v4("10.6.6.6:7000"), [0x77; 20], token), "a token must not work from a different address");
    }

    /// Sends `bytes` to the node as if from `from`, and lets it answer.
    fn deliver(dht: &mut Dht<&MockTransport>, from: SocketAddr, bytes: Vec<u8>) {
        let _ = dht.handle_inbound(&bytes, from);
    }

    #[test]
    fn hostile_datagrams_never_panic_the_node_or_grow_its_store_past_its_limits() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let from = v4("10.9.9.9:6881");
        let id = [0x02; 20];
        let ih = [0x77; 20];
        let token = harvest_token(&mut dht, &transport, from, ih);
        let seeds = vec![
            KrpcMessage::Query { t: b"p".to_vec(), query: Query::Ping { id } }.encode(),
            KrpcMessage::Query { t: b"f".to_vec(), query: Query::FindNode { id, target: ih } }.encode(),
            KrpcMessage::Query { t: b"g".to_vec(), query: Query::GetPeers { id, info_hash: ih } }.encode(),
            KrpcMessage::Query { t: b"a".to_vec(), query: Query::AnnouncePeer { id, info_hash: ih, port: 6881, token, implied_port: false } }.encode(),
            KrpcMessage::Response { t: b"r".to_vec(), response: Response { id, ..Default::default() } }.encode(),
        ];
        crate::fuzz::hammer(&seeds, 2000, |input| {
            deliver(&mut dht, from, input.to_vec());
            assert!(dht.peer_store.values().all(|peers| peers.len() <= MAX_STORED_PEERS_PER_HASH));
            assert!(dht.peer_store.len() <= MAX_STORED_INFOHASHES, "store holds {} info-hashes", dht.peer_store.len());
        });
    }

    #[test]
    fn announcing_endless_distinct_info_hashes_cannot_grow_the_store_without_limit() {
        // A token is bound only to the sender's address, so one get_peers
        // buys the right to announce any info-hash at all.
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let from = v4("10.9.9.9:6881");
        let token = harvest_token(&mut dht, &transport, from, [0x77; 20]);

        for n in 0..(MAX_STORED_INFOHASHES as u32 * 3) {
            let mut info_hash = [0u8; 20];
            info_hash[..4].copy_from_slice(&n.to_be_bytes());
            let q = KrpcMessage::Query { t: b"a".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port: 6881, token: token.clone(), implied_port: false } };
            deliver(&mut dht, from, q.encode());
        }

        assert_eq!(dht.peer_store.len(), MAX_STORED_INFOHASHES, "full, and no fuller");
    }

    #[test]
    fn an_info_hash_already_stored_can_still_gain_peers_when_the_store_is_full() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let token_holder = v4("10.9.9.9:6881");
        let token = harvest_token(&mut dht, &transport, token_holder, [0; 20]);
        let announce = |dht: &mut Dht<&MockTransport>, n: u32, port: u16| {
            let mut info_hash = [0u8; 20];
            info_hash[..4].copy_from_slice(&n.to_be_bytes());
            let q = KrpcMessage::Query { t: b"a".to_vec(), query: Query::AnnouncePeer { id: [0x02; 20], info_hash, port, token: token.clone(), implied_port: false } };
            deliver(dht, token_holder, q.encode());
        };
        for n in 0..MAX_STORED_INFOHASHES as u32 {
            announce(&mut dht, n, 1000);
        }
        announce(&mut dht, 0, 2000); // an existing hash, a second port

        let mut first = [0u8; 20];
        first[..4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(dht.peer_store[&first].len(), 2, "an entry we already hold keeps accepting peers");
    }

    // ---- BEP 32: a node on IPv6 ----

    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn reply(transport: &MockTransport, to: SocketAddr) -> Response {
        match KrpcMessage::decode(&transport.sent_to(to)[0]).unwrap() {
            KrpcMessage::Response { response, .. } => response,
            other => panic!("expected a response, got {:?}", other),
        }
    }

    #[test]
    fn an_ipv6_node_answers_a_ping_from_an_ipv6_address_and_remembers_it() {
        let transport = MockTransport::new_v6();
        let mut dht = Dht::new(&transport);
        let asker = v6("[2001:db8::9]:6881");
        deliver(&mut dht, asker, KrpcMessage::Query { t: b"xy".to_vec(), query: Query::Ping { id: [0x01; 20] } }.encode());

        assert_eq!(reply(&transport, asker).id, *dht.node_id());
        assert_eq!(dht.table_len(), 1);
    }

    #[test]
    fn a_node_ignores_datagrams_from_the_other_family() {
        for (transport, from) in [(MockTransport::new_v6(), v4("10.1.1.1:6881")), (MockTransport::new(), v6("[2001:db8::9]:6881"))] {
            let mut dht = Dht::new(&transport);
            deliver(&mut dht, from, KrpcMessage::Query { t: b"xy".to_vec(), query: Query::Ping { id: [0x01; 20] } }.encode());
            assert!(transport.sent_to(from).is_empty(), "no answer");
            assert_eq!(dht.table_len(), 0, "and nothing remembered");
        }
    }

    #[test]
    fn ipv6_announces_are_stored_with_the_senders_v6_address_and_served_as_18_byte_values() {
        let transport = MockTransport::new_v6();
        let mut dht = Dht::new(&transport);
        let info_hash = [0x77; 20];
        let asker = v6("[2001:db8::5]:7000");
        let token = harvest_token(&mut dht, &transport, asker, info_hash);
        assert!(announce_accepted(&mut dht, &transport, asker, info_hash, token));

        let other = v6("[2001:db8::6]:7001");
        deliver(&mut dht, other, KrpcMessage::Query { t: b"t3".to_vec(), query: Query::GetPeers { id: [0x03; 20], info_hash } }.encode());
        assert_eq!(reply(&transport, other).values, vec![v6("[2001:db8::5]:9999")]);
        // On the wire, that value is eighteen bytes.
        let raw = transport.sent_to(other)[0].clone();
        assert!(raw.windows(3).any(|w| w == b"18:"), "{:?}", String::from_utf8_lossy(&raw));
    }

    #[test]
    fn ipv6_answers_to_find_node_are_in_nodes6_and_only_ipv6_nodes_are_in_them() {
        let transport = MockTransport::new_v6();
        let mut dht = Dht::new(&transport);
        for (i, ip) in ["[2001:db8::a]:1", "[2001:db8::b]:2", "[2001:db8::c]:3"].iter().enumerate() {
            dht.seed_node([0x10 + i as u8; 20], v6(ip));
        }
        dht.seed_node([0x20; 20], v4("10.0.0.9:9")); // of the other family, and so not kept
        assert_eq!(dht.table_len(), 3);
        let asker = v6("[2001:db8::99]:6881");
        deliver(&mut dht, asker, KrpcMessage::Query { t: b"f".to_vec(), query: Query::FindNode { id: [0x05; 20], target: [0x10; 20] } }.encode());
        let raw = transport.sent_to(asker)[0].clone();
        assert!(String::from_utf8_lossy(&raw).contains("6:nodes6"), "{:?}", String::from_utf8_lossy(&raw));
        let nodes = reply(&transport, asker).nodes;
        assert_eq!(nodes.len(), 4, "the three seeded, and the asker, which the query itself taught it");
        assert!(nodes.iter().all(|n| n.addr.is_ipv6()));
    }

    #[test]
    fn a_token_from_one_family_is_no_good_from_another_address_of_the_other() {
        let transport = MockTransport::new_v6();
        let mut dht = Dht::new(&transport);
        let token = harvest_token(&mut dht, &transport, v6("[2001:db8::5]:7000"), [0x77; 20]);
        assert!(!announce_accepted(&mut dht, &transport, v6("[2001:db8::6]:7000"), [0x77; 20], token), "bound to the requester's IPv6 address");
    }
}
