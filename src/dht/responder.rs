//! The server side of the DHT: answering the queries other nodes send us,
//! and remembering the peers they announce.

use super::krpc::{KrpcMessage, Query, Response};
use super::routing::K;
use super::store::PutError;
use super::{Dht, Transport, RECV_TICK};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The BEP 44 error code a rejected `put` is reported under.
fn put_error_code(e: PutError) -> (i64, &'static str) {
    match e {
        PutError::ValueTooLarge => (205, "message (v field) too big"),
        PutError::SaltTooLarge => (207, "salt (salt field) too big"),
        PutError::BadSignature => (206, "invalid signature"),
        PutError::CasMismatch => (301, "the CAS hash mismatched, re-read value and try again"),
        PutError::SequenceTooLow => (302, "sequence number less than current"),
        PutError::StoreFull => (201, "generic error: no room to store any more items"),
    }
}

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
                if self.read_only {
                    return None; // BEP 43: a read-only node answers no one
                }
                self.tokens.rotate_if_due(Instant::now());
                // A node that queries us is alive at that address --
                // exactly the freshness signal the routing table wants. Unless it
                // says (BEP 43) that it is not to be remembered: it cannot be reached.
                if !super::krpc::is_read_only(data) {
                    self.table.insert(*query.sender_id(), from);
                }
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
                    Query::Get { target, seq, .. } => {
                        let token = Some(self.tokens.issue(&from.ip()));
                        match self.item_store.get(target, Instant::now()) {
                            Some(item) => {
                                // BEP 44: if the requester already has this sequence number or
                                // newer, the value/key/signature are left out -- only worth
                                // sending when it would tell them something new.
                                let stale_to_them = matches!((item.mutable, seq), (Some((_, item_seq, _)), Some(their_seq)) if item_seq <= *their_seq);
                                if stale_to_them {
                                    Response { id: self.node_id, token, ..Default::default() }
                                } else {
                                    let (k, seq, sig) = match item.mutable {
                                        Some((k, seq, sig)) => (Some(k), Some(seq), Some(sig)),
                                        None => (None, None, None),
                                    };
                                    Response { id: self.node_id, token, v: Some(item.v), k, seq, sig, ..Default::default() }
                                }
                            }
                            None => Response { id: self.node_id, token, nodes: self.table.closest(target, K), ..Default::default() },
                        }
                    }
                    Query::Put { token, item, .. } => {
                        if !self.tokens.accepts(&from.ip(), token) {
                            let err = KrpcMessage::Error { t, code: 203, message: "bad token".to_string() };
                            let _ = self.transport.send_to(&err.encode(), from);
                            return None;
                        }
                        let now = Instant::now();
                        let stored = match &item.mutable {
                            None => self.item_store.put_immutable(item.v.clone(), now),
                            Some(m) => self.item_store.put_mutable(m.k, m.salt.clone(), m.seq, m.sig, item.v.clone(), m.cas, now),
                        };
                        match stored {
                            Ok(_) => Response { id: self.node_id, ..Default::default() },
                            Err(e) => {
                                let (code, message) = put_error_code(e);
                                let err = KrpcMessage::Error { t, code, message: message.to_string() };
                                let _ = self.transport.send_to(&err.encode(), from);
                                return None;
                            }
                        }
                    }
                };
                // The address the query came from, which is what BEP 42 has a node tell the one it answers.
                let reply = Response { ip: Some(from), ..reply };
                let _ = self.transport.send_to(&KrpcMessage::Response { t, response: reply }.encode(), from);
                None
            }
            KrpcMessage::Response { t, response } => {
                if let Some(reported) = response.ip {
                    self.note_reported_address(from.ip(), reported.ip());
                }
                Some((t, response, from))
            }
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

    // ---- BEP 42: ids that say where they are from, and the address others see us at ----

    fn ping() -> KrpcMessage {
        KrpcMessage::Query { t: b"xy".to_vec(), query: Query::Ping { id: [0x01; 20] } }
    }

    /// A response to something we asked, from `from`, saying it sees us at `seen`.
    fn told_we_are_at(dht: &mut Dht<&MockTransport>, from: &str, seen: &str) {
        let response = Response { id: [0x0F; 20], ip: Some(v4(&format!("{}:6881", seen))), ..Default::default() };
        let data = KrpcMessage::Response { t: b"zz".to_vec(), response }.encode();
        let _ = dht.handle_inbound(&data, v4(&format!("{}:6881", from)));
    }

    #[test]
    fn every_answer_says_the_address_the_query_came_from() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("203.0.113.9:6881");
        deliver(&mut dht, asker, ping().encode());
        assert_eq!(reply(&transport, asker).ip, Some(asker));
        let v6_transport = MockTransport::new_v6();
        let mut dht6 = Dht::new(&v6_transport);
        let asker6 = v6("[2001:db8::9]:6881");
        deliver(&mut dht6, asker6, ping().encode());
        assert_eq!(reply(&v6_transport, asker6).ip, Some(asker6));
    }

    #[test]
    fn a_query_that_says_it_is_read_only_is_answered_and_its_sender_left_out_of_the_table() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let (quiet, ordinary) = (v4("198.51.100.1:6881"), v4("198.51.100.2:6881"));
        deliver(&mut dht, quiet, ping().encode_with(true));
        assert_eq!(reply(&transport, quiet).id, *dht.node_id(), "it is answered like any other");
        assert_eq!(dht.table_len(), 0, "and not remembered");
        deliver(&mut dht, ordinary, ping().encode());
        assert_eq!(dht.table_len(), 1, "one that is not read-only is");
    }

    #[test]
    fn a_read_only_node_answers_no_query_and_marks_the_ones_it_sends() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        dht.set_read_only(true);
        let asker = v4("198.51.100.1:6881");
        deliver(&mut dht, asker, ping().encode());
        assert!(transport.sent_to(asker).is_empty(), "BEP 43: it does not answer");
        assert_eq!(dht.table_len(), 0);
        let peer = v4("198.51.100.3:6881");
        dht.send_query(Query::Ping { id: *dht.node_id() }, peer).unwrap();
        assert!(crate::dht::krpc::is_read_only(&transport.sent_to(peer)[0]), "what it asks says it is read-only");
        dht.set_read_only(false);
        let other = v4("198.51.100.4:6881");
        dht.send_query(Query::Ping { id: *dht.node_id() }, other).unwrap();
        assert!(!crate::dht::krpc::is_read_only(&transport.sent_to(other)[0]));
    }

    #[test]
    fn nodes_that_agree_where_this_one_is_give_it_an_id_made_from_that_address_and_it_keeps_its_table() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        for i in 0..6u8 {
            dht.seed_node([0x40 + i * 0x10; 20], v4(&format!("198.51.100.{}:1", 100 + i)));
        }
        let before = (*dht.node_id(), dht.table_len());
        let ours = "203.0.113.77";
        for reporter in 1..=4 {
            told_we_are_at(&mut dht, &format!("198.51.100.{}", reporter), ours);
        }
        assert_eq!((*dht.node_id(), dht.external_ip()), (before.0, None), "four nodes are not enough");
        told_we_are_at(&mut dht, "198.51.100.5", ours);
        let ip: std::net::IpAddr = ours.parse().unwrap();
        assert_eq!(dht.external_ip(), Some(ip), "the fifth agrees");
        assert_ne!(*dht.node_id(), before.0);
        assert!(crate::dht::secure_id::is_valid(dht.node_id(), ip), "and the id is now one that the address makes");
        assert_eq!(dht.table_len(), before.1, "the nodes it knew are still known");
        assert_eq!(dht.table.self_id(), dht.node_id(), "and the table is centred on the new id, not the old one");
    }

    #[test]
    fn the_same_node_saying_it_again_is_one_vote_and_a_scatter_of_answers_is_none() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let id = *dht.node_id();
        for _ in 0..20 {
            told_we_are_at(&mut dht, "198.51.100.1", "203.0.113.77");
        }
        assert_eq!(dht.external_ip(), None, "one node, twenty times");
        for i in 1..=40 {
            told_we_are_at(&mut dht, &format!("198.51.100.{}", i), &format!("203.0.113.{}", 100 + i));
        }
        assert_eq!((*dht.node_id(), dht.external_ip()), (id, None), "forty nodes and forty addresses: nothing agreed");
        assert!(dht.address_reports.len() <= super::super::MAX_ADDRESS_CANDIDATES, "and not every address kept");
    }

    #[test]
    fn an_answer_that_is_not_about_the_internet_or_this_family_is_not_counted() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        for reporter in 1..=10 {
            for seen in ["192.168.1.5", "10.0.0.7", "127.0.0.1"] {
                told_we_are_at(&mut dht, &format!("198.51.100.{}", reporter), seen);
            }
        }
        assert_eq!(dht.external_ip(), None, "a private address says nothing of where this node is on the internet");
        assert!(dht.address_reports.is_empty());
        for reporter in 1..=10u8 {
            dht.note_reported_address(format!("198.51.100.{}", reporter).parse().unwrap(), "2001:db8::1".parse().unwrap());
        }
        assert_eq!(dht.external_ip(), None, "an IPv6 address is of no use to an IPv4 node");
    }

    #[test]
    fn the_first_address_that_five_agree_on_is_believed_and_four_and_four_decide_nothing() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        for reporter in 1..=4 {
            told_we_are_at(&mut dht, &format!("198.51.100.{}", reporter), "203.0.113.50");
        }
        for reporter in 11..=14 {
            told_we_are_at(&mut dht, &format!("198.51.100.{}", reporter), "203.0.113.60");
        }
        assert_eq!(dht.external_ip(), None, "four and four");
        told_we_are_at(&mut dht, "198.51.100.15", "203.0.113.60");
        assert_eq!(dht.external_ip(), Some("203.0.113.60".parse().unwrap()), "five to four");
        // Once believed, further reports of the same address change nothing (the id is not made anew every time).
        let id = *dht.node_id();
        for reporter in 20..30 {
            told_we_are_at(&mut dht, &format!("198.51.100.{}", reporter), "203.0.113.60");
        }
        assert_eq!(*dht.node_id(), id);
    }

    // ---- BEP 44: get / put ----

    use super::super::krpc::{MutableFields, PutItem};
    use super::super::store::{immutable_target, mutable_target, sign_mutable};
    use crate::bencode::Bencode;
    use ed25519_dalek::SigningKey;

    /// Sends `get` for `target` from `asker` and returns the token in the reply.
    fn harvest_get_token(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddr, target: [u8; 20]) -> Vec<u8> {
        let stop = AtomicBool::new(false);
        let q = KrpcMessage::Query { t: b"g".to_vec(), query: Query::Get { id: [0x02; 20], target, seq: None } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Response { response, .. } => response.token.expect("get response must carry a token"),
            other => panic!("expected response, got {:?}", other),
        }
    }

    fn immutable_put(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddr, token: Vec<u8>, v: Bencode) -> Response {
        let stop = AtomicBool::new(false);
        let q = KrpcMessage::Query { t: b"p".to_vec(), query: Query::Put { id: [0x02; 20], token, item: PutItem { v, mutable: None } } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Response { response, .. } => response,
            other => panic!("expected response, got {:?}", other),
        }
    }

    fn get(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddr, target: [u8; 20], seq: Option<i64>) -> Response {
        let stop = AtomicBool::new(false);
        let q = KrpcMessage::Query { t: b"g2".to_vec(), query: Query::Get { id: [0x03; 20], target, seq } };
        transport.push_inbound(q.encode(), asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Response { response, .. } => response,
            other => panic!("expected response, got {:?}", other),
        }
    }

    fn error_code(dht: &mut Dht<&MockTransport>, transport: &MockTransport, asker: SocketAddr, msg: Vec<u8>) -> i64 {
        let stop = AtomicBool::new(false);
        transport.push_inbound(msg, asker);
        dht.serve_for(Duration::from_millis(1), &stop);
        match KrpcMessage::decode(transport.sent_to(asker).last().unwrap()).unwrap() {
            KrpcMessage::Error { code, .. } => code,
            other => panic!("expected an error, got {:?}", other),
        }
    }

    #[test]
    fn a_get_for_something_not_stored_gets_a_token_and_nodes_not_a_value() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("10.5.5.5:7000");
        let response = get(&mut dht, &transport, asker, [0x77; 20], None);
        assert!(response.token.is_some());
        assert!(response.v.is_none());
    }

    #[test]
    fn an_immutable_item_is_stored_by_put_and_returned_by_a_later_get() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let value = Bencode::Bytes(b"Hello World!".to_vec());
        let target = immutable_target(&crate::bencode::encode(&value));
        let asker = v4("10.5.5.5:7000");

        let token = harvest_get_token(&mut dht, &transport, asker, target);
        let put_response = immutable_put(&mut dht, &transport, asker, token, value.clone());
        assert_eq!(put_response.id, *dht.node_id());

        let other = v4("10.6.6.6:7001");
        let got = get(&mut dht, &transport, other, target, None);
        assert_eq!(got.v, Some(value));
    }

    #[test]
    fn a_put_with_a_bad_token_is_refused_with_error_203_and_nothing_is_stored() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("10.5.5.5:7000");
        let value = Bencode::Bytes(b"x".to_vec());
        let target = immutable_target(&crate::bencode::encode(&value));

        let q = KrpcMessage::Query { t: b"p".to_vec(), query: Query::Put { id: [0x02; 20], token: b"forged".to_vec(), item: PutItem { v: value, mutable: None } } }.encode();
        assert_eq!(error_code(&mut dht, &transport, asker, q), 203);
        assert!(get(&mut dht, &transport, asker, target, None).v.is_none());
    }

    #[test]
    fn a_put_larger_than_the_bep_allows_is_refused_with_error_205() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let asker = v4("10.5.5.5:7000");
        let value = Bencode::Bytes(vec![b'x'; super::super::store::MAX_VALUE_LEN + 1]);
        let target = immutable_target(&crate::bencode::encode(&value));
        let token = harvest_get_token(&mut dht, &transport, asker, target);

        let q = KrpcMessage::Query { t: b"p".to_vec(), query: Query::Put { id: [0x02; 20], token, item: PutItem { v: value, mutable: None } } }.encode();
        assert_eq!(error_code(&mut dht, &transport, asker, q), 205);
    }

    fn signed_mutable_put(id: [u8; 20], token: Vec<u8>, key: &SigningKey, salt: Option<Vec<u8>>, seq: i64, v: Bencode, cas: Option<i64>) -> KrpcMessage {
        let bencoded = crate::bencode::encode(&v);
        let sig = sign_mutable(key, salt.as_deref(), seq, &bencoded);
        KrpcMessage::Query { t: b"p".to_vec(), query: Query::Put { id, token, item: PutItem { v, mutable: Some(MutableFields { k: key.verifying_key().to_bytes(), salt, seq, sig, cas }) } } }
    }

    #[test]
    fn a_mutable_item_is_stored_and_a_later_get_returns_its_key_seq_and_signature() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let target = mutable_target(&key.verifying_key().to_bytes(), None);
        let asker = v4("10.5.5.5:7000");
        let value = Bencode::Bytes(b"v1".to_vec());

        let token = harvest_get_token(&mut dht, &transport, asker, target);
        let q = signed_mutable_put([0x02; 20], token, &key, None, 1, value.clone(), None).encode();
        transport.push_inbound(q, asker);
        dht.serve_for(Duration::from_millis(1), &AtomicBool::new(false));

        let got = get(&mut dht, &transport, v4("10.6.6.6:1"), target, None);
        assert_eq!(got.v, Some(value));
        assert_eq!(got.k, Some(key.verifying_key().to_bytes()));
        assert_eq!(got.seq, Some(1));
        assert!(got.sig.is_some());
    }

    #[test]
    fn a_mutable_put_with_a_bad_signature_is_refused_with_error_206() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let target = mutable_target(&key.verifying_key().to_bytes(), None);
        let asker = v4("10.5.5.5:7000");
        let token = harvest_get_token(&mut dht, &transport, asker, target);

        let mut msg = signed_mutable_put([0x02; 20], token, &key, None, 1, Bencode::Bytes(b"v1".to_vec()), None);
        if let KrpcMessage::Query { query: Query::Put { item: PutItem { mutable: Some(m), .. }, .. }, .. } = &mut msg {
            m.sig[0] ^= 0xff;
        }
        assert_eq!(error_code(&mut dht, &transport, asker, msg.encode()), 206);
    }

    #[test]
    fn a_mutable_put_with_a_lower_seq_than_stored_is_refused_with_error_302() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let target = mutable_target(&key.verifying_key().to_bytes(), None);
        let asker = v4("10.5.5.5:7000");

        let token = harvest_get_token(&mut dht, &transport, asker, target);
        let q1 = signed_mutable_put([0x02; 20], token.clone(), &key, None, 5, Bencode::Bytes(b"v5".to_vec()), None).encode();
        transport.push_inbound(q1, asker);
        dht.serve_for(Duration::from_millis(1), &AtomicBool::new(false));

        let q2 = signed_mutable_put([0x02; 20], token, &key, None, 4, Bencode::Bytes(b"v4".to_vec()), None).encode();
        assert_eq!(error_code(&mut dht, &transport, asker, q2), 302);
    }

    #[test]
    fn a_mutable_put_with_a_mismatched_cas_is_refused_with_error_301() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let target = mutable_target(&key.verifying_key().to_bytes(), None);
        let asker = v4("10.5.5.5:7000");

        let token = harvest_get_token(&mut dht, &transport, asker, target);
        let q1 = signed_mutable_put([0x02; 20], token.clone(), &key, None, 1, Bencode::Bytes(b"v1".to_vec()), None).encode();
        transport.push_inbound(q1, asker);
        dht.serve_for(Duration::from_millis(1), &AtomicBool::new(false));

        let q2 = signed_mutable_put([0x02; 20], token, &key, None, 2, Bencode::Bytes(b"v2".to_vec()), Some(99)).encode();
        assert_eq!(error_code(&mut dht, &transport, asker, q2), 301);
    }

    #[test]
    fn a_get_with_seq_omits_the_value_when_the_stored_seq_is_no_newer() {
        let transport = MockTransport::new();
        let mut dht = Dht::new(&transport);
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let target = mutable_target(&key.verifying_key().to_bytes(), None);
        let asker = v4("10.5.5.5:7000");

        let token = harvest_get_token(&mut dht, &transport, asker, target);
        let q = signed_mutable_put([0x02; 20], token, &key, None, 5, Bencode::Bytes(b"v5".to_vec()), None).encode();
        transport.push_inbound(q, asker);
        dht.serve_for(Duration::from_millis(1), &AtomicBool::new(false));

        let other = v4("10.6.6.6:1");
        let stale = get(&mut dht, &transport, other, target, Some(5));
        assert!(stale.v.is_none(), "the requester already has seq 5");
        let fresh = get(&mut dht, &transport, other, target, Some(4));
        assert!(fresh.v.is_some(), "seq 5 is newer than what the requester has");
    }
}
