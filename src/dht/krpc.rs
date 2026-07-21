//! KRPC: the bencoded-dict-over-UDP RPC format the mainline DHT speaks
//! (BEP 5). Three message kinds -- query, response, error -- correlated
//! by a transaction id (`t`) chosen by the querier and echoed back.
//!
//! IPv4 only: compact node info is the 26-byte `(20-byte id, 4-byte IP,
//! 2-byte port)` form and compact peer info the 6-byte form. BEP 32
//! (IPv6 DHT) is a separate, materially different encoding and is out of
//! scope, matching the UDP tracker's IPv4-only stance elsewhere in this
//! crate.

use crate::bencode::{self, Bencode};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};

pub type NodeId = [u8; 20];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactNode {
    pub id: NodeId,
    pub addr: SocketAddrV4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Ping { id: NodeId },
    FindNode { id: NodeId, target: NodeId },
    GetPeers { id: NodeId, info_hash: NodeId },
    AnnouncePeer { id: NodeId, info_hash: NodeId, port: u16, token: Vec<u8>, implied_port: bool },
}

impl Query {
    pub fn name(&self) -> &'static str {
        match self {
            Query::Ping { .. } => "ping",
            Query::FindNode { .. } => "find_node",
            Query::GetPeers { .. } => "get_peers",
            Query::AnnouncePeer { .. } => "announce_peer",
        }
    }

    /// The querying node's own id, present in every query's `a` dict.
    pub fn sender_id(&self) -> &NodeId {
        match self {
            Query::Ping { id } | Query::FindNode { id, .. } | Query::GetPeers { id, .. } | Query::AnnouncePeer { id, .. } => id,
        }
    }
}

/// A response's `r` dict, flattened: which fields are present depends on
/// the query it answers (ping -> just `id`; find_node -> `nodes`;
/// get_peers -> `token` + either `values` or `nodes`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub id: NodeId,
    pub nodes: Vec<CompactNode>,
    pub values: Vec<SocketAddrV4>,
    pub token: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KrpcMessage {
    Query { t: Vec<u8>, query: Query },
    Response { t: Vec<u8>, response: Response },
    Error { t: Vec<u8>, code: i64, message: String },
}

#[derive(Debug)]
pub enum KrpcError {
    Decode(bencode::DecodeError),
    NotADict,
    MissingField(&'static str),
    UnknownMessageType,
    UnknownQuery(String),
    MalformedCompact(&'static str),
}

impl std::fmt::Display for KrpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KrpcError::Decode(e) => write!(f, "bencode decode error: {}", e),
            KrpcError::NotADict => write!(f, "krpc message is not a dict"),
            KrpcError::MissingField(name) => write!(f, "krpc message missing field: {}", name),
            KrpcError::UnknownMessageType => write!(f, "krpc 'y' field is not one of q/r/e"),
            KrpcError::UnknownQuery(q) => write!(f, "unknown krpc query: {}", q),
            KrpcError::MalformedCompact(what) => write!(f, "malformed compact encoding: {}", what),
        }
    }
}

impl std::error::Error for KrpcError {}

fn bytes20(value: Option<&Bencode>, field: &'static str) -> Result<NodeId, KrpcError> {
    let b = value.and_then(Bencode::as_bytes).ok_or(KrpcError::MissingField(field))?;
    b.try_into().map_err(|_| KrpcError::MalformedCompact("id/hash not 20 bytes"))
}

/// 26 bytes per node: 20-byte id, 4-byte IPv4, 2-byte big-endian port.
// `is_multiple_of` needs a very recent stdlib; keep buildable on older
// toolchains (same stance as tracker::parse_compact_peers).
#[allow(clippy::manual_is_multiple_of)]
pub fn parse_compact_nodes(data: &[u8]) -> Result<Vec<CompactNode>, KrpcError> {
    if data.len() % 26 != 0 {
        return Err(KrpcError::MalformedCompact("nodes length not a multiple of 26"));
    }
    Ok(data
        .chunks_exact(26)
        .map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            let ip = Ipv4Addr::new(c[20], c[21], c[22], c[23]);
            let port = u16::from_be_bytes([c[24], c[25]]);
            CompactNode { id, addr: SocketAddrV4::new(ip, port) }
        })
        .collect())
}

pub fn encode_compact_nodes(nodes: &[CompactNode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 26);
    for n in nodes {
        out.extend_from_slice(&n.id);
        out.extend_from_slice(&n.addr.ip().octets());
        out.extend_from_slice(&n.addr.port().to_be_bytes());
    }
    out
}

fn parse_values(list: &[Bencode]) -> Vec<SocketAddrV4> {
    // Each value is a 6-byte compact peer; entries that aren't get
    // skipped rather than failing the whole response (lenient in what we
    // accept -- some nodes pad or mix garbage in).
    list.iter()
        .filter_map(|v| {
            let b = v.as_bytes()?;
            if b.len() != 6 {
                return None;
            }
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            if port == 0 {
                return None;
            }
            Some(SocketAddrV4::new(ip, port))
        })
        .collect()
}

impl KrpcMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut top: BTreeMap<Vec<u8>, Bencode> = BTreeMap::new();
        match self {
            KrpcMessage::Query { t, query } => {
                let mut a: BTreeMap<Vec<u8>, Bencode> = BTreeMap::new();
                a.insert(b"id".to_vec(), Bencode::Bytes(query.sender_id().to_vec()));
                match query {
                    Query::Ping { .. } => {}
                    Query::FindNode { target, .. } => {
                        a.insert(b"target".to_vec(), Bencode::Bytes(target.to_vec()));
                    }
                    Query::GetPeers { info_hash, .. } => {
                        a.insert(b"info_hash".to_vec(), Bencode::Bytes(info_hash.to_vec()));
                    }
                    Query::AnnouncePeer { info_hash, port, token, implied_port, .. } => {
                        a.insert(b"implied_port".to_vec(), Bencode::Int(if *implied_port { 1 } else { 0 }));
                        a.insert(b"info_hash".to_vec(), Bencode::Bytes(info_hash.to_vec()));
                        a.insert(b"port".to_vec(), Bencode::Int(*port as i64));
                        a.insert(b"token".to_vec(), Bencode::Bytes(token.clone()));
                    }
                }
                top.insert(b"a".to_vec(), Bencode::Dict(a));
                top.insert(b"q".to_vec(), Bencode::Bytes(query.name().as_bytes().to_vec()));
                top.insert(b"t".to_vec(), Bencode::Bytes(t.clone()));
                top.insert(b"y".to_vec(), Bencode::Bytes(b"q".to_vec()));
            }
            KrpcMessage::Response { t, response } => {
                let mut r: BTreeMap<Vec<u8>, Bencode> = BTreeMap::new();
                r.insert(b"id".to_vec(), Bencode::Bytes(response.id.to_vec()));
                if !response.nodes.is_empty() {
                    r.insert(b"nodes".to_vec(), Bencode::Bytes(encode_compact_nodes(&response.nodes)));
                }
                if let Some(token) = &response.token {
                    r.insert(b"token".to_vec(), Bencode::Bytes(token.clone()));
                }
                if !response.values.is_empty() {
                    let vals = response
                        .values
                        .iter()
                        .map(|p| {
                            let mut b = Vec::with_capacity(6);
                            b.extend_from_slice(&p.ip().octets());
                            b.extend_from_slice(&p.port().to_be_bytes());
                            Bencode::Bytes(b)
                        })
                        .collect();
                    r.insert(b"values".to_vec(), Bencode::List(vals));
                }
                top.insert(b"r".to_vec(), Bencode::Dict(r));
                top.insert(b"t".to_vec(), Bencode::Bytes(t.clone()));
                top.insert(b"y".to_vec(), Bencode::Bytes(b"r".to_vec()));
            }
            KrpcMessage::Error { t, code, message } => {
                top.insert(b"e".to_vec(), Bencode::List(vec![Bencode::Int(*code), Bencode::Bytes(message.as_bytes().to_vec())]));
                top.insert(b"t".to_vec(), Bencode::Bytes(t.clone()));
                top.insert(b"y".to_vec(), Bencode::Bytes(b"e".to_vec()));
            }
        }
        bencode::encode(&Bencode::Dict(top))
    }

    /// Lenient decode -- DHT nodes in the wild are the least canonical
    /// bencode producers there are.
    pub fn decode(data: &[u8]) -> Result<Self, KrpcError> {
        let value = bencode::decode_lenient(data).map_err(KrpcError::Decode)?;
        let dict = value.as_dict().ok_or(KrpcError::NotADict)?;
        let t = dict.get(b"t".as_slice()).and_then(Bencode::as_bytes).ok_or(KrpcError::MissingField("t"))?.to_vec();
        let y = dict.get(b"y".as_slice()).and_then(Bencode::as_bytes).ok_or(KrpcError::MissingField("y"))?;

        match y {
            b"q" => {
                let q_name = dict.get(b"q".as_slice()).and_then(Bencode::as_str).ok_or(KrpcError::MissingField("q"))?;
                let a = dict.get(b"a".as_slice()).and_then(Bencode::as_dict).ok_or(KrpcError::MissingField("a"))?;
                let id = bytes20(a.get(b"id".as_slice()), "a.id")?;
                let query = match q_name {
                    "ping" => Query::Ping { id },
                    "find_node" => Query::FindNode { id, target: bytes20(a.get(b"target".as_slice()), "a.target")? },
                    "get_peers" => Query::GetPeers { id, info_hash: bytes20(a.get(b"info_hash".as_slice()), "a.info_hash")? },
                    "announce_peer" => Query::AnnouncePeer {
                        id,
                        info_hash: bytes20(a.get(b"info_hash".as_slice()), "a.info_hash")?,
                        port: a.get(b"port".as_slice()).and_then(Bencode::as_int).unwrap_or(0) as u16,
                        token: a.get(b"token".as_slice()).and_then(Bencode::as_bytes).unwrap_or_default().to_vec(),
                        implied_port: a.get(b"implied_port".as_slice()).and_then(Bencode::as_int).unwrap_or(0) == 1,
                    },
                    other => return Err(KrpcError::UnknownQuery(other.to_string())),
                };
                Ok(KrpcMessage::Query { t, query })
            }
            b"r" => {
                let r = dict.get(b"r".as_slice()).and_then(Bencode::as_dict).ok_or(KrpcError::MissingField("r"))?;
                let id = bytes20(r.get(b"id".as_slice()), "r.id")?;
                let nodes = match r.get(b"nodes".as_slice()).and_then(Bencode::as_bytes) {
                    Some(raw) => parse_compact_nodes(raw)?,
                    None => Vec::new(),
                };
                let values = r.get(b"values".as_slice()).and_then(Bencode::as_list).map(parse_values).unwrap_or_default();
                let token = r.get(b"token".as_slice()).and_then(Bencode::as_bytes).map(<[u8]>::to_vec);
                Ok(KrpcMessage::Response { t, response: Response { id, nodes, values, token } })
            }
            b"e" => {
                let e = dict.get(b"e".as_slice()).and_then(Bencode::as_list).ok_or(KrpcError::MissingField("e"))?;
                let code = e.first().and_then(Bencode::as_int).unwrap_or(0);
                let message = e.get(1).and_then(Bencode::as_str).unwrap_or("").to_string();
                Ok(KrpcMessage::Error { t, code, message })
            }
            _ => Err(KrpcError::UnknownMessageType),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Round-trip tests pinned against the *exact example byte strings in
    //! BEP 5* -- if our encoder emits what the spec prints and our
    //! decoder reads the spec's strings back into the same struct, we
    //! interoperate with anything that follows the spec.
    use super::*;

    fn id(s: &[u8; 20]) -> NodeId {
        *s
    }

    #[test]
    fn ping_query_matches_bep5_example() {
        let msg = KrpcMessage::Query { t: b"aa".to_vec(), query: Query::Ping { id: id(b"abcdefghij0123456789") } };
        let encoded = msg.encode();
        assert_eq!(encoded, b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe".to_vec());
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn ping_response_matches_bep5_example() {
        let msg = KrpcMessage::Response {
            t: b"aa".to_vec(),
            response: Response { id: id(b"mnopqrstuvwxyz123456"), ..Default::default() },
        };
        let encoded = msg.encode();
        assert_eq!(encoded, b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re".to_vec());
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn find_node_query_matches_bep5_example() {
        let msg = KrpcMessage::Query {
            t: b"aa".to_vec(),
            query: Query::FindNode { id: id(b"abcdefghij0123456789"), target: id(b"mnopqrstuvwxyz123456") },
        };
        let encoded = msg.encode();
        assert_eq!(encoded, b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe".to_vec());
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn get_peers_query_matches_bep5_example() {
        let msg = KrpcMessage::Query {
            t: b"aa".to_vec(),
            query: Query::GetPeers { id: id(b"abcdefghij0123456789"), info_hash: id(b"mnopqrstuvwxyz123456") },
        };
        let encoded = msg.encode();
        assert_eq!(encoded, b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe".to_vec());
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn get_peers_response_with_values_decodes_bep5_example() {
        let raw = b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re";
        let msg = KrpcMessage::decode(raw).unwrap();
        match msg {
            KrpcMessage::Response { t, response } => {
                assert_eq!(t, b"aa".to_vec());
                assert_eq!(response.token.as_deref(), Some(b"aoeusnth".as_slice()));
                // "axje.u" = 97,120,106,101,46,117 -> 97.120.106.101:11893
                assert_eq!(response.values.len(), 2);
                assert_eq!(response.values[0], "97.120.106.101:11893".parse().unwrap());
            }
            other => panic!("expected response, got {:?}", other),
        }
    }

    #[test]
    fn announce_peer_query_matches_bep5_example() {
        let msg = KrpcMessage::Query {
            t: b"aa".to_vec(),
            query: Query::AnnouncePeer {
                id: id(b"abcdefghij0123456789"),
                info_hash: id(b"mnopqrstuvwxyz123456"),
                port: 6881,
                token: b"aoeusnth".to_vec(),
                implied_port: true,
            },
        };
        let encoded = msg.encode();
        assert_eq!(
            encoded,
            b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe".to_vec()
        );
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn error_message_decodes_bep5_example() {
        let raw = b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee";
        match KrpcMessage::decode(raw).unwrap() {
            KrpcMessage::Error { t, code, message } => {
                assert_eq!(t, b"aa".to_vec());
                assert_eq!(code, 201);
                assert_eq!(message, "A Generic Error Ocurred");
            }
            other => panic!("expected error, got {:?}", other),
        }
    }

    #[test]
    fn compact_nodes_round_trip() {
        let nodes = vec![
            CompactNode { id: [1; 20], addr: "10.0.0.1:6881".parse().unwrap() },
            CompactNode { id: [2; 20], addr: "192.168.7.9:51413".parse().unwrap() },
        ];
        let raw = encode_compact_nodes(&nodes);
        assert_eq!(raw.len(), 52);
        assert_eq!(parse_compact_nodes(&raw).unwrap(), nodes);
    }

    #[test]
    fn rejects_bad_compact_nodes_length() {
        assert!(matches!(parse_compact_nodes(&[0u8; 27]), Err(KrpcError::MalformedCompact(_))));
    }

    #[test]
    fn rejects_garbage_and_non_krpc_dicts() {
        assert!(KrpcMessage::decode(b"not bencode at all").is_err());
        assert!(KrpcMessage::decode(b"le").is_err());
        assert!(KrpcMessage::decode(b"d1:t2:aa1:y1:xe").is_err()); // unknown y
        assert!(KrpcMessage::decode(b"d1:y1:qe").is_err()); // missing t
    }

    #[test]
    fn decodes_query_with_unsorted_keys_from_sloppy_node() {
        // y before t before q before a -- thoroughly unsorted, still valid
        // to a lenient decoder.
        let raw = b"d1:y1:q1:t2:zz1:q4:ping1:ad2:id20:abcdefghij0123456789ee";
        match KrpcMessage::decode(raw).unwrap() {
            KrpcMessage::Query { t, query: Query::Ping { id } } => {
                assert_eq!(t, b"zz".to_vec());
                assert_eq!(&id, b"abcdefghij0123456789");
            }
            other => panic!("expected ping, got {:?}", other),
        }
    }
}
