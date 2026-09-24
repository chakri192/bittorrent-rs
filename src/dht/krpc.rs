//! KRPC: the bencoded-dict-over-UDP RPC format the mainline DHT speaks
//! (BEP 5). Three message kinds -- query, response, error -- correlated
//! by a transaction id (`t`) chosen by the querier and echoed back.
//!
//! Both address families (BEP 32). IPv4 compact node info is the 26-byte
//! `(20-byte id, 4-byte IP, 2-byte port)` form, sent under `nodes`; IPv6 is
//! the 38-byte form (a 16-byte IP), under `nodes6`. Compact peer info in
//! `values` is 6 bytes for IPv4 and 18 for IPv6, and a list may hold both.
//! A response can carry `nodes` and `nodes6` together, and they are read
//! into one list, told apart by their addresses.
//!
//! BEP 32's `want` parameter (which families a querier would like nodes of)
//! is not read: a node answers with nodes of the family the query came in on,
//! which is what the BEP says to do without it.

use crate::bencode::{self, Bencode};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub type NodeId = [u8; 20];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactNode {
    pub id: NodeId,
    pub addr: SocketAddr,
}

/// One `put` request's payload: the `v` value, and, for a mutable item, the public key,
/// optional salt, sequence number, signature and optional CAS precondition (BEP 44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutItem {
    pub v: Bencode,
    pub mutable: Option<MutableFields>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutableFields {
    pub k: [u8; 32],
    pub salt: Option<Vec<u8>>,
    pub seq: i64,
    pub sig: [u8; 64],
    /// `cas`: only performed if the value currently stored has this sequence number.
    pub cas: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    Ping { id: NodeId },
    FindNode { id: NodeId, target: NodeId },
    GetPeers { id: NodeId, info_hash: NodeId },
    AnnouncePeer { id: NodeId, info_hash: NodeId, port: u16, token: Vec<u8>, implied_port: bool },
    /// BEP 44: `target` is the SHA-1 hash of an immutable item's value, or of a mutable item's
    /// public key (and salt, if any). `seq`, if given, asks that `k`/`v`/`sig` be left out of
    /// the response unless the stored item's own sequence number is greater.
    Get { id: NodeId, target: NodeId, seq: Option<i64> },
    /// BEP 44: stores `item` under the write-token `token` (issued by a prior `get` from the
    /// same node), immutable or mutable depending on `item.mutable`.
    Put { id: NodeId, token: Vec<u8>, item: PutItem },
}

impl Query {
    pub fn name(&self) -> &'static str {
        match self {
            Query::Ping { .. } => "ping",
            Query::FindNode { .. } => "find_node",
            Query::GetPeers { .. } => "get_peers",
            Query::AnnouncePeer { .. } => "announce_peer",
            Query::Get { .. } => "get",
            Query::Put { .. } => "put",
        }
    }

    /// The querying node's own id, present in every query's `a` dict.
    pub fn sender_id(&self) -> &NodeId {
        match self {
            Query::Ping { id } | Query::FindNode { id, .. } | Query::GetPeers { id, .. } | Query::AnnouncePeer { id, .. } | Query::Get { id, .. } | Query::Put { id, .. } => id,
        }
    }
}

/// A response's `r` dict, flattened: which fields are present depends on
/// the query it answers (ping -> just `id`; find_node -> `nodes`;
/// get_peers -> `token` + either `values` or `nodes`; BEP 44 `get` ->
/// `token` + `v` (and, for a mutable item, `k`/`seq`/`sig`)).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub id: NodeId,
    pub nodes: Vec<CompactNode>,
    pub values: Vec<SocketAddr>,
    pub token: Option<Vec<u8>>,
    /// BEP 42: the address the answer's recipient was seen at, which is how a node behind a NAT learns its external one. It is
    /// a key of the message, not of its `r` dict, in the same compact form as a peer.
    pub ip: Option<SocketAddr>,
    /// BEP 44 `get`: the stored value, whatever bencoded type it is.
    pub v: Option<Bencode>,
    /// BEP 44 `get` on a mutable item: its public key, sequence number and signature.
    pub k: Option<[u8; 32]>,
    pub seq: Option<i64>,
    pub sig: Option<[u8; 64]>,
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

fn bytes32(value: Option<&Bencode>, field: &'static str) -> Result<[u8; 32], KrpcError> {
    let b = value.and_then(Bencode::as_bytes).ok_or(KrpcError::MissingField(field))?;
    b.try_into().map_err(|_| KrpcError::MalformedCompact("public key not 32 bytes"))
}

fn bytes64(value: Option<&Bencode>, field: &'static str) -> Result<[u8; 64], KrpcError> {
    let b = value.and_then(Bencode::as_bytes).ok_or(KrpcError::MissingField(field))?;
    b.try_into().map_err(|_| KrpcError::MalformedCompact("signature not 64 bytes"))
}

/// Bytes in one compact IPv4 node (`nodes`) and one compact IPv6 node (`nodes6`).
pub const NODE4_LEN: usize = 26;
pub const NODE6_LEN: usize = 38;

/// 26 bytes per node: 20-byte id, 4-byte IPv4, 2-byte big-endian port.
// `is_multiple_of` needs a very recent stdlib; keep buildable on older
// toolchains (same stance as tracker::parse_compact_peers).
#[allow(clippy::manual_is_multiple_of)]
pub fn parse_compact_nodes(data: &[u8]) -> Result<Vec<CompactNode>, KrpcError> {
    if data.len() % NODE4_LEN != 0 {
        return Err(KrpcError::MalformedCompact("nodes length not a multiple of 26"));
    }
    Ok(data
        .as_chunks::<NODE4_LEN>()
        .0
        .iter()
        .map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            let ip = Ipv4Addr::new(c[20], c[21], c[22], c[23]);
            let port = u16::from_be_bytes([c[24], c[25]]);
            CompactNode { id, addr: SocketAddr::V4(SocketAddrV4::new(ip, port)) }
        })
        .collect())
}

/// 38 bytes per node: 20-byte id, 16-byte IPv6, 2-byte big-endian port (BEP 32).
#[allow(clippy::manual_is_multiple_of)]
pub fn parse_compact_nodes6(data: &[u8]) -> Result<Vec<CompactNode>, KrpcError> {
    if data.len() % NODE6_LEN != 0 {
        return Err(KrpcError::MalformedCompact("nodes6 length not a multiple of 38"));
    }
    Ok(data
        .as_chunks::<NODE6_LEN>()
        .0
        .iter()
        .map(|c| {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&c[20..36]);
            let port = u16::from_be_bytes([c[36], c[37]]);
            CompactNode { id, addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0)) }
        })
        .collect())
}

/// The IPv4 nodes among `nodes`, in the 26-byte form. IPv6 ones have their
/// own encoding and are left out.
pub fn encode_compact_nodes(nodes: &[CompactNode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * NODE4_LEN);
    for n in nodes {
        if let SocketAddr::V4(addr) = n.addr {
            out.extend_from_slice(&n.id);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    out
}

/// The IPv6 nodes among `nodes`, in the 38-byte form.
pub fn encode_compact_nodes6(nodes: &[CompactNode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * NODE6_LEN);
    for n in nodes {
        if let SocketAddr::V6(addr) = n.addr {
            out.extend_from_slice(&n.id);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    out
}

/// One compact peer: 6 bytes for IPv4, 18 for IPv6.
fn encode_peer(peer: &SocketAddr) -> Vec<u8> {
    let mut out = match peer {
        SocketAddr::V4(p) => p.ip().octets().to_vec(),
        SocketAddr::V6(p) => p.ip().octets().to_vec(),
    };
    out.extend_from_slice(&peer.port().to_be_bytes());
    out
}

/// A compact peer or `ip`: 6 bytes for IPv4, 18 for IPv6.
fn parse_compact_addr(b: &[u8]) -> Option<SocketAddr> {
    match b.len() {
        6 => Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(b[0], b[1], b[2], b[3]), u16::from_be_bytes([b[4], b[5]])))),
        18 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), u16::from_be_bytes([b[16], b[17]]), 0, 0)))
        }
        _ => None,
    }
}

/// Whether a query says (BEP 43) that its sender is read-only: a node that cannot be reached, or does not answer, and so is not to
/// be put in anyone's routing table. Any datagram that is not such a query is not.
pub fn is_read_only(data: &[u8]) -> bool {
    bencode::decode_lenient(data).ok().and_then(|value| value.get("ro").and_then(Bencode::as_int)) == Some(1)
}

fn parse_values(list: &[Bencode]) -> Vec<SocketAddr> {
    // Each value is a compact peer, 6 bytes (IPv4) or 18 (IPv6); entries that
    // are neither get skipped rather than failing the whole response (lenient
    // in what we accept -- some nodes pad or mix garbage in).
    list.iter().filter_map(|v| parse_compact_addr(v.as_bytes()?)).filter(|peer| peer.port() != 0).collect()
}

impl KrpcMessage {
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with(false)
    }

    /// [`encode`](Self::encode), with a query marked read-only (BEP 43) if `read_only` says so: the top-level key `ro` is 1.
    pub fn encode_with(&self, read_only: bool) -> Vec<u8> {
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
                    Query::Get { target, seq, .. } => {
                        a.insert(b"target".to_vec(), Bencode::Bytes(target.to_vec()));
                        if let Some(seq) = seq {
                            a.insert(b"seq".to_vec(), Bencode::Int(*seq));
                        }
                    }
                    Query::Put { token, item, .. } => {
                        a.insert(b"token".to_vec(), Bencode::Bytes(token.clone()));
                        a.insert(b"v".to_vec(), item.v.clone());
                        if let Some(m) = &item.mutable {
                            a.insert(b"k".to_vec(), Bencode::Bytes(m.k.to_vec()));
                            if let Some(salt) = &m.salt {
                                a.insert(b"salt".to_vec(), Bencode::Bytes(salt.clone()));
                            }
                            a.insert(b"seq".to_vec(), Bencode::Int(m.seq));
                            a.insert(b"sig".to_vec(), Bencode::Bytes(m.sig.to_vec()));
                            if let Some(cas) = m.cas {
                                a.insert(b"cas".to_vec(), Bencode::Int(cas));
                            }
                        }
                    }
                }
                top.insert(b"a".to_vec(), Bencode::Dict(a));
                if read_only {
                    top.insert(b"ro".to_vec(), Bencode::Int(1));
                }
                top.insert(b"q".to_vec(), Bencode::Bytes(query.name().as_bytes().to_vec()));
                top.insert(b"t".to_vec(), Bencode::Bytes(t.clone()));
                top.insert(b"y".to_vec(), Bencode::Bytes(b"q".to_vec()));
            }
            KrpcMessage::Response { t, response } => {
                let mut r: BTreeMap<Vec<u8>, Bencode> = BTreeMap::new();
                r.insert(b"id".to_vec(), Bencode::Bytes(response.id.to_vec()));
                let (nodes, nodes6) = (encode_compact_nodes(&response.nodes), encode_compact_nodes6(&response.nodes));
                if !nodes.is_empty() {
                    r.insert(b"nodes".to_vec(), Bencode::Bytes(nodes));
                }
                if !nodes6.is_empty() {
                    r.insert(b"nodes6".to_vec(), Bencode::Bytes(nodes6));
                }
                if let Some(token) = &response.token {
                    r.insert(b"token".to_vec(), Bencode::Bytes(token.clone()));
                }
                if !response.values.is_empty() {
                    let vals = response.values.iter().map(|p| Bencode::Bytes(encode_peer(p))).collect();
                    r.insert(b"values".to_vec(), Bencode::List(vals));
                }
                if let Some(v) = &response.v {
                    r.insert(b"v".to_vec(), v.clone());
                }
                if let Some(k) = &response.k {
                    r.insert(b"k".to_vec(), Bencode::Bytes(k.to_vec()));
                }
                if let Some(seq) = response.seq {
                    r.insert(b"seq".to_vec(), Bencode::Int(seq));
                }
                if let Some(sig) = &response.sig {
                    r.insert(b"sig".to_vec(), Bencode::Bytes(sig.to_vec()));
                }
                top.insert(b"r".to_vec(), Bencode::Dict(r));
                if let Some(ip) = &response.ip {
                    top.insert(b"ip".to_vec(), Bencode::Bytes(encode_peer(ip)));
                }
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
                    "get" => Query::Get { id, target: bytes20(a.get(b"target".as_slice()), "a.target")?, seq: a.get(b"seq".as_slice()).and_then(Bencode::as_int) },
                    "put" => {
                        let v = a.get(b"v".as_slice()).cloned().ok_or(KrpcError::MissingField("a.v"))?;
                        let token = a.get(b"token".as_slice()).and_then(Bencode::as_bytes).unwrap_or_default().to_vec();
                        // Mutable iff a `k` (public key) is present -- BEP 44's own way of telling the two apart.
                        let mutable = match a.get(b"k".as_slice()) {
                            Some(_) => Some(MutableFields {
                                k: bytes32(a.get(b"k".as_slice()), "a.k")?,
                                salt: a.get(b"salt".as_slice()).and_then(Bencode::as_bytes).map(<[u8]>::to_vec),
                                seq: a.get(b"seq".as_slice()).and_then(Bencode::as_int).ok_or(KrpcError::MissingField("a.seq"))?,
                                sig: bytes64(a.get(b"sig".as_slice()), "a.sig")?,
                                cas: a.get(b"cas".as_slice()).and_then(Bencode::as_int),
                            }),
                            None => None,
                        };
                        Query::Put { id, token, item: PutItem { v, mutable } }
                    }
                    other => return Err(KrpcError::UnknownQuery(other.to_string())),
                };
                Ok(KrpcMessage::Query { t, query })
            }
            b"r" => {
                let r = dict.get(b"r".as_slice()).and_then(Bencode::as_dict).ok_or(KrpcError::MissingField("r"))?;
                let id = bytes20(r.get(b"id".as_slice()), "r.id")?;
                let mut nodes = match r.get(b"nodes".as_slice()).and_then(Bencode::as_bytes) {
                    Some(raw) => parse_compact_nodes(raw)?,
                    None => Vec::new(),
                };
                if let Some(raw) = r.get(b"nodes6".as_slice()).and_then(Bencode::as_bytes) {
                    nodes.extend(parse_compact_nodes6(raw)?);
                }
                let values = r.get(b"values".as_slice()).and_then(Bencode::as_list).map(parse_values).unwrap_or_default();
                let token = r.get(b"token".as_slice()).and_then(Bencode::as_bytes).map(<[u8]>::to_vec);
                let ip = dict.get(b"ip".as_slice()).and_then(Bencode::as_bytes).and_then(parse_compact_addr);
                let v = r.get(b"v".as_slice()).cloned();
                let k = r.get(b"k".as_slice()).and_then(Bencode::as_bytes).and_then(|b| b.try_into().ok());
                let seq = r.get(b"seq".as_slice()).and_then(Bencode::as_int);
                let sig = r.get(b"sig".as_slice()).and_then(Bencode::as_bytes).and_then(|b| b.try_into().ok());
                Ok(KrpcMessage::Response { t, response: Response { id, nodes, values, token, ip, v, k, seq, sig } })
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

    // ---- BEP 32: IPv6 ----

    fn node6(byte: u8, ip: &str, port: u16) -> CompactNode {
        CompactNode { id: [byte; 20], addr: SocketAddr::new(ip.parse().unwrap(), port) }
    }

    #[test]
    fn a_compact_ipv6_node_is_38_bytes_id_then_sixteen_bytes_of_address_then_the_port() {
        let node = node6(0x11, "2001:db8::1", 6881);
        let raw = encode_compact_nodes6(std::slice::from_ref(&node));
        let mut expected = vec![0x11u8; 20];
        expected.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        expected.extend_from_slice(&[0x1a, 0xe1]);
        assert_eq!(raw, expected);
        assert_eq!(raw.len(), NODE6_LEN);
        assert_eq!(parse_compact_nodes6(&raw).unwrap(), vec![node]);
    }

    #[test]
    fn each_family_is_encoded_in_its_own_form_and_the_other_left_out_of_it() {
        let both = [node6(1, "10.0.0.1", 1), node6(2, "2001:db8::2", 2), node6(3, "10.0.0.3", 3)];
        assert_eq!(encode_compact_nodes(&both).len(), 2 * NODE4_LEN);
        assert_eq!(encode_compact_nodes6(&both).len(), NODE6_LEN);
        assert_eq!(parse_compact_nodes(&encode_compact_nodes(&both)).unwrap(), vec![both[0].clone(), both[2].clone()]);
    }

    #[test]
    fn a_response_with_nodes_of_both_families_carries_nodes_and_nodes6_and_reads_back_as_one_list() {
        let nodes = vec![node6(1, "10.0.0.1", 6881), node6(2, "2001:db8::2", 6882)];
        let msg = KrpcMessage::Response { t: b"aa".to_vec(), response: Response { id: [9; 20], nodes: nodes.clone(), ..Default::default() } };
        let encoded = msg.encode();
        let text = String::from_utf8_lossy(&encoded);
        assert!(text.contains("5:nodes26:") && text.contains("6:nodes638:"), "{}", text);
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg, "the two lists come back as the one, IPv4 first");
    }

    #[test]
    fn a_response_from_another_client_with_only_nodes6_is_read() {
        let mut raw = b"d1:rd2:id20:abcdefghij01234567896:nodes638:".to_vec();
        raw.extend_from_slice(&[0x22; 20]);
        raw.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x50]);
        raw.extend_from_slice(b"e1:t2:aa1:y1:re");
        match KrpcMessage::decode(&raw).unwrap() {
            KrpcMessage::Response { response, .. } => assert_eq!(response.nodes, vec![node6(0x22, "fe80::1", 80)]),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn peers_in_values_are_six_bytes_for_ipv4_or_eighteen_for_ipv6_and_may_be_mixed() {
        let peers: Vec<SocketAddr> = vec!["1.2.3.4:5678".parse().unwrap(), "[2001:db8::5]:6881".parse().unwrap()];
        let msg = KrpcMessage::Response { t: b"aa".to_vec(), response: Response { id: [9; 20], values: peers.clone(), token: Some(b"tk".to_vec()), ..Default::default() } };
        let encoded = msg.encode();
        assert!(encoded.windows(5).any(|w| w == b"6:\x01\x02\x03"), "the IPv4 one is 6 bytes");
        assert!(String::from_utf8_lossy(&encoded).contains("18:"), "and the IPv6 one is 18");
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn values_of_any_other_size_or_with_port_zero_are_skipped_not_fatal() {
        let mut raw = b"d1:rd2:id20:abcdefghij01234567895:token2:tk6:valuesl6:".to_vec();
        raw.extend_from_slice(&[1, 2, 3, 4, 0, 0]); // port 0
        raw.extend_from_slice(b"5:abcde"); // neither size
        raw.extend_from_slice(b"18:");
        raw.extend_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0x1a, 0xe1]);
        raw.extend_from_slice(b"ee1:t2:aa1:y1:re");
        match KrpcMessage::decode(&raw).unwrap() {
            KrpcMessage::Response { response, .. } => assert_eq!(response.values, vec!["[2001:db8::7]:6881".parse::<SocketAddr>().unwrap()]),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn a_nodes6_field_that_is_not_a_whole_number_of_nodes_is_refused() {
        assert!(matches!(parse_compact_nodes6(&[0u8; 39]), Err(KrpcError::MalformedCompact(_))));
        let raw = b"d1:rd2:id20:abcdefghij01234567896:nodes65:xxxxxe1:t2:aa1:y1:re";
        assert!(KrpcMessage::decode(raw).is_err());
    }

    #[test]
    fn a_query_with_a_want_list_is_still_a_query() {
        // BEP 32's `want` says which families a querier wants nodes of; it is read past, not refused.
        let raw = b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:wantl2:n42:n6ee1:q9:get_peers1:t2:aa1:y1:qe";
        match KrpcMessage::decode(raw).unwrap() {
            KrpcMessage::Query { query: Query::GetPeers { info_hash, .. }, .. } => assert_eq!(&info_hash, b"mnopqrstuvwxyz123456"),
            other => panic!("{:?}", other),
        }
    }

    // ---- BEP 42 and BEP 43 ----

    #[test]
    fn a_response_carries_the_address_it_saw_you_at_at_the_top_level_and_reads_it_back_for_both_families() {
        for ip in ["203.0.113.9:6881", "[2001:db8::7]:6882"] {
            let seen: SocketAddr = ip.parse().unwrap();
            let msg = KrpcMessage::Response { t: b"aa".to_vec(), response: Response { id: [7; 20], ip: Some(seen), ..Default::default() } };
            let encoded = msg.encode();
            let dict = bencode::decode_lenient(&encoded).unwrap();
            let top = dict.as_dict().unwrap();
            assert!(top.contains_key(b"ip".as_slice()), "`ip` is a key of the message, beside `r`, not in it");
            assert!(!dict.get("r").unwrap().as_dict().unwrap().contains_key(b"ip".as_slice()));
            assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
        }
        let plain = KrpcMessage::Response { t: b"aa".to_vec(), response: Response { id: [7; 20], ..Default::default() } };
        assert!(!String::from_utf8_lossy(&plain.encode()).contains("2:ip"), "no address seen, none said");
    }

    #[test]
    fn a_response_ip_of_the_wrong_length_is_ignored_and_costs_nothing() {
        let mut top: BTreeMap<Vec<u8>, Bencode> = BTreeMap::new();
        let mut r: BTreeMap<Vec<u8>, Bencode> = BTreeMap::new();
        r.insert(b"id".to_vec(), Bencode::Bytes(vec![1; 20]));
        top.insert(b"r".to_vec(), Bencode::Dict(r));
        top.insert(b"ip".to_vec(), Bencode::Bytes(vec![1, 2, 3]));
        top.insert(b"t".to_vec(), Bencode::Bytes(b"aa".to_vec()));
        top.insert(b"y".to_vec(), Bencode::Bytes(b"r".to_vec()));
        let KrpcMessage::Response { response, .. } = KrpcMessage::decode(&bencode::encode(&Bencode::Dict(top))).unwrap() else { panic!("a response") };
        assert_eq!(response.ip, None);
    }

    #[test]
    fn a_query_says_it_is_read_only_at_the_top_level_and_only_when_it_is() {
        let query = KrpcMessage::Query { t: b"aa".to_vec(), query: Query::Ping { id: [3; 20] } };
        assert!(!is_read_only(&query.encode()));
        assert!(!is_read_only(&query.encode_with(false)));
        let marked = query.encode_with(true);
        assert!(is_read_only(&marked), "{:?}", String::from_utf8_lossy(&marked));
        assert_eq!(KrpcMessage::decode(&marked).unwrap(), query, "and it is the same query otherwise");
        assert!(String::from_utf8_lossy(&marked).contains("2:roi1e"));
        // Anything that is not a well-formed dict with `ro` 1 is not read-only.
        assert!(!is_read_only(b"not bencode"));
        assert!(!is_read_only(b"d2:roi0ee") && !is_read_only(b"d2:roi2ee") && !is_read_only(b"d2:ro1:1e"));
    }

    // ---- BEP 44: get / put ----

    #[test]
    fn get_query_without_seq_encodes_and_decodes_exactly() {
        let msg = KrpcMessage::Query { t: b"aa".to_vec(), query: Query::Get { id: id(b"abcdefghij0123456789"), target: id(b"mnopqrstuvwxyz123456"), seq: None } };
        let encoded = msg.encode();
        assert_eq!(encoded, b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q3:get1:t2:aa1:y1:qe".to_vec());
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn get_query_with_seq_encodes_and_decodes_exactly() {
        let msg = KrpcMessage::Query { t: b"aa".to_vec(), query: Query::Get { id: id(b"abcdefghij0123456789"), target: id(b"mnopqrstuvwxyz123456"), seq: Some(3) } };
        let encoded = msg.encode();
        assert_eq!(encoded, b"d1:ad2:id20:abcdefghij01234567893:seqi3e6:target20:mnopqrstuvwxyz123456e1:q3:get1:t2:aa1:y1:qe".to_vec());
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn get_response_for_an_immutable_item_round_trips() {
        let msg = KrpcMessage::Response { t: b"aa".to_vec(), response: Response { id: id(b"mnopqrstuvwxyz123456"), token: Some(b"tok".to_vec()), v: Some(Bencode::Bytes(b"Hello World!".to_vec())), ..Default::default() } };
        let encoded = msg.encode();
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
        assert!(String::from_utf8_lossy(&encoded).contains("1:v12:Hello World!"));
    }

    #[test]
    fn get_response_for_a_mutable_item_round_trips_with_k_seq_and_sig() {
        let msg = KrpcMessage::Response {
            t: b"aa".to_vec(),
            response: Response { id: id(b"mnopqrstuvwxyz123456"), token: Some(b"tok".to_vec()), v: Some(Bencode::Bytes(b"Hello World!".to_vec())), k: Some([0x11; 32]), seq: Some(4), sig: Some([0x22; 64]), ..Default::default() },
        };
        let encoded = msg.encode();
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
    }

    #[test]
    fn put_query_for_an_immutable_item_round_trips() {
        let msg = KrpcMessage::Query { t: b"aa".to_vec(), query: Query::Put { id: id(b"abcdefghij0123456789"), token: b"tok".to_vec(), item: PutItem { v: Bencode::Bytes(b"Hello World!".to_vec()), mutable: None } } };
        let encoded = msg.encode();
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
        assert!(!String::from_utf8_lossy(&encoded).contains("1:k32:"), "no k field for an immutable put");
    }

    #[test]
    fn put_query_for_a_mutable_item_round_trips_with_every_field() {
        let msg = KrpcMessage::Query {
            t: b"aa".to_vec(),
            query: Query::Put {
                id: id(b"abcdefghij0123456789"),
                token: b"tok".to_vec(),
                item: PutItem { v: Bencode::Bytes(b"Hello World!".to_vec()), mutable: Some(MutableFields { k: [0x11; 32], salt: Some(b"foobar".to_vec()), seq: 4, sig: [0x22; 64], cas: Some(3) }) },
            },
        };
        let encoded = msg.encode();
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
        let text = String::from_utf8_lossy(&encoded);
        assert!(text.contains("3:cas") && text.contains("4:salt6:foobar") && text.contains("3:seqi4e"));
    }

    #[test]
    fn put_query_for_a_mutable_item_without_salt_or_cas_omits_them() {
        let msg = KrpcMessage::Query {
            t: b"aa".to_vec(),
            query: Query::Put { id: id(b"abcdefghij0123456789"), token: b"tok".to_vec(), item: PutItem { v: Bencode::Bytes(b"x".to_vec()), mutable: Some(MutableFields { k: [0x11; 32], salt: None, seq: 1, sig: [0x22; 64], cas: None }) } },
        };
        let encoded = msg.encode();
        assert_eq!(KrpcMessage::decode(&encoded).unwrap(), msg);
        let text = String::from_utf8_lossy(&encoded);
        assert!(!text.contains("salt") && !text.contains("cas"));
    }

    #[test]
    fn a_put_query_is_told_apart_from_an_immutable_one_by_the_presence_of_k() {
        // BEP 44's own way of telling the two kinds apart on decode: no other field does it.
        let raw = b"d1:ad2:id20:abcdefghij01234567895:token3:tok1:v1:xe1:q3:put1:t2:aa1:y1:qe";
        match KrpcMessage::decode(raw).unwrap() {
            KrpcMessage::Query { query: Query::Put { item, .. }, .. } => assert!(item.mutable.is_none()),
            other => panic!("{:?}", other),
        }
    }
}
