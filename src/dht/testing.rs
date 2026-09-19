//! A scripted in-memory transport shared by the DHT's tests.

use super::krpc::{CompactNode, KrpcMessage, NodeId, Query, Response};
use super::Transport;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

/// Scripted in-memory transport: `send_to` records every outgoing
/// datagram and, if the destination is scripted, synthesizes that
/// node's reply into the inbox (echoing the transaction id, as a
/// real node would).
pub(super) struct MockTransport {
    inbox: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    script: Mutex<HashMap<SocketAddr, ScriptedNode>>,
    ipv6: bool,
}

#[derive(Clone)]
pub(super) struct ScriptedNode {
    pub(super) id: NodeId,
    pub(super) nodes: Vec<CompactNode>,
    pub(super) values: Vec<SocketAddr>,
    pub(super) token: Option<Vec<u8>>,
}

impl MockTransport {
    pub(super) fn new() -> Self {
        MockTransport { inbox: Mutex::new(VecDeque::new()), sent: Mutex::new(Vec::new()), script: Mutex::new(HashMap::new()), ipv6: false }
    }

    /// A transport that says it is an IPv6 socket.
    pub(super) fn new_v6() -> Self {
        MockTransport { ipv6: true, ..MockTransport::new() }
    }

    pub(super) fn script_node(&self, addr: SocketAddr, node: ScriptedNode) {
        self.script.lock().unwrap().insert(addr, node);
    }

    pub(super) fn push_inbound(&self, data: Vec<u8>, from: SocketAddr) {
        self.inbox.lock().unwrap().push_back((data, from));
    }

    pub(super) fn sent_to(&self, addr: SocketAddr) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().iter().filter(|(_, a)| *a == addr).map(|(d, _)| d.clone()).collect()
    }
}

impl Transport for &MockTransport {
    fn ipv6(&self) -> bool {
        self.ipv6
    }

    fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.sent.lock().unwrap().push((data.to_vec(), addr));
        if let Some(node) = self.script.lock().unwrap().get(&addr).cloned() {
            if let Ok(KrpcMessage::Query { t, query }) = KrpcMessage::decode(data) {
                let response = match query {
                    Query::GetPeers { .. } => Response { id: node.id, nodes: node.nodes.clone(), values: node.values.clone(), token: node.token.clone() },
                    Query::FindNode { .. } => Response { id: node.id, nodes: node.nodes.clone(), ..Default::default() },
                    _ => Response { id: node.id, ..Default::default() },
                };
                let reply = KrpcMessage::Response { t, response };
                self.inbox.lock().unwrap().push_back((reply.encode(), addr));
            }
        }
        Ok(())
    }

    fn recv(&self, _timeout: Duration) -> io::Result<Option<(Vec<u8>, SocketAddr)>> {
        Ok(self.inbox.lock().unwrap().pop_front())
    }
}

pub(super) fn v4(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
