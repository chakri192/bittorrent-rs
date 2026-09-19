//! A scripted in-memory transport shared by the DHT's tests.

use super::krpc::{CompactNode, KrpcMessage, NodeId, Query, Response};
use super::Transport;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
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
}

#[derive(Clone)]
pub(super) struct ScriptedNode {
    pub(super) id: NodeId,
    pub(super) nodes: Vec<CompactNode>,
    pub(super) values: Vec<SocketAddrV4>,
    pub(super) token: Option<Vec<u8>>,
}

impl MockTransport {
    pub(super) fn new() -> Self {
        MockTransport { inbox: Mutex::new(VecDeque::new()), sent: Mutex::new(Vec::new()), script: Mutex::new(HashMap::new()) }
    }

    pub(super) fn script_node(&self, addr: SocketAddrV4, node: ScriptedNode) {
        self.script.lock().unwrap().insert(SocketAddr::V4(addr), node);
    }

    pub(super) fn push_inbound(&self, data: Vec<u8>, from: SocketAddrV4) {
        self.inbox.lock().unwrap().push_back((data, SocketAddr::V4(from)));
    }

    pub(super) fn sent_to(&self, addr: SocketAddrV4) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().iter().filter(|(_, a)| *a == SocketAddr::V4(addr)).map(|(d, _)| d.clone()).collect()
    }
}

impl Transport for &MockTransport {
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

pub(super) fn v4(s: &str) -> SocketAddrV4 {
    s.parse().unwrap()
}
