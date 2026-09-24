//! What lets one peer's connection (BEP 55's relay, "R") act on the other side of a message
//! that arrived on a *different* connection: forwarding a `connect` to the target peer it names,
//! or, for the initiating side, asking some other live connection to send a `rendezvous` on this
//! client's behalf. Every worker connection owns its own stream and reads it on its own thread
//! (see `mod.rs`'s module doc), so reaching another connection's peer means handing the message
//! to *that* connection's own thread rather than writing to its socket directly -- structurally
//! parallel to [`super::PeerRegistry`] (same per-torrent, address-keyed, enter-and-drop-removes
//! shape), just carrying an outbound channel instead of dashboard numbers.

use crate::peer::HolepunchMessage;
use crate::sync::lock;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

/// Whether a registered connection's peer supports the extension, and where to send it a message.
type Relay = (Arc<AtomicBool>, Sender<HolepunchMessage>);

/// The registry of connections currently able to relay a holepunch message, and the reactive-dial
/// targets `connect` messages have named, waiting for the coordinator to act on them.
#[derive(Debug, Default)]
pub struct HolepunchHub {
    relays: Mutex<HashMap<SocketAddr, Relay>>,
    dial_targets: Mutex<VecDeque<SocketAddr>>,
}

/// One connection's place in the hub, removed when dropped.
pub struct HolepunchEntry<'a> {
    hub: &'a HolepunchHub,
    addr: SocketAddr,
    /// Flipped once this connection's peer is known (from its own extended handshake) to
    /// support the extension. Shared with the hub's own map entry, so another connection's
    /// `relay`/`is_unsupported` sees it the moment it changes.
    pub supports: Arc<AtomicBool>,
}

impl Drop for HolepunchEntry<'_> {
    fn drop(&mut self) {
        let mut relays = lock(&self.hub.relays);
        // Only if it is still this entry: an address reconnecting before the
        // old one's cleanup runs must not lose the new connection's place.
        if relays.get(&self.addr).is_some_and(|(flag, _)| Arc::ptr_eq(flag, &self.supports)) {
            relays.remove(&self.addr);
        }
    }
}

impl HolepunchHub {
    /// Registers a connection to `addr`, before it is known whether the peer supports the
    /// extension at all (that is learned later, from its own extended handshake, and set on
    /// the returned entry's `supports` flag). Held for the connection's whole life; the
    /// `Receiver` is drained once per loop iteration for a message to relay onward.
    pub fn enter(&self, addr: SocketAddr) -> (HolepunchEntry<'_>, Receiver<HolepunchMessage>) {
        let supports = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        lock(&self.relays).insert(addr, (Arc::clone(&supports), tx));
        (HolepunchEntry { hub: self, addr, supports }, rx)
    }

    /// Sends `msg` to the connection with `to`, if there is one and it supports the extension.
    /// `true` if it was queued for delivery.
    pub fn relay(&self, to: SocketAddr, msg: HolepunchMessage) -> bool {
        let relays = lock(&self.relays);
        match relays.get(&to) {
            Some((supports, tx)) if supports.load(Ordering::Relaxed) => tx.send(msg).is_ok(),
            _ => false,
        }
    }

    /// Whether `addr` is a connection we have, but it does not (yet, or ever) support the
    /// extension -- as opposed to no connection at all. Used to tell a rendezvous's
    /// [`crate::peer::HolepunchErrorCode::NotConnected`] apart from its `NoSupport`.
    pub fn is_unsupported(&self, addr: &SocketAddr) -> bool {
        matches!(lock(&self.relays).get(addr), Some((supports, _)) if !supports.load(Ordering::Relaxed))
    }

    /// Some address, other than `exclude`, currently able to relay a rendezvous for us -- who
    /// to ask when a fresh dial has failed and this client wants a peer's help reaching it.
    pub fn any_supporting(&self, exclude: SocketAddr) -> Option<SocketAddr> {
        lock(&self.relays).iter().find(|(addr, (supports, _))| **addr != exclude && supports.load(Ordering::Relaxed)).map(|(addr, _)| *addr)
    }

    /// Queues `target` to be dialed over uTP in reaction to a `connect` message (BEP 55).
    pub fn request_dial(&self, target: SocketAddr) {
        lock(&self.dial_targets).push_back(target);
    }

    /// Every dial target queued since the last call.
    pub fn take_dial_targets(&self) -> Vec<SocketAddr> {
        lock(&self.dial_targets).drain(..).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::HolepunchErrorCode;

    fn addr(last: u8) -> SocketAddr {
        format!("10.0.0.{}:6881", last).parse().unwrap()
    }

    #[test]
    fn a_registered_connection_that_never_declares_support_cannot_be_relayed_to() {
        let hub = HolepunchHub::default();
        let (entry, _rx) = hub.enter(addr(1));
        assert!(!hub.relay(addr(1), HolepunchMessage::Connect { endpoint: addr(2) }));
        assert!(hub.is_unsupported(&addr(1)), "connected, but no support seen yet");
        drop(entry);
    }

    #[test]
    fn once_marked_supported_a_relayed_message_is_delivered() {
        let hub = HolepunchHub::default();
        let (entry, rx) = hub.enter(addr(1));
        entry.supports.store(true, Ordering::Relaxed);
        assert!(!hub.is_unsupported(&addr(1)));

        let msg = HolepunchMessage::Connect { endpoint: addr(2) };
        assert!(hub.relay(addr(1), msg));
        assert_eq!(rx.try_recv().unwrap(), msg);
    }

    #[test]
    fn an_address_never_entered_is_not_relayed_to_and_not_called_unsupported() {
        let hub = HolepunchHub::default();
        assert!(!hub.relay(addr(9), HolepunchMessage::Error { target: addr(1), code: HolepunchErrorCode::NotConnected }));
        assert!(!hub.is_unsupported(&addr(9)), "not connected at all is a different case from connected-without-support");
    }

    #[test]
    fn dropping_the_entry_removes_it_and_a_reconnection_is_not_clobbered_by_the_old_ones_cleanup() {
        let hub = HolepunchHub::default();
        let (old, _old_rx) = hub.enter(addr(1));
        let (new, new_rx) = hub.enter(addr(1)); // reconnected before the old one's cleanup ran
        new.supports.store(true, Ordering::Relaxed);

        drop(old);

        assert!(hub.relay(addr(1), HolepunchMessage::Connect { endpoint: addr(2) }), "the new connection's place is kept");
        assert_eq!(new_rx.try_recv().unwrap(), HolepunchMessage::Connect { endpoint: addr(2) });
        drop(new);
        assert!(!hub.is_unsupported(&addr(1)), "and now truly gone");
    }

    #[test]
    fn any_supporting_finds_a_capable_peer_other_than_the_one_excluded() {
        let hub = HolepunchHub::default();
        let (a, _ra) = hub.enter(addr(1));
        let (b, _rb) = hub.enter(addr(2));
        assert_eq!(hub.any_supporting(addr(9)), None, "neither has declared support yet");

        b.supports.store(true, Ordering::Relaxed);
        assert_eq!(hub.any_supporting(addr(9)), Some(addr(2)));
        assert_eq!(hub.any_supporting(addr(2)), None, "the only capable one is the one excluded");
        drop((a, b));
    }

    #[test]
    fn dial_targets_are_queued_and_drained_once() {
        let hub = HolepunchHub::default();
        assert!(hub.take_dial_targets().is_empty());
        hub.request_dial(addr(1));
        hub.request_dial(addr(2));
        assert_eq!(hub.take_dial_targets(), vec![addr(1), addr(2)]);
        assert!(hub.take_dial_targets().is_empty(), "drained once");
    }
}
