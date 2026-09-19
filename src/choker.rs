//! Who the seeder unchokes.
//!
//! Serving every interested peer at once splits the upload bandwidth into
//! many thin streams, so each peer downloads slowly and none is worth much
//! to the swarm. BitTorrent's answer is to *choke*: serve only a few peers
//! at a time -- here [`DEFAULT_SLOTS`] -- and change who now and then.
//!
//! The choice is made in rounds. Most slots go to the peers taking the most
//! from us in the last round, so bandwidth goes where it is used. One slot
//! is *optimistic*: it goes to a peer picked without regard to speed and
//! changes every [`OPTIMISTIC_EVERY`] rounds, so a new peer, which has had
//! nothing yet and so ranks last, is still tried.
//!
//! This is the seeding half of the standard algorithm. The other half --
//! favouring peers that upload to us -- has nothing to work on here, since
//! inbound peers are only ever served, not downloaded from.

use crate::sync::lock;
use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

/// Peers served at once: three by speed and one optimistic.
pub const DEFAULT_SLOTS: usize = 4;
/// The optimistic slot moves on every this many rounds.
pub const OPTIMISTIC_EVERY: u64 = 3;

pub type PeerId = u64;

/// What the choice needs to know about one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub id: PeerId,
    pub interested: bool,
    /// Bytes sent to it since the last round.
    pub uploaded: u64,
}

/// The peers to serve for a round: up to `slots` interested ones, the
/// fastest `slots - 1` and then `optimistic`, if it is interested and not
/// already among them (else the next fastest). Ties go to the lower id, so
/// the answer does not depend on the order `peers` came in.
pub fn choose(peers: &[Candidate], slots: usize, optimistic: Option<PeerId>) -> HashSet<PeerId> {
    if slots == 0 {
        return HashSet::new();
    }
    let mut interested: Vec<Candidate> = peers.iter().copied().filter(|p| p.interested).collect();
    interested.sort_by(|a, b| b.uploaded.cmp(&a.uploaded).then(a.id.cmp(&b.id)));

    // With a single slot there is no room for both kinds; speed wins.
    let regular = if slots == 1 { 1 } else { slots - 1 };
    let mut chosen: HashSet<PeerId> = interested.iter().take(regular).map(|p| p.id).collect();
    if slots > 1 {
        let optimistic = optimistic.filter(|id| interested.iter().any(|p| p.id == *id) && !chosen.contains(id));
        match optimistic {
            Some(id) => {
                chosen.insert(id);
            }
            None => {
                // Nobody optimistic to add: the next fastest fills the slot.
                if let Some(next) = interested.iter().find(|p| !chosen.contains(&p.id)) {
                    chosen.insert(next.id);
                }
            }
        }
    }
    chosen
}

#[derive(Debug)]
struct Slot {
    interested: bool,
    unchoked: bool,
    /// Bytes sent to it since the last round.
    uploaded: u64,
}

#[derive(Debug, Default)]
struct State {
    peers: BTreeMap<PeerId, Slot>,
    next_id: PeerId,
    optimistic: Option<PeerId>,
    round: u64,
}

/// The seeder's record of its peers and who is unchoked.
#[derive(Debug)]
pub struct Choker {
    slots: usize,
    state: Mutex<State>,
}

impl Choker {
    pub fn new(slots: usize) -> Self {
        Choker { slots, state: Mutex::new(State::default()) }
    }

    /// A new connection, choked and not interested.
    pub fn register(&self) -> PeerId {
        let mut state = lock(&self.state);
        let id = state.next_id;
        state.next_id += 1;
        state.peers.insert(id, Slot { interested: false, unchoked: false, uploaded: 0 });
        id
    }

    /// The connection ended; its slot, if it held one, is free for the next
    /// peer that asks.
    pub fn unregister(&self, id: PeerId) {
        let mut state = lock(&self.state);
        state.peers.remove(&id);
        if state.optimistic == Some(id) {
            state.optimistic = None;
        }
    }

    /// Records whether the peer wants data. One that stops wanting it gives
    /// up its slot.
    pub fn set_interested(&self, id: PeerId, interested: bool) {
        let mut state = lock(&self.state);
        if let Some(slot) = state.peers.get_mut(&id) {
            slot.interested = interested;
            if !interested {
                slot.unchoked = false;
            }
        }
    }

    /// Unchokes the peer at once if a slot is free, without waiting for the
    /// next round: a peer that has just shown interest should not wait ten
    /// seconds for its first byte on a seeder with nobody else. Returns
    /// whether it is now unchoked.
    pub fn grant_if_free(&self, id: PeerId) -> bool {
        let mut state = lock(&self.state);
        let held = state.peers.values().filter(|p| p.unchoked).count();
        let Some(slot) = state.peers.get_mut(&id) else { return false };
        if slot.unchoked {
            return true;
        }
        if slot.interested && held < self.slots {
            slot.unchoked = true;
            return true;
        }
        false
    }

    /// Counts `bytes` sent to the peer, for the next round's ranking.
    pub fn record_upload(&self, id: PeerId, bytes: u64) {
        if let Some(slot) = lock(&self.state).peers.get_mut(&id) {
            slot.uploaded += bytes;
        }
    }

    /// Whether the peer is to be served now.
    pub fn is_unchoked(&self, id: PeerId) -> bool {
        lock(&self.state).peers.get(&id).is_some_and(|p| p.unchoked)
    }

    /// How many peers are unchoked.
    pub fn unchoked_count(&self) -> usize {
        lock(&self.state).peers.values().filter(|p| p.unchoked).count()
    }

    /// One round: picks who to serve, from what was sent since the last,
    /// and starts the next window. The optimistic slot moves every
    /// [`OPTIMISTIC_EVERY`] rounds, to the interested peer after the last
    /// one that had it (in the order they connected).
    pub fn rechoke(&self) {
        let mut state = lock(&self.state);
        state.round += 1;
        if self.slots > 1 && (state.round % OPTIMISTIC_EVERY == 1 || state.optimistic.is_none_or(|id| !state.peers.get(&id).is_some_and(|p| p.interested))) {
            let after = state.optimistic;
            let candidates: Vec<PeerId> = state.peers.iter().filter(|(_, p)| p.interested).map(|(id, _)| *id).collect();
            state.optimistic = candidates.iter().copied().find(|id| after.is_none_or(|a| *id > a)).or_else(|| candidates.first().copied());
        }
        let candidates: Vec<Candidate> = state.peers.iter().map(|(id, p)| Candidate { id: *id, interested: p.interested, uploaded: p.uploaded }).collect();
        let chosen = choose(&candidates, self.slots, state.optimistic);
        for (id, slot) in state.peers.iter_mut() {
            slot.unchoked = chosen.contains(id);
            slot.uploaded = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: PeerId, interested: bool, uploaded: u64) -> Candidate {
        Candidate { id, interested, uploaded }
    }

    fn ids(set: &HashSet<PeerId>) -> Vec<PeerId> {
        let mut v: Vec<PeerId> = set.iter().copied().collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn the_fastest_take_the_regular_slots_and_the_optimistic_one_is_added() {
        let peers: Vec<Candidate> = (0..8).map(|i| peer(i, true, (8 - i) * 100)).collect(); // 0 is fastest
        assert_eq!(ids(&choose(&peers, 4, Some(7))), vec![0, 1, 2, 7], "three by speed and the optimistic one");
    }

    #[test]
    fn a_peer_that_is_not_interested_is_never_chosen_however_fast() {
        let peers = vec![peer(0, false, 1_000_000), peer(1, true, 10), peer(2, true, 5)];
        assert_eq!(ids(&choose(&peers, 4, Some(0))), vec![1, 2], "not even as the optimistic one");
    }

    #[test]
    fn when_the_optimistic_peer_is_already_fast_the_next_fastest_takes_the_slot() {
        let peers: Vec<Candidate> = (0..6).map(|i| peer(i, true, (6 - i) * 100)).collect();
        // 1 is optimistic but is also among the three fastest: the slot goes on to 3.
        assert_eq!(ids(&choose(&peers, 4, Some(1))), vec![0, 1, 2, 3]);
        assert_eq!(ids(&choose(&peers, 4, None)), vec![0, 1, 2, 3], "no optimistic peer: the next fastest");
    }

    #[test]
    fn fewer_interested_peers_than_slots_are_all_served() {
        let peers = vec![peer(3, true, 0), peer(9, true, 0), peer(1, false, 0)];
        assert_eq!(ids(&choose(&peers, 4, None)), vec![3, 9]);
        assert!(choose(&[], 4, None).is_empty());
    }

    #[test]
    fn ties_go_to_the_lower_id_whatever_order_the_peers_arrive_in() {
        let forward = vec![peer(1, true, 50), peer(2, true, 50), peer(3, true, 50), peer(4, true, 50), peer(5, true, 50)];
        let mut backward = forward.clone();
        backward.reverse();
        assert_eq!(choose(&forward, 4, None), choose(&backward, 4, None));
        assert_eq!(ids(&choose(&forward, 4, None)), vec![1, 2, 3, 4]);
    }

    #[test]
    fn one_slot_goes_to_speed_and_none_to_no_one() {
        let peers = vec![peer(1, true, 10), peer(2, true, 99)];
        assert_eq!(ids(&choose(&peers, 1, Some(1))), vec![2]);
        assert!(choose(&peers, 0, Some(1)).is_empty());
    }

    // ---- the record over time ----

    #[test]
    fn a_new_interested_peer_gets_a_free_slot_at_once_and_a_full_house_makes_it_wait() {
        let choker = Choker::new(2);
        let (a, b, c) = (choker.register(), choker.register(), choker.register());
        for id in [a, b, c] {
            choker.set_interested(id, true);
        }

        assert!(choker.grant_if_free(a) && choker.grant_if_free(b));
        assert!(!choker.grant_if_free(c), "both slots are taken");
        assert!(!choker.is_unchoked(c));
        assert_eq!(choker.unchoked_count(), 2);
        assert!(choker.grant_if_free(a), "asking again changes nothing");
    }

    #[test]
    fn a_peer_must_be_interested_to_be_granted_a_slot() {
        let choker = Choker::new(2);
        let a = choker.register();
        assert!(!choker.grant_if_free(a), "it has not said it wants anything");
        assert!(!choker.grant_if_free(999), "and an unknown one is refused");
    }

    #[test]
    fn a_peer_that_loses_interest_or_leaves_frees_its_slot() {
        let choker = Choker::new(1);
        let (a, b) = (choker.register(), choker.register());
        choker.set_interested(a, true);
        choker.set_interested(b, true);
        assert!(choker.grant_if_free(a));
        assert!(!choker.grant_if_free(b));

        choker.set_interested(a, false);
        assert!(!choker.is_unchoked(a));
        assert!(choker.grant_if_free(b), "a is no longer using it");

        choker.unregister(b);
        assert_eq!(choker.unchoked_count(), 0);
    }

    #[test]
    fn a_round_serves_the_peers_that_took_the_most_and_starts_the_next_window() {
        let choker = Choker::new(2); // one by speed, one optimistic
        let ids: Vec<PeerId> = (0..3).map(|_| choker.register()).collect();
        for &id in &ids {
            choker.set_interested(id, true);
        }
        choker.record_upload(ids[2], 5000);

        choker.rechoke();
        assert!(choker.is_unchoked(ids[2]), "the one that took the most keeps the speed slot");
        assert_eq!(choker.unchoked_count(), 2, "and one optimistic");

        // Nothing has been sent since, so what it took last round no longer
        // counts: the lowest ids fill the slots.
        choker.rechoke();
        assert!(!choker.is_unchoked(ids[2]), "last round's traffic was forgotten");
        assert!(choker.is_unchoked(ids[0]) && choker.is_unchoked(ids[1]));
    }

    #[test]
    fn the_optimistic_slot_visits_each_interested_peer_in_turn() {
        let choker = Choker::new(2);
        let ids: Vec<PeerId> = (0..3).map(|_| choker.register()).collect();
        for &id in &ids {
            choker.set_interested(id, true);
        }
        // Nobody uploads anything, so the regular slot is always the lowest id
        // and the optimistic slot decides who else is served.
        let mut seen_second = HashSet::new();
        for _ in 0..(OPTIMISTIC_EVERY * 4) {
            choker.rechoke();
            for &id in &ids[1..] {
                if choker.is_unchoked(id) {
                    seen_second.insert(id);
                }
            }
        }
        assert_eq!(seen_second.len(), 2, "both peers that were never fastest got their turn: {:?}", seen_second);
    }

    #[test]
    fn a_round_with_no_interested_peers_serves_no_one_and_does_not_panic() {
        let choker = Choker::new(4);
        choker.register();
        choker.rechoke();
        assert_eq!(choker.unchoked_count(), 0);
        Choker::new(4).rechoke();
        Choker::new(0).rechoke();
    }
}
