//! Announce tokens (BEP 5): what stops a node from announcing an address
//! that is not its own.

use super::random_node_id;
use sha1::{Digest, Sha1};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// How often the announce-token secret is replaced. BEP 5 leaves the
/// schedule to the implementation but requires a token to stay valid for
/// a while after it is issued; mainline rotates every 5 minutes and
/// accepts the previous generation too, so a token is good for 5-10.
const TOKEN_ROTATION: Duration = Duration::from_secs(300);

/// The secrets announce tokens are derived from: the current one, plus
/// the one before it so a token handed out just before a rotation still
/// verifies. Anything older is rejected, which is the point -- a token
/// harvested once cannot be replayed indefinitely.
pub(super) struct TokenSecrets {
    current: [u8; 20],
    previous: Option<[u8; 20]>,
    rotated_at: Instant,
}

impl TokenSecrets {
    pub(super) fn new(now: Instant) -> Self {
        TokenSecrets { current: random_node_id(), previous: None, rotated_at: now }
    }

    /// The token to hand `ip` now.
    pub(super) fn issue(&self, ip: &Ipv4Addr) -> Vec<u8> {
        token_for(&self.current, ip)
    }

    pub(super) fn rotate(&mut self, now: Instant) {
        self.previous = Some(std::mem::replace(&mut self.current, random_node_id()));
        self.rotated_at = now;
    }

    pub(super) fn rotate_if_due(&mut self, now: Instant) {
        if now.saturating_duration_since(self.rotated_at) >= TOKEN_ROTATION {
            self.rotate(now);
        }
    }

    /// Whether `token` is one we issued to `ip` under the current or the
    /// previous secret.
    pub(super) fn accepts(&self, ip: &Ipv4Addr, token: &[u8]) -> bool {
        token_for(&self.current, ip) == token || self.previous.is_some_and(|prev| token_for(&prev, ip) == token)
    }
}

/// Announce token for `ip` under `secret`: the first 8 bytes of
/// sha1(secret || ip). Opaque to the receiver (BEP 5), verifiable by us.
fn token_for(secret: &[u8; 20], ip: &Ipv4Addr) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(secret);
    h.update(ip.octets());
    h.finalize()[..8].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_happens_only_once_the_interval_has_elapsed() {
        let start = Instant::now();
        let mut secrets = TokenSecrets::new(start);
        let original = secrets.current;

        secrets.rotate_if_due(start + TOKEN_ROTATION - Duration::from_secs(1));
        assert_eq!(secrets.current, original, "must not rotate early");
        assert!(secrets.previous.is_none());

        secrets.rotate_if_due(start + TOKEN_ROTATION);
        assert_ne!(secrets.current, original, "must rotate at the interval");
        assert_eq!(secrets.previous, Some(original), "the old secret is kept for one more generation");
    }
}
