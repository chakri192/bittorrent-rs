//! How many block requests to keep in flight to a peer.
//!
//! A request only pays off one round trip later, so a fixed queue caps
//! throughput at `depth * 16 KiB / round-trip time`: 5 blocks over a 100 ms
//! link is 800 KB/s however fast either end is. The queue has to be as long
//! as the link is fat. It is sized from what the peer is actually
//! delivering: enough requests to cover [`QUEUE_SECONDS`] of data at the
//! current rate, never fewer than the configured minimum, and never more
//! than the peer said it will queue (`reqq`) or [`MAX_DEPTH`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How many seconds of data to keep requested.
const QUEUE_SECONDS: f64 = 2.0;
/// The most requests ever queued, whatever the rate (2 MiB).
pub const MAX_DEPTH: usize = 128;
/// What to assume when the peer does not say what it will queue.
pub const DEFAULT_PEER_LIMIT: usize = 64;
/// The block size requests are made in.
const BLOCK: f64 = 16384.0;
/// The span the rate is measured over.
const WINDOW: Duration = Duration::from_secs(3);
/// A rate is never computed over less than this, so that the first block
/// or two of a connection cannot read as a huge rate.
const MIN_SPAN: Duration = Duration::from_millis(500);

/// The rate at which a peer's blocks have been arriving.
#[derive(Debug, Default)]
pub struct Throughput {
    /// (when, bytes) for each block within the window.
    samples: VecDeque<(Instant, usize)>,
}

impl Throughput {
    pub fn record(&mut self, now: Instant, bytes: usize) {
        self.samples.push_back((now, bytes));
        self.forget_old(now);
    }

    fn forget_old(&mut self, now: Instant) {
        while self.samples.front().is_some_and(|&(at, _)| now.saturating_duration_since(at) > WINDOW) {
            self.samples.pop_front();
        }
    }

    /// Bytes per second over the last few seconds; 0 before any block.
    pub fn rate(&self, now: Instant) -> f64 {
        let Some(&(first, _)) = self.samples.iter().find(|&&(at, _)| now.saturating_duration_since(at) <= WINDOW) else {
            return 0.0;
        };
        let bytes: usize = self.samples.iter().filter(|&&(at, _)| now.saturating_duration_since(at) <= WINDOW).map(|&(_, n)| n).sum();
        let span = now.saturating_duration_since(first).clamp(MIN_SPAN, WINDOW);
        bytes as f64 / span.as_secs_f64()
    }
}

/// The queue length for a peer delivering `rate` bytes per second:
/// `min_depth` at least, `peer_limit` (or [`DEFAULT_PEER_LIMIT`]) and
/// [`MAX_DEPTH`] at most. A peer that says it queues fewer than
/// `min_depth` gets what it said.
pub fn depth_for(rate: f64, min_depth: usize, peer_limit: Option<usize>) -> usize {
    let cap = peer_limit.unwrap_or(DEFAULT_PEER_LIMIT).clamp(1, MAX_DEPTH);
    let wanted = (rate * QUEUE_SECONDS / BLOCK).ceil() as usize;
    wanted.clamp(min_depth.min(cap), cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    #[test]
    fn with_no_blocks_yet_the_rate_is_zero() {
        assert_eq!(Throughput::default().rate(Instant::now()), 0.0);
    }

    #[test]
    fn the_rate_is_bytes_over_the_time_they_took() {
        let t0 = Instant::now();
        let mut meter = Throughput::default();
        // 10 blocks of 16 KiB, one every 100 ms, from 0 to 900 ms.
        for i in 0..10 {
            meter.record(at(t0, i * 100), 16384);
        }
        // Measured at 1 s: 163840 bytes since the first sample, 1 s ago.
        assert_eq!(meter.rate(at(t0, 1000)), 163840.0);
    }

    #[test]
    fn the_first_blocks_cannot_read_as_an_enormous_rate() {
        let t0 = Instant::now();
        let mut meter = Throughput::default();
        meter.record(t0, 16384);
        meter.record(at(t0, 1), 16384);
        // Two blocks a millisecond apart: over the 500 ms floor, not over 1 ms.
        assert_eq!(meter.rate(at(t0, 1)), 32768.0 / 0.5);
    }

    #[test]
    fn old_blocks_age_out_of_the_rate() {
        let t0 = Instant::now();
        let mut meter = Throughput::default();
        for i in 0..10 {
            meter.record(at(t0, i * 100), 16384);
        }
        // A quiet ten seconds: nothing within the window any more.
        assert_eq!(meter.rate(at(t0, 11_000)), 0.0);
        // Then a single fresh block is all there is.
        meter.record(at(t0, 11_000), 16384);
        assert_eq!(meter.rate(at(t0, 11_000)), 16384.0 / 0.5);
        assert!(meter.samples.len() == 1, "the old samples were dropped, not just ignored");
    }

    #[test]
    fn a_slow_peer_keeps_the_minimum_queue() {
        assert_eq!(depth_for(0.0, 5, None), 5);
        assert_eq!(depth_for(10_000.0, 5, None), 5, "10 KB/s wants two blocks, and the minimum is more");
    }

    #[test]
    fn the_queue_covers_two_seconds_of_the_rate() {
        // 800 KB/s is 2 s * 800000 / 16384 = 97.7 blocks, rounded up.
        assert_eq!(depth_for(800_000.0, 5, Some(500)), 98);
        // 160 KB/s: 19.5 -> 20.
        assert_eq!(depth_for(160_000.0, 5, None), 20);
    }

    #[test]
    fn what_the_peer_says_it_will_queue_is_a_ceiling() {
        assert_eq!(depth_for(800_000.0, 5, Some(30)), 30);
        assert_eq!(depth_for(800_000.0, 5, Some(2)), 2, "even below the minimum: the peer would drop the rest");
    }

    #[test]
    fn a_peer_that_does_not_say_gets_a_cautious_ceiling() {
        assert_eq!(depth_for(10_000_000.0, 5, None), DEFAULT_PEER_LIMIT);
    }

    #[test]
    fn nothing_ever_exceeds_the_absolute_maximum() {
        assert_eq!(depth_for(1e12, 5, Some(100_000)), MAX_DEPTH);
        assert_eq!(depth_for(f64::INFINITY, 5, Some(usize::MAX)), MAX_DEPTH);
    }

    #[test]
    fn a_limit_of_zero_still_allows_one_request() {
        assert_eq!(depth_for(1e9, 5, Some(0)), 1);
    }
}
