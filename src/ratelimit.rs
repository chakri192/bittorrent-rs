//! A shared token-bucket rate limiter for `--max-down` and `--max-up`.
//!
//! One limiter is shared by every connection, so the limit is on the whole
//! client, not per peer. A thread asks for the bytes it is about to move
//! and sleeps for as long as the answer says. Reading slowly is honest
//! backpressure: the peer's TCP window fills and it slows down.

use crate::sync::lock;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

struct State {
    /// Bytes that may be moved right now. Negative after a large request:
    /// the debt is what the caller is told to wait out.
    tokens: f64,
    last: Instant,
}

/// Limits a byte stream to a rate, allowing about a second's worth in a
/// burst.
pub struct RateLimiter {
    bytes_per_sec: f64,
    burst: f64,
    state: Mutex<State>,
}

impl RateLimiter {
    /// A limiter of `bytes_per_sec` (at least 1), starting with a full
    /// bucket.
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = bytes_per_sec.max(1) as f64;
        RateLimiter { bytes_per_sec: rate, burst: rate, state: Mutex::new(State { tokens: rate, last: Instant::now() }) }
    }

    /// The configured rate.
    pub fn bytes_per_sec(&self) -> u64 {
        self.bytes_per_sec as u64
    }

    /// Accounts for moving `n` bytes at `now` and returns how long the
    /// caller must wait before doing so. Does not sleep, so the arithmetic
    /// can be tested without a clock.
    ///
    /// The bucket refills at the rate, up to one burst. A request larger
    /// than what is in it is granted, on credit, and its debt is the wait;
    /// so a block bigger than a whole burst still gets through, slowly.
    pub fn reserve(&self, n: usize, now: Instant) -> Duration {
        let mut state = lock(&self.state);
        let elapsed = now.saturating_duration_since(state.last).as_secs_f64();
        state.last = state.last.max(now);
        state.tokens = (state.tokens + elapsed * self.bytes_per_sec).min(self.burst);
        state.tokens -= n as f64;
        if state.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-state.tokens / self.bytes_per_sec)
        }
    }

    /// Blocks until `n` more bytes may be moved.
    pub fn acquire(&self, n: usize) {
        let wait = self.reserve(n, Instant::now());
        if !wait.is_zero() {
            thread::sleep(wait);
        }
    }
}

/// Parses a rate such as `500`, `64K`, `1.5M` or `2MiB` (binary units,
/// bytes per second) as given to `--max-down` and `--max-up`.
pub fn parse_rate(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let split = t.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(t.len());
    let (number, suffix) = t.split_at(split);
    let value: f64 = number.parse().map_err(|_| format!("not a rate: {:?} (try 500, 64K or 1.5M)", text))?;
    let multiplier: f64 = match suffix.to_ascii_lowercase().trim_end_matches("/s").trim_end_matches('b').trim_end_matches('i') {
        "" => 1.0,
        "k" => 1024.0,
        "m" => 1024.0 * 1024.0,
        "g" => 1024.0 * 1024.0 * 1024.0,
        _ => return Err(format!("unknown unit in {:?} (use K, M or G)", text)),
    };
    let bytes = value * multiplier;
    if !(1.0..=u64::MAX as f64).contains(&bytes) {
        return Err(format!("a rate must be at least 1 byte per second: {:?}", text));
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: f64) -> Duration {
        Duration::from_secs_f64(n)
    }

    #[test]
    fn a_full_bucket_lets_a_burst_through_at_once() {
        let l = RateLimiter::new(1000);
        let t0 = Instant::now();
        assert_eq!(l.reserve(600, t0), Duration::ZERO);
        assert_eq!(l.reserve(400, t0), Duration::ZERO, "the whole second's worth is free");
    }

    #[test]
    fn beyond_the_burst_the_wait_is_the_debt_over_the_rate() {
        let l = RateLimiter::new(1000);
        let t0 = Instant::now();
        l.reserve(1000, t0);
        let wait = l.reserve(500, t0);
        assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "500 bytes at 1000/s is half a second, got {:?}", wait);
    }

    #[test]
    fn waiting_out_the_debt_leaves_nothing_owed() {
        let l = RateLimiter::new(1000);
        let t0 = Instant::now();
        l.reserve(1000, t0);
        let wait = l.reserve(500, t0);
        // After sleeping exactly that long, the same request costs the same
        // again: the rate holds instead of drifting.
        let next = l.reserve(500, t0 + wait);
        assert!((next.as_secs_f64() - 0.5).abs() < 1e-6, "{:?}", next);
    }

    #[test]
    fn the_bucket_refills_with_time_but_never_past_a_burst() {
        let l = RateLimiter::new(1000);
        let t0 = Instant::now();
        l.reserve(1000, t0);
        assert_eq!(l.reserve(500, t0 + secs(0.5)), Duration::ZERO, "half a second refilled 500");
        assert_eq!(l.reserve(1000, t0 + secs(100.0)), Duration::ZERO, "a long idle stretch banks only one burst...");
        assert!(l.reserve(500, t0 + secs(100.0)) > Duration::ZERO, "...not a hundred");
    }

    #[test]
    fn a_block_larger_than_a_whole_burst_still_gets_through_slowly() {
        // 16 KiB at 400 B/s: the bucket only ever holds 400.
        let l = RateLimiter::new(400);
        let wait = l.reserve(16384, Instant::now());
        assert!((wait.as_secs_f64() - (16384.0 - 400.0) / 400.0).abs() < 1e-6, "{:?}", wait);
    }

    #[test]
    fn concurrent_reservations_add_up_instead_of_each_getting_the_full_rate() {
        let l = RateLimiter::new(1000);
        let t0 = Instant::now();
        l.reserve(1000, t0);
        let waits: Vec<f64> = (0..4).map(|_| l.reserve(250, t0).as_secs_f64()).collect();
        // Four threads asking for 250 each at the same instant must queue
        // behind each other: 0.25, 0.5, 0.75, 1.0 seconds.
        for (i, w) in waits.iter().enumerate() {
            assert!((w - 0.25 * (i + 1) as f64).abs() < 1e-6, "{:?}", waits);
        }
    }

    #[test]
    fn a_clock_that_goes_backwards_is_harmless() {
        let l = RateLimiter::new(1000);
        let t0 = Instant::now();
        l.reserve(1000, t0 + secs(5.0));
        let wait = l.reserve(10, t0); // earlier than the last call
        assert!(wait.as_secs_f64() < 0.02, "{:?}", wait);
    }

    #[test]
    fn acquire_really_takes_the_time_the_rate_demands() {
        let l = RateLimiter::new(20_000);
        let start = Instant::now();
        l.acquire(20_000); // the burst
        l.acquire(6_000); // 0.3 s of debt
        assert!(start.elapsed() >= Duration::from_millis(250), "{:?}", start.elapsed());
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn a_zero_rate_is_treated_as_one_byte_per_second_rather_than_dividing_by_zero() {
        assert_eq!(RateLimiter::new(0).bytes_per_sec(), 1);
    }

    #[test]
    fn rates_are_parsed_with_binary_units() {
        assert_eq!(parse_rate("500"), Ok(500));
        assert_eq!(parse_rate("64K"), Ok(64 * 1024));
        assert_eq!(parse_rate("64k"), Ok(64 * 1024));
        assert_eq!(parse_rate("1.5M"), Ok(1_572_864));
        assert_eq!(parse_rate("2MiB"), Ok(2 * 1024 * 1024));
        assert_eq!(parse_rate("2MB/s"), Ok(2 * 1024 * 1024));
        assert_eq!(parse_rate(" 1G "), Ok(1024 * 1024 * 1024));
    }

    #[test]
    fn nonsense_rates_are_refused_with_a_message() {
        for bad in ["", "abc", "0", "0K", "-5", "5X", "K", "1.2.3", "nan"] {
            assert!(parse_rate(bad).is_err(), "{:?} should be refused", bad);
        }
        assert!(parse_rate("5X").unwrap_err().contains("unit"));
    }
}
