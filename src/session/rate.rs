//! Smoothed transfer rates for the dashboard.

use std::time::Instant;

/// Samples closer together than this are skipped: over a shorter window a
/// handful of bytes either way swings the instantaneous rate wildly.
const MIN_SAMPLE_SECS: f64 = 0.25;

/// Weight kept from the previous smoothed value; the new instantaneous
/// rate gets the rest. Exponential smoothing, so a stalled peer decays
/// the displayed rate over a couple of seconds instead of snapping to 0.
const KEEP: f64 = 0.6;

/// Turns running byte totals into smoothed down/up rates.
///
/// Feed it the cumulative totals whenever convenient; it takes a sample
/// only when enough time has passed since the last one. Both directions
/// share one clock, so they always move together.
pub struct RateSampler {
    last_at: Instant,
    last_down: u64,
    last_up: u64,
    down: f64,
    up: f64,
}

impl RateSampler {
    /// Starts measuring from `now`. The totals given here are the
    /// baseline: bytes already counted (say, pieces resumed from disk)
    /// must not show up as a burst of throughput on the first sample.
    pub fn new(now: Instant, down_total: u64, up_total: u64) -> Self {
        RateSampler { last_at: now, last_down: down_total, last_up: up_total, down: 0.0, up: 0.0 }
    }

    /// Takes a sample if at least [`MIN_SAMPLE_SECS`] have passed.
    /// Returns whether it did, so callers can refresh anything else that
    /// should update at the same cadence.
    pub fn sample(&mut self, now: Instant, down_total: u64, up_total: u64) -> bool {
        let dt = now.saturating_duration_since(self.last_at).as_secs_f64();
        if dt < MIN_SAMPLE_SECS {
            return false;
        }
        let inst_down = down_total.saturating_sub(self.last_down) as f64 / dt;
        let inst_up = up_total.saturating_sub(self.last_up) as f64 / dt;
        self.down = KEEP * self.down + (1.0 - KEEP) * inst_down;
        self.up = KEEP * self.up + (1.0 - KEEP) * inst_up;
        self.last_at = now;
        self.last_down = down_total;
        self.last_up = up_total;
        true
    }

    /// Smoothed download rate, bytes per second.
    pub fn down_rate(&self) -> f64 {
        self.down
    }

    /// Smoothed upload rate, bytes per second.
    pub fn up_rate(&self) -> f64 {
        self.up
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn secs(t0: Instant, s: f64) -> Instant {
        t0 + Duration::from_secs_f64(s)
    }

    #[test]
    fn a_sample_inside_the_minimum_window_is_skipped() {
        let t0 = Instant::now();
        let mut r = RateSampler::new(t0, 0, 0);
        assert!(!r.sample(secs(t0, 0.1), 1_000, 0));
        assert_eq!(r.down_rate(), 0.0, "nothing is measured until the window has passed");
    }

    #[test]
    fn the_first_sample_is_weighted_by_the_smoothing_factor() {
        let t0 = Instant::now();
        let mut r = RateSampler::new(t0, 0, 0);
        assert!(r.sample(secs(t0, 1.0), 1_000, 500));
        // instantaneous 1000 B/s and 500 B/s; smoothed = 0.4 * inst from a zero start
        assert!((r.down_rate() - 400.0).abs() < 1e-9);
        assert!((r.up_rate() - 200.0).abs() < 1e-9);
    }

    #[test]
    fn a_steady_rate_converges_on_itself() {
        let t0 = Instant::now();
        let mut r = RateSampler::new(t0, 0, 0);
        for i in 1..=40 {
            r.sample(secs(t0, i as f64), i * 1_000, 0);
        }
        assert!((r.down_rate() - 1_000.0).abs() < 1.0, "got {}", r.down_rate());
    }

    #[test]
    fn a_stall_decays_the_rate_instead_of_dropping_it_to_zero() {
        let t0 = Instant::now();
        let mut r = RateSampler::new(t0, 0, 0);
        for i in 1..=40 {
            r.sample(secs(t0, i as f64), i * 1_000, 0);
        }
        let before = r.down_rate();
        r.sample(secs(t0, 41.0), 40_000, 0); // no new bytes
        assert!((r.down_rate() - before * 0.6).abs() < 1e-6);
        assert!(r.down_rate() > 0.0);
    }

    #[test]
    fn the_baseline_totals_do_not_count_as_throughput() {
        let t0 = Instant::now();
        let mut r = RateSampler::new(t0, 5_000_000, 0); // e.g. resumed from disk
        r.sample(secs(t0, 1.0), 5_000_000, 0);
        assert_eq!(r.down_rate(), 0.0);
    }

    #[test]
    fn a_total_that_goes_backwards_is_treated_as_no_progress() {
        let t0 = Instant::now();
        let mut r = RateSampler::new(t0, 1_000, 1_000);
        assert!(r.sample(secs(t0, 1.0), 10, 10));
        assert_eq!(r.down_rate(), 0.0);
        assert_eq!(r.up_rate(), 0.0);
    }

    #[test]
    fn the_window_restarts_after_each_sample() {
        let t0 = Instant::now();
        let mut r = RateSampler::new(t0, 0, 0);
        assert!(r.sample(secs(t0, 1.0), 1_000, 0));
        assert!(!r.sample(secs(t0, 1.1), 2_000, 0), "only 0.1s since the last sample");
        assert!(r.sample(secs(t0, 1.3), 2_000, 0));
    }
}
