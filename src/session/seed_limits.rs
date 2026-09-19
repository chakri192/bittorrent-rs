//! When to stop seeding: `--seed-ratio` and `--seed-time`.
//!
//! Without a limit a seeding client runs until it is told to stop, which
//! is right for a machine that is always on and wrong for a laptop. The
//! ratio is what was uploaded over the size of the torrent (the files
//! selected, when only some were), so 1.0 means "gave back as much as the
//! torrent weighs". Whichever limit is met first ends the seeding.

use crate::ui::format_duration;
use std::fmt;
use std::time::Duration;

/// The limits, either of which may be unset.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SeedLimits {
    pub ratio: Option<f64>,
    pub time: Option<Duration>,
}

/// Which limit ended the seeding.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeedEnd {
    Ratio(f64),
    Time(Duration),
}

impl fmt::Display for SeedEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedEnd::Ratio(target) => write!(f, "seed ratio {:.2} reached", target),
            SeedEnd::Time(after) => write!(f, "seed time of {} reached", format_duration(after.as_secs())),
        }
    }
}

impl SeedLimits {
    pub fn is_set(&self) -> bool {
        self.ratio.is_some() || self.time.is_some()
    }

    /// The limit that has been reached, if any, given what has been
    /// uploaded, the torrent's size and how long seeding has gone on. The
    /// ratio is checked first, so when both are met at once the ratio is
    /// the one reported.
    pub fn reached(&self, uploaded: u64, torrent_size: u64, seeded_for: Duration) -> Option<SeedEnd> {
        if let Some(target) = self.ratio {
            // A torrent of no bytes has no ratio to reach.
            if torrent_size > 0 && uploaded as f64 / torrent_size as f64 >= target {
                return Some(SeedEnd::Ratio(target));
            }
        }
        if let Some(limit) = self.time {
            if seeded_for >= limit {
                return Some(SeedEnd::Time(limit));
            }
        }
        None
    }
}

impl fmt::Display for SeedLimits {
    /// "ratio 2.00 or 30m", for the line that says when seeding will stop.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.ratio, self.time) {
            (Some(r), Some(t)) => write!(f, "ratio {:.2} or {}", r, format_duration(t.as_secs())),
            (Some(r), None) => write!(f, "ratio {:.2}", r),
            (None, Some(t)) => write!(f, "{}", format_duration(t.as_secs())),
            (None, None) => write!(f, "never"),
        }
    }
}

/// Parses a ratio such as `1`, `2.5` or `0.5`.
pub fn parse_ratio(text: &str) -> Result<f64, String> {
    let value: f64 = text.trim().parse().map_err(|_| format!("not a ratio: {:?} (try 1, 2.5 or 0.5)", text))?;
    check_ratio(value)
}

/// A ratio from somewhere that has already parsed it (the config file):
/// finite and greater than 0.
pub fn check_ratio(value: f64) -> Result<f64, String> {
    if !value.is_finite() || value <= 0.0 {
        return Err(format!("a ratio must be greater than 0: {}", value));
    }
    Ok(value)
}

/// Parses a duration such as `90` (seconds), `45s`, `30m`, `2h`, `1.5h`, `1d`
/// or `1h30m`.
pub fn parse_duration(text: &str) -> Result<Duration, String> {
    let bad = || format!("not a duration: {:?} (try 90, 30m, 2h, 1d or 1h30m)", text);
    let t = text.trim();
    if t.is_empty() {
        return Err(bad());
    }
    // A bare number is seconds; otherwise every number carries a unit.
    if let Ok(secs) = t.parse::<f64>() {
        return finish(secs, text);
    }
    let mut total = 0.0;
    let mut rest = t;
    while !rest.is_empty() {
        let number_end = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).ok_or_else(bad)?;
        let number: f64 = rest[..number_end].parse().map_err(|_| bad())?;
        let unit = rest[number_end..].chars().next().ok_or_else(bad)?;
        let per_unit = match unit.to_ascii_lowercase() {
            's' => 1.0,
            'm' => 60.0,
            'h' => 3600.0,
            'd' => 86400.0,
            _ => return Err(bad()),
        };
        total += number * per_unit;
        rest = &rest[number_end + unit.len_utf8()..];
    }
    finish(total, text)
}

fn finish(secs: f64, text: &str) -> Result<Duration, String> {
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("a duration must be greater than 0: {:?}", text));
    }
    Duration::try_from_secs_f64(secs).map_err(|_| format!("that duration is too long: {:?}", text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(ratio: Option<f64>, time: Option<u64>) -> SeedLimits {
        SeedLimits { ratio, time: time.map(Duration::from_secs) }
    }

    #[test]
    fn with_no_limits_seeding_never_ends() {
        let none = SeedLimits::default();
        assert!(!none.is_set());
        assert_eq!(none.reached(u64::MAX, 1, Duration::from_secs(u32::MAX as u64)), None);
    }

    #[test]
    fn the_ratio_is_reached_exactly_when_uploaded_is_that_multiple_of_the_size() {
        let l = limits(Some(2.0), None);
        assert_eq!(l.reached(1999, 1000, Duration::ZERO), None);
        assert_eq!(l.reached(2000, 1000, Duration::ZERO), Some(SeedEnd::Ratio(2.0)));
        assert_eq!(l.reached(5000, 1000, Duration::ZERO), Some(SeedEnd::Ratio(2.0)));
    }

    #[test]
    fn a_ratio_below_one_needs_only_part_of_the_torrent_uploaded() {
        let l = limits(Some(0.5), None);
        assert_eq!(l.reached(499, 1000, Duration::ZERO), None);
        assert_eq!(l.reached(500, 1000, Duration::ZERO), Some(SeedEnd::Ratio(0.5)));
    }

    #[test]
    fn a_torrent_of_no_bytes_never_reaches_a_ratio() {
        assert_eq!(limits(Some(1.0), None).reached(0, 0, Duration::ZERO), None);
        assert_eq!(limits(Some(1.0), None).reached(100, 0, Duration::ZERO), None);
    }

    #[test]
    fn the_time_is_reached_once_seeding_has_gone_on_that_long() {
        let l = limits(None, Some(600));
        assert_eq!(l.reached(0, 1000, Duration::from_secs(599)), None);
        assert_eq!(l.reached(0, 1000, Duration::from_secs(600)), Some(SeedEnd::Time(Duration::from_secs(600))));
    }

    #[test]
    fn whichever_limit_comes_first_ends_the_seeding() {
        let l = limits(Some(1.0), Some(600));
        assert_eq!(l.reached(1000, 1000, Duration::from_secs(10)), Some(SeedEnd::Ratio(1.0)), "the ratio first");
        assert_eq!(l.reached(10, 1000, Duration::from_secs(601)), Some(SeedEnd::Time(Duration::from_secs(600))), "the time first");
        assert_eq!(l.reached(10, 1000, Duration::from_secs(10)), None, "neither yet");
    }

    #[test]
    fn when_both_are_met_together_the_ratio_is_reported() {
        let l = limits(Some(1.0), Some(600));
        assert_eq!(l.reached(1000, 1000, Duration::from_secs(700)), Some(SeedEnd::Ratio(1.0)));
    }

    #[test]
    fn the_end_is_described_for_the_log() {
        assert_eq!(SeedEnd::Ratio(2.0).to_string(), "seed ratio 2.00 reached");
        assert_eq!(SeedEnd::Time(Duration::from_secs(5400)).to_string(), "seed time of 1h30m reached");
        assert_eq!(limits(Some(1.5), Some(1800)).to_string(), "ratio 1.50 or 30m00s");
        assert_eq!(limits(Some(1.5), None).to_string(), "ratio 1.50");
        assert_eq!(limits(None, Some(45)).to_string(), "45s");
    }

    #[test]
    fn ratios_parse_and_bad_ones_are_refused() {
        assert_eq!(check_ratio(1.5), Ok(1.5));
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(check_ratio(bad).is_err(), "{} should be refused", bad);
        }
        assert_eq!(parse_ratio("2"), Ok(2.0));
        assert_eq!(parse_ratio(" 0.25 "), Ok(0.25));
        for bad in ["0", "-1", "abc", "", "inf", "NaN", "1x"] {
            assert!(parse_ratio(bad).is_err(), "{:?} should be refused", bad);
        }
    }

    #[test]
    fn durations_parse_in_every_unit() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)), "bare numbers are seconds");
        assert_eq!(parse_duration("45s"), Ok(Duration::from_secs(45)));
        assert_eq!(parse_duration("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86400)));
        assert_eq!(parse_duration("1.5h"), Ok(Duration::from_secs(5400)));
        assert_eq!(parse_duration("1h30m"), Ok(Duration::from_secs(5400)));
        assert_eq!(parse_duration("1d2h3m4s"), Ok(Duration::from_secs(86400 + 7200 + 180 + 4)));
        assert_eq!(parse_duration(" 10M "), Ok(Duration::from_secs(600)), "units are case-insensitive");
    }

    #[test]
    fn bad_durations_are_refused() {
        for bad in ["", "   ", "0", "0s", "-5", "abc", "m", "5x", "1h30", "h1", "1..5h", "1e400", "99999999999999999999d"] {
            assert!(parse_duration(bad).is_err(), "{:?} should be refused", bad);
        }
    }
}
