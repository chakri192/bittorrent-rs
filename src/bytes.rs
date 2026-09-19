//! Bounds-checked fixed-width reads from buffers that came off the network.
//!
//! These return `None` rather than panicking when the buffer is too short,
//! so a truncated or hostile packet is an error the caller handles, not a
//! crash.

/// The `N` bytes starting at `at`, if the buffer has them.
fn array_at<const N: usize>(buf: &[u8], at: usize) -> Option<[u8; N]> {
    buf.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// A big-endian `u16` at `at`.
pub fn be_u16(buf: &[u8], at: usize) -> Option<u16> {
    array_at(buf, at).map(u16::from_be_bytes)
}

/// A big-endian `u32` at `at`.
pub fn be_u32(buf: &[u8], at: usize) -> Option<u32> {
    array_at(buf, at).map(u32::from_be_bytes)
}

/// A big-endian `u64` at `at`.
pub fn be_u64(buf: &[u8], at: usize) -> Option<u64> {
    array_at(buf, at).map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUF: [u8; 10] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];

    #[test]
    fn reads_are_big_endian_at_the_given_offset() {
        assert_eq!(be_u16(&BUF, 0), Some(0x0102));
        assert_eq!(be_u16(&BUF, 8), Some(0x090A));
        assert_eq!(be_u32(&BUF, 0), Some(0x0102_0304));
        assert_eq!(be_u32(&BUF, 6), Some(0x0708_090A));
        assert_eq!(be_u64(&BUF, 1), Some(0x0203_0405_0607_0809));
    }

    #[test]
    fn a_read_that_would_run_past_the_end_is_none_not_a_panic() {
        assert_eq!(be_u16(&BUF, 9), None);
        assert_eq!(be_u32(&BUF, 7), None);
        assert_eq!(be_u64(&BUF, 3), None);
        assert_eq!(be_u32(&[], 0), None);
    }

    #[test]
    fn an_offset_at_or_beyond_the_end_is_none() {
        assert_eq!(be_u16(&BUF, 10), None);
        assert_eq!(be_u32(&BUF, 100), None);
    }

    #[test]
    fn an_offset_that_overflows_when_the_width_is_added_is_none() {
        assert_eq!(be_u32(&BUF, usize::MAX), None);
        assert_eq!(be_u64(&BUF, usize::MAX - 3), None);
    }
}
