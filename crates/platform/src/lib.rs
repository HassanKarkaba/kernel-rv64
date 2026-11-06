#![no_std]
#![forbid(unsafe_code)]

pub mod dtb;
pub mod virtqueue;

/// Widen before multiplication; positive deadlines always round upwards.
pub fn ticks_for_ms(ms: u64, frequency: u64) -> Option<u64> {
    if frequency == 0 {
        return None;
    }
    u64::try_from((u128::from(ms) * u128::from(frequency)).div_ceil(1000)).ok()
}

pub fn nanoseconds(ticks: u64, frequency: u64) -> Option<u64> {
    if frequency == 0 {
        return None;
    }
    Some(((u128::from(ticks) * 1_000_000_000 / u128::from(frequency)).min(i64::MAX as u128)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_conversions_do_not_round_sleep_down_or_overflow() {
        assert_eq!(ticks_for_ms(1, 32768), Some(33));
        assert_eq!(ticks_for_ms(60000, 10_000_000), Some(600_000_000));
        assert_eq!(ticks_for_ms(u64::MAX, u64::MAX), None);
        assert_eq!(nanoseconds(u64::MAX, 1), Some(i64::MAX as u64));
        assert_eq!(nanoseconds(1, 0), None);
    }
}
