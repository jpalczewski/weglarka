//! The renewal policy: a pure function, so the table of cases is the specification.

use std::time::{Duration, SystemTime};

/// What to do with a certificate that exists on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Still comfortably valid.
    Wait,
    /// Inside the renewal window: order a new one; the current one is still served meanwhile.
    Renew,
    /// Already expired: order a new one (and report it louder).
    Expired,
}

/// Default renewal window: renew about 30 days before expiry (issue #96).
pub const DEFAULT_RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 3600);

pub fn decide(now: SystemTime, not_after: SystemTime, renew_before: Duration) -> Decision {
    match not_after.duration_since(now) {
        Err(_) => Decision::Expired,
        Ok(left) if left.is_zero() => Decision::Expired,
        Ok(left) if left <= renew_before => Decision::Renew,
        Ok(_) => Decision::Wait,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 3600);

    #[test]
    fn decision_table() {
        let now = SystemTime::UNIX_EPOCH + 1000 * DAY;
        let w = 30 * DAY;
        for (not_after, want) in [
            (now + 90 * DAY, Decision::Wait),
            (now + 30 * DAY + Duration::from_secs(1), Decision::Wait),
            (now + 30 * DAY, Decision::Renew),
            (now + DAY, Decision::Renew),
            (now, Decision::Expired),
            (now - DAY, Decision::Expired),
        ] {
            assert_eq!(
                decide(now, not_after, w),
                want,
                "{:?}",
                not_after.duration_since(now)
            );
        }
    }
}
