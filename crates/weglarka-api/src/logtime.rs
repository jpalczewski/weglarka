//! The RFC 3339 prefix libpod puts on every log *record* when `timestamps=true`.
//!
//! A record is one frame of libpod's multiplexed stream. A line longer than the runtime's record size
//! (about 8 KiB) is stored as several records, and every one of them is stamped, so a long line would
//! carry timestamps in its middle. The logs endpoint removes the stamp from a record that continues
//! a line ([`stamp_len`]), so a client sees exactly one stamp per line, at its start.

use std::time::Duration;

/// The longest timestamp prefix looked for (`2026-10-31T10:00:00.123456789+01:00` is 35 bytes).
pub const MAX_STAMP: usize = 40;

/// The length of the timestamp and the space after it at the start of `record`, if it starts with
/// one (`2026-10-31T10:00:00.5Z `); `None` when the first word is not an RFC 3339 time.
pub fn stamp_len(record: &[u8]) -> Option<usize> {
    let space = record.iter().take(MAX_STAMP + 1).position(|&b| b == b' ')?;
    parse_rfc3339(&record[..space]).map(|_| space + 1)
}

/// An RFC 3339 time (`2026-10-31T10:00:00.123456789+01:00`, the fraction optional, `Z` or a
/// `+hh:mm` offset) as a duration since the unix epoch; `None` for anything else, including times
/// before 1970. Sub-nanosecond digits are dropped.
pub fn parse_rfc3339(raw: &[u8]) -> Option<Duration> {
    fn num(b: &[u8]) -> Option<i64> {
        (!b.is_empty() && b.iter().all(u8::is_ascii_digit))
            .then(|| b.iter().fold(0, |n, d| n * 10 + i64::from(d - b'0')))
    }
    if raw.len() < 20 || raw[4] != b'-' || raw[7] != b'-' || raw[10] != b'T' {
        return None;
    }
    if raw[13] != b':' || raw[16] != b':' {
        return None;
    }
    let (year, month, day) = (num(&raw[0..4])?, num(&raw[5..7])?, num(&raw[8..10])?);
    let (hour, minute, second) = (num(&raw[11..13])?, num(&raw[14..16])?, num(&raw[17..19])?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut at = 19;
    let mut nanos = 0u32;
    if raw[at] == b'.' {
        let digits = raw[at + 1..]
            .iter()
            .take_while(|d| d.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        let kept = &raw[at + 1..at + 1 + digits.min(9)];
        nanos = u32::try_from(num(kept)?).ok()? * 10u32.pow(9 - kept.len() as u32);
        at += 1 + digits;
    }
    let offset = match raw.get(at..)? {
        b"Z" => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let (h, m) = (num(&[*h1, *h2])?, num(&[*m1, *m2])?);
            if h > 23 || m > 59 {
                return None;
            }
            let secs = h * 3600 + m * 60;
            if *sign == b'+' { secs } else { -secs }
        }
        _ => return None,
    };
    // Days since 1970-01-01 of a proleptic Gregorian date (Hinnant's `days_from_civil`).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second.min(59) - offset;
    Some(Duration::new(u64::try_from(secs).ok()?, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parsing() {
        let p = |s: &str| parse_rfc3339(s.as_bytes());
        assert_eq!(p("1970-01-01T00:00:00Z"), Some(Duration::ZERO));
        assert_eq!(
            p("2026-10-31T10:00:00.123456789012+01:00"),
            Some(Duration::new(1_793_437_200, 123_456_789))
        );
        assert_eq!(
            p("2024-02-29T00:00:00-02:30"),
            Some(Duration::from_secs(1_709_173_800))
        );
        for bad in [
            "",
            "x",
            "2026-10-31 10:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-10-31T24:00:00Z",
            "2026-10-31T10:00:00",
            "2026-10-31T10:00:00.Z",
            "1969-12-31T23:59:59Z",
            "2026-10-31T10:00:00+0100",
            "2026-10-31T10:00:00Zjunk",
        ] {
            assert_eq!(p(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_stamp_is_found_only_at_the_start_and_only_when_it_parses() {
        assert_eq!(stamp_len(b"2026-10-31T10:00:00.5Z rest"), Some(23));
        assert_eq!(stamp_len(b"2026-10-31T10:00:00Z "), Some(21));
        for no in [
            &b"plain text"[..],
            b"",
            b"2026-10-31T10:00:00Z",
            b" 2026-10-31T10:00:00Z x",
            b"2026-13-31T10:00:00Z x",
        ] {
            assert_eq!(stamp_len(no), None, "{no:?}");
        }
    }
}
