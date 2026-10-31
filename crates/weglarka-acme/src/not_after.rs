//! A small, non-verifying reader for the `notAfter` of the first certificate in a PEM chain.
//!
//! It walks `Certificate → TBSCertificate → validity → notAfter` in DER and nothing else. It does **not**
//! verify signatures, names or the chain: trust in the certificate comes from the ACME exchange, and the
//! result only schedules renewal. It is **fail closed**: anything it does not understand (bad PEM or
//! base64, a truncated or oversized length, indefinite lengths, an unexpected tag, an impossible date,
//! trailing bytes) is an [`AcmeError::Expiry`], never a guessed date, and the renewal logic treats an
//! unreadable certificate as one to replace.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::error::AcmeError;

const BEGIN: &str = "-----BEGIN ";
const END: &str = "-----END ";
const DASHES: &str = "-----";
const LABEL: &str = "CERTIFICATE";

const TAG_INTEGER: u8 = 0x02;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
/// `[0] EXPLICIT`, the optional `version` of a TBSCertificate.
const TAG_VERSION: u8 = 0xA0;

/// `notAfter` of the first certificate of `chain_pem` (the leaf), clamped to the Unix epoch when it is
/// earlier.
pub fn chain_not_after(chain_pem: &[u8]) -> Result<SystemTime, AcmeError> {
    let der = first_certificate(chain_pem)?;
    let secs = not_after_secs(&der)?;
    Ok(UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0)))
}

fn bad(why: &str) -> AcmeError {
    AcmeError::Expiry(why.to_owned())
}

/// DER of the first PEM block, which must be a `CERTIFICATE`.
fn first_certificate(pem: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let text = std::str::from_utf8(pem).map_err(|_| bad("the chain is not text"))?;
    let start = text.find(BEGIN).ok_or_else(|| bad("no PEM block"))?;
    let rest = &text[start + BEGIN.len()..];
    let (label, rest) = rest
        .split_once(DASHES)
        .ok_or_else(|| bad("malformed PEM header"))?;
    if label != LABEL {
        return Err(bad("the first PEM block is not a certificate"));
    }
    let end = rest
        .find(END)
        .ok_or_else(|| bad("the PEM block is not terminated"))?;
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(body)
        .map_err(|_| bad("the PEM body is not base64"))
}

/// One DER element: its tag, its content and what follows it.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
}

/// Reads one definite-length element with a single-byte tag; anything else is an error.
fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, AcmeError> {
    let (&tag, rest) = input.split_first().ok_or_else(|| bad("truncated DER"))?;
    if tag & 0x1f == 0x1f {
        return Err(bad("multi-byte DER tags are not supported"));
    }
    let (&first, rest) = rest.split_first().ok_or_else(|| bad("truncated DER"))?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 {
            return Err(bad("indefinite DER length"));
        }
        // Four length bytes (4 GiB) is far more than a certificate; refuse longer forms.
        if count > 4 || rest.len() < count {
            return Err(bad("invalid DER length"));
        }
        let (len_bytes, rest) = rest.split_at(count);
        let len = len_bytes
            .iter()
            .try_fold(0usize, |acc, &b| {
                acc.checked_mul(256)?.checked_add(usize::from(b))
            })
            .ok_or_else(|| bad("invalid DER length"))?;
        (len, rest)
    };
    if len > rest.len() {
        return Err(bad("DER length exceeds the data"));
    }
    let (content, rest) = rest.split_at(len);
    Ok(Tlv { tag, content, rest })
}

fn expect(input: &[u8], tag: u8) -> Result<Tlv<'_>, AcmeError> {
    let tlv = read_tlv(input)?;
    if tlv.tag == tag {
        Ok(tlv)
    } else {
        Err(bad("unexpected DER element"))
    }
}

/// Seconds since the Unix epoch of the `notAfter` of the DER certificate.
fn not_after_secs(der: &[u8]) -> Result<i64, AcmeError> {
    let cert = expect(der, TAG_SEQUENCE)?;
    if !cert.rest.is_empty() {
        return Err(bad("trailing data after the certificate"));
    }
    let signed = cert.content;
    let tbs = expect(signed, TAG_SEQUENCE)?;

    let mut fields = tbs.content;
    // version [0] is optional (absent in v1 certificates).
    if fields.first() == Some(&TAG_VERSION) {
        fields = read_tlv(fields)?.rest;
    }
    let serial = expect(fields, TAG_INTEGER)?;
    let signature = expect(serial.rest, TAG_SEQUENCE)?;
    let issuer = expect(signature.rest, TAG_SEQUENCE)?;
    let validity = expect(issuer.rest, TAG_SEQUENCE)?;

    let not_before = read_tlv(validity.content)?;
    let not_after = read_tlv(not_before.rest)?;
    if !not_after.rest.is_empty() {
        return Err(bad("unexpected data in the validity"));
    }
    parse_time(not_after.tag, not_after.content)
}

/// `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) in UTC, as RFC 5280 requires.
fn parse_time(tag: u8, text: &[u8]) -> Result<i64, AcmeError> {
    let (year, rest) = match tag {
        TAG_UTC_TIME if text.len() == 13 => {
            let yy = digits(&text[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        TAG_GENERALIZED_TIME if text.len() == 15 => (digits(&text[..4])?, &text[4..]),
        _ => return Err(bad("unsupported time encoding")),
    };
    let [month, day, hour, minute, second] = [0, 2, 4, 6, 8].map(|i| digits(&rest[i..i + 2]));
    let (month, day, hour, minute, second) = (month?, day?, hour?, minute?, second?);
    if rest[10] != b'Z' {
        return Err(bad("the time is not in UTC"));
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(bad("invalid month")),
    };
    if day < 1 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return Err(bad("invalid date"));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Exactly the decimal digits of `text`.
fn digits(text: &[u8]) -> Result<i64, AcmeError> {
    text.iter().try_fold(0i64, |acc, &b| match b {
        b'0'..=b'9' => Ok(acc * 10 + i64::from(b - b'0')),
        _ => Err(bad("non-digit in the time")),
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generalized time (year 2126), `openssl x509 -enddate`: Oct  1 07:51:01 2126 GMT.
    const LEAF: &[u8] = include_bytes!("../tests/fixtures/leaf.crt");
    /// UTCTime: `openssl x509 -enddate`: Dec 31 23:59:59 2030 GMT.
    const UTC_LEAF: &[u8] = include_bytes!("../tests/fixtures/leaf-utctime.crt");

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn der_of(pem: &[u8]) -> Vec<u8> {
        first_certificate(pem).unwrap()
    }

    fn pem_of(der: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(der)
        )
        .into_bytes()
    }

    /// DER element with a definite length.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n if n < 0x80 => out.push(u8::try_from(n).unwrap()),
            n => {
                out.push(0x82);
                out.extend(u16::try_from(n).unwrap().to_be_bytes());
            }
        }
        out.extend_from_slice(content);
        out
    }

    /// A minimal certificate skeleton with the given `notAfter` element.
    fn cert_with_not_after(not_after: &[u8]) -> Vec<u8> {
        let validity = tlv(
            TAG_SEQUENCE,
            &[tlv(TAG_UTC_TIME, b"260101000000Z"), not_after.to_vec()].concat(),
        );
        let tbs = tlv(
            TAG_SEQUENCE,
            &[
                tlv(TAG_VERSION, &tlv(TAG_INTEGER, &[2])),
                tlv(TAG_INTEGER, &[1]),
                tlv(TAG_SEQUENCE, &[]),
                tlv(TAG_SEQUENCE, &[]),
                validity,
                tlv(TAG_SEQUENCE, &[]),
            ]
            .concat(),
        );
        tlv(TAG_SEQUENCE, &tbs)
    }

    fn secs_of(not_after: &[u8]) -> Result<SystemTime, AcmeError> {
        chain_not_after(&pem_of(&cert_with_not_after(not_after)))
    }

    #[test]
    fn generalized_time_of_a_real_certificate() {
        assert_eq!(chain_not_after(LEAF).unwrap(), at(4_946_514_661));
    }

    #[test]
    fn utc_time_of_a_real_certificate() {
        assert_eq!(chain_not_after(UTC_LEAF).unwrap(), at(1_924_991_999));
    }

    #[test]
    fn only_the_first_certificate_of_a_chain_counts() {
        let chain = [UTC_LEAF, LEAF].concat();
        assert_eq!(chain_not_after(&chain).unwrap(), at(1_924_991_999));
        let swapped = [LEAF, UTC_LEAF].concat();
        assert_eq!(chain_not_after(&swapped).unwrap(), at(4_946_514_661));
    }

    #[test]
    fn utc_time_pivots_at_1950() {
        let after = |t: &[u8]| secs_of(&tlv(TAG_UTC_TIME, t)).unwrap();
        assert_eq!(after(b"491231235959Z"), at(2_524_607_999)); // 2049-12-31
        assert_eq!(after(b"500101000000Z"), UNIX_EPOCH); // 1950 is before the epoch
    }

    #[test]
    fn generalized_time_leap_day_and_epoch_clamp() {
        let general = |t: &[u8]| secs_of(&tlv(TAG_GENERALIZED_TIME, t)).unwrap();
        assert_eq!(general(b"20240229120000Z"), at(1_709_208_000));
        assert_eq!(general(b"19700101000000Z"), UNIX_EPOCH);
        assert_eq!(general(b"19691231235959Z"), UNIX_EPOCH);
    }

    #[test]
    fn impossible_dates_are_refused() {
        for text in [
            &b"20230229120000Z"[..], // not a leap year
            b"20241301120000Z",
            b"20240001120000Z",
            b"20240132120000Z",
            b"20240101240000Z",
            b"20240101126000Z",
            b"20240101120060Z", // leap second is not allowed in RFC 5280
            b"2024010112000aZ",
            b"20240101120000+",
            b"2024010112000Z",   // too short
            b"202401011200000Z", // too long
        ] {
            assert!(
                matches!(
                    secs_of(&tlv(TAG_GENERALIZED_TIME, text)),
                    Err(AcmeError::Expiry(_))
                ),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
        // UTCTime must not carry four-digit years and GeneralizedTime must not carry two.
        assert!(secs_of(&tlv(TAG_UTC_TIME, b"20300101000000Z")).is_err());
        assert!(secs_of(&tlv(TAG_GENERALIZED_TIME, b"300101000000Z")).is_err());
        // A time with an offset or without a zone is refused.
        assert!(secs_of(&tlv(TAG_UTC_TIME, b"3001010000+0100")).is_err());
        // Not a time at all.
        assert!(secs_of(&tlv(0x04, b"300101000000Z")).is_err());
    }

    #[test]
    fn every_truncation_of_a_real_certificate_is_an_error() {
        let der = der_of(LEAF);
        for cut in 0..der.len() {
            assert!(
                matches!(
                    chain_not_after(&pem_of(&der[..cut])),
                    Err(AcmeError::Expiry(_))
                ),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn corrupted_headers_are_errors_and_never_a_panic() {
        let der = der_of(UTC_LEAF);
        // Flip every byte of the first 120 (the structure up to the validity) and of the whole file
        // by a few patterns: the reader must either error or return a time, never panic.
        for i in 0..der.len() {
            for byte in [0x00, 0xff, 0x80, 0x1f] {
                let mut copy = der.clone();
                copy[i] = byte;
                let _ = chain_not_after(&pem_of(&copy));
            }
        }
    }

    #[test]
    fn malformed_der_is_an_error() {
        let valid = cert_with_not_after(&tlv(TAG_UTC_TIME, b"300101000000Z"));
        assert!(chain_not_after(&pem_of(&valid)).is_ok());

        let mut trailing = valid.clone();
        trailing.push(0);
        let indefinite = [&[TAG_SEQUENCE, 0x80][..], &valid[2..], &[0, 0]].concat();
        let huge_length = [TAG_SEQUENCE, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00];
        let overflow = [TAG_SEQUENCE, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let long_tag = [0x1f, 0x81, 0x00, 0x00];
        let wrong_outer = tlv(TAG_INTEGER, &[1]);
        let empty_seq = tlv(TAG_SEQUENCE, &[]);
        for (name, der) in [
            ("trailing byte", trailing),
            ("indefinite length", indefinite),
            ("length beyond the data", huge_length.to_vec()),
            ("length overflow", overflow.to_vec()),
            ("multi-byte tag", long_tag.to_vec()),
            ("outer element is not a sequence", wrong_outer),
            ("empty sequence", empty_seq),
            ("empty input", vec![]),
        ] {
            assert!(
                matches!(chain_not_after(&pem_of(&der)), Err(AcmeError::Expiry(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn broken_pem_is_an_error() {
        let body = STANDARD.encode(der_of(UTC_LEAF));
        for (name, pem) in [
            ("empty", String::new()),
            ("plain text", "not a pem".to_owned()),
            (
                "not utf-8",
                String::from_utf8_lossy(&[0xff, 0xfe]).into_owned(),
            ),
            (
                "unterminated",
                format!("-----BEGIN CERTIFICATE-----\n{body}\n"),
            ),
            (
                "wrong label",
                format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            ),
            (
                "bad base64",
                "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n".to_owned(),
            ),
            ("no header terminator", "-----BEGIN CERTIFICATE".to_owned()),
        ] {
            assert!(
                matches!(chain_not_after(pem.as_bytes()), Err(AcmeError::Expiry(_))),
                "{name}"
            );
        }
        assert!(matches!(
            chain_not_after(&[0xff, 0xfe]),
            Err(AcmeError::Expiry(_))
        ));
    }
}
