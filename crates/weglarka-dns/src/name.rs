//! Syntax checks for the strings that end up in a DNS API request.

/// Longest TXT string a single DNS character-string can carry.
const MAX_TXT: usize = 255;

/// A lower-case FQDN without a trailing dot: labels of `[a-z0-9_-]` (the underscore is what
/// `_acme-challenge` needs), 1–63 bytes each, 253 bytes in total, at least two labels. Rejecting
/// everything else keeps request paths and query strings free of injected characters.
pub fn valid_record_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let mut labels = 0;
    for label in name.split('.') {
        labels += 1;
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        if !ok {
            return false;
        }
    }
    labels >= 2
}

/// A TXT value that is safe to send verbatim: printable ASCII without quotes or backslashes,
/// 1–255 bytes. ACME DNS-01 values are 43 characters of unpadded base64url, well inside this.
pub fn valid_txt_value(value: &str) -> bool {
    (1..=MAX_TXT).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_names_are_plain_lowercase_fqdns() {
        assert!(valid_record_name("_acme-challenge.example.eu"));
        assert!(valid_record_name("a.b.example.co.uk"));
        for bad in [
            "",
            "example",
            ".example.eu",
            "example.eu.",
            "Example.eu",
            "a..eu",
            "a b.eu",
            "a/b.eu",
            "a?x=1.eu",
            "ex\u{e4}mple.eu",
            "*.example.eu",
        ] {
            assert!(!valid_record_name(bad), "{bad:?}");
        }
        assert!(!valid_record_name(&format!("{}.eu", "a".repeat(64))));
        assert!(!valid_record_name(&format!("{}.eu", "a.".repeat(130))));
    }

    #[test]
    fn txt_values_are_bounded_printable_ascii() {
        assert!(valid_txt_value(
            "gfj9Xq-Ae1w0lBsJ4M2zQ8Yh7N3uKdR5vTpCoEiLxHk"
        ));
        assert!(!valid_txt_value(""));
        assert!(!valid_txt_value("has space"));
        assert!(!valid_txt_value("quo\"te"));
        assert!(!valid_txt_value("back\\slash"));
        assert!(!valid_txt_value(&"a".repeat(256)));
        assert!(valid_txt_value(&"a".repeat(255)));
    }
}
