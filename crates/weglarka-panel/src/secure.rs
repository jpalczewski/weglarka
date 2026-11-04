//! Random values and comparisons for session ids and CSRF tokens, and the constant-time check of
//! the OIDC `state` (which `weglarka_oidc::begin_code_flow` generates).

use subtle::ConstantTimeEq;
use weglarka_oidc::random_b64url;

/// A 256-bit identifier or secret token.
pub fn random_token() -> String {
    random_b64url(32)
}

/// Equality that does not stop at the first differing byte (the length is not secret).
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_long_unique_and_url_safe() {
        let (a, b) = (random_token(), random_token());
        assert_eq!(a.len(), 43);
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }

    #[test]
    fn comparison() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }
}
