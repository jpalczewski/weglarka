//! Random values and comparisons for session ids, CSRF tokens and OIDC `state`/`nonce`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

/// `bytes` random bytes from the OS, base64url without padding. The system generator failing means
/// the host cannot give out randomness at all; nothing safe can continue, so this panics.
pub fn random_b64url(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut buf)
        .expect("the operating system cannot provide random bytes");
    URL_SAFE_NO_PAD.encode(buf)
}

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
