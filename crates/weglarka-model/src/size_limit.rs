//! One byte-size guard shared by every bounded state file.
//!
//! Each bounded state file (`managed-images.toml`, `image-reservations.toml`,
//! `platform-pins.toml`, `platform-transitions.toml`, `platform-update.toml`,
//! `host-capabilities.toml`) parses and serializes through the same limit check, so a writer can
//! never produce a file its own reader rejects. Every file keeps its own error type; this module
//! only centralizes the comparison.

/// A byte length over the limit a file allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimit {
    /// The byte length that was checked.
    pub size: usize,
    /// The largest accepted byte length.
    pub limit: usize,
}

/// Returns `Err(SizeLimit { size, limit })` when `size` exceeds `limit`.
///
/// Callers map the result into their own error type, adding the file name and any wording that is
/// specific to that file.
pub fn check(size: usize, limit: usize) -> Result<(), SizeLimit> {
    if size > limit {
        Err(SizeLimit { size, limit })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_rejects_only_sizes_over_the_limit() {
        assert_eq!(check(10, 10), Ok(()));
        assert_eq!(check(9, 10), Ok(()));
        assert_eq!(
            check(11, 10),
            Err(SizeLimit {
                size: 11,
                limit: 10
            })
        );
    }
}
