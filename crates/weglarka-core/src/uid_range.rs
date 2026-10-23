//! Per-instance uid/gid range allocation (path (a) of docs/decisions/0009).
//!
//! Offsets are in the namespace the rootless Podman user runs in: 0 is the user itself and
//! `1..=pool_size` are its subuids in order, so the same code serves a CI runner (65536 subuids) and
//! the production host (2000000). The allocator is pure; reading the pool size from `/etc/subuid` and
//! persisting the result in `state.toml` (`AppState::uid_range`) belong to session 1.

use serde::{Deserialize, Serialize};

/// Default size of an instance's range: a full 16-bit uid space, so images using any uid up to 65535
/// work.
pub const DEFAULT_RANGE_SIZE: u32 = 65_536;

/// Range of `size` subuid offsets starting at `start` (>= 1). Used for both uid and gid maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UidRange {
    pub start: u32,
    pub size: u32,
}

impl UidRange {
    fn end(self) -> u64 {
        u64::from(self.start) + u64::from(self.size)
    }

    pub fn overlaps(self, other: Self) -> bool {
        u64::from(self.start) < other.end() && u64::from(other.start) < self.end()
    }
}

/// First-fit allocation of `size` offsets out of `1..=pool_size`, avoiding `used`. `None` if the pool
/// is exhausted (or `size` is 0). Deterministic: the lowest free gap wins, so freed ranges are reused.
pub fn allocate(used: &[UidRange], pool_size: u64, size: u32) -> Option<UidRange> {
    if size == 0 {
        return None;
    }
    let mut sorted: Vec<UidRange> = used.to_vec();
    sorted.sort_by_key(|r| r.start);
    let mut candidate: u64 = 1;
    for r in sorted {
        if candidate + u64::from(size) <= u64::from(r.start) {
            break;
        }
        candidate = candidate.max(r.end());
    }
    let end = candidate + u64::from(size);
    // `pool_size` offsets are valid: 1..=pool_size, i.e. the exclusive end is at most pool_size + 1.
    if end > pool_size + 1 {
        return None;
    }
    Some(UidRange {
        start: u32::try_from(candidate).ok()?,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(start: u32, size: u32) -> UidRange {
        UidRange { start, size }
    }

    #[test]
    fn first_instance_starts_at_one() {
        assert_eq!(allocate(&[], 65_536, 1000), Some(r(1, 1000)));
    }

    #[test]
    fn ranges_never_overlap() {
        let mut used = Vec::new();
        for _ in 0..4 {
            let next = allocate(&used, 4_000, 1000).unwrap();
            assert!(used.iter().all(|u: &UidRange| !u.overlaps(next)));
            used.push(next);
        }
        assert_eq!(
            used,
            [r(1, 1000), r(1001, 1000), r(2001, 1000), r(3001, 1000)]
        );
        assert_eq!(allocate(&used, 4_000, 1000), None, "pool exhausted");
    }

    #[test]
    fn freed_gap_is_reused_first_fit() {
        let used = [r(1, 1000), r(2001, 1000)];
        assert_eq!(allocate(&used, 10_000, 1000), Some(r(1001, 1000)));
        // Does not fit into the gap → goes after the last range.
        assert_eq!(allocate(&used, 10_000, 1500), Some(r(3001, 1500)));
    }

    #[test]
    fn order_of_used_is_irrelevant() {
        assert_eq!(
            allocate(&[r(1001, 1000), r(1, 1000)], 10_000, 10),
            Some(r(2001, 10))
        );
    }

    #[test]
    fn edges() {
        assert_eq!(allocate(&[], 100, 100), Some(r(1, 100)));
        assert_eq!(allocate(&[], 99, 100), None);
        assert_eq!(allocate(&[], 100, 0), None);
        assert_eq!(allocate(&[], 0, 1), None);
    }
}
