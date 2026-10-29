//! Bounded in-memory history of engine events, for the read-scope `GET /v1/events` (ADR 0057).
//!
//! [`EventHistory`] is an [`EventSink`]: it stamps each event with a monotonic sequence number and a
//! wall-clock time and keeps the last [`DEFAULT_CAPACITY`] of them. `emit` runs under the engine
//! mutex, so it only takes a short-lived lock and never does I/O or allocates beyond the entry itself
//! (ADR 0021). Nothing is persisted: a restart starts a new history and sequence at 1.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::events::{Event, EventSink, Severity};

/// Entries kept. Small on purpose: this is a "what just happened" view, not a journal.
pub const DEFAULT_CAPACITY: usize = 256;

/// Events below this severity are not recorded: `Debug` bookkeeping (a redelivered webhook, a pruned
/// container) would evict the deploys and failures the history is for.
pub const DEFAULT_MIN_SEVERITY: Severity = Severity::Info;

/// One recorded event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEntry {
    /// Starts at 1, grows by one per emitted event, never reused within a process.
    pub seq: u64,
    pub at: SystemTime,
    pub event: Event,
}

/// What [`EventHistory::since`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recent {
    /// Retained entries with `seq` greater than the cursor, oldest first.
    pub entries: Vec<EventEntry>,
    /// `seq` of the oldest retained entry; `None` while the history is empty.
    pub oldest_seq: Option<u64>,
    /// Highest `seq` assigned so far (0 = nothing emitted yet): the cursor for the next call.
    pub latest_seq: u64,
    /// A cursor was given and events after it were evicted before they could be returned. Always
    /// `false` without a cursor: a first call has nothing to have missed.
    pub dropped: bool,
}

#[derive(Default)]
struct Inner {
    latest_seq: u64,
    entries: VecDeque<EventEntry>,
}

pub struct EventHistory {
    capacity: usize,
    min_severity: Severity,
    boot_id: String,
    inner: Mutex<Inner>,
}

impl Default for EventHistory {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl EventHistory {
    /// A history keeping at most `capacity` entries (at least 1).
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(capacity, DEFAULT_MIN_SEVERITY)
    }

    /// Keeps at most `capacity` entries (at least 1) of severity `min_severity` or higher.
    pub fn new(capacity: usize, min_severity: Severity) -> Self {
        let capacity = capacity.max(1);
        // Identifies this process: `seq` restarts at 1 with every daemon, and a client holding a cursor
        // from an earlier process must be able to tell. Not a secret, only needs to differ per start.
        static BOOTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let boots = BOOTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self {
            capacity,
            min_severity,
            boot_id: format!("{nanos:x}-{:x}-{boots:x}", std::process::id()),
            inner: Mutex::new(Inner {
                latest_seq: 0,
                entries: VecDeque::with_capacity(capacity),
            }),
        }
    }

    /// Differs between daemon processes (see [`EventHistory::new`]).
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // Never panic under the engine mutex: the data is a plain buffer, a poisoned lock is still valid.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Entries with `seq > after` (`None` = everything retained). An unknown or too-old cursor is not
    /// an error: what is retained comes back and `dropped` says whether anything was missed.
    pub fn since(&self, cursor: Option<u64>) -> Recent {
        let inner = self.lock();
        let after = cursor.unwrap_or(0);
        let oldest_seq = inner.entries.front().map(|e| e.seq);
        let dropped =
            cursor.is_some() && oldest_seq.is_some_and(|oldest| oldest > after.saturating_add(1));
        // Seqs are contiguous, so the first wanted entry sits at a computable index.
        let skip = oldest_seq.map_or(0, |oldest| after.saturating_add(1).saturating_sub(oldest));
        let skip = usize::try_from(skip).unwrap_or(usize::MAX);
        Recent {
            entries: inner.entries.iter().skip(skip).cloned().collect(),
            oldest_seq,
            latest_seq: inner.latest_seq,
            dropped,
        }
    }
}

impl EventSink for EventHistory {
    fn emit(&self, event: Event) {
        if event.severity() < self.min_severity {
            return;
        }
        let at = SystemTime::now();
        let mut inner = self.lock();
        inner.latest_seq += 1;
        if inner.entries.len() == self.capacity {
            inner.entries.pop_front();
        }
        let seq = inner.latest_seq;
        inner.entries.push_back(EventEntry { seq, at, event });
    }
}

/// Forwards every event to each of its sinks, in order. Lets the history sit next to whatever sink the
/// daemon already uses (notifier or `tracing`) without either knowing about the other.
pub struct FanOut(Vec<Arc<dyn EventSink>>);

impl FanOut {
    pub fn new(sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self(sinks)
    }
}

impl EventSink for FanOut {
    fn emit(&self, event: Event) {
        let Some((last, rest)) = self.0.split_last() else {
            return;
        };
        for sink in rest {
            sink.emit(event.clone());
        }
        last.emit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::VecSink;

    fn event(n: u32) -> Event {
        Event::Recreated {
            instance: crate::app::InstanceName::new("a").unwrap(),
            reason: format!("d{n}"),
        }
    }

    fn debug_event(n: u32) -> Event {
        Event::WebhookDuplicate {
            delivery_id: format!("d{n}"),
        }
    }

    fn seqs(recent: &Recent) -> Vec<u64> {
        recent.entries.iter().map(|e| e.seq).collect()
    }

    #[test]
    fn seq_is_monotonic_from_one() {
        let history = EventHistory::default();
        assert_eq!(history.since(None).latest_seq, 0);
        for n in 0..5 {
            history.emit(event(n));
        }
        let recent = history.since(None);
        assert_eq!(seqs(&recent), [1, 2, 3, 4, 5]);
        assert_eq!(recent.latest_seq, 5);
        assert!(!recent.dropped);
    }

    #[test]
    fn since_returns_only_newer_entries() {
        let history = EventHistory::default();
        for n in 0..5 {
            history.emit(event(n));
        }
        assert_eq!(seqs(&history.since(Some(3))), [4, 5]);
        assert!(history.since(Some(5)).entries.is_empty());
        // A cursor from the future (e.g. from before a daemon restart) yields nothing, not an error.
        let ahead = history.since(Some(99));
        assert!(ahead.entries.is_empty() && !ahead.dropped);
        assert_eq!(ahead.latest_seq, 5);
    }

    #[test]
    fn wrap_around_evicts_oldest_and_reports_drops() {
        let history = EventHistory::with_capacity(3);
        for n in 0..7 {
            history.emit(event(n));
        }
        let all = history.since(None);
        assert_eq!(seqs(&all), [5, 6, 7]);
        assert_eq!(all.oldest_seq, Some(5));
        assert!(!all.dropped, "no cursor: nothing to have missed");
        // Cursor exactly before the oldest: nothing missed.
        let edge = history.since(Some(4));
        assert_eq!(seqs(&edge), [5, 6, 7]);
        assert!(!edge.dropped);
        // Cursor too old: what is retained comes back, flagged.
        let old = history.since(Some(2));
        assert_eq!(seqs(&old), [5, 6, 7]);
        assert!(old.dropped);
        assert_eq!(seqs(&history.since(Some(6))), [7]);
    }

    #[test]
    fn debug_events_are_not_recorded_and_take_no_seq() {
        let history = EventHistory::with_capacity(2);
        history.emit(event(0));
        for n in 0..10 {
            history.emit(debug_event(n));
        }
        let recent = history.since(None);
        assert_eq!(seqs(&recent), [1]);
        assert_eq!(recent.latest_seq, 1);
    }

    #[test]
    fn boot_id_differs_per_history() {
        let (a, b) = (EventHistory::default(), EventHistory::default());
        assert!(!a.boot_id().is_empty());
        assert_ne!(a.boot_id(), b.boot_id());
    }

    #[test]
    fn zero_capacity_is_clamped() {
        let history = EventHistory::with_capacity(0);
        history.emit(event(1));
        history.emit(event(2));
        assert_eq!(seqs(&history.since(None)), [2]);
    }

    #[test]
    fn concurrent_emit_assigns_unique_contiguous_seqs() {
        let history = Arc::new(EventHistory::with_capacity(1000));
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let history = history.clone();
                std::thread::spawn(move || {
                    for n in 0..100 {
                        history.emit(event(t * 100 + n));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let recent = history.since(None);
        assert_eq!(recent.latest_seq, 800);
        assert_eq!(seqs(&recent), (1..=800).collect::<Vec<_>>());
    }

    #[test]
    fn fan_out_reaches_every_sink() {
        let history = Arc::new(EventHistory::default());
        let vec = Arc::new(VecSink::default());
        let fan = FanOut::new(vec![vec.clone(), history.clone()]);
        fan.emit(event(1));
        assert_eq!(vec.events(), [event(1)]);
        assert_eq!(history.since(None).entries[0].event, event(1));
        FanOut::new(Vec::new()).emit(event(2)); // no sinks: a no-op
    }
}
