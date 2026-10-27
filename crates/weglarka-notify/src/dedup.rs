//! Flapping suppression: per-key windows.
//!
//! An event opens a window for its dedup key; further events of that key inside the window are
//! counted instead of delivered, and one summary is delivered when the window closes. Windows live in
//! memory only — the outbox, not the window, is the durable part (a daemon restart forgets them and
//! the next event starts a fresh window).

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::message::{self, Message};

#[derive(Debug, Clone)]
struct Window {
    opened: SystemTime,
    first: Message,
    last: Message,
    /// Events of this key suppressed since the window opened.
    suppressed: u32,
}

impl Window {
    fn new(at: SystemTime, message: &Message) -> Self {
        Self {
            opened: at,
            first: message.clone(),
            last: message.clone(),
            suppressed: 0,
        }
    }

    fn expired(&self, now: SystemTime, window: Duration) -> bool {
        now.duration_since(self.opened).unwrap_or_default() >= window
    }

    /// The summary of a window that is closing with suppressed events; `None` when nothing was
    /// suppressed (a single event needs no summary).
    fn summary(&self, window: Duration) -> Option<Message> {
        (self.suppressed > 0)
            .then(|| message::summary(&self.first, &self.last, self.suppressed, window))
    }
}

/// What to enqueue for one event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admission {
    /// Summary of a window of the same key that expired just now — enqueue this first.
    pub summary: Option<Message>,
    /// The event's own notification; `None` when the event was suppressed inside an open window.
    pub message: Option<Message>,
}

/// Open windows, keyed by [`Message::key`].
#[derive(Debug)]
pub struct Windows {
    window: Duration,
    open: HashMap<String, Window>,
}

impl Windows {
    /// `window` of zero disables deduplication: every event is admitted as it is.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            open: HashMap::new(),
        }
    }

    pub fn admit(&mut self, message: Message, now: SystemTime) -> Admission {
        if self.window.is_zero() {
            return Admission {
                summary: None,
                message: Some(message),
            };
        }
        match self.open.remove(&message.key) {
            None => {
                self.open
                    .insert(message.key.clone(), Window::new(now, &message));
                Admission {
                    summary: None,
                    message: Some(message),
                }
            }
            Some(open) if open.expired(now, self.window) => {
                let summary = open.summary(self.window);
                self.open
                    .insert(message.key.clone(), Window::new(now, &message));
                Admission {
                    summary,
                    message: Some(message),
                }
            }
            Some(mut open) => {
                open.suppressed += 1;
                open.last = message;
                self.open.insert(open.last.key.clone(), open);
                Admission::default()
            }
        }
    }

    /// Closes the windows that expired, returning their summaries (windows without suppressed
    /// events are closed silently).
    pub fn flush(&mut self, now: SystemTime) -> Vec<Message> {
        let window = self.window;
        let mut summaries = Vec::new();
        self.open.retain(|_, open| {
            if !open.expired(now, window) {
                return true;
            }
            summaries.extend(open.summary(window));
            false
        });
        summaries
    }

    /// Number of open windows (for tests and `notify status`).
    pub fn open(&self) -> usize {
        self.open.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_model::events::Severity;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn message(key: &str, severity: Severity, title: &str) -> Message {
        Message {
            severity,
            key: key.to_owned(),
            title: title.to_owned(),
            body: String::new(),
            priority: 3,
            tags: vec![],
            click: None,
        }
    }

    #[test]
    fn first_event_is_admitted_and_the_rest_are_suppressed() {
        let mut windows = Windows::new(Duration::from_secs(300));
        let first = windows.admit(message("k", Severity::Warning, "one"), at(0));
        assert_eq!(first.message.unwrap().title, "one");
        assert_eq!(first.summary, None);
        for second in 1..4 {
            let admission = windows.admit(message("k", Severity::Warning, "again"), at(second));
            assert_eq!(admission, Admission::default());
        }
        assert_eq!(windows.open(), 1);
    }

    #[test]
    fn a_window_expiry_emits_one_summary_then_admits_the_new_event() {
        let mut windows = Windows::new(Duration::from_secs(300));
        windows.admit(message("k", Severity::Warning, "first"), at(0));
        windows.admit(message("k", Severity::Warning, "second"), at(10));
        windows.admit(message("k", Severity::Critical, "third"), at(20));
        let admission = windows.admit(message("k", Severity::Warning, "fourth"), at(301));
        let summary = admission.summary.expect("summary of the closed window");
        assert_eq!(summary.title, "2 more: third");
        // The critical event inside the window escalates the summary.
        assert_eq!(summary.severity, Severity::Critical);
        assert_eq!(admission.message.unwrap().title, "fourth");
    }

    #[test]
    fn flush_closes_only_expired_windows_and_skips_summaries_without_suppression() {
        let mut windows = Windows::new(Duration::from_secs(60));
        windows.admit(message("a", Severity::Info, "a1"), at(0));
        windows.admit(message("a", Severity::Info, "a2"), at(1));
        windows.admit(message("b", Severity::Info, "b1"), at(0));
        assert_eq!(windows.open(), 2);
        let summaries = windows.flush(at(61));
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].key, "a");
        assert_eq!(windows.open(), 0);
    }

    #[test]
    fn a_zero_window_disables_deduplication() {
        let mut windows = Windows::new(Duration::ZERO);
        for _ in 0..3 {
            let admission = windows.admit(message("k", Severity::Warning, "x"), at(0));
            assert!(admission.message.is_some());
            assert_eq!(admission.summary, None);
        }
        assert_eq!(windows.open(), 0);
        assert!(windows.flush(at(10_000)).is_empty());
    }

    #[test]
    fn different_keys_do_not_interfere() {
        let mut windows = Windows::new(Duration::from_secs(60));
        assert!(
            windows
                .admit(message("a", Severity::Info, "a"), at(0))
                .message
                .is_some()
        );
        assert!(
            windows
                .admit(message("b", Severity::Info, "b"), at(0))
                .message
                .is_some()
        );
        assert_eq!(windows.open(), 2);
    }
}
