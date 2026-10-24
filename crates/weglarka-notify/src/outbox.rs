//! Durable queue of notifications that have not been delivered yet.
//!
//! The file is written with an atomic replace (`weglarka_core::state::write_atomic`, mode 0600) after
//! every mutation, so a notification that was accepted stays pending across a daemon restart — this is
//! what makes "ntfy is being redeployed by Węglarka itself" harmless.
//!
//! The format is deliberately **tolerant** (unlike our own TOML files, which use `deny_unknown_fields`):
//! this is internal transient state, and a field added by a newer daemon must not stop an older one from
//! starting. Timestamps are unix seconds — scheduling only; `notify status` renders them as RFC 3339.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use weglarka_core::events::Severity;

use crate::message::Message;

/// Cap on queued notifications; the oldest is dropped first (and counted in `dropped`).
pub const MAX_PENDING: usize = 200;
/// A notification older than this is dropped (a week-old "deploy failed" is not useful).
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Attempts before a retryable notification is given up on (≈3.5 h with [`backoff`]).
pub const MAX_ATTEMPTS: u32 = 12;

const BASE_DELAY: Duration = Duration::from_secs(30);
const MAX_DELAY: Duration = Duration::from_secs(30 * 60);
/// Pending notifications can name apps and reasons; keep the file owner-only.
const FILE_MODE: u32 = 0o600;

fn secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn time(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Delay before retrying after the `attempts`-th failure: 30 s, 1 min, 2 min … capped at 30 min.
pub fn backoff(attempts: u32) -> Duration {
    let factor = 1u32
        .checked_shl(attempts.saturating_sub(1))
        .unwrap_or(u32::MAX);
    BASE_DELAY.saturating_mul(factor).min(MAX_DELAY)
}

/// One queued notification: the rendered message (rendered at enqueue time, so an upgrade or a config
/// change never rewrites queued history) plus its delivery bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Pending {
    pub id: u64,
    /// [`Channel::name`](crate::Channel::name) of the channel that must deliver it.
    pub channel: String,
    pub severity: Severity,
    /// Dedup key of the event that produced it.
    pub key: String,
    pub title: String,
    pub body: String,
    pub priority: u8,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub click: Option<String>,
    /// Unix seconds.
    pub created: u64,
    pub attempts: u32,
    /// Unix seconds.
    pub next_attempt: u64,
}

impl Default for Pending {
    fn default() -> Self {
        Self {
            id: 0,
            channel: String::new(),
            severity: Severity::Info,
            key: String::new(),
            title: String::new(),
            body: String::new(),
            priority: 3,
            tags: Vec::new(),
            click: None,
            created: 0,
            attempts: 0,
            next_attempt: 0,
        }
    }
}

impl Pending {
    pub fn message(&self) -> Message {
        Message {
            severity: self.severity,
            key: self.key.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
            priority: self.priority,
            tags: self.tags.clone(),
            click: self.click.clone(),
        }
    }

    /// RFC 3339 of the enqueue time (for `notify status`).
    pub fn created_at(&self) -> String {
        weglarka_core::secrets::rfc3339_utc(time(self.created))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct File {
    next_id: u64,
    dropped: u64,
    pending: Vec<Pending>,
}

#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot serialize the outbox: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// The pending queue of one daemon. Single writer: the notification worker.
#[derive(Debug)]
pub struct Outbox {
    path: PathBuf,
    next_id: u64,
    dropped: u64,
    pending: Vec<Pending>,
}

impl Outbox {
    /// Loads the outbox. A missing file is an empty queue; a corrupt one is renamed next to itself
    /// (`<path>.corrupt-<unix>`) and the queue starts empty — notifications are not worth refusing to
    /// start the daemon for.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let file = match fs::read_to_string(&path) {
            Ok(src) => match toml::from_str::<File>(&src) {
                Ok(file) => file,
                Err(e) => {
                    let aside = path.with_extension(format!("corrupt-{}", secs(SystemTime::now())));
                    tracing::error!(
                        path = %path.display(),
                        error = %e,
                        aside = %aside.display(),
                        "corrupt notification outbox; starting empty"
                    );
                    let _ = fs::rename(&path, &aside);
                    File::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "cannot read the notification outbox; starting empty");
                File::default()
            }
        };
        Self {
            path,
            next_id: file.next_id,
            dropped: file.dropped,
            pending: file.pending,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pending(&self) -> &[Pending] {
        &self.pending
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Notifications dropped since the daemon was first started with this file (overflow, age,
    /// permanent errors, exhausted attempts).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Pending notifications per channel.
    pub fn per_channel(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for item in &self.pending {
            *counts.entry(item.channel.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Enqueue `message` for `channel`; returns the notification id. Persists the file.
    pub fn push(
        &mut self,
        channel: &str,
        message: &Message,
        now: SystemTime,
    ) -> Result<u64, OutboxError> {
        let id = self.next_id;
        self.next_id += 1;
        if self.pending.len() >= MAX_PENDING
            && let Some(oldest) = self
                .pending
                .iter()
                .enumerate()
                .min_by_key(|(_, item)| (item.id, item.created))
                .map(|(index, _)| index)
        {
            let dropped = self.pending.remove(oldest);
            self.dropped += 1;
            tracing::warn!(id = dropped.id, channel = %dropped.channel, "notification outbox full; dropped the oldest notification");
        }
        self.pending.push(Pending {
            id,
            channel: channel.to_owned(),
            severity: message.severity,
            key: message.key.clone(),
            title: message.title.clone(),
            body: message.body.clone(),
            priority: message.priority,
            tags: message.tags.clone(),
            click: message.click.clone(),
            created: secs(now),
            attempts: 0,
            next_attempt: secs(now),
        });
        self.save()?;
        Ok(id)
    }

    /// The next notification that may be attempted at `now`: among the due ones, the oldest first
    /// (a retry that is not due yet does not block fresher notifications).
    pub fn due(&self, now: SystemTime) -> Option<Pending> {
        let now = secs(now);
        self.pending
            .iter()
            .filter(|item| item.next_attempt <= now)
            .min_by_key(|item| item.id)
            .cloned()
    }

    /// When the next retry is due (for the worker's wake-up timer).
    pub fn next_attempt(&self) -> Option<SystemTime> {
        self.pending
            .iter()
            .map(|item| item.next_attempt)
            .min()
            .map(time)
    }

    /// Records a failed attempt. A permanent error or [`MAX_ATTEMPTS`] drops the notification;
    /// otherwise the retry is scheduled with [`backoff`]. Returns the dropped item, if any.
    pub fn fail(
        &mut self,
        id: u64,
        now: SystemTime,
        permanent: bool,
    ) -> Result<Option<Pending>, OutboxError> {
        let Some(index) = self.pending.iter().position(|item| item.id == id) else {
            return Ok(None);
        };
        self.pending[index].attempts += 1;
        let attempts = self.pending[index].attempts;
        if permanent || attempts >= MAX_ATTEMPTS {
            let dropped = self.pending.remove(index);
            self.dropped += 1;
            self.save()?;
            return Ok(Some(dropped));
        }
        let delay = backoff(attempts);
        self.pending[index].next_attempt = secs(now) + delay.as_secs();
        self.save()?;
        Ok(None)
    }

    /// Removes a delivered notification. Returns it (for `last_delivered` bookkeeping).
    pub fn delivered(&mut self, id: u64) -> Result<Option<Pending>, OutboxError> {
        let Some(index) = self.pending.iter().position(|item| item.id == id) else {
            return Ok(None);
        };
        let delivered = self.pending.remove(index);
        self.save()?;
        Ok(Some(delivered))
    }

    /// Removes a notification whose channel is no longer configured (it can never be delivered).
    pub fn forget(&mut self, id: u64) -> Result<Option<Pending>, OutboxError> {
        let Some(index) = self.pending.iter().position(|item| item.id == id) else {
            return Ok(None);
        };
        let dropped = self.pending.remove(index);
        self.dropped += 1;
        self.save()?;
        Ok(Some(dropped))
    }

    /// Drops notifications older than [`MAX_AGE`]; returns how many were removed.
    pub fn prune(&mut self, now: SystemTime) -> Result<usize, OutboxError> {
        let now = secs(now);
        let max_age = MAX_AGE.as_secs();
        let before = self.pending.len();
        self.pending
            .retain(|item| now.saturating_sub(item.created) < max_age);
        let removed = before - self.pending.len();
        if removed > 0 {
            self.dropped += removed as u64;
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> Result<(), OutboxError> {
        let file = File {
            next_id: self.next_id,
            dropped: self.dropped,
            pending: self.pending.clone(),
        };
        let bytes = toml::to_string_pretty(&file)?;
        weglarka_core::state::write_atomic(&self.path, bytes.as_bytes(), FILE_MODE).map_err(
            |source| OutboxError::Write {
                path: self.path.clone(),
                source,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(title: &str) -> Message {
        Message {
            severity: Severity::Warning,
            key: "deploy-failed:ntfy".into(),
            title: title.into(),
            body: "health gate failed".into(),
            priority: 4,
            tags: vec!["warning".into()],
            click: Some("https://nz.example.com".into()),
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn enqueue_persist_and_deliver_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.toml");
        let mut outbox = Outbox::load(&path);
        assert!(outbox.is_empty());

        let id = outbox.push("ntfy", &message("one"), at(1_000)).unwrap();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox.due(at(1_000)).unwrap().id, id);
        assert!(outbox.due(at(999)).is_none());

        let reloaded = Outbox::load(&path);
        assert_eq!(reloaded.len(), 1);
        let item = &reloaded.pending()[0];
        assert_eq!(item.channel, "ntfy");
        assert_eq!(item.severity, Severity::Warning);
        assert_eq!(item.title, "one");
        assert_eq!(item.created_at(), "1970-01-01T00:16:40Z");
        assert_eq!(item.click.as_deref(), Some("https://nz.example.com"));

        let mut outbox = reloaded;
        let delivered = outbox.delivered(id).unwrap().unwrap();
        assert_eq!(delivered.title, "one");
        assert!(outbox.is_empty());
        assert!(Outbox::load(&path).is_empty());
    }

    #[test]
    fn fifo_order_and_backoff_retries() {
        let dir = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::load(dir.path().join("notifications.toml"));
        let first = outbox.push("ntfy", &message("first"), at(0)).unwrap();
        let second = outbox.push("ntfy", &message("second"), at(0)).unwrap();
        assert_eq!(outbox.due(at(0)).unwrap().id, first);

        // A retryable failure schedules the retry and leaves the item pending.
        assert_eq!(outbox.fail(first, at(0), false).unwrap(), None);
        assert_eq!(outbox.pending()[0].attempts, 1);
        assert_eq!(outbox.pending()[0].next_attempt, 30);
        assert_eq!(outbox.due(at(0)).unwrap().id, second);
        assert_eq!(outbox.due(at(30)).unwrap().id, first);

        // A permanent failure drops it and counts it.
        let dropped = outbox.fail(second, at(30), true).unwrap().unwrap();
        assert_eq!(dropped.id, second);
        assert_eq!(outbox.dropped(), 1);
        assert_eq!(outbox.len(), 1);
    }

    #[test]
    fn retries_are_given_up_after_max_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::load(dir.path().join("notifications.toml"));
        let id = outbox.push("ntfy", &message("one"), at(0)).unwrap();
        for _ in 0..MAX_ATTEMPTS {
            outbox.fail(id, at(0), false).unwrap();
        }
        assert!(outbox.is_empty(), "dropped after {MAX_ATTEMPTS} attempts");
        assert_eq!(outbox.dropped(), 1);
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(3), Duration::from_secs(120));
        assert_eq!(backoff(20), MAX_DELAY);
        assert_eq!(backoff(u32::MAX), MAX_DELAY);
    }

    #[test]
    fn the_queue_is_capped_and_drops_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::load(dir.path().join("notifications.toml"));
        for i in 0..(MAX_PENDING + 5) {
            outbox
                .push("ntfy", &message(&format!("m{i}")), at(0))
                .unwrap();
        }
        assert_eq!(outbox.len(), MAX_PENDING);
        assert_eq!(outbox.dropped(), 5);
        assert_eq!(outbox.pending()[0].title, "m5");
    }

    #[test]
    fn old_notifications_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let mut outbox = Outbox::load(dir.path().join("notifications.toml"));
        outbox.push("ntfy", &message("old"), at(0)).unwrap();
        outbox.push("ntfy", &message("fresh"), at(100)).unwrap();
        let removed = outbox.prune(at(MAX_AGE.as_secs() + 50)).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox.pending()[0].title, "fresh");
        assert_eq!(outbox.dropped(), 1);
        assert_eq!(outbox.prune(at(MAX_AGE.as_secs() + 50)).unwrap(), 0);
    }

    #[test]
    fn a_corrupt_file_is_moved_aside_and_the_queue_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.toml");
        fs::write(&path, "this is not toml [").unwrap();
        let outbox = Outbox::load(&path);
        assert!(outbox.is_empty());
        assert!(!path.exists());
        let aside: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert!(aside[0].starts_with("notifications.corrupt-"), "{aside:?}");
    }

    #[test]
    fn unknown_fields_and_missing_optional_fields_are_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notifications.toml");
        fs::write(
            &path,
            r#"
next_id = 3
something_from_the_future = "ignored"
[[pending]]
id = 2
channel = "ntfy"
title = "kept"
"#,
        )
        .unwrap();
        let outbox = Outbox::load(&path);
        assert_eq!(outbox.len(), 1);
        let item = &outbox.pending()[0];
        assert_eq!(item.id, 2);
        assert_eq!(item.title, "kept");
        assert_eq!(item.severity, Severity::Info);
        assert!(item.click.is_none());
        assert_eq!(
            outbox.per_channel().get("ntfy").copied(),
            Some(1),
            "pending count per channel"
        );
        // The next push continues the id sequence from the file.
        let mut outbox = outbox;
        let id = outbox.push("ntfy", &message("next"), at(0)).unwrap();
        assert_eq!(id, 3);
    }
}
