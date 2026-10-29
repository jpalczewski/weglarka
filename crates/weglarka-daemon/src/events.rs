//! `GET /v1/events` (`read` scope, docs/decisions/0057): recent domain events from the bounded
//! in-memory [`EventHistory`], rendered as flat [`EventRecord`]s.
//!
//! The text is built from structured fields only (see [`describe`]); the engine's free-form failure
//! text never reaches a `read` token. Both text fields are capped in length.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use weglarka_api::{EventRecord, EventsQuery, EventsResponse, endpoints};
use weglarka_model::app::Digest;
use weglarka_model::events::Event;
use weglarka_model::history::EventEntry;
use weglarka_model::podman::PodmanClient;

use crate::admin::Fail;
use crate::app::Daemon;

/// Upper bounds of `message` and `detail`, in characters.
const MESSAGE_MAX_CHARS: usize = 200;
const DETAIL_MAX_CHARS: usize = 512;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(endpoints::EVENTS_RECENT.path, get(recent::<P>))
}

async fn recent<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    RawQuery(query): RawQuery,
) -> Result<Response, Fail> {
    let query = EventsQuery::parse(query.as_deref()).map_err(Fail::invalid)?;
    let boot_id = d.events.boot_id().to_owned();
    // A cursor from another process is meaningless: `seq` started over with the restart.
    let reset = query.boot.as_deref().is_some_and(|boot| boot != boot_id);
    let cursor = if reset { None } else { query.since };
    let recent = d.events.since(cursor);
    Ok(axum::Json(EventsResponse {
        events: recent.entries.iter().map(record).collect(),
        boot_id,
        reset,
        next_seq: recent.latest_seq,
        oldest_seq: recent.oldest_seq,
        dropped: recent.dropped,
    })
    .into_response())
}

fn record(entry: &EventEntry) -> EventRecord {
    let (message, detail) = describe(&entry.event);
    EventRecord {
        seq: entry.seq,
        ts: rfc3339(entry.at),
        severity: entry.event.severity(),
        kind: entry.event.kind().to_owned(),
        app: entry.event.instance().cloned(),
        message: cap(message, MESSAGE_MAX_CHARS),
        detail: cap(detail, DETAIL_MAX_CHARS),
    }
}

fn cap(text: String, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => text[..end].to_owned(),
        None => text,
    }
}

/// First 12 hex digits of a digest.
fn short(digest: &Digest) -> &str {
    // `sha256:` + 64 hex digits; `Digest` validates the form.
    &digest.as_str()[7..19]
}

/// `(message, detail)` for the panel. An allow-list on purpose: only structured fields appear (names,
/// digest prefixes, counters). The engine's free-form `reason`/`output` strings carry podman and
/// validator output that may name registries, paths or config content; they stay in the daemon log
/// and the notification channel, and a `read` token never sees them. No wildcard arm: a new `Event`
/// variant must be classified here.
fn describe(event: &Event) -> (String, String) {
    let (message, detail) = match event {
        Event::DeployOk {
            instance,
            digest,
            generation,
        } => (
            format!("deployed {instance}"),
            format!("{} · generation {generation}", short(digest)),
        ),
        Event::Provisioned { instance, digest } => {
            (format!("provisioned {instance}"), short(digest).to_owned())
        }
        Event::DeployFailed {
            instance, digest, ..
        } => (
            format!("deploy failed: {instance}"),
            digest
                .as_ref()
                .map_or_else(String::new, |d| format!("image {}", short(d))),
        ),
        Event::RolledBack {
            instance,
            failed,
            restored,
            ..
        } => (
            format!("rolled back {instance}"),
            format!("failed {} · restored {}", short(failed), short(restored)),
        ),
        Event::RollbackFailed { instance, .. } => {
            (format!("rollback failed: {instance}"), String::new())
        }
        Event::Recreated { instance, .. } => (format!("recreated {instance}"), String::new()),
        Event::Pruned { container } => (format!("removed container {container}"), String::new()),
        Event::WaitingForSecret { instance, missing } => (
            format!("waiting for secrets: {instance}"),
            format!("missing: {}", missing.join(", ")),
        ),
        Event::WaitingForDependency {
            instance,
            dependencies,
        } => (
            format!("waiting for dependencies: {instance}"),
            dependencies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        Event::WebhookDuplicate { .. } => ("duplicate webhook".to_owned(), String::new()),
        Event::CrashLooping { instance, restarts } => (
            format!("crash loop: {instance}"),
            format!("{restarts} restarts"),
        ),
        Event::Unhealthy { instance } => (format!("unhealthy: {instance}"), String::new()),
        Event::Recovered { instance } => (format!("running again: {instance}"), String::new()),
        Event::SelfUpdated { from, to } => (
            "weglarka updated".to_owned(),
            match from {
                Some(from) => format!("{} → {}", short(from), short(to)),
                None => short(to).to_owned(),
            },
        ),
        Event::SelfUpdatePending { expected, actual } => (
            "self-update pending".to_owned(),
            format!("expected {} · running {}", short(expected), short(actual)),
        ),
        Event::SelfUpdateFellBack { from, to } => (
            "self-update fell back".to_owned(),
            format!("failed {} · restored {}", short(from), short(to)),
        ),
        Event::CertificateIssued {
            cert,
            renewed,
            expires_in_days,
        } => (
            format!(
                "certificate {}: {cert}",
                if *renewed { "renewed" } else { "issued" }
            ),
            format!("valid for {expires_in_days} days"),
        ),
        Event::CertificateRenewalFailed {
            cert,
            expires_in_days,
            ..
        } => (
            format!("certificate renewal failed: {cert}"),
            expires_in_days.map_or_else(
                || "no valid certificate on disk".to_owned(),
                |days| format!("{days} days left"),
            ),
        ),
        Event::GeneratedConfigApplied {
            id,
            consumer,
            validated,
            ..
        } => (
            format!("config {id} applied to {consumer}"),
            if *validated {
                "validated"
            } else {
                "not validated (bootstrap)"
            }
            .to_owned(),
        ),
        Event::GeneratedConfigInvalid { id, consumer, .. } => (
            format!("config {id} rejected for {consumer}"),
            String::new(),
        ),
        Event::GeneratedConfigRolledBack { id, consumer } => (
            format!("config {id} rolled back for {consumer}"),
            String::new(),
        ),
    };
    (message, detail)
}

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC) without a date-time dependency.
fn rfc3339(at: SystemTime) -> String {
    let secs = at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil-from-days, shifted to a year starting on 1 March.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rfc3339_formats_known_instants() {
        let at = |s| UNIX_EPOCH + Duration::from_secs(s);
        assert_eq!(rfc3339(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(at(951_782_400)), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(at(1_793_275_199)), "2026-10-29T11:59:59Z");
    }
}

#[cfg(test)]
mod describe_tests {
    use super::*;
    use weglarka_model::app::InstanceName;

    #[test]
    fn free_form_failure_text_is_not_exposed() {
        let secretish = "pull ghcr.io/x: token=hunter2";
        let events = [
            Event::DeployFailed {
                instance: InstanceName::new("a").unwrap(),
                digest: None,
                reason: secretish.into(),
            },
            Event::RollbackFailed {
                instance: InstanceName::new("a").unwrap(),
                reason: secretish.into(),
            },
            Event::GeneratedConfigInvalid {
                id: "g".into(),
                consumer: InstanceName::new("a").unwrap(),
                output: secretish.into(),
            },
            Event::CertificateRenewalFailed {
                cert: "c.example.com".into(),
                reason: secretish.into(),
                expires_in_days: Some(3),
            },
        ];
        for event in events {
            let (message, detail) = describe(&event);
            assert!(
                !message.contains("hunter2") && !detail.contains("hunter2"),
                "{event:?}"
            );
        }
    }

    #[test]
    fn long_text_is_capped_on_char_boundaries() {
        assert_eq!(cap("ł".repeat(300), 200).chars().count(), 200);
        assert_eq!(cap("short".into(), 200), "short");
    }
}
