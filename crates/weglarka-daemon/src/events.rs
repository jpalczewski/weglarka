//! `GET /v1/events` (`read` scope, docs/decisions/0057): recent domain events from the bounded
//! in-memory [`EventHistory`], rendered as flat [`EventRecord`]s.
//!
//! The text is the same one a notification channel receives (`weglarka_notify::message`): names of
//! instances, digests prefixes, secret *names* and the engine's failure reasons — never secret
//! values — and it is capped in length.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{RawQuery, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use weglarka_api::{EventRecord, EventsResponse, endpoints};
use weglarka_model::history::EventEntry;
use weglarka_model::podman::PodmanClient;
use weglarka_notify::message;

use crate::admin::Fail;
use crate::app::Daemon;

/// Upper bound of `detail`, in characters.
const DETAIL_MAX_CHARS: usize = 512;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(endpoints::EVENTS_RECENT.path, get(recent::<P>))
}

/// `since` from a raw query string; anything but a decimal `u64` is a 400.
fn parse_since(query: Option<&str>) -> Result<Option<u64>, Fail> {
    let mut since = None;
    for kv in query
        .unwrap_or_default()
        .split('&')
        .filter(|kv| !kv.is_empty())
    {
        let (key, value) = kv.split_once('=').unwrap_or((kv, ""));
        if key == "since" {
            since = Some(
                value
                    .parse()
                    .map_err(|_| Fail::invalid("`since` must be a non-negative integer"))?,
            );
        }
    }
    Ok(since)
}

async fn recent<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    RawQuery(query): RawQuery,
) -> Result<Response, Fail> {
    let recent = d.events.since(parse_since(query.as_deref())?);
    Ok(axum::Json(EventsResponse {
        events: recent.entries.iter().map(record).collect(),
        next_seq: recent.latest_seq,
        oldest_seq: recent.oldest_seq,
        dropped: recent.dropped,
    })
    .into_response())
}

fn record(entry: &EventEntry) -> EventRecord {
    let rendered = message::build(&entry.event);
    EventRecord {
        seq: entry.seq,
        ts: rfc3339(entry.at),
        severity: entry.event.severity(),
        kind: entry.event.kind().to_owned(),
        app: entry.event.instance().cloned(),
        message: rendered.title,
        detail: rendered.body.chars().take(DETAIL_MAX_CHARS).collect(),
    }
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

    #[test]
    fn since_parsing() {
        assert_eq!(parse_since(None).unwrap(), None);
        assert_eq!(parse_since(Some("")).unwrap(), None);
        assert_eq!(parse_since(Some("since=12")).unwrap(), Some(12));
        assert_eq!(parse_since(Some("x=1&since=0")).unwrap(), Some(0));
        assert!(parse_since(Some("since=-1")).is_err());
        assert!(parse_since(Some("since=")).is_err());
        assert!(parse_since(Some("since=1.5")).is_err());
    }
}
