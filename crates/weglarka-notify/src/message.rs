//! Rendering engine events into user-facing notifications, and the dedup key of each event kind.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use weglarka_model::app::{AppsFile, Digest};
use weglarka_model::events::{Event, Severity};

/// A ready-to-send notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub severity: Severity,
    /// Dedup key (`kind:subject`): repeated events of one key are coalesced (see [`crate::dedup`]).
    pub key: String,
    pub title: String,
    pub body: String,
    /// ntfy priority: 1 (min) … 5 (max).
    pub priority: u8,
    pub tags: Vec<String>,
    /// Opened when the notification is tapped — the app's first domain, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub click: Option<String>,
}

/// First 12 hex digits of a digest, for a readable message.
fn short(digest: &Digest) -> &str {
    // `sha256:` + 64 hex digits; the slice is always in range because `Digest` validates the form.
    &digest.as_str()[7..19]
}

/// ntfy priority of a severity.
fn priority(severity: Severity) -> u8 {
    match severity {
        Severity::Debug => 2,
        Severity::Info => 3,
        Severity::Warning => 4,
        Severity::Critical => 5,
    }
}

fn tag(tag: &str) -> Vec<String> {
    vec![tag.to_owned()]
}

fn tags(tags: &[&str]) -> Vec<String> {
    tags.iter().map(|t| (*t).to_owned()).collect()
}

/// Renders an event; `apps` only supplies the click-through link (the app's first domain) and may be
/// stale — a notification must never be dropped because `apps.toml` cannot be read.
pub fn render(event: &Event, apps: &AppsFile) -> Message {
    let mut message = build(event);
    if message.click.is_none() {
        message.click = event
            .instance()
            .and_then(|instance| apps.apps.get(instance))
            .and_then(|spec| spec.domains.first())
            .map(|domain| format!("https://{domain}"));
    }
    message
}

/// Renders an event without the `apps.toml` lookup (pure; see [`render`]).
pub fn build(event: &Event) -> Message {
    let severity = event.severity();
    let (key, title, body, event_tags) = match event {
        Event::DeployOk {
            instance,
            digest,
            generation,
        } => (
            format!("deploy:{instance}"),
            format!("deployed {instance}"),
            format!("{} · generation {generation}", short(digest)),
            tag("white_check_mark"),
        ),
        Event::Provisioned { instance, digest } => (
            format!("provision:{instance}"),
            format!("provisioned {instance}"),
            format!("{} · ready for `apps start`", short(digest)),
            tag("package"),
        ),
        Event::DeployFailed {
            instance,
            digest,
            reason,
        } => {
            let body = match digest {
                Some(digest) => format!("{reason}\nimage {}", short(digest)),
                None => reason.clone(),
            };
            (
                format!("deploy-failed:{instance}"),
                format!("deploy failed: {instance}"),
                body,
                tag("warning"),
            )
        }
        Event::RolledBack {
            instance,
            failed,
            restored,
            reason,
        } => (
            format!("rollback:{instance}"),
            format!("rolled back {instance}"),
            format!(
                "failed: {}\nrestored: {}\n{reason}",
                short(failed),
                short(restored)
            ),
            tags(&["rewind", "warning"]),
        ),
        Event::RollbackFailed { instance, reason } => (
            format!("rollback-failed:{instance}"),
            format!("ROLLBACK FAILED: {instance}"),
            reason.clone(),
            tag("rotating_light"),
        ),
        Event::Recreated { instance, reason } => (
            format!("recreate:{instance}"),
            format!("recreated {instance}"),
            reason.clone(),
            tag("arrows_counterclockwise"),
        ),
        Event::Pruned { container } => (
            format!("pruned:{container}"),
            format!("removed container {container}"),
            format!("{container} is not in apps.toml"),
            tag("wastebasket"),
        ),
        Event::WaitingForSecret { instance, missing } => (
            format!("secret:{instance}"),
            format!("waiting for secrets: {instance}"),
            format!("missing: {}", missing.join(", ")),
            tag("key"),
        ),
        Event::WaitingForDependency {
            instance,
            dependencies,
        } => (
            format!("dependency:{instance}"),
            format!("waiting for dependencies: {instance}"),
            format!(
                "not running yet: {}",
                dependencies
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            tag("hourglass"),
        ),
        Event::WebhookDuplicate { delivery_id } => (
            format!("webhook-dup:{delivery_id}"),
            format!("duplicate webhook {delivery_id}"),
            "already handled (deduplicated by delivery id)".to_owned(),
            tag("recycle"),
        ),
        Event::CrashLooping { instance, restarts } => (
            format!("crash:{instance}"),
            format!("crash loop: {instance}"),
            format!("{restarts} restarts; check the logs with `weglarka apps show {instance}`"),
            tag("rotating_light"),
        ),
        Event::Unhealthy { instance } => (
            format!("unhealthy:{instance}"),
            format!("unhealthy: {instance}"),
            "the container healthcheck is failing".to_owned(),
            tag("warning"),
        ),
        Event::Recovered { instance } => (
            format!("recovered:{instance}"),
            format!("running again: {instance}"),
            "no new restarts and the healthcheck passes".to_owned(),
            tag("white_check_mark"),
        ),
        // The two events below concern Węglarka itself, not an app: no click-through link.
        Event::SelfUpdated { from, to } => (
            "self-update:daemon".to_owned(),
            "Węglarka updated".to_owned(),
            match from {
                Some(from) => format!("{} → {}", short(from), short(to)),
                None => short(to).to_owned(),
            },
            tag("arrow_up"),
        ),
        Event::SelfUpdatePending { expected, actual } => (
            "self-update:daemon".to_owned(),
            "Węglarka self-update did not take effect".to_owned(),
            format!(
                "pinned {} but the container runs {}; \
                 `weglarka-daemon self-update --rollback` returns to the previous image",
                short(expected),
                short(actual)
            ),
            tag("warning"),
        ),
        // Issue #100: the watchdog reverted an image that never became healthy.
        Event::SelfUpdateFellBack { from, to } => (
            "self-update:daemon".to_owned(),
            "Węglarka fell back to the previous image".to_owned(),
            format!(
                "the switch to {} did not answer the admin API in time, so the watchdog restored {}; \
                 the failed digest is not retried until the tag moves (`--force` overrides that)",
                short(from),
                short(to)
            ),
            tag("warning"),
        ),
        Event::GeneratedConfigApplied {
            id,
            consumer,
            fingerprint,
            validated,
        } => (
            format!("generated:{id}"),
            format!("config {id} applied to {consumer}"),
            format!(
                "{}{}",
                fingerprint.chars().take(12).collect::<String>(),
                if *validated { "" } else { " · not validated (first start)" }
            ),
            tag("gear"),
        ),
        Event::GeneratedConfigInvalid {
            id,
            consumer,
            output,
        } => (
            format!("generated:{id}"),
            format!("config {id} for {consumer} failed validation"),
            format!("the previous version stays live. {output}"),
            tag("warning"),
        ),
        Event::GeneratedConfigRolledBack { id, consumer } => (
            format!("generated:{id}"),
            format!("config {id} rolled back on {consumer}"),
            "the consumer failed its health gate on the new version; the previous one is live again"
                .to_owned(),
            tag("rewind"),
        ),
        // Issue #96: certificates belong to the host, not to an app.
        Event::CertificateIssued {
            cert,
            renewed,
            expires_in_days,
        } => (
            format!("acme:{cert}"),
            format!(
                "certificate {}: {cert}",
                if *renewed { "renewed" } else { "issued" }
            ),
            format!("valid for {expires_in_days} more days"),
            tag("lock"),
        ),
        Event::CertificateRenewalFailed {
            cert,
            reason,
            expires_in_days,
        } => (
            format!("acme:{cert}"),
            format!("certificate renewal failed: {cert}"),
            match expires_in_days {
                Some(0) => format!("{reason}; the current certificate has expired"),
                Some(days) => format!("{reason}; the current certificate has {days} days left"),
                None => format!("{reason}; there is no certificate for this domain yet"),
            },
            tag("warning"),
        ),
    };
    Message {
        severity,
        key,
        title,
        body,
        priority: priority(severity),
        tags: event_tags,
        click: None,
    }
}

/// One notification standing in for the events of a window that were suppressed: it keeps the key
/// and the link of the last event, the worst severity of the window and the first/last titles.
pub fn summary(first: &Message, last: &Message, suppressed: u32, window: Duration) -> Message {
    let severity = first.severity.max(last.severity);
    Message {
        severity,
        key: last.key.clone(),
        title: format!("{suppressed} more: {}", last.title),
        body: format!(
            "{suppressed} more event(s) of this kind in the last {}s\nfirst: {}\nlast: {}",
            window.as_secs(),
            first.title,
            last.title
        ),
        priority: priority(severity),
        tags: last.tags.clone(),
        click: last.click.clone(),
    }
}

/// Message of `weglarka notify test`: delivered immediately, bypassing the outbox and dedup.
pub fn test_message(label: &str) -> Message {
    Message {
        severity: Severity::Info,
        key: "test".to_owned(),
        title: "Węglarka test notification".to_owned(),
        body: format!("notifications from {label} work"),
        priority: priority(Severity::Info),
        tags: tag("bell"),
        click: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_model::app::InstanceName;

    fn instance() -> InstanceName {
        InstanceName::new("ntfy").unwrap()
    }

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn apps() -> AppsFile {
        toml::from_str(
            r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["nz.example.com"]
[apps.worker]
image = "ghcr.io/x/worker:1"
"#,
        )
        .unwrap()
    }

    fn every_event() -> Vec<(Event, Severity)> {
        vec![
            (
                Event::DeployOk {
                    instance: instance(),
                    digest: digest('a'),
                    generation: 7,
                },
                Severity::Info,
            ),
            (
                Event::Provisioned {
                    instance: instance(),
                    digest: digest('b'),
                },
                Severity::Info,
            ),
            (
                Event::DeployFailed {
                    instance: instance(),
                    digest: Some(digest('c')),
                    reason: "health gate failed after 10 attempts: connection refused".into(),
                },
                Severity::Warning,
            ),
            (
                Event::DeployFailed {
                    instance: instance(),
                    digest: None,
                    reason: "pull failed: unauthorized".into(),
                },
                Severity::Warning,
            ),
            (
                Event::RolledBack {
                    instance: instance(),
                    failed: digest('c'),
                    restored: digest('a'),
                    reason: "health gate failed after 10 attempts".into(),
                },
                Severity::Warning,
            ),
            (
                Event::RollbackFailed {
                    instance: instance(),
                    reason: "cannot start container: image not found".into(),
                },
                Severity::Critical,
            ),
            (
                Event::Recreated {
                    instance: instance(),
                    reason: "SpecDrift".into(),
                },
                Severity::Info,
            ),
            (
                Event::Pruned {
                    container: "gone".into(),
                },
                Severity::Debug,
            ),
            (
                Event::WaitingForSecret {
                    instance: instance(),
                    missing: vec!["config".into(), "token".into()],
                },
                Severity::Info,
            ),
            (
                Event::WaitingForDependency {
                    instance: instance(),
                    dependencies: vec![InstanceName::new("db").unwrap()],
                },
                Severity::Debug,
            ),
            (
                Event::WebhookDuplicate {
                    delivery_id: "abc-123".into(),
                },
                Severity::Debug,
            ),
            (
                Event::CrashLooping {
                    instance: instance(),
                    restarts: 4,
                },
                Severity::Critical,
            ),
            (
                Event::Unhealthy {
                    instance: instance(),
                },
                Severity::Warning,
            ),
            (
                Event::Recovered {
                    instance: instance(),
                },
                Severity::Info,
            ),
            (
                Event::SelfUpdated {
                    from: Some(digest('a')),
                    to: digest('d'),
                },
                Severity::Info,
            ),
            (
                Event::SelfUpdated {
                    from: None,
                    to: digest('d'),
                },
                Severity::Info,
            ),
            (
                Event::SelfUpdatePending {
                    expected: digest('d'),
                    actual: digest('a'),
                },
                Severity::Warning,
            ),
            (
                Event::CertificateIssued {
                    cert: "app.example.eu".into(),
                    renewed: false,
                    expires_in_days: 89,
                },
                Severity::Info,
            ),
            (
                Event::CertificateRenewalFailed {
                    cert: "app.example.eu".into(),
                    reason: "rate limited".into(),
                    expires_in_days: Some(12),
                },
                Severity::Warning,
            ),
            (
                Event::CertificateRenewalFailed {
                    cert: "app.example.eu".into(),
                    reason: "challenge failed".into(),
                    expires_in_days: None,
                },
                Severity::Critical,
            ),
        ]
    }

    #[test]
    fn renders_every_event() {
        let apps = apps();
        let rendered: Vec<Message> = every_event()
            .into_iter()
            .map(|(event, _)| render(&event, &apps))
            .collect();
        insta::assert_json_snapshot!(rendered);
    }

    #[test]
    fn priority_follows_severity_and_the_click_link_the_first_domain() {
        let rendered = every_event()
            .into_iter()
            .map(|(event, severity)| (render(&event, &apps()), severity))
            .collect::<Vec<_>>();
        for (message, severity) in rendered {
            assert_eq!(message.severity, severity, "{message:?}");
            assert_eq!(message.priority, priority(severity), "{message:?}");
            let has_instance = !message.key.starts_with("pruned:")
                && !message.key.starts_with("webhook-dup:")
                && !message.key.starts_with("self-update:")
                && !message.key.starts_with("acme:");
            if has_instance {
                assert_eq!(
                    message.click.as_deref(),
                    Some("https://nz.example.com"),
                    "{message:?}"
                );
            } else {
                assert_eq!(message.click, None, "{message:?}");
            }
        }
    }

    #[test]
    fn events_without_a_domain_have_no_click_link() {
        let apps = apps();
        let message = render(
            &Event::DeployOk {
                instance: InstanceName::new("worker").unwrap(),
                digest: digest('a'),
                generation: 1,
            },
            &apps,
        );
        assert_eq!(message.click, None);
        assert_eq!(message.title, "deployed worker");
    }

    #[test]
    fn summary_keeps_the_key_link_and_the_worst_severity() {
        let apps = apps();
        let first = render(
            &Event::DeployFailed {
                instance: instance(),
                digest: None,
                reason: "first".into(),
            },
            &apps,
        );
        let last = render(
            &Event::DeployFailed {
                instance: instance(),
                digest: None,
                reason: "last".into(),
            },
            &apps,
        );
        let digest_summary = summary(&first, &last, 4, Duration::from_secs(300));
        assert_eq!(digest_summary.key, "deploy-failed:ntfy");
        assert_eq!(digest_summary.title, "4 more: deploy failed: ntfy");
        assert_eq!(digest_summary.severity, Severity::Warning);
        assert_eq!(digest_summary.priority, 4);
        assert_eq!(digest_summary.click, last.click);
        assert!(digest_summary.body.contains("first: deploy failed: ntfy"));
        assert!(digest_summary.body.contains("300s"));

        // One critical event among warnings escalates the summary.
        let critical = render(
            &Event::RollbackFailed {
                instance: instance(),
                reason: "boom".into(),
            },
            &apps,
        );
        let escalated = summary(&first, &critical, 1, Duration::from_secs(60));
        assert_eq!(escalated.severity, Severity::Critical);
        assert_eq!(escalated.priority, 5);
    }

    #[test]
    fn test_message_is_labelled() {
        let message = test_message("weglarka.example.com");
        assert!(message.body.contains("weglarka.example.com"));
        assert_eq!(message.severity, Severity::Info);
        assert_eq!(message.tags, ["bell"]);
    }
}
