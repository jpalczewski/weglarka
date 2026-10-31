//! Daemon metrics (issue #352): deploy, rollback and health-transition counters per app, certificate
//! expiry per routed domain, and the self-update state.
//!
//! Counters come from the engine's events through [`EventCounters`], one more sink in the daemon's
//! event fan-out; they live in memory and start at zero with every process. The rest is read at
//! scrape time from files the daemon already keeps: no libpod call, no background task. A file that
//! cannot be read omits its family; a scrape never fails.
//!
//! Label values follow ADR 0061 (decision 8): `app` is a validated instance name, `domain` a domain
//! the ingress routes, everything else a fixed enum. A failure reason, an error message, a digest or
//! an image reference never becomes a label.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use weglarka_model::app::InstanceName;
use weglarka_model::events::{Event, EventSink};
use weglarka_model::podman::PodmanClient;

use super::encode::{Family, Kind, Sample};
use crate::app::Daemon;
use crate::certificates;

/// How long certificate expiry is reused: `collect` reads `apps.toml` and parses every chain in
/// `tls/`, which a scrape every few seconds should not repeat. Expiry moves in days, renewals in hours.
pub const CERT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Event counts of one app.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct AppCounts {
    deploy_ok: u64,
    deploy_failed: u64,
    rollback_ok: u64,
    rollback_failed: u64,
    crash_looping: u64,
    unhealthy: u64,
    recovered: u64,
}

/// Counts deploy, rollback and health events per app. An [`EventSink`]: `emit` runs under the engine
/// mutex (ADR 0021), so it takes one short lock and allocates only for an app it has not seen yet.
#[derive(Debug, Default)]
pub struct EventCounters(Mutex<BTreeMap<InstanceName, AppCounts>>);

impl EventSink for EventCounters {
    fn emit(&self, event: Event) {
        // Exhaustive on purpose: a new variant is a conscious decision about whether it counts.
        let (instance, bump): (&InstanceName, fn(&mut AppCounts)) = match &event {
            Event::DeployOk { instance, .. } => (instance, |c| c.deploy_ok += 1),
            Event::DeployFailed { instance, .. } => (instance, |c| c.deploy_failed += 1),
            Event::RolledBack { instance, .. } => (instance, |c| c.rollback_ok += 1),
            Event::RollbackFailed { instance, .. } => (instance, |c| c.rollback_failed += 1),
            Event::CrashLooping { instance, .. } => (instance, |c| c.crash_looping += 1),
            Event::Unhealthy { instance } => (instance, |c| c.unhealthy += 1),
            Event::Recovered { instance } => (instance, |c| c.recovered += 1),
            Event::Provisioned { .. }
            | Event::Recreated { .. }
            | Event::Pruned { .. }
            | Event::WaitingForSecret { .. }
            | Event::WaitingForDependency { .. }
            | Event::WebhookDuplicate { .. }
            | Event::SelfUpdated { .. }
            | Event::SelfUpdatePending { .. }
            | Event::SelfUpdateFellBack { .. }
            | Event::CertificateIssued { .. }
            | Event::CertificateRenewalFailed { .. }
            | Event::GeneratedConfigApplied { .. }
            | Event::GeneratedConfigInvalid { .. }
            | Event::GeneratedConfigRolledBack { .. } => return,
        };
        let mut apps = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match apps.get_mut(instance) {
            Some(counts) => bump(counts),
            None => {
                let mut counts = AppCounts::default();
                bump(&mut counts);
                apps.insert(instance.clone(), counts);
            }
        }
    }
}

impl EventCounters {
    fn families(&self) -> Vec<Family> {
        let apps = self.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let (mut deploys, mut rollbacks, mut health) = (Vec::new(), Vec::new(), Vec::new());
        // Only series that moved: an app that never failed has no `result="failed"` line.
        let push = |into: &mut Vec<Sample>, app: &InstanceName, key, value, count: u64| {
            if count > 0 {
                into.push(Sample::new(
                    vec![("app", app.to_string()), (key, value)],
                    count as f64,
                ));
            }
        };
        for (app, c) in &apps {
            push(&mut deploys, app, "result", "ok".into(), c.deploy_ok);
            push(
                &mut deploys,
                app,
                "result",
                "failed".into(),
                c.deploy_failed,
            );
            push(&mut rollbacks, app, "result", "ok".into(), c.rollback_ok);
            push(
                &mut rollbacks,
                app,
                "result",
                "failed".into(),
                c.rollback_failed,
            );
            push(
                &mut health,
                app,
                "to",
                "crash_looping".into(),
                c.crash_looping,
            );
            push(&mut health, app, "to", "unhealthy".into(), c.unhealthy);
            push(&mut health, app, "to", "recovered".into(), c.recovered);
        }
        vec![
            Family {
                name: "weglarka_deploys_total",
                help: "Deploys since the daemon started, by app and result (ok, failed). A deploy the \
                       health gate rejected counts in weglarka_rollbacks_total instead.",
                kind: Kind::Counter,
                samples: deploys,
            },
            Family {
                name: "weglarka_rollbacks_total",
                help: "Rollbacks to the previous digest since the daemon started, by app and result \
                       (ok, failed).",
                kind: Kind::Counter,
                samples: rollbacks,
            },
            Family {
                name: "weglarka_app_health_transitions_total",
                help: "Health transitions seen by the crash-loop and healthcheck monitor since the daemon \
                       started, by app and new state (crash_looping, unhealthy, recovered).",
                kind: Kind::Counter,
                samples: health,
            },
        ]
    }
}

/// What the daemon source keeps between scrapes: the counters and the certificate cache.
#[derive(Debug, Default)]
pub struct DaemonSource {
    pub counters: std::sync::Arc<EventCounters>,
    certs: Mutex<Option<(Instant, Vec<Sample>)>>,
}

impl DaemonSource {
    pub fn new(counters: std::sync::Arc<EventCounters>) -> Self {
        Self {
            counters,
            certs: Mutex::default(),
        }
    }
}

/// Every family of this source.
pub fn families<P: PodmanClient + 'static>(d: &Daemon<P>, source: &DaemonSource) -> Vec<Family> {
    let mut out = source.counters.families();
    if let Some(family) = certificate_family(d, source) {
        out.push(family);
    }
    out.extend(self_update_families(d));
    out
}

/// `weglarka_certificate_not_after_seconds{domain}`; `None` without an enabled `[acme]`.
fn certificate_family<P: PodmanClient + 'static>(
    d: &Daemon<P>,
    source: &DaemonSource,
) -> Option<Family> {
    let config = d.host.acme.as_ref().filter(|c| c.enabled)?;
    let mut cache = source.certs.lock().unwrap_or_else(|e| e.into_inner());
    let fresh = cache
        .as_ref()
        .filter(|(at, _)| at.elapsed() < CERT_CACHE_TTL)
        .map(|(_, samples)| samples.clone());
    let samples = match fresh {
        Some(samples) => samples,
        None => {
            // `apps.toml` unreadable: no family this time, and the next scrape tries again.
            let domains = certificates::routed_domains(d)?;
            let certs =
                certificates::collect(&d.ingress.tls_dir(), config, &domains, SystemTime::now());
            let samples = certificate_samples(&certs);
            *cache = Some((Instant::now(), samples.clone()));
            samples
        }
    };
    Some(Family {
        name: "weglarka_certificate_not_after_seconds",
        help: "Expiry (notAfter) of the certificate nginx serves for a routed domain, as a Unix \
               timestamp; a domain without a readable certificate has no line.",
        kind: Kind::Gauge,
        samples,
    })
}

/// One sample per routed domain with a known expiry: its own chain, or else the wildcard that serves
/// it. Wildcard rows themselves are not domains the ingress routes and get no line of their own.
fn certificate_samples(certs: &[certificates::Cert]) -> Vec<Sample> {
    let wildcard_expiry = |apex: &str| {
        certs
            .iter()
            .find(|c| c.wildcard && c.names.get(1).is_some_and(|name| name == apex))
            .and_then(|c| c.not_after)
    };
    certs
        .iter()
        .filter(|c| !c.wildcard)
        .filter_map(|c| {
            let at = c
                .not_after
                .or_else(|| c.covered_by.as_deref().and_then(wildcard_expiry))?;
            Some(Sample::new(vec![("domain", c.id.clone())], unix_secs(at)))
        })
        .collect()
}

fn unix_secs(at: SystemTime) -> f64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs() as f64)
}

/// Self-update state; nothing without `[self_update]` or when the state file cannot be read.
fn self_update_families<P: PodmanClient + 'static>(d: &Daemon<P>) -> Vec<Family> {
    if d.host.self_update.is_none() {
        return Vec::new();
    }
    let state = match weglarka_model::self_update::load(&d.paths.state_dir) {
        Ok(state) => state,
        Err(error) => {
            tracing::debug!(%error, "self-update state unreadable; metrics omitted");
            return Vec::new();
        }
    };
    let gauge = |name, help, value: Option<u64>| Family {
        name,
        help,
        kind: Kind::Gauge,
        samples: value
            .map(|v| Sample::new(Vec::new(), v as f64))
            .into_iter()
            .collect(),
    };
    vec![
        gauge(
            "weglarka_self_update_pending",
            "1 while a new daemon image is pinned but not yet confirmed running, else 0.",
            Some(u64::from(state.pending.is_some())),
        ),
        gauge(
            "weglarka_self_update_last_check_timestamp_seconds",
            "Unix time of the last completed self-update check.",
            state.checked_at,
        ),
        gauge(
            "weglarka_self_update_last_error_timestamp_seconds",
            "Unix time of the last failed or refused self-update attempt (kept until the next check).",
            state.error.as_ref().map(|e| e.at),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_model::app::Digest;

    fn name(s: &str) -> InstanceName {
        InstanceName::new(s).unwrap()
    }

    fn digest() -> Digest {
        Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap()
    }

    #[test]
    fn counters_follow_events_and_never_carry_the_reason() {
        let counters = EventCounters::default();
        counters.emit(Event::DeployOk {
            instance: name("web"),
            digest: digest(),
            generation: 1,
        });
        counters.emit(Event::DeployFailed {
            instance: name("web"),
            digest: None,
            reason: "secret-reason \"quoted\"".into(),
        });
        counters.emit(Event::RolledBack {
            instance: name("api"),
            failed: digest(),
            restored: digest(),
            reason: "gate".into(),
        });
        counters.emit(Event::Unhealthy {
            instance: name("api"),
        });
        counters.emit(Event::Recovered {
            instance: name("api"),
        });
        counters.emit(Event::Pruned {
            container: "old".into(),
        });
        let text = super::super::encode::encode(counters.families());
        assert!(!text.contains("secret-reason"), "{text}");
        assert!(!text.contains("sha256"), "{text}");
        insta::assert_snapshot!(text);
    }

    #[test]
    fn a_covered_domain_reports_the_wildcard_expiry_and_an_unknown_one_is_skipped() {
        let at = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let wild = UNIX_EPOCH + Duration::from_secs(1_900_000_000);
        let cert = |id: &str, not_after, covered_by: Option<&str>| certificates::Cert {
            id: id.into(),
            names: vec![id.into()],
            wildcard: false,
            not_after,
            covered_by: covered_by.map(str::to_owned),
        };
        let certs = vec![
            cert("a.example.com", Some(at), None),
            cert("b.example.com", None, Some("example.com")),
            cert("c.example.org", None, None),
            certificates::Cert {
                id: "_wildcard.example.com".into(),
                names: vec!["*.example.com".into(), "example.com".into()],
                wildcard: true,
                not_after: Some(wild),
                covered_by: None,
            },
        ];
        assert_eq!(
            certificate_samples(&certs),
            vec![
                Sample::new(vec![("domain", "a.example.com".into())], 2_000_000_000.0),
                Sample::new(vec![("domain", "b.example.com".into())], 1_900_000_000.0),
            ]
        );
    }
}
