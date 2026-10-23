//! Engine tests (reconcile + deploy + secrets) on `FakePodman`. Virtual time (`start_paused`),
//! so the health gate does not really wait.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::app::{Digest, InstanceName};
use crate::deploy::DeployOutcome;
use crate::events::{Event, VecSink};
use crate::labels;
use crate::podman::{ContainerState, HealthStatus, PodmanClient};
use crate::reconcile::{
    Action, ActionOutcome, ReconcileReport, Reconciler, ReconcilerOptions, RecreateReason,
    SecretChangePolicy, Trigger,
};
use crate::secret_store::{SecretStore, SecretValue};
use crate::secrets::FileSecretStore;
use crate::state::{StatePaths, load_state};
use crate::testing::{Call, FakePodman};
use crate::webhook::WebhookEvent;

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

fn digest(c: char) -> Digest {
    Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
}

fn name(s: &str) -> InstanceName {
    InstanceName::new(s).unwrap()
}

struct Harness {
    dir: tempfile::TempDir,
    fake: FakePodman,
    store: Arc<FileSecretStore>,
    sink: Arc<VecSink>,
    rec: Arc<Reconciler<FakePodman>>,
}

impl Harness {
    fn new(apps_toml: &str) -> Self {
        Self::with_policy(apps_toml, SecretChangePolicy::Immediate)
    }

    fn with_policy(apps_toml: &str, policy: SecretChangePolicy) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::in_dir(dir.path());
        std::fs::write(&paths.apps, apps_toml).unwrap();
        let fake = FakePodman::new();
        let store = Arc::new(FileSecretStore::new(dir.path().join("secrets.toml")));
        let sink = Arc::new(VecSink::default());
        let secrets: Arc<dyn SecretStore> = store.clone();
        let rec = Arc::new(
            Reconciler::new(
                fake.clone(),
                secrets,
                paths,
                ReconcilerOptions {
                    secret_change: policy,
                    ..Default::default()
                },
            )
            .with_events(sink.clone()),
        );
        Self {
            dir,
            fake,
            store,
            sink,
            rec,
        }
    }

    fn set_apps(&self, toml: &str) {
        std::fs::write(&self.rec.paths().apps, toml).unwrap();
    }

    fn state(&self, inst: &str) -> crate::state::AppState {
        load_state(&self.rec.paths().state)
            .unwrap()
            .apps
            .remove(&name(inst))
            .unwrap_or_default()
    }

    fn container_digest_ref(&self, cname: &str) -> String {
        self.fake
            .containers()
            .into_iter()
            .find(|c| c.name == cname)
            .unwrap()
            .image
    }
}

fn single(report: &ReconcileReport) -> &ActionOutcome {
    assert_eq!(report.actions.len(), 1, "{:?}", report.actions);
    report.actions[0].result.as_ref().unwrap()
}

const NTFY: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
health = { attempts = 3, window_secs = 6 }
"#;

#[tokio::test(start_paused = true)]
async fn fresh_deploy_then_converged() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    let report = h.rec.reconcile().await.unwrap();
    assert!(matches!(
        single(&report),
        ActionOutcome::Deployed(DeployOutcome::Deployed { generation: 1, .. })
    ));

    let st = h.state("ntfy");
    assert_eq!(st.current, Some(digest('a')));
    assert_eq!(st.previous, None);
    assert!(st.spec_hash.is_some());
    assert_eq!(h.fake.networks(), vec!["net-ntfy".to_owned()]);
    let c = &h.fake.containers()[0];
    assert_eq!(c.name, "ntfy");
    assert_eq!(c.labels[labels::INSTANCE], "ntfy");
    assert_eq!(c.labels[labels::GENERATION], "1");
    assert_eq!(c.labels[labels::SPEC_HASH], st.spec_hash.unwrap().as_str());
    assert_eq!(
        c.image,
        format!("ghcr.io/jpalczewski/ntfy.zig@{}", digest('a'))
    );
    assert_eq!(c.state, ContainerState::Running);
    assert!(matches!(
        h.sink.events()[0],
        Event::DeployOk { generation: 1, .. }
    ));

    // Second pass: nothing to do.
    assert!(h.rec.reconcile().await.unwrap().actions.is_empty());
}

#[tokio::test(start_paused = true)]
async fn deploy_without_changes_is_unchanged_and_new_digest_moves_pointers() {
    let h = Harness::new(NTFY);
    let ntfy = name("ntfy");
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();

    assert_eq!(
        h.rec.deploy(&ntfy, false).await.unwrap(),
        DeployOutcome::Unchanged {
            digest: digest('a')
        }
    );
    let before = h.fake.calls().len();

    h.fake.set_pull_digest(IMAGE, digest('b'));
    assert_eq!(
        h.rec.deploy(&ntfy, false).await.unwrap(),
        DeployOutcome::Deployed {
            digest: digest('b'),
            generation: 2
        }
    );
    let st = h.state("ntfy");
    assert_eq!(
        (st.current, st.previous),
        (Some(digest('b')), Some(digest('a')))
    );
    assert!(
        h.container_digest_ref("ntfy")
            .ends_with(digest('b').as_str())
    );

    // Order: pull → stop old → remove → create → start → (gate without a healthcheck).
    let calls = h.fake.calls()[before..].to_vec();
    let pos = |c: &Call| calls.iter().position(|x| x == c).unwrap();
    assert!(pos(&Call::ImagePull(IMAGE.into())) < pos(&Call::ContainerStop("ntfy".into())));
    assert!(pos(&Call::ContainerStop("ntfy".into())) < pos(&Call::ContainerCreate("ntfy".into())));
    assert!(pos(&Call::ContainerCreate("ntfy".into())) < pos(&Call::ContainerStart("ntfy".into())));
}

#[tokio::test(start_paused = true)]
async fn rollback_uses_local_image_when_registry_cannot_serve_it() {
    let h = Harness::new(NTFY);
    let ntfy = name("ntfy");
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health("ntfy", [HealthStatus::Healthy]);
    h.rec.reconcile().await.unwrap();

    // The old version is no longer addressable as repo@digest and the registry no longer serves it.
    let pinned = format!("ghcr.io/jpalczewski/ntfy.zig@{}", digest('a'));
    h.fake.image_remove(&pinned).await.unwrap();
    h.fake.fail_pull(&pinned, "manifest unknown");

    h.fake.set_pull_digest(IMAGE, digest('b'));
    h.fake.script_health(
        "ntfy",
        [
            HealthStatus::Unhealthy,
            HealthStatus::Unhealthy,
            HealthStatus::Unhealthy,
            HealthStatus::Healthy,
        ],
    );
    let out = h.rec.deploy(&ntfy, false).await.unwrap();
    assert!(
        matches!(&out, DeployOutcome::RolledBack { restored, .. } if *restored == digest('a')),
        "{out:?}"
    );
    assert_eq!(h.state("ntfy").current, Some(digest('a')));
    assert!(!h.fake.calls().contains(&Call::ImagePull(pinned)));
}

#[tokio::test(start_paused = true)]
async fn failed_health_gate_rolls_back_and_marks_state() {
    let h = Harness::new(NTFY);
    let ntfy = name("ntfy");
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health("ntfy", [HealthStatus::Healthy]);
    h.rec.reconcile().await.unwrap();

    // New version: 3 unhealthy attempts, then (for the container after rollback) healthy.
    h.fake.set_pull_digest(IMAGE, digest('b'));
    h.fake.script_health(
        "ntfy",
        [
            HealthStatus::Unhealthy,
            HealthStatus::Unhealthy,
            HealthStatus::Unhealthy,
            HealthStatus::Healthy,
        ],
    );
    let out = h.rec.deploy(&ntfy, false).await.unwrap();
    assert!(
        matches!(&out, DeployOutcome::RolledBack { failed, restored, .. }
            if *failed == digest('b') && *restored == digest('a')),
        "{out:?}"
    );

    let st = h.state("ntfy");
    assert_eq!(st.current, Some(digest('a')));
    assert_eq!(st.generation, 3);
    assert_eq!(st.failed.as_ref().unwrap().digest, digest('b'));
    assert!(
        h.container_digest_ref("ntfy")
            .ends_with(digest('a').as_str())
    );
    assert_eq!(
        h.fake
            .calls()
            .iter()
            .filter(|c| **c == Call::HealthcheckRun("ntfy".into()))
            .count(),
        1 + 3 + 1
    );
    assert!(
        h.sink
            .events()
            .iter()
            .any(|e| matches!(e, Event::RolledBack { .. }))
    );

    // Known-bad digest: the webhook does not retry it, force does.
    assert_eq!(
        h.rec.deploy(&ntfy, false).await.unwrap(),
        DeployOutcome::KnownBad {
            digest: digest('b')
        }
    );
    assert!(h.rec.reconcile().await.unwrap().actions.is_empty());
}

#[tokio::test(start_paused = true)]
async fn failed_first_deploy_removes_container_and_waits_for_manual_deploy() {
    let h = Harness::new(NTFY);
    h.fake.script_health("ntfy", [HealthStatus::Unhealthy]);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    let report = h.rec.reconcile().await.unwrap();
    assert!(matches!(
        single(&report),
        ActionOutcome::Deployed(DeployOutcome::Failed { .. })
    ));
    assert!(h.fake.containers().is_empty());
    let st = h.state("ntfy");
    assert_eq!(st.current, None);
    assert_eq!(st.failed.unwrap().digest, digest('a'));

    // The next reconcile does not retry endlessly.
    let again = h.rec.reconcile().await.unwrap();
    assert!(again.actions.is_empty());
    assert_eq!(again.blocked.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn crash_inside_gate_window_fails_running_only_gate() {
    // Without a healthcheck: a container that died does not pass the gate.
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    h.fake.set_pull_digest(IMAGE, digest('b'));
    let rec = h.rec.clone();
    let fake = h.fake.clone();
    let task = tokio::spawn(async move { rec.deploy(&name("ntfy"), false).await });
    tokio::time::sleep(Duration::from_secs(3)).await; // in the middle of the gate window (6 s)
    fake.crash_container("ntfy", 1);
    let out = task.await.unwrap().unwrap();
    assert!(matches!(out, DeployOutcome::RolledBack { .. }), "{out:?}");
}

#[tokio::test(start_paused = true)]
async fn pull_failure_leaves_everything_untouched() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    h.fake.fail_pull(IMAGE, "manifest unknown");
    let err = h.rec.deploy(&name("ntfy"), false).await.unwrap_err();
    assert!(err.to_string().contains("manifest unknown"));
    assert_eq!(h.state("ntfy").current, Some(digest('a')));
    assert_eq!(h.fake.containers()[0].state, ContainerState::Running);
    assert!(
        h.sink
            .events()
            .iter()
            .any(|e| matches!(e, Event::DeployFailed { digest: None, .. }))
    );
}

#[tokio::test(start_paused = true)]
async fn spec_drift_missing_container_and_stopped_container() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();

    // Drift: env change in apps.toml → recreate without a pull.
    h.set_apps(&format!("{NTFY}env = {{ A = \"1\" }}\n"));
    let pulls = |h: &Harness| {
        h.fake
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::ImagePull(_)))
            .count()
    };
    let before = pulls(&h);
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.actions[0].action,
        Action::Recreate {
            instance: name("ntfy"),
            reason: RecreateReason::SpecDrift
        }
    );
    assert_eq!(pulls(&h), before);
    assert_eq!(h.state("ntfy").generation, 2);
    assert!(h.rec.reconcile().await.unwrap().actions.is_empty());

    // The container disappeared.
    h.fake.container_remove("ntfy", true).await.unwrap();
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.actions[0].action,
        Action::Recreate {
            instance: name("ntfy"),
            reason: RecreateReason::Missing
        }
    );

    // The container died → plain start.
    h.fake.crash_container("ntfy", 137);
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(single(&report), &ActionOutcome::Started);
    assert_eq!(h.fake.containers()[0].state, ContainerState::Running);
}

#[tokio::test(start_paused = true)]
async fn removed_app_is_pruned_with_its_state() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    h.rec.remove_app(&name("ntfy")).await.unwrap();
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(single(&report), &ActionOutcome::Removed);
    assert!(h.fake.containers().is_empty());
    assert!(load_state(&h.rec.paths().state).unwrap().apps.is_empty());
    assert!(matches!(
        h.rec.remove_app(&name("ntfy")).await,
        Err(crate::reconcile::EngineError::UnknownInstance(_))
    ));
}

const WITH_SECRET: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 1, window_secs = 1 }
secrets = [
  { secret = "config", kind = "mount", path = "/config.json" },
  { secret = "token", kind = "env", var = "TOKEN" },
]
"#;

#[tokio::test(start_paused = true)]
async fn secrets_are_materialized_and_change_recreates_immediately() {
    let h = Harness::new(WITH_SECRET);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    // No secrets: the instance is blocked with a clear reason, nothing is created.
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.actions.iter().all(|a| a.result.is_err()));
    assert!(h.fake.containers().is_empty());

    h.store.set("ntfy.config", SecretValue::new("{}")).unwrap();
    h.store.set("ntfy.token", SecretValue::new("t1")).unwrap();
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert!(h.fake.has_secret("ntfy.config") && h.fake.has_secret("ntfy.token"));

    // Value change → hash drift → recreate.
    h.store.set("ntfy.token", SecretValue::new("t2")).unwrap();
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.actions[0].action,
        Action::Recreate {
            instance: name("ntfy"),
            reason: RecreateReason::SpecDrift
        }
    );
    assert!(h.rec.reconcile().await.unwrap().actions.is_empty());
}

#[tokio::test(start_paused = true)]
async fn secret_change_waits_for_next_deploy_when_configured() {
    let h = Harness::with_policy(WITH_SECRET, SecretChangePolicy::NextDeploy);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.store.set("ntfy.config", SecretValue::new("{}")).unwrap();
    h.store.set("ntfy.token", SecretValue::new("t1")).unwrap();
    h.rec.reconcile().await.unwrap();

    h.store.set("ntfy.token", SecretValue::new("t2")).unwrap();
    assert!(h.rec.reconcile().await.unwrap().actions.is_empty());
    // The next deploy (forced here) recreates the container with the new secret.
    let creates = |h: &Harness| {
        h.fake
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::SecretCreate(_)))
            .count()
    };
    let before = creates(&h);
    assert!(matches!(
        h.rec.deploy(&name("ntfy"), true).await.unwrap(),
        DeployOutcome::Deployed { generation: 2, .. }
    ));
    assert_eq!(creates(&h), before + 2);
}

#[tokio::test(start_paused = true)]
async fn webhook_fans_out_to_tracking_instances_and_dedups() {
    let h = Harness::new(
        r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 1, window_secs = 1 }
[apps.ntfy-preview]
image = "ghcr.io/jpalczewski/ntfy.zig"
health = { attempts = 1, window_secs = 1 }
[apps.ntfy-v2]
image = "ghcr.io/jpalczewski/ntfy.zig:v2"
health = { attempts = 1, window_secs = 1 }
[apps.pinned]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
auto_update = false
health = { attempts = 1, window_secs = 1 }
[apps.other]
image = "ghcr.io/jpalczewski/other:latest"
health = { attempts = 1, window_secs = 1 }
"#,
    );
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake
        .set_pull_digest("ghcr.io/jpalczewski/ntfy.zig", digest('a'));
    h.fake
        .set_pull_digest("ghcr.io/jpalczewski/ntfy.zig:v2", digest('c'));
    h.fake
        .set_pull_digest("ghcr.io/jpalczewski/other:latest", digest('d'));
    h.rec.reconcile().await.unwrap();

    h.fake.set_pull_digest(IMAGE, digest('b'));
    h.fake
        .set_pull_digest("ghcr.io/jpalczewski/ntfy.zig", digest('b'));
    let ev = WebhookEvent {
        delivery_id: Some("d-1".into()),
        image_ref: IMAGE.into(),
    };
    let out = h.rec.handle_webhook(&ev).await.unwrap();
    assert!(!out.duplicate);
    assert_eq!(out.matched, vec![name("ntfy"), name("ntfy-preview")]);
    assert!(
        out.results
            .iter()
            .all(|(_, r)| matches!(r, Ok(DeployOutcome::Deployed { .. })))
    );
    assert_eq!(h.state("ntfy").current, Some(digest('b')));
    assert_eq!(h.state("ntfy-preview").current, Some(digest('b')));
    assert_eq!(h.state("ntfy-v2").current, Some(digest('c')));
    assert_eq!(h.state("pinned").current, Some(digest('a')));

    // Same delivery → duplicate, no calls.
    let calls = h.fake.calls().len();
    let dup = h.rec.handle_webhook(&ev).await.unwrap();
    assert!(dup.duplicate && dup.results.is_empty());
    assert_eq!(h.fake.calls().len(), calls);
    assert!(
        h.sink
            .events()
            .iter()
            .any(|e| matches!(e, Event::WebhookDuplicate { .. }))
    );

    // Without a delivery_id we do not dedupe (but deploy is idempotent: Unchanged).
    let anon = WebhookEvent {
        delivery_id: None,
        image_ref: IMAGE.into(),
    };
    let again = h.rec.handle_webhook(&anon).await.unwrap();
    assert!(
        again
            .results
            .iter()
            .all(|(_, r)| matches!(r, Ok(DeployOutcome::Unchanged { .. })))
    );
}

#[tokio::test(start_paused = true)]
async fn health_gate_polls_healthcheck_until_healthy() {
    let h = Harness::new(
        r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 5, window_secs = 10 }
"#,
    );
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health(
        "ntfy",
        [
            HealthStatus::Starting,
            HealthStatus::Unhealthy,
            HealthStatus::Healthy,
        ],
    );
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.fake
            .calls()
            .iter()
            .filter(|c| **c == Call::HealthcheckRun("ntfy".into()))
            .count(),
        3
    );
    assert_eq!(h.state("ntfy").current, Some(digest('a')));
}

#[tokio::test(start_paused = true)]
async fn run_loop_reconciles_on_start_on_trigger_and_periodically() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let (tx, rx) = mpsc::channel(4);
    let rec = h.rec.clone();
    let task = tokio::spawn(async move { rec.run(rx, Duration::from_secs(60)).await });

    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(h.fake.containers().len(), 1, "start reconcile");

    // After a state change: trigger, without waiting for the period.
    h.set_apps(&format!(
        "{NTFY}\n[apps.second]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\n"
    ));
    tx.send(Trigger::Changed).await.unwrap();
    tokio::time::sleep(Duration::from_secs(40)).await; // default gate: 30 s
    assert_eq!(h.fake.containers().len(), 2);

    // Periodically: a removed container comes back after the period elapses.
    h.fake.container_remove("second", true).await.unwrap();
    tokio::time::sleep(Duration::from_secs(150)).await;
    assert_eq!(h.fake.containers().len(), 2);

    drop(tx);
    task.await.unwrap();
    let _ = &h.dir;
}

// ── Iteration 2: limits, health.command, health.http ────────────────────────────

use crate::app::HttpProbe;
use crate::limits::{HttpProber, ProbeFuture};
use std::sync::Mutex;

/// Prober that answers from a script (last result repeats) and records the hosts it was asked for.
struct ScriptedProber {
    script: Mutex<std::collections::VecDeque<Result<(), String>>>,
    hosts: Mutex<Vec<String>>,
}

impl ScriptedProber {
    fn new(results: impl IntoIterator<Item = Result<(), String>>) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(results.into_iter().collect()),
            hosts: Mutex::default(),
        })
    }
}

impl HttpProber for ScriptedProber {
    fn probe<'a>(&'a self, host: &'a str, _probe: &'a HttpProbe) -> ProbeFuture<'a> {
        self.hosts.lock().unwrap().push(host.to_owned());
        let mut script = self.script.lock().unwrap();
        let r = if script.len() > 1 {
            script.pop_front().unwrap()
        } else {
            script.front().cloned().unwrap_or(Ok(()))
        };
        Box::pin(async move { r })
    }
}

const WHOAMI: &str = r#"
[apps.who]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 80
domains = ["who.example.com", "alias.example.com"]
resources = { memory = "256m", pids_limit = 100, cpus = 0.5 }
health = { attempts = 3, window_secs = 6, command = ["/app", "-health"], http = { path = "/up" } }
"#;

fn with_prober(h: &mut Harness, prober: Arc<ScriptedProber>) {
    let rec = Arc::get_mut(&mut h.rec).expect("sole owner");
    rec.http_prober = Some(prober);
}

#[tokio::test(start_paused = true)]
async fn spec_limits_and_healthcheck_reach_the_container_and_both_probes_must_pass() {
    let mut h = Harness::new(WHOAMI);
    let prober = ScriptedProber::new([Err("status 503".into()), Ok(())]);
    with_prober(&mut h, prober.clone());
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health("who", [HealthStatus::Healthy]);
    let out = h.rec.deploy(&name("who"), false).await.unwrap();
    assert!(matches!(out, DeployOutcome::Deployed { .. }), "{out:?}");
    // Attempt 1: command healthy but http 503 → retry; attempt 2: both pass.
    assert_eq!(*prober.hosts.lock().unwrap(), ["who.example.com"; 2]);

    let spec = h.fake.container_spec("who").unwrap();
    assert_eq!(spec.resources.pids_limit, Some(100));
    assert_eq!(spec.resources.memory.unwrap().bytes(), 256 << 20);
    assert_eq!(spec.resources.cpus.unwrap().millis(), 500);
    assert_eq!(spec.healthcheck.unwrap().command, ["/app", "-health"]);
}

#[tokio::test(start_paused = true)]
async fn failing_http_probe_fails_the_gate_even_when_the_command_is_healthy() {
    let mut h = Harness::new(WHOAMI);
    with_prober(&mut h, ScriptedProber::new([Err("status 502".into())]));
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health("who", [HealthStatus::Healthy]);
    let out = h.rec.deploy(&name("who"), false).await.unwrap();
    assert!(
        matches!(&out, DeployOutcome::Failed { reason, .. } if reason.contains("status 502")),
        "{out:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn failing_command_fails_the_gate_even_when_http_passes() {
    let mut h = Harness::new(WHOAMI);
    with_prober(&mut h, ScriptedProber::new([Ok(())]));
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health("who", [HealthStatus::Unhealthy]);
    let out = h.rec.deploy(&name("who"), false).await.unwrap();
    assert!(
        matches!(&out, DeployOutcome::Failed { reason, .. } if reason.contains("Unhealthy")),
        "{out:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn http_only_gate_does_not_pass_on_merely_running() {
    let apps = r#"
[apps.who]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 80
domains = ["who.example.com"]
health = { attempts = 2, window_secs = 4, http = {} }
"#;
    let mut h = Harness::new(apps);
    with_prober(&mut h, ScriptedProber::new([Err("timeout".into())]));
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let out = h.rec.deploy(&name("who"), false).await.unwrap();
    assert!(matches!(out, DeployOutcome::Failed { .. }), "{out:?}");
    // No healthcheck exists, so the engine must not have called `healthcheck run` at all.
    assert!(
        !h.fake
            .calls()
            .iter()
            .any(|c| matches!(c, Call::HealthcheckRun(_)))
    );
}

#[tokio::test(start_paused = true)]
async fn http_probe_without_a_prober_fails_closed() {
    let h = Harness::new(WHOAMI);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health("who", [HealthStatus::Healthy]);
    let out = h.rec.deploy(&name("who"), false).await.unwrap();
    assert!(
        matches!(&out, DeployOutcome::Failed { reason, .. } if reason.contains("prober")),
        "{out:?}"
    );
}
