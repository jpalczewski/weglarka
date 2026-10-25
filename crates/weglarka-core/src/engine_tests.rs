//! Engine tests (reconcile + deploy + secrets) on `FakePodman`. Virtual time (`start_paused`),
//! so the health gate does not really wait.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::mpsc;

use crate::app::{Digest, InstanceName};
use crate::crash;
use crate::deploy::{DeployOutcome, ReloadOutcome};
use crate::events::{Event, VecSink};
use crate::labels;
use crate::podman::{
    BindMount, ContainerState, HealthStatus, NetworkSpec, PodmanClient, PortMapping, RegistryAuth,
};
use crate::reconcile::{
    Action, ActionOutcome, ActivityKind, EngineError, ReconcileReport, Reconciler,
    ReconcilerOptions, RecreateReason, SecretChangePolicy, Trigger,
};
use crate::secret_store::{SecretError, SecretStore, SecretValue};
use crate::secrets::FileSecretStore;
use crate::state::{StatePaths, load_state};
use crate::testing::{Call, DEFAULT_IMAGE_SIZE_BYTES, FakePodman};
use crate::volumes::RemoveAppOptions;
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
        Self::with_options(
            apps_toml,
            ReconcilerOptions {
                secret_change: policy,
                ..Default::default()
            },
        )
    }

    /// Harness with failure detection enabled at `monitor` (the crash-loop / health scenarios).
    fn with_monitor(apps_toml: &str, monitor: crash::Policy) -> Self {
        Self::build(apps_toml, ReconcilerOptions::default(), monitor)
    }

    /// Harness with explicit reconciler options (e.g. a `config_root`, issue #118).
    fn with_options(apps_toml: &str, options: ReconcilerOptions) -> Self {
        Self::build(apps_toml, options, crash::Policy::disabled())
    }

    fn build(apps_toml: &str, options: ReconcilerOptions, monitor: crash::Policy) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::in_dir(dir.path());
        std::fs::write(&paths.apps, apps_toml).unwrap();
        let fake = FakePodman::new();
        let store = Arc::new(FileSecretStore::new(dir.path().join("secrets.toml")));
        let sink = Arc::new(VecSink::default());
        let secrets: Arc<dyn SecretStore> = store.clone();
        let rec = Arc::new(
            Reconciler::new(fake.clone(), secrets, paths, options)
                .with_events(sink.clone())
                .with_monitor(monitor),
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

/// `start = false`: provisioned only, no container is created/started.
const PROVISION_ONLY: &str = r#"
[apps.gate]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
start = false
volumes = [{ name = "data", target = "/data" }]
"#;

/// `start = false` binds a secret that is not set: that must not block provisioning.
const STOPPED_WITH_SECRET: &str = r#"
[apps.gate]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
start = false
secrets = [{ secret = "token", kind = "env", var = "TOKEN" }]
"#;

/// Running app with a volume, used to check that flipping `start` off keeps the data.
const RUNNING_WITH_VOLUME: &str = r#"
[apps.gate]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
volumes = [{ name = "data", target = "/data" }]
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

/// `doctor` reads the engine to tell a deploy from drift (issue #30): while a deploy runs, the
/// instance is reported as in flight; the guard clears it on every exit path.
#[tokio::test(start_paused = true)]
async fn in_flight_is_visible_during_a_deploy() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let rec = h.rec.clone();
    let instance = name("ntfy");
    let deploy = tokio::spawn({
        let instance = instance.clone();
        async move { rec.deploy(&instance, false).await }
    });

    // Let the deploy reach the health gate (a real await) and look at the engine from the outside.
    let mut seen = None;
    for _ in 0..1000 {
        tokio::task::yield_now().await;
        if let Some(activity) = h.rec.in_flight() {
            seen = Some(activity);
            break;
        }
    }
    let activity = seen.expect("a running deploy must be visible as in flight");
    assert_eq!(activity.instance, instance);
    assert_eq!(activity.kind, ActivityKind::Deploy);

    let outcome = deploy.await.unwrap().unwrap();
    assert!(matches!(outcome, DeployOutcome::Deployed { .. }));
    assert!(h.rec.in_flight().is_none(), "cleared after the deploy");
}

#[tokio::test(start_paused = true)]
async fn in_flight_is_cleared_when_the_deploy_fails() {
    let h = Harness::new(NTFY);
    h.fake.fail_pull(IMAGE, "registry down");
    assert!(h.rec.deploy(&name("ntfy"), false).await.is_err());
    assert!(
        h.rec.in_flight().is_none(),
        "a failed deploy must not leave the instance in flight"
    );
}

#[tokio::test(start_paused = true)]
async fn start_false_provisions_without_a_container() {
    let h = Harness::new(PROVISION_ONLY);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    let report = h.rec.reconcile().await.unwrap();
    assert!(matches!(
        single(&report),
        ActionOutcome::Provisioned(DeployOutcome::Provisioned { .. })
    ));
    assert!(
        h.fake.containers().is_empty(),
        "start = false means no container"
    );
    let gate = name("gate");
    assert_eq!(h.fake.networks(), vec![labels::network_name(&gate)]);
    let volumes: Vec<String> = h.fake.volumes().into_iter().map(|v| v.name).collect();
    assert_eq!(volumes, vec![labels::volume_name(&gate, "data")]);
    let st = h.state("gate");
    assert_eq!(st.current, Some(digest('a')));
    assert!(st.uid_range.is_some());

    // Idempotent: the next pass has nothing to do and does not pull again.
    let pulls = |h: &Harness| {
        h.fake
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::ImagePull(_)))
            .count()
    };
    let before = pulls(&h);
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.actions.is_empty(), "{:?}", report.actions);
    assert!(report.is_clean());
    assert_eq!(pulls(&h), before);
}

#[tokio::test(start_paused = true)]
async fn deploy_honours_start_false_and_needs_no_secrets() {
    let h = Harness::new(STOPPED_WITH_SECRET);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    let outcome = h.rec.deploy(&name("gate"), false).await.unwrap();
    assert!(matches!(outcome, DeployOutcome::Provisioned { .. }));
    assert!(h.fake.containers().is_empty());
    assert_eq!(h.state("gate").current, Some(digest('a')));
}

#[tokio::test(start_paused = true)]
async fn start_false_with_unset_secrets_does_not_wait() {
    let h = Harness::new(STOPPED_WITH_SECRET);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean());
    assert!(report.waiting.is_empty(), "{:?}", report.waiting);
    assert!(h.state("gate").waiting_for_secrets.is_empty());
    assert!(matches!(single(&report), ActionOutcome::Provisioned(_)));
}

#[tokio::test(start_paused = true)]
async fn start_after_provision_starts_from_the_pinned_digest() {
    let h = Harness::new(PROVISION_ONLY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap(); // provision only
    h.set_apps(&PROVISION_ONLY.replace("start = false", "start = true"));

    let report = h.rec.reconcile().await.unwrap();
    assert!(matches!(
        single(&report),
        ActionOutcome::Recreated(DeployOutcome::Deployed { .. })
    ));
    let containers = h.fake.containers();
    assert_eq!(containers.len(), 1);
    assert_eq!(containers[0].state, ContainerState::Running);
    assert!(h.state("gate").generation > 0);
}

#[tokio::test(start_paused = true)]
async fn flipping_start_off_removes_the_container_and_keeps_the_data() {
    let h = Harness::new(RUNNING_WITH_VOLUME);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap(); // deploy
    assert_eq!(h.fake.containers().len(), 1);

    h.set_apps(&RUNNING_WITH_VOLUME.replace("port = 8085", "port = 8085\nstart = false"));
    let report = h.rec.reconcile().await.unwrap();
    assert!(matches!(single(&report), ActionOutcome::Provisioned(_)));
    assert!(h.fake.containers().is_empty());
    let st = h.state("gate");
    assert_eq!(st.current, Some(digest('a')));
    assert!(st.uid_range.is_some());
    assert_eq!(h.fake.volumes().len(), 1, "the volume and its data stay");
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
    h.fake.forget_image_reference(&pinned);
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

/// Per-app registry credentials (docs/decisions/0026): `<instance>.registry-auth` is sent on every
/// pull of that app; without it the registry's 401 becomes a `RegistryAuth` error that names the
/// secret, and nothing is created.
#[tokio::test(start_paused = true)]
async fn private_image_pulls_with_the_apps_registry_auth_secret() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let creds = RegistryAuth::new("ci", "tok:en");
    h.fake.require_pull_auth(IMAGE, creds.clone());

    // No secret: the registry answers 401 → actionable error, no container, a DeployFailed event.
    let err = h.rec.deploy(&name("ntfy"), false).await.unwrap_err();
    assert!(
        matches!(
            &err,
            EngineError::RegistryAuth {
                sent_credentials: false,
                ..
            }
        ),
        "{err:?}"
    );
    let text = err.to_string();
    assert!(
        text.contains("ntfy.registry-auth") || text.contains("secrets set ntfy registry-auth"),
        "{text}"
    );
    assert!(h.fake.containers().is_empty());
    assert!(
        h.sink
            .events()
            .iter()
            .any(|e| matches!(e, Event::DeployFailed { .. }))
    );

    // Wrong credentials: rejected, reported as such, and the value is nowhere in the message.
    h.store
        .set("ntfy.registry-auth", SecretValue::new("ci:wrong"))
        .unwrap();
    let err = h.rec.deploy(&name("ntfy"), false).await.unwrap_err();
    assert!(
        matches!(
            &err,
            EngineError::RegistryAuth {
                sent_credentials: true,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(!err.to_string().contains("wrong"));

    // Right credentials: the pull succeeds and the same value is what was sent.
    h.store
        .set("ntfy.registry-auth", SecretValue::new("ci:tok:en"))
        .unwrap();
    h.rec.deploy(&name("ntfy"), false).await.unwrap();
    assert_eq!(h.state("ntfy").current, Some(digest('a')));
    let log = h.fake.pull_auth_log();
    assert_eq!(log.last().unwrap(), &(IMAGE.to_owned(), Some(creds)));
    // The reserved secret is never materialized as a Podman secret.
    assert!(!h.fake.has_secret("ntfy.registry-auth"));
}

#[tokio::test(start_paused = true)]
async fn malformed_registry_auth_secret_fails_instead_of_pulling_anonymously() {
    let h = Harness::new(NTFY);
    h.store
        .set("ntfy.registry-auth", SecretValue::new("no-colon-here"))
        .unwrap();
    let err = h.rec.deploy(&name("ntfy"), false).await.unwrap_err();
    assert!(
        matches!(&err, EngineError::Secret(SecretError::Malformed { .. })),
        "{err:?}"
    );
    assert!(!err.to_string().contains("no-colon-here"));
    assert!(h.fake.pull_auth_log().is_empty(), "no pull was attempted");
}

#[test]
fn registry_auth_secret_cannot_be_bound_to_a_container() {
    let apps = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
secrets = [{ secret = "registry-auth", kind = "env", var = "X" }]
"#;
    let file: crate::app::AppsFile = toml::from_str(apps).unwrap();
    let err = crate::state::validate_app(&name("ntfy"), &file.apps[&name("ntfy")]).unwrap_err();
    assert!(err.contains("reserved"), "{err}");
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

/// `host_ports` reach libpod through `ContainerSpec.publish` (loopback unless the spec names an
/// address) and a change recreates the container — they are part of the spec hash (ADR 0013).
#[tokio::test(start_paused = true)]
async fn host_ports_are_published_and_a_change_recreates() {
    const WITH_PORTS: &str = r#"
[apps.git]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
domains = ["git.example.eu"]
host_ports = [{ host = 2222, container = 22 }]
"#;
    let h = Harness::new(WITH_PORTS);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    let publish = |h: &Harness| {
        h.fake
            .container_spec("git")
            .expect("the container exists")
            .publish
    };
    assert_eq!(
        publish(&h),
        vec![PortMapping {
            host_ip: Some("127.0.0.1".into()),
            host_port: 2222,
            container_port: 22,
        }]
    );

    // Exposing the port publicly is a different container.
    h.set_apps(&WITH_PORTS.replace(
        "host_ports = [{ host = 2222, container = 22 }]",
        "host_ports = [{ host = 2222, container = 22, ip = \"0.0.0.0\" }]",
    ));
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.actions[0].action,
        Action::Recreate {
            instance: name("git"),
            reason: RecreateReason::SpecDrift
        }
    );
    assert_eq!(publish(&h)[0].host_ip.as_deref(), Some("0.0.0.0"));
}

/// `command` reaches libpod through `ContainerSpec.command` (arguments to the image's entrypoint) and
/// a change recreates the container — it is part of the spec hash (issue #79).
#[tokio::test(start_paused = true)]
async fn command_reaches_the_container_and_a_change_recreates() {
    const NTFY: &str = r#"
[apps.ntfy]
image = "docker.io/binwiederhier/ntfy:latest"
port = 80
domains = ["ntfy.example.eu"]
"#;
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    let command = |h: &Harness| {
        h.fake
            .container_spec("ntfy")
            .expect("the container exists")
            .command
    };
    assert!(command(&h).is_empty(), "no command = the image's own CMD");

    // An image with only an ENTRYPOINT needs its subcommand as an argument.
    h.set_apps(&NTFY.replace("port = 80", "port = 80\ncommand = [\"serve\"]"));
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.actions[0].action,
        Action::Recreate {
            instance: name("ntfy"),
            reason: RecreateReason::SpecDrift
        }
    );
    assert_eq!(command(&h), ["serve"]);

    // The argument vector is ordered, so a different order is a different container.
    h.set_apps(&NTFY.replace(
        "port = 80",
        "port = 80\ncommand = [\"serve\", \"--no-log\"]",
    ));
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.actions[0].action,
        Action::Recreate {
            instance: name("ntfy"),
            reason: RecreateReason::SpecDrift
        }
    );
    assert_eq!(command(&h), ["serve", "--no-log"]);
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

#[tokio::test(start_paused = true)]
async fn removed_app_network_is_cleaned_up_but_other_networks_stay() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    assert!(h.fake.networks().contains(&"net-ntfy".to_owned()));
    // Not ours (no Węglarka label) and Węglarka's own network: both must survive the cleanup.
    for (net, labels) in [
        ("net-foreign", BTreeMap::new()),
        (
            crate::labels::INGRESS_NETWORK,
            BTreeMap::from([("weglarka.managed".to_owned(), "ingress".to_owned())]),
        ),
    ] {
        h.fake
            .network_create(&NetworkSpec {
                name: net.to_owned(),
                internal: false,
                labels,
            })
            .await
            .unwrap();
    }

    h.rec.remove_app(&name("ntfy")).await.unwrap();
    h.rec.reconcile().await.unwrap();
    let nets = h.fake.networks();
    assert!(!nets.contains(&"net-ntfy".to_owned()), "{nets:?}");
    assert!(nets.contains(&"net-foreign".to_owned()));
    assert!(nets.contains(&crate::labels::INGRESS_NETWORK.to_owned()));
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

    // No secrets: the instance waits, nothing is attempted or created.
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.actions.is_empty(), "{report:?}");
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
async fn missing_secrets_mean_waiting_not_failure_and_setting_them_deploys() {
    let h = Harness::new(WITH_SECRET);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "waiting is not a problem: {report:?}");
    assert!(report.actions.is_empty() && h.fake.containers().is_empty());
    assert_eq!(
        report.waiting,
        vec![(name("ntfy"), vec!["config".to_owned(), "token".to_owned()])]
    );
    assert_eq!(h.state("ntfy").waiting_for_secrets, ["config", "token"]);
    assert!(
        !h.fake
            .calls()
            .iter()
            .any(|c| matches!(c, Call::ImagePull(_)))
    );

    // Logged once on entering the state, not on every pass; never as a failure.
    h.rec.reconcile().await.unwrap();
    let events = h.sink.events();
    let waits = events
        .iter()
        .filter(|e| matches!(e, Event::WaitingForSecret { .. }))
        .count();
    assert_eq!(waits, 1, "{events:?}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::DeployFailed { .. }))
    );

    // A manual deploy does not try either; it reports what is missing.
    let err = h.rec.deploy(&name("ntfy"), false).await.unwrap_err();
    assert!(
        matches!(&err, EngineError::MissingSecrets(m) if m.len() == 2),
        "{err:?}"
    );

    // One of two set: still waiting, for the other one.
    h.store.set("ntfy.config", SecretValue::new("{}")).unwrap();
    h.rec.reconcile().await.unwrap();
    assert_eq!(h.state("ntfy").waiting_for_secrets, ["token"]);
    assert!(h.fake.containers().is_empty());

    // The last one: the wait clears and the deploy starts by itself.
    h.store.set("ntfy.token", SecretValue::new("t")).unwrap();
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean() && report.waiting.is_empty(), "{report:?}");
    assert!(matches!(
        single(&report),
        ActionOutcome::Deployed(DeployOutcome::Deployed { .. })
    ));
    let st = h.state("ntfy");
    assert!(st.waiting_for_secrets.is_empty() && st.failed.is_none());
}

const BOUND_SECRET: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 1, window_secs = 1 }
secrets = [{ secret = "token", kind = "env", var = "TOKEN" }]
"#;

/// Issue #80: a secret the spec still binds is refused without `force` (nothing is touched); with
/// `force` it is gone and the app waits for it — its running container is left alone.
#[tokio::test(start_paused = true)]
async fn removing_a_bound_secret_needs_force_and_leaves_the_container_running() {
    let h = Harness::new(BOUND_SECRET);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.store.set("ntfy.token", SecretValue::new("t1")).unwrap();
    h.rec.reconcile().await.unwrap();
    assert_eq!(h.fake.containers().len(), 1);

    let err = h
        .rec
        .remove_secret(&name("ntfy"), "token", false)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, EngineError::SecretInUse { name: inst, secret }
            if inst == &name("ntfy") && secret == "token"),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "secret token is still bound by the spec of ntfy; unbind it first or pass --force"
    );
    assert!(
        h.store.get("ntfy.token").unwrap().is_some(),
        "a refused removal touches the store"
    );

    h.rec
        .remove_secret(&name("ntfy"), "token", true)
        .await
        .unwrap();
    assert!(h.store.get("ntfy.token").unwrap().is_none());

    // The next pass reports waiting and leaves the container (still holding the old value) in place.
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.actions.is_empty(), "{report:?}");
    assert_eq!(
        report.waiting,
        vec![(name("ntfy"), vec!["token".to_owned()])]
    );
    assert_eq!(h.state("ntfy").waiting_for_secrets, ["token"]);
    assert_eq!(h.fake.containers().len(), 1);
}

const TWO_APPS_WITH_SECRETS: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 1, window_secs = 1 }
secrets = [
  { secret = "config", kind = "mount", path = "/config.json" },
  { secret = "token", kind = "env", var = "TOKEN" },
]
[apps.other]
image = "ghcr.io/x/other:latest"
health = { attempts = 1, window_secs = 1 }
secrets = [{ secret = "key", kind = "env", var = "KEY" }]
"#;

/// Issue #80: `apps remove --purge-secrets` deletes the whole `<instance>.*` scope (unbound
/// `webhook-hmac` included) and nothing of another app. Re-adding the app under the same name with
/// the same binding then waits for the secret instead of deploying the stale value.
#[tokio::test(start_paused = true)]
async fn purge_secrets_drops_only_the_instances_scope_and_a_readded_app_waits() {
    let h = Harness::new(TWO_APPS_WITH_SECRETS);
    for (key, value) in [
        ("ntfy.config", "{}"),
        ("ntfy.token", "t1"),
        // Set lazily by the webhook flow and not bound by the spec: still part of the scope.
        ("ntfy.webhook-hmac", "hmac"),
        ("other.key", "k1"),
    ] {
        h.store.set(key, SecretValue::new(value)).unwrap();
    }
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(h.fake.containers().len(), 2);

    h.rec
        .remove_app_with_purges(
            &name("ntfy"),
            RemoveAppOptions {
                purge_volumes: false,
                purge_secrets: true,
            },
        )
        .await
        .unwrap();
    let names: Vec<String> = h
        .store
        .list()
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(names, ["other.key"], "only the instance's scope is gone");
    assert!(
        !crate::state::load_apps(&h.rec.paths().apps)
            .unwrap()
            .apps
            .contains_key(&name("ntfy"))
    );

    // Re-adding the app: the bindings have no values any more, so it waits — the stale secret is not
    // silently reused (plain `apps remove` keeps secrets, `--purge-secrets` does not).
    h.set_apps(TWO_APPS_WITH_SECRETS);
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert!(report.actions.is_empty(), "{report:?}");
    assert_eq!(
        report.waiting,
        vec![(name("ntfy"), vec!["config".to_owned(), "token".to_owned()])]
    );
    assert!(h.fake.container_spec("ntfy").is_some(), "left alone");
}

/// Issue #80: `secrets remove` needs no app in `apps.toml` — that is how leftovers of a renamed or
/// removed instance are cleaned up. An absent secret is `SecretError::NotFound`.
#[tokio::test(start_paused = true)]
async fn remove_secret_works_for_an_app_absent_from_apps_toml() {
    let h = Harness::new(NTFY);
    h.store.set("ntfy.token", SecretValue::new("t1")).unwrap();
    h.store.set("gone.old", SecretValue::new("v")).unwrap();

    h.rec
        .remove_secret(&name("gone"), "old", false)
        .await
        .unwrap();
    assert!(h.store.get("gone.old").unwrap().is_none());
    assert!(
        h.store.get("ntfy.token").unwrap().is_some(),
        "another scope is untouched"
    );

    // Leftovers of a removed app as well (`apps remove` keeps secrets by default).
    h.rec.remove_app(&name("ntfy")).await.unwrap();
    h.rec
        .remove_secret(&name("ntfy"), "token", false)
        .await
        .unwrap();
    assert!(h.store.get("ntfy.token").unwrap().is_none());

    let err = h
        .rec
        .remove_secret(&name("ntfy"), "token", false)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            EngineError::Secret(crate::secret_store::SecretError::NotFound(_))
        ),
        "{err:?}"
    );
}

/// Issue #80: purging an app that is not in `apps.toml` fails before any purge runs — neither the
/// secrets of another scope nor `apps.toml` are touched.
#[tokio::test(start_paused = true)]
async fn purge_of_an_unknown_app_errors_and_touches_state_nor_secrets() {
    let h = Harness::new(NTFY);
    h.store.set("ntfy.token", SecretValue::new("t1")).unwrap();
    h.store.set("nope.left", SecretValue::new("v")).unwrap();
    let apps_before = std::fs::read(&h.rec.paths().apps).unwrap();

    let err = h
        .rec
        .remove_app_with_purges(
            &name("nope"),
            RemoveAppOptions {
                purge_volumes: true,
                purge_secrets: true,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::UnknownInstance(_)), "{err:?}");
    assert_eq!(
        std::fs::read(&h.rec.paths().apps).unwrap(),
        apps_before,
        "apps.toml is untouched"
    );
    assert!(
        h.store.get("nope.left").unwrap().is_some(),
        "the secret purge is not reached"
    );
}

#[tokio::test(start_paused = true)]
async fn new_secret_binding_on_a_running_app_keeps_the_old_container() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    let before = h.container_digest_ref("ntfy");

    h.set_apps(WITH_SECRET);
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.actions.is_empty() && report.is_clean(), "{report:?}");
    assert_eq!(h.state("ntfy").waiting_for_secrets, ["config", "token"]);
    assert_eq!(h.container_digest_ref("ntfy"), before);

    h.store.set("ntfy.config", SecretValue::new("{}")).unwrap();
    h.store.set("ntfy.token", SecretValue::new("t")).unwrap();
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.actions[0].action,
        Action::Recreate {
            instance: name("ntfy"),
            reason: RecreateReason::SpecDrift
        }
    );
    assert!(h.state("ntfy").waiting_for_secrets.is_empty());
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

/// Issue #41: handled delivery ids survive a restart — a fresh engine over the same state directory
/// answers a redelivery as a duplicate and does not pull (self-update makes restarts routine).
#[tokio::test(start_paused = true)]
async fn webhook_dedup_survives_daemon_restart() {
    let h = Harness::new(
        r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 1, window_secs = 1 }
"#,
    );
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    let event = WebhookEvent {
        delivery_id: Some("restart-1".into()),
        image_ref: IMAGE.into(),
    };
    h.fake.set_pull_digest(IMAGE, digest('b'));
    assert!(!h.rec.handle_webhook(&event).await.unwrap().duplicate);

    // "Restart": a new engine (empty in-memory set) over the same state directory.
    let restarted = Reconciler::new(
        h.fake.clone(),
        h.store.clone(),
        h.rec.paths().clone(),
        ReconcilerOptions::default(),
    )
    .with_events(h.sink.clone())
    .with_monitor(crash::Policy::disabled());
    let calls = h.fake.calls().len();
    let dup = restarted.handle_webhook(&event).await.unwrap();
    assert!(dup.duplicate && dup.results.is_empty());
    assert_eq!(
        h.fake.calls().len(),
        calls,
        "a redelivery after a restart must not pull"
    );
    assert!(
        h.sink
            .events()
            .iter()
            .any(|e| matches!(e, Event::WebhookDuplicate { .. }))
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
    paths: Mutex<Vec<String>>,
}

impl ScriptedProber {
    fn new(results: impl IntoIterator<Item = Result<(), String>>) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(results.into_iter().collect()),
            hosts: Mutex::default(),
            paths: Mutex::default(),
        })
    }
}

impl HttpProber for ScriptedProber {
    fn probe<'a>(&'a self, host: &'a str, probe: &'a HttpProbe) -> ProbeFuture<'a> {
        self.hosts.lock().unwrap().push(host.to_owned());
        self.paths.lock().unwrap().push(probe.path.clone());
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
async fn http_probe_requests_the_apps_path_prefix() {
    let apps = r#"
[apps.who]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 80
domains = ["who.example.com"]
paths = ["/api", "/healthz"]
health = { attempts = 1, window_secs = 2, http = { path = "/up" } }
"#;
    let mut h = Harness::new(apps);
    let prober = ScriptedProber::new([Ok(())]);
    with_prober(&mut h, prober.clone());
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let out = h.rec.deploy(&name("who"), false).await.unwrap();
    assert!(matches!(out, DeployOutcome::Deployed { .. }), "{out:?}");
    // Through nginx a shared domain is routed by prefix: the probe must carry the app's own.
    assert_eq!(*prober.paths.lock().unwrap(), ["/api/up"]);
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

// ── depends_on: start order and the dependency gate (issue #35) ─────────────────

/// `db` + `api`, where `api` must start after `db`.
const DEPENDS: &str = r#"
[apps.api]
image = "ghcr.io/x/api:latest"
depends_on = ["db"]

[apps.db]
image = "ghcr.io/x/db:latest"
"#;

fn first_call(calls: &[Call], needle: Call) -> Option<usize> {
    calls.iter().position(|c| *c == needle)
}

#[tokio::test(start_paused = true)]
async fn depends_on_starts_dependencies_first() {
    let h = Harness::new(DEPENDS);
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert!(report.waiting_for_dependencies.is_empty(), "{report:?}");

    let calls = h.fake.calls();
    let db = first_call(&calls, Call::ContainerCreate("db".into())).expect("db created");
    let api = first_call(&calls, Call::ContainerCreate("api".into())).expect("api created");
    assert!(db < api, "db must be created before api: {calls:?}");
    assert!(h.state("db").current.is_some());
    assert!(h.state("api").current.is_some());
}

#[tokio::test(start_paused = true)]
async fn a_failed_dependency_leaves_the_dependent_waiting_not_failed() {
    let h = Harness::new(
        r#"
[apps.api]
image = "ghcr.io/x/api:latest"
depends_on = ["db"]

[apps.db]
image = "ghcr.io/x/db:latest"
health = { attempts = 1, window_secs = 1 }
"#,
    );
    h.fake.script_health("db", [HealthStatus::Unhealthy]);
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.waiting_for_dependencies,
        vec![(name("api"), vec![name("db")])],
        "{report:?}"
    );
    assert!(
        h.state("api").failed.is_none(),
        "a broken dependency is not the app's failed deploy"
    );
    assert!(h.state("api").current.is_none());
    assert!(h.fake.containers().iter().all(|c| c.name != "api"));

    // Once the dependency deploys, the dependent follows on the next pass.
    h.fake.script_health("db", [HealthStatus::Healthy]);
    h.rec.deploy(&name("db"), true).await.unwrap();
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert!(h.state("api").current.is_some());
}

#[tokio::test(start_paused = true)]
async fn a_provision_only_dependency_keeps_the_dependent_waiting() {
    let h = Harness::new(
        r#"
[apps.api]
image = "ghcr.io/x/api:latest"
depends_on = ["db"]

[apps.db]
image = "ghcr.io/x/db:latest"
start = false
"#,
    );
    let report = h.rec.reconcile().await.unwrap();
    assert_eq!(
        report.waiting_for_dependencies,
        vec![(name("api"), vec![name("db")])],
        "{report:?}"
    );
    // `start = false` app stays "not started" by design: provisioned (digest pinned), no container.
    assert!(h.state("api").current.is_none());
    assert!(h.state("api").failed.is_none());
    assert!(h.state("db").current.is_some());
    assert!(h.fake.containers().iter().all(|c| c.name != "db"));
}

#[tokio::test(start_paused = true)]
async fn the_gate_polls_a_starting_dependency_before_starting_the_dependent() {
    let h = Harness::new(
        r#"
[apps.api]
image = "ghcr.io/x/api:latest"
depends_on = ["db"]
health = { command = ["/app", "-health"], attempts = 1, window_secs = 1 }

[apps.db]
image = "ghcr.io/x/db:latest"
health = { command = ["/app", "-health"], attempts = 1, window_secs = 1 }
"#,
    );
    h.fake.script_health("db", [HealthStatus::Healthy]);
    h.fake.script_health("api", [HealthStatus::Healthy]);
    h.rec.reconcile().await.unwrap();

    // Both crash; the next pass starts `db` first, and `api`'s gate has to poll `db` to health.
    h.fake.crash_container("db", 1);
    h.fake.crash_container("api", 1);
    h.fake
        .script_health("db", [HealthStatus::Starting, HealthStatus::Healthy]);
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");

    let calls = h.fake.calls();
    let api_start = calls
        .iter()
        .rposition(|c| *c == Call::ContainerStart("api".into()))
        .expect("api started");
    assert_eq!(
        calls[api_start - 1],
        Call::HealthcheckRun("db".into()),
        "the last thing before starting api is the dependency's health: {calls:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_manual_deploy_is_refused_while_the_dependency_is_down() {
    let h = Harness::new(DEPENDS);
    h.rec.reconcile().await.unwrap();
    h.fake.crash_container("db", 1);
    let err = h.rec.deploy(&name("api"), true).await.unwrap_err();
    assert!(
        matches!(&err, EngineError::DependenciesNotReady { pending, .. }
            if pending.iter().any(|(dep, _)| dep == &name("db"))),
        "{err:?}"
    );
    // Nothing was touched: the dependent still has its previous container and state.
    assert!(h.state("api").current.is_some());
    assert!(
        h.fake
            .containers()
            .iter()
            .any(|c| c.name == "api" && c.state == ContainerState::Running)
    );
}

#[tokio::test(start_paused = true)]
async fn replacing_a_running_container_is_not_blocked_by_its_dependency() {
    let h = Harness::new(DEPENDS);
    h.rec.reconcile().await.unwrap();
    let creates = |h: &Harness| {
        h.fake
            .calls()
            .iter()
            .filter(|c| **c == Call::ContainerCreate("api".into()))
            .count()
    };
    assert_eq!(creates(&h), 1);

    // `db` becomes provision-only (its container is removed) and `api` gets a spec change. Replacing
    // a container that is already running is not a start, so the gate must not block the recreate.
    let apps = DEPENDS.replace(
        "[apps.db]\nimage = \"ghcr.io/x/db:latest\"\n",
        "[apps.db]\nimage = \"ghcr.io/x/db:latest\"\nstart = false\n",
    );
    let apps = apps.replace(
        "depends_on = [\"db\"]",
        "depends_on = [\"db\"]\nenv = { A = \"1\" }",
    );
    h.set_apps(&apps);
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert!(report.waiting_for_dependencies.is_empty(), "{report:?}");
    assert_eq!(
        creates(&h),
        2,
        "api was recreated despite the dependency being down"
    );
}

#[tokio::test(start_paused = true)]
async fn removing_a_dependency_is_refused() {
    let h = Harness::new(DEPENDS);
    let err = h.rec.remove_app(&name("db")).await.unwrap_err();
    assert!(
        matches!(&err, EngineError::DependencyInUse { dependents, .. }
            if dependents == &vec![name("api")]),
        "{err:?}"
    );
    let apps = crate::state::load_apps(&h.rec.paths().apps).unwrap();
    assert!(apps.apps.contains_key(&name("db")), "nothing was removed");

    h.rec.remove_app(&name("api")).await.unwrap();
    h.rec.remove_app(&name("db")).await.unwrap();
}

/// Retention of 1 (issue #40): with `current` and `previous` saved, a successful deploy removes the
/// app's older images — and nothing else.
#[tokio::test(start_paused = true)]
async fn deploy_keeps_only_the_current_and_the_previous_image() {
    let h = Harness::new(NTFY);
    let ntfy = name("ntfy");
    h.fake.script_health("ntfy", [HealthStatus::Healthy]);
    let hex = |c: char| c.to_string().repeat(64);

    for (c, expected_images) in [('a', 1), ('b', 2), ('c', 2)] {
        h.fake.set_pull_digest(IMAGE, digest(c));
        let out = h.rec.deploy(&ntfy, false).await.unwrap();
        assert!(matches!(out, DeployOutcome::Deployed { .. }), "{out:?}");
        assert_eq!(h.fake.images().len(), expected_images, "after deploy {c}");
    }

    let ids: Vec<String> = h.fake.images().iter().map(|i| i.id.clone()).collect();
    assert!(
        !ids.contains(&hex('a')),
        "the oldest image is gone: {ids:?}"
    );
    assert!(
        ids.contains(&hex('b')),
        "the rollback target stays: {ids:?}"
    );
    assert!(ids.contains(&hex('c')), "the running image stays: {ids:?}");
    assert!(
        h.fake.calls().contains(&Call::ImageRemove(hex('a'))),
        "the removal went through the client"
    );
}

/// A deploy touches only the repository of the app it deploys: a stale image of another app's
/// repository survives (`scope` in [`crate::images::plan`]).
#[tokio::test(start_paused = true)]
async fn a_deploy_does_not_prune_another_apps_repository() {
    let h = Harness::new(
        r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
health = { attempts = 3, window_secs = 6 }
[apps.other]
image = "ghcr.io/x/other:latest"
port = 8086
health = { attempts = 3, window_secs = 6 }
"#,
    );
    h.fake.set_pull_digest(IMAGE, digest('a'));

    // A leftover of an earlier deploy of the *other* app, which is never deployed here.
    let stale = format!("ghcr.io/x/other@{}", digest('e'));
    h.fake.set_pull_digest(&stale, digest('e'));
    h.fake.image_pull(&stale).collect::<Vec<_>>().await;

    h.fake.set_pull_digest(IMAGE, digest('b'));
    h.rec.deploy(&name("ntfy"), false).await.unwrap();
    h.fake.set_pull_digest(IMAGE, digest('c'));
    h.rec.deploy(&name("ntfy"), false).await.unwrap();

    let ids: Vec<String> = h.fake.images().iter().map(|i| i.id.clone()).collect();
    assert!(
        ids.contains(&'e'.to_string().repeat(64)),
        "the other repository was not touched: {ids:?}"
    );
    assert!(
        !h.fake
            .calls()
            .contains(&Call::ImageRemove('e'.to_string().repeat(64)))
    );

    // ... while an explicit prune does cover it — the scope above was the only thing protecting it.
    let out = h.rec.prune_images(false).await.unwrap();
    assert!(
        out.removed
            .iter()
            .any(|i| i.id == 'e'.to_string().repeat(64)),
        "{out:?}"
    );
}

/// `weglarka images prune`: a dry run reports the candidates of every repository named in
/// `apps.toml` and removes nothing; the real run removes them and reports the space.
#[tokio::test(start_paused = true)]
async fn prune_images_dry_run_then_removes_leftovers() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake.script_health("ntfy", [HealthStatus::Healthy]);
    h.rec.reconcile().await.unwrap();

    // Unknown to `state.toml`: what earlier deploys (before retention existed) left behind.
    let stale = format!("ghcr.io/jpalczewski/ntfy.zig@{}", digest('e'));
    h.fake.set_pull_digest(&stale, digest('e'));
    h.fake.image_pull(&stale).collect::<Vec<_>>().await;
    assert_eq!(h.fake.images().len(), 2);

    let dry = h.rec.prune_images(true).await.unwrap();
    assert!(dry.dry_run);
    assert!(dry.failed.is_empty());
    assert_eq!(
        dry.removed.iter().map(|i| i.id.clone()).collect::<Vec<_>>(),
        ['e'.to_string().repeat(64)]
    );
    assert_eq!(dry.reclaimed_bytes, DEFAULT_IMAGE_SIZE_BYTES);
    assert_eq!(h.fake.images().len(), 2, "a dry run removes nothing");

    let out = h.rec.prune_images(false).await.unwrap();
    assert!(!out.dry_run);
    assert_eq!(out.removed.len(), 1);
    assert_eq!(out.reclaimed_bytes, DEFAULT_IMAGE_SIZE_BYTES);
    let ids: Vec<String> = h.fake.images().iter().map(|i| i.id.clone()).collect();
    assert_eq!(ids, ['a'.to_string().repeat(64)], "only the running image");
}

// ── config_root mounts and reload (issue #118, ADR 0028) ────────────────────────

/// App with two config mounts (a file and a directory) and a signal-based reload.
const WITH_CONFIGS: &str = r#"
[apps.prometheus]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 1, window_secs = 1 }
configs = [
  { source = "prometheus/prometheus.yml", target = "/etc/prometheus/prometheus.yml" },
  { source = "prometheus/rules", target = "/etc/prometheus/rules" },
]
reload_signal = "SIGHUP"
"#;

/// A spec whose config source does not exist under the root.
const MISSING_CONFIG: &str = r#"
[apps.prometheus]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
health = { attempts = 1, window_secs = 1 }
configs = [{ source = "missing.yml", target = "/etc/prometheus/missing.yml" }]
"#;

/// `start = false` with a config source that does not exist: provisioning must validate too.
const STOPPED_WITH_MISSING_CONFIG: &str = r#"
[apps.gate]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
start = false
configs = [{ source = "missing.yml", target = "/etc/gate.yml" }]
"#;

/// A temporary `config_root` with the tree `WITH_CONFIGS` expects.
fn config_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("prometheus/rules")).unwrap();
    std::fs::write(
        root.path().join("prometheus/prometheus.yml"),
        "global: {}\n",
    )
    .unwrap();
    root
}

fn with_config_root(apps_toml: &str, root: &std::path::Path) -> Harness {
    Harness::with_options(
        apps_toml,
        ReconcilerOptions {
            config_root: Some(root.to_owned()),
            ..Default::default()
        },
    )
}

/// Every config mount reaches libpod as a read-only `BindMount` from the **canonical** host path.
#[tokio::test(start_paused = true)]
async fn configs_are_mounted_read_only_from_the_canonical_root() {
    let root = config_root();
    let root = root.path();
    let h = with_config_root(WITH_CONFIGS, root);
    h.fake.set_pull_digest(IMAGE, digest('a'));

    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    let spec = h
        .fake
        .container_spec("prometheus")
        .expect("the container exists");
    let canonical = root.canonicalize().unwrap();
    assert_eq!(
        spec.mounts,
        vec![
            BindMount {
                source: canonical
                    .join("prometheus/prometheus.yml")
                    .display()
                    .to_string(),
                target: "/etc/prometheus/prometheus.yml".into(),
                read_only: true,
            },
            BindMount {
                source: canonical.join("prometheus/rules").display().to_string(),
                target: "/etc/prometheus/rules".into(),
                read_only: true,
            },
        ]
    );
    // The container is created from the pinned digest, as usual.
    assert_eq!(h.state("prometheus").current, Some(digest('a')));
}

/// An allowlisted host path reaches libpod as a read-only bind from its canonical path; one that is
/// not on the list blocks the app instead of mounting anything (issue #178).
#[tokio::test(start_paused = true)]
async fn host_mounts_are_read_only_and_need_the_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let journal = dir.path().canonicalize().unwrap().join("journal");
    std::fs::create_dir(&journal).unwrap();
    let apps = format!(
        "[apps.alloy]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\nhealth = {{ attempts = 1, window_secs = 1 }}\n\
         host_mounts = [{{ source = {:?}, target = \"/var/log/journal\" }}]\n",
        journal.display().to_string()
    );

    let h = Harness::with_options(
        &apps,
        ReconcilerOptions {
            host_mounts: vec![journal.clone()],
            ..Default::default()
        },
    );
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(
        h.fake.container_spec("alloy").unwrap().mounts,
        vec![BindMount {
            source: journal.display().to_string(),
            target: "/var/log/journal".into(),
            read_only: true,
        }]
    );

    // Without the allowlist entry the app is blocked and no container is created.
    let h = Harness::new(&apps);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let report = h.rec.reconcile().await.unwrap();
    assert!(!report.is_clean(), "{report:?}");
    assert!(h.fake.container_spec("alloy").is_none());
}

/// `group_add` makes the container keep the runtime user's groups, and only when the operator
/// allowlisted the name (issue #178).
#[tokio::test(start_paused = true)]
async fn group_add_needs_the_allowlist_and_sets_keep_groups() {
    let apps = "[apps.alloy]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\n\
                health = { attempts = 1, window_secs = 1 }\ngroup_add = [\"systemd-journal\"]\n";
    let h = Harness::with_options(
        apps,
        ReconcilerOptions {
            group_add: vec!["systemd-journal".into()],
            ..Default::default()
        },
    );
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert!(h.fake.container_spec("alloy").unwrap().keep_groups);

    let h = Harness::new(apps);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    assert!(!h.rec.reconcile().await.unwrap().is_clean());
    assert!(h.fake.container_spec("alloy").is_none());
}

/// A broken config fails the deploy **before** the old container is touched: no stop, no remove, no
/// rollback that would only bring back the same broken spec.
#[tokio::test(start_paused = true)]
async fn a_missing_config_source_fails_the_deploy_before_touching_the_old_container() {
    let root = config_root();
    let h = with_config_root(NTFY, root.path());
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    let old = h.container_digest_ref("ntfy");

    h.set_apps(&format!(
        "{NTFY}configs = [{{ source = \"missing.yml\", target = \"/etc/app.yml\" }}]\n"
    ));
    let before = h.fake.calls().len();
    let err = h.rec.deploy(&name("ntfy"), false).await.unwrap_err();
    assert!(matches!(&err, EngineError::Configs(_)), "{err:?}");
    let calls = h.fake.calls()[before..].to_vec();
    assert!(
        !calls.iter().any(|c| matches!(
            c,
            Call::ContainerStop(_) | Call::ContainerRemove(_) | Call::ContainerCreate(_)
        )),
        "the old container must not be touched: {calls:?}"
    );
    assert_eq!(h.container_digest_ref("ntfy"), old);
    assert_eq!(h.fake.containers()[0].state, ContainerState::Running);
}

/// Provisioning validates the mounts too: nothing is pinned, pulled or created for a broken spec.
#[tokio::test(start_paused = true)]
async fn provisioning_validates_the_config_mounts() {
    let root = config_root();
    let h = with_config_root(STOPPED_WITH_MISSING_CONFIG, root.path());
    let err = h.rec.deploy(&name("gate"), false).await.unwrap_err();
    assert!(matches!(&err, EngineError::Configs(_)), "{err:?}");
    assert_eq!(h.state("gate").current, None);
    assert!(h.fake.containers().is_empty() && h.fake.networks().is_empty());
    assert!(
        !h.fake
            .calls()
            .iter()
            .any(|c| matches!(c, Call::ImagePull(_) | Call::ContainerCreate(_)))
    );
}

/// A config that cannot be mounted blocks the instance in reconcile instead of failing a deploy.
#[tokio::test(start_paused = true)]
async fn reconcile_blocks_an_instance_whose_configs_cannot_be_mounted() {
    let root = config_root();
    let h = with_config_root(MISSING_CONFIG, root.path());
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.actions.is_empty(), "{report:?}");
    assert_eq!(report.blocked.len(), 1, "{report:?}");
    assert_eq!(report.blocked[0].0, name("prometheus"));
    assert!(report.blocked[0].1.contains("missing.yml"), "{report:?}");
    assert!(h.fake.containers().is_empty());
    assert!(
        !h.fake
            .calls()
            .iter()
            .any(|c| matches!(c, Call::ImagePull(_)))
    );

    // Declaring configs while the host sets no `config_root` blocks it the same way.
    let h = Harness::new(WITH_CONFIGS);
    let report = h.rec.reconcile().await.unwrap();
    assert!(report.actions.is_empty(), "{report:?}");
    assert_eq!(report.blocked.len(), 1, "{report:?}");
    assert!(report.blocked[0].1.contains("config_root"), "{report:?}");
    assert!(h.fake.containers().is_empty());
}

/// `reload` sends `reload_signal` (normalized, without `SIG`) to the running container and does not
/// recreate, stop or pull anything. No state is written.
#[tokio::test(start_paused = true)]
async fn reload_signals_the_running_container() {
    let root = config_root();
    let h = with_config_root(WITH_CONFIGS, root.path());
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();

    let before = h.fake.calls().len();
    let outcome = h.rec.reload(&name("prometheus")).await.unwrap();
    assert_eq!(
        outcome,
        ReloadOutcome::Signalled {
            signal: "HUP".into()
        }
    );
    let calls = h.fake.calls()[before..].to_vec();
    assert_eq!(
        calls,
        vec![Call::ContainerKill {
            name: "prometheus".into(),
            signal: "HUP".into(),
        }],
        "only the signal, nothing else"
    );
    assert_eq!(h.fake.containers()[0].state, ContainerState::Running);
    // Reload is not a deploy: the pinned state and the generation are untouched.
    let st = h.state("prometheus");
    assert_eq!(st.current, Some(digest('a')));
    assert_eq!(st.generation, 1);
}

/// Without `reload_signal` the same container is stopped and started again — never recreated.
#[tokio::test(start_paused = true)]
async fn reload_without_a_signal_restarts_the_container() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();

    let before = h.fake.calls().len();
    assert_eq!(
        h.rec.reload(&name("ntfy")).await.unwrap(),
        ReloadOutcome::Restarted
    );
    let calls = h.fake.calls()[before..].to_vec();
    let stop = first_call(&calls, Call::ContainerStop("ntfy".into())).expect("stopped");
    let start = first_call(&calls, Call::ContainerStart("ntfy".into())).expect("started");
    assert!(stop < start, "{calls:?}");
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, Call::ContainerCreate(_) | Call::ContainerRemove(_))),
        "a restart reuses the container: {calls:?}"
    );
    assert_eq!(h.fake.containers()[0].state, ContainerState::Running);
}

/// Reload refuses an app with no running container (missing or exited) instead of starting it.
#[tokio::test(start_paused = true)]
async fn reload_of_a_non_running_app_is_refused() {
    let h = Harness::new(NTFY);
    h.fake.set_pull_digest(IMAGE, digest('a'));
    // Not deployed at all: no container exists.
    let err = h.rec.reload(&name("ntfy")).await.unwrap_err();
    assert!(
        matches!(&err, EngineError::ReloadNotRunning(instance) if instance.as_str() == "ntfy"),
        "{err:?}"
    );

    h.rec.reconcile().await.unwrap();
    h.fake.crash_container("ntfy", 1);
    let before = h.fake.calls().len();
    let err = h.rec.reload(&name("ntfy")).await.unwrap_err();
    assert!(matches!(&err, EngineError::ReloadNotRunning(_)), "{err:?}");
    assert!(
        h.fake.calls()[before..].is_empty(),
        "an exited container is neither signalled nor restarted"
    );
}

// ---------- crash loops and failing healthchecks (issue #112) ----------

fn monitor_policy() -> crash::Policy {
    crash::Policy {
        crash_loop_restarts: 3,
        crash_loop_window: Duration::from_secs(60),
        unhealthy_observations: 2,
    }
}

/// Deploy the single `ntfy` app and take one more pass, so the watcher has seen the container once
/// (its first observation only sets the restart baseline).
async fn deployed_and_watched(h: &Harness) {
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap(); // first deploy
    h.rec.reconcile().await.unwrap(); // the container is observed for the first time
}

#[tokio::test(start_paused = true)]
async fn a_crash_loop_is_reported_once_and_recovers_after_a_quiet_window() {
    let h = Harness::with_monitor(NTFY, monitor_policy());
    deployed_and_watched(&h).await;
    let baseline = h.sink.events().len();

    h.fake.set_restarts("ntfy", 2);
    h.rec.reconcile().await.unwrap();
    assert_eq!(h.sink.events().len(), baseline, "below the threshold");

    h.fake.set_restarts("ntfy", 3);
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().last(),
        Some(&Event::CrashLooping {
            instance: name("ntfy"),
            restarts: 3,
        })
    );
    let alerted = h.sink.events().len();

    // The same streak is not reported again.
    h.rec.reconcile().await.unwrap();
    h.fake.set_restarts("ntfy", 4);
    h.rec.reconcile().await.unwrap();
    assert_eq!(h.sink.events().len(), alerted);

    // A full quiet window means the loop is over.
    tokio::time::advance(Duration::from_secs(61)).await;
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().last(),
        Some(&Event::Recovered {
            instance: name("ntfy"),
        })
    );
    h.rec.reconcile().await.unwrap();
    assert_eq!(h.sink.events().len(), alerted + 1, "recovery once");
}

#[tokio::test(start_paused = true)]
async fn a_recreated_container_resets_the_crash_counters() {
    let h = Harness::with_monitor(NTFY, monitor_policy());
    deployed_and_watched(&h).await;
    h.fake.set_restarts("ntfy", 3);
    h.rec.reconcile().await.unwrap();
    assert!(matches!(
        h.sink.events().last(),
        Some(Event::CrashLooping { restarts: 3, .. })
    ));

    // The container disappears and is recreated from the pinned digest: new generation, count 0.
    h.fake.container_remove("ntfy", true).await.unwrap();
    h.rec.reconcile().await.unwrap();
    assert!(
        matches!(h.sink.events().last(), Some(Event::Recreated { .. })),
        "the recreate is reported; the old alert is dropped without a recovery"
    );
    h.rec.reconcile().await.unwrap(); // observe the new container (baseline 0)
    let mark = h.sink.events().len();

    h.fake.set_restarts("ntfy", 2);
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().len(),
        mark,
        "the new container counts from zero"
    );

    h.fake.set_restarts("ntfy", 3);
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().last(),
        Some(&Event::CrashLooping {
            instance: name("ntfy"),
            restarts: 3,
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_failing_healthcheck_is_reported_once_and_recovers() {
    let h = Harness::with_monitor(NTFY, monitor_policy());
    deployed_and_watched(&h).await;
    let baseline = h.sink.events().len();

    h.fake.set_health("ntfy", Some(HealthStatus::Unhealthy));
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().len(),
        baseline,
        "one failed observation is a flaky probe"
    );

    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().last(),
        Some(&Event::Unhealthy {
            instance: name("ntfy"),
        })
    );
    let alerted = h.sink.events().len();
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().len(),
        alerted,
        "one alert per unhealthy streak"
    );

    h.fake.set_health("ntfy", Some(HealthStatus::Healthy));
    h.rec.reconcile().await.unwrap();
    assert_eq!(
        h.sink.events().last(),
        Some(&Event::Recovered {
            instance: name("ntfy"),
        })
    );
}

#[tokio::test(start_paused = true)]
async fn the_test_harness_does_not_watch_without_a_policy() {
    // The rest of the engine tests assert their event lists: detection is explicitly disabled there.
    let h = Harness::new(NTFY);
    deployed_and_watched(&h).await;
    let baseline = h.sink.events().len();
    h.fake.set_restarts("ntfy", 5);
    h.fake.set_health("ntfy", Some(HealthStatus::Unhealthy));
    for _ in 0..3 {
        h.rec.reconcile().await.unwrap();
    }
    assert_eq!(h.sink.events().len(), baseline);
}

// ---------- shared networks (issue #128) ----------

const GROUP: &str = r#"
[shared_networks.kajet]

[apps.kajet-api]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"

[apps.kajet-proxy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
shared_networks = [{ name = "kajet", aliases = ["gateway"] }]

[apps.loner]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
"#;

fn group_with_members() -> String {
    GROUP.replace(
        "[apps.kajet-api]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\n",
        "[apps.kajet-api]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\nshared_networks = [\"kajet\"]\n",
    )
}

#[tokio::test(start_paused = true)]
async fn group_members_share_an_internal_network_and_outsiders_do_not() {
    let h = Harness::new(&group_with_members());
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();

    let shared = "net-shared-kajet";
    let spec = h
        .fake
        .network_spec(shared)
        .expect("created lazily by the first member");
    assert!(spec.internal, "group traffic gets no route out");
    assert_eq!(
        spec.labels.get(labels::SHARED_NETWORK).map(String::as_str),
        Some("kajet")
    );
    assert!(
        !spec.labels.contains_key(labels::INSTANCE),
        "instance-keyed cleanup must never see a group network"
    );

    let mut members = h.fake.network_members(shared);
    members.sort();
    assert_eq!(members, vec!["kajet-api", "kajet-proxy"]);

    // The member keeps its own network first (primary); the alias rides on the group network only.
    let proxy = h.fake.container_spec("kajet-proxy").unwrap();
    assert_eq!(proxy.networks, vec!["net-kajet-proxy", shared]);
    assert_eq!(
        proxy.network_aliases,
        BTreeMap::from([(shared.to_owned(), vec!["gateway".to_owned()])])
    );
    // An app outside the group is attached to its own network only.
    let loner = h.fake.container_spec("loner").unwrap();
    assert_eq!(loner.networks, vec!["net-loner"]);
    assert!(
        h.fake
            .network_members("net-loner")
            .contains(&"loner".to_owned())
    );
}

#[tokio::test(start_paused = true)]
async fn removing_a_member_leaves_the_group_working() {
    let h = Harness::new(&group_with_members());
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();

    // Drop kajet-api from the desired state.
    let without_api = group_with_members().replace(
        "[apps.kajet-api]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\nshared_networks = [\"kajet\"]\n",
        "",
    );
    h.set_apps(&without_api);
    h.rec.reconcile().await.unwrap();

    let names: Vec<String> = h.fake.containers().into_iter().map(|c| c.name).collect();
    assert!(!names.contains(&"kajet-api".to_owned()), "{names:?}");
    assert!(names.contains(&"kajet-proxy".to_owned()), "{names:?}");
    // The group network is owned by its declaration, not by a member: it survives and the
    // remaining member is still attached to it.
    assert!(h.fake.networks().contains(&"net-shared-kajet".to_owned()));
    assert_eq!(
        h.fake.network_members("net-shared-kajet"),
        vec!["kajet-proxy"]
    );
    assert!(
        !h.fake.networks().contains(&"net-kajet-api".to_owned()),
        "per-app network pruned"
    );
}

#[tokio::test(start_paused = true)]
async fn joining_or_leaving_a_group_recreates_the_container() {
    let h = Harness::new(
        "[shared_networks.g]\n[apps.a]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\n",
    );
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.rec.reconcile().await.unwrap();
    let before = h.fake.container_spec("a").unwrap();
    assert_eq!(before.networks, vec!["net-a"]);

    h.set_apps(
        "[shared_networks.g]\n[apps.a]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\nshared_networks = [\"g\"]\n",
    );
    h.rec.reconcile().await.unwrap();
    let joined = h.fake.container_spec("a").unwrap();
    assert_eq!(joined.networks, vec!["net-a", "net-shared-g"]);
    assert_ne!(
        before.labels[labels::SPEC_HASH],
        joined.labels[labels::SPEC_HASH],
        "the container's networks changed, so it is a different container"
    );
}

#[tokio::test(start_paused = true)]
async fn only_undeclared_group_networks_are_pruned() {
    let h = Harness::new("[shared_networks.kept]\n");
    let group_net = |group: &str| NetworkSpec {
        name: format!("net-shared-{group}"),
        internal: true,
        labels: BTreeMap::from([(labels::SHARED_NETWORK.to_owned(), group.to_owned())]),
    };
    h.fake.network_create(&group_net("kept")).await.unwrap();
    h.fake.network_create(&group_net("gone")).await.unwrap();
    // Looks like the per-app network of an instance called `shared-kept` by name, but the label
    // says it is a group network: the name must not decide.
    h.rec.reconcile().await.unwrap();
    let nets = h.fake.networks();
    assert!(nets.contains(&"net-shared-kept".to_owned()), "{nets:?}");
    assert!(!nets.contains(&"net-shared-gone".to_owned()), "{nets:?}");
}

#[tokio::test(start_paused = true)]
async fn a_declaration_with_members_cannot_be_removed() {
    let h = Harness::new(&group_with_members());
    let net = crate::app::SharedNetworkName::new("kajet").unwrap();
    let err = h.rec.remove_shared_network(&net).await.unwrap_err();
    assert!(
        matches!(&err, EngineError::SharedNetworkInUse { members, .. } if members == "kajet-api, kajet-proxy"),
        "{err}"
    );
    // Declared, unused, then removed; removing it again is a clean "unknown".
    h.set_apps("[shared_networks.kajet]\n");
    h.rec.remove_shared_network(&net).await.unwrap();
    assert!(matches!(
        h.rec.remove_shared_network(&net).await,
        Err(EngineError::UnknownSharedNetwork(_))
    ));
    // Declaring is idempotent.
    h.rec.declare_shared_network(net.clone()).await.unwrap();
    h.rec.declare_shared_network(net).await.unwrap();
}

// ── One-off containers (`weglarka run`, issue #106) ─────────────────────────

mod run {
    use super::*;
    use crate::podman::{ContainerSpec, LogChunk, LogSource};
    use crate::run::{MAX_CONCURRENT_RUNS, RunOptions, RunOutcome};
    use crate::testing::RunScript;

    const APP: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
domains = ["ntfy.example.eu"]
env = { MODE = "prod", KEEP = "yes" }
host_ports = [{ host = 2222, container = 22 }]
command = ["serve"]
"#;

    async fn deployed() -> Harness {
        let h = Harness::new(APP);
        h.fake.set_pull_digest(IMAGE, digest('a'));
        h.rec.reconcile().await.unwrap();
        h
    }

    fn options(cmd: &[&str]) -> RunOptions {
        RunOptions {
            command: cmd.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        }
    }

    fn chunk(source: LogSource, text: &str) -> (LogSource, Vec<u8>) {
        (source, text.as_bytes().to_vec())
    }

    /// The single run container ever created, whether or not it still exists.
    fn run_spec(h: &Harness) -> ContainerSpec {
        let mut runs: Vec<_> = h
            .fake
            .created_specs()
            .into_iter()
            .filter(|s| s.labels.contains_key(labels::RUN))
            .collect();
        assert_eq!(runs.len(), 1, "{runs:?}");
        runs.remove(0)
    }

    #[tokio::test(start_paused = true)]
    async fn output_and_exit_code_come_back_and_the_container_is_removed() {
        let h = deployed().await;
        h.fake.script_next_run(RunScript {
            output: vec![
                chunk(LogSource::Stdout, "migrating\n"),
                chunk(LogSource::Stderr, "warning\n"),
            ],
            exit_code: 3,
            hang: false,
        });
        let calls_before = h.fake.calls().len();
        let (tx, mut rx) = mpsc::channel(16);
        let outcome = h
            .rec
            .run_once(&name("ntfy"), options(&["migrate", "--up"]), tx)
            .await
            .unwrap();
        assert_eq!(outcome, RunOutcome::Exited(3));
        let mut got = Vec::new();
        while let Some(c) = rx.recv().await {
            got.push((c.source, String::from_utf8(c.data.to_vec()).unwrap()));
        }
        assert_eq!(
            got,
            [
                (LogSource::Stdout, "migrating\n".to_owned()),
                (LogSource::Stderr, "warning\n".to_owned())
            ]
        );
        // Only the app is left, and it was neither stopped nor recreated.
        let names: Vec<_> = h.fake.containers().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["ntfy"]);
        let calls = h.fake.calls().split_off(calls_before);
        for app_call in [
            Call::ContainerStop("ntfy".into()),
            Call::ContainerRemove("ntfy".into()),
            Call::ContainerCreate("ntfy".into()),
        ] {
            assert!(!calls.contains(&app_call), "{app_call:?} in {calls:?}");
        }
        assert_eq!(h.state("ntfy").generation, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_container_never_gets_host_ports_ingress_or_the_apps_identity() {
        let h = deployed().await;
        let (tx, _rx) = mpsc::channel(16);
        let mut opts = options(&["sh", "-c", "env"]);
        opts.entrypoint = Some(vec!["/bin/busybox".into()]);
        opts.env = BTreeMap::from([("MODE".into(), "debug".into())]);
        h.rec.run_once(&name("ntfy"), opts, tx).await.unwrap();

        let run = run_spec(&h);
        assert!(run.publish.is_empty(), "host_ports must not be published");
        assert_eq!(run.restart, crate::podman::RestartPolicy::No);
        assert!(run.healthcheck.is_none());
        assert!(run.network_aliases.is_empty());
        assert_eq!(run.networks, ["net-ntfy"]);
        assert_eq!(run.command, ["sh", "-c", "env"]);
        assert_eq!(run.entrypoint, Some(vec!["/bin/busybox".to_owned()]));
        // The app's env, with the request's values on top.
        assert_eq!(run.env["MODE"], "debug");
        assert_eq!(run.env["KEEP"], "yes");
        assert_eq!(
            run.image,
            format!("ghcr.io/jpalczewski/ntfy.zig@{}", digest('a'))
        );
        // Not the app: reconcile, the crash watcher and ingress key on `weglarka.instance`.
        assert!(!run.labels.contains_key(labels::INSTANCE));
        assert_eq!(run.labels[labels::RUN_FOR], "ntfy");
        assert_ne!(run.name, "ntfy");
        assert!(run.name.starts_with("wg-run.ntfy."), "{}", run.name);
        // The app's own spec keeps its port.
        assert_eq!(h.fake.container_spec("ntfy").unwrap().publish.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn an_app_that_was_never_deployed_is_refused() {
        let h = Harness::new(APP);
        let (tx, _rx) = mpsc::channel(1);
        let err = h
            .rec
            .run_once(&name("ntfy"), options(&["true"]), tx)
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::RunNotDeployed(_)), "{err:?}");
        let err = h
            .rec
            .run_once(&name("nope"), options(&["true"]), mpsc::channel(1).0)
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::UnknownInstance(_)), "{err:?}");
        assert!(h.fake.created_specs().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn requests_that_cannot_start_a_process_are_refused_before_anything_is_created() {
        let h = deployed().await;
        let before = h.fake.created_specs().len();
        let bad = [
            options(&[]),
            RunOptions {
                entrypoint: Some(vec![]),
                ..options(&["x"])
            },
            RunOptions {
                env: BTreeMap::from([("A=B".into(), "c".into())]),
                ..options(&["x"])
            },
            RunOptions {
                timeout: Some(Duration::ZERO),
                ..options(&["x"])
            },
        ];
        for opts in bad {
            let err = h
                .rec
                .run_once(&name("ntfy"), opts.clone(), mpsc::channel(1).0)
                .await
                .unwrap_err();
            assert!(
                matches!(err, EngineError::RunInvalid(_)),
                "{opts:?}: {err:?}"
            );
        }
        assert_eq!(h.fake.created_specs().len(), before);
        // An entrypoint alone is enough.
        let ok = RunOptions {
            entrypoint: Some(vec!["/bin/sh".into()]),
            ..Default::default()
        };
        assert!(ok.validate().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_run_that_overstays_its_timeout_is_killed_and_removed() {
        let h = deployed().await;
        h.fake.script_next_run(RunScript {
            hang: true,
            ..Default::default()
        });
        let (tx, _rx) = mpsc::channel(1);
        let mut opts = options(&["sleep", "infinity"]);
        opts.timeout = Some(Duration::from_secs(30));
        let outcome = h.rec.run_once(&name("ntfy"), opts, tx).await.unwrap();
        assert_eq!(outcome, RunOutcome::TimedOut);
        assert!(h.fake.calls().iter().any(|c| matches!(
            c,
            Call::ContainerKill { name, signal } if name.starts_with("wg-run.") && signal == "KILL"
        )));
        assert_eq!(h.fake.containers().len(), 1, "only the app is left");
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_goes_away_cancels_the_run() {
        let h = deployed().await;
        h.fake.script_next_run(RunScript {
            hang: true,
            ..Default::default()
        });
        let (tx, rx) = mpsc::channel::<LogChunk>(1);
        let rec = h.rec.clone();
        let task = tokio::spawn(async move {
            rec.run_once(&name("ntfy"), options(&["sleep", "infinity"]), tx)
                .await
        });
        // Let the run start, then hang up.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(h.fake.containers().len(), 2);
        drop(rx);
        assert_eq!(task.await.unwrap().unwrap(), RunOutcome::Cancelled);
        assert_eq!(h.fake.containers().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_few_runs_may_be_alive_at_once() {
        let h = deployed().await;
        let mut keep = Vec::new();
        for _ in 0..MAX_CONCURRENT_RUNS {
            h.fake.script_next_run(RunScript {
                hang: true,
                ..Default::default()
            });
            let (tx, rx) = mpsc::channel::<LogChunk>(1);
            keep.push(rx);
            let rec = h.rec.clone();
            tokio::spawn(async move {
                let _ = rec
                    .run_once(&name("ntfy"), options(&["sleep", "1d"]), tx)
                    .await;
            });
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let err = h
            .rec
            .run_once(&name("ntfy"), options(&["true"]), mpsc::channel(1).0)
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::RunLimit(_)), "{err:?}");
        // A finished run frees its slot.
        keep.pop();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let (tx, _rx) = mpsc::channel(4);
        h.rec
            .run_once(&name("ntfy"), options(&["true"]), tx)
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stale_run_containers_are_swept_and_the_app_is_left_alone() {
        let h = deployed().await;
        let mut stale = h.fake.container_spec("ntfy").unwrap();
        stale.name = "wg-run.ntfy.dead".into();
        stale.labels = BTreeMap::from([
            (labels::RUN.to_owned(), "true".to_owned()),
            (labels::RUN_FOR.to_owned(), "ntfy".to_owned()),
        ]);
        h.fake.container_create(&stale).await.unwrap();
        h.fake.container_start("wg-run.ntfy.dead").await.unwrap();
        assert_eq!(h.rec.remove_stale_runs().await.unwrap(), 1);
        let names: Vec<_> = h.fake.containers().into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["ntfy"]);
        assert_eq!(h.rec.remove_stale_runs().await.unwrap(), 0);
    }
}

// ── Temporary port forward (`weglarka forward`, issue #108) ─────────────────

mod forward {
    use super::*;
    use crate::app::Security;
    use crate::forward::{ForwardOptions, ForwardOutcome, MAX_CONCURRENT_FORWARDS};
    use crate::podman::{ContainerSpec, RestartPolicy};
    use crate::testing::RunScript;

    const APP: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
domains = ["ntfy.example.eu"]
host_ports = [{ host = 2222, container = 22 }]
"#;
    const RELAY_IMAGE: &str = "docker.io/library/nginx:1-alpine";

    async fn deployed() -> Harness {
        let h = Harness::new(APP);
        h.fake.set_pull_digest(IMAGE, digest('a'));
        h.rec.reconcile().await.unwrap();
        h
    }

    fn options(port: u16) -> ForwardOptions {
        ForwardOptions {
            port,
            timeout: None,
            image: RELAY_IMAGE.into(),
            security: Security::default(),
        }
    }

    fn hang() -> RunScript {
        RunScript {
            hang: true,
            ..Default::default()
        }
    }

    fn relay_spec(h: &Harness) -> ContainerSpec {
        let mut relays: Vec<_> = h
            .fake
            .created_specs()
            .into_iter()
            .filter(|s| s.labels.contains_key(labels::FORWARD))
            .collect();
        assert_eq!(relays.len(), 1, "{relays:?}");
        relays.remove(0)
    }

    fn container_names(h: &Harness) -> Vec<String> {
        h.fake.containers().into_iter().map(|c| c.name).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn the_relay_is_not_the_app_and_listens_on_loopback_only() {
        let h = deployed().await;
        h.fake.script_next_run(hang());
        let pending = h
            .rec
            .prepare_forward(&name("ntfy"), &options(8085))
            .await
            .unwrap();
        let spec = relay_spec(&h);
        assert!(spec.name.starts_with("wg-fwd.ntfy."), "{}", spec.name);
        assert!(!spec.labels.contains_key(labels::INSTANCE));
        assert_eq!(spec.labels[labels::FORWARD_FOR], "ntfy");
        assert_eq!(spec.networks.len(), 1, "{:?}", spec.networks);
        assert!(spec.network_aliases.is_empty());
        assert_eq!(spec.restart, RestartPolicy::No);
        assert!(spec.healthcheck.is_none());
        let [mapping] = spec.publish.as_slice() else {
            panic!("{:?}", spec.publish)
        };
        assert_eq!(mapping.host_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(mapping.host_port, 0, "the host port is left to libpod");
        // The target travels as positional arguments, never inside the script text.
        let entry = spec.entrypoint.unwrap();
        assert_eq!(entry[0..2], ["/bin/sh", "-c"]);
        assert_eq!(entry[4..], ["8080", "ntfy", "8085"]);
        assert!(!entry[2].contains("ntfy"));
        // The port that came back is the one libpod assigned.
        let info = h
            .fake
            .containers()
            .into_iter()
            .find(|c| c.name == spec.name)
            .unwrap();
        assert_eq!(info.published_ports[0].host_port, pending.host_port());
        assert_ne!(pending.host_port(), 0);
        pending.discard().await;
        assert_eq!(container_names(&h), ["ntfy"]);
    }

    #[tokio::test(start_paused = true)]
    async fn closing_the_caller_or_timing_out_removes_the_relay() {
        let h = deployed().await;
        h.fake.script_next_run(hang());
        let pending = h
            .rec
            .prepare_forward(&name("ntfy"), &options(8085))
            .await
            .unwrap();
        let outcome = pending.hold(std::future::ready(())).await;
        assert_eq!(outcome, ForwardOutcome::Closed);
        assert_eq!(container_names(&h), ["ntfy"]);

        h.fake.script_next_run(hang());
        let mut short = options(8085);
        short.timeout = Some(Duration::from_secs(30));
        let pending = h.rec.prepare_forward(&name("ntfy"), &short).await.unwrap();
        let outcome = pending.hold(std::future::pending()).await;
        assert_eq!(outcome, ForwardOutcome::TimedOut);
        assert_eq!(container_names(&h), ["ntfy"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_dies_ends_the_forward_and_is_removed() {
        let h = deployed().await;
        h.fake.script_next_run(RunScript {
            exit_code: 1,
            ..Default::default()
        });
        let pending = h
            .rec
            .prepare_forward(&name("ntfy"), &options(8085))
            .await
            .unwrap();
        assert_eq!(
            pending.hold(std::future::pending()).await,
            ForwardOutcome::RelayExited(1)
        );
        assert_eq!(container_names(&h), ["ntfy"]);
    }

    #[tokio::test(start_paused = true)]
    async fn what_cannot_be_forwarded_is_refused_before_anything_is_created() {
        let h = deployed().await;
        let err = |r: Result<_, EngineError>| match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        };
        assert!(matches!(
            err(h.rec.prepare_forward(&name("ntfy"), &options(0)).await),
            EngineError::ForwardInvalid(_)
        ));
        let mut zero = options(80);
        zero.timeout = Some(Duration::ZERO);
        assert!(matches!(
            err(h.rec.prepare_forward(&name("ntfy"), &zero).await),
            EngineError::ForwardInvalid(_)
        ));
        assert!(matches!(
            err(h.rec.prepare_forward(&name("nope"), &options(80)).await),
            EngineError::UnknownInstance(_)
        ));
        // Declared but never started: no container to forward to.
        let idle = Harness::new(APP);
        assert!(matches!(
            err(idle.rec.prepare_forward(&name("ntfy"), &options(80)).await),
            EngineError::ForwardNotRunning(_)
        ));
        assert!(
            h.fake
                .created_specs()
                .iter()
                .all(|s| !s.labels.contains_key(labels::FORWARD))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_few_forwards_may_be_alive_at_once() {
        let h = deployed().await;
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_FORWARDS {
            h.fake.script_next_run(hang());
            held.push(
                h.rec
                    .prepare_forward(&name("ntfy"), &options(8085))
                    .await
                    .unwrap(),
            );
        }
        h.fake.script_next_run(hang());
        let refused = h.rec.prepare_forward(&name("ntfy"), &options(8085)).await;
        assert!(matches!(refused, Err(EngineError::ForwardLimit(_))));
        // A finished forward frees its slot.
        held.pop().unwrap().discard().await;
        h.fake.script_next_run(hang());
        h.rec
            .prepare_forward(&name("ntfy"), &options(8085))
            .await
            .unwrap()
            .discard()
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn stale_relays_are_swept_and_the_app_is_left_alone() {
        let h = deployed().await;
        let mut stale = h.fake.container_spec("ntfy").unwrap();
        stale.name = "wg-fwd.ntfy.dead".into();
        stale.labels = BTreeMap::from([
            (labels::FORWARD.to_owned(), "true".to_owned()),
            (labels::FORWARD_FOR.to_owned(), "ntfy".to_owned()),
        ]);
        h.fake.container_create(&stale).await.unwrap();
        h.fake.container_start("wg-fwd.ntfy.dead").await.unwrap();
        assert_eq!(h.rec.remove_stale_forwards().await.unwrap(), 1);
        assert_eq!(container_names(&h), ["ntfy"]);
        assert_eq!(h.rec.remove_stale_forwards().await.unwrap(), 0);
    }
}

/// `weglarka push` (issue #109, docs/decisions/0042).
mod push {
    use bytes::Bytes;
    use futures_util::stream;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::podman::TarStream;
    use crate::push::PUSHED_TAG;

    const REPO: &str = "ghcr.io/jpalczewski/ntfy.zig";

    fn tar(bytes: &'static [u8]) -> TarStream {
        stream::iter([Ok(Bytes::from_static(bytes))]).boxed()
    }

    /// The digest the fake gives an archive: the hash of its bytes.
    fn archive_digest(bytes: &[u8]) -> Digest {
        Digest::new(format!("sha256:{}", hex::encode(Sha256::digest(bytes)))).unwrap()
    }

    async fn deployed(apps_toml: &str) -> Harness {
        let h = Harness::new(apps_toml);
        h.fake.set_pull_digest(IMAGE, digest('a'));
        h.rec.reconcile().await.unwrap();
        h
    }

    #[tokio::test(start_paused = true)]
    async fn a_pushed_reference_pins_its_digest_and_leaves_the_spec_alone() {
        let h = deployed(NTFY).await;
        let reference = format!("{REPO}:sha-1");
        h.fake.set_pull_digest(&reference, digest('b'));
        let before = h.fake.calls().len();

        let out = h.rec.push_reference(&name("ntfy"), &reference).await;
        assert_eq!(
            out.unwrap(),
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
        let calls = h.fake.calls()[before..].to_vec();
        assert!(calls.contains(&Call::ImagePull(reference)));
        assert!(
            !calls.contains(&Call::ImagePull(IMAGE.into())),
            "the tag in the spec must not be pulled: {calls:?}"
        );
        assert_eq!(std::fs::read_to_string(&h.rec.paths().apps).unwrap(), NTFY);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reference_of_another_repository_is_refused_before_anything_is_pulled() {
        let h = deployed(NTFY).await;
        let before = h.fake.calls().len();
        for reference in ["ghcr.io/jpalczewski/other:latest", "docker.io/x/ntfy.zig:1"] {
            let err = h
                .rec
                .push_reference(&name("ntfy"), reference)
                .await
                .unwrap_err();
            assert!(matches!(err, EngineError::PushInvalid(_)), "{err:?}");
        }
        assert_eq!(h.fake.calls().len(), before);
        assert_eq!(h.state("ntfy").current, Some(digest('a')));
    }

    #[tokio::test(start_paused = true)]
    async fn a_pushed_archive_is_loaded_tagged_into_the_apps_repository_and_deployed() {
        let h = deployed(NTFY).await;
        let before = h.fake.calls().len();

        let out = h.rec.push_archive(&name("ntfy"), tar(b"image-1")).await;
        let pushed = archive_digest(b"image-1");
        assert_eq!(
            out.unwrap(),
            DeployOutcome::Deployed {
                digest: pushed.clone(),
                generation: 2
            }
        );
        let st = h.state("ntfy");
        assert_eq!(
            (st.current, st.previous),
            (Some(pushed.clone()), Some(digest('a')))
        );
        assert!(h.container_digest_ref("ntfy").ends_with(pushed.as_str()));

        let calls = h.fake.calls()[before..].to_vec();
        assert!(calls.contains(&Call::ImageLoad { bytes: 7 }), "{calls:?}");
        assert!(
            calls
                .iter()
                .any(|c| matches!(c, Call::ImageTag { repo, tag, .. }
                if repo == REPO && tag == PUSHED_TAG)),
            "{calls:?}"
        );
        assert!(
            !calls.iter().any(|c| matches!(c, Call::ImagePull(_))),
            "a pushed image is never pulled: {calls:?}"
        );
        assert_eq!(std::fs::read_to_string(&h.rec.paths().apps).unwrap(), NTFY);
    }

    #[tokio::test(start_paused = true)]
    async fn pushing_the_same_archive_again_is_unchanged_and_a_new_one_moves_the_pointers() {
        let h = deployed(NTFY).await;
        let ntfy = name("ntfy");
        h.rec.push_archive(&ntfy, tar(b"image-1")).await.unwrap();
        let first = archive_digest(b"image-1");

        assert_eq!(
            h.rec.push_archive(&ntfy, tar(b"image-1")).await.unwrap(),
            DeployOutcome::Unchanged {
                digest: first.clone()
            }
        );

        let second = archive_digest(b"image-2");
        assert_eq!(
            h.rec.push_archive(&ntfy, tar(b"image-2")).await.unwrap(),
            DeployOutcome::Deployed {
                digest: second.clone(),
                generation: 3
            }
        );
        let st = h.state("ntfy");
        assert_eq!((st.current, st.previous), (Some(second), Some(first)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_pushed_image_that_fails_the_gate_rolls_back_and_is_retried_by_the_next_push() {
        let h = deployed(NTFY).await;
        let ntfy = name("ntfy");
        h.fake.script_health("ntfy", [HealthStatus::Healthy]);
        h.fake.script_health(
            "ntfy",
            [
                HealthStatus::Unhealthy,
                HealthStatus::Unhealthy,
                HealthStatus::Unhealthy,
                HealthStatus::Healthy,
            ],
        );
        let bad = archive_digest(b"broken");
        let out = h.rec.push_archive(&ntfy, tar(b"broken")).await.unwrap();
        assert!(
            matches!(&out, DeployOutcome::RolledBack { failed, restored, .. }
                if *failed == bad && *restored == digest('a')),
            "{out:?}"
        );
        let st = h.state("ntfy");
        assert_eq!(st.current, Some(digest('a')));
        assert_eq!(st.failed.as_ref().unwrap().digest, bad);

        // A manual push is the operator's will: the known-bad digest is tried again, not refused.
        h.fake.script_health(
            "ntfy",
            [
                HealthStatus::Unhealthy,
                HealthStatus::Unhealthy,
                HealthStatus::Unhealthy,
                HealthStatus::Healthy,
            ],
        );
        let again = h.rec.push_archive(&ntfy, tar(b"broken")).await.unwrap();
        assert!(
            matches!(again, DeployOutcome::RolledBack { .. }),
            "{again:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pushing_to_an_app_with_start_false_only_pins_the_image() {
        let h = Harness::new(PROVISION_ONLY);
        let out = h.rec.push_archive(&name("gate"), tar(b"image-1")).await;
        let pushed = archive_digest(b"image-1");
        assert_eq!(
            out.unwrap(),
            DeployOutcome::Provisioned {
                digest: pushed.clone()
            }
        );
        assert!(h.fake.containers().is_empty());
        assert_eq!(h.state("gate").current, Some(pushed));
    }

    #[tokio::test(start_paused = true)]
    async fn a_broken_archive_changes_nothing_and_frees_the_upload_slot() {
        let h = deployed(NTFY).await;
        let ntfy = name("ntfy");
        h.fake.script_next_load_failure("unrecognized image format");
        let err = h
            .rec
            .push_archive(&ntfy, tar(b"not a tar"))
            .await
            .unwrap_err();
        assert!(matches!(&err, EngineError::PushLoad(m) if m.contains("unrecognized")));
        assert_eq!(h.state("ntfy").current, Some(digest('a')));
        assert_eq!(h.state("ntfy").generation, 1);
        // The slot is free again.
        h.rec.push_archive(&ntfy, tar(b"image-1")).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_upload_is_refused_while_one_is_in_progress() {
        let h = deployed(NTFY).await;
        let rec = h.rec.clone();
        let upload = tokio::spawn(async move {
            let endless: TarStream = stream::pending().boxed();
            let _ = rec.push_archive(&name("ntfy"), endless).await;
        });
        tokio::time::sleep(Duration::from_secs(1)).await;
        let err = h
            .rec
            .push_archive(&name("ntfy"), tar(b"image-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::PushBusy), "{err:?}");
        // The engine itself is not held by the upload: a deploy still goes through.
        h.rec.deploy(&name("ntfy"), false).await.unwrap();
        upload.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn an_unknown_app_is_refused_before_the_archive_is_read() {
        let h = deployed(NTFY).await;
        let before = h.fake.calls().len();
        let err = h
            .rec
            .push_archive(&name("nope"), tar(b"image-1"))
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::UnknownInstance(_)), "{err:?}");
        assert_eq!(h.fake.calls().len(), before);
    }
}

/// Blue-green deploys (issue #39, `docs/decisions/0046-blue-green-deploy.md`).
mod blue_green {
    use super::*;

    const BG: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
strategy = "blue_green"
health = { attempts = 3, window_secs = 6, command = ["true"] }
"#;

    /// `BG` deployed once (digest `a`), the way a first deploy goes: nothing to swap with yet.
    async fn deployed_bg(apps: &str) -> Harness {
        let h = Harness::new(apps);
        h.fake.set_pull_digest(IMAGE, digest('a'));
        h.fake.script_health("ntfy", [HealthStatus::Healthy]);
        h.rec.reconcile().await.unwrap();
        h
    }

    /// Index of the **last** `c`: the sweep of leftovers at the start also calls stop/remove on the
    /// transient names, and it is the real stop at the end that matters for the order.
    fn pos(calls: &[Call], c: &Call) -> usize {
        calls
            .iter()
            .rposition(|x| x == c)
            .unwrap_or_else(|| panic!("{c:?} not in {calls:?}"))
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_deploy_has_nothing_to_swap_with() {
        let h = deployed_bg(BG).await;
        let calls = h.fake.calls();
        assert!(calls.contains(&Call::ContainerCreate("ntfy".into())));
        assert!(!calls.contains(&Call::ContainerCreate("ntfy.next".into())));
    }

    #[tokio::test(start_paused = true)]
    async fn the_new_container_takes_over_before_the_old_one_stops() {
        let h = deployed_bg(BG).await;
        let ntfy = name("ntfy");
        h.fake.set_pull_digest(IMAGE, digest('b'));
        h.fake.script_health("ntfy.next", [HealthStatus::Healthy]);
        let before = h.fake.calls().len();

        assert_eq!(
            h.rec.deploy(&ntfy, false).await.unwrap(),
            DeployOutcome::Deployed {
                digest: digest('b'),
                generation: 2
            }
        );
        let calls = h.fake.calls()[before..].to_vec();
        let app_net = labels::network_name(&ntfy);
        // The serving container is never stopped under its own name: it is renamed out of the way,
        // keeps serving through the drain, and only then stops.
        assert!(!calls.contains(&Call::ContainerStop("ntfy".into())));
        let order = [
            Call::ContainerCreate("ntfy.next".into()),
            Call::ContainerStart("ntfy.next".into()),
            Call::HealthcheckRun("ntfy.next".into()),
            Call::NetworkConnectAliased {
                network: app_net,
                container: "ntfy.next".into(),
                aliases: vec!["ntfy".into()],
            },
            Call::ContainerRename {
                from: "ntfy".into(),
                to: "ntfy.prev".into(),
            },
            Call::ContainerRename {
                from: "ntfy.next".into(),
                to: "ntfy".into(),
            },
            Call::ContainerStop("ntfy.prev".into()),
            Call::ContainerRemove("ntfy.prev".into()),
        ];
        let positions: Vec<usize> = order.iter().map(|c| pos(&calls, c)).collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?}");

        // One container, under the plain name, on the new digest; the staging network is gone.
        let containers = h.fake.containers();
        assert_eq!(containers.len(), 1, "{containers:?}");
        assert_eq!(containers[0].name, "ntfy");
        assert!(
            h.container_digest_ref("ntfy")
                .ends_with(digest('b').as_str())
        );
        assert!(
            !h.fake
                .networks()
                .contains(&labels::staging_network_name(&ntfy))
        );
        let st = h.state("ntfy");
        assert_eq!(
            (st.current, st.previous),
            (Some(digest('b')), Some(digest('a')))
        );
        // The new container is what the spec hash describes.
        assert_eq!(
            containers[0]
                .labels
                .get(labels::INSTANCE)
                .map(String::as_str),
            Some("ntfy")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_challenger_that_fails_its_gate_leaves_the_old_container_serving() {
        let h = deployed_bg(BG).await;
        let ntfy = name("ntfy");
        h.fake.set_pull_digest(IMAGE, digest('b'));
        h.fake.script_health("ntfy.next", [HealthStatus::Unhealthy]);
        let before = h.fake.calls().len();

        let out = h.rec.deploy(&ntfy, false).await.unwrap();
        assert!(
            matches!(&out, DeployOutcome::Failed { digest: d, .. } if *d == digest('b')),
            "{out:?}"
        );
        let calls = h.fake.calls()[before..].to_vec();
        // Not a single call touched the serving container: no outage on a bad deploy.
        assert!(!calls.iter().any(|c| matches!(
            c,
            Call::ContainerStop(n) | Call::ContainerRemove(n) if n == "ntfy"
        )));
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Call::ContainerRename { .. }))
        );

        let containers = h.fake.containers();
        assert_eq!(containers.len(), 1, "{containers:?}");
        assert_eq!(containers[0].state, ContainerState::Running);
        assert!(
            h.container_digest_ref("ntfy")
                .ends_with(digest('a').as_str())
        );
        assert!(
            !h.fake
                .networks()
                .contains(&labels::staging_network_name(&ntfy))
        );

        let st = h.state("ntfy");
        assert_eq!(st.current, Some(digest('a')));
        assert_eq!(st.failed.as_ref().unwrap().digest, digest('b'));
        let events = h.sink.events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::DeployFailed { .. }))
        );
        assert!(!events.iter().any(|e| matches!(e, Event::RolledBack { .. })));
        // The bad digest is not retried by the webhook.
        assert_eq!(
            h.rec.deploy(&ntfy, false).await.unwrap(),
            DeployOutcome::KnownBad {
                digest: digest('b')
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_container_healthcheck_the_swap_is_refused() {
        let h = deployed_bg(BG).await;
        // The check inside the container goes away (and the image declares none): `health.http` alone
        // would probe the old container through the ingress, so nothing can vouch for the new one.
        h.set_apps(
            r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
strategy = "blue_green"
health = { attempts = 3, window_secs = 6 }
"#,
        );
        h.fake.set_pull_digest(IMAGE, digest('b'));
        let out = h.rec.deploy(&name("ntfy"), false).await.unwrap();
        let DeployOutcome::Failed { reason, .. } = out else {
            panic!("{out:?}");
        };
        assert!(reason.contains("container healthcheck"), "{reason}");
        let calls = h.fake.calls();
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Call::ContainerRename { .. }))
        );
        // The old container still serves, and the challenger is gone.
        let containers = h.fake.containers();
        assert_eq!(containers.len(), 1, "{containers:?}");
        assert_eq!(containers[0].name, "ntfy");
        assert_eq!(containers[0].state, ContainerState::Running);
    }

    #[tokio::test(start_paused = true)]
    async fn reconcile_does_not_remove_the_transient_containers() {
        let h = deployed_bg(BG).await;
        // A challenger and a retiring container exist only inside a deploy, which holds the engine lock;
        // a pass that sees them must leave them to that deploy.
        for transient in ["ntfy.next", "ntfy.prev"] {
            h.fake.add_foreign_container(transient, IMAGE);
            h.fake.set_container_labels(
                transient,
                BTreeMap::from([(labels::INSTANCE.to_owned(), "ntfy".to_owned())]),
            );
        }
        let report = h.rec.reconcile().await.unwrap();
        assert!(
            !report
                .actions
                .iter()
                .any(|a| matches!(&a.action, Action::Remove { .. })),
            "{:?}",
            report.actions
        );
    }
}

/// Static sites (ADR 0049): a pinned image is unpacked into a release and `current` is switched.
mod static_sites {
    use super::*;

    const SITE: &str = r#"
[apps.blog]
kind = "static"
image = "registry.example.com/me/blog:latest"
domains = ["blog.example.com"]
"#;
    const SITE_IMAGE: &str = "registry.example.com/me/blog:latest";

    /// A `docker-archive` whose single layer holds `files`.
    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
            let mut b = tar::Builder::new(Vec::new());
            for (path, data) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, path, *data).unwrap();
            }
            b.into_inner().unwrap()
        }
        tar_of(&[
            (
                "manifest.json",
                br#"[{"Config":"c.json","Layers":["l/layer.tar"]}]"#,
            ),
            ("l/layer.tar", &tar_of(files)),
        ])
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let sites = dir.path().join("sites");
        let h = Harness::build(
            SITE,
            ReconcilerOptions {
                sites_root: Some(sites),
                ..Default::default()
            },
            crash::Policy::disabled(),
        );
        drop(dir);
        h
    }

    fn sites(h: &Harness) -> std::path::PathBuf {
        h.rec.options.sites_root.clone().unwrap()
    }

    fn publish(h: &Harness, d: char, files: &[(&str, &[u8])]) -> Digest {
        h.fake.set_pull_digest(SITE_IMAGE, digest(d));
        h.fake.script_image_archive(&digest(d), archive(files));
        digest(d)
    }

    #[tokio::test(start_paused = true)]
    async fn reconcile_unpacks_the_site_and_creates_no_container() {
        let h = harness();
        let d = publish(&h, 'a', &[("index.html", b"<h1>hi</h1>")]);
        let report = h.rec.reconcile().await.unwrap();
        assert!(matches!(
            single(&report),
            ActionOutcome::Deployed(DeployOutcome::Deployed { .. })
        ));
        let site = sites(&h).join("blog");
        assert_eq!(
            std::fs::read(site.join("current/index.html")).unwrap(),
            b"<h1>hi</h1>"
        );
        assert_eq!(h.state("blog").current, Some(d));
        assert!(h.fake.containers().is_empty());
        // Converged: the next pass does nothing.
        assert!(h.rec.reconcile().await.unwrap().actions.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_digest_switches_current_and_keeps_only_two_releases() {
        let h = harness();
        for (i, c) in ['a', 'b', 'c'].into_iter().enumerate() {
            let body = format!("v{i}");
            publish(&h, c, &[("index.html", body.as_bytes())]);
            h.rec.deploy(&name("blog"), false).await.unwrap();
            let served =
                std::fs::read_to_string(sites(&h).join("blog/current/index.html")).unwrap();
            assert_eq!(served, body);
        }
        let st = h.state("blog");
        assert_eq!(st.current, Some(digest('c')));
        assert_eq!(st.previous, Some(digest('b')));
        let releases = std::fs::read_dir(sites(&h).join("blog/releases"))
            .unwrap()
            .count();
        assert_eq!(releases, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_broken_site_never_replaces_the_one_being_served() {
        let h = harness();
        publish(&h, 'a', &[("index.html", b"good")]);
        h.rec.deploy(&name("blog"), false).await.unwrap();
        // No index.html: the release is rejected and `current` stays.
        publish(&h, 'b', &[("about.html", b"oops")]);
        let outcome = h.rec.deploy(&name("blog"), false).await.unwrap();
        assert!(
            matches!(outcome, DeployOutcome::Failed { .. }),
            "{outcome:?}"
        );
        let served = std::fs::read_to_string(sites(&h).join("blog/current/index.html")).unwrap();
        assert_eq!(served, "good");
        let st = h.state("blog");
        assert_eq!(st.current, Some(digest('a')));
        assert_eq!(st.failed.map(|f| f.digest), Some(digest('b')));
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_sites_directory_the_deploy_is_refused() {
        let h = Harness::new(SITE);
        h.fake.set_pull_digest(SITE_IMAGE, digest('a'));
        let err = h.rec.deploy(&name("blog"), false).await.unwrap_err();
        assert!(matches!(err, EngineError::Site(_)), "{err:?}");
    }
}
