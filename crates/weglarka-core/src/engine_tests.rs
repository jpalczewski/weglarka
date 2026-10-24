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
    BindMount, ContainerState, HealthStatus, NetworkSpec, PodmanClient, PortMapping,
};
use crate::reconcile::{
    Action, ActionOutcome, ActivityKind, EngineError, ReconcileReport, Reconciler,
    ReconcilerOptions, RecreateReason, SecretChangePolicy, Trigger,
};
use crate::secret_store::{SecretStore, SecretValue};
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

// ── config_root mounts and reload (issue #118, ADR 0026) ────────────────────────

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
