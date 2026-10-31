//! The Prometheus targets generator (#366, ADR 0064) against the real `promtool` in the official
//! Prometheus image, on a real rootless Podman. Validation is the only guard for this generator (no
//! health gate, no rollback), so its contract is measured here rather than read from the source: the
//! rendered files pass, and a malformed file, an empty label name, an invalid address and a file of the
//! wrong shape fail.
//!
//! Each case runs the way `validate_generated` runs it: a one-off container of the image with
//! `argv[0]` of `validate_argv` as the entrypoint (so `promtool` must be on the image's `PATH`) and the
//! version directory under a read-only bind of its parent at `/weglarka/generated`.
//!
//! Needs `WEGLARKA_PODMAN_SOCKET` (the `podman-tests` CI job sets it); skipped without it
//! (`docs/decisions/0002-podman-in-ci.md`). Run: `cargo test -p weglarka-daemon --test it -- promtool::`.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use weglarka_daemon::metrics::targets::{CHECK_FILE, PrometheusTargets, TARGETS_FILE};
use weglarka_model::app::{AppSpec, AppsFile, InstanceName};
use weglarka_model::generated::{ConfigGenerator, RenderInput};
use weglarka_model::podman::{BindMount, ContainerSpec, LogOptions, PodmanClient, PullEvent};
use weglarka_podman::LibpodClient;

/// The official image, pinned. `promtool` ships next to `prometheus` in `/bin`.
const PROMETHEUS: &str = "docker.io/prom/prometheus:v3.5.0";
const MOUNT: &str = "/weglarka/generated";
const VERSION: &str = "v-000000000000";
const STEP: Duration = Duration::from_secs(300);

const APPS: &str = r#"
[apps.prom]
image = "docker.io/prom/prometheus:v3.5.0"
port = 9090
metrics_port = 9090

[apps.forge]
image = "ghcr.io/example/forge:1"
port = 3000
metrics_port = 9100
metrics_path = "/internal/metrics"

[apps.blog]
image = "ghcr.io/example/blog:1"
port = 8080
"#;

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping the promtool test");
    }
    socket
}

fn generator() -> PrometheusTargets {
    PrometheusTargets::new(InstanceName::new("prom").unwrap(), 9464)
}

/// The generator's real output, as `(file name, text)`.
fn rendered() -> BTreeMap<String, String> {
    let apps: AppsFile = toml::from_str(APPS).unwrap();
    generator()
        .render(&RenderInput {
            apps: &apps,
            digests: &BTreeMap::new(),
        })
        .unwrap()
        .into_iter()
        .map(|f| {
            (
                f.name().as_str().to_owned(),
                String::from_utf8(f.bytes().to_vec()).unwrap(),
            )
        })
        .collect()
}

/// Lays `files` out as `<root>/v-…/` with the pipeline's modes (dirs 0755, files 0644), so the
/// image's `nobody` can read them through the bind.
fn lay_out(root: &Path, files: &BTreeMap<String, String>) {
    let version = root.join(VERSION);
    std::fs::create_dir_all(&version).unwrap();
    for dir in [root, version.as_path()] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for (name, text) in files {
        let path = version.join(name);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

/// Runs the generator's validator on `files` in a one-off container; returns the exit code and output.
async fn promtool(
    client: &LibpodClient,
    case: &str,
    files: &BTreeMap<String, String>,
) -> (i32, String) {
    let dir = tempfile::tempdir().unwrap();
    lay_out(dir.path(), files);
    let spec: AppSpec = toml::from_str(&format!("image = \"{PROMETHEUS}\"")).unwrap();
    let argv = generator()
        .validate_argv(&spec, &format!("{MOUNT}/{VERSION}"))
        .unwrap();
    let (program, args) = argv.split_first().unwrap();
    let name = format!(
        "wg-it-promtool-{case}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let container = ContainerSpec {
        command: args.to_vec(),
        entrypoint: Some(vec![program.clone()]),
        userns_auto: true,
        mounts: vec![BindMount {
            source: dir.path().to_string_lossy().into_owned(),
            target: MOUNT.into(),
            read_only: true,
        }],
        ..ContainerSpec::new(name.clone(), PROMETHEUS)
    };
    client.container_create(&container).await.unwrap();
    client.container_start(&name).await.unwrap();
    let code = tokio::time::timeout(STEP, client.container_wait(&name))
        .await
        .expect("promtool finished")
        .unwrap();
    let mut output = String::new();
    let mut logs = client
        .container_logs(&name, &LogOptions::default())
        .await
        .unwrap();
    while let Some(chunk) = logs.next().await {
        output.push_str(&String::from_utf8_lossy(&chunk.unwrap().data));
    }
    let _ = client.container_remove(&name, true).await;
    (code, output)
}

#[tokio::test]
async fn promtool_accepts_the_render_and_rejects_bad_targets() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(socket);
    let events: Vec<_> =
        tokio::time::timeout(STEP, client.image_pull(PROMETHEUS).collect::<Vec<_>>())
            .await
            .unwrap();
    assert!(
        matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
        "{events:?}"
    );
    let good = rendered();
    assert_eq!(good.len(), 2, "{good:?}");

    // The real render: exit 0, and promtool really went through the targets file.
    let (code, output) = promtool(&client, "valid", &good).await;
    assert_eq!(code, 0, "{output}");
    assert!(!output.contains("WARNING"), "{output}");

    let with_targets = |text: &str| {
        let mut files = good.clone();
        files.insert(TARGETS_FILE.to_owned(), text.to_owned());
        files
    };
    let bad = [
        ("malformed", "- targets: [\"forge:9100\"\n  labels: {\n"),
        // Prometheus 3 accepts any non-empty UTF-8 label name (`bad-label` passes, see below); an empty
        // name is invalid under both validation schemes.
        (
            "label",
            "- targets:\n    - \"forge:9100\"\n  labels:\n    \"\": \"x\"\n",
        ),
        // `/` is not allowed in a target address.
        (
            "address",
            "- targets:\n    - \"forge:9100/x\"\n  labels:\n    app: \"forge\"\n",
        ),
        // Not a list of target groups at all (what the check config itself would be).
        ("shape", good[CHECK_FILE].as_str()),
    ];
    for (case, text) in bad {
        let (code, output) = promtool(&client, case, &with_targets(text)).await;
        assert_ne!(code, 0, "{case}: promtool accepted it\n{output}");
    }

    // Measured in CI: the pinned Prometheus 3 validates label names as UTF-8, so a name outside the
    // legacy `[a-zA-Z_][a-zA-Z0-9_]*` alphabet is accepted. The generator only ever emits `app` and
    // `__metrics_path__`, so this does not matter for its output; the assertion keeps the ADR honest.
    let (code, output) = promtool(
        &client,
        "utf8-label",
        &with_targets("- targets:\n    - \"forge:9100\"\n  labels:\n    bad-label: \"x\"\n"),
    )
    .await;
    assert_eq!(code, 0, "{output}");

    // Without the targets file the check config alone would pass with a warning: the reason the
    // generator writes both files into one version. Measured, so the ADR's claim stays true.
    let mut alone = good.clone();
    alone.remove(TARGETS_FILE);
    let (code, output) = promtool(&client, "missing", &alone).await;
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("WARNING"), "{output}");
}
