//! Integration tests against a real Podman 6 (CI job `integration-podman`).
//! They require `WEGLARKA_PODMAN_SOCKET`; without it every test is skipped
//! (docs/decisions/0002-podman-in-ci.md).

use std::collections::BTreeMap;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use tokio::time::timeout;
use weglarka_model::app::SecretTarget;
use weglarka_model::podman::{
    ContainerFilter, ContainerSpec, ContainerState, EventFilter, EventKind, HealthStatus,
    LogSource, NetworkSpec, PodmanClient, PodmanError, PortMapping, PullEvent, RestartPolicy,
    SecretAttachment,
};
use weglarka_podman::LibpodClient;

/// A small image that runs forever (no shell, ~300 KB) and has `/pause -v` for the healthcheck.
const IMAGE: &str = "registry.k8s.io/pause:3.9";
/// Has a shell, so the test can make a container exit immediately (crash-loop detection).
const BUSYBOX: &str = "docker.io/library/busybox:latest";
const STEP: Duration = Duration::from_secs(60);
/// A crashed container is restarted quickly (the first restart has a short backoff).
const RESTART_DEADLINE: Duration = Duration::from_secs(30);

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

/// Unique per-run suffix so that parallel/repeated runs do not collide.
fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{}", std::process::id(), nanos % 1_000_000_000)
}

/// A loopback host port that was free a moment ago: bind `127.0.0.1:0`, read the assigned port and
/// release it again. Only this test publishes ports in the CI job, so the tiny TOCTOU race is
/// acceptable — losing it fails the container start loudly instead of passing silently.
fn free_host_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback port");
    listener.local_addr().expect("local addr").port()
}

/// `(host ip, host port)` pairs under one container-port key of `HostConfig.PortBindings` or
/// `NetworkSettings.Ports` (both use the same libpod inspect shape); empty when unset/null.
fn port_bindings(ports: &serde_json::Value, container_port: &str) -> Vec<(String, String)> {
    ports
        .get(container_port)
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    (
                        entry["HostIp"].as_str().unwrap_or_default().to_owned(),
                        entry["HostPort"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Raw API call via `curl` — for things outside the client contract (network cleanup,
/// a container with a healthcheck that `ContainerSpec` cannot describe).
fn raw(socket: &str, method: &str, path: &str, body: Option<&str>) -> (bool, String) {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "--fail-with-body",
        "--unix-socket",
        socket,
        "-X",
        method,
    ]);
    if let Some(body) = body {
        cmd.args(["-H", "content-type: application/json", "-d", body]);
    }
    cmd.arg(format!("http://d/v6.0.0/libpod{path}"));
    let out = cmd
        .output()
        .expect("curl is required for integration tests");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Cleans up after the test even on panic (`Drop`).
struct Cleanup {
    socket: String,
    containers: Vec<String>,
    networks: Vec<String>,
    secrets: Vec<String>,
    images: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &self.containers {
            raw(
                &self.socket,
                "DELETE",
                &format!("/containers/{c}?force=true&v=true"),
                None,
            );
        }
        for n in &self.networks {
            raw(
                &self.socket,
                "DELETE",
                &format!("/networks/{n}?force=true"),
                None,
            );
        }
        for s in &self.secrets {
            raw(&self.socket, "DELETE", &format!("/secrets/{s}"), None);
        }
        for i in &self.images {
            raw(&self.socket, "DELETE", &format!("/images/{i}"), None);
        }
    }
}

fn spec(name: &str, labels: BTreeMap<String, String>) -> ContainerSpec {
    ContainerSpec {
        name: name.into(),
        image: IMAGE.into(),
        command: vec![],
        entrypoint: None,
        labels,
        env: BTreeMap::from([("WEGLARKA_IT".into(), "1".into())]),
        networks: vec![],
        network_aliases: Default::default(),
        secrets: vec![],
        publish: vec![],
        restart: RestartPolicy::No,
        userns_auto: true,
        mounts: vec![],
        volumes: vec![],
        resources: Default::default(),
        healthcheck: None,
        id_mapping: None,
        keep_groups: false,
        security: Default::default(),
    }
}

#[tokio::test]
async fn version_is_podman_6() {
    let Some(socket) = socket() else { return };
    let v = LibpodClient::new(socket).version().await.unwrap();
    assert!(v.version.starts_with("6."), "{v:?}");
    assert!(v.api_version.starts_with("6."), "{v:?}");
}

#[tokio::test]
async fn pull_failure_is_an_error_not_a_completion() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(socket);
    let events: Vec<_> = timeout(
        STEP,
        client
            .image_pull("registry.k8s.io/weglarka-does-not-exist:nope")
            .collect::<Vec<_>>(),
    )
    .await
    .unwrap();
    assert!(
        matches!(events.last(), Some(Err(_))),
        "pull nieistniejącego obrazu musi skończyć się błędem: {events:?}"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Ok(PullEvent::Complete { .. })))
    );
}

#[tokio::test]
async fn full_lifecycle() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let (net_a, net_b) = (format!("weglarka-it-a-{id}"), format!("weglarka-it-b-{id}"));
    let (secret_env, secret_mount) = (
        format!("weglarka-it-env-{id}"),
        format!("weglarka-it-mnt-{id}"),
    );
    let (app, hc_app) = (
        format!("weglarka-it-app-{id}"),
        format!("weglarka-it-hc-{id}"),
    );
    let tag_repo = "localhost/weglarka-it";
    let tag = format!("rollback-{id}");
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![app.clone(), hc_app.clone()],
        networks: vec![net_a.clone(), net_b.clone()],
        secrets: vec![secret_env.clone(), secret_mount.clone()],
        images: vec![format!("{tag_repo}:{tag}")],
    };
    let labels = BTreeMap::from([
        ("weglarka.instance".to_owned(), format!("it-{id}")),
        ("weglarka.generation".to_owned(), "1".to_owned()),
        ("weglarka.spec-hash".to_owned(), "deadbeef".to_owned()),
    ]);

    // Image: pull as a stream ending in Complete with a digest; inspect agrees with the pull.
    let events: Vec<_> = timeout(STEP, client.image_pull(IMAGE).collect::<Vec<_>>())
        .await
        .unwrap();
    let Some(Ok(PullEvent::Complete { image_id, digest })) = events.last() else {
        panic!("pull nie zakończył się Complete: {events:?}");
    };
    let digest = digest.clone().expect("digest po pullu");
    let image = client.image_inspect(IMAGE).await.unwrap();
    assert_eq!(image.digest.as_ref(), Some(&digest));
    assert!(
        image.id.starts_with(image_id.trim_start_matches("sha256:"))
            || image_id.starts_with(&image.id)
    );

    // Tag (manual rollback) and removal of the tag alone.
    client.image_tag(&image.id, tag_repo, &tag).await.unwrap();
    let tagged = client
        .image_inspect(&format!("{tag_repo}:{tag}"))
        .await
        .unwrap();
    assert!(
        tagged
            .repo_tags
            .iter()
            .any(|t| t.ends_with(&format!(":{tag}")))
    );
    client
        .image_remove(&format!("{tag_repo}:{tag}"))
        .await
        .unwrap();
    assert!(matches!(
        client.image_inspect(&format!("{tag_repo}:{tag}")).await,
        Err(PodmanError::NotFound(_))
    ));

    // Retention (#40): the listing carries every name of the image plus its size, and an untagged
    // image stays attributable through its repository digest.
    let listed = client.image_list().await.unwrap();
    let entry = listed
        .iter()
        .find(|i| i.id == image.id)
        .expect("the pulled image is listed");
    assert!(entry.repo_tags.iter().any(|t| t == IMAGE));
    assert!(
        entry
            .repo_digests
            .iter()
            .any(|d| d.ends_with(digest.as_str()))
    );
    assert!(entry.size_bytes > 0, "libpod reports the image size");

    // Networks: idempotent create; secrets: create overwrites.
    let net = |name: &str| NetworkSpec {
        name: name.into(),
        internal: false,
        labels: BTreeMap::from([("weglarka.instance".into(), format!("it-{id}"))]),
    };
    client.network_create(&net(&net_a)).await.unwrap();
    client.network_create(&net(&net_a)).await.unwrap();
    client.network_create(&net(&net_b)).await.unwrap();
    client.secret_create(&secret_env, b"v1").await.unwrap();
    client.secret_create(&secret_env, b"v2").await.unwrap();
    client
        .secret_create(&secret_mount, b"{\"k\":1}")
        .await
        .unwrap();

    // Events: stream opened "from now" (since), read after the actions.
    let since = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        - 1;
    let event_filter = EventFilter {
        labels: BTreeMap::from([("weglarka.instance".into(), format!("it-{id}"))]),
        since: Some(since),
    };
    let mut events = Box::pin(client.events(&event_filter));

    // Container with weglarka.* labels, a network, an env secret and a mount, userns=auto.
    let mut app_spec = spec(&app, labels.clone());
    app_spec.networks = vec![net_a.clone()];
    app_spec.secrets = vec![
        SecretAttachment {
            secret: secret_env.clone(),
            target: SecretTarget::Env {
                var: "MY_SECRET".into(),
            },
        },
        SecretAttachment {
            secret: secret_mount.clone(),
            target: SecretTarget::Mount {
                path: "/config.json".into(),
                mode: Some(0o440),
                // Container-space ids (issue #55), mapped by libpod through the instance range.
                uid: Some(1000),
                gid: Some(1000),
            },
        },
    ];
    // A fixed loopback port, so the mapping can be checked against an exact expected value.
    let host_port = free_host_port();
    app_spec.publish = vec![PortMapping {
        host_ip: Some("127.0.0.1".into()),
        host_port,
        container_port: 8080,
    }];
    let created = client.container_create(&app_spec).await.unwrap();
    let duplicate = client.container_create(&app_spec).await;
    assert!(
        matches!(duplicate, Err(PodmanError::Conflict(_))),
        "duplikat nazwy: {duplicate:?}"
    );
    let info = client.container_inspect(&app).await.unwrap();
    assert_eq!(info.id, created);
    assert_eq!(info.state, ContainerState::Created);
    assert_eq!(info.labels, labels);
    assert_eq!(info.image, IMAGE);

    client.container_start(&app).await.unwrap();
    client.container_start(&app).await.unwrap(); // already running: idempotent (304)
    client.network_connect(&net_b, &app).await.unwrap();
    let info = client.container_inspect(&app).await.unwrap();
    assert_eq!(info.state, ContainerState::Running);
    assert!(
        info.networks.contains(&net_b),
        "connected network is reported"
    );
    // The published mapping took effect, not just got accepted at create: inspect reports the
    // requested loopback binding and the actual host-port assignment for the container port.
    // This image (pause) does not listen on 8080, so there is deliberately no TCP connect check.
    let (ok, body) = raw(&socket, "GET", &format!("/containers/{app}/json"), None);
    assert!(ok, "raw inspect: {body}");
    let inspected: serde_json::Value = serde_json::from_str(&body).unwrap();
    let expected_binding = vec![("127.0.0.1".to_owned(), host_port.to_string())];
    assert_eq!(
        port_bindings(&inspected["HostConfig"]["PortBindings"], "8080/tcp"),
        expected_binding,
        "HostConfig.PortBindings must publish 127.0.0.1:{host_port} -> 8080/tcp: {}",
        inspected["HostConfig"],
    );
    assert_eq!(
        port_bindings(&inspected["NetworkSettings"]["Ports"], "8080/tcp"),
        expected_binding,
        "NetworkSettings.Ports must report the applied mapping: {}",
        inspected["NetworkSettings"],
    );
    assert_eq!(info.health, None, "obraz bez healthchecka");
    assert!(matches!(
        client.healthcheck_run(&app).await,
        Err(PodmanError::Api { status: 409, .. })
    ));

    // List filtered by labels sees exactly our container.
    let listed = client
        .container_list(&ContainerFilter {
            labels: BTreeMap::from([("weglarka.instance".into(), format!("it-{id}"))]),
        })
        .await
        .unwrap();
    assert_eq!(
        listed.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        [app.as_str()]
    );
    let none = client
        .container_list(&ContainerFilter {
            labels: BTreeMap::from([("weglarka.instance".into(), "no-such".into())]),
        })
        .await
        .unwrap();
    assert!(none.is_empty());

    // Healthcheck run: a container with a healthcheck outside the `ContainerSpec` contract (created raw).
    let body = serde_json_body(&hc_app, &id);
    let (ok, out) = raw(&socket, "POST", "/containers/create", Some(&body));
    assert!(ok, "raw create: {out}");
    client.container_start(&hc_app).await.unwrap();
    assert_eq!(
        client.healthcheck_run(&hc_app).await.unwrap(),
        HealthStatus::Healthy
    );
    assert!(
        client
            .container_inspect(&hc_app)
            .await
            .unwrap()
            .health
            .is_some()
    );
    client.container_stop(&hc_app, 1).await.unwrap();
    client.container_remove(&hc_app, false).await.unwrap();

    // Stop (idempotent) and removal.
    client.container_stop(&app, 1).await.unwrap();
    client.container_stop(&app, 1).await.unwrap();
    let info = client.container_inspect(&app).await.unwrap();
    assert!(
        matches!(info.state, ContainerState::Exited | ContainerState::Stopped),
        "{info:?}"
    );
    assert!(info.exit_code.is_some());
    client.container_remove(&app, false).await.unwrap();
    assert!(matches!(
        client.container_inspect(&app).await,
        Err(PodmanError::NotFound(_))
    ));
    assert!(matches!(
        client.container_remove(&app, false).await,
        Err(PodmanError::NotFound(_))
    ));
    client.secret_remove(&secret_env).await.unwrap();
    client.secret_remove(&secret_mount).await.unwrap();
    assert!(matches!(
        client.secret_remove(&secret_env).await,
        Err(PodmanError::NotFound(_))
    ));

    // Events: the stream (opened with `since`) replays the start and stop of our container.
    let (mut started, mut stopped) = (false, false);
    while !(started && stopped) {
        let event = timeout(STEP, events.next())
            .await
            .expect("timeout czekając na zdarzenia")
            .expect("strumień zdarzeń nie powinien się kończyć")
            .unwrap();
        if event.kind == EventKind::Container && event.name == app {
            started |= event.action == "start";
            stopped |= matches!(event.action.as_str(), "die" | "died" | "stop");
        }
    }
}

fn serde_json_body(name: &str, id: &str) -> String {
    format!(
        r#"{{"name":"{name}","image":"{IMAGE}","labels":{{"weglarka.instance":"it-{id}-hc"}},
"healthconfig":{{"Test":["CMD","/pause","-v"],"Interval":30000000000,"Timeout":5000000000,"Retries":1}}}}"#
    )
}

#[tokio::test]
async fn network_list_shows_labels_and_remove_is_idempotent() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(socket);
    let net = format!("wg-it-net-{}", run_id());
    client
        .network_create(&NetworkSpec {
            name: net.clone(),
            internal: false,
            labels: BTreeMap::from([("weglarka.instance".to_owned(), "it".to_owned())]),
        })
        .await
        .unwrap();
    let listed = client.network_list().await.unwrap();
    let found = listed
        .iter()
        .find(|n| n.name == net)
        .expect("network listed");
    assert_eq!(
        found.labels.get("weglarka.instance").map(String::as_str),
        Some("it")
    );

    client.network_remove(&net).await.unwrap();
    // Missing → Ok (idempotent).
    client.network_remove(&net).await.unwrap();
    assert!(
        !client
            .network_list()
            .await
            .unwrap()
            .iter()
            .any(|n| n.name == net)
    );
}

#[tokio::test]
async fn hardened_container_starts_with_read_only_root_dropped_caps_and_no_new_privileges() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(socket.clone());
    let name = format!("wg-it-hardened-{}", run_id());
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![name.clone()],
        networks: vec![],
        secrets: vec![],
        images: vec![],
    };
    let mut s = spec(&name, BTreeMap::new());
    s.security = weglarka_model::app::Security {
        read_only: true,
        tmpfs: vec!["/cache".into()],
        cap_drop: vec!["ALL".into()],
        cap_add: vec![],
        no_new_privileges: true,
    };
    let events: Vec<_> = timeout(STEP, client.image_pull(IMAGE).collect::<Vec<_>>())
        .await
        .unwrap();
    assert!(
        matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
        "{events:?}"
    );
    client.container_create(&s).await.unwrap();
    client.container_start(&name).await.unwrap();

    let (ok, body) = raw(&socket, "GET", &format!("/containers/{name}/json"), None);
    assert!(ok, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let host = &v["HostConfig"];
    assert_eq!(host["ReadonlyRootfs"], true, "{host}");
    // Inspect reports either the literal ALL or the expanded list, and the effective set.
    let effective = v["EffectiveCaps"].as_array().cloned().unwrap_or_default();
    assert!(effective.is_empty(), "no capabilities left: {effective:?}");
    assert!(
        host["SecurityOpt"]
            .to_string()
            .contains("no-new-privileges"),
        "{}",
        host["SecurityOpt"]
    );
    let in_mounts = v["Mounts"]
        .as_array()
        .is_some_and(|ms| ms.iter().any(|m| m["Destination"] == "/cache"));
    let in_tmpfs = host["Tmpfs"].get("/cache").is_some();
    assert!(
        in_mounts || in_tmpfs,
        "tmpfs /cache mounted: Mounts={} Tmpfs={}",
        v["Mounts"],
        host["Tmpfs"]
    );
    assert_eq!(v["State"]["Status"], "running");
}

/// Issue #79: `ContainerSpec.command` reaches libpod as the arguments after the image's ENTRYPOINT
/// (`SpecGenerator.command` → OCI `Cmd`), not as an entrypoint override. `pause -v` prints its
/// version and exits 0, while `pause` with no arguments runs forever — so a zero exit code proves
/// the argument was delivered, and an entrypoint override would fail to exec.
#[tokio::test]
async fn command_reaches_libpod_as_arguments_to_the_image_entrypoint() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(socket.clone());
    let name = format!("wg-it-command-{}", run_id());
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![name.clone()],
        networks: vec![],
        secrets: vec![],
        images: vec![],
    };
    let events: Vec<_> = timeout(STEP, client.image_pull(IMAGE).collect::<Vec<_>>())
        .await
        .unwrap();
    assert!(
        matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
        "{events:?}"
    );
    let mut s = spec(&name, BTreeMap::new());
    s.command = vec!["-v".into()];
    client.container_create(&s).await.unwrap();
    let (ok, body) = raw(&socket, "GET", &format!("/containers/{name}/json"), None);
    assert!(ok, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(created["Config"]["Cmd"], serde_json::json!(["-v"]));

    client.container_start(&name).await.unwrap();
    let deadline = tokio::time::Instant::now() + STEP;
    let state = loop {
        let (ok, body) = raw(&socket, "GET", &format!("/containers/{name}/json"), None);
        assert!(ok, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let status = v["State"]["Status"].as_str().unwrap_or_default();
        if status == "exited" || status == "stopped" {
            break v["State"].clone();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "container still {status} (no argument reached it?)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(state["ExitCode"], 0, "{state}");
}

/// One-off containers (issue #106): `entrypoint` replaces the image's, the log stream arrives split
/// by stream with `follow`, `wait` returns the exit code, and a forced remove leaves nothing behind.
#[tokio::test]
async fn one_off_container_streams_its_output_and_reports_the_exit_code() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(socket.clone());
    let name = format!("wg-it-run-{}", run_id());
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![name.clone()],
        networks: vec![],
        secrets: vec![],
        images: vec![],
    };
    let events: Vec<_> = timeout(STEP, client.image_pull(BUSYBOX).collect::<Vec<_>>())
        .await
        .unwrap();
    assert!(
        matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
        "{events:?}"
    );
    let mut s = spec(&name, BTreeMap::new());
    s.image = BUSYBOX.into();
    s.entrypoint = Some(vec!["/bin/sh".into()]);
    s.command = vec!["-c".into(), "echo out; echo err >&2; exit 3".into()];
    s.restart = RestartPolicy::No;
    client.container_create(&s).await.unwrap();
    client.container_start(&name).await.unwrap();

    let mut logs = timeout(STEP, client.container_logs(&name, true))
        .await
        .unwrap()
        .unwrap();
    let (mut stdout, mut stderr) = (String::new(), String::new());
    while let Some(chunk) = timeout(STEP, logs.next()).await.unwrap() {
        let chunk = chunk.unwrap();
        let text = String::from_utf8(chunk.data.to_vec()).unwrap();
        match chunk.source {
            LogSource::Stdout => stdout.push_str(&text),
            LogSource::Stderr => stderr.push_str(&text),
        }
    }
    assert_eq!((stdout.as_str(), stderr.as_str()), ("out\n", "err\n"));
    assert_eq!(
        timeout(STEP, client.container_wait(&name))
            .await
            .unwrap()
            .unwrap(),
        3
    );

    client.container_remove(&name, true).await.unwrap();
    assert!(matches!(
        client.container_inspect(&name).await,
        Err(PodmanError::NotFound(_))
    ));
}

/// libpod reports `RestartCount` in `GET /containers/{name}/json`; `weglarka-engine`'s crash-loop detector
/// reads exactly that field. A fixture cannot prove the field name — a missing field silently reads 0 —
/// so this test makes a real container crash and waits for the counter to move.
#[tokio::test]
async fn restart_count_is_reported_and_grows_after_a_crash() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(socket.clone());
    let name = format!("wg-restarts-{}", run_id());
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![name.clone()],
        networks: vec![],
        secrets: vec![],
        images: vec![],
    };
    let events: Vec<_> = timeout(STEP, client.image_pull(BUSYBOX).collect::<Vec<_>>())
        .await
        .unwrap();
    assert!(
        matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
        "{events:?}"
    );
    let mut s = spec(&name, BTreeMap::new());
    s.image = BUSYBOX.into();
    // Exits immediately, so conmon restarts it (`restart = always`).
    s.command = vec!["sh".into(), "-c".into(), "exit 1".into()];
    s.restart = RestartPolicy::Always;
    client.container_create(&s).await.unwrap();
    client.container_start(&name).await.unwrap();
    let deadline = tokio::time::Instant::now() + RESTART_DEADLINE;
    let info = loop {
        let info = client.container_inspect(&name).await.unwrap();
        if info.restarts >= 1 {
            break info;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "libpod never reported a restart: {info:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert!(info.restarts >= 1, "{info:?}");
}
