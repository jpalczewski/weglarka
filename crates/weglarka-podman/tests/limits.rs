//! Resource limits and `health.command` against a real rootless Podman 6 (CI job
//! `integration-podman`). Requires `WEGLARKA_PODMAN_SOCKET`; skipped without it
//! (docs/decisions/0002-podman-in-ci.md). Containers go through the typed client, so the assertions
//! check what libpod *stored* (`inspect`) — it ignores unknown create-body fields silently.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use serde_json::Value;
use weglarka_model::app::{CpuLimit, MemoryLimit, Resources};
use weglarka_model::limits::container_healthcheck;
use weglarka_model::podman::{ContainerSpec, HealthStatus, PodmanClient, RestartPolicy};
use weglarka_podman::LibpodClient;

/// The pause image has no HEALTHCHECK of its own; `/pause -v` prints its version and exits 0.
const IMAGE: &str = "registry.k8s.io/pause:3.9";

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{}", std::process::id(), nanos % 1_000_000_000)
}

fn raw(socket: &str, method: &str, path: &str) -> Option<String> {
    let out = Command::new("curl")
        .args([
            "-sS",
            "--fail-with-body",
            "--unix-socket",
            socket,
            "-X",
            method,
        ])
        .arg(format!("http://d/v6.0.0/libpod{path}"))
        .output()
        .expect("curl is required for integration tests");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

struct Cleanup {
    socket: String,
    containers: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &self.containers {
            raw(
                &self.socket,
                "DELETE",
                &format!("/containers/{c}?force=true&v=true"),
            );
        }
    }
}

fn spec(name: &str) -> ContainerSpec {
    ContainerSpec {
        name: name.into(),
        image: IMAGE.into(),
        command: vec![],
        entrypoint: None,
        labels: BTreeMap::new(),
        env: BTreeMap::new(),
        networks: vec![],
        network_aliases: Default::default(),
        secrets: vec![],
        publish: vec![],
        restart: RestartPolicy::No,
        userns_auto: true,
        mounts: vec![],
        volumes: vec![],
        resources: Resources::default(),
        healthcheck: None,
        id_mapping: None,
        keep_groups: false,
        security: Default::default(),
    }
}

async fn pull(client: &LibpodClient) {
    let events: Vec<_> = client.image_pull(IMAGE).collect().await;
    assert!(events.last().is_some_and(Result::is_ok), "{events:?}");
}

fn inspect(socket: &str, name: &str) -> Value {
    let body = raw(socket, "GET", &format!("/containers/{name}/json")).expect("inspect");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn limits_reach_inspect_and_the_cgroup() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let name = format!("weglarka-it-lim-{}", run_id());
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![name.clone()],
    };
    pull(&client).await;

    let mut s = spec(&name);
    s.resources = Resources {
        memory: Some(MemoryLimit::parse("64m").unwrap()),
        pids_limit: Some(100),
        cpus: Some(CpuLimit::try_from(0.5).unwrap()),
    };
    client.container_create(&s).await.unwrap();
    client.container_start(&name).await.unwrap();

    let info = inspect(&socket, &name);
    let host = &info["HostConfig"];
    assert_eq!(host["Memory"], 64 << 20, "{host}");
    assert_eq!(host["PidsLimit"], 100, "{host}");
    assert_eq!(host["CpuQuota"], 50_000, "{host}");
    assert_eq!(host["CpuPeriod"], 100_000, "{host}");

    // The kernel side needs cgroup v2 controller delegation to the user; where it is missing libpod
    // still records the request (asserted above) but the cgroup files keep `max` / do not exist.
    let cgroup = info["State"]["CgroupPath"].as_str().unwrap_or_default();
    for (file, want) in [("memory.max", "67108864"), ("pids.max", "100")] {
        match std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/{file}")) {
            Ok(v) if v.trim() != "max" => assert_eq!(v.trim(), want, "{file}"),
            other => eprintln!("cgroup {file} not enforced here (no delegation?): {other:?}"),
        }
    }
}

#[tokio::test]
async fn unset_limits_stay_unlimited() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let name = format!("weglarka-it-nolim-{}", run_id());
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![name.clone()],
    };
    pull(&client).await;
    client.container_create(&spec(&name)).await.unwrap();
    let host = inspect(&socket, &name)["HostConfig"].clone();
    assert_eq!(host["Memory"], 0, "{host}");
    // `PidsLimit` is deliberately not asserted: unset means "whatever containers.conf says"
    // (Podman defaults to 2048), which is the host admin's policy, not ours.
    assert_eq!(host["CpuQuota"], 0, "{host}");
}

#[tokio::test]
async fn health_command_overrides_the_image_and_drives_healthcheck_run() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let (good, bad) = (
        format!("weglarka-it-hcok-{id}"),
        format!("weglarka-it-hcbad-{id}"),
    );
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![good.clone(), bad.clone()],
    };
    pull(&client).await;

    for (name, cmd, want_healthy) in [
        (&good, vec!["/pause", "-v"], true),
        (&bad, vec!["/weglarka-no-such-binary"], false),
    ] {
        let mut s = spec(name);
        let gate = weglarka_model::app::HealthGate {
            command: Some(cmd.iter().map(ToString::to_string).collect()),
            ..Default::default()
        };
        let mut hc = container_healthcheck(&gate).unwrap();
        hc.retries = 1; // a single failure counts as unhealthy
        s.healthcheck = Some(hc);
        client.container_create(&s).await.unwrap();
        client.container_start(name).await.unwrap();

        let test = inspect(&socket, name)["Config"]["Healthcheck"]["Test"].clone();
        let mut expected = vec!["CMD".to_owned()];
        expected.extend(cmd.iter().map(ToString::to_string));
        assert_eq!(
            test,
            serde_json::json!(expected),
            "healthconfig not applied"
        );
        assert!(
            client
                .container_inspect(name)
                .await
                .unwrap()
                .health
                .is_some()
        );

        let status = client.healthcheck_run(name).await.unwrap();
        assert_eq!(
            status == HealthStatus::Healthy,
            want_healthy,
            "{name}: {status:?}"
        );
    }
}

#[tokio::test]
async fn stats_report_running_containers_with_usage_and_the_limit_comes_from_inspect() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let (limited, free, stopped) = (
        format!("weglarka-it-stl-{id}"),
        format!("weglarka-it-stf-{id}"),
        format!("weglarka-it-sts-{id}"),
    );
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![limited.clone(), free.clone(), stopped.clone()],
    };
    pull(&client).await;

    let mut s = spec(&limited);
    s.resources.memory = Some(MemoryLimit::parse("64m").unwrap());
    client.container_create(&s).await.unwrap();
    client.container_create(&spec(&free)).await.unwrap();
    client.container_create(&spec(&stopped)).await.unwrap();
    for name in [&limited, &free, &stopped] {
        client.container_start(name).await.unwrap();
    }
    client.container_stop(&stopped, 1).await.unwrap();

    assert_eq!(
        client
            .container_inspect(&limited)
            .await
            .unwrap()
            .memory_limit,
        Some(64 << 20)
    );
    assert_eq!(
        client.container_inspect(&free).await.unwrap().memory_limit,
        None
    );

    let stats = client.container_stats().await.unwrap();
    for name in [&limited, &free] {
        let entry = stats.iter().find(|c| &c.name == name);
        let entry = entry.unwrap_or_else(|| panic!("{name} missing from {stats:?}"));
        assert!(entry.memory_usage > 0, "{name}: {entry:?}");
    }
    // Measured here and reported in the PR: whether a stopped container is listed at all.
    let stopped_listed = stats.iter().any(|c| c.name == stopped);
    eprintln!("stopped container listed in stats: {stopped_listed}");
    assert!(
        !stopped_listed,
        "a stopped container must not appear in stats: {stats:?}"
    );
}

/// The fields the resource metrics (#351) read, from Podman 6 itself. Block I/O depends on the `io`
/// controller being delegated to the runner's user, a host property, so it is printed, not asserted.
#[tokio::test]
async fn stats_report_cpu_pids_network_and_block_io() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let name = format!("weglarka-it-stx-{}", run_id());
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![name.clone()],
    };
    pull(&client).await;
    client.container_create(&spec(&name)).await.unwrap();
    client.container_start(&name).await.unwrap();

    let stats = client.container_stats().await.unwrap();
    let entry = stats
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("{name} missing from {stats:?}"));
    eprintln!("stats of a running pause container: {entry:?}");
    assert!(
        entry.cpu_nanos > 0,
        "starting a process costs CPU: {entry:?}"
    );
    assert!(
        entry.pids >= 1,
        "a running container has a process: {entry:?}"
    );
    assert!(
        entry.network.is_some(),
        "the default network gives the container an interface: {entry:?}"
    );
    // Both 0 without the `io` controller (libpod sums an empty `io.stat`).
    eprintln!(
        "block I/O read={} write={}",
        entry.block_read_bytes, entry.block_write_bytes
    );

    let info = client.container_inspect(&name).await.unwrap();
    assert!(!info.oom_killed, "never killed: {info:?}");
}
