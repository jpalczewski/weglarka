//! Ingress container identity against a real rootless Podman 6 (issue #95,
//! `docs/decisions/0036`): the nginx master is container uid 0 and has to read the TLS private keys
//! that the daemon writes `0600` in `<nginx_conf_dir>/tls`, while the worker (uid 101 in the image)
//! must stay inside the reserved ingress range.
//!
//! `weglarka_core::volumes::ingress_id_mapping` maps container uid 0 to the rootless namespace's
//! uid 0 (the daemon's host user) and the rest of the range as usual. This test measures that libpod
//! accepts that two-line map rootless and that it has the intended effect; without
//! `WEGLARKA_PODMAN_SOCKET` it is skipped (`docs/decisions/0002-podman-in-ci.md`).

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use futures_util::StreamExt;
use weglarka_core::podman::{
    BindMount, ContainerSpec, IdMapping, PodmanClient, PullEvent, RestartPolicy,
};
use weglarka_core::uid_range::allocate;
use weglarka_core::volumes::{id_mapping, ingress_id_mapping};
use weglarka_podman::LibpodClient;

const ALPINE: &str = "docker.io/library/alpine:3.20";
/// Range size of the ingress container (`uid_range::INFRA_RANGE_SIZE`), large enough for uid 101.
const RANGE: u32 = 4096;

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

/// Raw libpod call for the parts `PodmanClient` does not expose (cleanup).
fn raw(socket: &str, method: &str, path: &str) -> Result<String, String> {
    let out = Command::new("curl")
        .args([
            "-sS",
            "--fail-with-body",
            "--unix-socket",
            socket,
            "-X",
            method,
            &format!("http://d/v6.0.0/libpod{path}"),
        ])
        .output()
        .expect("curl is required for integration tests");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// Size of the current user's subuid pool from `/etc/subuid` (offsets of the explicit id map are
/// relative to it, ADR 0009 finding 6).
fn subuid_pool_size() -> u64 {
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    fs::read_to_string("/etc/subuid")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(':');
            if parts.next()? != user {
                return None;
            }
            parts.next()?.parse::<u64>().ok()?;
            parts.next()?.parse::<u64>().ok()
        })
        .next()
        .expect("the CI user has a /etc/subuid entry")
}

/// Removes the containers of the test, also on panic.
struct Env {
    socket: String,
    client: LibpodClient,
    containers: Vec<String>,
}

impl Drop for Env {
    fn drop(&mut self) {
        for name in &self.containers {
            let _ = raw(
                &self.socket,
                "DELETE",
                &format!("/containers/{name}?force=true&v=true&timeout=0"),
            );
        }
    }
}

impl Env {
    async fn new(socket: String) -> Self {
        let client = LibpodClient::new(&socket);
        let events: Vec<_> = client.image_pull(ALPINE).collect().await;
        assert!(
            matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
            "{events:?}"
        );
        Self {
            socket,
            client,
            containers: Vec::new(),
        }
    }

    /// A container with the given id map that mounts `dir` read-only at `/tls` and sleeps.
    async fn container(&mut self, name: &str, dir: &Path, mapping: IdMapping) {
        self.containers.push(name.to_owned());
        self.client
            .container_create(&ContainerSpec {
                name: name.to_owned(),
                image: ALPINE.to_owned(),
                command: vec!["sleep".into(), "300".into()],
                labels: BTreeMap::new(),
                env: BTreeMap::new(),
                networks: vec![],
                network_aliases: Default::default(),
                secrets: vec![],
                publish: vec![],
                restart: RestartPolicy::No,
                userns_auto: false,
                mounts: vec![BindMount {
                    source: dir.display().to_string(),
                    target: "/tls".to_owned(),
                    read_only: true,
                }],
                volumes: vec![],
                resources: Default::default(),
                healthcheck: None,
                id_mapping: Some(mapping),
                security: Default::default(),
            })
            .await
            .unwrap();
        self.client.container_start(name).await.unwrap();
    }

    async fn exec(&self, name: &str, cmd: &[&str]) -> i32 {
        let cmd: Vec<String> = cmd.iter().map(|c| (*c).to_owned()).collect();
        self.client.container_exec(name, &cmd).await.unwrap()
    }
}

#[tokio::test]
async fn ingress_id_map_keeps_the_master_on_the_host_user_and_the_worker_in_the_range() {
    let Some(socket) = socket() else {
        return;
    };
    let mut env = Env::new(socket).await;

    // The daemon writes the TLS material as the host user, `0600` inside a `0700` directory.
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let key = dir.path().join("h.example.eu.key");
    fs::write(&key, "secret key material\n").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let range = allocate(&[], subuid_pool_size(), RANGE).expect("subuid pool");

    // The nginx container (`ingress_id_mapping`): its master (container uid 0) is the host user, so
    // it reads the key; the worker's uid is in the ingress range.
    env.container("wg-it-master", dir.path(), ingress_id_mapping(range))
        .await;
    assert_eq!(
        env.exec(
            "wg-it-master",
            &["sh", "-c", "test -r /tls/h.example.eu.key"]
        )
        .await,
        0,
        "the TLS master (container uid 0) must read the daemon's 0600 key"
    );
    assert_eq!(
        env.exec(
            "wg-it-master",
            &[
                "sh",
                "-c",
                "grep -Eq '^[[:space:]]*0[[:space:]]+0[[:space:]]+1$' /proc/self/uid_map",
            ],
        )
        .await,
        0,
        "uid 0 of the container must be uid 0 of the rootless namespace (the host user)"
    );
    let worker_map = format!(
        "grep -Eq '^[[:space:]]*1[[:space:]]+{}[[:space:]]+{}$' /proc/self/uid_map",
        range.start,
        range.size - 1
    );
    assert_eq!(
        env.exec("wg-it-master", &["sh", "-c", &worker_map]).await,
        0,
        "uid 1.. of the container must map into the ingress range (worker = uid 101)"
    );

    // Control: an app-style container on the plain map cannot read the key — that is exactly what
    // the ingress map exists to avoid for the TLS master, and what the worker keeps.
    env.container("wg-it-app", dir.path(), id_mapping(range))
        .await;
    assert_ne!(
        env.exec("wg-it-app", &["sh", "-c", "test -r /tls/h.example.eu.key"])
            .await,
        0,
        "a container whose root is a subuid must not read the host user's 0600 key"
    );

    // Nothing here leaks into the daemon's state: the file is still owned by the test user.
    let uid = fs::metadata(&key).unwrap().uid();
    let me = Command::new("id").arg("-u").output().unwrap();
    assert_eq!(
        uid.to_string(),
        String::from_utf8_lossy(&me.stdout).trim(),
        "the key stays owned by the daemon's user"
    );
}
