//! Volumes and file ownership against a real rootless Podman 6 (CI job `integration-podman`).
//! Decision and measurements: docs/decisions/0009-volume-ownership.md. Requires
//! `WEGLARKA_PODMAN_SOCKET`; skipped without it (docs/decisions/0002-podman-in-ci.md).
//!
//! Volume operations go through the typed client. Containers are created with raw JSON because
//! `ContainerSpec` has no command/user (an alpine container needs `sleep`, the image-user case needs
//! `"user"`); the explicit-map body is the exact shape `weglarka-podman`'s wire layer sends.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use weglarka_core::podman::{
    PodmanClient, PodmanError, PullEvent, TarStream, VolumeFilter, VolumeSpec,
};
use weglarka_core::uid_range::{UidRange, allocate};
use weglarka_podman::LibpodClient;

const ALPINE: &str = "docker.io/library/alpine:3.20";
/// Instance range used by the tests; small, but covers uid 1000.
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

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{}", std::process::id(), nanos % 1_000_000_000)
}

/// Raw libpod call for what `ContainerSpec` cannot express; `Err` carries the response body.
fn raw(socket: &str, method: &str, path: &str, body: Option<&Value>) -> Result<String, String> {
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
        cmd.args([
            "-H",
            "content-type: application/json",
            "-d",
            &body.to_string(),
        ]);
    }
    cmd.arg(format!("http://d/v6.0.0/libpod{path}"));
    let out = cmd
        .output()
        .expect("curl is required for integration tests");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(text)
    } else {
        Err(format!("{text}{}", String::from_utf8_lossy(&out.stderr)))
    }
}

/// Size of the current user's subuid pool from /etc/subuid.
fn subuid_pool_size() -> u64 {
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    fs::read_to_string("/etc/subuid")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut p = l.split(':');
            (p.next()? == user).then_some(p.nth(1)?.parse().ok()?)
        })
        .next()
        .expect("the CI user has a /etc/subuid entry")
}

/// Removes everything the test created, also on panic.
struct Env {
    socket: String,
    client: LibpodClient,
    containers: Vec<String>,
    volumes: Vec<String>,
    /// Ranges handed out so far (the allocator under test picks disjoint ones).
    used: Vec<UidRange>,
    pool: u64,
}

impl Drop for Env {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = raw(
                &self.socket,
                "DELETE",
                &format!("/containers/{c}?force=true&v=true&timeout=0"),
                None,
            );
        }
        for v in &self.volumes {
            let _ = raw(
                &self.socket,
                "DELETE",
                &format!("/volumes/{v}?force=true"),
                None,
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
            client,
            socket,
            containers: vec![],
            volumes: vec![],
            used: vec![],
            pool: subuid_pool_size(),
        }
    }

    /// A fresh instance range from the pure allocator (no reserved prefix: the CI pool is 65 536).
    fn range(&mut self) -> UidRange {
        let r = allocate(&self.used, self.pool, RANGE, 0).expect("subuid pool exhausted");
        self.used.push(r);
        r
    }

    async fn volume(&mut self, name: &str) {
        self.volumes.push(name.to_owned());
        self.client
            .volume_create(&VolumeSpec {
                name: name.to_owned(),
                labels: BTreeMap::from([("weglarka.instance".into(), "it".into())]),
            })
            .await
            .unwrap();
    }

    /// Container with an explicit instance range (`private` + maps, as the wire layer sends).
    fn body(name: &str, user: Option<&str>, volume: &str, range: UidRange) -> Value {
        let map = json!([{"container_id": 0, "host_id": range.start, "size": range.size}]);
        let mut body = json!({
            "name": name, "image": ALPINE, "command": ["sleep", "3600"],
            "userns": {"nsmode": "private"},
            "idmappings": {"UIDMap": map, "GIDMap": map, "HostUIDMapping": false, "HostGIDMapping": false},
            "volumes": [{"Name": volume, "Dest": "/data", "Options": []}],
        });
        if let Some(user) = user {
            body["user"] = json!(user);
        }
        body
    }

    fn start(&mut self, body: &Value) {
        let name = body["name"].as_str().unwrap().to_owned();
        self.containers.push(name.clone());
        raw(&self.socket, "POST", "/containers/create", Some(body))
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
        raw(
            &self.socket,
            "POST",
            &format!("/containers/{name}/start"),
            None,
        )
        .unwrap_or_else(|e| panic!("start {name}: {e}"));
    }

    fn remove(&self, name: &str) {
        raw(
            &self.socket,
            "DELETE",
            &format!("/containers/{name}?force=true&v=true&timeout=0"),
            None,
        )
        .unwrap();
    }

    /// Exit code of a shell snippet run in the container.
    async fn sh(&self, container: &str, script: &str) -> i32 {
        self.client
            .container_exec(
                container,
                &["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            )
            .await
            .unwrap()
    }

    async fn export(&self, volume: &str) -> Vec<u8> {
        let mut tar = self.client.volume_export(volume).await.unwrap();
        let mut out = Vec::new();
        while let Some(chunk) = tar.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }
}

/// Splits a buffer into small chunks, so streaming import is exercised for real.
fn chunked(data: Vec<u8>) -> TarStream {
    let chunks: Vec<_> = data
        .chunks(700)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    stream::iter(chunks).boxed()
}

/// `tar` archive with one file `name` owned by `owner:owner` (numeric).
fn make_tar(name: &str, content: &str, owner: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("weglarka-it-tar-{}", run_id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name), content).unwrap();
    let out = Command::new("tar")
        .args(["-c", "-C", dir.to_str().unwrap()])
        .args(["--owner", owner, "--group", owner, "--numeric-owner", name])
        .output()
        .unwrap();
    assert!(out.status.success(), "tar -c");
    let _ = fs::remove_dir_all(&dir);
    out.stdout
}

fn tar_names(tar: &[u8]) -> Vec<String> {
    let mut child = Command::new("tar")
        .args(["-t"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(tar).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim_start_matches("./").to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The chosen design (ADR 0009): a fixed range per instance keeps file ownership stable across
/// container recreation (also when other containers come and go), and ranges isolate instances.
/// Covers both an image running as a non-root user and as root.
#[tokio::test]
async fn fixed_range_keeps_ownership_across_recreate_and_isolates() {
    let Some(socket) = socket() else { return };
    let mut env = Env::new(socket).await;
    for (label, user) in [("user", Some("1000:1000")), ("root", None)] {
        let id = run_id();
        let (range, other) = (env.range(), env.range());
        assert!(!range.overlaps(other));
        let vol = format!("weglarka-it-vol-{label}-{id}");
        env.volume(&vol).await;

        // First container writes a private file as the image user.
        let c1 = format!("weglarka-it-c1-{label}-{id}");
        env.start(&Env::body(&c1, user, &vol, range));
        let write = "echo v1 > /data/f && chmod 600 /data/f && id -u > /data/uid";
        assert_eq!(env.sh(&c1, write).await, 0);

        // Recreate (as the deploy does) while another instance is running: ownership must hold.
        env.remove(&c1);
        let neighbour = format!("weglarka-it-neighbour-{label}-{id}");
        let nvol = format!("weglarka-it-nvol-{label}-{id}");
        env.volume(&nvol).await;
        env.start(&Env::body(&neighbour, user, &nvol, other));
        let c2 = format!("weglarka-it-c2-{label}-{id}");
        env.start(&Env::body(&c2, user, &vol, range));
        let cmd = r#"test "$(id -u)" = "$(cat /data/uid)" && test "$(stat -c %u /data/f)" = "$(id -u)" && grep -q v1 /data/f && echo v2 > /data/f"#;
        assert_eq!(
            env.sh(&c2, cmd).await,
            0,
            "[{label}] c2 reads and overwrites"
        );

        // Isolation: a container with the other (disjoint) range cannot touch this volume's files.
        let intruder = format!("weglarka-it-intruder-{label}-{id}");
        env.start(&Env::body(&intruder, user, &vol, other));
        assert_ne!(env.sh(&intruder, "cat /data/f").await, 0, "[{label}] read");
        let evil = "echo x > /data/evil";
        assert_ne!(env.sh(&intruder, evil).await, 0, "[{label}] write");
        env.remove(&intruder);

        // Export, then import into a second volume of the same instance range (streamed, chunked).
        let tar = env.export(&vol).await;
        let names = tar_names(&tar);
        assert!(names.iter().any(|n| n == "f"), "{names:?}");
        let vol2 = format!("weglarka-it-vol2-{label}-{id}");
        env.volume(&vol2).await;
        env.client.volume_import(&vol2, chunked(tar)).await.unwrap();
        let c3 = format!("weglarka-it-c3-{label}-{id}");
        env.start(&Env::body(&c3, user, &vol2, range));
        let cmd = r#"test "$(stat -c %u /data/f)" = "$(id -u)" && grep -q v2 /data/f"#;
        assert_eq!(
            env.sh(&c3, cmd).await,
            0,
            "[{label}] own export imports losslessly"
        );

        // A foreign tar (owned by the image user, e.g. from Coolify): `container_archive_put` maps it
        // through the container's namespace, so the app owns it.
        let owner = user.map_or("0", |u| u.split(':').next().unwrap());
        let foreign = make_tar("imported.txt", "from-tar\n", owner);
        env.client
            .container_archive_put(&c3, "/data", chunked(foreign))
            .await
            .unwrap();
        let cmd = r#"test "$(stat -c %u /data/imported.txt)" = "$(id -u)" && echo more >> /data/imported.txt"#;
        assert_eq!(
            env.sh(&c3, cmd).await,
            0,
            "[{label}] foreign tar via archive"
        );
    }
}

/// The volume client: idempotent create, labels, label-filtered list, inspect, remove.
#[tokio::test]
async fn volume_lifecycle() {
    let Some(socket) = socket() else { return };
    let mut env = Env::new(socket).await;
    let name = format!("weglarka-it-lifecycle-{}", run_id());
    env.volume(&name).await;
    env.volume(&name).await; // idempotent

    let info = env.client.volume_inspect(&name).await.unwrap();
    assert_eq!(info.name, name);
    assert_eq!(
        info.labels.get("weglarka.instance").map(String::as_str),
        Some("it")
    );
    assert!(info.mountpoint.is_some());

    let filter = |value: &str| VolumeFilter {
        labels: BTreeMap::from([("weglarka.instance".into(), value.into())]),
    };
    let listed = env.client.volume_list(&filter("it")).await.unwrap();
    assert!(listed.iter().any(|v| v.name == name));
    assert!(
        env.client
            .volume_list(&filter("no-such"))
            .await
            .unwrap()
            .is_empty()
    );

    env.client.volume_remove(&name, false).await.unwrap();
    assert!(matches!(
        env.client.volume_inspect(&name).await,
        Err(PodmanError::NotFound(_))
    ));
    assert!(matches!(
        env.client.volume_remove(&name, false).await,
        Err(PodmanError::NotFound(_))
    ));
}

/// Finding behind ADR 0009: `userns: {nsmode: auto}` — what the MVP sends — does not engage under
/// rootless Podman. The container keeps the default map shared by all containers; real `auto` needs
/// `idmappings.AutoUserNs`. If this test starts failing, Podman changed and the ADR needs a revisit.
#[tokio::test]
async fn plain_userns_auto_is_a_noop_rootless() {
    let Some(socket) = socket() else { return };
    let mut env = Env::new(socket).await;
    let id = run_id();
    let shapes = [
        ("unset", json!({})),
        ("auto", json!({"userns": {"nsmode": "auto"}})),
        (
            "real-auto",
            json!({
                "userns": {"nsmode": "auto"},
                "idmappings": {"AutoUserNs": true, "AutoUserNsOpts": {"Size": 1024}},
            }),
        ),
    ];
    let mut maps = Vec::new();
    for (label, extra) in shapes {
        let vol = format!("weglarka-it-map-{label}-{id}");
        env.volume(&vol).await;
        let mut body = json!({
            "name": format!("weglarka-it-map-{label}-{id}"),
            "image": ALPINE, "command": ["sleep", "3600"],
            "volumes": [{"Name": vol, "Dest": "/out", "Options": []}],
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        env.start(&body);
        let name = body["name"].as_str().unwrap();
        let script = "cat /proc/self/uid_map | tr -s ' \\n' ' ' > /out/m; chmod 644 /out/m";
        assert_eq!(env.sh(name, script).await, 0);
        let mountpoint = env
            .client
            .volume_inspect(&vol)
            .await
            .unwrap()
            .mountpoint
            .unwrap();
        maps.push(
            fs::read_to_string(format!("{mountpoint}/m"))
                .unwrap()
                .trim()
                .to_owned(),
        );
    }
    assert_eq!(
        maps[0], maps[1],
        "plain `auto` equals no userns setting: {maps:?}"
    );
    assert!(maps[0].starts_with("0 "), "{maps:?}");
    assert_ne!(maps[0], maps[2], "AutoUserNs changes the map: {maps:?}");
    assert!(maps[2].ends_with(" 1024"), "{maps:?}");
}
