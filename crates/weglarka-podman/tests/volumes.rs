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
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use weglarka_core::app::SharedVolumeName;
use weglarka_core::labels;
use weglarka_core::podman::{
    ContainerSpec, PodmanClient, PodmanError, PullEvent, RestartPolicy, TarStream,
    VolumeAttachment, VolumeFilter, VolumeSpec,
};
use weglarka_core::uid_range::{UidRange, allocate};
use weglarka_core::volumes::id_mapping;
use weglarka_podman::LibpodClient;

const ALPINE: &str = "docker.io/library/alpine:3.20";
/// Image of the shared-volume test: unlike alpine it keeps running without a command
/// (`ContainerSpec` has no command field), so the test can `exec` into it.
const NGINX: &str = "docker.io/library/nginx:1-alpine";
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

/// The current user's first `/etc/subuid` entry — the rootless pool Podman maps subuid offsets
/// onto (`host_id` 1 is `start`; ADR 0009, finding 6).
fn subuid_pool() -> (u64, u64) {
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    fs::read_to_string("/etc/subuid")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut p = l.split(':');
            if p.next()? != user {
                return None;
            }
            let start = p.next()?.parse().ok()?;
            let size = p.next()?.parse().ok()?;
            Some((start, size))
        })
        .next()
        .expect("the CI user has a /etc/subuid entry")
}

/// Size of the current user's subuid pool from /etc/subuid.
fn subuid_pool_size() -> u64 {
    subuid_pool().1
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

    /// A fresh instance range from the pure allocator (the CI pool is 65 536).
    fn range(&mut self) -> UidRange {
        let r = allocate(&self.used, self.pool, RANGE).expect("subuid pool exhausted");
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

    /// Shared volume exactly as the engine creates it (ADR 0015): `wg-shared-<name>` labelled
    /// `weglarka.shared-volume=<name>` and deliberately **without** the `weglarka.instance` label.
    async fn shared_volume(&mut self, name: &SharedVolumeName) -> String {
        let volume = labels::shared_volume_name(name);
        self.volumes.push(volume.clone());
        self.client
            .volume_create(&VolumeSpec {
                name: volume.clone(),
                labels: BTreeMap::from([(labels::SHARED_VOLUME.to_owned(), name.to_string())]),
            })
            .await
            .unwrap();
        volume
    }

    /// Pulls an image and checks the stream completed; member images have to keep running by
    /// themselves (`ContainerSpec` has no command), so the test needs its own image.
    async fn pull(&self, image: &str) {
        let events: Vec<_> = self.client.image_pull(image).collect().await;
        assert!(
            matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
            "pull {image}: {events:?}"
        );
    }

    /// Creates and starts a container through the typed client, so the test sends the exact wire
    /// shape the engine sends for a member (`userns: private` + explicit `IdMapping`).
    async fn spawn(&mut self, spec: &ContainerSpec) {
        self.containers.push(spec.name.clone());
        self.client
            .container_create(spec)
            .await
            .unwrap_or_else(|e| panic!("create {}: {e}", spec.name));
        self.client
            .container_start(&spec.name)
            .await
            .unwrap_or_else(|e| panic!("start {}: {e}", spec.name));
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

    fn create(&mut self, body: &Value) {
        let name = body["name"].as_str().unwrap().to_owned();
        self.containers.push(name.clone());
        raw(&self.socket, "POST", "/containers/create", Some(body))
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
    }

    fn begin(&self, name: &str) {
        raw(
            &self.socket,
            "POST",
            &format!("/containers/{name}/start"),
            None,
        )
        .unwrap_or_else(|e| panic!("start {name}: {e}"));
    }

    fn start(&mut self, body: &Value) {
        self.create(body);
        self.begin(body["name"].as_str().unwrap());
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
        // A foreign tar (owned by the image user, e.g. from Coolify) goes in through
        // `container_archive_put` on a *created, not yet started* container — the app has not opened
        // its files yet — which maps the ids through the container's namespace.
        let c3 = format!("weglarka-it-c3-{label}-{id}");
        env.create(&Env::body(&c3, user, &vol2, range));
        let owner = user.map_or("0", |u| u.split(':').next().unwrap());
        let foreign = make_tar("imported.txt", "from-tar\n", owner);
        env.client
            .container_archive_put(&c3, "/data", chunked(foreign))
            .await
            .unwrap();
        env.begin(&c3);
        let cmd = r#"test "$(stat -c %u /data/f)" = "$(id -u)" && grep -q v2 /data/f"#;
        assert_eq!(
            env.sh(&c3, cmd).await,
            0,
            "[{label}] own export imports losslessly"
        );
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

/// Removes what the engine test creates, also on panic.
struct EngineCleanup {
    socket: String,
    instance: String,
}

impl Drop for EngineCleanup {
    fn drop(&mut self) {
        let (s, i) = (&self.socket, &self.instance);
        for path in [
            format!("/containers/{i}?force=true&timeout=0"),
            format!("/containers/wg-import.{i}?force=true&timeout=0"),
            format!("/volumes/{i}.data?force=true"),
            format!("/networks/net-{i}?force=true"),
            format!("/secrets/{i}.tok"),
        ] {
            let _ = raw(s, "DELETE", &path, None);
        }
    }
}

/// The whole iteration-2 flow through the engine on a real Podman: range assignment, volumes
/// surviving a recreate, Podman secrets of type `mount` readable by root and by a non-root user in the
/// new mapping, both import modes, migration of a container created on the default map, purge.
#[tokio::test]
async fn engine_ranges_volumes_secrets_import_migration_and_purge() {
    use std::sync::Arc;
    use std::time::Duration;

    use weglarka_core::app::InstanceName;
    use weglarka_core::labels;
    use weglarka_core::podman::{ContainerSpec, ContainerState, RestartPolicy};
    use weglarka_core::reconcile::{Reconciler, ReconcilerOptions};
    use weglarka_core::secret_store::{SecretStore, SecretValue};
    use weglarka_core::secrets::FileSecretStore;
    use weglarka_core::state::{StatePaths, load_state, save_state};
    use weglarka_core::volumes::ImportMode;

    let Some(socket) = socket() else { return };
    let instance = format!("wgit-{}", run_id());
    let _cleanup = EngineCleanup {
        socket: socket.clone(),
        instance: instance.clone(),
    };
    let name = InstanceName::new(&instance).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths::in_dir(dir.path());
    fs::write(
        &paths.apps,
        format!(
            r#"
[apps.{instance}]
image = "docker.io/library/nginx:1-alpine"
health = {{ attempts = 1, window_secs = 2 }}
volumes = [{{ name = "data", target = "/data" }}]
secrets = [{{ secret = "tok", kind = "mount", path = "/run/secrets/tok", mode = 0o444 }}]
"#
        ),
    )
    .unwrap();
    let store = Arc::new(FileSecretStore::new(dir.path().join("secrets.toml")));
    store.init().unwrap();
    store
        .set(&format!("{instance}.tok"), SecretValue::new("s3cret"))
        .unwrap();
    let client = LibpodClient::new(&socket);
    let rec = Reconciler::new(
        client.clone(),
        store,
        paths.clone(),
        ReconcilerOptions::default(),
    );
    let sh = |script: &'static str| {
        let (client, instance) = (client.clone(), instance.clone());
        async move {
            client
                .container_exec(
                    &instance,
                    &["sh".to_owned(), "-c".to_owned(), script.to_owned()],
                )
                .await
                .unwrap()
        }
    };
    const WAIT: Duration = Duration::from_secs(5);

    // First deploy: range 1+65536 (the whole CI pool), explicit map, volume created and labelled.
    let report = rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    let range = load_state(&paths.state).unwrap().apps[&name]
        .uid_range
        .unwrap();
    assert_eq!((range.start, range.size), (1, 65_536));
    assert_eq!(
        sh(r"grep -Eq '^ *0 +1 +65536 *$' /proc/self/uid_map").await,
        0
    );
    let vols = client
        .volume_list(&VolumeFilter {
            labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.clone())]),
        })
        .await
        .unwrap();
    assert_eq!(vols.len(), 1);

    // Secrets of type `mount` are readable in the new mapping, by root and by a non-root user.
    assert_eq!(sh("grep -q s3cret /run/secrets/tok").await, 0, "root");
    assert_eq!(
        sh("su -s /bin/sh daemon -c 'grep -q s3cret /run/secrets/tok'").await,
        0,
        "non-root"
    );

    // Data survives a forced redeploy (new container, same range).
    assert_eq!(sh("echo v1 > /data/f && chmod 600 /data/f").await, 0);
    rec.deploy(&name, true).await.unwrap();
    assert_eq!(sh("grep -q v1 /data/f && echo v2 > /data/f").await, 0);

    // Foreign tar (uid 1000, as made by Coolify) is chowned to the container user (root for nginx); the app is restarted.
    let foreign = make_tar("imported.txt", "from-coolify\n", "1000");
    rec.import_volume(&name, "data", ImportMode::Foreign, chunked(foreign), WAIT)
        .await
        .unwrap();
    assert_eq!(
        client.container_inspect(&instance).await.unwrap().state,
        ContainerState::Running
    );
    assert_eq!(
        sh("test -f /data/imported.txt").await,
        0,
        "imported file exists"
    );
    assert_eq!(
        sh("grep -q coolify /data/imported.txt").await,
        0,
        "imported file content"
    );
    assert_eq!(
        sh("test \"$(stat -c %u /data/imported.txt)\" = 0").await,
        0,
        "foreign files are owned by the container user (root), not by the tar's uid 1000"
    );
    assert!(
        client
            .container_inspect(&format!("wg-import.{instance}"))
            .await
            .is_err(),
        "helper gone"
    );

    // Own export → import round trip is lossless.
    let mut tar = client
        .volume_export(&format!("{instance}.data"))
        .await
        .unwrap();
    let mut bytes = Vec::new();
    while let Some(chunk) = tar.next().await {
        bytes.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(sh("echo gone > /data/f").await, 0);
    rec.import_volume(&name, "data", ImportMode::Own, chunked(bytes), WAIT)
        .await
        .unwrap();
    assert_eq!(
        sh(r#"grep -q v2 /data/f && test "$(stat -c %u /data/f)" = 0"#).await,
        0
    );

    // Migration: a container left on the default map (what the MVP created) and no range in state
    // is recreated once, now with the explicit map.
    let info = client.container_inspect(&instance).await.unwrap();
    let mut legacy_labels = info.labels.clone();
    legacy_labels.remove(labels::UID_RANGE);
    client.container_stop(&instance, 1).await.unwrap();
    client.container_remove(&instance, true).await.unwrap();
    client
        .container_create(&ContainerSpec {
            name: instance.clone(),
            image: info.image.clone(),
            labels: legacy_labels,
            env: BTreeMap::new(),
            networks: info.networks.clone(),
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::Always,
            userns_auto: true,
            mounts: vec![],
            volumes: vec![],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: None,
            security: Default::default(),
        })
        .await
        .unwrap();
    client.container_start(&instance).await.unwrap();
    assert_eq!(
        sh(r"grep -Eq '^ *0 +1 +65536 *$' /proc/self/uid_map").await,
        1,
        "legacy map"
    );
    let mut st = load_state(&paths.state).unwrap();
    st.apps.get_mut(&name).unwrap().uid_range = None;
    save_state(&paths.state, &st).unwrap();
    let report = rec.reconcile().await.unwrap();
    assert!(report.is_clean(), "{report:?}");
    assert_eq!(
        sh(r"grep -Eq '^ *0 +1 +65536 *$' /proc/self/uid_map").await,
        0,
        "migrated"
    );
    assert_eq!(
        sh("grep -q v2 /data/f").await,
        0,
        "data readable after the migration recreate"
    );

    // Purge: container, volume and range are gone.
    rec.remove_app_with_volumes(&name, true).await.unwrap();
    assert!(client.container_inspect(&instance).await.is_err());
    assert!(
        client
            .volume_inspect(&format!("{instance}.data"))
            .await
            .is_err()
    );
    assert!(!load_state(&paths.state).unwrap().apps.contains_key(&name));
}

/// Host owner of a file in a volume mountpoint, as the rootless Podman user sees it.
fn host_uid(path: &str) -> u32 {
    fs::metadata(path).unwrap().uid()
}

/// A member container as the engine creates one (ADR 0015): the shared volume's explicit uid range
/// (`userns: private` + one `IdMapping`, `userns_auto = false`), the `weglarka.uid-range` label and
/// the shared Podman volume mounted read-write. `ContainerSpec` has no command, so the member image
/// has to keep running by itself (nginx does) and commands run through `container_exec`.
fn member_spec(name: &str, shared_volume: &str, range: UidRange) -> ContainerSpec {
    ContainerSpec {
        name: name.to_owned(),
        image: NGINX.to_owned(),
        labels: BTreeMap::from([(labels::UID_RANGE.to_owned(), labels::uid_range_label(range))]),
        env: BTreeMap::new(),
        networks: vec![],
        secrets: vec![],
        publish: vec![],
        restart: RestartPolicy::No,
        userns_auto: false,
        mounts: vec![],
        volumes: vec![VolumeAttachment {
            volume: shared_volume.to_owned(),
            target: "/data".to_owned(),
            read_only: false,
        }],
        resources: Default::default(),
        healthcheck: None,
        id_mapping: Some(id_mapping(range)),
        security: Default::default(),
    }
}

/// Issue #33 data plane (ADR 0015): two containers of one shared volume run in the **same** explicit
/// uid range and read/overwrite the same file with one stable owner across recreation, while a
/// container with a disjoint range cannot touch the volume.
#[tokio::test]
async fn shared_volume_two_members_one_range_read_write_recreate_and_isolate() {
    let Some(socket) = socket() else { return };
    let mut env = Env::new(socket).await;
    env.pull(NGINX).await;
    let id = run_id();
    let (range, other) = (env.range(), env.range());
    assert!(!range.overlaps(other), "the test needs two disjoint ranges");
    let in_range = |range: UidRange| {
        format!(
            r"grep -Eq '^ *0 +{} +{} *$' /proc/self/uid_map",
            range.start, range.size
        )
    };

    // The engine creates the labelled shared volume before the first member's container; every
    // member's launch calls ensure again, so the create is idempotent and label-preserving.
    let shared = SharedVolumeName::new(format!("it-share-{id}")).unwrap();
    let volume = env.shared_volume(&shared).await;
    let _ = env.shared_volume(&shared).await;
    let info = env.client.volume_inspect(&volume).await.unwrap();
    let shared_label = shared.to_string();
    assert_eq!(info.labels.get(labels::SHARED_VOLUME), Some(&shared_label));
    assert!(
        !info.labels.contains_key(labels::INSTANCE),
        "a shared volume must not look like an instance volume: {:?}",
        info.labels
    );
    let mountpoint = info.mountpoint.clone().expect("volume mountpoint");

    // A writes a private file as the container user of the shared range.
    let a = format!("wgit-share-a-{id}");
    env.spawn(&member_spec(&a, &volume, range)).await;
    assert_eq!(
        env.sh(&a, &in_range(range)).await,
        0,
        "A runs in the shared range"
    );
    assert_eq!(
        env.sh(
            &a,
            "echo v1 > /data/f && chmod 600 /data/f && id -u > /data/uid"
        )
        .await,
        0
    );
    // Host-side ownership: `range.start` is an offset into the subuid pool (offset 1 = the pool's
    // first subuid), so the on-disk owner is `subuid_start + range.start + container_uid - 1`
    // (ADR 0009, finding 6).
    let container_uid: u32 = fs::read_to_string(format!("{mountpoint}/uid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let owner =
        u32::try_from(subuid_pool().0 + u64::from(range.start) + u64::from(container_uid) - 1)
            .unwrap();
    assert_eq!(
        host_uid(&format!("{mountpoint}/f")),
        owner,
        "A's file is owned through the shared range"
    );

    // B — the same range, the same volume, A still running — reads A's file and overwrites it.
    let b = format!("wgit-share-b-{id}");
    env.spawn(&member_spec(&b, &volume, range)).await;
    assert_eq!(
        env.sh(&b, &in_range(range)).await,
        0,
        "B runs in the same shared range"
    );
    let read_write = r#"test "$(id -u)" = "$(cat /data/uid)" && test "$(stat -c %u /data/f)" = "$(id -u)" && grep -q v1 /data/f && echo v2 > /data/f"#;
    assert_eq!(
        env.sh(&b, read_write).await,
        0,
        "B reads and overwrites A's file"
    );
    assert_eq!(
        host_uid(&format!("{mountpoint}/f")),
        owner,
        "B keeps the owner A created"
    );

    // Recreation (the deploy path) keeps ownership: the new A reads what B wrote.
    env.remove(&a);
    env.spawn(&member_spec(&a, &volume, range)).await;
    let recreated =
        r#"test "$(stat -c %u /data/f)" = "$(id -u)" && grep -q v2 /data/f && echo v3 > /data/f"#;
    assert_eq!(
        env.sh(&a, recreated).await,
        0,
        "recreated A reads B's content with the same owner"
    );
    assert_eq!(
        host_uid(&format!("{mountpoint}/f")),
        owner,
        "the owner survives the recreate"
    );

    // Isolation: a container with a disjoint range cannot read or write the shared volume's files.
    let intruder = format!("wgit-share-intruder-{id}");
    env.spawn(&member_spec(&intruder, &volume, other)).await;
    assert_eq!(
        env.sh(&intruder, &in_range(other)).await,
        0,
        "the intruder has the disjoint range"
    );
    assert_ne!(
        env.sh(&intruder, "cat /data/f").await,
        0,
        "disjoint range cannot read"
    );
    assert_ne!(
        env.sh(&intruder, "echo x > /data/evil").await,
        0,
        "disjoint range cannot write"
    );
    assert!(
        !std::path::Path::new(&format!("{mountpoint}/evil")).exists(),
        "nothing appeared on the volume"
    );
}
