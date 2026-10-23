//! SPIKE (iteration 2, step 0): file ownership of named volumes across container recreation under
//! rootless Podman 6.1 with `--userns=auto`. Drives libpod with raw JSON (curl) so the specgen shape
//! can be iterated on without touching the typed client. Every observation is printed as a
//! `SPIKE <label>: ...` line; the decision is recorded in docs/decisions/0009-volume-ownership.md.
//!
//! Requires `WEGLARKA_PODMAN_SOCKET`; skipped without it (docs/decisions/0002-podman-in-ci.md).

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use weglarka_core::podman::PodmanClient;
use weglarka_podman::LibpodClient;

const ALPINE: &str = "docker.io/library/alpine:3.20";

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

/// Raw libpod call; `Err` carries the response body (curl `--fail-with-body`).
fn raw(
    socket: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    extra: &[&str],
) -> Result<String, String> {
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
    cmd.args(extra);
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

struct Cleanup {
    socket: String,
    containers: Vec<String>,
    volumes: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = raw(
                &self.socket,
                "DELETE",
                &format!("/containers/{c}?force=true&v=true&timeout=0"),
                None,
                &[],
            );
        }
        for v in &self.volumes {
            let _ = raw(
                &self.socket,
                "DELETE",
                &format!("/volumes/{v}?force=true"),
                None,
                &[],
            );
        }
    }
}

/// `(first subuid, count)` of the current user from /etc/subuid.
fn subuid_pool() -> (u64, u64) {
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let text = fs::read_to_string("/etc/subuid").unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut p = l.split(':');
            (p.next()? == user).then_some((p.next()?.parse().ok()?, p.next()?.parse().ok()?))
        })
        .next()
        .unwrap_or((0, 0))
}

/// How a scenario shapes the container's user namespace and volume mount.
#[derive(Clone)]
struct Variant {
    label: &'static str,
    /// Libpod `userns` object, or `None` to leave it unset.
    userns: Option<Value>,
    /// libpod `idmappings` object (explicit uid/gid maps), if any.
    idmappings: Option<Value>,
    /// Options of the named-volume mount (`idmap`, `U`, ...).
    volume_options: Vec<&'static str>,
}

impl Variant {
    fn body(&self, name: &str, user: Option<&str>, volume: &str) -> Value {
        let mut b = json!({
            "name": name,
            "image": ALPINE,
            "command": ["sleep", "3600"],
            "volumes": [{"Name": volume, "Dest": "/data", "Options": self.volume_options}],
        });
        if let Some(user) = user {
            b["user"] = json!(user);
        }
        if let Some(u) = &self.userns {
            b["userns"] = u.clone();
        }
        if let Some(m) = &self.idmappings {
            b["idmappings"] = m.clone();
        }
        b
    }
}

fn auto_userns() -> Option<Value> {
    Some(json!({"nsmode": "auto"}))
}

/// Explicit maps for one instance: container 0..size → intermediate-namespace ids `offset..offset+size`
/// (rootless: 0 is the invoking user, 1.. are its subuids in order).
fn explicit_maps(offset: u64, size: u64) -> Value {
    let map = json!([{"container_id": 0, "host_id": offset, "size": size}]);
    json!({"UIDMap": map, "GIDMap": map, "HostUIDMapping": false, "HostGIDMapping": false})
}

struct Spike {
    socket: String,
    client: LibpodClient,
    cleanup: Cleanup,
}

impl Spike {
    fn new(socket: String) -> Self {
        Self {
            client: LibpodClient::new(&socket),
            cleanup: Cleanup {
                socket: socket.clone(),
                containers: vec![],
                volumes: vec![],
            },
            socket,
        }
    }

    fn pull(&self) {
        raw(
            &self.socket,
            "POST",
            &format!("/images/pull?reference={ALPINE}"),
            None,
            &[],
        )
        .expect("pull alpine");
    }

    /// Creates + starts a container from a raw body; `Err` = verbatim libpod error.
    fn start(&mut self, body: &Value) -> Result<(), String> {
        let name = body["name"].as_str().unwrap().to_owned();
        self.cleanup.containers.push(name.clone());
        raw(&self.socket, "POST", "/containers/create", Some(body), &[])?;
        raw(
            &self.socket,
            "POST",
            &format!("/containers/{name}/start"),
            None,
            &[],
        )
        .map(|_| ())
    }

    fn remove(&self, name: &str) {
        let _ = raw(
            &self.socket,
            "DELETE",
            &format!("/containers/{name}?force=true&v=true&timeout=0"),
            None,
            &[],
        );
    }

    /// Runs a shell snippet in the container; returns the exit code.
    async fn sh(&self, container: &str, script: &str) -> i32 {
        self.client
            .container_exec(
                container,
                &["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            )
            .await
            .unwrap_or(-1)
    }

    fn mountpoint(&self, volume: &str) -> Option<String> {
        let out = raw(
            &self.socket,
            "GET",
            &format!("/volumes/{volume}/json"),
            None,
            &[],
        )
        .ok()?;
        serde_json::from_str::<Value>(&out)
            .ok()?
            .get("Mountpoint")?
            .as_str()
            .map(str::to_owned)
    }

    /// Contents of a file in the volume, read from the host side.
    fn host_file(&self, volume: &str, file: &str) -> String {
        let Some(mp) = self.mountpoint(volume) else {
            return "no-mountpoint".into();
        };
        fs::read_to_string(format!("{mp}/{file}"))
            .map(|t| one_line(&t))
            .unwrap_or_else(|e| format!("read error: {e}"))
    }

    /// Host-side `uid:gid` of a file in the volume (as seen from outside the user namespace).
    fn host_owner(&self, volume: &str, file: &str) -> String {
        let Some(mp) = self.mountpoint(volume) else {
            return "no-mountpoint".into();
        };
        match Command::new("stat")
            .args(["-c", "%u:%g", &format!("{mp}/{file}")])
            .output()
        {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
            Ok(o) => format!("stat failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
            Err(e) => format!("stat error: {e}"),
        }
    }
}

fn say(label: &str, user: &str, step: &str, ok: bool) {
    eprintln!(
        "SPIKE {label} [{user}]: {step} -> {}",
        if ok { "ok" } else { "FAIL" }
    );
}

/// The full recreate scenario for one variant and one image user (`None` = root in the image).
async fn scenario(socket: &str, variant: &Variant, user: Option<&str>) {
    let who = user.unwrap_or("root").to_owned();
    let (label, who) = (variant.label, who.as_str());
    let id = run_id();
    let mut s = Spike::new(socket.to_owned());
    s.pull();
    let vol = format!("weglarka-spike-{label}-{id}");
    s.cleanup.volumes.push(vol.clone());
    let labels = json!({"Name": vol, "Label": {"weglarka.instance": format!("spike-{id}")}});
    raw(socket, "POST", "/volumes/create", Some(&labels), &[]).expect("volume create");

    // 1. first container writes a file.
    let c1 = format!("spike-{label}-1-{id}");
    if let Err(e) = s.start(&variant.body(&c1, user, &vol)) {
        eprintln!(
            "SPIKE {label} [{who}]: create/start c1 -> FAIL (libpod: {})",
            one_line(&e)
        );
        return;
    }
    let wrote = s
        .sh(
            &c1,
            "echo v1 > /data/f && chmod 644 /data/f && id -u > /data/uid",
        )
        .await
        == 0;
    say(label, who, "c1 writes /data/f", wrote);
    eprintln!(
        "SPIKE {label} [{who}]: host owner of /data/f after c1 = {}",
        s.host_owner(&vol, "f")
    );

    // 2. recreate: remove c1, let a dummy `auto` container take the freed range, create c2.
    s.remove(&c1);
    let dummy = format!("spike-dummy-{label}-{id}");
    let _ = s.start(&json!({
        "name": dummy, "image": ALPINE, "command": ["sleep", "3600"],
        "userns": {"nsmode": "auto"},
    }));
    let c2 = format!("spike-{label}-2-{id}");
    if let Err(e) = s.start(&variant.body(&c2, user, &vol)) {
        eprintln!(
            "SPIKE {label} [{who}]: create/start c2 -> FAIL (libpod: {})",
            one_line(&e)
        );
        return;
    }
    // Same uid inside as before?
    let same_uid = s.sh(&c2, "test \"$(id -u)\" = \"$(cat /data/uid)\"").await == 0;
    say(label, who, "c2 sees same uid as c1", same_uid);
    let owner = s
        .sh(&c2, "test \"$(stat -c %u /data/f)\" = \"$(id -u)\"")
        .await
        == 0;
    say(label, who, "c2: /data/f owned by c2's uid", owner);
    let read = s.sh(&c2, "grep -q v1 /data/f").await == 0;
    say(label, who, "c2 reads v1", read);
    let write = s.sh(&c2, "echo v2 > /data/f && grep -q v2 /data/f").await == 0;
    say(label, who, "c2 overwrites /data/f", write);
    eprintln!(
        "SPIKE {label} [{who}]: host owner of /data/f after c2 = {}",
        s.host_owner(&vol, "f")
    );

    // 3. import a tar owned by the image user, then read/write it from the container.
    let tar_uid = user.map_or("0", |u| u.split(':').next().unwrap());
    let dir = std::env::temp_dir().join(format!("weglarka-spike-{id}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("imported.txt"), "from-tar\n").unwrap();
    let tar = dir.join("in.tar");
    let made = Command::new("tar")
        .args([
            "-cf",
            tar.to_str().unwrap(),
            "-C",
            dir.to_str().unwrap(),
            "--owner",
            tar_uid,
            "--group",
            tar_uid,
            "--numeric-owner",
            "imported.txt",
        ])
        .status()
        .unwrap()
        .success();
    assert!(made, "tar -c");
    let imp = raw(
        socket,
        "POST",
        &format!("/volumes/{vol}/import"),
        None,
        &[
            "-H",
            "content-type: application/x-tar",
            "--data-binary",
            &format!("@{}", tar.display()),
        ],
    );
    match imp {
        Err(e) => eprintln!(
            "SPIKE {label} [{who}]: import -> FAIL (libpod: {})",
            one_line(&e)
        ),
        Ok(_) => {
            say(label, who, "import tar (owned by image user)", true);
            eprintln!(
                "SPIKE {label} [{who}]: host owner of imported.txt = {}",
                s.host_owner(&vol, "imported.txt")
            );
            let o = s
                .sh(
                    &c2,
                    "test \"$(stat -c %u /data/imported.txt)\" = \"$(id -u)\"",
                )
                .await
                == 0;
            say(label, who, "imported.txt owned by container uid", o);
            let w = s.sh(&c2, "echo more >> /data/imported.txt").await == 0;
            say(label, who, "container can write imported.txt", w);
        }
    }

    // 4. export streams back a tar containing our files.
    let out = dir.join("out.tar");
    let exp = raw(
        socket,
        "GET",
        &format!("/volumes/{vol}/export"),
        None,
        &["-o", out.to_str().unwrap()],
    );
    match exp {
        Err(e) => eprintln!(
            "SPIKE {label} [{who}]: export -> FAIL (libpod: {})",
            one_line(&e)
        ),
        Ok(_) => {
            let listing = Command::new("tar")
                .args(["-tvf", out.to_str().unwrap(), "--numeric-owner"])
                .output()
                .unwrap();
            for line in String::from_utf8_lossy(&listing.stdout).lines() {
                eprintln!("SPIKE {label} [{who}]: export entry: {line}");
            }
        }
    }
    let _ = fs::remove_dir_all(&dir);
}

fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

const USERS: [Option<&str>; 2] = [Some("1000:1000"), None];

/// Baseline: what happens today (`auto`, plain volume).
#[tokio::test]
async fn spike_baseline_auto() {
    let Some(socket) = socket() else { return };
    let v = Variant {
        label: "base",
        userns: auto_userns(),
        idmappings: None,
        volume_options: vec![],
    };
    for u in USERS {
        scenario(&socket, &v, u).await;
    }
}

/// Third option: `auto` + `:U` (chown the volume to the container user on every start).
#[tokio::test]
async fn spike_auto_chown_u() {
    let Some(socket) = socket() else { return };
    let v = Variant {
        label: "chownU",
        userns: auto_userns(),
        idmappings: None,
        volume_options: vec!["U"],
    };
    for u in USERS {
        scenario(&socket, &v, u).await;
    }
}

/// Path (b): `auto` + volume mounted with `idmap`.
#[tokio::test]
async fn spike_b_auto_idmap() {
    let Some(socket) = socket() else { return };
    let v = Variant {
        label: "b-idmap",
        userns: auto_userns(),
        idmappings: None,
        volume_options: vec!["idmap"],
    };
    for u in USERS {
        scenario(&socket, &v, u).await;
    }
}

/// Path (a): fixed explicit uid/gid maps for the instance (allocated from the subuid pool).
#[tokio::test]
async fn spike_a_fixed_range() {
    let Some(socket) = socket() else { return };
    let (base, count) = subuid_pool();
    eprintln!("SPIKE a: subuid pool of the user = {base}:{count}");
    // Offsets are in the intermediate namespace: 1.. = subuids in order.
    let v = Variant {
        label: "a-private",
        userns: Some(json!({"nsmode": "private"})),
        idmappings: Some(explicit_maps(1, 4096)),
        volume_options: vec![],
    };
    for u in USERS {
        scenario(&socket, &v, u).await;
    }
    // Same maps without an explicit nsmode, in case "private" + idmappings is rejected.
    let v = Variant {
        label: "a-nomode",
        userns: None,
        idmappings: Some(explicit_maps(1, 4096)),
        volume_options: vec![],
    };
    for u in USERS {
        scenario(&socket, &v, u).await;
    }
}

/// Path (a), isolation: two instances with disjoint ranges cannot touch each other's files.
#[tokio::test]
async fn spike_a_isolation() {
    let Some(socket) = socket() else { return };
    let mut s = Spike::new(socket.clone());
    s.pull();
    let id = run_id();
    let (vol_a, vol_b) = (
        format!("weglarka-spike-iso-a-{id}"),
        format!("weglarka-spike-iso-b-{id}"),
    );
    s.cleanup.volumes.extend([vol_a.clone(), vol_b.clone()]);
    for v in [&vol_a, &vol_b] {
        raw(
            &socket,
            "POST",
            "/volumes/create",
            Some(&json!({"Name": v})),
            &[],
        )
        .unwrap();
    }
    let mk = |name: &str, vol: &str, offset: u64, extra: &str| {
        json!({
            "name": name, "image": ALPINE, "command": ["sleep", "3600"],
            "user": "1000:1000",
            "userns": {"nsmode": "private"},
            "idmappings": explicit_maps(offset, 4096),
            "volumes": [{"Name": vol, "Dest": "/data", "Options": []}],
            "labels": {"spike": extra},
        })
    };
    let (ca, cb) = (format!("spike-iso-a-{id}"), format!("spike-iso-b-{id}"));
    let ra = s.start(&mk(&ca, &vol_a, 1, "a"));
    let rb = s.start(&mk(&cb, &vol_b, 4097, "b"));
    eprintln!("SPIKE iso: start a = {ra:?}, start b = {rb:?}");
    if ra.is_err() || rb.is_err() {
        return;
    }
    assert_eq!(
        s.sh(&ca, "echo secret > /data/s && chmod 600 /data/s")
            .await,
        0
    );
    // b mounts a's volume (a mistake or an attack): with disjoint ranges it must be unable to read it.
    s.remove(&cb);
    let cb2 = format!("spike-iso-b2-{id}");
    let rb2 = s.start(&json!({
        "name": cb2, "image": ALPINE, "command": ["sleep", "3600"], "user": "1000:1000",
        "userns": {"nsmode": "private"},
        "idmappings": explicit_maps(4097, 4096),
        "volumes": [{"Name": vol_a, "Dest": "/data", "Options": []}],
    }));
    eprintln!("SPIKE iso: b-range container on a's volume start = {rb2:?}");
    if rb2.is_ok() {
        let read = s.sh(&cb2, "cat /data/s").await;
        say(
            "iso",
            "1000",
            "other range cannot read a's 0600 file",
            read != 0,
        );
        let write = s.sh(&cb2, "echo x > /data/evil").await;
        say(
            "iso",
            "1000",
            "other range cannot create files in a's volume",
            write != 0,
        );
    }
}

/// Path (a) + `U`: explicit private maps, volume chowned to the container user on every start —
/// would make `import` independent of the offset without rewriting tar headers.
#[tokio::test]
async fn spike_a_fixed_range_chown_u() {
    let Some(socket) = socket() else { return };
    let v = Variant {
        label: "a-private-U",
        userns: Some(json!({"nsmode": "private"})),
        idmappings: Some(explicit_maps(1, 4096)),
        volume_options: vec!["U"],
    };
    for u in USERS {
        scenario(&socket, &v, u).await;
    }
}

/// What does `userns: auto` do under rootless Podman? Two concurrent containers per mode; their
/// `/proc/self/uid_map` is written to a volume and read back from the host.
#[tokio::test]
async fn spike_diag_userns_modes() {
    let Some(socket) = socket() else { return };
    let mut s = Spike::new(socket.clone());
    s.pull();
    let id = run_id();
    let modes: [(&str, Option<Value>); 4] = [
        ("auto", Some(json!({"nsmode": "auto"}))),
        (
            "auto-size",
            Some(json!({"nsmode": "auto", "value": "size=1024"})),
        ),
        ("private", Some(json!({"nsmode": "private"}))),
        ("unset", None),
    ];
    for (label, userns) in modes {
        let mut vols = Vec::new();
        for n in ["x", "y"] {
            let vol = format!("weglarka-spike-diag-{label}-{n}-{id}");
            s.cleanup.volumes.push(vol.clone());
            raw(
                &socket,
                "POST",
                "/volumes/create",
                Some(&json!({"Name": vol})),
                &[],
            )
            .unwrap();
            let name = format!("spike-diag-{label}-{n}-{id}");
            let mut body = json!({
                "name": name, "image": ALPINE, "command": ["sleep", "3600"],
                "volumes": [{"Name": vol, "Dest": "/out", "Options": []}],
            });
            if let Some(u) = &userns {
                body["userns"] = u.clone();
            }
            match s.start(&body) {
                Err(e) => eprintln!("SPIKE diag {label}/{n}: start -> FAIL ({})", one_line(&e)),
                Ok(()) => {
                    let code = s
                        .sh(&name, "cat /proc/self/uid_map > /out/uid_map; id -u > /out/uid; chmod 644 /out/*")
                        .await;
                    let inspect = raw(
                        &socket,
                        "GET",
                        &format!("/containers/{name}/json"),
                        None,
                        &[],
                    )
                    .ok()
                    .and_then(|t| serde_json::from_str::<Value>(&t).ok());
                    let mode = inspect
                        .as_ref()
                        .map(|j| j["HostConfig"]["UsernsMode"].to_string())
                        .unwrap_or_default();
                    eprintln!(
                        "SPIKE diag {label}/{n}: exec={code} HostConfig.UsernsMode={mode} uid_map=[{}]",
                        s.host_file(&vol, "uid_map")
                    );
                    vols.push(vol);
                }
            }
        }
    }
    // Is `idmap` on a volume honored? (mount options of /data as the container sees them)
    let vol = format!("weglarka-spike-diag-idmap-{id}");
    s.cleanup.volumes.push(vol.clone());
    raw(
        &socket,
        "POST",
        "/volumes/create",
        Some(&json!({"Name": vol})),
        &[],
    )
    .unwrap();
    let name = format!("spike-diag-idmap-{id}");
    let body = json!({
        "name": name, "image": ALPINE, "command": ["sleep", "3600"],
        "userns": {"nsmode": "auto"},
        "volumes": [{"Name": vol, "Dest": "/data", "Options": ["idmap"]}],
    });
    match s.start(&body) {
        Err(e) => eprintln!("SPIKE diag idmap: start -> FAIL ({})", one_line(&e)),
        Ok(()) => {
            s.sh(
                &name,
                "grep ' /data ' /proc/self/mountinfo > /data/mi; chmod 644 /data/mi",
            )
            .await;
            eprintln!("SPIKE diag idmap: mountinfo=[{}]", s.host_file(&vol, "mi"));
        }
    }
}

/// Import/export fixes for path (a): (1) `PUT/GET /containers/{name}/archive` (podman cp — maps ids
/// through the container's user namespace), (2) volume import followed by a container restart with
/// the `U` volume option.
#[tokio::test]
async fn spike_a_archive_and_u() {
    let Some(socket) = socket() else { return };
    for user in USERS {
        let who = user.unwrap_or("root");
        let tar_uid = user.map_or("0", |u| u.split(':').next().unwrap());
        let id = run_id();
        let mut s = Spike::new(socket.clone());
        s.pull();
        let dir = std::env::temp_dir().join(format!("weglarka-spike-ar-{id}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("imported.txt"), "from-tar\n").unwrap();
        let tar = dir.join("in.tar");
        assert!(
            Command::new("tar")
                .args(["-cf", tar.to_str().unwrap(), "-C", dir.to_str().unwrap()])
                .args([
                    "--owner",
                    tar_uid,
                    "--group",
                    tar_uid,
                    "--numeric-owner",
                    "imported.txt"
                ])
                .status()
                .unwrap()
                .success()
        );
        for (label, opts) in [("a-archive", vec![]), ("a-U-restart", vec!["U"])] {
            let v = Variant {
                label: "a-private",
                userns: Some(json!({"nsmode": "private"})),
                idmappings: Some(explicit_maps(1, 4096)),
                volume_options: opts,
            };
            let vol = format!("weglarka-spike-{label}-{id}");
            s.cleanup.volumes.push(vol.clone());
            raw(
                &socket,
                "POST",
                "/volumes/create",
                Some(&json!({"Name": vol})),
                &[],
            )
            .unwrap();
            let c = format!("spike-{label}-{id}");
            if let Err(e) = s.start(&v.body(&c, user, &vol)) {
                eprintln!("SPIKE {label} [{who}]: start -> FAIL ({})", one_line(&e));
                continue;
            }
            if label == "a-archive" {
                let put = raw(
                    &socket,
                    "PUT",
                    &format!("/containers/{c}/archive?path=/data"),
                    None,
                    &[
                        "-H",
                        "content-type: application/x-tar",
                        "--data-binary",
                        &format!("@{}", tar.display()),
                    ],
                );
                eprintln!(
                    "SPIKE {label} [{who}]: archive PUT = {:?}",
                    put.as_ref().map(|_| "ok").map_err(|e| one_line(e))
                );
                let o = s
                    .sh(
                        &c,
                        "test \"$(stat -c %u /data/imported.txt)\" = \"$(id -u)\"",
                    )
                    .await
                    == 0;
                say(label, who, "archive-put file owned by container uid", o);
                eprintln!(
                    "SPIKE {label} [{who}]: host owner = {}",
                    s.host_owner(&vol, "imported.txt")
                );
                let out = dir.join("get.tar");
                let get = raw(
                    &socket,
                    "GET",
                    &format!("/containers/{c}/archive?path=/data/imported.txt"),
                    None,
                    &["-o", out.to_str().unwrap()],
                );
                if get.is_ok() {
                    let l = Command::new("tar")
                        .args(["-tvf", out.to_str().unwrap(), "--numeric-owner"])
                        .output()
                        .unwrap();
                    for line in String::from_utf8_lossy(&l.stdout).lines() {
                        eprintln!("SPIKE {label} [{who}]: archive GET entry: {line}");
                    }
                } else {
                    eprintln!("SPIKE {label} [{who}]: archive GET -> FAIL");
                }
            } else {
                // volume import while the container is stopped, then start → `U` should chown.
                raw(
                    &socket,
                    "POST",
                    &format!("/containers/{c}/stop?timeout=0"),
                    None,
                    &[],
                )
                .unwrap();
                let imp = raw(
                    &socket,
                    "POST",
                    &format!("/volumes/{vol}/import"),
                    None,
                    &[
                        "-H",
                        "content-type: application/x-tar",
                        "--data-binary",
                        &format!("@{}", tar.display()),
                    ],
                );
                say(label, who, "volume import while stopped", imp.is_ok());
                eprintln!(
                    "SPIKE {label} [{who}]: host owner before restart = {}",
                    s.host_owner(&vol, "imported.txt")
                );
                raw(
                    &socket,
                    "POST",
                    &format!("/containers/{c}/start"),
                    None,
                    &[],
                )
                .unwrap();
                let o = s
                    .sh(
                        &c,
                        "test \"$(stat -c %u /data/imported.txt)\" = \"$(id -u)\"",
                    )
                    .await
                    == 0;
                say(label, who, "after restart: file owned by container uid", o);
                eprintln!(
                    "SPIKE {label} [{who}]: host owner after restart = {}",
                    s.host_owner(&vol, "imported.txt")
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
