//! Podman client contract (libpod v6). Implemented by `weglarka-podman` (session a) and by the
//! in-memory `testing::FakePodman` (session b, daemon). The models are *our* domain types —
//! wire models (serde with `#[serde(default)]`, only used fields) live in `weglarka-podman`.
//!
//! Async: native `async fn` in traits + generics (see `docs/decisions/0001-async-traits.md`).
//! Methods are written as `-> impl Future + Send` so implementations can use `async fn`
//! and callers can `tokio::spawn`.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;

use bytes::Bytes;
use futures_core::Stream;
use futures_util::stream::BoxStream;

use crate::app::{Digest, Resources, SecretTarget};

#[derive(Debug, thiserror::Error)]
pub enum PodmanError {
    #[error("podman socket unreachable: {0}")]
    Unreachable(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    Conflict(String),
    #[error("podman API error {status}: {message}")]
    Api { status: u16, message: String },
    /// Error reported mid-way through the pull stream (HTTP 200, error in the body).
    #[error("image pull failed: {0}")]
    Pull(String),
    #[error("unexpected podman response: {0}")]
    Protocol(String),
}

impl PodmanError {
    /// The registry refused the pull for lack of (valid) credentials: HTTP 401/403, or libpod's 500 /
    /// mid-stream error carrying the registry's `unauthorized` / `denied` message. Drives
    /// `EngineError::RegistryAuth`, so the operator is told to fix the credentials instead of
    /// reading a raw libpod error.
    pub fn is_registry_auth_failure(&self) -> bool {
        const MARKERS: [&str; 5] = [
            "unauthorized",
            "authentication required",
            "requested access to the resource is denied",
            "denied",
            "insufficient_scope",
        ];
        let has_marker = |message: &str| {
            let message = message.to_ascii_lowercase();
            MARKERS.iter().any(|m| message.contains(m))
        };
        match self {
            Self::Api {
                status: 401 | 403, ..
            } => true,
            Self::Api { message, .. } | Self::Pull(message) => has_marker(message),
            _ => false,
        }
    }
}

pub type Result<T, E = PodmanError> = std::result::Result<T, E>;

/// Credentials for one registry, sent as `X-Registry-Auth` on a pull. `Debug` never reveals the
/// password; the type is deliberately not `Serialize`.
#[derive(Clone, PartialEq, Eq)]
pub struct RegistryAuth {
    username: String,
    password: String,
}

impl RegistryAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Parses the stored secret value `<username>:<password>` (split at the first colon, so the
    /// password may contain colons). `None` for a malformed value (no colon, empty username or
    /// password).
    pub fn parse(value: &[u8]) -> Option<Self> {
        let (username, password) = std::str::from_utf8(value).ok()?.split_once(':')?;
        (!username.is_empty() && !password.is_empty()).then(|| Self::new(username, password))
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    /// For the wire encoding only — never log it.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryAuth")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: String,
    pub api_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    No,
    /// `--restart=always` — conmon does the restart, even when Węglarka is down.
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub host_ip: Option<String>,
    pub host_port: u16,
    pub container_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretAttachment {
    /// Secret name in Podman.
    pub secret: String,
    pub target: SecretTarget,
}

/// Bind mount of a host directory/file (e.g. the ingress `nginx.conf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

/// Named volume mounted into a container (iteration 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeAttachment {
    /// Podman volume name (`labels::volume_name`).
    pub volume: String,
    pub target: String,
    pub read_only: bool,
}

/// One line of a uid/gid map: container ids `container_id..+size` ↔ ids `host_id..+size` of the
/// namespace the Podman user runs in (rootless: 0 = the user itself, `1..` = its subuids in order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdRange {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

/// Explicit user-namespace mapping; when set it replaces `userns_auto` (the chosen path, ADR 0009).
/// libpod needs `userns: private` *and* the maps: `private` alone is rejected, maps alone are silently
/// ignored — the wire layer always sends the pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapping {
    pub uid_map: Vec<IdRange>,
    pub gid_map: Vec<IdRange>,
}

/// Healthcheck defined by the spec (`health.command`), overriding the image's `HEALTHCHECK`.
/// The deploy gate runs it with `healthcheck_run`; `interval_secs` only matters for the container's
/// own periodic runs. Mapping to libpod: session 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHealthcheck {
    /// Exec form, no shell.
    pub command: Vec<String>,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    /// Image reference or digest (`repo@sha256:…`) — reconcile pins the digest.
    pub image: String,
    /// Arguments to the image's entrypoint (`Cmd`); empty keeps the image's own `CMD` and this never
    /// overrides the entrypoint (issue #79).
    pub command: Vec<String>,
    /// Replaces the image's `ENTRYPOINT` when set (`weglarka run --entrypoint`); `None` keeps it. Apps
    /// never set it: only one-off containers may swap the entrypoint (ADR 0040).
    pub entrypoint: Option<Vec<String>>,
    pub labels: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    /// Networks the container joins on creation (first = primary).
    pub networks: Vec<String>,
    /// Extra DNS aliases per joined network (network name → aliases; issue #128). The container
    /// name is always an alias already; a network missing from here gets no extras. Names not in
    /// `networks` are ignored.
    pub network_aliases: BTreeMap<String, Vec<String>>,
    pub secrets: Vec<SecretAttachment>,
    pub publish: Vec<PortMapping>,
    pub restart: RestartPolicy,
    /// `--userns=auto` as the MVP sends it (`userns: {nsmode: auto}`). **A no-op under rootless Podman**:
    /// measured on 6.1, the container still gets the default map (`0 → the Podman user`, `1.. → all
    /// subuids`), shared by every container. Real `auto` needs `idmappings.AutoUserNs` too, which this
    /// contract does not express on purpose: iteration 2 uses explicit per-instance ranges
    /// ([`IdMapping`]) instead — see docs/decisions/0009-volume-ownership.md.
    pub userns_auto: bool,
    /// Host bind mounts (empty list for ordinary apps).
    pub mounts: Vec<BindMount>,
    /// Named volumes (iteration 2).
    pub volumes: Vec<VolumeAttachment>,
    /// Resource limits; unlimited unless set (iteration 2).
    pub resources: Resources,
    /// Healthcheck from the spec; `None` keeps the image's own (iteration 2).
    pub healthcheck: Option<ContainerHealthcheck>,
    /// Explicit uid/gid maps; replaces `userns_auto` when set (iteration 2).
    pub id_mapping: Option<IdMapping>,
    /// Keep the Podman user's own supplementary groups inside the container (crun's
    /// `run.oci.keep_original_groups`, the `--group-add keep-groups` of the CLI; ADR 0045). All
    /// groups, not a chosen one; access checks use the host gids even though the container shows
    /// them as `nobody`.
    pub keep_groups: bool,
    /// Hardening from the spec (read-only root, tmpfs, capabilities, no-new-privileges).
    pub security: crate::app::Security,
}

/// Named volume to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    pub name: String,
    /// Includes `weglarka.instance` (labels::INSTANCE).
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    /// Host path of the volume data, if reported.
    pub mountpoint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeFilter {
    pub labels: BTreeMap<String, String>,
}

/// Tar bytes in transit (volume import/export): streamed so a large volume never sits in RAM.
pub type TarStream = BoxStream<'static, Result<Bytes>>;

/// Which output stream a [`LogChunk`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    Stdout,
    Stderr,
}

/// A piece of a container's output (arbitrary bytes, not necessarily whole lines or valid UTF-8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogChunk {
    pub source: LogSource,
    pub data: Bytes,
}

pub type LogStream = BoxStream<'static, Result<LogChunk>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Paused,
    Stopped,
    Exited,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Starting,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    /// Image reference used at creation.
    pub image: String,
    pub image_id: String,
    pub labels: BTreeMap<String, String>,
    pub state: ContainerState,
    pub exit_code: Option<i32>,
    /// `None` — the image has no healthcheck.
    pub health: Option<HealthStatus>,
    /// How many times Podman restarted the container (libpod `RestartCount`); `0` until the first restart.
    /// Crash-loop detection compares it across reconcile passes (`crate::crash`).
    pub restarts: u32,
    /// Names of the networks the container is currently attached to (sorted).
    pub networks: Vec<String>,
    /// The container's own addresses on those networks (sorted, deduplicated); empty when it is not
    /// running. Ingress trusts the nginx container's own addresses as the port forwarder's source
    /// (`docs/decisions/0032`).
    pub addresses: Vec<IpAddr>,
    /// Ports the container publishes on the host as libpod reports them (`NetworkSettings.Ports`), with
    /// the **actual** host port — so a mapping created with `host_port = 0` shows the one it got.
    pub published_ports: Vec<PortMapping>,
}

/// Repository from an image reference — without tag and digest but **with** the registry port:
/// `host:5000/a/b:1@sha256:…` → `host:5000/a/b`. Only a `:` after the last `/` starts a tag, so
/// `localhost:5000/y` keeps its port instead of being cut to `localhost`.
pub fn image_repo(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    let name_start = image.rfind('/').map_or(0, |i| i + 1);
    match image[name_start..].rfind(':') {
        Some(i) => &image[..name_start + i],
        None => image,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub id: String,
    /// Repository digest (from the manifest), if known.
    pub digest: Option<Digest>,
    /// `repo:tag` names of the image (`<none>:<none>` is filtered out).
    pub repo_tags: Vec<String>,
    /// `repo@sha256:…` names of the image. An image whose tag moved away keeps these, which is how an
    /// image pulled by Węglarka stays attributable (docs/decisions/0020).
    pub repo_digests: Vec<String>,
    /// Uncompressed size as reported by libpod; `0` when it does not report one. Feeds the
    /// reclaimed-space estimate, which counts shared layers per image (an upper bound).
    pub size_bytes: u64,
    /// OCI labels of the image. The self-update reads `io.weglarka.state-schema` here before it
    /// replaces the daemon image (docs/decisions/0023); `image_list` does not fill this in.
    pub labels: std::collections::BTreeMap<String, String>,
}

/// An image created by [`PodmanClient::image_load`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedImage {
    pub id: String,
    /// Manifest digest of the loaded image. A docker archive carries no manifest, so libpod computes
    /// one: it need not equal the digest the image had in a registry, but it is stable for the same
    /// archive (docs/decisions/0042).
    pub digest: Option<Digest>,
    /// Names libpod reported for the archive's image; empty or just the id for an archive saved by id.
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullEvent {
    Progress {
        message: String,
    },
    /// End of the pull; `digest` is the digest that will be pinned in state.
    Complete {
        image_id: String,
        digest: Option<Digest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSpec {
    pub name: String,
    pub internal: bool,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Container,
    Image,
    Network,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodmanEvent {
    pub kind: EventKind,
    /// np. `start`, `die`, `health_status`, `pull`.
    pub action: String,
    pub id: String,
    pub name: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    /// Only events from objects with these labels (`k=v`).
    pub labels: BTreeMap<String, String>,
    /// Unix timestamp — replay events from this moment.
    pub since: Option<i64>,
}

/// A network as listed by [`PodmanClient::network_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSummary {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

/// Network data needed by ingress: gateway addresses where the network DNS (aardvark) listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub name: String,
    pub gateways: Vec<std::net::IpAddr>,
    /// Subnets in CIDR notation (`10.89.1.0/24`).
    pub subnets: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerFilter {
    pub labels: BTreeMap<String, String>,
}

/// libpod client. `Send + Sync`, cheaply cloned via `Arc` on the caller's side.
pub trait PodmanClient: Send + Sync {
    fn version(&self) -> impl Future<Output = Result<VersionInfo>> + Send;

    /// Number of subuids the Podman user may hand out (rootless: the sum of the non-zero entries of
    /// `host.idMappings.uidmap` in `GET /info`). The daemon runs in a container and cannot read the
    /// host's `/etc/subuid`, so the pool is asked of Podman itself. Feeds [`crate::uid_range::allocate`].
    fn subuid_pool(&self) -> impl Future<Output = Result<u64>> + Send;

    // Containers
    fn container_create(&self, spec: &ContainerSpec)
    -> impl Future<Output = Result<String>> + Send;
    fn container_start(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    fn container_stop(
        &self,
        name: &str,
        timeout_secs: u32,
    ) -> impl Future<Output = Result<()>> + Send;
    fn container_remove(&self, name: &str, force: bool) -> impl Future<Output = Result<()>> + Send;
    /// Sends a signal (name without `SIG`, e.g. `HUP`) to a running container — reloads nginx.
    /// Renames a container, running or not. libpod does **not** update the DNS entry of a running
    /// container on its networks: the old name keeps resolving and the new one does not (ADR 0046), so
    /// a rename is bookkeeping, never a way to move traffic. `Conflict` when `new_name` is taken.
    fn container_rename(
        &self,
        name: &str,
        new_name: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    fn container_kill(&self, name: &str, signal: &str) -> impl Future<Output = Result<()>> + Send;
    /// `PodmanError::NotFound` if missing.
    /// Runs `cmd` in a running container, waits for it to finish and returns the exit code.
    /// Output is not captured (used for `nginx -t`).
    fn container_exec(
        &self,
        name: &str,
        cmd: &[String],
    ) -> impl Future<Output = Result<i32>> + Send;
    /// The container's output from the beginning; with `follow` the stream stays open until the
    /// container exits (one-off `weglarka run`). Containers here have no TTY, so stdout and stderr
    /// arrive separated.
    fn container_logs(
        &self,
        name: &str,
        follow: bool,
    ) -> impl Future<Output = Result<LogStream>> + Send;
    /// Blocks until the container has stopped and returns its exit code. `NotFound` if missing.
    fn container_wait(&self, name: &str) -> impl Future<Output = Result<i32>> + Send;
    /// Extracts a tar archive into `path` of a container (`PUT /containers/{name}/archive`; works on
    /// created, not started containers). Unlike `volume_import`, libpod maps the archive's ids through
    /// the *container's* user namespace, so a foreign tar owned by uid 1000 becomes container uid 1000
    /// (docs/decisions/0009).
    fn container_archive_put(
        &self,
        name: &str,
        path: &str,
        tar: TarStream,
    ) -> impl Future<Output = Result<()>> + Send;
    fn container_inspect(&self, name: &str) -> impl Future<Output = Result<ContainerInfo>> + Send;
    fn container_list(
        &self,
        filter: &ContainerFilter,
    ) -> impl Future<Output = Result<Vec<ContainerInfo>>> + Send;

    // Images
    /// Pull as a stream; an error mid-pull appears as an `Err` in the stream. `auth` is sent as
    /// `X-Registry-Auth`; `None` leaves authentication to the podman user's `auth.json`
    /// (docs/decisions/0026).
    fn image_pull_with(
        &self,
        reference: &str,
        auth: Option<&RegistryAuth>,
    ) -> impl Stream<Item = Result<PullEvent>> + Send;
    /// Anonymous pull (public images, `auth.json`) — `image_pull_with` without credentials.
    fn image_pull(&self, reference: &str) -> impl Stream<Item = Result<PullEvent>> + Send {
        self.image_pull_with(reference, None)
    }
    fn image_inspect(&self, reference: &str) -> impl Future<Output = Result<ImageInfo>> + Send;
    /// Top-level images in the local store (one entry per image, intermediate layers excluded).
    /// Feeds image retention: keep the current and the previous image, drop older ones
    /// (docs/decisions/0020).
    fn image_list(&self) -> impl Future<Output = Result<Vec<ImageInfo>>> + Send;
    /// Gives image `id` an additional tag (manual rollback).
    fn image_tag(&self, id: &str, repo: &str, tag: &str)
    -> impl Future<Output = Result<()>> + Send;
    fn image_remove(&self, reference: &str) -> impl Future<Output = Result<()>> + Send;
    /// Loads an image archive (`oci-archive` or `docker-archive`) from a streamed tar and reports the
    /// image it created (`weglarka push`, docs/decisions/0042). Nothing is buffered by the client.
    fn image_load(&self, tar: TarStream) -> impl Future<Output = Result<LoadedImage>> + Send;

    // Networks
    /// Idempotent: an existing network with that name → `Ok`.
    fn network_create(&self, spec: &NetworkSpec) -> impl Future<Output = Result<()>> + Send;
    fn network_connect(
        &self,
        network: &str,
        container: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// [`Self::network_connect`] with DNS aliases on that network (ADR 0046). libpod refuses a network
    /// the container is already on ("network is already connected"), so a container that should gain
    /// an alias later has to start on a different network first.
    fn network_connect_aliased(
        &self,
        network: &str,
        container: &str,
        aliases: &[String],
    ) -> impl Future<Output = Result<()>> + Send;

    /// Detaches a running container from a network. Idempotent: not attached → `Ok`.
    fn network_disconnect(
        &self,
        network: &str,
        container: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// `PodmanError::NotFound` if the network is missing.
    fn network_inspect(&self, name: &str) -> impl Future<Output = Result<NetworkInfo>> + Send;

    /// All networks of the runtime user, with their labels.
    fn network_list(&self) -> impl Future<Output = Result<Vec<NetworkSummary>>> + Send;

    /// Removes a network. Idempotent: missing → `Ok`. Fails (without force) while containers are
    /// still attached — callers treat that as "try again later".
    fn network_remove(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

    // Secrets (Podman secrets); `create` overwrites an existing one with that name.
    fn secret_create(&self, name: &str, data: &[u8]) -> impl Future<Output = Result<()>> + Send;
    fn secret_remove(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

    // Volumes (iteration 2). Session 1 owns the callers; the libpod client implements all of these.
    /// Idempotent: an existing volume with that name → `Ok` (labels are not changed).
    fn volume_create(&self, spec: &VolumeSpec) -> impl Future<Output = Result<()>> + Send;
    /// `PodmanError::NotFound` if missing.
    fn volume_inspect(&self, name: &str) -> impl Future<Output = Result<VolumeInfo>> + Send;
    fn volume_list(
        &self,
        filter: &VolumeFilter,
    ) -> impl Future<Output = Result<Vec<VolumeInfo>>> + Send;
    /// Extracts a tar archive into the volume (`POST /libpod/volumes/{name}/import`).
    fn volume_import(&self, name: &str, tar: TarStream) -> impl Future<Output = Result<()>> + Send;
    /// The volume's contents as a tar archive (`GET /libpod/volumes/{name}/export`).
    fn volume_export(&self, name: &str) -> impl Future<Output = Result<TarStream>> + Send;
    /// `PodmanError::NotFound` if missing; `force` also removes it while containers use it.
    fn volume_remove(&self, name: &str, force: bool) -> impl Future<Output = Result<()>> + Send;

    /// One-shot healthcheck invocation (the deploy gate calls it itself — no systemd timers).
    fn healthcheck_run(&self, container: &str)
    -> impl Future<Output = Result<HealthStatus>> + Send;

    /// Event stream (never ends in normal operation).
    fn events(&self, filter: &EventFilter) -> impl Stream<Item = Result<PodmanEvent>> + Send;
}

#[cfg(test)]
mod tests {
    use super::{PodmanError, RegistryAuth, image_repo};

    #[test]
    fn registry_auth_parses_user_colon_password_and_hides_the_password() {
        let auth = RegistryAuth::parse(b"ci:p:ss").unwrap();
        assert_eq!((auth.username(), auth.password()), ("ci", "p:ss"));
        for bad in [&b"nocolon"[..], b":pw", b"user:", b"", &[0xff, b':', b'x']] {
            assert!(RegistryAuth::parse(bad).is_none(), "{bad:?}");
        }
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("ci") && !dbg.contains("p:ss"), "{dbg}");
    }

    #[test]
    fn registry_auth_failure_is_status_or_message_based() {
        let api = |status, message: &str| PodmanError::Api {
            status,
            message: message.into(),
        };
        assert!(api(401, "x").is_registry_auth_failure());
        assert!(api(403, "x").is_registry_auth_failure());
        assert!(
            api(500, "pinging container registry ghcr.io: unauthorized").is_registry_auth_failure()
        );
        assert!(
            PodmanError::Pull("denied: requested access to the resource is denied".into())
                .is_registry_auth_failure()
        );
        assert!(!api(500, "boom").is_registry_auth_failure());
        assert!(!PodmanError::Pull("manifest unknown".into()).is_registry_auth_failure());
        assert!(!PodmanError::NotFound("x".into()).is_registry_auth_failure());
    }

    /// Tag and digest are dropped, a registry port is not — deploy, retention and the podman wire
    /// parser all share this one helper.
    #[test]
    fn image_repo_strips_tag_and_digest_but_not_registry_port() {
        assert_eq!(image_repo("ghcr.io/a/b:latest"), "ghcr.io/a/b");
        assert_eq!(image_repo("ghcr.io/a/b"), "ghcr.io/a/b");
        assert_eq!(image_repo("localhost:5000/a/b:1"), "localhost:5000/a/b");
        assert_eq!(image_repo("localhost:5000/a"), "localhost:5000/a");
        assert_eq!(image_repo("ghcr.io/a/b:1@sha256:abc"), "ghcr.io/a/b");
        assert_eq!(image_repo("ghcr.io/x/y@sha256:ab"), "ghcr.io/x/y");
        assert_eq!(image_repo("localhost:5000/y"), "localhost:5000/y");
        assert_eq!(image_repo("localhost:5000/y:1"), "localhost:5000/y");
    }
}

#[cfg(all(test, feature = "testing"))]
mod fake_tests {
    use futures_util::StreamExt;

    use super::*;
    use crate::testing::FakePodman;

    fn spec(name: &str, image: &str) -> ContainerSpec {
        ContainerSpec {
            name: name.into(),
            image: image.into(),
            command: vec![],
            entrypoint: None,
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            network_aliases: Default::default(),
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::Always,
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

    #[test]
    fn registry_auth_failures_are_told_apart_from_missing_images() {
        let api = |status| PodmanError::Api {
            status,
            message: String::new(),
        };
        assert!(api(401).is_registry_auth_failure());
        assert!(api(403).is_registry_auth_failure());
        assert!(!api(500).is_registry_auth_failure());
        assert!(!PodmanError::NotFound("x".into()).is_registry_auth_failure());
        for m in [
            "unauthorized: authentication required",
            "requested access to the resource is denied",
        ] {
            assert!(
                PodmanError::Pull(m.into()).is_registry_auth_failure(),
                "{m}"
            );
        }
        assert!(!PodmanError::Pull("manifest unknown".into()).is_registry_auth_failure());
    }

    #[tokio::test]
    async fn pull_create_start_health() {
        let fake = FakePodman::new();
        let events: Vec<_> = fake.image_pull("ghcr.io/x/y:latest").collect().await;
        assert!(matches!(
            events.last(),
            Some(Ok(PullEvent::Complete {
                digest: Some(_),
                ..
            }))
        ));

        fake.container_create(&spec("app", "ghcr.io/x/y:latest"))
            .await
            .unwrap();
        fake.container_start("app").await.unwrap();
        fake.script_health("app", [HealthStatus::Starting, HealthStatus::Healthy]);
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Starting
        );
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Healthy
        );
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Healthy
        );
    }

    #[tokio::test]
    async fn pull_error_arrives_mid_stream_and_missing_image_is_not_found() {
        let fake = FakePodman::new();
        fake.fail_pull("ghcr.io/x/bad:latest", "manifest unknown");
        let events: Vec<_> = fake.image_pull("ghcr.io/x/bad:latest").collect().await;
        assert!(matches!(events[0], Ok(PullEvent::Progress { .. })));
        assert!(matches!(events[1], Err(PodmanError::Pull(_))));

        let err = fake
            .container_create(&spec("a", "ghcr.io/x/bad:latest"))
            .await
            .unwrap_err();
        assert!(matches!(err, PodmanError::NotFound(_)));
    }

    /// A registry port is not a tag: a pull of `localhost:5000/y` registers the image under the
    /// full repository, exactly as libpod names it (#76).
    #[tokio::test]
    async fn pull_registers_the_image_under_the_repository_with_the_registry_port() {
        let fake = FakePodman::new();
        let events: Vec<_> = fake.image_pull("localhost:5000/y").collect().await;
        let digest = match events.last() {
            Some(Ok(PullEvent::Complete {
                digest: Some(digest),
                ..
            })) => digest.clone(),
            other => panic!("pull did not complete: {other:?}"),
        };

        let pinned = format!("localhost:5000/y@{digest}");
        assert!(fake.image_inspect(&pinned).await.is_ok());
        let port_as_repo = format!("localhost@{digest}");
        assert!(matches!(
            fake.image_inspect(&port_as_repo).await,
            Err(PodmanError::NotFound(_))
        ));
    }
}
