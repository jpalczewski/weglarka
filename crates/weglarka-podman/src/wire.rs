//! libpod v6 wire models: only the used fields, `#[serde(default)]`, unknown fields ignored.
//! Conversions to the `weglarka_core::podman` domain types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use weglarka_core::app::{Digest, Resources, SecretTarget};
use weglarka_core::podman::{
    ContainerHealthcheck, ContainerInfo, ContainerSpec, ContainerState, EventKind, HealthStatus,
    IdRange, ImageInfo, NetworkInfo, NetworkSpec, NetworkSummary, PodmanError, PodmanEvent,
    PullEvent, RestartPolicy, Result, VersionInfo, VolumeInfo, VolumeSpec,
};

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| PodmanError::Protocol(format!("decoding response: {e}")))
}

// ---- version ----

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct Version {
    version: String,
    api_version: String,
    components: Vec<Component>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct Component {
    details: BTreeMap<String, String>,
}

/// `GET /info`: only the rootless uid map is used.
#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct Info {
    host: InfoHost,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct InfoHost {
    #[serde(rename = "idMappings")]
    id_mappings: InfoIdMappings,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct InfoIdMappings {
    uidmap: Vec<InfoIdRange>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct InfoIdRange {
    container_id: u64,
    size: u64,
}

impl Info {
    /// Subuids available to the rootless user: every uid map line except `0 → the user itself`.
    pub(crate) fn subuid_pool(&self) -> u64 {
        self.host
            .id_mappings
            .uidmap
            .iter()
            .filter(|r| r.container_id >= 1)
            .map(|r| r.size)
            .sum()
    }
}

impl Version {
    /// The top-level `ApiVersion` is the compat version ("1.41"); the libpod version is in the Podman Engine component.
    pub(crate) fn into_domain(self) -> VersionInfo {
        let api_version = self
            .components
            .iter()
            .find_map(|c| c.details.get("APIVersion"))
            .cloned()
            .unwrap_or(self.api_version);
        VersionInfo {
            version: self.version,
            api_version,
        }
    }
}

// ---- containers ----

#[derive(Serialize)]
pub(crate) struct CreateContainer<'a> {
    name: &'a str,
    image: &'a str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    labels: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    env: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_policy: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userns: Option<Namespace>,
    /// Explicit uid/gid maps. Only effective together with `userns: private` — libpod rejects
    /// `private` without maps and silently ignores maps without `private` (docs/decisions/0009).
    #[serde(skip_serializing_if = "Option::is_none")]
    idmappings: Option<IdMappings>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<NamedVolume<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    netns: Option<Namespace>,
    #[serde(rename = "Networks", skip_serializing_if = "BTreeMap::is_empty")]
    networks: BTreeMap<&'a str, EmptyObject>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    portmappings: Vec<PortMapping<'a>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    secrets: Vec<MountSecret<'a>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    secret_env: BTreeMap<&'a str, &'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<BindMountBody<'a>>,
    /// OCI `LinuxResources`; omitted entirely when the spec sets no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_limits: Option<ResourceLimits>,
    /// `Schema2HealthConfig`; omitted keeps the image's own HEALTHCHECK.
    #[serde(skip_serializing_if = "Option::is_none")]
    healthconfig: Option<HealthConfig<'a>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    read_only_filesystem: bool,
    /// With a read-only root: writable tmpfs on `/tmp`, `/var/tmp` and `/run` (the
    /// `podman run --read-only` default; the API defaults it to off).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    read_write_tmpfs: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cap_drop: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cap_add: Vec<&'a str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    no_new_privileges: bool,
}

/// Options of a tmpfs mount from `security.tmpfs` (writable, no devices or setuid).
const TMPFS_OPTIONS: [&str; 3] = ["rw", "nosuid", "nodev"];

#[derive(Serialize)]
struct ResourceLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<MemoryResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pids: Option<PidsResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu: Option<CpuResources>,
}

#[derive(Serialize)]
struct MemoryResources {
    limit: u64,
}

#[derive(Serialize)]
struct PidsResources {
    limit: i64,
}

#[derive(Serialize)]
struct CpuResources {
    quota: i64,
    period: u64,
}

/// CFS period used for `cpus` (the kernel default); `quota = cpus * period`.
const CPU_PERIOD_US: u64 = 100_000;

impl ResourceLimits {
    fn from_spec(r: &Resources) -> Option<Self> {
        if r.is_unlimited() {
            return None;
        }
        Some(Self {
            memory: r.memory.map(|m| MemoryResources { limit: m.bytes() }),
            pids: r.pids_limit.map(|l| PidsResources {
                limit: i64::from(l),
            }),
            cpu: r.cpus.map(|c| CpuResources {
                // millis / 1000 CPUs * period.
                quota: i64::from(c.millis()) * 100,
                period: CPU_PERIOD_US,
            }),
        })
    }
}

/// Go `Schema2HealthConfig` (no json tags besides `omitempty` — PascalCase); durations are nanoseconds.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct HealthConfig<'a> {
    test: Vec<&'a str>,
    interval: u64,
    timeout: u64,
    retries: u32,
}

impl<'a> HealthConfig<'a> {
    fn from_spec(h: &'a ContainerHealthcheck) -> Self {
        const NANOS: u64 = 1_000_000_000;
        Self {
            test: std::iter::once("CMD")
                .chain(h.command.iter().map(String::as_str))
                .collect(),
            interval: u64::from(h.interval_secs) * NANOS,
            timeout: u64::from(h.timeout_secs) * NANOS,
            retries: h.retries,
        }
    }
}

#[derive(Serialize)]
struct BindMountBody<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    source: &'a str,
    destination: &'a str,
    options: Vec<&'static str>,
}

/// `specgen.NamedVolume` (no json tags — Go matches names case-insensitively).
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct NamedVolume<'a> {
    name: &'a str,
    dest: &'a str,
    options: Vec<&'static str>,
}

#[derive(Serialize)]
struct IdMappings {
    #[serde(rename = "UIDMap")]
    uid_map: Vec<WireIdRange>,
    #[serde(rename = "GIDMap")]
    gid_map: Vec<WireIdRange>,
    #[serde(rename = "HostUIDMapping")]
    host_uid_mapping: bool,
    #[serde(rename = "HostGIDMapping")]
    host_gid_mapping: bool,
}

#[derive(Serialize)]
struct WireIdRange {
    container_id: u32,
    host_id: u32,
    size: u32,
}

impl From<&IdRange> for WireIdRange {
    fn from(r: &IdRange) -> Self {
        Self {
            container_id: r.container_id,
            host_id: r.host_id,
            size: r.size,
        }
    }
}

#[derive(Serialize)]
struct Namespace {
    nsmode: &'static str,
}

#[derive(Serialize)]
struct EmptyObject {}

#[derive(Serialize)]
struct PortMapping<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    host_ip: Option<&'a str>,
    host_port: u16,
    container_port: u16,
    protocol: &'static str,
}

/// `specgen.Secret` has no json tags — Go matches names case-insensitively.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MountSecret<'a> {
    source: &'a str,
    target: &'a str,
    #[serde(rename = "UID")]
    uid: u32,
    #[serde(rename = "GID")]
    gid: u32,
    /// Sent explicitly: libpod takes 0 literally (mode `000`), unlike `podman run --secret`.
    mode: u32,
}

/// Mode of a mounted secret when the spec sets none: readable by any user in the container, like
/// the `podman run --secret` default. Root-only `000` broke images that run as a non-root user.
const DEFAULT_SECRET_MODE: u32 = 0o444;

impl<'a> CreateContainer<'a> {
    pub(crate) fn new(spec: &'a ContainerSpec) -> Self {
        let mut secrets = Vec::new();
        let mut secret_env = BTreeMap::new();
        for attachment in &spec.secrets {
            match &attachment.target {
                SecretTarget::Env { var } => {
                    secret_env.insert(var.as_str(), attachment.secret.as_str());
                }
                SecretTarget::Mount { path, mode } => secrets.push(MountSecret {
                    source: &attachment.secret,
                    target: path,
                    uid: 0,
                    gid: 0,
                    mode: mode.unwrap_or(DEFAULT_SECRET_MODE),
                }),
            }
        }
        Self {
            name: &spec.name,
            image: &spec.image,
            labels: &spec.labels,
            env: &spec.env,
            restart_policy: match spec.restart {
                RestartPolicy::No => None,
                RestartPolicy::Always => Some("always"),
            },
            // Explicit maps replace `auto`; they need `private` (see `idmappings`).
            userns: match (&spec.id_mapping, spec.userns_auto) {
                (Some(_), _) => Some(Namespace { nsmode: "private" }),
                (None, true) => Some(Namespace { nsmode: "auto" }),
                (None, false) => None,
            },
            idmappings: spec.id_mapping.as_ref().map(|m| IdMappings {
                uid_map: m.uid_map.iter().map(Into::into).collect(),
                gid_map: m.gid_map.iter().map(Into::into).collect(),
                host_uid_mapping: false,
                host_gid_mapping: false,
            }),
            volumes: spec
                .volumes
                .iter()
                .map(|v| NamedVolume {
                    name: &v.volume,
                    dest: &v.target,
                    options: if v.read_only { vec!["ro"] } else { vec![] },
                })
                .collect(),
            // `Networks` works only with bridge mode.
            netns: (!spec.networks.is_empty()).then_some(Namespace { nsmode: "bridge" }),
            networks: spec
                .networks
                .iter()
                .map(|n| (n.as_str(), EmptyObject {}))
                .collect(),
            portmappings: spec
                .publish
                .iter()
                .map(|p| PortMapping {
                    host_ip: p.host_ip.as_deref(),
                    host_port: p.host_port,
                    container_port: p.container_port,
                    protocol: "tcp",
                })
                .collect(),
            secrets,
            secret_env,
            resource_limits: ResourceLimits::from_spec(&spec.resources),
            healthconfig: spec.healthcheck.as_ref().map(HealthConfig::from_spec),
            mounts: spec
                .mounts
                .iter()
                .map(|m| BindMountBody {
                    kind: "bind",
                    source: &m.source,
                    destination: &m.target,
                    options: if m.read_only { vec!["ro"] } else { vec![] },
                })
                .chain(spec.security.tmpfs.iter().map(|path| BindMountBody {
                    kind: "tmpfs",
                    source: "tmpfs",
                    destination: path,
                    options: TMPFS_OPTIONS.to_vec(),
                }))
                .collect(),
            read_only_filesystem: spec.security.read_only,
            read_write_tmpfs: spec.security.read_only,
            cap_drop: spec.security.cap_drop.iter().map(String::as_str).collect(),
            cap_add: spec.security.cap_add.iter().map(String::as_str).collect(),
            no_new_privileges: spec.security.no_new_privileges,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct CreatedContainer {
    pub(crate) id: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct ListedContainer {
    pub(crate) id: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct InspectContainer {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    /// Image ID.
    #[serde(rename = "Image")]
    image_id: String,
    /// Reference used at creation.
    #[serde(rename = "ImageName")]
    image_name: String,
    #[serde(rename = "Config")]
    config: InspectConfig,
    #[serde(rename = "State")]
    state: InspectState,
    #[serde(rename = "NetworkSettings")]
    network_settings: InspectNetworkSettings,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectNetworkSettings {
    /// Only the keys (network names) matter.
    networks: Option<BTreeMap<String, serde::de::IgnoredAny>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectConfig {
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectState {
    status: String,
    exit_code: i32,
    #[serde(alias = "Healthcheck")]
    health: Option<InspectHealth>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct InspectHealth {
    status: String,
}

fn container_state(status: &str) -> ContainerState {
    match status {
        "created" | "configured" => ContainerState::Created,
        "running" => ContainerState::Running,
        "paused" => ContainerState::Paused,
        "stopped" => ContainerState::Stopped,
        "exited" => ContainerState::Exited,
        _ => ContainerState::Unknown,
    }
}

pub(crate) fn health_status(status: &str) -> Option<HealthStatus> {
    match status {
        "healthy" => Some(HealthStatus::Healthy),
        "unhealthy" => Some(HealthStatus::Unhealthy),
        "starting" => Some(HealthStatus::Starting),
        _ => None,
    }
}

impl InspectContainer {
    pub(crate) fn into_domain(self) -> ContainerInfo {
        let state = container_state(&self.state.status);
        ContainerInfo {
            id: self.id,
            name: self.name.trim_start_matches('/').to_owned(),
            image: self.image_name,
            image_id: self.image_id,
            labels: self.config.labels.unwrap_or_default(),
            exit_code: matches!(state, ContainerState::Exited | ContainerState::Stopped)
                .then_some(self.state.exit_code),
            state,
            health: self.state.health.and_then(|h| health_status(&h.status)),
            networks: self
                .network_settings
                .networks
                .unwrap_or_default()
                .into_keys()
                .collect(),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct HealthReport {
    pub(crate) status: String,
}

// ---- volumes ----

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateVolume<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    label: &'a BTreeMap<String, String>,
}

impl<'a> CreateVolume<'a> {
    pub(crate) fn new(spec: &'a VolumeSpec) -> Self {
        Self {
            name: &spec.name,
            label: &spec.labels,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct WireVolume {
    name: String,
    labels: Option<BTreeMap<String, String>>,
    mountpoint: String,
}

impl WireVolume {
    pub(crate) fn into_domain(self) -> VolumeInfo {
        VolumeInfo {
            name: self.name,
            labels: self.labels.unwrap_or_default(),
            mountpoint: (!self.mountpoint.is_empty()).then_some(self.mountpoint),
        }
    }
}

// ---- images ----

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct InspectImage {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "RepoTags")]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "RepoDigests")]
    repo_digests: Option<Vec<String>>,
    /// Manifest digest (when `RepoDigests` is absent, e.g. a locally built image).
    #[serde(rename = "Digest")]
    digest: String,
}

impl InspectImage {
    /// Prefers the digest of the repository from `reference`, then any `RepoDigests`, then `Digest`.
    pub(crate) fn into_domain(self, reference: &str) -> ImageInfo {
        let repo = reference_repo(reference);
        let repo_digests = self.repo_digests.unwrap_or_default();
        let digest = repo_digests
            .iter()
            .find(|d| d.split_once('@').is_some_and(|(r, _)| r == repo))
            .or_else(|| repo_digests.first())
            .and_then(|d| d.split_once('@').map(|(_, digest)| digest))
            .or(Some(self.digest.as_str()))
            .and_then(|d| Digest::new(d).ok());
        ImageInfo {
            id: self.id,
            digest,
            repo_tags: self.repo_tags.unwrap_or_default(),
        }
    }
}

/// `ghcr.io/x/y:latest` / `ghcr.io/x/y@sha256:…` → `ghcr.io/x/y`.
fn reference_repo(reference: &str) -> &str {
    let without_digest = reference.split_once('@').map_or(reference, |(r, _)| r);
    match without_digest.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => repo,
        _ => without_digest,
    }
}

/// One line of the `images/pull` stream.
#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct PullReport {
    stream: String,
    error: String,
    images: Vec<String>,
}

pub(crate) enum PullLine {
    Progress(PullEvent),
    /// Report with the image ID (usually the last line).
    Image(String),
    Nothing,
}

impl PullReport {
    pub(crate) fn classify(self) -> Result<PullLine> {
        if !self.error.is_empty() {
            return Err(PodmanError::Pull(self.error));
        }
        if let Some(id) = self.images.into_iter().last() {
            return Ok(PullLine::Image(id));
        }
        let message = self.stream.trim();
        Ok(if message.is_empty() {
            PullLine::Nothing
        } else {
            PullLine::Progress(PullEvent::Progress {
                message: message.to_owned(),
            })
        })
    }
}

// ---- networks ----

#[derive(Serialize)]
pub(crate) struct CreateNetwork<'a> {
    name: &'a str,
    driver: &'static str,
    internal: bool,
    /// Container name resolution on the network (nginx → `proxy_pass` by name).
    dns_enabled: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    labels: &'a BTreeMap<String, String>,
}

impl<'a> CreateNetwork<'a> {
    pub(crate) fn new(spec: &'a NetworkSpec) -> Self {
        Self {
            name: &spec.name,
            driver: "bridge",
            internal: spec.internal,
            dns_enabled: true,
            labels: &spec.labels,
        }
    }
}

/// Element of `GET /libpod/networks/json` (only the used fields).
#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ListedNetwork {
    name: String,
    labels: Option<BTreeMap<String, String>>,
}

impl ListedNetwork {
    pub(crate) fn into_domain(self) -> NetworkSummary {
        NetworkSummary {
            name: self.name,
            labels: self.labels.unwrap_or_default(),
        }
    }
}

/// Element of the `DELETE /libpod/networks/{name}` response: an error can come with HTTP 200.
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct NetworkRmReport {
    pub(crate) err: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct InspectNetwork {
    name: String,
    subnets: Vec<Subnet>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Subnet {
    gateway: String,
    subnet: String,
}

impl InspectNetwork {
    pub(crate) fn into_domain(self) -> NetworkInfo {
        NetworkInfo {
            name: self.name,
            gateways: self
                .subnets
                .iter()
                .filter_map(|s| s.gateway.parse().ok())
                .collect(),
            subnets: self
                .subnets
                .iter()
                .filter(|s| !s.subnet.is_empty())
                .map(|s| s.subnet.clone())
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct ConnectNetwork<'a> {
    pub(crate) container: &'a str,
}

#[derive(Serialize)]
pub(crate) struct DisconnectNetwork<'a> {
    pub(crate) container: &'a str,
    pub(crate) force: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct CreateExec<'a> {
    pub(crate) cmd: &'a [String],
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct CreatedExec {
    pub(crate) id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct StartExec {
    pub(crate) detach: bool,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
pub(crate) struct InspectExec {
    pub(crate) running: bool,
    pub(crate) exit_code: i32,
}

// ---- events ----

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct WireEvent {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Action")]
    action: String,
    #[serde(rename = "Actor")]
    actor: Actor,
    /// Fields of the older docker format (`status`/`id`) — fallback.
    status: String,
    id: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct Actor {
    #[serde(rename = "ID")]
    id: String,
    attributes: Option<BTreeMap<String, String>>,
}

impl WireEvent {
    pub(crate) fn into_domain(self) -> PodmanEvent {
        let mut attributes = self.actor.attributes.unwrap_or_default();
        let name = attributes.get("name").cloned().unwrap_or_default();
        attributes.remove("name");
        PodmanEvent {
            kind: match self.kind.as_str() {
                "container" => EventKind::Container,
                "image" => EventKind::Image,
                "network" => EventKind::Network,
                _ => EventKind::Other,
            },
            action: if self.action.is_empty() {
                self.status
            } else {
                self.action
            },
            id: if self.actor.id.is_empty() {
                self.id
            } else {
                self.actor.id
            },
            name,
            attributes,
        }
    }
}

#[cfg(test)]
mod tests {
    use weglarka_core::podman::{PortMapping as DomainPort, SecretAttachment};

    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../tests/fixtures/", $name)).as_bytes()
        };
    }

    #[test]
    fn version_prefers_libpod_api_version_from_components() {
        let v = decode::<Version>(fixture!("version.json"))
            .unwrap()
            .into_domain();
        assert_eq!(v.version, "6.1.0");
        assert_eq!(v.api_version, "6.1.0");
    }

    #[test]
    fn inspect_running_container() {
        let info = decode::<InspectContainer>(fixture!("inspect_container_running.json"))
            .unwrap()
            .into_domain();
        assert_eq!(info.name, "app-1");
        assert_eq!(info.image, "ghcr.io/jpalczewski/ntfy.zig:latest");
        assert_eq!(info.state, ContainerState::Running);
        assert_eq!(info.exit_code, None);
        assert_eq!(info.health, Some(HealthStatus::Healthy));
        assert_eq!(info.labels["weglarka.generation"], "3");
    }

    #[test]
    fn inspect_exited_container_with_null_labels_and_no_health() {
        let info = decode::<InspectContainer>(fixture!("inspect_container_exited.json"))
            .unwrap()
            .into_domain();
        assert_eq!(info.name, "job");
        assert_eq!(info.state, ContainerState::Exited);
        assert_eq!(info.exit_code, Some(137));
        assert_eq!(info.health, None);
        assert!(info.labels.is_empty());

        let info = decode::<InspectContainer>(fixture!("inspect_container_nohealth.json"))
            .unwrap()
            .into_domain();
        assert_eq!(info.state, ContainerState::Created);
        assert_eq!(info.health, None, "pusty status = obraz bez healthchecka");
    }

    #[test]
    fn image_digest_prefers_repo_of_reference() {
        let json = fixture!("inspect_image.json");
        let ours = decode::<InspectImage>(json)
            .unwrap()
            .into_domain("ghcr.io/jpalczewski/ntfy.zig:latest");
        assert_eq!(
            ours.digest.unwrap().as_str(),
            format!("sha256:{}", "2".repeat(64))
        );
        assert_eq!(ours.repo_tags, ["ghcr.io/jpalczewski/ntfy.zig:latest"]);
        // unknown repo → the first of RepoDigests
        let other = decode::<InspectImage>(json).unwrap().into_domain("x/y:1");
        assert_eq!(
            other.digest.unwrap().as_str(),
            format!("sha256:{}", "1".repeat(64))
        );
    }

    #[test]
    fn image_digest_falls_back_to_manifest_digest() {
        let info = decode::<InspectImage>(fixture!("inspect_image_local.json"))
            .unwrap()
            .into_domain("local:1");
        assert_eq!(
            info.digest.unwrap().as_str(),
            format!("sha256:{}", "3".repeat(64))
        );
        assert!(info.repo_tags.is_empty());
    }

    #[test]
    fn reference_repo_strips_tag_and_digest_but_not_registry_port() {
        assert_eq!(reference_repo("ghcr.io/x/y:latest"), "ghcr.io/x/y");
        assert_eq!(reference_repo("ghcr.io/x/y@sha256:ab"), "ghcr.io/x/y");
        assert_eq!(reference_repo("localhost:5000/y"), "localhost:5000/y");
        assert_eq!(reference_repo("localhost:5000/y:1"), "localhost:5000/y");
    }

    #[test]
    fn pull_lines_classify() {
        let lines: Vec<_> = String::from_utf8_lossy(fixture!("pull_ok.ndjson"))
            .lines()
            .map(|l| {
                decode::<PullReport>(l.as_bytes())
                    .unwrap()
                    .classify()
                    .unwrap()
            })
            .collect();
        assert!(
            matches!(&lines[0], PullLine::Progress(PullEvent::Progress { message }) if message.starts_with("Trying"))
        );
        assert!(matches!(lines[2], PullLine::Nothing));
        assert!(matches!(&lines[3], PullLine::Image(id) if id.starts_with("9b8a")));

        let err = String::from_utf8_lossy(fixture!("pull_error.ndjson"))
            .lines()
            .map(|l| decode::<PullReport>(l.as_bytes()).unwrap().classify())
            .find_map(|r| r.err())
            .unwrap();
        assert!(matches!(err, PodmanError::Pull(m) if m.contains("unauthorized")));
    }

    #[test]
    fn events_decode_with_fallbacks() {
        let events: Vec<_> = String::from_utf8_lossy(fixture!("events.ndjson"))
            .lines()
            .map(|l| decode::<WireEvent>(l.as_bytes()).unwrap().into_domain())
            .collect();
        assert_eq!(events[0].kind, EventKind::Container);
        assert_eq!(events[0].action, "start");
        assert_eq!(events[0].name, "app-1");
        assert_eq!(events[0].attributes["weglarka.instance"], "ntfy");
        assert_eq!(events[1].attributes["health_status"], "healthy");
        assert_eq!(events[2].kind, EventKind::Other);
        assert_eq!(
            (events[3].action.as_str(), events[3].id.as_str()),
            ("die", "zz")
        );
    }

    #[test]
    fn subuid_pool_sums_the_subuid_lines_but_not_the_user_itself() {
        let info: Info = decode(
            br#"{"host":{"idMappings":{"uidmap":[
                {"container_id":0,"host_id":1001,"size":1},
                {"container_id":1,"host_id":1000000,"size":1000000}
            ],"gidmap":[]},"other":1},"version":{}}"#,
        )
        .unwrap();
        assert_eq!(info.subuid_pool(), 1_000_000);
        // Rootful or unknown layout: no pool rather than a guess.
        assert_eq!(decode::<Info>(b"{}").unwrap().subuid_pool(), 0);
    }

    #[test]
    fn decode_error_is_protocol() {
        let err = decode::<Version>(b"<html>").err().unwrap();
        assert!(matches!(err, PodmanError::Protocol(_)));
    }

    #[test]
    fn create_container_body_snapshot() {
        let spec = ContainerSpec {
            name: "ntfy-1".into(),
            image: "ghcr.io/jpalczewski/ntfy.zig@sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
            labels: BTreeMap::from([("weglarka.instance".into(), "ntfy".into())]),
            env: BTreeMap::from([("CONFIG_FILE".into(), "/config.json".into())]),
            networks: vec!["net-ntfy".into()],
            secrets: vec![
                SecretAttachment {
                    secret: "ntfy-config".into(),
                    target: SecretTarget::Mount { path: "/config.json".into(), mode: Some(0o440) },
                },
                SecretAttachment {
                    secret: "ntfy-token".into(),
                    target: SecretTarget::Env { var: "TOKEN".into() },
                },
            ],
            publish: vec![DomainPort { host_ip: Some("172.17.0.1".into()), host_port: 8085, container_port: 8085 }],
            restart: RestartPolicy::Always,
            userns_auto: true,
            mounts: vec![],
            volumes: vec![],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: None,
            security: Default::default(),
        };
        insta::assert_json_snapshot!(CreateContainer::new(&spec));
    }

    #[test]
    fn security_maps_to_libpod_fields_and_is_omitted_when_unset() {
        let mut spec = ContainerSpec {
            name: "a".into(),
            image: "i".into(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::No,
            userns_auto: false,
            mounts: vec![],
            volumes: vec![],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: None,
            security: Default::default(),
        };
        let plain = serde_json::to_value(CreateContainer::new(&spec)).unwrap();
        for key in [
            "read_only_filesystem",
            "read_write_tmpfs",
            "cap_drop",
            "cap_add",
            "no_new_privileges",
            "mounts",
        ] {
            assert!(plain.get(key).is_none(), "{key} omitted when unset");
        }
        spec.security = weglarka_core::app::Security {
            read_only: true,
            tmpfs: vec!["/cache".into()],
            cap_drop: vec!["ALL".into()],
            cap_add: vec!["NET_BIND_SERVICE".into()],
            no_new_privileges: true,
        };
        let v = serde_json::to_value(CreateContainer::new(&spec)).unwrap();
        assert_eq!(v["read_only_filesystem"], true);
        assert_eq!(v["read_write_tmpfs"], true);
        assert_eq!(v["cap_drop"], serde_json::json!(["ALL"]));
        assert_eq!(v["cap_add"], serde_json::json!(["NET_BIND_SERVICE"]));
        assert_eq!(v["no_new_privileges"], true);
        assert_eq!(v["mounts"][0]["type"], "tmpfs");
        assert_eq!(v["mounts"][0]["destination"], "/cache");
    }

    #[test]
    fn mounted_secret_without_mode_is_world_readable_not_000() {
        let spec = ContainerSpec {
            name: "a".into(),
            image: "i".into(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![SecretAttachment {
                secret: "a.config".into(),
                target: SecretTarget::Mount {
                    path: "/config.json".into(),
                    mode: None,
                },
            }],
            publish: vec![],
            restart: RestartPolicy::No,
            userns_auto: false,
            mounts: vec![],
            volumes: vec![],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: None,
            security: Default::default(),
        };
        let body = serde_json::to_value(CreateContainer::new(&spec)).unwrap();
        assert_eq!(body["secrets"][0]["Mode"], 0o444);
    }

    #[test]
    fn create_container_volumes_and_explicit_id_mapping() {
        use weglarka_core::podman::{IdMapping, VolumeAttachment};
        let range = IdRange {
            container_id: 0,
            host_id: 65_537,
            size: 65_536,
        };
        let spec = ContainerSpec {
            name: "pogoda".into(),
            image: "i".into(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::Always,
            userns_auto: true,
            mounts: vec![],
            volumes: vec![
                VolumeAttachment {
                    volume: "pogoda.data".into(),
                    target: "/data".into(),
                    read_only: false,
                },
                VolumeAttachment {
                    volume: "pogoda.cfg".into(),
                    target: "/cfg".into(),
                    read_only: true,
                },
            ],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: Some(IdMapping {
                uid_map: vec![range],
                gid_map: vec![range],
            }),
            security: Default::default(),
        };
        insta::assert_json_snapshot!(CreateContainer::new(&spec));
    }

    #[test]
    fn create_container_limits_and_healthcheck() {
        use weglarka_core::app::{CpuLimit, MemoryLimit};
        use weglarka_core::podman::ContainerHealthcheck;
        let spec = ContainerSpec {
            name: "a".into(),
            image: "i".into(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::No,
            userns_auto: false,
            mounts: vec![],
            volumes: vec![],
            resources: Resources {
                memory: Some(MemoryLimit::parse("256m").unwrap()),
                pids_limit: Some(200),
                cpus: Some(CpuLimit::try_from(1.5).unwrap()),
            },
            healthcheck: Some(ContainerHealthcheck {
                command: vec!["/app".into(), "-health".into()],
                interval_secs: 30,
                timeout_secs: 5,
                retries: 3,
            }),
            id_mapping: None,
            security: Default::default(),
        };
        insta::assert_json_snapshot!(CreateContainer::new(&spec));
    }

    #[test]
    fn partial_limits_send_only_what_is_set() {
        use weglarka_core::app::MemoryLimit;
        let r = Resources {
            memory: Some(MemoryLimit::parse("1g").unwrap()),
            ..Default::default()
        };
        let v = serde_json::to_value(ResourceLimits::from_spec(&r).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"memory": {"limit": 1u64 << 30}}));
        assert!(ResourceLimits::from_spec(&Resources::default()).is_none());
    }

    #[test]
    fn create_container_minimal_omits_empty_fields() {
        let spec = ContainerSpec {
            name: "a".into(),
            image: "i".into(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::No,
            userns_auto: false,
            mounts: vec![],
            volumes: vec![],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: None,
            security: Default::default(),
        };
        insta::assert_json_snapshot!(CreateContainer::new(&spec));
    }
}
