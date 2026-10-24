//! App model: `AppSpec` (an instance's desired state) and helper types.
//! On-disk format: `[apps.<instance>]` sections in `apps.toml` (sole writer: the daemon).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Instance name (key in `apps.toml`). Instance ≠ image: one image can have many instances.
/// Allowed `[a-z0-9-]`, 1–63 chars, no leading/trailing hyphen (safe as a container, network and
/// DNS host name, and as a component of a secret name).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InstanceName(String);

#[derive(Debug, thiserror::Error)]
#[error("invalid instance name {0:?}: expected 1-63 chars of [a-z0-9-], no leading/trailing '-'")]
pub struct InvalidInstanceName(pub String);

impl InstanceName {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidInstanceName> {
        let name = name.into();
        let ok = (1..=63).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-');
        if ok {
            Ok(Self(name))
        } else {
            Err(InvalidInstanceName(name))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for InstanceName {
    type Error = InvalidInstanceName;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<InstanceName> for String {
    fn from(value: InstanceName) -> Self {
        value.0
    }
}

impl fmt::Display for InstanceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Image digest in the form `sha256:<64 hex>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

#[derive(Debug, thiserror::Error)]
#[error("invalid digest {0:?}: expected sha256:<64 hex>")]
pub struct InvalidDigest(pub String);

impl Digest {
    pub fn new(digest: impl Into<String>) -> Result<Self, InvalidDigest> {
        let digest = digest.into();
        match digest.strip_prefix("sha256:") {
            Some(hex) if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Ok(Self(digest))
            }
            _ => Err(InvalidDigest(digest)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Digest {
    type Error = InvalidDigest;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a secret reaches the container (Podman secrets of type `env` or `mount`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretTarget {
    /// Environment variable with the given name.
    Env { var: String },
    /// File in the container (e.g. `config.json`).
    Mount {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
    },
}

/// Binding of a secret (name in `SecretStore`, scope: instance) to a container.
/// No `deny_unknown_fields` at this level (serde does not combine it with `flatten`); typos are
/// caught by `deny_unknown_fields` on [`SecretTarget`], which receives the remaining fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBinding {
    pub secret: String,
    #[serde(flatten)]
    pub target: SecretTarget,
}

/// Daemon-side HTTP probe (iteration 2): for `scratch` images without curl/wget. The daemon requests
/// `GET path` through the ingress nginx (the same route as real traffic), so no extra network is needed.
/// Owner: session 2 (`weglarka-daemon/src/health_probe.rs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProbe {
    /// Request path, starts with `/`.
    #[serde(default = "HttpProbe::default_path")]
    pub path: String,
    /// Status that counts as healthy.
    #[serde(default = "HttpProbe::default_expect_status")]
    pub expect_status: u16,
    /// Per-request timeout.
    #[serde(default = "HttpProbe::default_timeout_secs")]
    pub timeout_secs: u64,
}

impl HttpProbe {
    fn default_path() -> String {
        "/".to_owned()
    }
    fn default_expect_status() -> u16 {
        200
    }
    fn default_timeout_secs() -> u64 {
        5
    }
}

impl Default for HttpProbe {
    fn default() -> Self {
        Self {
            path: Self::default_path(),
            expect_status: Self::default_expect_status(),
            timeout_secs: Self::default_timeout_secs(),
        }
    }
}

/// Post-deploy health gate: the new container must be running (and healthy, if it has a
/// healthcheck) — up to `attempts` tries within `window_secs`; otherwise rollback.
///
/// Probes (iteration 2): `command` is a container healthcheck (overrides the image's `HEALTHCHECK`,
/// run by `healthcheck run`); `http` is a probe the daemon makes through the ingress. **Both may be set
/// and the gate passes only when every configured probe passes.** With neither set the behaviour is
/// the pre-iteration-2 one (the image's own healthcheck, if any).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthGate {
    #[serde(default = "HealthGate::default_attempts")]
    pub attempts: u32,
    #[serde(default = "HealthGate::default_window_secs")]
    pub window_secs: u64,
    /// Container healthcheck command (`["CMD", ...]` is implied; exec form, no shell).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Daemon-side HTTP probe; requires `port` in the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpProbe>,
}

impl HealthGate {
    fn default_attempts() -> u32 {
        5
    }
    fn default_window_secs() -> u64 {
        30
    }
}

impl Default for HealthGate {
    fn default() -> Self {
        Self {
            attempts: Self::default_attempts(),
            window_secs: Self::default_window_secs(),
            command: None,
            http: None,
        }
    }
}

/// Named Podman volume mounted into the app container. The Podman volume is called
/// `<instance>.<name>` ([`crate::labels::volume_name`]) and carries the `weglarka.instance` label.
/// `apps remove` keeps volumes unless purged explicitly. Owner: session 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeMount {
    /// Volume name within the instance (`[a-z0-9-]`, 1–63 chars).
    pub name: String,
    /// Absolute path in the container.
    pub target: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
}

/// Volume name within an instance: `[a-z0-9-]`, 1–63 chars, no leading/trailing hyphen.
pub fn valid_volume_name(name: &str) -> bool {
    InstanceName::new(name).is_ok()
}

/// Mount target in the container: an absolute path without `.`/`..` segments, `:` or `,`
/// (the separator of libpod's volume syntax). Shared by instance volumes and shared volumes.
pub fn valid_mount_target(target: &str) -> bool {
    target.starts_with('/')
        && target.len() > 1
        && !target.split('/').any(|s| s == "." || s == "..")
        && !target
            .chars()
            .any(|c| c.is_control() || c == ',' || c == ':')
}

/// Host file or directory mounted **read-only** into the app container from the host's
/// `config_root` (issue #118, `docs/decisions/0026-config-root-mounts.md`). `source` is always
/// relative to the root, and there is no `read_only` flag to get wrong: configs are configuration.
/// The list — not the content — is part of the spec hash, so mounting something else recreates the
/// container while editing a file does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigMount {
    /// Path under `config_root`, e.g. `prometheus/prometheus.yml`; relative, no `.`/`..` segments.
    pub source: String,
    /// Absolute path in the container.
    pub target: String,
}

/// Config source rules, lexical only (`state::validate_app` runs on every load/save and must not do
/// I/O): a non-empty relative path without `.`/`..` segments or control characters. The filesystem
/// rules (symlinks, containment in `config_root`) live in [`crate::config_mounts`].
pub fn valid_config_source(source: &str) -> bool {
    !source.is_empty()
        && !source.starts_with('/')
        && !source.split('/').any(|s| s == "." || s == "..")
        && !source.chars().any(char::is_control)
}

/// Normalizes `reload_signal` to the name the engine sends to the container: trimmed, upper case,
/// without the `SIG` prefix (`"sighup"` → `Some("HUP")`). A valid name is 2–10 characters of
/// `[A-Z][A-Z0-9]*`; anything else is rejected instead of forwarded to libpod.
pub fn normalize_signal(raw: &str) -> Option<String> {
    let upper = raw.trim().to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    let first = name.as_bytes().first().is_some_and(u8::is_ascii_uppercase);
    let valid = first
        && (2..=10).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    valid.then(|| name.to_owned())
}

/// Name of a shared volume (key in `apps.toml`'s `[shared_volumes]` section). Same character set
/// as [`InstanceName`], so it is also safe as a component of the Podman volume name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SharedVolumeName(String);

#[derive(Debug, thiserror::Error)]
#[error(
    "invalid shared volume name {0:?}: expected 1-63 chars of [a-z0-9-], no leading/trailing '-'"
)]
pub struct InvalidSharedVolumeName(pub String);

impl SharedVolumeName {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidSharedVolumeName> {
        let name = name.into();
        let ok = (1..=63).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-');
        if ok {
            Ok(Self(name))
        } else {
            Err(InvalidSharedVolumeName(name))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SharedVolumeName {
    type Error = InvalidSharedVolumeName;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SharedVolumeName> for String {
    fn from(value: SharedVolumeName) -> Self {
        value.0
    }
}

impl fmt::Display for SharedVolumeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Declaration of a volume shared between instances (issue #33,
/// `docs/decisions/0017-shared-volumes.md`). It has no options yet: the declaration itself is the
/// guard against typos in `AppSpec::shared_volumes` (an undeclared name is rejected) and the place
/// where per-volume options (backups, range size) will live. Strict, like every persisted type.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVolumeSpec {}

/// Mount of a declared shared volume in one instance's container. At most one per app in v1: a
/// shared volume is a uid/gid-range boundary (all members run in its range).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVolumeRef {
    pub name: SharedVolumeName,
    /// Absolute path in the container.
    pub target: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
}

/// A container port published directly on the host, next to the ingress (issue #34). Such ports
/// bypass nginx/Traefik completely: no TLS, no routing by domain, no access log — the host firewall
/// is the only gate, so the default bind address is loopback
/// ([`HostPort::DEFAULT_IP`], `docs/decisions/0013-host-ports.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPort {
    /// Port on the host (rootless Podman cannot bind below 1024 without a host sysctl).
    pub host: u16,
    /// Container port the host port is forwarded to.
    pub container: u16,
    /// Host address to bind; omitted means loopback. Public exposure has to be explicit,
    /// e.g. `ip = "0.0.0.0"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

impl HostPort {
    /// Address bound when the spec names none: loopback, so publishing is opt-in.
    pub const DEFAULT_IP: &'static str = "127.0.0.1";

    /// Effective bind address: the spec's `ip`, or loopback when unset.
    pub fn bind_ip(&self) -> &str {
        self.ip.as_deref().unwrap_or(Self::DEFAULT_IP)
    }
}

/// Memory limit in bytes. TOML accepts an integer (bytes) or a string with a binary suffix
/// (`"256m"`, `"1g"`); serialized in the largest exact unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MemoryRepr", into = "String")]
pub struct MemoryLimit(u64);

#[derive(Deserialize)]
#[serde(untagged)]
enum MemoryRepr {
    Bytes(u64),
    Text(String),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid memory limit {0:?}: expected bytes or <n>[k|m|g], > 0")]
pub struct InvalidMemoryLimit(pub String);

impl MemoryLimit {
    pub fn from_bytes(bytes: u64) -> Result<Self, InvalidMemoryLimit> {
        if bytes == 0 {
            Err(InvalidMemoryLimit("0".into()))
        } else {
            Ok(Self(bytes))
        }
    }

    pub fn bytes(self) -> u64 {
        self.0
    }

    pub fn parse(text: &str) -> Result<Self, InvalidMemoryLimit> {
        let err = || InvalidMemoryLimit(text.to_owned());
        let lower = text.trim().to_ascii_lowercase();
        let (digits, shift) = match lower.chars().last() {
            Some('k') => (&lower[..lower.len() - 1], 10),
            Some('m') => (&lower[..lower.len() - 1], 20),
            Some('g') => (&lower[..lower.len() - 1], 30),
            _ => (lower.as_str(), 0),
        };
        let n: u64 = digits.parse().map_err(|_| err())?;
        Self::from_bytes(n.checked_mul(1 << shift).ok_or_else(err)?).map_err(|_| err())
    }
}

impl TryFrom<MemoryRepr> for MemoryLimit {
    type Error = InvalidMemoryLimit;
    fn try_from(value: MemoryRepr) -> Result<Self, Self::Error> {
        match value {
            MemoryRepr::Bytes(b) => Self::from_bytes(b),
            MemoryRepr::Text(t) => Self::parse(&t),
        }
    }
}

impl From<MemoryLimit> for String {
    fn from(value: MemoryLimit) -> Self {
        let b = value.0;
        for (shift, suffix) in [(30, "g"), (20, "m"), (10, "k")] {
            if b.is_multiple_of(1 << shift) {
                return format!("{}{suffix}", b >> shift);
            }
        }
        b.to_string()
    }
}

/// CPU limit in thousandths of a CPU (`cpus = 1.5` → 1500). TOML accepts a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct CpuLimit(u32);

#[derive(Debug, thiserror::Error)]
#[error("invalid cpu limit {0}: expected a number in (0, 1024]")]
pub struct InvalidCpuLimit(pub f64);

impl CpuLimit {
    pub fn millis(self) -> u32 {
        self.0
    }
}

impl TryFrom<f64> for CpuLimit {
    type Error = InvalidCpuLimit;
    fn try_from(value: f64) -> Result<Self, Self::Error> {
        let millis = (value * 1000.0).round();
        if value.is_finite() && (1.0..=1_024_000.0).contains(&millis) {
            // Range-checked above.
            Ok(Self(millis as u32))
        } else {
            Err(InvalidCpuLimit(value))
        }
    }
}

impl From<CpuLimit> for f64 {
    fn from(value: CpuLimit) -> Self {
        f64::from(value.0) / 1000.0
    }
}

/// Container hardening, opt-in per app (nothing is applied by default, so existing apps keep their
/// behaviour). Part of the spec hash only when something is set. Comparable to what Coolify applied
/// to hardened services (`read_only`, `cap_drop: [ALL]`, `no-new-privileges`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    /// Read-only root filesystem. Podman then mounts writable tmpfs on `/tmp`, `/var/tmp` and
    /// `/run`; volumes and mounted secrets stay as declared.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    /// Extra writable tmpfs mounts (absolute paths), e.g. a cache directory under a read-only root.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tmpfs: Vec<String>,
    /// Capabilities to drop; `ALL` drops every capability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_drop: Vec<String>,
    /// Capabilities to add back after `cap_drop` (e.g. `NET_BIND_SERVICE` to listen below 1024).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_add: Vec<String>,
    /// `no-new-privileges`: setuid binaries and file capabilities cannot raise privileges.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_new_privileges: bool,
}

impl Security {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Capability name as accepted in the spec: `ALL` or `[A-Z_]+`, optionally with the `CAP_` prefix.
pub fn valid_capability(cap: &str) -> bool {
    !cap.is_empty() && cap.len() <= 64 && cap.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
}

/// Per-app resource limits. **No limit by default**: every field is `None` unless set in the spec.
/// Part of the spec hash only when something is set. Owner: session 2 (`weglarka-core/src/limits.rs`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<CpuLimit>,
}

impl Resources {
    pub fn is_unlimited(&self) -> bool {
        *self == Self::default()
    }
}

/// Per-app ingress behaviour (issue #64): settings that only change the generated nginx config and
/// never the container. Ingress-only by construction — [`crate::hash::HashInput`] does not include
/// them, so a change reloads nginx (`nginx -t` + `SIGHUP`) and never recreates the container, exactly
/// like `domains`. The nested table leaves room for further routing knobs without touching `AppSpec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppIngress {
    /// Streaming responses (SSE, chunked JSON, long polling): nginx stops buffering the response and
    /// the request body and waits `stream_timeout_secs` for the upstream instead of 60 s. Opt-in per
    /// app, because buffering is the right default for an ordinary HTTP app.
    #[serde(default)]
    pub streaming: bool,
    /// Idle timeout of a streaming app (`proxy_read_timeout`/`proxy_send_timeout`), in seconds.
    /// Rejected by validation unless `streaming = true`; the default comfortably covers SSE with
    /// keepalives every 45 s.
    #[serde(
        default = "default_stream_timeout_secs",
        skip_serializing_if = "AppIngress::is_default_stream_timeout"
    )]
    pub stream_timeout_secs: u64,
}

impl Default for AppIngress {
    fn default() -> Self {
        Self {
            streaming: false,
            stream_timeout_secs: Self::DEFAULT_STREAM_TIMEOUT_SECS,
        }
    }
}

impl AppIngress {
    /// Default idle timeout of a streaming app (nginx's own default of 60 s is too short for SSE).
    pub const DEFAULT_STREAM_TIMEOUT_SECS: u64 = 180;
    /// Upper bound: a stream idle for longer than an hour is a bug, not a slow producer.
    pub const MAX_STREAM_TIMEOUT_SECS: u64 = 3600;

    /// True when the app sets nothing, so `AppSpec` omits the whole `ingress` table.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Serde helper: the default timeout is omitted, so `streaming = true` alone is a complete spec.
    pub fn is_default_stream_timeout(value: &u64) -> bool {
        *value == Self::DEFAULT_STREAM_TIMEOUT_SECS
    }
}

fn default_stream_timeout_secs() -> u64 {
    AppIngress::DEFAULT_STREAM_TIMEOUT_SECS
}

/// Desired state of a single instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSpec {
    /// Image reference (floating tag, e.g. `ghcr.io/jpalczewski/ntfy.zig:latest`).
    /// State pins the resolved digest; see [`crate::state::AppState`].
    pub image: String,
    /// Arguments to the image's entrypoint (`Cmd` in the OCI spec), exec form — no shell and no
    /// quoting, every element is one argument. Empty keeps the image's own `CMD`; this never
    /// overrides the entrypoint. Images that define only an `ENTRYPOINT` and expect the subcommand as
    /// an argument need it (e.g. `command = ["serve"]` for ntfy, issue #79). Unlike `health.command`
    /// it configures the container's main process, not a probe. Part of the spec hash when set, so a
    /// change recreates the container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Domains routed to the app (ingress generators).
    #[serde(default)]
    pub domains: Vec<String>,
    /// HTTP port in the container that ingress proxies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Ingress behaviour of this app; omitted while it is the default. Not part of the spec hash, so
    /// changing it only re-renders the ingress.
    #[serde(default, skip_serializing_if = "AppIngress::is_default")]
    pub ingress: AppIngress,
    /// Plain environment variables (no secret values).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Vec<SecretBinding>,
    #[serde(default)]
    pub health: HealthGate,
    /// Named volumes (iteration 2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeMount>,
    /// Mounts of shared volumes declared in `AppsFile::shared_volumes` (issue #33,
    /// `docs/decisions/0017-shared-volumes.md`). Not part of the instance's own data: the container
    /// runs in the shared volume's uid range, and at most one is allowed per app.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_volumes: Vec<SharedVolumeRef>,
    /// Ports published directly on the host (issue #34); the ingress keeps routing `domains`/`port`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_ports: Vec<HostPort>,
    /// Apps that must already be running (and healthy) before this one starts (issue #35,
    /// `docs/decisions/0016-depends-on.md`). This is a **start order** only: reconcile starts the
    /// dependencies first and the deploy gate waits for them; it implies no network connectivity.
    /// Not part of the spec hash — editing it never recreates a container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<InstanceName>,
    /// Resource limits (iteration 2); all unlimited by default.
    #[serde(default, skip_serializing_if = "Resources::is_unlimited")]
    pub resources: Resources,
    /// Container hardening; nothing is set by default.
    #[serde(default, skip_serializing_if = "Security::is_default")]
    pub security: Security,
    /// `false` — webhook/reconcile does not swap the image on its own.
    #[serde(default = "default_true")]
    pub auto_update: bool,
    /// `false` — the instance is only **provisioned** (image digest pinned, network, uid range and
    /// volumes ready) and no container exists; `apps start` (or `start = true`) brings it up.
    /// Not part of the spec hash: flipping it neither recreates nor pulls anything by itself.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub start: bool,
    /// Host config files/directories mounted read-only from `config_root` (issue #118,
    /// `docs/decisions/0026-config-root-mounts.md`). The list — not the content — is part of the spec
    /// hash: mounting something else recreates the container, editing a file does not.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<ConfigMount>,
    /// Signal `apps reload` sends to the container (e.g. `SIGHUP`); omitted = restart instead. Not
    /// part of the spec hash: it only affects reload, never what the container is made of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_signal: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Serde helper: omits `start` while it is `true` (the default), so existing `apps.toml` files and
/// snapshots keep their shape.
fn is_true(value: &bool) -> bool {
    *value
}

/// Contents of `apps.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppsFile {
    /// On-disk schema version (issue #98, `docs/decisions/0023-state-schema-version.md`). `None` is
    /// the implicit v1 — the shape written before versioning, still the current one, so v1 files
    /// stay byte-for-byte unchanged. Written only once the schema moves past v1; serialized first
    /// because TOML wants values before tables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    /// Volumes shared between instances (issue #33, `docs/decisions/0017-shared-volumes.md`),
    /// declared once here and mounted by apps through [`AppSpec::shared_volumes`]. Serialized
    /// before `apps` so the TOML file keeps its top-level tables first.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shared_volumes: BTreeMap<SharedVolumeName, SharedVolumeSpec>,
    #[serde(default)]
    pub apps: BTreeMap<InstanceName, AppSpec>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_name_validation() {
        assert!(InstanceName::new("ntfy-zig").is_ok());
        for bad in ["", "-a", "a-", "A", "a_b", "a.b", &"x".repeat(64)] {
            assert!(InstanceName::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn iteration2_fields_parse_and_roundtrip() {
        let toml_src = r#"
[apps.pogoda]
image = "ghcr.io/x/pogoda:latest"
port = 3000
volumes = [{ name = "data", target = "/data" }, { name = "cfg", target = "/cfg", read_only = true }]
resources = { memory = "256m", pids_limit = 200, cpus = 1.5 }
health = { command = ["/app", "-health"], http = { path = "/healthz" } }
"#;
        let parsed: AppsFile = toml::from_str(toml_src).unwrap();
        insta::assert_json_snapshot!(parsed);
        let again: AppsFile = toml::from_str(&toml::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(parsed, again);
    }

    #[test]
    fn old_specs_stay_unlimited_and_serialize_without_new_fields() {
        let spec: AppSpec = toml::from_str("image = \"x:1\"\n").unwrap();
        assert!(
            spec.resources.is_unlimited()
                && spec.volumes.is_empty()
                && spec.host_ports.is_empty()
                && spec.depends_on.is_empty()
        );
        let text = toml::to_string(&spec).unwrap();
        assert!(
            !text.contains("volumes")
                && !text.contains("resources")
                && !text.contains("command")
                && !text.contains("ingress")
                && !text.contains("host_ports")
                && !text.contains("depends_on"),
            "{text}"
        );
    }

    #[test]
    fn command_parses_and_roundtrips() {
        let toml_src = r#"
[apps.ntfy]
image = "docker.io/binwiederhier/ntfy:latest"
command = ["serve"]
"#;
        let parsed: AppsFile = toml::from_str(toml_src).unwrap();
        let ntfy = &parsed.apps[&InstanceName::new("ntfy").unwrap()];
        assert_eq!(ntfy.command, ["serve"]);
        let text = toml::to_string(&parsed).unwrap();
        assert_eq!(text.matches("command").count(), 1, "{text}");
        assert_eq!(toml::from_str::<AppsFile>(&text).unwrap(), parsed);

        // An empty command is the image's own CMD, so it stays out of the file like an omitted field.
        let plain: AppsFile = toml::from_str("[apps.a]\nimage = \"i\"\n").unwrap();
        assert!(plain.apps.values().next().unwrap().command.is_empty());
        assert!(!toml::to_string(&plain).unwrap().contains("command"));
    }

    #[test]
    fn depends_on_roundtrip_and_defaults_to_empty() {
        let toml_src = r#"
[apps.api]
image = "ghcr.io/x/api:latest"
depends_on = ["db", "cache"]

[apps.db]
image = "ghcr.io/x/db:latest"
"#;
        let parsed: AppsFile = toml::from_str(toml_src).unwrap();
        insta::assert_json_snapshot!(parsed);
        let api = &parsed.apps[&InstanceName::new("api").unwrap()];
        assert_eq!(
            api.depends_on,
            vec![
                InstanceName::new("db").unwrap(),
                InstanceName::new("cache").unwrap()
            ]
        );
        // An empty list is not serialized, so an app without dependencies keeps its shape.
        let text = toml::to_string(&parsed).unwrap();
        assert_eq!(text.matches("depends_on").count(), 1, "{text}");
        let again: AppsFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed, again);
        // The strong name type rejects typos at parse time, before any validation runs.
        let bad = "[apps.a]\nimage = \"i\"\ndepends_on = [\"B\"]\n";
        assert!(toml::from_str::<AppsFile>(bad).is_err());
    }

    #[test]
    fn ingress_streaming_parses_and_roundtrips() {
        // Both spellings are accepted: an inline table and a `[apps.x.ingress]` table.
        let inline: AppsFile = toml::from_str(
            r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["nz.example.eu"]
port = 8085
ingress = { streaming = true }
"#,
        )
        .unwrap();
        let spec = &inline.apps[&InstanceName::new("ntfy").unwrap()];
        assert!(spec.ingress.streaming);
        assert_eq!(
            spec.ingress.stream_timeout_secs,
            AppIngress::DEFAULT_STREAM_TIMEOUT_SECS
        );

        // The default timeout stays out of the serialized form, so `streaming = true` is complete.
        let text = toml::to_string(&inline).unwrap();
        assert!(text.contains("streaming = true"), "{text}");
        assert!(!text.contains("stream_timeout_secs"), "{text}");

        // A custom timeout persists and round-trips.
        let custom: AppsFile = toml::from_str(
            r#"
[apps.a]
image = "i"

[apps.a.ingress]
streaming = true
stream_timeout_secs = 600
"#,
        )
        .unwrap();
        let text = toml::to_string(&custom).unwrap();
        assert!(text.contains("stream_timeout_secs = 600"), "{text}");
        assert_eq!(toml::from_str::<AppsFile>(&text).unwrap(), custom);

        // An app that sets nothing keeps the old shape entirely.
        let plain: AppSpec = toml::from_str("image = \"x:1\"\n").unwrap();
        assert!(plain.ingress.is_default());
        assert!(!toml::to_string(&plain).unwrap().contains("ingress"));

        // Unknown keys under `ingress` are rejected (`deny_unknown_fields`).
        let bad = "[apps.a]\nimage = \"i\"\n[apps.a.ingress]\nbogus = 1\n";
        assert!(toml::from_str::<AppsFile>(bad).is_err());
    }

    #[test]
    fn host_ports_roundtrip_and_default_to_loopback() {
        let toml_src = r#"
[apps.git]
image = "ghcr.io/x/forgejo:latest"
host_ports = [
    { host = 2222, container = 22 },
    { host = 2223, container = 22, ip = "0.0.0.0" },
]
"#;
        let parsed: AppsFile = toml::from_str(toml_src).unwrap();
        insta::assert_json_snapshot!(parsed);
        let spec = &parsed.apps[&InstanceName::new("git").unwrap()];
        assert_eq!(spec.host_ports[0].bind_ip(), HostPort::DEFAULT_IP);
        assert_eq!(spec.host_ports[1].bind_ip(), "0.0.0.0");
        // An omitted `ip` (loopback) stays omitted on the way out; explicit values round-trip.
        let text = toml::to_string(&parsed).unwrap();
        assert!(!text.contains(HostPort::DEFAULT_IP), "{text}");
        let again: AppsFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed, again);
        // Per-entry fields are strict (`deny_unknown_fields`).
        let bad =
            "[apps.a]\nimage = \"i\"\nhost_ports = [{ host = 1, container = 2, bogus = 3 }]\n";
        assert!(toml::from_str::<AppsFile>(bad).is_err());
    }

    #[test]
    fn memory_limit_forms() {
        for (src, bytes) in [
            ("256m", 256 << 20),
            ("1G", 1 << 30),
            ("64k", 64 << 10),
            ("1000", 1000),
        ] {
            assert_eq!(MemoryLimit::parse(src).unwrap().bytes(), bytes, "{src}");
        }
        for bad in [
            "",
            "0",
            "0m",
            "m",
            "1.5g",
            "-1",
            "1t",
            "99999999999999999999g",
        ] {
            assert!(MemoryLimit::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(String::from(MemoryLimit::parse("1024m").unwrap()), "1g");
        assert_eq!(String::from(MemoryLimit::from_bytes(1500).unwrap()), "1500");
    }

    #[test]
    fn cpu_limit_forms() {
        assert_eq!(CpuLimit::try_from(0.5).unwrap().millis(), 500);
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY, 2000.0] {
            assert!(CpuLimit::try_from(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn apps_file_roundtrip_and_unknown_fields() {
        let toml_src = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["nz.example.eu"]
port = 8085
env = { CONFIG_FILE = "/config.json" }
secrets = [{ secret = "config", kind = "mount", path = "/config.json" }]
"#;
        let parsed: AppsFile = toml::from_str(toml_src).unwrap();
        insta::assert_json_snapshot!(parsed);
        let again: AppsFile = toml::from_str(&toml::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(parsed, again);

        let bad = "[apps.x]\nimage = \"a\"\nbogus = 1\n";
        assert!(toml::from_str::<AppsFile>(bad).is_err());
    }

    #[test]
    fn start_defaults_to_true_is_omitted_and_false_roundtrips() {
        let plain: AppsFile = toml::from_str("[apps.a]\nimage = \"img\"\n").unwrap();
        assert!(plain.apps[&InstanceName::new("a").unwrap()].start);
        assert!(
            !toml::to_string(&plain).unwrap().contains("start"),
            "`start = true` (the default) must not be serialized"
        );

        let stopped: AppSpec = toml::from_str("image = \"img\"\nstart = false\n").unwrap();
        assert!(!stopped.start);
        let rendered = toml::to_string(&stopped).unwrap();
        assert!(rendered.contains("start = false"), "{rendered}");
        assert_eq!(toml::from_str::<AppSpec>(&rendered).unwrap(), stopped);
    }

    #[test]
    fn configs_and_reload_signal_parse_and_roundtrip() {
        let toml_src = r#"
[apps.prometheus]
image = "docker.io/prom/prometheus:latest"
configs = [
  { source = "prometheus/prometheus.yml", target = "/etc/prometheus/prometheus.yml" },
  { source = "prometheus/rules", target = "/etc/prometheus/rules" },
]
reload_signal = "SIGHUP"
"#;
        let parsed: AppsFile = toml::from_str(toml_src).unwrap();
        insta::assert_json_snapshot!(parsed);
        let roundtripped: AppsFile = toml::from_str(&toml::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(parsed, roundtripped);

        // Both fields stay out of the file while unset, so existing specs keep their shape.
        let plain: AppSpec = toml::from_str("image = \"x:1\"\n").unwrap();
        assert!(plain.configs.is_empty() && plain.reload_signal.is_none());
        let text = toml::to_string(&plain).unwrap();
        assert!(
            !text.contains("configs") && !text.contains("reload_signal"),
            "{text}"
        );

        // Per-entry fields are strict (`deny_unknown_fields`), so e.g. `read_only` is rejected.
        let bad = "[apps.a]\nimage = \"i\"\n\
                   configs = [{ source = \"a\", target = \"/a\", read_only = true }]\n";
        assert!(toml::from_str::<AppsFile>(bad).is_err());
        let bad = "[apps.a]\nimage = \"i\"\nbogus = 1\n";
        assert!(toml::from_str::<AppsFile>(bad).is_err());
    }

    #[test]
    fn config_sources_are_relative_and_inside_the_root() {
        for good in ["a", "app/config.yml", "a-b/c_d/e.f", "dir/"] {
            assert!(valid_config_source(good), "{good:?}");
        }
        for bad in [
            "",
            "/etc/shadow",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "../a",
            "a/..",
            "a\nb",
            "a\tb",
        ] {
            assert!(!valid_config_source(bad), "{bad:?}");
        }
    }

    #[test]
    fn reload_signals_are_normalized_to_the_sent_name() {
        for (raw, expected) in [
            ("SIGHUP", "HUP"),
            ("sighup", "HUP"),
            ("  HUP ", "HUP"),
            ("HUP", "HUP"),
            ("SIGUSR1", "USR1"),
            ("sigterm", "TERM"),
            ("SIGRTMIN", "RTMIN"),
        ] {
            assert_eq!(normalize_signal(raw).as_deref(), Some(expected), "{raw:?}");
        }
        for bad in [
            "",
            " ",
            "SIG",
            "H",
            "1HUP",
            "HUP4-YOU",
            "HU P",
            "TOOOOOOOOOOOLONG",
            "SIGKILL!",
            "-HUP",
            "HUP_1",
        ] {
            assert_eq!(normalize_signal(bad), None, "{bad:?}");
        }
    }
}
