//! On-disk state: `apps.toml` (desired state) and `state.toml` (runtime state).
//!
//! Both files are written only by the daemon, always atomically (tmp in the same directory + `fsync`
//! + `rename` + directory `fsync`). Reading validates the contents (`deny_unknown_fields` + invariants).
//!
//! Both carry an optional `schema_version`: a file written by a newer Węglarka is refused with a
//! clear message instead of an unknown-field parse error (`docs/decisions/0023-state-schema-version.md`).
//!
//! Decision on the two-file split: `docs/decisions/0003-state-toml.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::app::{
    AppKind, AppSpec, AppsFile, Digest, HostPort, InstanceName, SecretTarget, SharedVolumeName,
    normalize_signal, valid_config_source, valid_mount_target, valid_volume_name,
};
use crate::hash::SpecHash;
use crate::uid_range::UidRange;

/// On-disk schema version of `apps.toml` and `state.toml` (issue #98,
/// `docs/decisions/0023-state-schema-version.md`).
///
/// Bump it whenever a field of either file is added, renamed or changes meaning, and add the
/// matching entry to [`SCHEMA_STEPS`] — the assertion below refuses to compile until the two agree.
/// A daemon older than the file refuses to start with [`StateError::SchemaTooNew`] instead of
/// misreading it as a pile of unknown fields.
pub const SCHEMA_VERSION: u32 = 12;

/// Version of a file written before versioning. It stays v1 on purpose: stamping
/// `schema_version = 1` today would make a downgrade to a daemon that predates versioning fail —
/// the very rollback the marker exists to make predictable. The marker is written from the first
/// real schema bump on, i.e. once `SCHEMA_VERSION > IMPLICIT_SCHEMA_VERSION`.
const IMPLICIT_SCHEMA_VERSION: u32 = 1;

/// One schema migration: rewrites a parsed document in place, returning a reason on failure.
type SchemaStep = fn(&mut toml::Table) -> Result<(), String>;

/// v1 → v2: host config mounts (issue #118, ADR 0028). `AppSpec::configs` and
/// `AppSpec::reload_signal` are optional fields with defaults, so a v1 document needs no data
/// transformation — the version marker alone records that the file may carry them. The step is a
/// no-op on purpose: it must also accept a hand-edited v1 file that already has the new fields.
fn host_config_mounts_v2(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v2 → v3: shared volume groups (issue #129, ADR 0029). `[shared_volumes.<name>] group` is optional
/// and defaults to the volume's own name, so a v2 document needs no data transformation — the marker
/// records that the file may carry the field. A no-op that must accept a hand-edited file which
/// already has it.
fn shared_volume_groups_v3(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v3 → v4: shared networks (issue #128, ADR 0030). `[shared_networks.<name>]` and
/// `AppSpec::shared_networks` are optional and default to empty, so a v3 document needs no data
/// transformation — the marker records that the file may carry them. A no-op that must accept a
/// hand-edited file which already has them.
fn shared_networks_v4(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v4 → v5: path-prefix routing (issue #130, ADR 0031). `AppSpec::paths` and
/// `AppIngress::strip_prefix` are optional and default to empty/false, so a v4 document needs no data
/// transformation — the marker records that the file may carry them. A no-op that must accept a
/// hand-edited file which already has them.
fn path_prefix_routing_v5(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v5 → v6: per-app request body limit (ADR 0033). `AppIngress::max_body_size` is optional and
/// defaults to unset, so a v5 document needs no data transformation — the marker records that the
/// file may carry it. A no-op that must accept a hand-edited file which already has it.
fn ingress_max_body_size_v6(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v6 → v7: owner (`uid`/`gid`) of a mounted secret (issue #55, ADR 0037). Both are optional fields of
/// the existing `kind = "mount"` binding and default to unset, so a v6 document needs no data
/// transformation — the marker records that the file may carry them. A no-op that must accept a
/// hand-edited file which already has them.
fn secret_mount_ownership_v7(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v7 → v8: host mounts and groups (issue #178, ADR 0045). `AppSpec::host_mounts` and
/// `AppSpec::group_add` are optional fields that default to empty, so a v7 document needs no data transformation — the marker records that the
/// file may carry it. A no-op that must accept a hand-edited file which already has it.
fn host_mounts_v8(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v8 → v9: deploy strategy (issue #39, ADR 0046). `AppSpec::strategy` is an optional field that
/// defaults to `recreate`, so a v8 document needs no data transformation; the marker records that
/// the file may carry it. A no-op that must accept a hand-edited file which already has it.
fn deploy_strategy_v9(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v9 → v10: access-log exclusions (issue #181). `AppIngress::access_log_skip_paths` is optional and
/// defaults to empty, so a v9 document needs no data transformation — the marker records that the
/// file may carry it. A no-op that must accept a hand-edited file which already has it.
fn access_log_skip_paths_v10(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v10 → v11: streaming paths (issue #180). `AppIngress::streaming_paths` is optional and defaults to
/// empty, so a v10 document needs no data transformation — the marker records that the file may carry
/// it. A no-op that must accept a hand-edited file which already has it.
fn ingress_streaming_paths_v11(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// v11 → v12: static sites (issue #48, ADR 0049). `AppSpec::kind` is optional and defaults to
/// `container`, so a v11 document needs no data transformation — the marker records that the file may
/// carry `kind = "static"`. A no-op that must accept a hand-edited file which already has it.
fn static_sites_v12(_: &mut toml::Table) -> Result<(), String> {
    Ok(())
}

/// One step per version: `SCHEMA_STEPS[i]` upgrades `IMPLICIT_SCHEMA_VERSION + i` to the next one.
/// A step must tolerate data that was already migrated (a hand-edited file may carry the fields of
/// a newer schema without the marker).
const SCHEMA_STEPS: &[SchemaStep] = &[
    host_config_mounts_v2,
    shared_volume_groups_v3,
    shared_networks_v4,
    path_prefix_routing_v5,
    ingress_max_body_size_v6,
    secret_mount_ownership_v7,
    host_mounts_v8,
    deploy_strategy_v9,
    access_log_skip_paths_v10,
    ingress_streaming_paths_v11,
    static_sites_v12,
];

const _: () = assert!(
    SCHEMA_STEPS.len() as u32 == SCHEMA_VERSION - IMPLICIT_SCHEMA_VERSION,
    "one migration step per schema version above IMPLICIT_SCHEMA_VERSION"
);

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("i/o error on {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("cannot parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("invalid {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
    /// The file was written by a newer Węglarka. Refusing is the point: silently misreading it as
    /// unknown fields would hide why a rollback cannot start (issue #98).
    #[error(
        "{path}: schema version {found} is newer than this daemon supports ({supported}); written by \
         a newer Węglarka — roll forward to that version, or restore apps.toml and state.toml from \
         before the upgrade"
    )]
    SchemaTooNew {
        path: PathBuf,
        found: u32,
        supported: u32,
    },
}

/// Last failed deploy — a marker so webhook/reconcile do not retry the same thing endlessly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedDeploy {
    pub digest: Digest,
    pub reason: String,
}

/// State of a single instance. `previous` is retention 1, for rollback.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppState {
    /// Container generation number (increments on every recreate).
    #[serde(default)]
    pub generation: u64,
    /// Currently pinned digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Digest>,
    /// Previous (known-good) digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Digest>,
    /// Spec hash that `current` was started with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<SpecHash>,
    /// Last failed deploy (cleared after a successful one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<FailedDeploy>,
    /// Secrets the instance is waiting for (iteration 2, session 3): a deploy that cannot start
    /// because bound secrets are not set records their names here instead of failing; setting the
    /// last one triggers the deploy. Empty = not waiting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waiting_for_secrets: Vec<String>,
    /// Fixed uid/gid range of the instance (iteration 2, path (a) of docs/decisions/0009); allocated
    /// when the first container with volumes is created and kept for the instance's lifetime.
    /// `None` = the instance runs with `--userns=auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_range: Option<UidRange>,
    /// Last **effective** uid/gid range the instance's container and volumes were prepared with:
    /// its own [`Self::uid_range`] or the range of the shared volume it mounts
    /// (docs/decisions/0017). Written by `prepare_container` right before a container is created,
    /// so the range-change guard still knows the owner of the private volume data when there is no
    /// container to read the `weglarka.uid-range` label from (issue #75). It mirrors a range that
    /// is also stored here or in [`SharedVolumeState::uid_range`], so it is not part of the
    /// disjoint-ranges validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_uid_range: Option<UidRange>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFile {
    /// On-disk schema version (issue #98); `None` is the implicit v1 — see
    /// [`crate::state::SCHEMA_VERSION`] and `crates/weglarka-core/src/app.rs` (`AppsFile`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default)]
    pub apps: BTreeMap<InstanceName, AppState>,
    /// Fixed uid/gid range of the ingress nginx container (iteration 2, docs/decisions/0009): like
    /// instances, it must not stay on libpod's default map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_uid_range: Option<UidRange>,
    /// Shared volumes between instances (issue #33, docs/decisions/0017): the uid/gid range belongs
    /// to the volume, not to an instance, and members run in it. `None` until a member is deployed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shared_volumes: BTreeMap<SharedVolumeName, SharedVolumeState>,
}

/// Runtime state of one shared volume (issue #33).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedVolumeState {
    /// Fixed uid/gid range shared by every member instance; `None` until the first member is
    /// deployed or provisioned. Kept as long as the volume holds data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_range: Option<UidRange>,
}

/// Location of the state files (the daemon's single data directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    pub apps: PathBuf,
    pub state: PathBuf,
    /// Handled webhook delivery ids (issue #41, ADR 0035): bookkeeping, deliberately not versioned.
    pub deliveries: PathBuf,
}

impl StatePaths {
    pub fn in_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            apps: dir.join("apps.toml"),
            state: dir.join("state.toml"),
            deliveries: dir.join(crate::delivery::FILE_NAME),
        }
    }
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StateError + '_ {
    move |source| StateError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Atomic write: tmp in the same directory (created with `mode`) → `fsync` → `rename` → directory `fsync`.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), io::Error> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    let result = (|| {
        // `create_new` + always a fresh file: tmp never inherits foreign permissions/contents.
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn read_optional(path: &Path) -> Result<Option<String>, StateError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

fn invalid(path: &Path, reason: impl Into<String>) -> StateError {
    StateError::Invalid {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

/// `apps.toml` invariants that serde cannot express.
pub fn validate_app(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    if spec.image.is_empty() || spec.image.chars().any(char::is_whitespace) {
        return Err(format!("{name}: image must be a non-empty reference"));
    }
    if spec.port == Some(0) {
        return Err(format!("{name}: port must be non-zero"));
    }
    // The command is an exec-form argv handed to libpod verbatim: an empty element is a typo, not an
    // argument (issue #79).
    for (i, arg) in spec.command.iter().enumerate() {
        if arg.is_empty() {
            return Err(format!("{name}: command argument {i} must not be empty"));
        }
    }
    if spec.health.attempts == 0 || spec.health.window_secs == 0 {
        return Err(format!("{name}: health attempts and window must be > 0"));
    }
    for b in &spec.secrets {
        if b.secret == crate::secret_store::REGISTRY_AUTH_SECRET {
            return Err(format!(
                "{name}: secret {:?} is reserved for registry credentials and cannot be bound to the container",
                b.secret
            ));
        }
        if !crate::secret_store::valid_secret_name(&b.secret) {
            return Err(format!("{name}: invalid secret name {:?}", b.secret));
        }
        // A mounted secret's owner is a numeric id in the container's space; Podman maps it through
        // the instance's uid/gid range, which is exactly `DEFAULT_RANGE_SIZE` ids wide (ADR 0009), so
        // an id outside `0..DEFAULT_RANGE_SIZE` cannot be mapped. The bound is derived from the range
        // size on purpose: a magic 65535 would silently stop matching if the range ever changed.
        if let SecretTarget::Mount { uid, gid, .. } = &b.target {
            let range = crate::uid_range::DEFAULT_RANGE_SIZE;
            for (field, id) in [("uid", uid), ("gid", gid)] {
                if let Some(id) = id
                    && *id >= range
                {
                    return Err(format!(
                        "{name}: secret {:?}: {field} must be in 0..={} (the instance's uid/gid range is {range} ids wide, ADR 0009)",
                        b.secret,
                        range - 1
                    ));
                }
            }
        }
    }
    validate_depends_on(name, spec)?;
    validate_ingress(name, spec)?;
    validate_strategy(name, spec)?;
    validate_iteration2(name, spec)?;
    validate_static(name, spec)
}

/// A static site (ADR 0049) has no process: every field that configures one is a typo or a mistaken
/// `kind`, and silently ignoring it would hide that.
fn validate_static(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    if spec.kind != AppKind::Static {
        return Ok(());
    }
    let defaults: AppSpec = toml::from_str("image = \"i\"").expect("minimal spec parses");
    let rejected = [
        ("port", spec.port.is_some()),
        ("command", !spec.command.is_empty()),
        ("env", !spec.env.is_empty()),
        ("secrets", !spec.secrets.is_empty()),
        ("health", spec.health != defaults.health),
        ("volumes", !spec.volumes.is_empty()),
        ("shared_volumes", !spec.shared_volumes.is_empty()),
        ("shared_networks", !spec.shared_networks.is_empty()),
        ("host_ports", !spec.host_ports.is_empty()),
        ("depends_on", !spec.depends_on.is_empty()),
        ("resources", spec.resources != defaults.resources),
        ("security", spec.security != defaults.security),
        ("configs", !spec.configs.is_empty()),
        ("reload_signal", spec.reload_signal.is_some()),
        ("ingress", spec.ingress != defaults.ingress),
        ("start", !spec.start),
        ("host_mounts", !spec.host_mounts.is_empty()),
        ("group_add", !spec.group_add.is_empty()),
        ("strategy", spec.strategy != defaults.strategy),
    ];
    if let Some((field, _)) = rejected.iter().find(|(_, set)| *set) {
        return Err(format!(
            "{name}: `{field}` does not apply to kind = \"static\" (a static site has no container)"
        ));
    }
    Ok(())
}

/// `blue_green` runs two containers of the app at once, so it is only for stateless apps (ADR 0046):
/// two containers cannot bind one host port, and a read-write volume would have two writers (SQLite
/// has a single one). Read-only volumes and host config mounts are fine.
fn validate_strategy(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    if spec.strategy != crate::app::Strategy::BlueGreen {
        return Ok(());
    }
    if !spec.host_ports.is_empty() {
        return Err(format!(
            "{name}: strategy \"blue_green\" cannot be combined with host_ports (two containers cannot bind one host port)"
        ));
    }
    if spec.volumes.iter().any(|v| !v.read_only) || spec.shared_volumes.iter().any(|v| !v.read_only)
    {
        return Err(format!(
            "{name}: strategy \"blue_green\" needs a stateless app: read-write volumes (private or shared) would have two writers"
        ));
    }
    Ok(())
}

/// `depends_on` rules an app can break on its own. The cross-app rules (an unknown target, a cycle)
/// live in [`crate::depends::validate`], which needs the whole `apps.toml`.
fn validate_depends_on(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for dep in &spec.depends_on {
        if dep == name {
            return Err(format!("{name}: depends_on must not list the app itself"));
        }
        if !seen.insert(dep) {
            return Err(format!("{name}: duplicate depends_on entry \"{dep}\""));
        }
    }
    Ok(())
}

/// Ingress options are rendered into `nginx.conf` verbatim, so they are checked here rather than in the
/// generator. A timeout without `streaming` and a `strip_prefix` without a real prefix would be silent
/// no-ops, hence errors. Cross-app overlap of `paths` is the ingress plan's job (needs all apps).
fn validate_ingress(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    use crate::app::AppIngress;
    let ingress = &spec.ingress;
    if !ingress.streaming {
        if ingress.stream_timeout_secs != AppIngress::DEFAULT_STREAM_TIMEOUT_SECS {
            return Err(format!(
                "{name}: ingress.stream_timeout_secs requires ingress.streaming = true"
            ));
        }
    } else if !(1..=AppIngress::MAX_STREAM_TIMEOUT_SECS).contains(&ingress.stream_timeout_secs) {
        return Err(format!(
            "{name}: ingress.stream_timeout_secs must be 1..={} (default {})",
            AppIngress::MAX_STREAM_TIMEOUT_SECS,
            AppIngress::DEFAULT_STREAM_TIMEOUT_SECS
        ));
    }
    if !spec.paths.is_empty() && spec.domains.is_empty() {
        return Err(format!("{name}: paths requires at least one domain"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for path in &spec.paths {
        crate::app::check_path_prefix(path)
            .map_err(|reason| format!("{name}: invalid path {path:?}: {reason}"))?;
        if !seen.insert(path) {
            return Err(format!("{name}: duplicate path {path:?}"));
        }
    }
    if ingress.strip_prefix && spec.paths.iter().all(|p| p == "/") {
        return Err(format!(
            "{name}: ingress.strip_prefix requires a path other than \"/\""
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for path in &ingress.access_log_skip_paths {
        crate::app::check_skip_path(path).map_err(|reason| {
            format!("{name}: invalid ingress.access_log_skip_paths entry {path:?}: {reason}")
        })?;
        if !seen.insert(path) {
            return Err(format!(
                "{name}: duplicate ingress.access_log_skip_paths entry {path:?}"
            ));
        }
    }
    if !ingress.access_log_skip_paths.is_empty() && spec.domains.is_empty() {
        return Err(format!(
            "{name}: ingress.access_log_skip_paths requires at least one domain"
        ));
    }
    if !ingress.streaming_paths.is_empty() {
        if ingress.streaming {
            return Err(format!(
                "{name}: ingress.streaming_paths is redundant with ingress.streaming = true"
            ));
        }
        if spec.paths.iter().any(|p| p != "/") {
            return Err(format!(
                "{name}: ingress.streaming_paths cannot be combined with path prefixes in `paths`"
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for path in &ingress.streaming_paths {
            crate::app::check_path_prefix(path)
                .map_err(|reason| format!("{name}: invalid streaming path {path:?}: {reason}"))?;
            if path == "/" {
                return Err(format!(
                    "{name}: use ingress.streaming = true instead of streaming path \"/\""
                ));
            }
            if !seen.insert(path) {
                return Err(format!("{name}: duplicate streaming path {path:?}"));
            }
        }
    }
    Ok(())
}

/// Hardening values end up in the container spec verbatim, so they are checked strictly.
fn validate_security(name: &InstanceName, sec: &crate::app::Security) -> Result<(), String> {
    for cap in sec.cap_drop.iter().chain(&sec.cap_add) {
        if !crate::app::valid_capability(cap) {
            return Err(format!(
                "{name}: invalid capability {cap:?} (expected ALL or e.g. NET_BIND_SERVICE)"
            ));
        }
    }
    if sec.cap_add.iter().any(|c| c == "ALL") {
        return Err(format!("{name}: cap_add must not be ALL"));
    }
    let mut seen = BTreeSet::new();
    for path in &sec.tmpfs {
        let ok = path.starts_with('/')
            && path.len() > 1
            && !path.split('/').any(|s| s == "." || s == "..")
            && !path.chars().any(|c| c.is_control() || c == ',' || c == ':');
        if !ok {
            return Err(format!(
                "{name}: tmpfs path {path:?} must be absolute (no '..', ':' or ',')"
            ));
        }
        if !seen.insert(path.trim_end_matches('/')) {
            return Err(format!("{name}: duplicate tmpfs path {path:?}"));
        }
    }
    Ok(())
}

/// Rules for the iteration 2 fields (volumes, resources, health probes).
fn validate_iteration2(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    let mut seen_names = BTreeSet::new();
    let mut seen_targets = BTreeSet::new();
    for v in &spec.volumes {
        if !valid_volume_name(&v.name) {
            return Err(format!("{name}: invalid volume name {:?}", v.name));
        }
        if !valid_mount_target(&v.target) {
            return Err(format!(
                "{name}: volume {:?} target must be an absolute path (no '..', ':' or ',')",
                v.name
            ));
        }
        if !seen_names.insert(&v.name) {
            return Err(format!("{name}: duplicate volume name {:?}", v.name));
        }
        if !seen_targets.insert(v.target.trim_end_matches('/')) {
            return Err(format!("{name}: duplicate volume target {:?}", v.target));
        }
    }
    // Which group each volume belongs to needs the declarations, so "one group per app" is checked
    // across apps in `shared_volumes::validate`.
    let mut seen_shared = BTreeSet::new();
    for v in &spec.shared_volumes {
        if !seen_shared.insert(&v.name) {
            return Err(format!(
                "{name}: shared volume {:?} is mounted twice",
                v.name
            ));
        }
        if !valid_mount_target(&v.target) {
            return Err(format!(
                "{name}: shared volume {:?} target must be an absolute path (no '..', ':' or ',')",
                v.name
            ));
        }
        if !seen_targets.insert(v.target.trim_end_matches('/')) {
            return Err(format!("{name}: duplicate volume target {:?}", v.target));
        }
    }
    // Host config mounts (issue #118): lexical rules only. Whether the root is set and the sources
    // really stay inside it is a filesystem question answered by `crate::config_mounts::validate_host`
    // (and by `launch`/reconcile/reload, which do have the host config).
    for mount in &spec.configs {
        if !valid_config_source(&mount.source) {
            return Err(format!(
                "{name}: config source {:?} must be a relative path inside config_root (no '..')",
                mount.source
            ));
        }
        if !valid_mount_target(&mount.target) {
            return Err(format!(
                "{name}: config mount target {:?} must be an absolute path (no '..', ':' or ',')",
                mount.target
            ));
        }
        if !seen_targets.insert(mount.target.trim_end_matches('/')) {
            return Err(format!(
                "{name}: duplicate config target {:?}",
                mount.target
            ));
        }
    }
    // Host mounts (issue #178): lexical rules only; membership in the operator's allowlist is
    // checked against the host config by `crate::host_mounts` (admin API, reconcile, launch).
    for mount in &spec.host_mounts {
        if !crate::app::valid_host_source(&mount.source) {
            return Err(format!(
                "{name}: host mount source {:?} must be an absolute, normalized path",
                mount.source
            ));
        }
        if !valid_mount_target(&mount.target) {
            return Err(format!(
                "{name}: host mount target {:?} must be an absolute path (no '..', ':' or ',')",
                mount.target
            ));
        }
        if !seen_targets.insert(mount.target.trim_end_matches('/')) {
            return Err(format!(
                "{name}: duplicate host mount target {:?}",
                mount.target
            ));
        }
    }
    let mut groups = BTreeSet::new();
    for group in &spec.group_add {
        if !crate::app::valid_group_name(group) {
            return Err(format!("{name}: invalid group_add entry {group:?}"));
        }
        if !groups.insert(group) {
            return Err(format!("{name}: duplicate group_add entry {group:?}"));
        }
    }
    if let Some(signal) = &spec.reload_signal
        && normalize_signal(signal).is_none()
    {
        return Err(format!(
            "{name}: invalid reload_signal {signal:?} (expected a signal name like HUP or SIGHUP)"
        ));
    }
    validate_security(name, &spec.security)?;
    if spec.resources.pids_limit == Some(0) {
        return Err(format!(
            "{name}: pids_limit must be > 0 (omit it for no limit)"
        ));
    }
    if let Some(cmd) = &spec.health.command
        && (cmd.is_empty() || cmd[0].is_empty())
    {
        return Err(format!("{name}: health.command must not be empty"));
    }
    if let Some(http) = &spec.health.http {
        if spec.port.is_none() {
            return Err(format!("{name}: health.http requires port"));
        }
        // The probe goes through nginx, which routes by `Host` (docs/decisions/0010).
        if spec.domains.is_empty() {
            return Err(format!("{name}: health.http requires at least one domain"));
        }
        if !http.path.starts_with('/') {
            return Err(format!("{name}: health.http.path must start with '/'"));
        }
        if !(100..=599).contains(&http.expect_status) {
            return Err(format!("{name}: health.http.expect_status must be 100-599"));
        }
        if http.timeout_secs == 0 {
            return Err(format!("{name}: health.http.timeout_secs must be > 0"));
        }
    }
    validate_host_ports(name, &spec.host_ports)?;
    Ok(())
}

/// Rules an app can break on its own for ports published directly on the host. The host-dependent
/// ones (privileged ports, conflicts between apps, the ingress bind) are in
/// [`crate::host_ports::validate`], which needs `weglarka.toml`.
fn validate_host_ports(name: &InstanceName, ports: &[HostPort]) -> Result<(), String> {
    let mut seen: Vec<(u16, std::net::IpAddr)> = Vec::new();
    for entry in ports {
        if entry.host == 0 || entry.container == 0 {
            return Err(format!(
                "{name}: host_ports need non-zero host and container ports"
            ));
        }
        let bind = entry.bind_ip().parse::<std::net::IpAddr>().map_err(|_| {
            format!(
                "{name}: host_ports bind address {:?} is not an IP literal",
                entry.bind_ip()
            )
        })?;
        if seen.iter().any(|(port, other)| {
            *port == entry.host && crate::host_ports::bind_overlaps(bind, *other)
        }) {
            return Err(format!(
                "{name}: host port {} is published twice on the same address",
                entry.host
            ));
        }
        seen.push((entry.host, bind));
    }
    Ok(())
}

/// The schema version declared by the file; no marker means the implicit v1.
fn declared_schema_version(path: &Path, src: &str) -> Result<u32, StateError> {
    #[derive(Deserialize)]
    struct Header {
        #[serde(default)]
        schema_version: Option<toml::Value>,
    }
    // Deliberately tolerant (`deny_unknown_fields` off): the rest of the document is not this
    // struct's business, and a newer schema must fail on its version, not on its fields.
    let header: Header = toml::from_str(src).map_err(|e| StateError::Parse {
        path: path.to_owned(),
        message: e.to_string(),
    })?;
    match header.schema_version {
        None => Ok(IMPLICIT_SCHEMA_VERSION),
        // Any positive integer is a version; an absurdly large one saturates, so it is reported as
        // "newer than supported" rather than as a malformed field.
        Some(toml::Value::Integer(v)) if v >= i64::from(IMPLICIT_SCHEMA_VERSION) => {
            Ok(u32::try_from(v).unwrap_or(u32::MAX))
        }
        Some(toml::Value::Integer(_)) => {
            Err(invalid(path, "schema_version must be an integer >= 1"))
        }
        Some(_) => Err(invalid(path, "schema_version must be an integer")),
    }
}

/// Runs the migration steps that bring a file written by `from` up to [`SCHEMA_VERSION`] and stamps
/// the version, so the next save writes the marker. Steps transform the parsed table (they may add,
/// rename or fill nested fields); the result is deserialized directly, so a parse error here has no
/// line numbers — acceptable for a file that is migrated once.
fn migrate<T: DeserializeOwned>(path: &Path, src: &str, from: u32) -> Result<T, StateError> {
    let mut table: toml::Table = toml::from_str(src).map_err(|e| StateError::Parse {
        path: path.to_owned(),
        message: e.to_string(),
    })?;
    // In bounds: `declared_schema_version` guarantees `IMPLICIT <= from < SCHEMA_VERSION`, and the
    // assertion next to `SCHEMA_STEPS` ties the slice length to the version difference.
    for step in &SCHEMA_STEPS[(from - IMPLICIT_SCHEMA_VERSION) as usize..] {
        step(&mut table).map_err(|reason| invalid(path, format!("schema migration: {reason}")))?;
    }
    table.insert(
        "schema_version".to_owned(),
        toml::Value::Integer(SCHEMA_VERSION.into()),
    );
    toml::Value::Table(table)
        .try_into()
        .map_err(|e| StateError::Parse {
            path: path.to_owned(),
            message: e.to_string(),
        })
}

/// The shared reader: version gate first (a newer file gets a clear message, never a confusing
/// `deny_unknown_fields` error), then migration, then the strict parse of the current schema.
fn load_versioned<T: DeserializeOwned + Default>(path: &Path, src: &str) -> Result<T, StateError> {
    // An empty file means "nothing declared yet", like a missing one.
    if src.trim().is_empty() {
        return Ok(T::default());
    }
    let found = declared_schema_version(path, src)?;
    if found > SCHEMA_VERSION {
        return Err(StateError::SchemaTooNew {
            path: path.to_owned(),
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found < SCHEMA_VERSION {
        return migrate(path, src, found);
    }
    toml::from_str(src).map_err(|e| StateError::Parse {
        path: path.to_owned(),
        message: e.to_string(),
    })
}

/// Parses `apps.toml` content: the schema gate plus the invariants of [`load_apps`], without I/O —
/// `weglarka doctor --preflight` reads the file itself and must report a too-new schema instead of
/// an unknown field.
pub fn parse_apps(path: &Path, src: &str) -> Result<AppsFile, StateError> {
    let apps: AppsFile = load_versioned(path, src)?;
    for (name, spec) in &apps.apps {
        validate_app(name, spec).map_err(|r| invalid(path, r))?;
    }
    crate::depends::validate(&apps).map_err(|r| invalid(path, r))?;
    crate::shared_volumes::validate(&apps).map_err(|r| invalid(path, r))?;
    crate::shared_networks::validate(&apps).map_err(|r| invalid(path, r))?;
    Ok(apps)
}

pub fn load_apps(path: &Path) -> Result<AppsFile, StateError> {
    let Some(src) = read_optional(path)? else {
        return Ok(AppsFile::default());
    };
    parse_apps(path, &src)
}

pub fn save_apps(path: &Path, apps: &AppsFile) -> Result<(), StateError> {
    for (name, spec) in &apps.apps {
        validate_app(name, spec).map_err(|r| invalid(path, r))?;
    }
    crate::depends::validate(apps).map_err(|r| invalid(path, r))?;
    crate::shared_volumes::validate(apps).map_err(|r| invalid(path, r))?;
    crate::shared_networks::validate(apps).map_err(|r| invalid(path, r))?;
    let text = toml::to_string(apps).map_err(|e| invalid(path, e.to_string()))?;
    write_atomic(path, text.as_bytes(), 0o644).map_err(io_err(path))
}

fn validate_state(path: &Path, state: &StateFile) -> Result<(), StateError> {
    for (name, s) in &state.apps {
        if s.spec_hash.is_some() && s.current.is_none() {
            return Err(invalid(path, format!("{name}: spec_hash without current")));
        }
        if s.previous.is_some() && s.previous == s.current {
            return Err(invalid(path, format!("{name}: previous equals current")));
        }
    }
    let ingress = "ingress".to_owned();
    let ranges: Vec<_> = state
        .apps
        .iter()
        .filter_map(|(n, s)| s.uid_range.map(|r| (n.to_string(), r)))
        .chain(
            state
                .shared_volumes
                .iter()
                .filter_map(|(n, s)| s.uid_range.map(|r| (format!("shared volume {n}"), r))),
        )
        .chain(state.ingress_uid_range.map(|r| (ingress, r)))
        .collect();
    for (i, (a, ra)) in ranges.iter().enumerate() {
        if ra.start == 0 || ra.size == 0 {
            return Err(invalid(
                path,
                format!("{a}: uid_range must start at >= 1 and be non-empty"),
            ));
        }
        if let Some((b, _)) = ranges[i + 1..].iter().find(|(_, rb)| ra.overlaps(*rb)) {
            return Err(invalid(path, format!("{a} and {b}: uid ranges overlap")));
        }
    }
    Ok(())
}

/// Parses `state.toml` content: the schema gate plus [`validate_state`], without I/O.
pub fn parse_state(path: &Path, src: &str) -> Result<StateFile, StateError> {
    let state: StateFile = load_versioned(path, src)?;
    validate_state(path, &state)?;
    Ok(state)
}

pub fn load_state(path: &Path) -> Result<StateFile, StateError> {
    let Some(src) = read_optional(path)? else {
        return Ok(StateFile::default());
    };
    parse_state(path, &src)
}

pub fn save_state(path: &Path, state: &StateFile) -> Result<(), StateError> {
    validate_state(path, state)?;
    let text = toml::to_string(state).map_err(|e| invalid(path, e.to_string()))?;
    write_atomic(path, text.as_bytes(), 0o644).map_err(io_err(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn name(s: &str) -> InstanceName {
        InstanceName::new(s).unwrap()
    }

    #[test]
    fn depends_on_self_and_duplicates_are_rejected() {
        let spec = |deps: &str| -> AppSpec {
            toml::from_str(&format!("image = \"i\"\ndepends_on = [{deps}]")).unwrap()
        };
        assert!(
            validate_app(&name("a"), &spec("\"a\""))
                .unwrap_err()
                .contains("app itself")
        );
        assert!(
            validate_app(&name("a"), &spec("\"b\", \"b\""))
                .unwrap_err()
                .contains("duplicate depends_on")
        );
        assert!(validate_app(&name("a"), &spec("\"b\"")).is_ok());
    }

    #[test]
    fn command_arguments_must_not_be_empty() {
        let spec = |command: &str| -> AppSpec {
            toml::from_str(&format!("image = \"i\"\ncommand = [{command}]")).unwrap()
        };
        assert!(validate_app(&name("a"), &spec("\"serve\"")).is_ok());
        assert!(validate_app(&name("a"), &spec("\"serve\", \"-v\"")).is_ok());
        // An empty list is the image's own CMD, so it is valid like an omitted field.
        assert!(validate_app(&name("a"), &spec("")).is_ok());
        let err = validate_app(&name("a"), &spec("\"serve\", \"\"")).unwrap_err();
        assert!(err.contains("command argument 1"), "{err}");
    }

    /// Issue #55: a mounted secret's owner must fit the instance's uid/gid range (ADR 0009), because
    /// Podman maps container-space ids through it; an env binding has no owner at all.
    #[test]
    fn mounted_secret_ownership_must_fit_the_instance_range() {
        let spec = |secrets: &str| -> AppSpec {
            toml::from_str(&format!("image = \"i\"\nsecrets = [{secrets}]")).unwrap()
        };
        let mount = |extra: &str| {
            spec(&format!(
                "{{ secret = \"s\", kind = \"mount\", path = \"/run/secrets/s\"{extra} }}"
            ))
        };
        for id in [0, 1000, 65_535] {
            assert!(
                validate_app(&name("a"), &mount(&format!(", uid = {id}, gid = {id}"))).is_ok(),
                "{id}"
            );
        }
        for field in ["uid", "gid"] {
            let err = validate_app(&name("a"), &mount(&format!(", {field} = 65_536"))).unwrap_err();
            assert!(
                err.contains(&format!("{field} must be in 0..=65535")),
                "{field}: {err}"
            );
            assert!(err.contains("\"s\""), "the message names the secret: {err}");
            assert!(
                err.starts_with("a:"),
                "the message names the instance: {err}"
            );
        }
        // An env binding keeps working: it has no ownership field.
        assert!(
            validate_app(
                &name("a"),
                &spec("{ secret = \"s\", kind = \"env\", var = \"V\" }")
            )
            .is_ok()
        );
    }

    #[test]
    fn ingress_options_are_validated() {
        use crate::app::AppIngress;
        let check = |ingress: AppIngress| {
            let spec = AppSpec {
                ingress,
                ..toml::from_str("image = \"i\"").unwrap()
            };
            validate_app(&name("a"), &spec)
        };
        assert!(check(AppIngress::default()).is_ok());
        assert!(
            check(AppIngress {
                streaming: true,
                stream_timeout_secs: 1,
                strip_prefix: false,
                ..AppIngress::default()
            })
            .is_ok()
        );
        assert!(
            check(AppIngress {
                streaming: true,
                stream_timeout_secs: AppIngress::MAX_STREAM_TIMEOUT_SECS,
                strip_prefix: false,
                ..AppIngress::default()
            })
            .is_ok()
        );
        for bad in [0, AppIngress::MAX_STREAM_TIMEOUT_SECS + 1] {
            let err = check(AppIngress {
                streaming: true,
                stream_timeout_secs: bad,
                strip_prefix: false,
                ..AppIngress::default()
            })
            .unwrap_err();
            assert!(err.contains("stream_timeout_secs"), "{bad}: {err}");
        }
        // A timeout without streaming would be a silent no-op, so it is refused.
        let err = check(AppIngress {
            streaming: false,
            stream_timeout_secs: 600,
            strip_prefix: false,
            ..AppIngress::default()
        })
        .unwrap_err();
        assert!(err.contains("requires ingress.streaming = true"), "{err}");
    }

    #[test]
    fn streaming_paths_are_validated() {
        let ok = |extra: &str| -> Result<(), String> {
            let spec: AppSpec = toml::from_str(&format!(
                "image = \"i\"\ndomains = [\"a.example.com\"]\n{extra}"
            ))
            .unwrap();
            validate_app(&name("a"), &spec)
        };
        assert!(ok("ingress = { streaming_paths = [\"/user/events\", \"/a/b\"] }").is_ok());
        for (extra, needle) in [
            (
                "ingress = { streaming_paths = [\"/\"] }",
                "instead of streaming path",
            ),
            (
                "ingress = { streaming_paths = [\"x\"] }",
                "invalid streaming path",
            ),
            (
                "ingress = { streaming_paths = [\"/a\", \"/a\"] }",
                "duplicate",
            ),
            (
                "ingress = { streaming = true, streaming_paths = [\"/a\"] }",
                "redundant",
            ),
            (
                "paths = [\"/p\"]\ningress = { streaming_paths = [\"/a\"] }",
                "cannot be combined",
            ),
        ] {
            let err = ok(extra).unwrap_err();
            assert!(err.contains(needle), "{extra}: {err}");
        }
    }

    #[test]
    fn paths_and_strip_prefix_are_validated() {
        let spec = |extra: &str| -> AppSpec {
            toml::from_str(&format!(
                "image = \"i\"\ndomains = [\"a.example.com\"]\n{extra}"
            ))
            .unwrap()
        };
        let ok = |extra: &str| validate_app(&name("a"), &spec(extra));
        assert!(ok("").is_ok());
        assert!(ok("paths = [\"/\"]").is_ok());
        assert!(ok("paths = [\"/api\", \"/.well-known\", \"/a/b-c_d.e\"]").is_ok());
        assert!(ok("paths = [\"/api\"]\ningress = { strip_prefix = true }").is_ok());
        for bad in [
            "api", "/api/", "//a", "/a//b", "/a/../b", "/a/./b", "/a b", "/a%2f", "/ä", "",
        ] {
            let err = ok(&format!("paths = [{bad:?}]")).unwrap_err();
            assert!(err.contains("invalid path"), "{bad}: {err}");
        }
        let err = ok("paths = [\"/a\", \"/a\"]").unwrap_err();
        assert!(err.contains("duplicate path"), "{err}");
        // `paths` without a domain would silently route nothing.
        let no_domain: AppSpec = toml::from_str("image = \"i\"\npaths = [\"/a\"]").unwrap();
        assert!(
            validate_app(&name("a"), &no_domain)
                .unwrap_err()
                .contains("requires at least one domain")
        );
        // A strip with nothing to strip is a silent no-op.
        for extra in [
            "ingress = { strip_prefix = true }",
            "paths = [\"/\"]\ningress = { strip_prefix = true }",
        ] {
            let err = ok(extra).unwrap_err();
            assert!(err.contains("strip_prefix requires a path"), "{err}");
        }
    }

    #[test]
    fn access_log_skip_paths_are_validated() {
        let ok = |list: &str| {
            let spec: AppSpec = toml::from_str(&format!(
                "image = \"i\"\ndomains = [\"a.example.com\"]\ningress = {{ access_log_skip_paths = {list} }}"
            ))
            .unwrap();
            validate_app(&name("a"), &spec)
        };
        assert!(ok("[]").is_ok());
        assert!(ok(r#"["/healthz", "/api/poll/", "/a.b/c-d_e"]"#).is_ok());
        for bad in [
            "/", "healthz", "/a//b", "/a/../b/", "/a b", "/a;b", "/a\"b", "/ä", "//", "",
        ] {
            let err = ok(&format!("[{bad:?}]")).unwrap_err();
            assert!(err.contains("access_log_skip_paths"), "{bad}: {err}");
        }
        let err = ok(r#"["/a", "/a"]"#).unwrap_err();
        assert!(err.contains("duplicate"), "{err}");
        let no_domain: AppSpec =
            toml::from_str("image = \"i\"\ningress = { access_log_skip_paths = [\"/a\"] }")
                .unwrap();
        assert!(
            validate_app(&name("a"), &no_domain)
                .unwrap_err()
                .contains("requires at least one domain")
        );
    }

    #[test]
    fn security_values_are_validated() {
        let ok = |sec: crate::app::Security| {
            let spec = AppSpec {
                security: sec,
                ..toml::from_str("image = \"i\"").unwrap()
            };
            validate_app(&name("a"), &spec)
        };
        let sec = |f: &dyn Fn(&mut crate::app::Security)| {
            let mut s = crate::app::Security::default();
            f(&mut s);
            s
        };
        assert!(
            ok(sec(&|s| {
                s.read_only = true;
                s.tmpfs = vec!["/cache".into()];
                s.cap_drop = vec!["ALL".into()];
                s.cap_add = vec!["NET_BIND_SERVICE".into()];
                s.no_new_privileges = true;
            }))
            .is_ok()
        );
        assert!(
            ok(sec(&|s| s.cap_drop = vec!["all".into()])).is_err(),
            "upper case only"
        );
        assert!(ok(sec(&|s| s.cap_drop = vec!["NET_ADMIN,SYS".into()])).is_err());
        assert!(ok(sec(&|s| s.cap_add = vec!["ALL".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["cache".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["/a,mode=777".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["/a/../b".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["/a".into(), "/a/".into()])).is_err());
    }

    #[test]
    fn state_roundtrip_and_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::in_dir(dir.path());
        assert_eq!(load_state(&paths.state).unwrap(), StateFile::default());

        let mut st = StateFile::default();
        st.apps.insert(
            name("ntfy"),
            AppState {
                generation: 3,
                current: Some(digest('a')),
                previous: Some(digest('b')),
                spec_hash: None,
                failed: Some(FailedDeploy {
                    digest: digest('c'),
                    reason: "unhealthy".into(),
                }),
                waiting_for_secrets: vec![],
                uid_range: Some(UidRange {
                    start: 1,
                    size: 65_536,
                }),
                effective_uid_range: Some(UidRange {
                    start: 1,
                    size: 65_536,
                }),
            },
        );
        save_state(&paths.state, &st).unwrap();
        let loaded = load_state(&paths.state).unwrap();
        // The saved file has no marker (v1), so reading it runs the migration chain: the payload is
        // unchanged, only the in-memory marker is the current version (ADR 0023).
        assert_eq!(loaded.schema_version, Some(SCHEMA_VERSION));
        assert_eq!(
            StateFile {
                schema_version: None,
                ..loaded
            },
            st
        );
        insta::assert_snapshot!(fs::read_to_string(&paths.state).unwrap());
    }

    #[test]
    fn atomic_write_leaves_no_tmp_and_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.toml");
        write_atomic(&path, b"one", 0o600).unwrap();
        write_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn rejects_unknown_fields_and_broken_invariants() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.toml");
        fs::write(&p, "[apps.a]\nbogus = 1\n").unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Parse { .. })));

        let hash = "0".repeat(64);
        fs::write(&p, format!("[apps.a]\nspec_hash = \"{hash}\"\n")).unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Invalid { .. })));

        let d = digest('a');
        fs::write(
            &p,
            format!("[apps.a]\ncurrent = \"{d}\"\nprevious = \"{d}\"\n"),
        )
        .unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Invalid { .. })));

        fs::write(
            &p,
            "[apps.a]\nuid_range = { start = 1, size = 100 }\n[apps.b]\nuid_range = { start = 100, size = 100 }\n",
        )
        .unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Invalid { .. })));

        fs::write(&p, "[apps.A_b]\n").unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Parse { .. })));
    }

    #[test]
    fn iteration2_validation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        let check = |extra: &str| {
            fs::write(
                &p,
                format!(
                    "[apps.a]\nimage = \"x:1\"\nport = 80\ndomains = [\"a.example.com\"]\n{extra}\n"
                ),
            )
            .unwrap();
            load_apps(&p).is_ok()
        };
        assert!(check("volumes = [{ name = \"data\", target = \"/data\" }]"));
        assert!(check(
            "health = { http = { path = \"/up\", expect_status = 204 } }"
        ));
        assert!(check("resources = { pids_limit = 10 }"));
        for bad in [
            "volumes = [{ name = \"Data\", target = \"/data\" }]",
            "volumes = [{ name = \"d\", target = \"data\" }]",
            "volumes = [{ name = \"d\", target = \"/a/../b\" }]",
            "volumes = [{ name = \"d\", target = \"/a:ro\" }]",
            "volumes = [{ name = \"d\", target = \"/a\" }, { name = \"d\", target = \"/b\" }]",
            "volumes = [{ name = \"d\", target = \"/a\" }, { name = \"e\", target = \"/a/\" }]",
            "resources = { pids_limit = 0 }",
            "resources = { memory = \"0\" }",
            "health = { command = [] }",
            "health = { http = { path = \"up\" } }",
            "health = { http = { expect_status = 99 } }",
            "health = { http = { timeout_secs = 0 } }",
        ] {
            assert!(!check(bad), "{bad}");
        }
        // The HTTP probe needs a port and a domain to go through the ingress.
        for no_route in [
            "image = \"x:1\"\ndomains = [\"a.example.com\"]",
            "image = \"x:1\"\nport = 80",
        ] {
            fs::write(
                &p,
                format!("[apps.a]\n{no_route}\nhealth = {{ http = {{}} }}\n"),
            )
            .unwrap();
            assert!(matches!(load_apps(&p), Err(StateError::Invalid { .. })));
        }
    }

    #[test]
    fn host_ports_are_validated_per_app() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        let check = |extra: &str| {
            fs::write(&p, format!("[apps.a]\nimage = \"x:1\"\n{extra}\n")).unwrap();
            load_apps(&p).is_ok()
        };
        assert!(check("host_ports = [{ host = 2222, container = 22 }]"));
        assert!(check(
            "host_ports = [{ host = 2222, container = 22, ip = \"0.0.0.0\" }]"
        ));
        // The same host port on two different, specific addresses is two distinct sockets.
        assert!(check(
            "host_ports = [\
             { host = 2222, container = 22, ip = \"10.0.0.5\" }, \
             { host = 2222, container = 23, ip = \"10.0.0.6\" }]"
        ));
        for bad in [
            "host_ports = [{ host = 0, container = 22 }]",
            "host_ports = [{ host = 2222, container = 0 }]",
            "host_ports = [{ host = 2222, container = 22, ip = \"nope\" }]",
            "host_ports = [{ host = 2222, container = 22 }, { host = 2222, container = 22 }]",
            "host_ports = [{ host = 2222, container = 22 }, \
             { host = 2222, container = 23, ip = \"0.0.0.0\" }]",
        ] {
            assert!(!check(bad), "{bad}");
        }
    }

    #[test]
    fn shared_volumes_are_validated_across_apps() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        let load = |src: &str| {
            fs::write(&p, src).unwrap();
            load_apps(&p)
        };
        // A declared shared volume mounted by two apps, mixed with a private volume, is valid and
        // round-trips through the daemon's writer.
        let good = r#"
[shared_volumes.kajet-data]

[apps.a]
image = "x:1"
volumes = [{ name = "own", target = "/own" }]
shared_volumes = [{ name = "kajet-data", target = "/data" }]

[apps.b]
image = "x:1"
shared_volumes = [{ name = "kajet-data", target = "/data", read_only = true }]
"#;
        let apps = load(good).expect("valid");
        save_apps(&p, &apps).unwrap();
        assert_eq!(load(&fs::read_to_string(&p).unwrap()).unwrap(), apps);

        // Mounting an undeclared shared volume is a typo, not a new volume.
        let err = load(
            "[apps.a]\nimage = \"x:1\"\nshared_volumes = [{ name = \"d\", target = \"/d\" }]\n",
        )
        .unwrap_err();
        assert!(matches!(err, StateError::Invalid { .. }), "{err:?}");
        // At most one shared volume per app (a shared volume is a uid-range boundary).
        assert!(matches!(
            load(
                "[shared_volumes.a]\n[shared_volumes.b]\n\
                 [apps.x]\nimage = \"x:1\"\n\
                 shared_volumes = [{ name = \"a\", target = \"/a\" }, { name = \"b\", target = \"/b\" }]\n"
            ),
            Err(StateError::Invalid { .. })
        ));
        // Mount targets are unique across private and shared mounts.
        assert!(matches!(
            load(
                "[shared_volumes.d]\n\
                 [apps.x]\nimage = \"x:1\"\n\
                 volumes = [{ name = \"own\", target = \"/data\" }]\n\
                 shared_volumes = [{ name = \"d\", target = \"/data/\" }]\n"
            ),
            Err(StateError::Invalid { .. })
        ));
        // The declaration itself is strict (`deny_unknown_fields`).
        assert!(matches!(
            load("[shared_volumes.d]\nbogus = 1\n"),
            Err(StateError::Parse { .. })
        ));
        // A shared range must not overlap an instance range.
        fs::write(
            &p,
            "[apps.a]\nuid_range = { start = 1, size = 100 }\n\
             [shared_volumes.v]\nuid_range = { start = 50, size = 100 }\n",
        )
        .unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Invalid { .. })));
    }

    #[test]
    fn blue_green_needs_a_stateless_app() {
        let check = |extra: &str| {
            let spec: AppSpec = toml::from_str(&format!(
                "image = \"i\"\nstrategy = \"blue_green\"\n{extra}"
            ))
            .unwrap();
            validate_app(&name("a"), &spec)
        };
        assert!(check("").is_ok());
        assert!(
            check("volumes = [{ name = \"cfg\", target = \"/cfg\", read_only = true }]").is_ok()
        );
        assert!(
            check("shared_volumes = [{ name = \"s\", target = \"/s\", read_only = true }]").is_ok()
        );
        for bad in [
            "volumes = [{ name = \"data\", target = \"/data\" }]",
            "shared_volumes = [{ name = \"s\", target = \"/s\" }]",
            "host_ports = [{ host = 8080, container = 80 }]",
        ] {
            let err = check(bad).unwrap_err();
            assert!(err.contains("blue_green"), "{bad}: {err}");
        }
        // The default strategy has no such restriction.
        let spec: AppSpec =
            toml::from_str("image = \"i\"\nvolumes = [{ name = \"data\", target = \"/data\" }]")
                .unwrap();
        assert!(validate_app(&name("a"), &spec).is_ok());
    }

    #[test]
    fn config_mounts_and_reload_signal_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        let load = |src: &str| {
            fs::write(&p, src).unwrap();
            load_apps(&p)
        };
        let app = |extra: &str| format!("[apps.a]\nimage = \"x:1\"\n{extra}\n");

        // A file and a directory mount, plus a signal spelled any way: all valid. These are lexical
        // rules only — whether `config_root` is set is a host question answered by config_mounts.
        assert!(
            load(&app("configs = [\
                 { source = \"app/config.yml\", target = \"/etc/app/config.yml\" }, \
                 { source = \"app/conf.d\", target = \"/etc/app/conf.d\" }]\n\
                 reload_signal = \"sighup\""))
            .is_ok()
        );

        for bad in [
            "configs = [{ source = \"\", target = \"/a\" }]",
            "configs = [{ source = \"/etc/shadow\", target = \"/a\" }]",
            "configs = [{ source = \"a/../b\", target = \"/a\" }]",
            "configs = [{ source = \"a/./b\", target = \"/a\" }]",
            "configs = [{ source = \"a\", target = \"relative\" }]",
            "configs = [{ source = \"a\", target = \"/a:ro\" }]",
            "configs = [{ source = \"a\", target = \"/a/../b\" }]",
            "configs = [{ source = \"a\", target = \"/a\" }, { source = \"b\", target = \"/a/\" }]",
            "volumes = [{ name = \"d\", target = \"/data\" }]\n\
             configs = [{ source = \"a\", target = \"/data/\" }]",
            "reload_signal = \"SIG\"",
            "reload_signal = \"\"",
            "reload_signal = \"HU P\"",
            "reload_signal = \"H\"",
        ] {
            assert!(
                matches!(load(&app(bad)), Err(StateError::Invalid { .. })),
                "{bad}"
            );
        }

        // Config targets share the uniqueness namespace with shared-volume mounts.
        assert!(matches!(
            load(
                "[shared_volumes.d]\n[apps.a]\nimage = \"x:1\"\n\
                 shared_volumes = [{ name = \"d\", target = \"/data\" }]\n\
                 configs = [{ source = \"a\", target = \"/data/\" }]\n"
            ),
            Err(StateError::Invalid { .. })
        ));
    }

    #[test]
    fn apps_validation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        fs::write(&p, "[apps.a]\nimage = \"x y\"\n").unwrap();
        assert!(matches!(load_apps(&p), Err(StateError::Invalid { .. })));
        fs::write(&p, "[apps.a]\nimage = \"x:1\"\nhealth = { attempts = 0 }\n").unwrap();
        assert!(matches!(load_apps(&p), Err(StateError::Invalid { .. })));
        fs::write(&p, "[apps.a]\nimage = \"x:1\"\n").unwrap();
        let apps = load_apps(&p).unwrap();
        save_apps(&p, &apps).unwrap();
        assert_eq!(load_apps(&p).unwrap(), apps);
    }

    #[test]
    fn files_without_a_version_are_v1_and_get_stamped_by_the_first_save() {
        // A file without the marker is v1 (ADR 0023). From the first real schema bump on, loading it
        // runs the migration chain and the next ordinary save writes the marker — that is what
        // turns a silent `deny_unknown_fields` parse error into a clear downgrade message.
        let dir = tempfile::tempdir().unwrap();
        let apps_path = dir.path().join("apps.toml");
        fs::write(&apps_path, "[apps.a]\nimage = \"x:1\"\n").unwrap();
        // A v1 file is migrated in memory and stamped; its content is untouched.
        let apps = load_apps(&apps_path).unwrap();
        assert_eq!(apps.schema_version, Some(SCHEMA_VERSION));
        save_apps(&apps_path, &apps).unwrap();
        assert!(
            fs::read_to_string(&apps_path)
                .unwrap()
                .contains(&format!("schema_version = {SCHEMA_VERSION}"))
        );

        let state_path = dir.path().join("state.toml");
        fs::write(&state_path, "[apps.a]\ngeneration = 3\n").unwrap();
        let st = load_state(&state_path).unwrap();
        assert_eq!(st.schema_version, Some(SCHEMA_VERSION));
        save_state(&state_path, &st).unwrap();
        assert!(
            fs::read_to_string(&state_path)
                .unwrap()
                .contains(&format!("schema_version = {SCHEMA_VERSION}"))
        );
    }

    #[test]
    fn a_v1_file_that_already_carries_the_new_app_fields_migrates_cleanly() {
        // The v1 → v2 step is a no-op and must accept a hand-edited/rollback-restored file that
        // already contains `configs`/`reload_signal` (issue #118).
        let dir = tempfile::tempdir().unwrap();
        let apps_path = dir.path().join("apps.toml");
        fs::write(
            &apps_path,
            "[apps.a]\nimage = \"x:1\"\nconfigs = [{ source = \"a.yml\", target = \"/a.yml\" }]\nreload_signal = \"HUP\"\n",
        )
        .unwrap();
        let apps = load_apps(&apps_path).unwrap();
        assert_eq!(apps.schema_version, Some(SCHEMA_VERSION));
        assert_eq!(apps.apps[&name("a")].configs.len(), 1);
    }

    #[test]
    fn an_explicit_current_version_is_accepted_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.toml");
        fs::write(
            &p,
            format!("schema_version = {SCHEMA_VERSION}\n[apps.a]\ngeneration = 1\n"),
        )
        .unwrap();
        let st = load_state(&p).unwrap();
        assert_eq!(st.schema_version, Some(SCHEMA_VERSION));
        save_state(&p, &st).unwrap();
        // A marker that is already there is preserved, not silently dropped on the next write.
        assert!(
            fs::read_to_string(&p)
                .unwrap()
                .starts_with(&format!("schema_version = {SCHEMA_VERSION}"))
        );
    }

    #[test]
    fn a_newer_schema_is_refused_before_the_payload_is_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let apps_path = dir.path().join("apps.toml");
        // Under `deny_unknown_fields` the `bogus` field would win; the version must be reported
        // first — that is the whole point of issue #98.
        let newer = SCHEMA_VERSION + 1;
        fs::write(
            &apps_path,
            format!("schema_version = {newer}\n[apps.a]\nimage = \"x:1\"\nbogus = 1\n"),
        )
        .unwrap();
        let err = load_apps(&apps_path).unwrap_err();
        assert!(
            matches!(
                err,
                StateError::SchemaTooNew {
                    found,
                    supported: SCHEMA_VERSION,
                    ..
                } if found == newer
            ),
            "{err}"
        );
        let message = err.to_string();
        assert!(
            message.contains("apps.toml") && message.contains(&format!("schema version {newer}")),
            "{message}"
        );

        let state_path = dir.path().join("state.toml");
        fs::write(&state_path, format!("schema_version = {newer}\n")).unwrap();
        assert!(matches!(
            load_state(&state_path),
            Err(StateError::SchemaTooNew { found, .. }) if found == newer
        ));

        // A value beyond `u32` is still "newer", not a malformed field.
        fs::write(&state_path, "schema_version = 4294967296\n").unwrap();
        assert!(matches!(
            load_state(&state_path),
            Err(StateError::SchemaTooNew {
                found: u32::MAX,
                ..
            })
        ));
    }

    #[test]
    fn invalid_versions_and_empty_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.toml");
        for bad in [
            "schema_version = 0",
            "schema_version = -1",
            "schema_version = \"1\"",
            "schema_version = 1.5",
        ] {
            fs::write(&p, format!("{bad}\n")).unwrap();
            let err = load_state(&p).unwrap_err();
            assert!(matches!(err, StateError::Invalid { .. }), "{bad}: {err}");
            assert!(err.to_string().contains("schema_version"), "{bad}: {err}");
        }
        // An empty (or comment-only) file is "nothing yet", not a parse error.
        fs::write(&p, "").unwrap();
        assert_eq!(load_state(&p).unwrap(), StateFile::default());
        // A comment-only file has no marker, so it is a (migrated, stamped) empty v1 file.
        fs::write(&p, "# nothing yet\n").unwrap();
        let loaded = load_state(&p).unwrap();
        assert_eq!(loaded.schema_version, Some(SCHEMA_VERSION));
        assert!(loaded.apps.is_empty());
    }

    #[test]
    fn migrating_stamps_the_schema_version() {
        // Exercise the chain directly through the implicit version: the migrated document must
        // carry the current version (the v1 → v2 step is a no-op, ADR 0023/0026).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let st: StateFile =
            migrate(&path, "[apps.a]\ngeneration = 2\n", IMPLICIT_SCHEMA_VERSION).unwrap();
        assert_eq!(st.schema_version, Some(SCHEMA_VERSION));
        assert_eq!(st.apps[&name("a")].generation, 2);
    }
}
