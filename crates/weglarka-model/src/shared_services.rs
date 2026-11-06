//! Shared services (issue #590, managed Redis contract v1 in #593, Postgres in #596): an app
//! instance that Węglarka runs as a service for other instances, its members.
//!
//! A service is declared once in `[shared_services.<name>]` and joined by apps through
//! `AppSpec::shared_services`; the identity provider joins one through `[identity] session_store`.
//! This module holds the types, their lexical rules and the rollout gate: every declaration and
//! every membership is rejected with [`GATE`] until the PR of each kind lifts it.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::{AppSpec, AppsFile, InstanceName, SharedNetworkName, SharedNetworkRef};

/// The rollout gate message (#590). Later PRs lift it per kind.
pub const GATE: &str = "shared services are not enabled in this release";

/// Name of a shared service (key in `apps.toml`'s `[shared_services]` section). Same character set
/// as [`InstanceName`]: it becomes part of the network name `net-shared-<name>` and of the secret
/// name `svc-<name>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

#[derive(Debug, thiserror::Error)]
#[error(
    "invalid shared service name {0:?}: expected 1-63 chars of [a-z0-9-], no leading/trailing '-', \
     not ending in -digest or -pgpass"
)]
pub struct InvalidServiceName(pub String);

impl ServiceName {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidServiceName> {
        let name = name.into();
        // The same alphabet as an instance name; reuse it instead of repeating the rule. A name
        // ending in a reserved suffix would make its derived secret names (`svc-<name>-digest`,
        // `svc-<name>-pgpass`) collide with another service's `svc-<name>` (ADR 0079).
        let reserved = RESERVED_SUFFIXES.iter().any(|s| name.ends_with(s));
        match InstanceName::new(name.clone()) {
            Ok(_) if !reserved => Ok(Self(name)),
            _ => Err(InvalidServiceName(name)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The shared network the service and its members join (`net-shared-<name>`, ADR 0030/0079).
    /// Infallible: a service name is a valid network name (the same alphabet), and the namespace
    /// is shared on purpose (`NameTaken`).
    pub fn network(&self) -> SharedNetworkName {
        SharedNetworkName::new(self.0.clone()).expect("a service name is a valid network name")
    }
}

/// Suffixes a service name must not end in (ADR 0079).
pub const RESERVED_SUFFIXES: [&str; 2] = ["-digest", "-pgpass"];

impl TryFrom<String> for ServiceName {
    type Error = InvalidServiceName;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ServiceName> for String {
    fn from(value: ServiceName) -> Self {
        value.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the service instance runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Redis,
    Postgres,
}

/// Persistence profile of a Redis service (#593).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedisProfile {
    /// AOF on, `noeviction`; needs a volume at `/data`.
    Durable,
    /// No persistence, `allkeys-lru`; needs `maxmemory`.
    Cache,
}

/// A Redis memory limit as written into `redis.conf`: `<n>` (bytes) or `<n>kb|mb|gb`.
///
/// Accepted: `<n>`, `<n>kb`, `<n>mb`, `<n>gb`, where `<n>` is 1-12 ASCII digits not starting with
/// `0`. The value is kept verbatim (the generated `redis.conf` repeats what the operator wrote),
/// only the shape is checked. The 12-digit bound keeps the size far inside Redis's own 64-bit
/// parse; a leading zero is rejected because `0` is Redis's "no limit", the opposite of what a
/// `maxmemory` on a `cache` service is for. Uppercase units, other suffixes (`k`, `m`, `b`, `tb`),
/// signs, spaces and a unit without a number are rejected too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Maxmemory(String);

#[derive(Debug, thiserror::Error)]
#[error("invalid maxmemory {0:?}: {1}")]
pub struct InvalidMaxmemory(pub String, pub &'static str);

impl Maxmemory {
    /// Checks the lexical rule documented on the type; the reason is a short English phrase.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidMaxmemory> {
        let value = value.into();
        if value.is_empty() {
            return Err(InvalidMaxmemory(value, "must not be empty"));
        }
        // Digits first, then the optional unit: a Redis memory string has no other shape.
        let (digits, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
            Some(pos) => value.split_at(pos),
            None => (value.as_str(), ""),
        };
        if digits.is_empty() {
            return Err(InvalidMaxmemory(
                value,
                "expected 1-12 digits, then an optional kb, mb or gb",
            ));
        }
        if digits.starts_with('0') {
            return Err(InvalidMaxmemory(
                value,
                "must not start with '0': a zero limit means unlimited in Redis",
            ));
        }
        if digits.len() > 12 {
            return Err(InvalidMaxmemory(
                value,
                "more than 12 digits is not a memory size",
            ));
        }
        if !matches!(unit, "" | "kb" | "mb" | "gb") {
            return Err(InvalidMaxmemory(
                value,
                "unit must be kb, mb or gb (lower-case), or no unit for bytes",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Maxmemory {
    type Error = InvalidMaxmemory;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Maxmemory> for String {
    fn from(value: Maxmemory) -> Self {
        value.0
    }
}

impl fmt::Display for Maxmemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Declaration of a shared service, `[shared_services.<name>]` in `apps.toml`. Strict, like every
/// persisted type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedServiceSpec {
    pub kind: ServiceKind,
    /// The app instance that runs the service.
    pub instance: InstanceName,
    /// Redis only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<RedisProfile>,
    /// Redis only: required for `cache`, optional for `durable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maxmemory: Option<Maxmemory>,
}

/// A violated shared-service rule (ADR 0079). The variant names are the rejection names of the
/// managed Redis and Postgres contracts (#593, #596), so fixtures are checked by name
/// ([`ServiceRule::name`]); `Display` adds the detail an operator needs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceRule {
    /// A `[shared_services]` and a `[shared_networks]` entry with the same name.
    #[error("[shared_services.{0}]: the name is already a [shared_networks] entry")]
    NameTaken(ServiceName),
    /// The declaration names an instance that is not in `apps.toml`.
    #[error("[shared_services.{service}]: instance {instance} is not in apps.toml")]
    UnknownInstance {
        service: ServiceName,
        instance: InstanceName,
    },
    /// A member names an undeclared service.
    #[error(
        "{member}: shared_services names {service}, which is not declared in [shared_services]"
    )]
    UnknownService {
        member: InstanceName,
        service: ServiceName,
    },
    /// The service instance sets a field the service owns.
    #[error("{instance}: {field} is owned by [shared_services.{service}] and must not be set")]
    ServiceSpecOwned {
        service: ServiceName,
        instance: InstanceName,
        field: &'static str,
    },
    /// The service instance is a member of its own service.
    #[error("{instance}: the instance of [shared_services.{service}] cannot be its member")]
    ServiceIsMember {
        service: ServiceName,
        instance: InstanceName,
    },
    /// A member uses more than one service of one kind (v1).
    #[error("{member}: at most one shared service per kind ({kind:?}): {first}, {second}")]
    TooManyServicesOfKind {
        member: InstanceName,
        kind: ServiceKind,
        first: ServiceName,
        second: ServiceName,
    },
}

impl ServiceRule {
    /// The contract's rejection name (`"NameTaken"`, …).
    pub fn name(&self) -> &'static str {
        match self {
            Self::NameTaken(_) => "NameTaken",
            Self::UnknownInstance { .. } => "UnknownInstance",
            Self::UnknownService { .. } => "UnknownService",
            Self::ServiceSpecOwned { .. } => "ServiceSpecOwned",
            Self::ServiceIsMember { .. } => "ServiceIsMember",
            Self::TooManyServicesOfKind { .. } => "TooManyServicesOfKind",
        }
    }
}

/// The kind-independent rules of ADR 0079, in a fixed order (the first violation wins). Pure.
pub fn check(apps: &AppsFile) -> Result<(), ServiceRule> {
    // TODO(#592 A): NameTaken, UnknownInstance, ServiceSpecOwned, ServiceIsMember, UnknownService,
    // TooManyServicesOfKind.
    let _ = apps;
    Ok(())
}

/// Whether a kind is released (ADR 0079): a declaration of an unreleased kind is rejected with
/// [`GATE`]. Each kind's PR flips its own arm (#593 Redis, #596 Postgres).
pub const fn kind_released(kind: ServiceKind) -> bool {
    match kind {
        ServiceKind::Redis => false,
        ServiceKind::Postgres => false,
    }
}

fn kind_enabled(kind: ServiceKind) -> bool {
    kind_released(kind) || testing::gates_open()
}

/// Checks the shared-service declarations and memberships of `apps.toml`, on every load and save:
/// the rules of [`check`] first, then the gate per kind (ADR 0079).
pub fn validate(apps: &AppsFile) -> Result<(), String> {
    check(apps).map_err(|rule| rule.to_string())?;
    if let Some((name, _)) = apps
        .shared_services
        .iter()
        .find(|(_, spec)| !kind_enabled(spec.kind))
    {
        return Err(format!("[shared_services.{name}]: {GATE}"));
    }
    Ok(())
}

/// Instances that list `service`, ordered by name. Drives the removal guard, `apps list` and
/// `doctor`.
pub fn members(apps: &AppsFile, service: &ServiceName) -> Vec<InstanceName> {
    apps.apps
        .iter()
        .filter(|(_, spec)| spec.shared_services.contains(service))
        .map(|(name, _)| name.clone())
        .collect()
}

/// The service an instance runs, if it is the instance of a declaration.
pub fn service_of<'a>(apps: &'a AppsFile, instance: &InstanceName) -> Option<&'a ServiceName> {
    apps.shared_services
        .iter()
        .find(|(_, spec)| &spec.instance == instance)
        .map(|(name, _)| name)
}

/// Names that own a `net-shared-<name>` network: the `[shared_networks]` and the
/// `[shared_services]` entries (one namespace, `NameTaken`). Network pruning and `doctor` keep a
/// group network while its name is in this set.
pub fn network_groups(apps: &AppsFile) -> std::collections::BTreeSet<SharedNetworkName> {
    apps.shared_networks
        .keys()
        .cloned()
        .chain(apps.shared_services.keys().map(ServiceName::network))
        .collect()
}

/// The service relations of ADR 0079 laid over a spec, after the identity overlay
/// (`identity::effective_spec`): a member waits for each service instance (`depends_on`) and joins
/// each service's network; the service instance joins its own. Never written to `apps.toml`.
/// Borrowed (identical hash) for an instance outside every service.
pub fn overlay<'a>(
    instance: &InstanceName,
    spec: Cow<'a, AppSpec>,
    services: &BTreeMap<ServiceName, SharedServiceSpec>,
) -> Cow<'a, AppSpec> {
    let mut joins: Vec<(&ServiceName, Option<&InstanceName>)> = Vec::new();
    for (name, decl) in services {
        if &decl.instance == instance {
            joins.push((name, None));
        } else if spec.shared_services.contains(name) {
            joins.push((name, Some(&decl.instance)));
        }
    }
    if joins.is_empty() {
        return spec;
    }
    let mut out = spec.into_owned();
    for (name, wait_for) in joins {
        if let Some(dep) = wait_for
            && !out.depends_on.contains(dep)
        {
            out.depends_on.push(dep.clone());
        }
        let network = name.network();
        if !out.shared_networks.iter().any(|n| n.name == network) {
            out.shared_networks.push(SharedNetworkRef {
                name: network,
                aliases: Vec::new(),
            });
        }
    }
    Cow::Owned(out)
}

/// Test-only switch for the gate (ADR 0079): the engine and daemon tests of the shared wiring need
/// declarations that load before any kind is released. Behind the `testing` feature, which only
/// `[dev-dependencies]` enable, so a production binary has no way to open the gate.
pub mod testing {
    #[cfg(feature = "testing")]
    static OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Opens the gate of every kind for the rest of the process. Never closed again: the gate's
    /// own tests live in this crate and never call it.
    #[cfg(feature = "testing")]
    pub fn open_kind_gates() {
        OPEN.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(super) fn gates_open() -> bool {
        #[cfg(feature = "testing")]
        {
            OPEN.load(std::sync::atomic::Ordering::SeqCst)
        }
        #[cfg(not(feature = "testing"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps(src: &str) -> AppsFile {
        toml::from_str(src).expect("valid apps.toml")
    }

    fn name(s: &str) -> ServiceName {
        ServiceName::new(s).unwrap()
    }

    /// A declaration with one member: the shape the gate and the lexical rules are tested on.
    const DECLARED: &str = r#"
[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache"]
"#;

    #[test]
    fn a_declaration_parses_with_its_lexical_fields() {
        let a = apps(DECLARED);
        let decl = &a.shared_services[&name("cache")];
        assert_eq!(decl.kind, ServiceKind::Redis);
        assert_eq!(decl.instance, InstanceName::new("cache-redis").unwrap());
        assert_eq!(decl.profile, Some(RedisProfile::Cache));
        assert_eq!(decl.maxmemory.as_ref().map(Maxmemory::as_str), Some("64mb"));
        // `postgres` has no profile and no maxmemory: optional fields stay unset.
        let pg = apps("[shared_services.db]\nkind = \"postgres\"\ninstance = \"db-pg\"\n");
        let decl = &pg.shared_services[&name("db")];
        assert_eq!(decl.kind, ServiceKind::Postgres);
        assert_eq!((decl.profile, decl.maxmemory.as_ref()), (None, None));
    }

    #[test]
    fn a_declaration_rejects_unknown_fields_and_bad_values() {
        let head = "[shared_services.cache]\ninstance = \"cache-redis\"\n";
        // Strict, like every persisted type.
        assert!(
            toml::from_str::<AppsFile>(&format!("{head}kind = \"redis\"\nbogus = 1\n")).is_err()
        );
        // The name follows the instance alphabet.
        assert!(toml::from_str::<AppsFile>("[shared_services.Bad_Name]\n").is_err());
        // `kind` and `profile` are closed enums.
        assert!(
            toml::from_str::<AppsFile>("[shared_services.c]\nkind = \"mongo\"\ninstance = \"c\"\n")
                .is_err()
        );
        assert!(
            toml::from_str::<AppsFile>(&format!("{head}kind = \"redis\"\nprofile = \"memory\"\n"))
                .is_err()
        );
        // `kind` and `instance` are required.
        assert!(toml::from_str::<AppsFile>("[shared_services.c]\ninstance = \"c\"\n").is_err());
        assert!(toml::from_str::<AppsFile>("[shared_services.c]\nkind = \"redis\"\n").is_err());
    }

    #[test]
    fn membership_accepts_only_the_bare_string_form() {
        let member = |list: &str| {
            toml::from_str::<AppsFile>(&format!(
                "[apps.api]\nimage = \"x:1\"\nshared_services = {list}\n"
            ))
        };
        assert_eq!(
            member(r#"["cache"]"#).unwrap().apps[&InstanceName::new("api").unwrap()]
                .shared_services,
            vec![name("cache")]
        );
        // v1 accepts only the bare name; the table form is reserved for later.
        assert!(member(r#"[{ name = "cache" }]"#).is_err());
        assert!(member(r#"["Bad_Name"]"#).is_err());
    }

    #[test]
    fn maxmemory_accepts_bytes_and_lowercase_units() {
        for value in ["1", "64mb", "512kb", "2gb", "1048576", "999999999999"] {
            assert_eq!(Maxmemory::new(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn maxmemory_rejects_everything_else() {
        for value in [
            "",
            "0",
            "064mb",
            "64MB",
            "64 mb",
            "64 megabytes",
            "64m",
            "-1",
            "1tb",
            "1234567890123",
        ] {
            let err = Maxmemory::new(value).unwrap_err();
            assert_eq!(err.0, value);
            assert!(!err.1.is_empty(), "{value:?} needs a reason");
        }
        assert!(Maxmemory::new("1").is_ok());
    }

    #[test]
    fn a_bad_maxmemory_in_apps_toml_fails_to_parse() {
        for value in ["64 megabytes", "0", "1TB"] {
            let src = format!(
                "[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\
                 profile = \"cache\"\nmaxmemory = \"{value}\"\n"
            );
            assert!(
                toml::from_str::<AppsFile>(&src).is_err(),
                "{value:?} parsed"
            );
        }
    }

    #[test]
    fn the_gate_names_the_first_declaration_then_a_membership() {
        let decl = apps(
            "[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\
             [shared_services.queue]\nkind = \"redis\"\ninstance = \"queue-redis\"\n",
        );
        assert_eq!(
            validate(&decl).unwrap_err(),
            format!("[shared_services.cache]: {GATE}")
        );
        let member = apps("[apps.api]\nimage = \"x:1\"\nshared_services = [\"cache\"]\n");
        assert_eq!(
            validate(&member).unwrap_err(),
            format!("api: shared_services: {GATE}")
        );
    }

    #[test]
    fn a_file_without_shared_services_passes_the_gate() {
        let a = apps(
            "[shared_networks.g]\n\n[apps.ntfy]\nimage = \"x:1\"\nshared_networks = [\"g\"]\n",
        );
        assert!(a.shared_services.is_empty());
        validate(&a).unwrap();
    }

    #[test]
    fn a_declaration_round_trips_and_membership_stays_a_bare_string() {
        let a = apps(DECLARED);
        let text = toml::to_string(&a).unwrap();
        assert!(text.contains("maxmemory = \"64mb\""), "{text}");
        assert!(text.contains(r#"shared_services = ["cache"]"#), "{text}");
        assert_eq!(apps(&text), a);
    }

    /// Every `apps_toml` of the "Fixture files" JSON of the managed-Redis contract (#593), by case
    /// name. Most are rejected by semantic checks that arrive with #592/#593; none may get past
    /// this PR, so each must fail to parse or hit the gate.
    const CONTRACT_FIXTURES: &[(&str, &str)] = &[
        (
            "sessions-durable",
            r#"[shared_services.sessions]
kind = "redis"
instance = "sessions-redis"
profile = "durable"

[apps.sessions-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
volumes = [{ name = "data", target = "/data" }]

[apps.authelia]
image = "ghcr.io/authelia/authelia:4.39"
port = 9091
domains = ["auth.example.com"]
auto_update = false
"#,
        ),
        (
            "cache-two-members",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["cache"]
"#,
        ),
        (
            "name-taken",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["cache"]

[shared_networks.cache]
"#,
        ),
        (
            "unknown-instance",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache"]
"#,
        ),
        (
            "unknown-service",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["queue"]
"#,
        ),
        (
            "service-spec-owned-command",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
command = ["redis-server", "--appendonly", "no"]
"#,
        ),
        (
            "service-spec-owned-auto-update",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = true
"#,
        ),
        (
            "service-spec-owned-reload-signal",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
reload_signal = "SIGHUP"
"#,
        ),
        (
            "service-is-member",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
shared_services = ["cache"]
"#,
        ),
        (
            "service-has-members",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["cache"]
"#,
        ),
        (
            "profile-requires-volume",
            r#"[shared_services.sessions]
kind = "redis"
instance = "sessions-redis"
profile = "durable"

[apps.sessions-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
"#,
        ),
        (
            "cache-requires-maxmemory",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
"#,
        ),
        (
            "invalid-maxmemory",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64 megabytes"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
"#,
        ),
        (
            "too-many-services-of-kind",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[shared_services.queue]
kind = "redis"
instance = "queue-redis"
profile = "durable"

[apps.queue-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
volumes = [{ name = "data", target = "/data" }]

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache", "queue"]
"#,
        ),
        (
            "missing-credential",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["cache"]
"#,
        ),
        (
            "unsupported-server-version",
            r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:6.2"
auto_update = false
"#,
        ),
        (
            "session-store-not-redis",
            r#"[shared_services.sessions]
kind = "postgres"
instance = "sessions-db"

[apps.sessions-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]

[apps.authelia]
image = "ghcr.io/authelia/authelia:4.39"
port = 9091
domains = ["auth.example.com"]
auto_update = false
"#,
        ),
        (
            "session-store-not-durable",
            r#"[shared_services.sessions]
kind = "redis"
instance = "sessions-redis"
profile = "cache"
maxmemory = "64mb"

[apps.sessions-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
volumes = [{ name = "data", target = "/data" }]

[apps.authelia]
image = "ghcr.io/authelia/authelia:4.39"
port = 9091
domains = ["auth.example.com"]
auto_update = false
"#,
        ),
        (
            "session-store-shared",
            r#"[shared_services.sessions]
kind = "redis"
instance = "sessions-redis"
profile = "durable"

[apps.sessions-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
volumes = [{ name = "data", target = "/data" }]

[apps.authelia]
image = "ghcr.io/authelia/authelia:4.39"
port = 9091
domains = ["auth.example.com"]
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["sessions"]
"#,
        ),
        (
            "session-store-in-spec",
            r#"[shared_services.sessions]
kind = "redis"
instance = "sessions-redis"
profile = "durable"

[apps.sessions-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
volumes = [{ name = "data", target = "/data" }]

[apps.authelia]
image = "ghcr.io/authelia/authelia:4.39"
port = 9091
domains = ["auth.example.com"]
auto_update = false
shared_services = ["sessions"]
"#,
        ),
    ];

    #[test]
    fn the_gate_stops_every_contract_fixture() {
        assert_eq!(CONTRACT_FIXTURES.len(), 20);
        for (case, src) in CONTRACT_FIXTURES {
            // `invalid-maxmemory` is rejected by the lexical rule, the rest by the gate.
            match toml::from_str::<AppsFile>(src) {
                Err(_) => (),
                Ok(parsed) => {
                    let err = validate(&parsed).expect_err(case);
                    assert!(err.contains(GATE), "{case}: {err}");
                }
            }
        }
    }
}
