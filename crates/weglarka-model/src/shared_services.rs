//! Shared services (issue #590, managed Redis contract v1 in #593, Postgres in #596): an app
//! instance that Węglarka runs as a service for other instances, its members.
//!
//! A service is declared once in `[shared_services.<name>]` and joined by apps through
//! `AppSpec::shared_services`; the identity provider joins one through `[identity] session_store`.
//! This module holds the types, their lexical rules, the kind-independent rules of [`check`] (ADR
//! 0079), the `effective_spec` overlay and the rollout gate: a declaration of a kind whose PR has
//! not landed yet is rejected with [`GATE`].

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::{AppKind, AppSpec, AppsFile, InstanceName, SharedNetworkName, SharedNetworkRef};

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
///
/// The order is the contract's: one namespace with `[shared_networks]`, then the declaration's
/// instance exists, then that instance's spec sets nothing the service owns, then every membership
/// names a declared service, then no member uses two services of one kind. Declarations and apps
/// are `BTreeMap`s, so the reported violation is deterministic.
pub fn check(apps: &AppsFile) -> Result<(), ServiceRule> {
    // One namespace: a service and a network of the same name would both become
    // `net-shared-<name>` (ADR 0079, rejected alternative).
    for name in apps.shared_services.keys() {
        if apps
            .shared_networks
            .keys()
            .any(|net| net.as_str() == name.as_str())
        {
            return Err(ServiceRule::NameTaken(name.clone()));
        }
    }
    // The instance that runs the service has to exist, or the declaration points nowhere.
    for (service, decl) in &apps.shared_services {
        if !apps.apps.contains_key(&decl.instance) {
            return Err(ServiceRule::UnknownInstance {
                service: service.clone(),
                instance: decl.instance.clone(),
            });
        }
    }
    // The declaration owns its instance while it exists: the fields below are derived (command,
    // apply mode, generated config) or would route the service (`domains`, ports). Field order is
    // the contract's, so a fixture rejection names the first owned field it sets.
    for (service, decl) in &apps.shared_services {
        let Some(spec) = apps.apps.get(&decl.instance) else {
            // Unreachable after the loop above; kept so a later rule can never panic on it.
            continue;
        };
        let owned = |field: &'static str| ServiceRule::ServiceSpecOwned {
            service: service.clone(),
            instance: decl.instance.clone(),
            field,
        };
        let fields = [
            ("kind", spec.kind != AppKind::Container),
            ("sites", apps.origin(&decl.instance).is_some()),
            ("command", !spec.command.is_empty()),
            ("domains", !spec.domains.is_empty()),
            ("paths", !spec.paths.is_empty()),
            ("port", spec.port.is_some()),
            ("host_ports", !spec.host_ports.is_empty()),
        ];
        if let Some((field, _)) = fields.iter().find(|(_, violated)| *violated) {
            return Err(owned(field));
        }
        // `shared_services` is owned too, but a service naming itself is a relation error with its
        // own name (`ServiceIsMember`); any other list is the owned field.
        if spec.shared_services.contains(service) {
            return Err(ServiceRule::ServiceIsMember {
                service: service.clone(),
                instance: decl.instance.clone(),
            });
        }
        if !spec.shared_services.is_empty() {
            return Err(owned("shared_services"));
        }
        let rest = [
            ("reload_signal", spec.reload_signal.is_some()),
            ("auto_update", spec.auto_update),
        ];
        if let Some((field, _)) = rest.iter().find(|(_, violated)| *violated) {
            return Err(owned(field));
        }
    }
    // A membership names a declared service; an undeclared one is a typo, and silently ignoring it
    // would start a member without its network, env and secret.
    for (member, spec) in &apps.apps {
        for service in &spec.shared_services {
            if !apps.shared_services.contains_key(service) {
                return Err(ServiceRule::UnknownService {
                    member: member.clone(),
                    service: service.clone(),
                });
            }
        }
    }
    // v1 gives a member one set of variables per kind, so at most one service per kind. A name
    // listed twice is one service (the same relation written twice), not a violation.
    for (member, spec) in &apps.apps {
        let list = &spec.shared_services;
        for (position, first) in list.iter().enumerate() {
            for second in &list[position + 1..] {
                if first == second {
                    continue;
                }
                let (Some(one), Some(two)) = (
                    apps.shared_services.get(first),
                    apps.shared_services.get(second),
                ) else {
                    // Unreachable after the membership loop; never guess a kind here.
                    continue;
                };
                if one.kind == two.kind {
                    return Err(ServiceRule::TooManyServicesOfKind {
                        member: member.clone(),
                        kind: one.kind,
                        first: first.clone(),
                        second: second.clone(),
                    });
                }
            }
        }
    }
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
    fn the_gate_names_the_first_declaration_and_a_lone_membership_is_unknown_service() {
        // Every rule passes, so the gate of the kind decides; the first declaration is reported.
        let decl = apps(
            "[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\
             [apps.cache-redis]\nimage = \"docker.io/library/redis:7.4\"\nauto_update = false\n\
             [shared_services.queue]\nkind = \"redis\"\ninstance = \"queue-redis\"\n\
             [apps.queue-redis]\nimage = \"docker.io/library/redis:7.4\"\nauto_update = false\n",
        );
        assert_eq!(check(&decl), Ok(()));
        assert_eq!(
            validate(&decl).unwrap_err(),
            format!("[shared_services.cache]: {GATE}")
        );
        // #592: a membership without a declaration is a rule error, checked before the gate.
        let member = apps("[apps.api]\nimage = \"x:1\"\nshared_services = [\"cache\"]\n");
        let rule = check(&member).unwrap_err();
        assert_eq!(rule.name(), "UnknownService");
        assert_eq!(validate(&member).unwrap_err(), rule.to_string());
    }

    fn instance(name: &str) -> InstanceName {
        InstanceName::new(name).unwrap()
    }

    /// `check` of a small inline `apps.toml`; the callers assert the rule it returns.
    fn rule(src: &str) -> ServiceRule {
        check(&apps(src)).expect_err("a rejected apps.toml")
    }

    /// `check` of a declaration of `cache` whose instance `cache-redis` sets `body` on top of a spec
    /// that is valid for a service.
    fn service_spec(body: &str) -> Result<(), ServiceRule> {
        service_spec_fields(&format!("auto_update = false\n{body}"))
    }

    /// [`service_spec`] with the instance's fields written verbatim, for the `auto_update` default.
    fn service_spec_fields(fields: &str) -> Result<(), ServiceRule> {
        check(&apps(&format!(
            "[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\n\
             [apps.cache-redis]\nimage = \"docker.io/library/redis:7.4\"\n{fields}"
        )))
    }

    #[test]
    fn a_name_used_by_a_network_and_a_service_is_taken() {
        let rule = rule(
            "[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\n\
             [shared_networks.cache]\n",
        );
        assert_eq!(rule.name(), "NameTaken");
        assert!(rule.to_string().contains("cache"), "{rule}");
    }

    #[test]
    fn a_declaration_naming_a_missing_instance_is_unknown() {
        let rule = rule("[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n");
        assert_eq!(rule.name(), "UnknownInstance");
        assert!(rule.to_string().contains("cache-redis"), "{rule}");
        assert!(rule.to_string().contains("cache"), "{rule}");
    }

    #[test]
    fn every_owned_field_of_the_service_instance_is_rejected_in_contract_order() {
        // The shape every rejection below shares is valid on its own: image, volumes, resources and
        // env stay the operator's (ADR 0079).
        assert_eq!(service_spec(""), Ok(()));
        for (body, field) in [
            ("kind = \"static\"\n", "kind"),
            ("command = [\"redis-server\"]\n", "command"),
            ("domains = [\"db.example.com\"]\n", "domains"),
            ("paths = [\"/metrics\"]\n", "paths"),
            ("port = 6379\n", "port"),
            (
                "host_ports = [{ host = 6379, container = 6379 }]\n",
                "host_ports",
            ),
            ("reload_signal = \"SIGHUP\"\n", "reload_signal"),
        ] {
            match service_spec(body).expect_err(body) {
                ServiceRule::ServiceSpecOwned {
                    service,
                    instance: owner,
                    field: reported,
                } => {
                    assert_eq!(reported, field, "{body}");
                    assert_eq!(owner, instance("cache-redis"), "{body}");
                    assert_eq!(service, name("cache"), "{body}");
                }
                rule => panic!("{body}: {rule}"),
            }
        }
        // `auto_update` is owned while unset as well: its default is `true`, and the contract's
        // `service-spec-owned-auto-update` fixture sets it explicitly.
        for fields in ["", "auto_update = true\n"] {
            match service_spec_fields(fields).expect_err(fields) {
                ServiceRule::ServiceSpecOwned { field, .. } => {
                    assert_eq!(field, "auto_update", "{fields}");
                }
                rule => panic!("{fields}: {rule}"),
            }
        }
        // Several owned fields report the first in the contract's order, not the first in the file.
        for fields in [
            "command = [\"x\"]\nreload_signal = \"SIGHUP\"\n",
            "reload_signal = \"SIGHUP\"\ncommand = [\"x\"]\n",
        ] {
            match service_spec_fields(fields).expect_err(fields) {
                ServiceRule::ServiceSpecOwned { field, .. } => {
                    assert_eq!(field, "command", "{fields}");
                }
                rule => panic!("{fields}: {rule}"),
            }
        }
    }

    #[test]
    fn a_service_instance_cannot_list_its_own_service() {
        // The contract fixture `service-is-member` expects this name, not `ServiceSpecOwned`.
        let rule = service_spec("shared_services = [\"cache\"]\n").expect_err("own service");
        assert_eq!(rule.name(), "ServiceIsMember");
        assert!(rule.to_string().contains("cache-redis"), "{rule}");
        assert!(rule.to_string().contains("cache"), "{rule}");
    }

    #[test]
    fn a_service_instance_cannot_be_a_member_of_another_service() {
        let src = "[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\n\
             [apps.cache-redis]\nimage = \"docker.io/library/redis:7.4\"\nauto_update = false\n\
             shared_services = [\"queue\"]\n\n\
             [shared_services.queue]\nkind = \"redis\"\ninstance = \"queue-redis\"\n\n\
             [apps.queue-redis]\nimage = \"docker.io/library/redis:7.4\"\nauto_update = false\n";
        match rule(src) {
            ServiceRule::ServiceSpecOwned { field, .. } => assert_eq!(field, "shared_services"),
            rule => panic!("{rule}"),
        }
    }

    #[test]
    fn a_site_instance_is_owned_even_when_it_is_a_container() {
        // `[sites]` expands to `static` instances only, so in practice the `kind` arm fires first;
        // the `sites` arm guards the origin map itself, which this test reaches directly.
        let blog = instance("blog-prod");
        let mut a = apps(
            "[shared_services.blog]\nkind = \"redis\"\ninstance = \"blog-prod\"\n\n\
             [sites.blog]\nkind = \"static\"\nimage = \"ghcr.io/example/blog\"\n\
             [sites.blog.env.prod]\ntrack = \"main\"\n",
        );
        assert!(a.origin(&blog).is_some(), "the instance comes from [sites]");
        match check(&a).expect_err("a site instance") {
            ServiceRule::ServiceSpecOwned { field, .. } => assert_eq!(field, "kind"),
            rule => panic!("{rule}"),
        }
        a.apps.get_mut(&blog).unwrap().kind = AppKind::Container;
        match check(&a).expect_err("a site instance") {
            ServiceRule::ServiceSpecOwned { field, .. } => assert_eq!(field, "sites"),
            rule => panic!("{rule}"),
        }
    }

    #[test]
    fn a_member_naming_an_undeclared_service_is_unknown() {
        let rule = rule(&format!(
            "{DECLARED}\n[apps.worker]\nimage = \"ghcr.io/example/worker:1\"\n\
             shared_services = [\"queue\"]\n"
        ));
        assert_eq!(rule.name(), "UnknownService");
        assert!(rule.to_string().contains("worker"), "{rule}");
        assert!(rule.to_string().contains("queue"), "{rule}");
    }

    /// `check` of `cache`, `session` (both Redis) and `main` (Postgres), each with its instance, and
    /// a member `api` listing `list`.
    fn services_of_both_kinds(list: &str) -> Result<(), ServiceRule> {
        check(&apps(&format!(
            "[shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\n\
             [apps.cache-redis]\nimage = \"docker.io/library/redis:7.4\"\nauto_update = false\n\n\
             [shared_services.session]\nkind = \"redis\"\ninstance = \"session-redis\"\n\n\
             [apps.session-redis]\nimage = \"docker.io/library/redis:7.4\"\nauto_update = false\n\n\
             [shared_services.main]\nkind = \"postgres\"\ninstance = \"main-db\"\n\n\
             [apps.main-db]\nimage = \"docker.io/library/postgres:17\"\nauto_update = false\n\n\
             [apps.api]\nimage = \"ghcr.io/example/api:1\"\nshared_services = {list}\n"
        )))
    }

    #[test]
    fn a_member_uses_at_most_one_service_per_kind() {
        // One of each kind is the v1 shape.
        assert_eq!(services_of_both_kinds(r#"["cache", "main"]"#), Ok(()));
        // The same name twice is one relation written twice, not two services.
        assert_eq!(services_of_both_kinds(r#"["cache", "cache"]"#), Ok(()));
        // Two of one kind: the first pair in list order is reported.
        let rule = services_of_both_kinds(r#"["session", "main", "cache"]"#)
            .expect_err("two Redis services");
        assert_eq!(rule.name(), "TooManyServicesOfKind");
        match rule {
            ServiceRule::TooManyServicesOfKind {
                member,
                kind,
                first,
                second,
            } => {
                assert_eq!((member, kind), (instance("api"), ServiceKind::Redis));
                assert_eq!((first, second), (name("session"), name("cache")));
            }
            rule => panic!("{rule}"),
        }
    }

    #[test]
    fn the_reserved_suffixes_are_lexical_errors() {
        // A name ending in a reserved suffix would make `svc-<name>-digest`/`-pgpass` collide with
        // another service's `svc-<name>` (ADR 0079).
        for bad in ["cache-digest", "db-pgpass"] {
            assert!(ServiceName::new(bad).is_err(), "{bad} is reserved");
            assert!(
                toml::from_str::<AppsFile>(&format!(
                    "[shared_services.{bad}]\nkind = \"redis\"\ninstance = \"x\"\n"
                ))
                .is_err(),
                "{bad} parsed as a declaration key"
            );
        }
        // Only the suffix is reserved, not the word.
        for good in ["digest", "pgpass", "cache-digests", "cache-pgpasses"] {
            assert_eq!(ServiceName::new(good).unwrap().as_str(), good);
            assert!(
                toml::from_str::<AppsFile>(&format!(
                    "[shared_services.{good}]\nkind = \"redis\"\ninstance = \"x\"\n"
                ))
                .is_ok(),
                "{good} does not parse"
            );
        }
    }

    #[test]
    fn members_service_of_and_network_groups_read_the_declarations() {
        let a = apps(DECLARED);
        assert_eq!(check(&a), Ok(()));
        assert_eq!(members(&a, &name("cache")), vec![instance("api")]);
        assert!(members(&a, &name("queue")).is_empty());
        assert_eq!(
            service_of(&a, &instance("cache-redis")),
            Some(&name("cache"))
        );
        assert_eq!(service_of(&a, &instance("api")), None);

        // Both kinds of declaration own a `net-shared-<name>` group.
        let a = apps(&format!("{DECLARED}\n[shared_networks.kajet]\n"));
        let groups = network_groups(&a);
        assert_eq!(groups.len(), 2, "{groups:?}");
        for name in ["cache", "kajet"] {
            assert!(
                groups.contains(&SharedNetworkName::new(name).unwrap()),
                "{name} in {groups:?}"
            );
        }
    }

    /// The [shared service overlay](overlay) of `instance` in a parsed `apps.toml`.
    fn overlaid<'a>(apps: &'a AppsFile, instance: &InstanceName) -> Cow<'a, AppSpec> {
        overlay(
            instance,
            Cow::Borrowed(&apps.apps[instance]),
            &apps.shared_services,
        )
    }

    #[test]
    fn the_overlay_waits_for_the_service_and_joins_its_network() {
        let a = apps(DECLARED);
        let cache_net = SharedNetworkRef {
            name: name("cache").network(),
            aliases: Vec::new(),
        };
        let member = overlaid(&a, &instance("api"));
        assert_eq!(member.depends_on, vec![instance("cache-redis")]);
        assert_eq!(member.shared_networks, vec![cache_net.clone()]);

        // The service instance joins its own network and waits for nobody.
        let service = overlaid(&a, &instance("cache-redis"));
        assert!(service.depends_on.is_empty());
        assert_eq!(service.shared_networks, vec![cache_net]);
    }

    #[test]
    fn an_instance_outside_every_service_keeps_its_spec_borrowed() {
        // The hash of such an app must not move because a declaration exists elsewhere.
        let a = apps(&format!("{DECLARED}\n[apps.ntfy]\nimage = \"x:1\"\n"));
        assert!(matches!(overlaid(&a, &instance("ntfy")), Cow::Borrowed(_)));
    }

    #[test]
    fn the_overlay_does_not_repeat_a_dependency_already_listed() {
        let a = apps(&format!(
            "{DECLARED}\n[apps.worker]\nimage = \"x:1\"\n\
             shared_services = [\"cache\"]\ndepends_on = [\"cache-redis\"]\n"
        ));
        let worker = overlaid(&a, &instance("worker"));
        assert_eq!(worker.depends_on, vec![instance("cache-redis")]);
    }

    #[test]
    fn a_member_of_two_services_joins_both_networks() {
        // v1 rejects this in `check` (`TooManyServicesOfKind`), but the overlay is a pure fold and
        // the reserved table form (#593) will allow it: every relation is laid over.
        let a = apps(&format!(
            "{DECLARED}\n[shared_services.main]\nkind = \"postgres\"\ninstance = \"main-db\"\n\n\
             [apps.main-db]\nimage = \"docker.io/library/postgres:17\"\nauto_update = false\n\n\
             [apps.worker]\nimage = \"x:1\"\nshared_services = [\"cache\", \"main\"]\n"
        ));
        let worker = overlaid(&a, &instance("worker"));
        let networks: Vec<&str> = worker
            .shared_networks
            .iter()
            .map(|net| net.name.as_str())
            .collect();
        assert_eq!(networks, ["cache", "main"]);
        assert_eq!(worker.depends_on.len(), 2);
    }

    #[test]
    fn an_existing_network_group_stays_first() {
        // The overlay appends, it never reorders what the operator wrote: the app's own group and
        // the service network coexist (a container may join several shared networks, ADR 0079).
        let a = apps(
            "[shared_networks.kajet]\n\n\
             [shared_services.cache]\nkind = \"redis\"\ninstance = \"cache-redis\"\n\n\
             [apps.cache-redis]\nimage = \"docker.io/library/redis:7.4\"\nauto_update = false\n\n\
             [apps.api]\nimage = \"x:1\"\nshared_networks = [\"kajet\"]\n\
             shared_services = [\"cache\"]\n",
        );
        let api = overlaid(&a, &instance("api"));
        let networks: Vec<&str> = api
            .shared_networks
            .iter()
            .map(|net| net.name.as_str())
            .collect();
        assert_eq!(networks, ["kajet", "cache"]);
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

    /// What a contract fixture's `"result"` asks of the model. The names are the contracts'
    /// rejection names (#593, #596), so a fixture is checked by name (`ServiceRule::name`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Expected {
        /// A rule of [`check`].
        Rule(&'static str),
        /// A lexical value error: `apps.toml` does not parse, because the value has its own type
        /// (`InvalidMaxmemory`, #593).
        Parse(&'static str),
        /// Not a model rule: `"valid"`, a kind-specific rejection of a later PR (#593/#596), or an
        /// operation (`ServiceHasMembers`). `check` passes; the rollout gate still rejects it.
        Gate,
    }

    /// Every `apps_toml` of the "Fixture files" JSON of the managed-Redis contract (#593), by case
    /// name and with the `"result"` it expects. The shared-model rules run in `check`; everything
    /// else is a later PR, so the fixture stops at the per-kind gate.
    const CONTRACT_FIXTURES: &[(&str, &str, Expected)] = &[
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
            Expected::Gate,
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
            Expected::Gate,
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
            Expected::Rule("NameTaken"),
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
            Expected::Rule("UnknownInstance"),
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
            Expected::Rule("UnknownService"),
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
            Expected::Rule("ServiceSpecOwned"),
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
            Expected::Rule("ServiceSpecOwned"),
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
            Expected::Rule("ServiceSpecOwned"),
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
            Expected::Rule("ServiceIsMember"),
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
            Expected::Gate,
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
            Expected::Gate,
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
            Expected::Gate,
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
            Expected::Parse("InvalidMaxmemory"),
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
            Expected::Rule("TooManyServicesOfKind"),
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
            Expected::Gate,
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
            Expected::Gate,
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
            Expected::Gate,
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
            Expected::Gate,
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
            Expected::Gate,
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
            Expected::Gate,
        ),
    ];

    /// Every `apps_toml` of the "Fixture files" JSON of the managed-Postgres contract (#596), in
    /// the same shape. The Postgres kind is gated too, so the kind-specific rejections stop at the
    /// gate here.
    const POSTGRES_FIXTURES: &[(&str, &str, Expected)] = &[
        (
            "main-two-members",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["main"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["main"]
"#,
            Expected::Gate,
        ),
        (
            "main-no-members",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]
"#,
            Expected::Gate,
        ),
        (
            "requires-data-volume",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
"#,
            Expected::Gate,
        ),
        (
            "reserved-name",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]

[apps.postgres]
image = "ghcr.io/example/api:1"
shared_services = ["main"]
"#,
            Expected::Gate,
        ),
        (
            "service-spec-owned-command",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]
command = ["postgres", "-c", "hba_file=/tmp/open.conf"]
"#,
            Expected::Rule("ServiceSpecOwned"),
        ),
        (
            "service-spec-owned-domains",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]
domains = ["db.example.com"]
"#,
            Expected::Rule("ServiceSpecOwned"),
        ),
        (
            "unknown-instance",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["main"]
"#,
            Expected::Rule("UnknownInstance"),
        ),
        (
            "service-has-members",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["main"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["main"]
"#,
            Expected::Gate,
        ),
        (
            "missing-credential",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["main"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["main"]
"#,
            Expected::Gate,
        ),
        (
            "unsupported-server-version",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:14"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]
"#,
            Expected::Gate,
        ),
        (
            "too-many-services-of-kind",
            r#"[shared_services.main]
kind = "postgres"
instance = "main-db"

[apps.main-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["main"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["main"]

[shared_services.other]
kind = "postgres"
instance = "other-db"

[apps.other-db]
image = "docker.io/library/postgres:17"
auto_update = false
volumes = [{ name = "data", target = "/var/lib/postgresql/data" }]

[apps.reporter]
image = "ghcr.io/example/reporter:1"
shared_services = ["main", "other"]
"#,
            Expected::Rule("TooManyServicesOfKind"),
        ),
    ];

    #[test]
    fn every_contract_fixture_gets_the_result_its_contract_names() {
        let mut cases = 0;
        for (contract, fixtures) in [
            ("managed-redis-v1", CONTRACT_FIXTURES),
            ("managed-postgres-v1", POSTGRES_FIXTURES),
        ] {
            for (case, src, expected) in fixtures {
                let case = format!("{contract}/{case}");
                let expected = *expected;
                let parsed = toml::from_str::<AppsFile>(src);
                match expected {
                    Expected::Parse(rule) => {
                        // The only table entry that is a parse error: `InvalidMaxmemory` has its own
                        // type, so the fixture never reaches a rule (#593).
                        assert_eq!(rule, "InvalidMaxmemory", "{case}");
                        let err = parsed.expect_err(&case).to_string();
                        assert!(err.contains("invalid maxmemory"), "{case}: {err}");
                    }
                    Expected::Rule(rule) => {
                        let parsed = parsed.unwrap_or_else(|err| panic!("{case}: {err}"));
                        assert_eq!(check(&parsed).expect_err(&case).name(), rule, "{case}");
                    }
                    Expected::Gate => {
                        let parsed = parsed.unwrap_or_else(|err| panic!("{case}: {err}"));
                        assert_eq!(check(&parsed), Ok(()), "{case}");
                        let err = validate(&parsed).expect_err(&case);
                        assert!(err.contains(GATE), "{case}: {err}");
                    }
                }
                cases += 1;
            }
        }
        // 20 cases of the Redis contract and 11 of the Postgres contract, each with an
        // `apps_toml`.
        assert_eq!(cases, 31);
    }
}
