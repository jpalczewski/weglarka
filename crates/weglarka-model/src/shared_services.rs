//! Shared services (issue #590, managed Redis contract v1 in #593, Postgres in #596): an app
//! instance that Węglarka runs as a service for other instances, its members.
//!
//! A service is declared once in `[shared_services.<name>]` and joined by apps through
//! `AppSpec::shared_services`; the identity provider joins one through `[identity] session_store`.
//! This module holds the types, their lexical rules and the rollout gate: every declaration and
//! every membership is rejected with [`GATE`] until the PR of each kind lifts it.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::{AppsFile, InstanceName};

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
    "invalid shared service name {0:?}: expected 1-63 chars of [a-z0-9-], no leading/trailing '-'"
)]
pub struct InvalidServiceName(pub String);

impl ServiceName {
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidServiceName> {
        let name = name.into();
        // The same alphabet as an instance name; reuse it instead of repeating the rule.
        match InstanceName::new(name.clone()) {
            Ok(_) => Ok(Self(name)),
            Err(_) => Err(InvalidServiceName(name)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Maxmemory(String);

#[derive(Debug, thiserror::Error)]
#[error("invalid maxmemory {0:?}: {1}")]
pub struct InvalidMaxmemory(pub String, pub &'static str);

impl Maxmemory {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidMaxmemory> {
        let value = value.into();
        // TODO(#590 A): the lexical rule.
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

/// Checks the shared-service declarations and memberships of `apps.toml`, on every load and save.
///
/// Gate (#590): any declaration and any non-empty `AppSpec::shared_services` is rejected.
pub fn validate(apps: &AppsFile) -> Result<(), String> {
    // TODO(#590 A): the gate.
    let _ = apps;
    Ok(())
}
