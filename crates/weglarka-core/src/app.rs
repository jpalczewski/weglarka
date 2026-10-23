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

/// Post-deploy health gate: the new container must be running (and healthy, if the image has a
/// healthcheck) — up to `attempts` tries of `healthcheck run` within `window_secs`; otherwise rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthGate {
    #[serde(default = "HealthGate::default_attempts")]
    pub attempts: u32,
    #[serde(default = "HealthGate::default_window_secs")]
    pub window_secs: u64,
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
        }
    }
}

/// Desired state of a single instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSpec {
    /// Image reference (floating tag, e.g. `ghcr.io/jpalczewski/ntfy.zig:latest`).
    /// State pins the resolved digest; see [`crate::state::AppState`].
    pub image: String,
    /// Domains routed to the app (ingress generators).
    #[serde(default)]
    pub domains: Vec<String>,
    /// HTTP port in the container that ingress proxies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Plain environment variables (no secret values).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Vec<SecretBinding>,
    #[serde(default)]
    pub health: HealthGate,
    /// `false` — webhook/reconcile does not swap the image on its own.
    #[serde(default = "default_true")]
    pub auto_update: bool,
}

fn default_true() -> bool {
    true
}

/// Contents of `apps.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppsFile {
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
}
