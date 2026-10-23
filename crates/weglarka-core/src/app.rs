//! Model apki: `AppSpec` (stan pożądany instancji) i typy pomocnicze.
//! Format zapisu: sekcje `[apps.<instancja>]` w `apps.toml` (jedyny pisarz: demon).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Nazwa instancji (klucz w `apps.toml`). Instancja ≠ obraz: jeden obraz może mieć wiele instancji.
/// Dozwolone `[a-z0-9-]`, 1–63 znaki, bez myślnika na brzegach (bezpieczne jako nazwa kontenera,
/// sieci i hosta DNS oraz jako element nazwy sekretu).
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

/// Digest obrazu w postaci `sha256:<64 hex>`.
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

/// Jak sekret trafia do kontenera (Podman secrets typu `env` albo `mount`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretTarget {
    /// Zmienna środowiskowa o podanej nazwie.
    Env { var: String },
    /// Plik w kontenerze (np. `config.json`).
    Mount {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
    },
}

/// Powiązanie sekretu (nazwa w `SecretStore`, zakres: instancja) z kontenerem.
/// Brak `deny_unknown_fields` na tym poziomie (serde nie łączy tego z `flatten`); literówki
/// wyłapuje `deny_unknown_fields` na [`SecretTarget`], do którego spływają pozostałe pola.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBinding {
    pub secret: String,
    #[serde(flatten)]
    pub target: SecretTarget,
}

/// Bramka zdrowia po deployu: nowy kontener musi być running (i healthy, jeśli obraz ma
/// healthcheck) — do `attempts` prób `healthcheck run` w oknie `window_secs`; inaczej rollback.
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

/// Stan pożądany jednej instancji.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSpec {
    /// Referencja obrazu (ruchomy tag, np. `ghcr.io/jpalczewski/ntfy.zig:latest`).
    /// Stan przypina rozwiązany digest; patrz [`crate::state::AppState`].
    pub image: String,
    /// Domeny kierowane do apki (generatory ingressu).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Port HTTP w kontenerze, na który proxuje ingress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Jawne zmienne środowiskowe (bez wartości tajnych).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: Vec<SecretBinding>,
    #[serde(default)]
    pub health: HealthGate,
    /// `false` — webhook/reconcile nie podmienia obrazu samoczynnie.
    #[serde(default = "default_true")]
    pub auto_update: bool,
}

fn default_true() -> bool {
    true
}

/// Zawartość `apps.toml`.
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
