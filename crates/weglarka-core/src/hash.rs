//! `spec_hash` — spec fingerprint that decides whether the container is recreated.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::app::{AppSpec, Digest, Resources, SecretBinding, VolumeMount};

/// Version of the hash input format; bump when fields change (forces recreate of all instances).
const HASH_FORMAT: &str = "weglarka.spec-hash/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpecHash(String);

impl SpecHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SpecHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Only fields that affect the container. `domains` and the gate's timing/HTTP probe are deliberately
/// omitted — changing routing or the gate does not require recreating the container. The struct's
/// field order is part of the format.
///
/// Iteration 2 fields (`volumes`, `resources`, `health_command`) are appended and skipped while unset,
/// so a spec that does not use them hashes exactly as before (`HASH_FORMAT` stays v1 and existing
/// instances are not recreated by upgrading Węglarka).
#[derive(Serialize)]
struct HashInput<'a> {
    format: &'static str,
    image_digest: &'a Digest,
    port: Option<u16>,
    env: &'a BTreeMap<String, String>,
    secrets: Vec<&'a SecretBinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    volumes: Vec<&'a VolumeMount>,
    #[serde(skip_serializing_if = "Resources::is_unlimited")]
    resources: &'a Resources,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_command: Option<&'a Vec<String>>,
}

/// Deterministic hash of the spec + the pinned image digest (hex SHA-256).
pub fn spec_hash(spec: &AppSpec, image_digest: &Digest) -> SpecHash {
    let mut secrets: Vec<&SecretBinding> = spec.secrets.iter().collect();
    secrets.sort_by(|a, b| {
        (
            &a.secret,
            serde_json::to_string(&a.target).unwrap_or_default(),
        )
            .cmp(&(
                &b.secret,
                serde_json::to_string(&b.target).unwrap_or_default(),
            ))
    });
    let mut volumes: Vec<&VolumeMount> = spec.volumes.iter().collect();
    volumes.sort_by(|a, b| (&a.name, &a.target).cmp(&(&b.name, &b.target)));
    let input = HashInput {
        format: HASH_FORMAT,
        image_digest,
        port: spec.port,
        env: &spec.env,
        secrets,
        volumes,
        resources: &spec.resources,
        health_command: spec.health.command.as_ref(),
    };
    let json = serde_json::to_vec(&input).expect("hash input is always serializable");
    SpecHash(hex::encode(Sha256::digest(json)))
}

/// Like [`spec_hash`], but also mixes in secret value fingerprints (`binding name → fingerprint`),
/// so a secret change changes the hash and forces a container recreate. With an empty map the
/// result is identical to [`spec_hash`] (format v1 stays stable when recreate-on-secret-change is
/// disabled).
pub fn spec_hash_with_secrets(
    spec: &AppSpec,
    image_digest: &Digest,
    fingerprints: &BTreeMap<String, String>,
) -> SpecHash {
    let base = spec_hash(spec, image_digest);
    if fingerprints.is_empty() {
        return base;
    }
    let json = serde_json::to_vec(&(base.as_str(), "secrets", fingerprints))
        .expect("hash input is always serializable");
    SpecHash(hex::encode(Sha256::digest(json)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::SecretTarget;

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn spec() -> AppSpec {
        toml::from_str(
            r#"
image = "ghcr.io/x/y:latest"
domains = ["a.example"]
port = 8080
env = { B = "2", A = "1" }
"#,
        )
        .unwrap()
    }

    #[test]
    fn golden_value_is_stable() {
        // Changing this hash = changing the format = recreate of all containers. Deliberate.
        insta::assert_snapshot!(spec_hash(&spec(), &digest('a')));
    }

    /// Upgrading Węglarka must not recreate existing instances: a spec without any iteration 2 field
    /// hashes exactly as the pre-iteration-2 input did (reconstructed here by hand).
    #[test]
    fn unset_iteration2_fields_do_not_change_the_hash() {
        #[derive(Serialize)]
        struct LegacyInput<'a> {
            format: &'static str,
            image_digest: &'a Digest,
            port: Option<u16>,
            env: &'a BTreeMap<String, String>,
            secrets: Vec<&'a SecretBinding>,
        }
        let s = spec();
        let d = digest('a');
        let legacy = LegacyInput {
            format: HASH_FORMAT,
            image_digest: &d,
            port: s.port,
            env: &s.env,
            secrets: vec![],
        };
        let expected = hex::encode(Sha256::digest(serde_json::to_vec(&legacy).unwrap()));
        assert_eq!(spec_hash(&s, &d).as_str(), expected);
    }

    #[test]
    fn iteration2_fields_change_the_hash_only_when_they_matter() {
        let base = spec_hash(&spec(), &digest('a'));
        let hash = |f: &dyn Fn(&mut AppSpec)| {
            let mut s = spec();
            f(&mut s);
            spec_hash(&s, &digest('a'))
        };
        let vol = |name: &str| VolumeMount {
            name: name.into(),
            target: "/data".into(),
            read_only: false,
        };
        assert_ne!(base, hash(&|s| s.volumes.push(vol("data"))));
        assert_ne!(
            hash(&|s| s.volumes.push(vol("data"))),
            hash(&|s| s.volumes.push(vol("other")))
        );
        assert_ne!(
            base,
            hash(&|s| s.resources.pids_limit = Some(100)),
            "limits are container settings"
        );
        assert_ne!(
            base,
            hash(&|s| s.health.command = Some(vec!["/app".into(), "-health".into()]))
        );
        // Daemon-side gate settings never recreate the container.
        assert_eq!(
            base,
            hash(&|s| s.health.http = Some(crate::app::HttpProbe::default()))
        );
    }

    #[test]
    fn deterministic_and_order_independent() {
        let a = spec();
        let mut b = spec();
        b.env = [
            ("A".to_owned(), "1".to_owned()),
            ("B".to_owned(), "2".to_owned()),
        ]
        .into();
        assert_eq!(spec_hash(&a, &digest('a')), spec_hash(&b, &digest('a')));
    }

    #[test]
    fn sensitive_to_runtime_fields_only() {
        let base = spec_hash(&spec(), &digest('a'));
        assert_ne!(base, spec_hash(&spec(), &digest('b')));

        let mut s = spec();
        s.env.insert("C".into(), "3".into());
        assert_ne!(base, spec_hash(&s, &digest('a')));

        let mut s = spec();
        s.secrets.push(SecretBinding {
            secret: "k".into(),
            target: SecretTarget::Env { var: "K".into() },
        });
        assert_ne!(base, spec_hash(&s, &digest('a')));

        let mut s = spec();
        s.domains.push("b.example".into());
        s.health.attempts = 9;
        s.auto_update = false;
        assert_eq!(base, spec_hash(&s, &digest('a')));
    }

    #[test]
    fn secret_fingerprints_change_hash_only_when_present() {
        let base = spec_hash(&spec(), &digest('a'));
        let none = BTreeMap::new();
        assert_eq!(base, spec_hash_with_secrets(&spec(), &digest('a'), &none));
        let one = BTreeMap::from([("k".to_owned(), "aaaa".to_owned())]);
        let two = BTreeMap::from([("k".to_owned(), "bbbb".to_owned())]);
        let h1 = spec_hash_with_secrets(&spec(), &digest('a'), &one);
        assert_ne!(base, h1);
        assert_ne!(h1, spec_hash_with_secrets(&spec(), &digest('a'), &two));
    }
}
