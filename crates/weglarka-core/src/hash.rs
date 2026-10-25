//! `spec_hash` — spec fingerprint that decides whether the container is recreated.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::app::{AppSpec, ConfigMount, Digest, Resources, SecretBinding, Security, VolumeMount};

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

/// Only fields that affect the container. `domains`, `paths` (issue #130), the per-app ingress options
/// (`streaming`/`stream_timeout_secs`, issue #64) and the gate's timing/HTTP probe are deliberately
/// omitted — changing routing or the gate does not require recreating the container. `start` (run vs
/// provision-only intent) is omitted as well: it controls whether a container exists, not what it is
/// made of. `depends_on` is omitted for the same reason: it is a start order between apps, so editing
/// it never recreates a container (issue #35). The struct's field order is part of the format.
///
/// Iteration 2 fields (`volumes`, `resources`, `health_command`) are appended and skipped while unset,
/// so a spec that does not use them hashes exactly as before (`HASH_FORMAT` stays v1 and existing
/// instances are not recreated by upgrading Węglarka). `command` (issue #79) is appended for the same
/// reason: an app that does not set it keeps its hash, a change to it recreates the container.
/// `configs` (issue #118, `docs/decisions/0028-config-root-mounts.md`) is appended last the same way:
/// the **list** of host config mounts is a container setting, while the file content is deliberately
/// outside the hash — editing a config must not recreate the container. `reload_signal` is omitted
/// entirely: it only affects `apps reload`, never what the container is made of.
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
    /// Appended after iteration 2 the same way: skipped while the app sets no hardening.
    #[serde(skip_serializing_if = "Security::is_default")]
    security: &'a Security,
    /// Ports published on the host are container settings, so a change recreates the container.
    /// Normalized to the effective bind address and sorted (their order in the spec is not
    /// meaningful), and skipped while empty so existing instances keep their hash.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    host_ports: Vec<HashHostPort<'a>>,
    /// Shared-volume mounts (issue #33): the mount is a container setting, so a change recreates the
    /// container. Appended after `host_ports` and skipped while empty, so an app without shared
    /// volumes hashes exactly as before (the format version stays v1).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    shared_volumes: Vec<HashSharedVolume<'a>>,
    /// Shared-network membership (issue #128): it changes the container's networks, so a change
    /// recreates the container. Appended after `shared_volumes` and skipped while empty, so an app
    /// outside any group hashes exactly as before (the format version stays v1).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    shared_networks: Vec<HashSharedNetwork<'a>>,
    /// The container's command (issue #79): arguments to the image's entrypoint, so a change — the
    /// argument order included — recreates the container. Appended last and skipped while empty, so
    /// an app without a command hashes exactly as before (the format version stays v1).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    command: &'a Vec<String>,
    /// Host config mounts (issue #118): the list — source and target — is a container setting, so a
    /// change recreates the container; the content is deliberately outside the hash. Sorted (the
    /// order in the spec is not meaningful) and skipped while empty, so an app without configs hashes
    /// exactly as before (the format version stays v1).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    configs: Vec<&'a ConfigMount>,
    /// Host mounts (issue #178): the allowlisted source and the target are container settings.
    /// Sorted and skipped while empty, so an app without them hashes exactly as before.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    host_mounts: Vec<&'a crate::app::HostMount>,
    /// Requested supplementary groups (issue #178); sorted, skipped while empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    group_add: Vec<&'a str>,
}

/// One shared-volume mount as it enters the hash: the volume name and the mount point.
#[derive(Serialize)]
struct HashSharedVolume<'a> {
    name: &'a crate::app::SharedVolumeName,
    target: &'a str,
    read_only: bool,
}

/// One shared-network membership as it enters the hash: the network and the sorted extra aliases
/// (their order in the spec is not meaningful).
#[derive(Serialize)]
struct HashSharedNetwork<'a> {
    name: &'a crate::app::SharedNetworkName,
    aliases: Vec<&'a str>,
}

/// One `host_ports` entry as it enters the hash: the effective address (loopback when the spec names
/// none) instead of `Option`, so `ip = "127.0.0.1"` and an omitted `ip` hash the same.
#[derive(Serialize)]
struct HashHostPort<'a> {
    ip: &'a str,
    host: u16,
    container: u16,
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
    let mut host_ports: Vec<HashHostPort> = spec
        .host_ports
        .iter()
        .map(|p| HashHostPort {
            ip: p.bind_ip(),
            host: p.host,
            container: p.container,
        })
        .collect();
    host_ports.sort_by(|a, b| (a.ip, a.host, a.container).cmp(&(b.ip, b.host, b.container)));
    let mut shared_volumes: Vec<HashSharedVolume> = spec
        .shared_volumes
        .iter()
        .map(|v| HashSharedVolume {
            name: &v.name,
            target: &v.target,
            read_only: v.read_only,
        })
        .collect();
    shared_volumes
        .sort_by(|a, b| (&a.name, &a.target, a.read_only).cmp(&(&b.name, &b.target, b.read_only)));
    let mut configs: Vec<&ConfigMount> = spec.configs.iter().collect();
    configs.sort_by(|a, b| (&a.source, &a.target).cmp(&(&b.source, &b.target)));
    let mut host_mounts: Vec<&crate::app::HostMount> = spec.host_mounts.iter().collect();
    host_mounts.sort_by(|a, b| (&a.source, &a.target).cmp(&(&b.source, &b.target)));
    let mut group_add: Vec<&str> = spec.group_add.iter().map(String::as_str).collect();
    group_add.sort_unstable();
    group_add.dedup();
    let mut shared_networks: Vec<HashSharedNetwork> = spec
        .shared_networks
        .iter()
        .map(|n| {
            let mut aliases: Vec<&str> = n.aliases.iter().map(String::as_str).collect();
            aliases.sort_unstable();
            aliases.dedup();
            HashSharedNetwork {
                name: &n.name,
                aliases,
            }
        })
        .collect();
    shared_networks.sort_by(|a, b| a.name.cmp(b.name));
    let input = HashInput {
        format: HASH_FORMAT,
        image_digest,
        port: spec.port,
        env: &spec.env,
        secrets,
        volumes,
        resources: &spec.resources,
        health_command: spec.health.command.as_ref(),
        security: &spec.security,
        host_ports,
        shared_volumes,
        shared_networks,
        command: &spec.command,
        configs,
        host_mounts,
        group_add,
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

    /// `start` toggles "should run" vs "provisioned only"; it must never recreate the container.
    #[test]
    fn start_does_not_change_the_hash() {
        let running = spec();
        let mut stopped = running.clone();
        stopped.start = false;
        assert_eq!(
            spec_hash(&running, &digest('a')),
            spec_hash(&stopped, &digest('a'))
        );
    }

    /// `depends_on` is a start order between apps, not a container setting (issue #35).
    #[test]
    fn depends_on_does_not_change_the_hash() {
        let base = spec();
        let mut dependent = base.clone();
        dependent.depends_on = vec![crate::app::InstanceName::new("db").unwrap()];
        assert_eq!(
            spec_hash(&base, &digest('a')),
            spec_hash(&dependent, &digest('a'))
        );
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
        assert_ne!(
            base,
            hash(&|s| s.security.read_only = true),
            "hardening is a container setting"
        );
        assert_eq!(
            base,
            hash(&|s| s.security = crate::app::Security::default()),
            "no hardening hashes as before"
        );
        // Daemon-side gate settings never recreate the container.
        assert_eq!(
            base,
            hash(&|s| s.health.http = Some(crate::app::HttpProbe::default()))
        );
    }

    #[test]
    fn command_changes_the_hash_only_when_set() {
        let base = spec_hash(&spec(), &digest('a'));
        let hash = |command: &[&str]| {
            let mut s = spec();
            s.command = command.iter().map(|a| (*a).to_owned()).collect();
            spec_hash(&s, &digest('a'))
        };
        // Unset (and an explicitly empty list) is the image's own CMD: no recreate on upgrade.
        assert_eq!(base, hash(&[]));
        assert_ne!(
            base,
            hash(&["serve"]),
            "the command changes what runs, so it recreates the container"
        );
        // The argument vector is ordered, unlike the set-like lists.
        assert_ne!(hash(&["serve", "-v"]), hash(&["-v", "serve"]));
        // Clearing it returns to the base hash: the image default is restored by a recreate.
        assert_eq!(base, hash(&[]));
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
        s.ingress = crate::app::AppIngress {
            streaming: true,
            stream_timeout_secs: 600,
            strip_prefix: true,
            max_body_size: Some(crate::app::BodySizeLimit::UNLIMITED),
            access_log_skip_paths: vec!["/healthz".into()],
        };
        s.paths = vec!["/api".into()];
        assert_eq!(
            base,
            spec_hash(&s, &digest('a')),
            "ingress options and paths (issues #64, #130, #181, ADR 0033) only re-render nginx"
        );
    }

    #[test]
    fn host_ports_are_container_settings() {
        use crate::app::HostPort;
        let base = spec_hash(&spec(), &digest('a'));
        let hash = |f: &dyn Fn(&mut AppSpec)| {
            let mut s = spec();
            f(&mut s);
            spec_hash(&s, &digest('a'))
        };
        let port = |host: u16, container: u16, ip: Option<&str>| HostPort {
            host,
            container,
            ip: ip.map(ToOwned::to_owned),
        };
        assert_eq!(base, hash(&|_| {}), "no host ports hashes as before");
        assert_ne!(base, hash(&|s| s.host_ports.push(port(2222, 22, None))));
        assert_ne!(
            hash(&|s| s.host_ports.push(port(2222, 22, None))),
            hash(&|s| s.host_ports.push(port(2222, 23, None))),
            "the container port is part of the mapping"
        );
        assert_ne!(
            hash(&|s| s.host_ports.push(port(2222, 22, None))),
            hash(&|s| s.host_ports.push(port(2223, 22, None)))
        );
        // The omitted address means loopback, so spelling it out must not recreate the container.
        assert_eq!(
            hash(&|s| s.host_ports.push(port(2222, 22, None))),
            hash(&|s| s.host_ports.push(port(2222, 22, Some("127.0.0.1"))))
        );
        assert_ne!(
            hash(&|s| s.host_ports.push(port(2222, 22, None))),
            hash(&|s| s.host_ports.push(port(2222, 22, Some("0.0.0.0")))),
            "exposing the port is a different container"
        );
        // Order in the spec is not meaningful.
        let a = hash(&|s| {
            s.host_ports.push(port(2222, 22, None));
            s.host_ports.push(port(2223, 22, Some("10.0.0.5")));
        });
        let b = hash(&|s| {
            s.host_ports.push(port(2223, 22, Some("10.0.0.5")));
            s.host_ports.push(port(2222, 22, None));
        });
        assert_eq!(a, b);
    }

    #[test]
    fn shared_volume_mounts_are_container_settings() {
        use crate::app::{SharedVolumeName, SharedVolumeRef};
        let base = spec_hash(&spec(), &digest('a'));
        let hash = |f: &dyn Fn(&mut AppSpec)| {
            let mut s = spec();
            f(&mut s);
            spec_hash(&s, &digest('a'))
        };
        let mount = |name: &str, target: &str, read_only: bool| SharedVolumeRef {
            name: SharedVolumeName::new(name).unwrap(),
            target: target.into(),
            read_only,
        };
        assert_eq!(base, hash(&|_| {}), "no shared mounts hashes as before");
        assert_ne!(
            base,
            hash(&|s| s.shared_volumes.push(mount("data", "/data", false)))
        );
        assert_ne!(
            hash(&|s| s.shared_volumes.push(mount("data", "/data", false))),
            hash(&|s| s.shared_volumes.push(mount("other", "/data", false))),
            "the volume name is part of the mount"
        );
        assert_ne!(
            hash(&|s| s.shared_volumes.push(mount("data", "/data", false))),
            hash(&|s| s.shared_volumes.push(mount("data", "/cache", false)))
        );
        assert_ne!(
            hash(&|s| s.shared_volumes.push(mount("data", "/data", false))),
            hash(&|s| s.shared_volumes.push(mount("data", "/data", true)))
        );
        // The order in the spec is not meaningful.
        let a = hash(&|s| {
            s.shared_volumes.push(mount("a", "/a", false));
            s.shared_volumes.push(mount("b", "/b", true));
        });
        let b = hash(&|s| {
            s.shared_volumes.push(mount("b", "/b", true));
            s.shared_volumes.push(mount("a", "/a", false));
        });
        assert_eq!(a, b);
    }

    #[test]
    fn shared_network_membership_is_a_container_setting() {
        use crate::app::{SharedNetworkName, SharedNetworkRef};
        let base = spec_hash(&spec(), &digest('a'));
        let hash = |f: &dyn Fn(&mut AppSpec)| {
            let mut s = spec();
            f(&mut s);
            spec_hash(&s, &digest('a'))
        };
        let join = |name: &str, aliases: &[&str]| SharedNetworkRef {
            name: SharedNetworkName::new(name).unwrap(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
        };
        assert_eq!(base, hash(&|_| {}), "no membership hashes as before");
        assert_ne!(base, hash(&|s| s.shared_networks.push(join("g", &[]))));
        assert_ne!(
            hash(&|s| s.shared_networks.push(join("g", &[]))),
            hash(&|s| s.shared_networks.push(join("h", &[]))),
            "the group is part of the membership"
        );
        assert_ne!(
            hash(&|s| s.shared_networks.push(join("g", &[]))),
            hash(&|s| s.shared_networks.push(join("g", &["web"]))),
            "an alias changes how the container is found"
        );
        // The order of the aliases is not meaningful.
        assert_eq!(
            hash(&|s| s.shared_networks.push(join("g", &["a", "b"]))),
            hash(&|s| s.shared_networks.push(join("g", &["b", "a"])))
        );
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

    /// `configs` (issue #118): the list of mounts is a container setting, the content and
    /// `reload_signal` are not. An app without configs keeps its hash (the golden value above).
    #[test]
    fn configs_are_container_settings_but_reload_signal_is_not() {
        let base = spec_hash(&spec(), &digest('a'));
        let hash = |f: &dyn Fn(&mut AppSpec)| {
            let mut s = spec();
            f(&mut s);
            spec_hash(&s, &digest('a'))
        };
        let mount = |source: &str, target: &str| ConfigMount {
            source: source.into(),
            target: target.into(),
        };
        assert_eq!(base, hash(&|_| {}), "no configs hashes as before");
        assert_ne!(base, hash(&|s| s.configs.push(mount("a.yml", "/a.yml"))));
        assert_ne!(
            hash(&|s| s.configs.push(mount("a.yml", "/a.yml"))),
            hash(&|s| s.configs.push(mount("b.yml", "/a.yml"))),
            "the source is part of the mount"
        );
        assert_ne!(
            hash(&|s| s.configs.push(mount("a.yml", "/a.yml"))),
            hash(&|s| s.configs.push(mount("a.yml", "/etc/a.yml"))),
            "the container target is part of the mount"
        );
        // The order in the spec is not meaningful.
        let a = hash(&|s| {
            s.configs.push(mount("a.yml", "/a.yml"));
            s.configs.push(mount("dir", "/dir"));
        });
        let b = hash(&|s| {
            s.configs.push(mount("dir", "/dir"));
            s.configs.push(mount("a.yml", "/a.yml"));
        });
        assert_eq!(a, b);
        // `reload_signal` only affects `apps reload`, so it must not recreate the container.
        let mut s = spec();
        s.reload_signal = Some("SIGHUP".into());
        assert_eq!(base, spec_hash(&s, &digest('a')));
    }

    #[test]
    fn host_mounts_are_container_settings_and_absent_ones_hash_as_before() {
        let base = spec_hash(&spec(), &digest('a'));
        let with = |source: &str, target: &str| {
            let mut s = spec();
            s.host_mounts.push(crate::app::HostMount {
                source: source.into(),
                target: target.into(),
            });
            spec_hash(&s, &digest('a'))
        };
        assert_ne!(base, with("/var/log/journal", "/var/log/journal"));
        assert_ne!(
            with("/var/log/journal", "/j"),
            with("/run/log/journal", "/j"),
            "the source is part of the mount"
        );
        assert_ne!(with("/etc/machine-id", "/a"), with("/etc/machine-id", "/b"));
    }

    #[test]
    fn group_add_recreates_but_order_and_absence_do_not() {
        let base = spec_hash(&spec(), &digest('a'));
        let with = |groups: &[&str]| {
            let mut s = spec();
            s.group_add = groups.iter().map(|g| (*g).to_owned()).collect();
            spec_hash(&s, &digest('a'))
        };
        assert_eq!(base, with(&[]));
        assert_ne!(base, with(&["systemd-journal"]));
        assert_eq!(
            with(&["adm", "systemd-journal"]),
            with(&["systemd-journal", "adm"])
        );
    }

    fn mounting(uid: Option<u32>, gid: Option<u32>) -> AppSpec {
        let mut s = spec();
        s.secrets = vec![SecretBinding {
            secret: "cfg".into(),
            target: SecretTarget::Mount {
                path: "/config.json".into(),
                mode: Some(0o400),
                uid,
                gid,
            },
        }];
        s
    }

    /// Issue #55: `uid`/`gid` are new optional fields of a mount binding. While unset they are
    /// skipped, so the binding enters the hash exactly as before the feature (`HASH_FORMAT` stays
    /// v1) and upgrading Węglarka recreates no container. `LegacyInput` mirrors the pre-feature
    /// `HashInput` for a spec whose other optional fields are all unset (like `spec()`).
    #[test]
    fn unset_secret_mount_ownership_does_not_change_the_hash() {
        #[derive(Serialize)]
        struct LegacyInput<'a> {
            format: &'static str,
            image_digest: &'a Digest,
            port: Option<u16>,
            env: &'a BTreeMap<String, String>,
            secrets: Vec<&'a SecretBinding>,
        }
        let s = mounting(None, None);
        let d = digest('a');
        let legacy = LegacyInput {
            format: HASH_FORMAT,
            image_digest: &d,
            port: s.port,
            env: &s.env,
            secrets: s.secrets.iter().collect(),
        };
        let expected = hex::encode(Sha256::digest(serde_json::to_vec(&legacy).unwrap()));
        assert_eq!(spec_hash(&s, &d).as_str(), expected);
    }

    /// Ownership is applied when the container is created (`MountSecret.UID`/`GID` in libpod), so
    /// setting it — or changing it — must recreate the container.
    #[test]
    fn secret_mount_ownership_changes_the_hash_only_when_set() {
        let hash = |uid, gid| spec_hash(&mounting(uid, gid), &digest('a'));
        let base = hash(None, None);
        assert_eq!(base, hash(None, None));
        assert_ne!(base, hash(Some(1000), None), "uid");
        assert_ne!(base, hash(None, Some(1000)), "gid");
        assert_ne!(
            hash(Some(1000), Some(1000)),
            hash(Some(1001), Some(1000)),
            "the owner id is part of the container"
        );
    }
}
