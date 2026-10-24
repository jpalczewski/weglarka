//! Shared volumes between instances (issue #33, `docs/decisions/0017-shared-volumes.md`) — the pure
//! desired-state checks and lookups.
//!
//! A shared volume is declared once in `[shared_volumes.<name>]` and mounted by apps through
//! `AppSpec::shared_volumes`. The volume owns one uid/gid range; every member container runs in it
//! (allocation and persistence live in [`crate::volumes`] with the engine lock, because they need
//! `state.toml` and Podman).

use crate::app::{AppSpec, AppsFile, InstanceName, SharedVolumeName, SharedVolumeRef};

/// Checks the shared-volume rules that span several apps, on every `apps.toml` load and save.
///
/// * every `AppSpec::shared_volumes` entry names a declared volume — an undeclared name is a typo,
///   and silently creating a second empty volume for it is the failure mode this rule prevents;
/// * at most one shared volume per app (enforced per app in `state::validate_app`, repeated here is
///   not needed);
/// * mount target rules are validated per app in `state::validate_app`.
///
/// Unused declarations are allowed: a volume may be declared before the first member is added.
pub fn validate(apps: &AppsFile) -> Result<(), String> {
    for (instance, spec) in &apps.apps {
        for mount in &spec.shared_volumes {
            if !apps.shared_volumes.contains_key(&mount.name) {
                return Err(format!(
                    "{instance}: mounts undeclared shared volume {:?}; declare it with \
                     `[shared_volumes.{}]` in apps.toml (or `weglarka volumes add {}`)",
                    mount.name, mount.name, mount.name
                ));
            }
        }
    }
    Ok(())
}

/// Instances mounting `volume`, ordered by name (`apps.toml` is a `BTreeMap`, so this is
/// deterministic). The list drives "who still uses it" for purge and for doctor.
pub fn members(apps: &AppsFile, volume: &SharedVolumeName) -> Vec<InstanceName> {
    apps.apps
        .iter()
        .filter(|(_, spec)| spec.shared_volumes.iter().any(|m| &m.name == volume))
        .map(|(name, _)| name.clone())
        .collect()
}

/// The shared volume a spec mounts, if any (v1 allows at most one).
pub fn mount(spec: &AppSpec) -> Option<&SharedVolumeRef> {
    spec.shared_volumes.first()
}

/// Whether `instance` mounts a shared volume; the effective uid range of its container then belongs
/// to that volume instead of `AppState::uid_range`.
pub fn instance_volume<'a>(
    apps: &'a AppsFile,
    instance: &InstanceName,
) -> Option<&'a SharedVolumeRef> {
    apps.apps.get(instance).and_then(mount)
}

/// Other instances mounting the same volume as `instance` (used by the purge and import guards —
/// the message lists the instances whose data/processes are at stake).
pub fn other_members(
    apps: &AppsFile,
    instance: &InstanceName,
    volume: &SharedVolumeName,
) -> Vec<InstanceName> {
    members(apps, volume)
        .into_iter()
        .filter(|m| m != instance)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps(src: &str) -> AppsFile {
        toml::from_str(src).expect("valid apps.toml")
    }

    fn name(s: &str) -> SharedVolumeName {
        SharedVolumeName::new(s).unwrap()
    }

    const DECLARED: &str = r#"
[shared_volumes.kajet-data]

[apps.kajet-api]
image = "ghcr.io/x/api:latest"
shared_volumes = [{ name = "kajet-data", target = "/data" }]

[apps.kajet-mcp]
image = "ghcr.io/x/mcp:latest"
shared_volumes = [{ name = "kajet-data", target = "/data", read_only = true }]

[apps.ntfy]
image = "ghcr.io/x/ntfy:latest"
"#;

    #[test]
    fn declared_volume_with_members_is_valid() {
        let a = apps(DECLARED);
        validate(&a).unwrap();
        assert_eq!(
            members(&a, &name("kajet-data")),
            vec![
                InstanceName::new("kajet-api").unwrap(),
                InstanceName::new("kajet-mcp").unwrap()
            ]
        );
        assert_eq!(
            other_members(
                &a,
                &InstanceName::new("kajet-api").unwrap(),
                &name("kajet-data")
            ),
            vec![InstanceName::new("kajet-mcp").unwrap()]
        );
        assert!(instance_volume(&a, &InstanceName::new("ntfy").unwrap()).is_none());
    }

    #[test]
    fn undeclared_mount_is_rejected() {
        let a = apps(
            r#"
[apps.kajet-api]
image = "ghcr.io/x/api:latest"
shared_volumes = [{ name = "kajet-data", target = "/data" }]
"#,
        );
        let err = validate(&a).unwrap_err();
        assert!(err.contains("undeclared shared volume"), "{err}");
        assert!(err.contains("weglarka volumes add kajet-data"), "{err}");
    }

    #[test]
    fn unused_declaration_is_allowed() {
        let a = apps("[shared_volumes.future]\n\n[apps.ntfy]\nimage = \"x:1\"\n");
        validate(&a).unwrap();
        assert!(members(&a, &name("future")).is_empty());
    }

    #[test]
    fn tomllib_roundtrip_keeps_the_declaration_and_the_mounts() {
        let a = apps(DECLARED);
        let text = toml::to_string(&a).unwrap();
        assert!(text.contains("[shared_volumes.kajet-data]"), "{text}");
        let back: AppsFile = toml::from_str(&text).unwrap();
        assert_eq!(a, back);
        // A spec without shared volumes serializes exactly as before (no `shared_volumes` key).
        let plain: AppsFile = toml::from_str("[apps.a]\nimage = \"x:1\"\n").unwrap();
        assert!(!toml::to_string(&plain).unwrap().contains("shared_volumes"));
    }
}
