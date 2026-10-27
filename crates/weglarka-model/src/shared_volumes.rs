//! Shared volumes between instances (issue #33, `docs/decisions/0017-shared-volumes.md`) — the pure
//! desired-state checks and lookups.
//!
//! A shared volume is declared once in `[shared_volumes.<name>]` and mounted by apps through
//! `AppSpec::shared_volumes`. The volume (its group) owns one uid/gid range; every member container runs in it
//! (allocation and persistence live in `weglarka_engine::volumes` under the engine lock, because they need
//! `state.toml` and Podman). Since issue #129 the range belongs to a *group* of volumes
//! (`docs/decisions/0029-shared-volume-groups.md`); a volume without `group` is its own group.

use crate::app::{AppSpec, AppsFile, InstanceName, SharedVolumeName, SharedVolumeRef};

/// Group a declared volume belongs to: its explicit `group`, otherwise its own name (the behaviour
/// before groups, issue #129). The uid/gid range is allocated per group.
pub fn volume_group(apps: &AppsFile, volume: &SharedVolumeName) -> SharedVolumeName {
    apps.shared_volumes
        .get(volume)
        .and_then(|spec| spec.group.clone())
        .unwrap_or_else(|| volume.clone())
}

/// Checks the shared-volume rules that span several apps, on every `apps.toml` load and save.
///
/// * every `AppSpec::shared_volumes` entry names a declared volume — an undeclared name is a typo,
///   and silently creating a second empty volume for it is the failure mode this rule prevents;
/// * all shared volumes of one app belong to the same group — the container runs in a single uid
///   range (docs/decisions/0029);
/// * an explicit group named like another volume is that volume's group, so the two must agree —
///   otherwise one name would denote two ranges;
/// * mount target rules are validated per app in `state::validate_app`.
///
/// Unused declarations are allowed: a volume may be declared before the first member is added.
pub fn validate(apps: &AppsFile) -> Result<(), String> {
    for (volume, spec) in &apps.shared_volumes {
        if let Some(group) = &spec.group
            && group != volume
            && apps.shared_volumes.contains_key(group)
            && volume_group(apps, group) != *group
        {
            return Err(format!(
                "shared volume {volume:?}: group {group:?} is the name of a volume that belongs to \
                 group {:?}; pick another group name",
                volume_group(apps, group)
            ));
        }
    }
    for (instance, spec) in &apps.apps {
        let mut first: Option<(&SharedVolumeName, SharedVolumeName)> = None;
        for mount in &spec.shared_volumes {
            if !apps.shared_volumes.contains_key(&mount.name) {
                return Err(format!(
                    "{instance}: mounts undeclared shared volume {:?}; declare it with \
                     `[shared_volumes.{}]` in apps.toml (or `weglarka volumes add {}`)",
                    mount.name, mount.name, mount.name
                ));
            }
            let group = volume_group(apps, &mount.name);
            match &first {
                None => first = Some((&mount.name, group)),
                Some((other, other_group)) if *other_group != group => {
                    return Err(format!(
                        "{instance}: shared volumes {other:?} (group {other_group:?}) and {:?} \
                         (group {group:?}) belong to different groups; an app runs in a single uid \
                         range, so it can mount volumes of one group only (see \
                         docs/decisions/0029-shared-volume-groups.md)",
                        mount.name
                    ));
                }
                Some(_) => {}
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

/// Declared volumes of `group`, ordered by name.
pub fn group_volumes(apps: &AppsFile, group: &SharedVolumeName) -> Vec<SharedVolumeName> {
    apps.shared_volumes
        .keys()
        .filter(|v| volume_group(apps, v) == *group)
        .cloned()
        .collect()
}

/// Instances mounting any volume of `group`, ordered by name.
pub fn group_members(apps: &AppsFile, group: &SharedVolumeName) -> Vec<InstanceName> {
    apps.apps
        .iter()
        .filter(|(_, spec)| {
            spec.shared_volumes
                .iter()
                .any(|m| volume_group(apps, &m.name) == *group)
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// The group a spec's container runs in: the group of its shared volumes (all of them agree, see
/// [`validate`]), if it mounts any. The effective uid range of its container then belongs to that
/// group instead of `AppState::uid_range`.
pub fn spec_group(apps: &AppsFile, spec: &AppSpec) -> Option<SharedVolumeName> {
    spec.shared_volumes
        .first()
        .map(|m| volume_group(apps, &m.name))
}

/// Whether `instance` mounts a shared volume.
pub fn instance_volume<'a>(
    apps: &'a AppsFile,
    instance: &InstanceName,
) -> Option<&'a SharedVolumeRef> {
    apps.apps
        .get(instance)
        .and_then(|spec| spec.shared_volumes.first())
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

    const GROUPED: &str = r#"
[shared_volumes.kajet-data]
group = "kajet"

[shared_volumes.kajet-workspaces]
group = "kajet"

[shared_volumes.other]

[apps.kajet-api]
image = "ghcr.io/x/api:latest"
shared_volumes = [
  { name = "kajet-data", target = "/data" },
  { name = "kajet-workspaces", target = "/workspaces" },
]
"#;

    #[test]
    fn several_volumes_of_one_group_are_valid() {
        let a = apps(GROUPED);
        validate(&a).unwrap();
        assert_eq!(volume_group(&a, &name("kajet-data")), name("kajet"));
        assert_eq!(volume_group(&a, &name("other")), name("other"), "default");
        assert_eq!(
            group_volumes(&a, &name("kajet")),
            vec![name("kajet-data"), name("kajet-workspaces")]
        );
        assert_eq!(
            group_members(&a, &name("kajet")),
            vec![InstanceName::new("kajet-api").unwrap()]
        );
        assert_eq!(
            spec_group(&a, &a.apps[&InstanceName::new("kajet-api").unwrap()]),
            Some(name("kajet"))
        );
    }

    #[test]
    fn volumes_of_two_groups_in_one_app_are_rejected() {
        let a = apps(&format!(
            "{GROUPED}\n[apps.mixed]\nimage = \"x:1\"\nshared_volumes = [\
             {{ name = \"kajet-data\", target = \"/data\" }}, \
             {{ name = \"other\", target = \"/other\" }}]\n"
        ));
        let err = validate(&a).unwrap_err();
        assert!(err.contains("mixed"), "{err}");
        assert!(err.contains("different groups"), "{err}");
        assert!(err.contains("kajet-data") && err.contains("other"), "{err}");
    }

    #[test]
    fn a_group_named_like_a_volume_of_another_group_is_rejected() {
        let a = apps("[shared_volumes.a]\ngroup = \"b\"\n[shared_volumes.b]\ngroup = \"c\"\n");
        let err = validate(&a).unwrap_err();
        assert!(err.contains("pick another group name"), "{err}");
        // A volume that is its own group is fine as a group for others.
        validate(&apps(
            "[shared_volumes.a]\ngroup = \"b\"\n[shared_volumes.b]\n",
        ))
        .unwrap();
    }

    #[test]
    fn the_same_volume_twice_in_one_app_is_rejected() {
        let src = "[shared_volumes.v]\n[apps.a]\nimage = \"x:1\"\nshared_volumes = [\
                   {name=\"v\",target=\"/a\"},{name=\"v\",target=\"/b\"}]\n";
        let a: AppsFile = toml::from_str(src).unwrap();
        let err = crate::state::validate_app(
            &InstanceName::new("a").unwrap(),
            &a.apps[&InstanceName::new("a").unwrap()],
        )
        .unwrap_err();
        assert!(err.contains("mounted twice"), "{err}");
    }

    #[test]
    fn an_unset_group_is_not_serialized() {
        let a = apps(GROUPED);
        let text = toml::to_string(&a).unwrap();
        assert_eq!(text.matches("group = ").count(), 2, "{text}");
        let plain = apps("[shared_volumes.v]\n");
        assert!(!toml::to_string(&plain).unwrap().contains("group"));
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
