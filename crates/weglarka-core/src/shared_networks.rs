//! Networks shared by a group of instances (issue #128, `docs/decisions/0030-shared-networks.md`) —
//! the pure desired-state checks and lookups.
//!
//! A shared network is declared once in `[shared_networks.<name>]` and joined by apps through
//! `AppSpec::shared_networks`. Creating the Podman network lives in [`crate::deploy`] (it needs the
//! engine lock and Podman).

use std::collections::BTreeMap;

use crate::app::{AppSpec, AppsFile, InstanceName, SharedNetworkName, SharedNetworkRef};
use crate::labels;
use crate::podman::PodmanClient;
use crate::reconcile::{EngineError, Reconciler};
use crate::state;

/// Checks the shared-network rules, on every `apps.toml` load and save.
///
/// * every `AppSpec::shared_networks` entry names a declared network — an undeclared name is a
///   typo, and silently creating a second, empty group for it would leave the app isolated;
/// * at most one shared network per app (v1);
/// * `aliases` are valid DNS names (the instance-name alphabet), do not repeat, and neither equal
///   another instance's name nor an alias of another member of the same group — two containers
///   answering to one name would make the resolver pick one of them at random.
///
/// Unused declarations are allowed: a network may be declared before the first member is added.
pub fn validate(apps: &AppsFile) -> Result<(), String> {
    // Per group: DNS name → who answers to it (an instance name or `<instance> alias`).
    let mut names: BTreeMap<&SharedNetworkName, BTreeMap<String, String>> = BTreeMap::new();
    for (instance, spec) in &apps.apps {
        if spec.shared_networks.len() > 1 {
            return Err(format!(
                "{instance}: at most one shared network per app (see \
                 docs/decisions/0030-shared-networks.md)"
            ));
        }
        for net in &spec.shared_networks {
            if !apps.shared_networks.contains_key(&net.name) {
                return Err(format!(
                    "{instance}: joins undeclared shared network {:?}; declare it with \
                     `[shared_networks.{}]` in apps.toml (or `weglarka networks add {}`)",
                    net.name, net.name, net.name
                ));
            }
            let group = names.entry(&net.name).or_default();
            group.insert(instance.to_string(), instance.to_string());
            for alias in &net.aliases {
                if InstanceName::new(alias.as_str()).is_err() {
                    return Err(format!(
                        "{instance}: invalid network alias {alias:?}: expected 1-63 chars of \
                         [a-z0-9-], no leading/trailing '-'"
                    ));
                }
            }
        }
    }
    // Aliases are checked after every member's own name is known, so a clash with an instance that
    // sorts later in `apps.toml` is found too.
    for (instance, spec) in &apps.apps {
        for net in &spec.shared_networks {
            let group = names.entry(&net.name).or_default();
            for alias in &net.aliases {
                match group.get(alias) {
                    Some(holder) if holder != &format!("{instance} {alias}") => {
                        return Err(format!(
                            "{instance}: network alias {alias:?} is already used by {holder} in \
                             shared network {:?}",
                            net.name
                        ));
                    }
                    _ => {
                        group.insert(alias.clone(), format!("{instance} {alias}"));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Instances joining `network`, ordered by name (`apps.toml` is a `BTreeMap`, so this is
/// deterministic). The list drives "who still uses it" for removal and for doctor.
pub fn members(apps: &AppsFile, network: &SharedNetworkName) -> Vec<InstanceName> {
    apps.apps
        .iter()
        .filter(|(_, spec)| spec.shared_networks.iter().any(|m| &m.name == network))
        .map(|(name, _)| name.clone())
        .collect()
}

/// The shared network a spec joins, if any (v1 allows at most one).
pub fn membership(spec: &AppSpec) -> Option<&SharedNetworkRef> {
    spec.shared_networks.first()
}

impl<P: PodmanClient> Reconciler<P> {
    /// Declares a shared network (idempotent, issue #128). Apps join it through `shared_networks`;
    /// the Podman network is created lazily by the first member's deploy.
    pub async fn declare_shared_network(&self, name: SharedNetworkName) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if apps.shared_networks.contains_key(&name) {
            return Ok(());
        }
        apps.shared_networks.insert(name, Default::default());
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// Removes a shared network declaration (issue #128). Refused while any app joins it. The
    /// Podman network goes with it when nothing is attached; otherwise reconcile removes the empty
    /// network once the last container is gone (best effort, like per-app networks).
    pub async fn remove_shared_network(&self, name: &SharedNetworkName) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if !apps.shared_networks.contains_key(name) {
            return Err(EngineError::UnknownSharedNetwork(name.clone()));
        }
        let members = members(&apps, name);
        if !members.is_empty() {
            return Err(EngineError::SharedNetworkInUse {
                network: name.clone(),
                members: members
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        apps.shared_networks.remove(name);
        state::save_apps(&self.paths.apps, &apps)?;
        // Best effort and idempotent: a network still attached (a stopped member that was removed
        // from the spec but whose container lingers) is picked up by `prune_networks` later.
        if let Err(e) = self
            .podman
            .network_remove(&labels::shared_network_name(name))
            .await
        {
            tracing::debug!(network = %name, error = %e, "shared network not removed yet");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps(src: &str) -> AppsFile {
        toml::from_str(src).expect("valid apps.toml")
    }

    fn name(s: &str) -> SharedNetworkName {
        SharedNetworkName::new(s).unwrap()
    }

    const DECLARED: &str = r#"
[shared_networks.kajet]

[apps.kajet-api]
image = "ghcr.io/x/api:latest"
shared_networks = ["kajet"]

[apps.kajet-proxy]
image = "ghcr.io/x/caddy:latest"
shared_networks = [{ name = "kajet", aliases = ["gateway"] }]

[apps.ntfy]
image = "ghcr.io/x/ntfy:latest"
"#;

    #[test]
    fn declared_network_with_members_is_valid() {
        let a = apps(DECLARED);
        validate(&a).unwrap();
        assert_eq!(
            members(&a, &name("kajet")),
            vec![
                InstanceName::new("kajet-api").unwrap(),
                InstanceName::new("kajet-proxy").unwrap()
            ]
        );
        let proxy = &a.apps[&InstanceName::new("kajet-proxy").unwrap()];
        assert_eq!(membership(proxy).unwrap().aliases, vec!["gateway"]);
        assert!(membership(&a.apps[&InstanceName::new("ntfy").unwrap()]).is_none());
    }

    #[test]
    fn shorthand_round_trips_and_aliases_keep_the_table_form() {
        let a = apps(DECLARED);
        let text = toml::to_string(&a).unwrap();
        assert!(text.contains(r#"shared_networks = ["kajet"]"#), "{text}");
        assert!(text.contains("aliases"), "{text}");
        assert_eq!(apps(&text), a);
    }

    #[test]
    fn undeclared_network_is_rejected() {
        let a = apps("[apps.a]\nimage = \"x:1\"\nshared_networks = [\"nope\"]\n");
        let err = validate(&a).unwrap_err();
        assert!(err.contains("undeclared shared network"), "{err}");
    }

    #[test]
    fn at_most_one_network_per_app() {
        let a = apps(
            "[shared_networks.a]\n[shared_networks.b]\n\
             [apps.x]\nimage = \"x:1\"\nshared_networks = [\"a\", \"b\"]\n",
        );
        assert!(validate(&a).unwrap_err().contains("at most one"));
    }

    #[test]
    fn aliases_must_be_valid_and_unique_in_the_group() {
        let base = "[shared_networks.g]\n[apps.a]\nimage = \"x:1\"\nshared_networks = [\"g\"]\n";
        let bad_chars = format!(
            "{base}[apps.b]\nimage = \"x:1\"\nshared_networks = [{{ name = \"g\", aliases = [\"Bad_Name\"] }}]\n"
        );
        assert!(
            validate(&apps(&bad_chars))
                .unwrap_err()
                .contains("invalid network alias")
        );
        // An alias equal to another member's instance name.
        let clash_instance = format!(
            "{base}[apps.b]\nimage = \"x:1\"\nshared_networks = [{{ name = \"g\", aliases = [\"a\"] }}]\n"
        );
        assert!(
            validate(&apps(&clash_instance))
                .unwrap_err()
                .contains("already used")
        );
        // The same alias on two members.
        let clash_alias = "[shared_networks.g]\n\
            [apps.a]\nimage = \"x:1\"\nshared_networks = [{ name = \"g\", aliases = [\"web\"] }]\n\
            [apps.b]\nimage = \"x:1\"\nshared_networks = [{ name = \"g\", aliases = [\"web\"] }]\n";
        assert!(
            validate(&apps(clash_alias))
                .unwrap_err()
                .contains("already used")
        );
        // The same alias in two different groups is fine.
        let two_groups = "[shared_networks.g]\n[shared_networks.h]\n\
            [apps.a]\nimage = \"x:1\"\nshared_networks = [{ name = \"g\", aliases = [\"web\"] }]\n\
            [apps.b]\nimage = \"x:1\"\nshared_networks = [{ name = \"h\", aliases = [\"web\"] }]\n";
        validate(&apps(two_groups)).unwrap();
    }

    #[test]
    fn the_documented_example_is_valid() {
        // `docs/examples/shared-network.toml` is an `apps.toml` excerpt: keep it valid.
        let example = include_str!("../../../docs/examples/shared-network.toml");
        let a = apps(example);
        validate(&a).unwrap();
        assert_eq!(members(&a, &name("notes")).len(), 3);
    }

    #[test]
    fn declaration_rejects_unknown_fields_and_bad_names() {
        assert!(toml::from_str::<AppsFile>("[shared_networks.g]\nbogus = 1\n").is_err());
        assert!(toml::from_str::<AppsFile>("[shared_networks.Bad_Name]\n").is_err());
    }
}
