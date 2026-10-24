//! `depends_on`: the start-order graph between apps (issue #35, `docs/decisions/0016-depends-on.md`).
//!
//! Two small pieces:
//! * the pure cross-app rules ([`validate`]) and the deterministic topological order ([`order`]),
//!   used by [`crate::state::load_apps`]/[`crate::state::save_apps`] and by the reconcile plan;
//! * the deploy-side gate ([`Reconciler::dependency_gate`]): before Węglarka starts a container that
//!   was not running, every app in `depends_on` must be running (and healthy when it declares a
//!   probe). It is a **start order only** — every app keeps its own `net-<instance>` network, so
//!   `depends_on` gives no connectivity. The shared-database part of issue #35 is separate.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::app::{AppSpec, AppsFile, InstanceName};
use crate::events::Event;
use crate::labels;
use crate::podman::{ContainerState, HealthStatus, PodmanClient, PodmanError};
use crate::reconcile::{EngineError, Reconciler};
use crate::state::{self, StateFile};

/// Poll step of the gate; the total budget is `ReconcilerOptions::dependency_wait_secs`.
const POLL: Duration = Duration::from_secs(1);

// ── Cross-app rules (pure) ──────────────────────────────────────────────────

/// The rules of `apps.toml` that need the whole file: every `depends_on` entry names an app of the
/// same file, and the graph is acyclic. Called from both `load_apps` (a bad file refuses to load at
/// daemon start) and `save_apps` (a bad write is rejected by the admin API).
pub fn validate(apps: &AppsFile) -> Result<(), String> {
    for (name, spec) in &apps.apps {
        for dep in &spec.depends_on {
            if !apps.apps.contains_key(dep) {
                return Err(format!(
                    "{name}: depends_on references unknown app \"{dep}\" (add it to apps.toml first)"
                ));
            }
        }
    }
    if let Some(cycle) = first_cycle(apps) {
        let path: Vec<String> = cycle.iter().map(ToString::to_string).collect();
        return Err(format!("cycle in depends_on: {}", path.join(" -> ")));
    }
    Ok(())
}

/// The first cycle of the graph as a node path plus the repeated start node (`[a, b, a]`), or `None`.
/// The walk starts from the apps in alphabetical order, so the message is deterministic.
fn first_cycle(apps: &AppsFile) -> Option<Vec<InstanceName>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        Open,
        Done,
    }

    fn walk<'a>(
        node: &'a InstanceName,
        apps: &'a AppsFile,
        marks: &mut BTreeMap<&'a InstanceName, Mark>,
        stack: &mut Vec<&'a InstanceName>,
    ) -> Option<Vec<InstanceName>> {
        marks.insert(node, Mark::Open);
        stack.push(node);
        if let Some(spec) = apps.apps.get(node) {
            for dep in &spec.depends_on {
                // References are validated before the walk; skip a dangling one defensively.
                let Some((dep, _)) = apps.apps.get_key_value(dep) else {
                    continue;
                };
                match marks.get(dep) {
                    None => {
                        if let Some(cycle) = walk(dep, apps, marks, stack) {
                            return Some(cycle);
                        }
                    }
                    Some(Mark::Open) => {
                        let start = stack.iter().position(|n| *n == dep).unwrap_or(0);
                        let mut cycle: Vec<InstanceName> =
                            stack[start..].iter().map(|n| (*n).clone()).collect();
                        cycle.push(dep.clone());
                        return Some(cycle);
                    }
                    Some(Mark::Done) => {}
                }
            }
        }
        stack.pop();
        marks.insert(node, Mark::Done);
        None
    }

    let mut marks = BTreeMap::new();
    for name in apps.apps.keys() {
        if marks.contains_key(name) {
            continue;
        }
        let mut stack = Vec::new();
        if let Some(cycle) = walk(name, apps, &mut marks, &mut stack) {
            return Some(cycle);
        }
    }
    None
}

/// Topological order of the given nodes: an app always comes after the apps it depends on.
/// Deterministic — alphabetical among the nodes that are ready — and a dependency outside the given
/// set is ignored (it cannot exist after [`validate`]). A cycle (impossible for a validated file)
/// falls back to appending the remaining nodes alphabetically instead of looping forever.
pub fn order<'a, I>(deps_of: I) -> Vec<InstanceName>
where
    I: IntoIterator<Item = (&'a InstanceName, &'a [InstanceName])>,
{
    let pairs: Vec<(&InstanceName, &[InstanceName])> = deps_of.into_iter().collect();
    let known: BTreeSet<&InstanceName> = pairs.iter().map(|(name, _)| *name).collect();
    let mut deps: BTreeMap<&InstanceName, BTreeSet<&InstanceName>> = BTreeMap::new();
    let mut dependents: BTreeMap<&InstanceName, BTreeSet<&InstanceName>> = BTreeMap::new();
    for (name, list) in &pairs {
        let set: BTreeSet<&InstanceName> = list.iter().filter(|dep| known.contains(*dep)).collect();
        for dep in &set {
            dependents.entry(*dep).or_default().insert(*name);
        }
        deps.insert(*name, set);
    }

    let mut ready: BTreeSet<&InstanceName> = deps
        .iter()
        .filter(|(_, remaining)| remaining.is_empty())
        .map(|(name, _)| *name)
        .collect();
    let mut out = Vec::with_capacity(known.len());
    while let Some(name) = ready.pop_first() {
        out.push((*name).clone());
        for dependent in dependents.get(name).into_iter().flatten() {
            if let Some(remaining) = deps.get_mut(dependent) {
                remaining.remove(name);
                if remaining.is_empty() {
                    ready.insert(dependent);
                }
            }
        }
    }
    // Defensive: a cycle would leave nodes out; emit every app exactly once.
    for name in &known {
        if !out.iter().any(|done| done == *name) {
            out.push((*name).clone());
        }
    }
    out
}

/// Apps whose `depends_on` lists `name` (sorted, as they appear in `apps.toml`).
pub fn dependents_of(apps: &AppsFile, name: &InstanceName) -> Vec<InstanceName> {
    apps.apps
        .iter()
        .filter(|(app, spec)| *app != name && spec.depends_on.contains(name))
        .map(|(app, _)| app.clone())
        .collect()
}

/// Refuses to remove an app that another app depends on: the dependent would be left with a dangling
/// reference, and its data (`--purge-volumes`) may still be needed. The caller holds the engine lock
/// and has not modified anything yet.
pub(crate) fn ensure_not_depended_on(
    apps: &AppsFile,
    name: &InstanceName,
) -> Result<(), EngineError> {
    let dependents = dependents_of(apps, name);
    if dependents.is_empty() {
        Ok(())
    } else {
        Err(EngineError::DependencyInUse {
            name: name.clone(),
            dependents,
        })
    }
}

// ── Deploy-side gate ────────────────────────────────────────────────────────

impl<P: PodmanClient> Reconciler<P> {
    /// Blocks a start until every app in `spec.depends_on` is running (and healthy when it declares
    /// a probe). Called before a container that was not running is started: a first deploy, a
    /// re-pin, `apps start`, a webhook deploy and a recreate of a missing container. `start = false`
    /// provisioning, and replacing a container that is already running (`spec-hash` drift), are not
    /// gated.
    ///
    /// The wait is bounded by `ReconcilerOptions::dependency_wait_secs`; a dependency without a
    /// container fails immediately (there is nothing to wait for), which keeps a broken dependency
    /// from stalling the reconcile loop.
    pub(crate) async fn dependency_gate(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<(), EngineError> {
        if spec.depends_on.is_empty() {
            return Ok(());
        }
        let apps = state::load_apps(&self.paths.apps)?;
        let st = state::load_state(&self.paths.state)?;
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.options.dependency_wait_secs.into());
        loop {
            let pending = self.pending_dependencies(&apps, &st, spec).await;
            if pending.is_empty() {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                self.events.emit(Event::WaitingForDependency {
                    instance: instance.clone(),
                    dependencies: pending.iter().map(|(dep, _)| dep.clone()).collect(),
                });
                return Err(EngineError::DependenciesNotReady {
                    instance: instance.clone(),
                    pending,
                });
            }
            tokio::time::sleep(POLL.min(deadline - now)).await;
        }
    }

    /// Dependencies that are not ready yet, with a short human-readable reason for each.
    async fn pending_dependencies(
        &self,
        apps: &AppsFile,
        st: &StateFile,
        spec: &AppSpec,
    ) -> Vec<(InstanceName, String)> {
        let mut pending = Vec::new();
        for dep in &spec.depends_on {
            if let Err(reason) = self.dependency_ready(apps, st, dep).await {
                pending.push((dep.clone(), reason));
            }
        }
        pending
    }

    async fn dependency_ready(
        &self,
        apps: &AppsFile,
        st: &StateFile,
        dep: &InstanceName,
    ) -> Result<(), String> {
        let Some(spec) = apps.apps.get(dep) else {
            return Err("not declared in apps.toml".to_owned());
        };
        if !spec.start {
            return Err("start = false".to_owned());
        }
        let name = labels::container_name(dep);
        let info = match self.podman.container_inspect(&name).await {
            Ok(info) => info,
            Err(PodmanError::NotFound(_)) => {
                return Err(match st.apps.get(dep) {
                    Some(state) if !state.waiting_for_secrets.is_empty() => {
                        format!(
                            "waiting for secrets: {}",
                            state.waiting_for_secrets.join(", ")
                        )
                    }
                    _ => "no container".to_owned(),
                });
            }
            Err(e) => return Err(format!("inspect failed: {e}")),
        };
        if info.state != ContainerState::Running {
            return Err(match info.exit_code {
                Some(code) => format!("not running ({:?}, exit code {code})", info.state),
                None => format!("not running ({:?})", info.state),
            });
        }
        // Same rule as the deploy health gate: a healthcheck from the spec (health.command) or from
        // the image must pass; the daemon-side `health.http` is probed through the ingress.
        if spec.health.command.is_some() || info.health.is_some() {
            match self.podman.healthcheck_run(&name).await {
                Ok(HealthStatus::Healthy) => {}
                Ok(status) => return Err(format!("healthcheck {status:?}")),
                Err(e) => return Err(format!("healthcheck error: {e}")),
            }
        }
        if let Some(probe) = &spec.health.http {
            self.http_probe(spec, probe).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apps(src: &str) -> AppsFile {
        toml::from_str(src).unwrap()
    }

    fn order_of(apps: &AppsFile) -> Vec<String> {
        let edges: Vec<(&InstanceName, &[InstanceName])> = apps
            .apps
            .iter()
            .map(|(name, spec)| (name, spec.depends_on.as_slice()))
            .collect();
        order(edges).iter().map(ToString::to_string).collect()
    }

    const THREE: &str = r#"
[apps.api]
image = "i"
depends_on = ["db"]

[apps.db]
image = "i"

[apps.cache]
image = "i"
"#;

    #[test]
    fn validate_rejects_unknown_references_and_cycles() {
        let unknown = apps("[apps.api]\nimage = \"i\"\ndepends_on = [\"db\"]\n");
        let err = validate(&unknown).unwrap_err();
        assert!(err.contains("api") && err.contains("db"), "{err}");

        let cycle = apps(
            "[apps.a]\nimage = \"i\"\ndepends_on = [\"b\"]\n[apps.b]\nimage = \"i\"\ndepends_on = [\"a\"]\n",
        );
        let err = validate(&cycle).unwrap_err();
        assert!(err.starts_with("cycle in depends_on:"), "{err}");
        assert!(err.contains("a -> b -> a"), "{err}");

        assert!(validate(&apps(THREE)).is_ok());
    }

    #[test]
    fn order_is_topological_and_alphabetical_among_ready_nodes() {
        // `db` before `api` even though `api` sorts first; `cache` is independent and ready first.
        assert_eq!(order_of(&apps(THREE)), ["cache", "db", "api"]);
        let chain = apps(
            "[apps.a]\nimage = \"i\"\ndepends_on = [\"b\"]\n\
             [apps.b]\nimage = \"i\"\ndepends_on = [\"c\"]\n\
             [apps.c]\nimage = \"i\"\n",
        );
        assert_eq!(order_of(&chain), ["c", "b", "a"]);
        // No dependencies at all: the previous alphabetical order, unchanged.
        let plain = apps("[apps.b]\nimage = \"i\"\n[apps.a]\nimage = \"i\"\n");
        assert_eq!(order_of(&plain), ["a", "b"]);
    }

    #[test]
    fn order_ignores_a_reference_outside_the_given_set() {
        // Validated files cannot have one, but `plan` must not lose or repeat a node because of it.
        let parsed =
            apps("[apps.a]\nimage = \"i\"\ndepends_on = [\"ghost\"]\n[apps.b]\nimage = \"i\"\n");
        assert_eq!(order_of(&parsed), ["a", "b"]);
    }

    #[test]
    fn dependents_are_listed_for_a_removal_refusal() {
        let parsed = apps(THREE);
        let db = InstanceName::new("db").unwrap();
        assert_eq!(
            dependents_of(&parsed, &db)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["api"]
        );
        assert!(dependents_of(&parsed, &InstanceName::new("cache").unwrap()).is_empty());
        assert!(ensure_not_depended_on(&parsed, &db).is_err());
        assert!(ensure_not_depended_on(&parsed, &InstanceName::new("api").unwrap()).is_ok());
    }
}
