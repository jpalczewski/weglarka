//! `depends_on`: the start-order graph between apps (issue #35, `docs/decisions/0016-depends-on.md`).
//!
//! The pure cross-app rules ([`validate`]) and the deterministic topological order ([`order`]), used
//! by [`crate::state::load_apps`]/[`crate::state::save_apps`] and by the reconcile plan. The
//! deploy-side start gate lives in the engine (`weglarka_engine::depends`). It is a **start order
//! only** — every app keeps its own `net-<instance>` network, so `depends_on` gives no connectivity
//! by itself; joining a shared network (issue #128) is what gives it, and the two compose.

use std::collections::{BTreeMap, BTreeSet};

use crate::app::{AppsFile, InstanceName};

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
}
