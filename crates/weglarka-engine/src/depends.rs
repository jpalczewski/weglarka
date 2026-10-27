//! `depends_on` at run time: the deploy-side start gate and the removal guard (issue #35,
//! `docs/decisions/0016-depends-on.md`). The pure graph rules (`validate`, `order`, `dependents_of`)
//! live in [`weglarka_model::depends`].
//!
//! Before Węglarka starts a container that was not running, every app in `depends_on` must be
//! running (and healthy when it declares a probe) (`Reconciler::dependency_gate`). It is a **start
//! order only** — every app keeps its own `net-<instance>` network, so `depends_on` gives no
//! connectivity by itself; joining a shared network (issue #128) is what gives it, and the two
//! compose. The shared-database part of issue #35 is separate.

use std::time::Duration;

use weglarka_model::app::{AppSpec, AppsFile, InstanceName};
use weglarka_model::depends::dependents_of;
use weglarka_model::events::Event;
use weglarka_model::labels;
use weglarka_model::podman::{ContainerState, HealthStatus, PodmanClient, PodmanError};
use weglarka_model::state::{self, StateFile};

use crate::reconcile::{EngineError, Reconciler};

/// Poll step of the gate; the total budget is `ReconcilerOptions::dependency_wait_secs`.
const POLL: Duration = Duration::from_secs(1);

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
    fn dependents_are_listed_for_a_removal_refusal() {
        let parsed: AppsFile = toml::from_str(THREE).unwrap();
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
