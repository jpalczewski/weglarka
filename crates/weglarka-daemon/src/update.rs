//! `apps update` (`PUT /v1/apps/{name}`, [`weglarka_api::UpdateAppRequest`]) and the "waiting for
//! secret" state. **Owner: session 3 (iteration 2).**
//!
//! Semantics: **full spec replacement** — validate like `add`, persist `apps.toml` atomically, wake the
//! reconcile and ingress. What happens to the running container follows from the new spec:
//!
//! * `domains` and the health-gate settings are not part of the `spec-hash`: only ingress is
//!   re-rendered (nginx reload), the container is untouched;
//! * `port`, `env`, `secrets`, `volumes`, `resources`, `health.command` change the `spec-hash`: the
//!   next reconcile recreates the container from the *pinned* digest (no pull);
//! * `image` (repo or tag) is a deliberate re-pin: the update runs a deploy right away (pull, health
//!   gate, rollback to the previous digest on failure) and the result is in the response.
//! * `start` (run vs provision-only intent) is applied right away as well: `true` deploys (the usual
//!   pull + health gate + rollback), `false` provisions — pins the digest, prepares the network, uid
//!   range and volumes and removes any container — and the outcome is in the response.
//!
//! "Waiting for secret": the engine records `AppState::waiting_for_secrets` (see
//! `weglarka_core::waiting`); this module only renders it (`RuntimeState::WaitingForSecret`, doctor).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use weglarka_api::{
    CheckStatus, DeployOutcome, DeployResponse, DoctorCheck, ErrorCode, RuntimeState,
    ShowAppResponse, UpdateAppRequest, UpdateAppResponse,
};
use weglarka_core::app::InstanceName;
use weglarka_core::deploy::DeployOutcome as CoreOutcome;
use weglarka_core::labels;
use weglarka_core::podman::PodmanClient;
use weglarka_core::reconcile::EngineError;
use weglarka_core::state::{self, AppState};

use crate::admin::{Fail, runtime_state_for};
use crate::app::{Daemon, MUTATION_TIMEOUT};

/// Runtime state with "waiting for secret" taking the place of `Missing`: there is no container
/// because the bound secrets are not set yet. (With a running container the app keeps `Running`;
/// the pending names are in `state.waiting_for_secrets`.)
pub(crate) fn with_waiting(runtime: RuntimeState, state: Option<&AppState>) -> RuntimeState {
    match (runtime, state) {
        (RuntimeState::Missing, Some(s)) if !s.waiting_for_secrets.is_empty() => {
            RuntimeState::WaitingForSecret
        }
        (r, _) => r,
    }
}

/// `PUT /v1/apps/{name}`.
pub async fn update_app<P: PodmanClient + 'static>(
    State(d): State<Arc<Daemon<P>>>,
    Path(raw): Path<String>,
    body: Bytes,
) -> Result<Response, Fail> {
    let invalid = |m: String| Fail(ErrorCode::InvalidRequest, m);
    let name = InstanceName::new(&raw).map_err(|e| invalid(e.to_string()))?;
    let req: UpdateAppRequest =
        serde_json::from_slice(&body).map_err(|e| invalid(format!("invalid JSON body: {e}")))?;
    state::validate_app(&name, &req.spec).map_err(invalid)?;

    let (old_image, old_start) = {
        let _g = d.desired_lock.lock().await;
        let mut apps = state::load_apps(&d.paths.state.apps).map_err(internal)?;
        let old = apps
            .apps
            .insert(name.clone(), req.spec.clone())
            .ok_or_else(|| Fail(ErrorCode::NotFound, format!("unknown app: {name}")))?;
        // Shared volumes (issue #33): a mount of an undeclared volume is rejected here with the
        // `weglarka volumes add` hint, and a uid-range change with existing volume data is refused
        // before anything is persisted — the old container and its files stay untouched.
        weglarka_core::shared_volumes::validate(&apps).map_err(invalid)?;
        // Host-wide `host_ports` rules first, then domains/ports must be renderable (and not taken
        // by another app), as in `add`. Both see the candidate app set.
        weglarka_core::host_ports::validate(&d.host, &apps).map_err(|e| invalid(e.to_string()))?;
        // `depends_on`: a target must exist and the graph must stay acyclic (issue #35).
        weglarka_core::depends::validate(&apps).map_err(invalid)?;
        weglarka_ingress::Plan::build(&d.host, &apps.apps).map_err(|e| invalid(e.to_string()))?;
        d.engine.check_range_change(&name, &req.spec).await?;
        match tokio::time::timeout(
            MUTATION_TIMEOUT,
            d.engine.upsert_app(name.clone(), req.spec.clone()),
        )
        .await
        {
            Ok(r) => r.map_err(internal)?,
            Err(_) => {
                return Err(Fail(
                    ErrorCode::Busy,
                    "daemon is busy (deploy in progress); retry shortly".into(),
                ));
            }
        }
        (old.image, old.start)
    };

    // An image change is a re-pin and a `start` flip is an explicit run/stop: both deploy right away.
    let deploy = if old_image != req.spec.image || old_start != req.spec.start {
        redeploy(&d, &name).await?
    } else {
        None
    };
    d.changed();

    let st = state::load_state(&d.paths.state.state).map_err(internal)?;
    let container = d
        .engine
        .podman()
        .container_inspect(&labels::container_name(&name))
        .await
        .ok();
    let app_state = st.apps.get(&name);
    let app = ShowAppResponse {
        runtime: with_waiting(
            runtime_state_for(&req.spec, app_state, container.as_ref()),
            app_state,
        ),
        state: app_state.cloned().unwrap_or_default(),
        name,
        spec: req.spec,
    };
    Ok(axum::Json(UpdateAppResponse { app, deploy }).into_response())
}

fn internal(e: impl ToString) -> Fail {
    Fail(ErrorCode::Internal, e.to_string())
}

/// Deploy after an image change. Like a manual deploy it holds the engine mutex through pull and
/// health gate. `None` = the app waits for secrets (nothing attempted, not an error).
async fn redeploy<P: PodmanClient + 'static>(
    d: &Daemon<P>,
    name: &InstanceName,
) -> Result<Option<DeployResponse>, Fail> {
    let mut outcome = match d.engine.deploy(name, false).await {
        Ok(o) => o,
        Err(EngineError::MissingSecrets(_)) => return Ok(None),
        Err(e) => return Err(deploy_failed(e)),
    };
    if matches!(outcome, CoreOutcome::KnownBad { .. }) {
        // An explicit image change is the operator's will: retry a known-bad digest.
        outcome = d.engine.deploy(name, true).await.map_err(deploy_failed)?;
    }
    let generation = state::load_state(&d.paths.state.state)
        .map_err(internal)?
        .apps
        .get(name)
        .map_or(0, |a| a.generation);
    Ok(Some(match outcome {
        CoreOutcome::Deployed { digest, generation } => DeployResponse {
            outcome: DeployOutcome::Deployed,
            generation,
            digest: Some(digest),
        },
        CoreOutcome::Unchanged { digest } => DeployResponse {
            outcome: DeployOutcome::Unchanged,
            generation,
            digest: Some(digest),
        },
        CoreOutcome::RolledBack { restored, .. } => DeployResponse {
            outcome: DeployOutcome::RolledBack,
            generation,
            digest: Some(restored),
        },
        CoreOutcome::Provisioned { digest } => DeployResponse {
            outcome: DeployOutcome::Provisioned,
            generation,
            digest: Some(digest),
        },
        CoreOutcome::Failed { reason, .. } => return Err(saved_but_failed(reason)),
        CoreOutcome::KnownBad { .. } => {
            return Err(saved_but_failed("known bad digest"));
        }
    }))
}

fn saved_but_failed(why: impl ToString) -> Fail {
    internal(format!(
        "spec saved, but the deploy failed: {}",
        why.to_string()
    ))
}

/// Error of the deploy that follows a spec write. An unmet dependency is a conflict (409) with the
/// dependencies listed, not a failed deploy: the start was never attempted (issue #35).
fn deploy_failed(e: EngineError) -> Fail {
    match e {
        e @ EngineError::DependenciesNotReady { .. } => Fail::from(e),
        e => saved_but_failed(e),
    }
}

/// Doctor: apps waiting for secrets are a warning with the exact command to fix it.
pub(crate) fn doctor_check<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Ok(st) = state::load_state(&d.paths.state.state) else {
        return;
    };
    let waiting: Vec<(&InstanceName, &AppState)> = st
        .apps
        .iter()
        .filter(|(_, s)| !s.waiting_for_secrets.is_empty())
        .collect();
    let (status, message, hint) = if waiting.is_empty() {
        (
            CheckStatus::Ok,
            "no app is waiting for secrets".to_owned(),
            None,
        )
    } else {
        let mut seen = BTreeSet::new();
        let commands: Vec<String> = waiting
            .iter()
            .flat_map(|(n, s)| {
                s.waiting_for_secrets
                    .iter()
                    .map(move |sec| format!("weglarka secrets set {n} {sec} < file"))
            })
            .filter(|c| seen.insert(c.clone()))
            .collect();
        (
            CheckStatus::Warn,
            waiting
                .iter()
                .map(|(n, s)| format!("{n} waits for: {}", s.waiting_for_secrets.join(", ")))
                .collect::<Vec<_>>()
                .join("; "),
            Some(format!(
                "set the missing secrets; the deploy starts by itself: {}",
                commands.join("; ")
            )),
        )
    };
    out.push(DoctorCheck {
        id: "state.waiting_for_secrets".to_owned(),
        status,
        message,
        hint,
    });
}
