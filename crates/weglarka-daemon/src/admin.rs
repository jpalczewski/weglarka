//! Admin API (axum) on a unix socket. Paths and methods come from `weglarka_api::endpoints`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use serde::Serialize;
use serde::de::DeserializeOwned;
use weglarka_api::{
    AddAppRequest, ApiError, AppSummary, DeployOutcome, DeployRequest, DeployResponse, ErrorCode,
    ListAppsResponse, ListSecretsResponse, RuntimeState, SecretInfo, SetSecretRequest,
    ShowAppResponse, StatusResponse, endpoints,
};
use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::deploy::DeployOutcome as CoreOutcome;
use weglarka_core::podman::{
    ContainerFilter, ContainerInfo, ContainerState, HealthStatus, PodmanClient,
};
use weglarka_core::reconcile::EngineError;
use weglarka_core::secret_store::{
    SecretStore, SecretValue, fingerprint, scoped_name, valid_secret_name,
};
use weglarka_core::state::{self, AppState};

use crate::app::{Daemon, MUTATION_TIMEOUT};
use crate::doctor;
use crate::update;
use crate::volumes;

const BODY_LIMIT: usize = 1024 * 1024;

type Shared<P> = State<Arc<Daemon<P>>>;
type ApiResult<T> = Result<T, Fail>;

/// API error: domain code + message; the HTTP status derives from `ErrorCode::http_status`.
#[derive(Debug)]
pub struct Fail(pub ErrorCode, pub String);

impl Fail {
    fn invalid(msg: impl Into<String>) -> Self {
        Self(ErrorCode::InvalidRequest, msg.into())
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self(ErrorCode::NotFound, msg.into())
    }
    fn internal(msg: impl ToString) -> Self {
        Self(ErrorCode::Internal, msg.to_string())
    }
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        let Fail(code, message) = self;
        if code == ErrorCode::Internal {
            tracing::error!(%message, "admin API internal error");
        }
        let status =
            StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, axum::Json(ApiError { code, message })).into_response()
    }
}

impl From<EngineError> for Fail {
    fn from(e: EngineError) -> Self {
        match e {
            EngineError::UnknownInstance(n) => Fail::not_found(format!("unknown app: {n}")),
            EngineError::Volume(m) => Fail::invalid(m),
            EngineError::Busy => Fail(
                ErrorCode::Conflict,
                "daemon is busy (deploy in progress); retry shortly".into(),
            ),
            e @ EngineError::MissingSecrets(_) => Fail(
                ErrorCode::Conflict,
                format!(
                    "{e}; set them with `weglarka secrets set` and the deploy starts by itself"
                ),
            ),
            other => Fail::internal(other),
        }
    }
}

fn json<T: Serialize>(v: T) -> Response {
    axum::Json(v).into_response()
}

fn parse_json<T: DeserializeOwned>(body: &Bytes) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|e| Fail::invalid(format!("invalid JSON body: {e}")))
}

fn parse_name(raw: &str) -> ApiResult<InstanceName> {
    InstanceName::new(raw).map_err(|e| Fail::invalid(e.to_string()))
}

/// Mutations wait for the engine mutex at most `MUTATION_TIMEOUT`; then 409 instead of hanging.
async fn mutating<T>(fut: impl Future<Output = Result<T, EngineError>>) -> ApiResult<T> {
    match tokio::time::timeout(MUTATION_TIMEOUT, fut).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(Fail(
            ErrorCode::Conflict,
            "daemon is busy (deploy in progress); retry shortly".into(),
        )),
    }
}

pub fn router<P: PodmanClient + 'static>(daemon: Arc<Daemon<P>>) -> Router {
    Router::new()
        .route(endpoints::STATUS.path, get(status::<P>))
        .route(
            endpoints::APPS_LIST.path,
            get(list_apps::<P>).post(add_app::<P>),
        )
        .route(
            endpoints::APPS_SHOW.path,
            get(show_app::<P>)
                .put(update::update_app::<P>)
                .delete(remove_app::<P>),
        )
        .route(endpoints::APPS_DEPLOY.path, post(deploy_app::<P>))
        .route(endpoints::SECRETS_LIST.path, get(list_secrets::<P>))
        .route(endpoints::SECRETS_SET.path, put(set_secret::<P>))
        .route(endpoints::DOCTOR.path, get(run_doctor::<P>))
        .fallback(|| async { Fail::not_found("no such endpoint") })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .merge(volumes::routes()) // after the layer: tar bodies are streamed and have their own cap
        .with_state(daemon)
}

// ── Reads (no engine mutex) ──────────────────────────────────────────────────

pub(crate) fn runtime_state(c: Option<&ContainerInfo>) -> RuntimeState {
    match c {
        None => RuntimeState::Missing,
        Some(c) if c.health == Some(HealthStatus::Unhealthy) => RuntimeState::Unhealthy,
        Some(c) if c.state == ContainerState::Running => RuntimeState::Running,
        Some(_) => RuntimeState::Stopped,
    }
}

async fn containers_by_instance<P: PodmanClient>(
    d: &Daemon<P>,
) -> Option<BTreeMap<String, ContainerInfo>> {
    match d
        .engine
        .podman()
        .container_list(&ContainerFilter::default())
        .await
    {
        Ok(list) => Some(list.into_iter().map(|c| (c.name.clone(), c)).collect()),
        Err(e) => {
            tracing::warn!(error = %e, "cannot list containers");
            None
        }
    }
}

async fn summaries<P: PodmanClient>(d: &Daemon<P>) -> ApiResult<Vec<AppSummary>> {
    let apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
    let st = state::load_state(&d.paths.state.state).map_err(Fail::internal)?;
    let containers = containers_by_instance(d).await;
    Ok(apps
        .apps
        .iter()
        .map(|(name, spec)| AppSummary {
            name: name.clone(),
            image: spec.image.clone(),
            domains: spec.domains.clone(),
            // Podman unavailable → unknown; `Missing` + a log warning (details: doctor).
            runtime: update::with_waiting(
                runtime_state(
                    containers
                        .as_ref()
                        .and_then(|m| m.get(&weglarka_core::labels::container_name(name))),
                ),
                st.apps.get(name),
            ),
            digest: st.apps.get(name).and_then(|s| s.current.clone()),
        })
        .collect())
}

async fn status<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    let podman_version = match d.engine.podman().version().await {
        Ok(v) => v.version,
        Err(e) => {
            tracing::warn!(error = %e, "podman version unavailable");
            "unreachable".to_owned()
        }
    };
    Ok(json(StatusResponse {
        api_version: weglarka_api::API_VERSION.to_owned(),
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        podman_version,
        apps: summaries(&d).await?,
    }))
}

async fn list_apps<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    Ok(json(ListAppsResponse {
        apps: summaries(&d).await?,
    }))
}

async fn show_app<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> ApiResult<Response> {
    let name = parse_name(&raw)?;
    let spec = load_spec(&d, &name)?;
    let st = state::load_state(&d.paths.state.state).map_err(Fail::internal)?;
    let container = d
        .engine
        .podman()
        .container_inspect(&weglarka_core::labels::container_name(&name))
        .await
        .ok();
    Ok(json(ShowAppResponse {
        state: st.apps.get(&name).cloned().unwrap_or_default(),
        runtime: update::with_waiting(runtime_state(container.as_ref()), st.apps.get(&name)),
        name,
        spec,
    }))
}

fn load_spec<P: PodmanClient>(d: &Daemon<P>, name: &InstanceName) -> ApiResult<AppSpec> {
    state::load_apps(&d.paths.state.apps)
        .map_err(Fail::internal)?
        .apps
        .remove(name)
        .ok_or_else(|| Fail::not_found(format!("unknown app: {name}")))
}

// ── Mutations ────────────────────────────────────────────────────────────────

async fn add_app<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    body: Bytes,
) -> ApiResult<Response> {
    let req: AddAppRequest = parse_json(&body)?;
    state::validate_app(&req.name, &req.spec).map_err(Fail::invalid)?;
    {
        let _g = d.desired_lock.lock().await;
        let mut apps = state::load_apps(&d.paths.state.apps)
            .map_err(Fail::internal)?
            .apps;
        if apps.contains_key(&req.name) {
            return Err(Fail(
                ErrorCode::AlreadyExists,
                format!("app {} already exists", req.name),
            ));
        }
        apps.insert(req.name.clone(), req.spec.clone());
        // Domains/ports must be renderable — otherwise ingress would fail to build.
        weglarka_ingress::Plan::build(&d.host, &apps).map_err(|e| Fail::invalid(e.to_string()))?;
        mutating(d.engine.upsert_app(req.name.clone(), req.spec.clone())).await?;
    }
    d.changed();
    Ok(json(ShowAppResponse {
        name: req.name,
        spec: req.spec,
        state: AppState::default(),
        runtime: RuntimeState::Missing,
    }))
}

async fn remove_app<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> ApiResult<StatusCode> {
    let name = parse_name(&raw)?;
    {
        let _g = d.desired_lock.lock().await;
        mutating(
            d.engine
                .remove_app_with_volumes(&name, volumes::flag(query.as_deref(), "purge_volumes")),
        )
        .await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

async fn deploy_app<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    let name = parse_name(&raw)?;
    let req: DeployRequest = if body.is_empty() {
        DeployRequest::default()
    } else {
        parse_json(&body)?
    };
    if req.image_ref.is_some() {
        return Err(Fail::invalid(
            "image_ref override is not supported yet; change `image` in the app spec",
        ));
    }
    load_spec(&d, &name)?;
    // A deploy holds the engine mutex through pull and health gate — deliberately without a timeout.
    let mut outcome = d.engine.deploy(&name, false).await?;
    if matches!(outcome, CoreOutcome::KnownBad { .. }) {
        // A manual deploy is the operator's explicit will: retry a known-bad digest.
        outcome = d.engine.deploy(&name, true).await?;
    }
    d.changed();
    let generation = state::load_state(&d.paths.state.state)
        .map(|s| s.apps.get(&name).map_or(0, |a| a.generation))
        .map_err(Fail::internal)?;
    let resp = match outcome {
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
        CoreOutcome::Failed { reason, .. } => {
            return Err(Fail::internal(format!("deploy failed: {reason}")));
        }
        CoreOutcome::KnownBad { .. } => {
            return Err(Fail::internal("deploy refused: known bad digest"));
        }
    };
    Ok(json(resp))
}

// ── Secrets ──────────────────────────────────────────────────────────────────

fn secret_infos<P: PodmanClient>(
    d: &Daemon<P>,
    instance: &InstanceName,
) -> ApiResult<Vec<SecretInfo>> {
    let prefix = format!("{instance}.");
    Ok(d.secrets
        .list()
        .map_err(Fail::internal)?
        .into_iter()
        .filter_map(|m| {
            m.name.strip_prefix(&prefix).map(|n| SecretInfo {
                name: n.to_owned(),
                updated_at: m.updated_at.clone(),
                fingerprint: m.fingerprint.clone(),
            })
        })
        .collect())
}

async fn list_secrets<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> ApiResult<Response> {
    let name = parse_name(&raw)?;
    load_spec(&d, &name)?;
    let d2 = d.clone();
    let secrets = tokio::task::spawn_blocking(move || secret_infos(&d2, &name))
        .await
        .map_err(Fail::internal)??;
    Ok(json(ListSecretsResponse { secrets }))
}

async fn set_secret<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path((raw, secret)): Path<(String, String)>,
    body: Bytes,
) -> ApiResult<Response> {
    let name = parse_name(&raw)?;
    if !valid_secret_name(&secret) {
        return Err(Fail::invalid("secret name must match [A-Za-z0-9_-]{1,64}"));
    }
    let req: SetSecretRequest = parse_json(&body)?;
    if req.value.is_empty() {
        return Err(Fail::invalid("secret value must not be empty"));
    }
    load_spec(&d, &name)?;
    let d2 = d.clone();
    let info = tokio::task::spawn_blocking(move || -> ApiResult<SecretInfo> {
        let value = SecretValue::new(req.value.into_bytes());
        let fp = fingerprint(&value);
        d2.secrets
            .set(&scoped_name(&name, &secret), value)
            .map_err(Fail::internal)?;
        let updated_at = secret_infos(&d2, &name)?
            .into_iter()
            .find(|i| i.name == secret)
            .map(|i| i.updated_at)
            .unwrap_or_default();
        Ok(SecretInfo {
            name: secret,
            updated_at,
            fingerprint: fp,
        })
    })
    .await
    .map_err(Fail::internal)??;
    d.changed();
    Ok(json(info))
}

async fn run_doctor<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    Ok(json(doctor::run(&d).await))
}
