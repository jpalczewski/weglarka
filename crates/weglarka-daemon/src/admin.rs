//! Admin API (axum) on a unix socket. Paths and methods come from `weglarka_api::endpoints`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::mpsc;
use weglarka_api::{
    AddAppRequest, ApiError, AppSummary, ConfigMountStatus, ConfigMountView, DeployOutcome,
    DeployRequest, DeployResponse, ErrorCode, HealthResponse,
    HostMountStatus as ApiHostMountStatus, HostMountView, ListAppsResponse, ListSecretsResponse,
    NotifyChannelSummary, NotifyStatusResponse, NotifyTestResponse, ReloadAction, ReloadRequest,
    ReloadResponse, RunFrame, RunRequest, RuntimeState, SecretInfo, SetSecretRequest,
    ShowAppResponse, StatusResponse, endpoints,
};
use weglarka_engine::config_mounts::{self, MountStatus, MountView};
use weglarka_engine::deploy::DeployOutcome as CoreOutcome;
use weglarka_engine::deploy::ReloadOutcome;
use weglarka_engine::reconcile::EngineError;
use weglarka_engine::run::{RunOptions, RunOutcome};
use weglarka_engine::volumes::RemoveAppOptions;
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::labels;
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ContainerState, HealthStatus, LogChunk, LogSource, PodmanClient,
};
use weglarka_model::secret_store::{
    SecretError, SecretStore, SecretValue, fingerprint, is_oidc_reserved, scoped_name,
    valid_secret_name,
};
use weglarka_model::state::{self, AppState};

use crate::app::{Daemon, MUTATION_TIMEOUT};
use crate::doctor;
use crate::images;
use crate::push;
use crate::shared_networks;
use crate::shared_volumes;
use crate::sites;
use crate::update;
use crate::volumes;

const BODY_LIMIT: usize = 1024 * 1024;

type Shared<P> = State<Arc<Daemon<P>>>;
type ApiResult<T> = Result<T, Fail>;

/// API error: domain code + message; the HTTP status derives from `ErrorCode::http_status`.
#[derive(Debug)]
pub struct Fail(pub ErrorCode, pub String);

impl Fail {
    pub(crate) fn invalid(msg: impl Into<String>) -> Self {
        Self(ErrorCode::InvalidRequest, msg.into())
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self(ErrorCode::NotFound, msg.into())
    }
    pub(crate) fn internal(msg: impl ToString) -> Self {
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
            EngineError::UnknownSharedVolume(n) => {
                Fail::not_found(format!("unknown shared volume: {n}"))
            }
            EngineError::UnknownSharedNetwork(n) => {
                Fail::not_found(format!("unknown shared network: {n}"))
            }
            EngineError::Volume(m) => Fail::invalid(m),
            EngineError::Busy => Fail(
                ErrorCode::Busy,
                "daemon is busy (deploy in progress); retry shortly".into(),
            ),
            e @ EngineError::MissingSecrets(_) => Fail(
                ErrorCode::Conflict,
                format!(
                    "{e}; set them with `weglarka secrets set` and the deploy starts by itself"
                ),
            ),
            // `depends_on` apps are not up yet: the start is refused, nothing was deployed.
            e @ EngineError::DependenciesNotReady { .. } => Fail(
                ErrorCode::Conflict,
                format!("{e}; start the dependencies first and retry the same command"),
            ),
            // Removing an app another one depends on: nothing was deleted.
            e @ EngineError::DependencyInUse { .. } => Fail(ErrorCode::Conflict, e.to_string()),
            // `secrets remove` (issue #80): an absent secret is a 404, a spec-bound one a 409
            // unless the request forces it.
            EngineError::Secret(SecretError::NotFound(m)) => Fail::not_found(m),
            e @ EngineError::SecretInUse { .. } => Fail(ErrorCode::Conflict, e.to_string()),
            // Private-registry credentials (docs/decisions/0026): the operator fixes the secret and retries.
            e @ (EngineError::RegistryAuth { .. }
            | EngineError::Secret(SecretError::Malformed { .. })) => {
                Fail(ErrorCode::Conflict, e.to_string())
            }
            // Shared-volume guards (issue #33): the engine message carries the members / the hint.
            e @ (EngineError::SharedVolumeInUse { .. }
            | EngineError::SharedVolumeHasData { .. }
            | EngineError::SharedVolumeBusy { .. }
            | EngineError::SharedGroupChange { .. }
            | EngineError::SharedNetworkInUse { .. }
            | EngineError::RangeChangeWithData { .. }) => Fail(ErrorCode::Conflict, e.to_string()),
            // Config mounts (issue #118): a spec/source problem is the request's fault (400).
            EngineError::Configs(message) => Fail::invalid(message),
            // `apps reload` of an app whose container is not running: nothing to signal or restart.
            // The engine message already points at `apps start`.
            e @ EngineError::ReloadNotRunning(_) => Fail(ErrorCode::Conflict, e.to_string()),
            // `weglarka run` (issue #106): nothing was created for any of these.
            e @ (EngineError::RunNotDeployed(_) | EngineError::RunLimit(_)) => {
                Fail(ErrorCode::Conflict, e.to_string())
            }
            EngineError::RunInvalid(message) => Fail::invalid(message),
            // `weglarka forward` (issue #108): nothing was created for any of these.
            e @ (EngineError::ForwardNotRunning(_) | EngineError::ForwardLimit(_)) => {
                Fail(ErrorCode::Conflict, e.to_string())
            }
            EngineError::ForwardInvalid(message) => Fail::invalid(message),
            // Sites with environments (issue #205): nothing was changed for any of these.
            e @ (EngineError::PromoteOnly(_)
            | EngineError::PromoteRefused(_)
            | EngineError::ManagedBySite { .. }) => Fail(ErrorCode::Conflict, e.to_string()),
            e @ EngineError::UnknownSite(_) => Fail::not_found(e.to_string()),
            EngineError::PromoteInvalid(message) => Fail::invalid(message),
            // `weglarka push` (issue #109): nothing was deployed for any of these.
            e @ EngineError::PushBusy => Fail(ErrorCode::Conflict, e.to_string()),
            e @ (EngineError::PushLoad(_) | EngineError::PushInvalid(_)) => {
                Fail::invalid(e.to_string())
            }
            other => Fail::internal(other),
        }
    }
}

fn json<T: Serialize>(v: T) -> Response {
    axum::Json(v).into_response()
}

pub(crate) fn parse_json<T: DeserializeOwned>(body: &Bytes) -> ApiResult<T> {
    serde_json::from_slice(body).map_err(|e| Fail::invalid(format!("invalid JSON body: {e}")))
}

pub(crate) fn parse_name(raw: &str) -> ApiResult<InstanceName> {
    InstanceName::new(raw).map_err(|e| Fail::invalid(e.to_string()))
}

/// Mutations wait for the engine mutex at most `MUTATION_TIMEOUT`; then 409 instead of hanging.
pub(crate) async fn mutating<T>(fut: impl Future<Output = Result<T, EngineError>>) -> ApiResult<T> {
    match tokio::time::timeout(MUTATION_TIMEOUT, fut).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(Fail(
            ErrorCode::Busy,
            "daemon is busy (deploy in progress); retry shortly".into(),
        )),
    }
}

pub fn router<P: PodmanClient + 'static>(daemon: Arc<Daemon<P>>) -> Router {
    Router::new()
        .route(endpoints::STATUS.path, get(status::<P>))
        .route(endpoints::HEALTH.path, get(health::<P>))
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
        .route(endpoints::APPS_RELOAD.path, post(reload_app::<P>))
        .route(endpoints::APPS_RUN.path, post(run_app::<P>))
        .route(endpoints::SECRETS_LIST.path, get(list_secrets::<P>))
        .route(endpoints::SECRETS_SET.path, put(set_secret::<P>))
        .route(endpoints::SECRETS_REMOVE.path, delete(remove_secret::<P>))
        .route(endpoints::DOCTOR.path, get(run_doctor::<P>))
        .route(
            endpoints::NOTIFICATIONS_STATUS.path,
            get(notify_status::<P>),
        )
        .route(endpoints::NOTIFICATIONS_TEST.path, post(notify_test::<P>))
        .route(
            endpoints::APPS_FORWARD.path,
            post(crate::forward::forward_app::<P>),
        )
        .fallback(|| async { Fail::not_found("no such endpoint") })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .merge(volumes::routes()) // after the layer: tar bodies are streamed and have their own cap
        .merge(shared_volumes::routes())
        .merge(shared_networks::routes())
        .merge(sites::routes())
        .merge(images::routes())
        .merge(push::routes()) // a streamed archive, like the volume tars
        .with_state(daemon)
}

// ── Notifications (issue #38) ────────────────────────────────────────────────

/// `GET /v1/notifications`: channels, the pending outbox and the last delivery error.
async fn notify_status<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    let Some(handle) = &d.notify else {
        return Ok(json(NotifyStatusResponse::default()));
    };
    let snapshot = handle.snapshot();
    Ok(json(NotifyStatusResponse {
        enabled: snapshot.enabled,
        channels: snapshot
            .channels
            .into_iter()
            .map(|channel| NotifyChannelSummary {
                name: channel.name,
                min_severity: channel.min_severity,
                pending: u32::try_from(channel.pending).unwrap_or(u32::MAX),
            })
            .collect(),
        pending: u32::try_from(snapshot.pending).unwrap_or(u32::MAX),
        dropped: snapshot.dropped,
        last_error: snapshot.last_error,
        last_delivered_at: snapshot.last_delivered_at,
    }))
}

/// `POST /v1/notifications/test`: delivers a test notification now (it bypasses the outbox, so a test
/// is visible even while the queue is empty, and it never pollutes it).
async fn notify_test<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    let Some(handle) = &d.notify else {
        return Err(Fail(
            ErrorCode::Conflict,
            "notifications are not configured: add a [notify.ntfy] section to weglarka.toml and restart the daemon"
                .into(),
        ));
    };
    let response = match handle.test(&d.host.webhook.domain).await {
        Ok(()) => NotifyTestResponse {
            delivered: true,
            error: None,
        },
        Err(error) => NotifyTestResponse {
            delivered: false,
            error: Some(error),
        },
    };
    Ok(json(response))
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

/// Runtime state that also knows the `start = false` intent: a provisioned app has a pinned digest
/// but no container, i.e. Podman reports it as `Missing` while the spec says "not started by
/// design" — [`RuntimeState::NotStarted`]. Everything else falls back to [`runtime_state`].
pub(crate) fn runtime_state_for(
    spec: &AppSpec,
    state: Option<&AppState>,
    container: Option<&ContainerInfo>,
) -> RuntimeState {
    match (container, state) {
        (None, Some(s)) if !spec.start && s.current.is_some() => RuntimeState::NotStarted,
        _ => runtime_state(container),
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
        .map(|(name, spec)| {
            let container = containers
                .as_ref()
                .and_then(|m| m.get(&labels::container_name(name)));
            let app_state = st.apps.get(name);
            AppSummary {
                name: name.clone(),
                image: spec.image.clone(),
                domains: spec.domains.clone(),
                // Podman unavailable → unknown; `Missing` + a log warning (details: doctor).
                runtime: update::with_waiting(
                    runtime_state_for(spec, app_state, container),
                    app_state,
                ),
                digest: app_state.and_then(|s| s.current.clone()),
                site: apps.origin(name).map(|o| format!("{}/{}", o.site, o.env)),
            }
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

/// `GET /v1/health`: the admin API answers, which is the readiness signal the host-side self-update
/// watchdog treats as "the switched daemon came up" (issue #100, `docs/decisions/0034`).
///
/// Deliberately cheap — no Podman call and no state read — so a Podman hiccup cannot look like a
/// failed update. The socket is bound only after every startup precondition, so answering means the
/// process really got that far.
async fn health<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    Ok(json(HealthResponse {
        status: "ok".to_owned(),
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_secs: d.started.elapsed().as_secs(),
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
        .container_inspect(&labels::container_name(&name))
        .await
        .ok();
    let app_state = st.apps.get(&name);
    Ok(json(ShowAppResponse {
        state: app_state.cloned().unwrap_or_default(),
        runtime: update::with_waiting(
            runtime_state_for(&spec, app_state, container.as_ref()),
            app_state,
        ),
        configs: config_views(&d, &spec),
        host_mounts: host_mount_views(&d, &spec),
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

/// Contract view of one declared mount (issue #118): what `apps show`/`apps reload` report.
fn mount_view(view: MountView) -> ConfigMountView {
    ConfigMountView {
        source: view.source,
        target: view.target,
        status: match view.status {
            MountStatus::Ok => ConfigMountStatus::Ok,
            MountStatus::Missing => ConfigMountStatus::Missing,
            MountStatus::NoRoot => ConfigMountStatus::NoRoot,
            MountStatus::OutsideRoot => ConfigMountStatus::OutsideRoot,
            MountStatus::NotFileOrDir => ConfigMountStatus::NotFileOrDir,
            MountStatus::Unreadable => ConfigMountStatus::Unreadable,
        },
        fingerprint: view.fingerprint,
        detail: view.detail,
    }
}

/// Resolved config mounts of `spec` (issue #118); `None` when the app declares none, so the field
/// stays out of the response and apps without configs keep their shape. `describe` never fails: a
/// broken mount is a status the caller reports.
fn config_views<P: PodmanClient>(d: &Daemon<P>, spec: &AppSpec) -> Option<Vec<ConfigMountView>> {
    (!spec.configs.is_empty()).then(|| {
        config_mounts::describe(d.paths.config_root.as_deref(), spec)
            .into_iter()
            .map(mount_view)
            .collect()
    })
}

/// Declared host mounts of `spec` (issue #178) against the allowlist; `None` when there are none.
fn host_mount_views<P: PodmanClient>(d: &Daemon<P>, spec: &AppSpec) -> Option<Vec<HostMountView>> {
    use weglarka_engine::host_mounts::{self, HostMountStatus as S};
    (!spec.host_mounts.is_empty()).then(|| {
        host_mounts::describe(&d.host.runtime.host_mounts, spec)
            .into_iter()
            .map(|v| HostMountView {
                source: v.source,
                target: v.target,
                status: match v.status {
                    S::Ok => ApiHostMountStatus::Ok,
                    S::NotAllowed => ApiHostMountStatus::NotAllowed,
                    S::Missing => ApiHostMountStatus::Missing,
                    S::Redirected => ApiHostMountStatus::Redirected,
                    S::NotFileOrDir => ApiHostMountStatus::NotFileOrDir,
                    S::Unreadable => ApiHostMountStatus::Unreadable,
                },
                detail: v.detail,
            })
            .collect()
    })
}

/// `apps add`/`apps update`: an app with `configs` needs `config_root` in `weglarka.toml`. The
/// sources themselves are not checked here — a file that does not exist yet must not block adding
/// the app; reconcile blocks the instance and `doctor` warns until the source appears. The lexical
/// rules (`relative`, no `..`, unique `target`) are already enforced by `state::validate_app`.
pub(crate) fn validate_host_rules<P: PodmanClient>(
    d: &Daemon<P>,
    name: &InstanceName,
    spec: &AppSpec,
) -> ApiResult<()> {
    // Host mounts (issue #178): the source must be an exact entry of the operator's allowlist, so a
    // bad one is a 400 now instead of a blocked app later.
    weglarka_engine::host_mounts::check_allowed(&d.host.runtime.host_mounts, spec)
        .map_err(|e| Fail::invalid(e.to_string()))?;
    weglarka_engine::host_mounts::check_groups(&d.host.runtime.group_add, spec)
        .map_err(|e| Fail::invalid(e.to_string()))?;
    // Forward auth needs `[identity]` and domains, and the provider cannot protect itself.
    weglarka_model::identity::validate_host_app(&d.host, name, spec).map_err(Fail::invalid)?;
    if spec.configs.is_empty() || d.paths.config_root.is_some() {
        return Ok(());
    }
    Err(Fail::invalid(
        "the app declares `configs`, but weglarka.toml sets no `config_root`; set it to the host \
         directory with the config files, then re-run `weglarka platform install` so the daemon \
         container mounts it read-only",
    ))
}

// ── Mutations ────────────────────────────────────────────────────────────────

async fn add_app<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    body: Bytes,
) -> ApiResult<Response> {
    let req: AddAppRequest = parse_json(&body)?;
    state::validate_app(&req.name, &req.spec).map_err(Fail::invalid)?;
    validate_host_rules(&d, &req.name, &req.spec)?;
    {
        let _g = d.desired_lock.lock().await;
        let mut apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
        if apps.apps.contains_key(&req.name) {
            return Err(Fail(
                ErrorCode::AlreadyExists,
                format!("app {} already exists", req.name),
            ));
        }
        apps.apps.insert(req.name.clone(), req.spec.clone());
        // Every shared-volume mount must name a declared volume (issue #33): a typo would silently
        // create a second empty volume. Cross-app rule, so it sees the candidate app set.
        weglarka_model::shared_volumes::validate(&apps).map_err(Fail::invalid)?;
        // Same for a shared-network membership (issue #128), plus the alias rules.
        weglarka_model::shared_networks::validate(&apps).map_err(Fail::invalid)?;
        // Host-wide `host_ports` rules first (privileged ports, another app on the same socket, the
        // ingress bind), then domains/ports must be renderable. Both see the candidate app set.
        weglarka_model::host_ports::validate(&d.host, &apps)
            .map_err(|e| Fail::invalid(e.to_string()))?;
        // `depends_on`: a target must exist and the graph must stay acyclic (issue #35).
        weglarka_model::depends::validate(&apps).map_err(Fail::invalid)?;
        weglarka_ingress::Plan::build(&d.host, &apps.apps)
            .map_err(|e| Fail::invalid(e.to_string()))?;
        mutating(d.engine.upsert_app(req.name.clone(), req.spec.clone())).await?;
    }
    // `start = false`: provision synchronously (pin the digest, create the network, uid range and
    // volumes) so the response can already report `not_started`. `start = true` is deployed by the
    // reconcile woken by `changed()`.
    if !req.spec.start {
        d.engine.deploy(&req.name, false).await?;
    }
    d.changed();
    let st = state::load_state(&d.paths.state.state).map_err(Fail::internal)?;
    let container = d
        .engine
        .podman()
        .container_inspect(&labels::container_name(&req.name))
        .await
        .ok();
    let app_state = st.apps.get(&req.name);
    Ok(json(ShowAppResponse {
        runtime: update::with_waiting(
            runtime_state_for(&req.spec, app_state, container.as_ref()),
            app_state,
        ),
        state: app_state.cloned().unwrap_or_default(),
        // Only `GET /v1/apps/{name}` resolves the mounts: add/update never touch `config_root`.
        configs: None,
        host_mounts: None,
        name: req.name,
        spec: req.spec,
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
        mutating(d.engine.remove_app_with_purges(
            &name,
            RemoveAppOptions {
                purge_volumes: volumes::flag(query.as_deref(), "purge_volumes"),
                purge_secrets: volumes::flag(query.as_deref(), "purge_secrets"),
            },
        ))
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
    load_spec(&d, &name)?;
    // A deploy holds the engine mutex through pull and health gate — deliberately without a timeout.
    let outcome = match &req.image_ref {
        // An image of the same repository: pinned in the state, the spec keeps its tag (issue #109).
        Some(reference) => d.engine.push_reference(&name, reference).await?,
        None => {
            let mut outcome = d.engine.deploy(&name, false).await?;
            if matches!(outcome, CoreOutcome::KnownBad { .. }) {
                // A manual deploy is the operator's explicit will: retry a known-bad digest.
                outcome = d.engine.deploy(&name, true).await?;
            }
            outcome
        }
    };
    deploy_response(&d, &name, outcome)
}

/// Marks the state as changed and turns the engine's outcome into the `deploy` response; shared by
/// `apps deploy` and `weglarka push`.
pub(crate) fn deploy_response<P: PodmanClient + 'static>(
    d: &Daemon<P>,
    name: &InstanceName,
    outcome: CoreOutcome,
) -> ApiResult<Response> {
    deploy_result(d, name, outcome).map(json)
}

/// The typed body of [`deploy_response`].
pub(crate) fn deploy_result<P: PodmanClient + 'static>(
    d: &Daemon<P>,
    name: &InstanceName,
    outcome: CoreOutcome,
) -> ApiResult<DeployResponse> {
    d.changed();
    let generation = state::load_state(&d.paths.state.state)
        .map(|s| s.apps.get(name).map_or(0, |a| a.generation))
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
        CoreOutcome::Provisioned { digest } => DeployResponse {
            outcome: DeployOutcome::Provisioned,
            generation,
            digest: Some(digest),
        },
        CoreOutcome::Failed { reason, .. } => {
            return Err(Fail::internal(format!("deploy failed: {reason}")));
        }
        CoreOutcome::KnownBad { .. } => {
            return Err(Fail::internal("deploy refused: known bad digest"));
        }
    };
    Ok(resp)
}

// ── Reload (issue #118) ─────────────────────────────────────────────────────

/// `POST /v1/apps/{name}/reload`: send `reload_signal` to the running container, restart it when the
/// spec sets none, or recreate it from the pinned digest with `{"recreate": true}` (the escape hatch
/// for editors that save by write-and-rename — a single-file bind mount keeps the old inode).
/// Changes no desired state; the response reports the mount views the app now sees.
async fn reload_app<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    let name = parse_name(&raw)?;
    let req: ReloadRequest = if body.is_empty() {
        ReloadRequest::default()
    } else {
        parse_json(&body)?
    };
    let spec = load_spec(&d, &name)?;
    let (action, signal) = if req.recreate {
        // Recreating still needs a container to replace: a provisioned (`start = false`) or stopped
        // app gets the same conflict as a plain reload, with the `apps start` hint.
        let running = matches!(
            d.engine
                .podman()
                .container_inspect(&labels::container_name(&name))
                .await,
            Ok(info) if info.state == ContainerState::Running
        );
        if !running {
            return Err(Fail::from(EngineError::ReloadNotRunning(name)));
        }
        // A forced deploy goes through the existing recreate path (`launch`): ADR 0022 prescribes it
        // for editors that save with write-and-rename. Like a deploy, it holds the engine mutex
        // through the health gate, so it is not wrapped in `mutating()`.
        d.engine.deploy(&name, true).await?;
        (ReloadAction::Recreated, None)
    } else {
        match mutating(d.engine.reload(&name)).await? {
            ReloadOutcome::Signalled { signal } => (ReloadAction::Signalled, Some(signal)),
            ReloadOutcome::Restarted => (ReloadAction::Restarted, None),
        }
    };
    d.changed();
    Ok(json(ReloadResponse {
        name,
        action,
        signal,
        configs: config_views(&d, &spec),
    }))
}

// ── One-off containers (issue #106) ─────────────────────────────────────────

/// `POST /v1/apps/{name}/run`: run a command once in a fresh container of the app and stream its
/// output as [`RunFrame`]s. Everything that can be refused is refused with an ordinary JSON error
/// *before* the stream starts; after that the last frame says how the run ended. Closing the
/// connection kills the run and removes the container. Changes no desired state.
async fn run_app<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    body: Bytes,
) -> ApiResult<Response> {
    let name = parse_name(&raw)?;
    let req: RunRequest = if body.is_empty() {
        RunRequest::default()
    } else {
        parse_json(&body)?
    };
    let options = RunOptions {
        command: req.command,
        entrypoint: req.entrypoint,
        env: req.env,
        timeout: req.timeout_secs.map(|s| Duration::from_secs(s.into())),
    };
    let pending = mutating(d.engine.prepare_run(&name, &options)).await?;

    let (chunks_tx, mut chunks_rx) = mpsc::channel::<LogChunk>(16);
    let (frames_tx, frames_rx) = mpsc::channel::<Bytes>(16);
    // The run lives in its own task, so it ends the same way whether the client reads on or hangs up:
    // a dropped response body closes `frames_tx`, the pump stops and drops `chunks_rx`, and the
    // engine sees its output channel close and kills the container.
    tokio::spawn(async move {
        let pump = {
            let frames_tx = frames_tx.clone();
            async move {
                loop {
                    tokio::select! {
                        chunk = chunks_rx.recv() => {
                            let Some(chunk) = chunk else { break };
                            let frame = match chunk.source {
                                LogSource::Stdout => RunFrame::Stdout(chunk.data.to_vec()),
                                LogSource::Stderr => RunFrame::Stderr(chunk.data.to_vec()),
                            };
                            if frames_tx.send(Bytes::from(frame.encode())).await.is_err() {
                                break;
                            }
                        }
                        () = frames_tx.closed() => break,
                    }
                }
            }
        };
        let (outcome, ()) = tokio::join!(pending.drive(chunks_tx), pump);
        let last = match outcome {
            Ok(RunOutcome::Exited(code)) => Some(RunFrame::Exit(code)),
            Ok(RunOutcome::TimedOut) => Some(RunFrame::TimedOut),
            Ok(RunOutcome::Cancelled) => None,
            Err(e) => Some(RunFrame::Error(e.to_string())),
        };
        if let Some(frame) = last {
            let _ = frames_tx.send(Bytes::from(frame.encode())).await;
        }
    });

    let stream = futures_util::stream::unfold(frames_rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|frame| (Ok::<_, std::convert::Infallible>(frame), rx))
    });
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            weglarka_api::RUN_STREAM_CONTENT_TYPE,
        )],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
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

/// The OIDC client credentials are minted as a pair by `SecretOps` (#213); `set` or `remove` of one
/// half would split it, so both are refused.
fn refuse_reserved(secret: &str) -> ApiResult<()> {
    if is_oidc_reserved(secret) {
        return Err(Fail::invalid(format!(
            "secret {secret} is managed by Węglarka and cannot be set or removed directly; \
             use `weglarka oidc rotate <app>` to replace it"
        )));
    }
    Ok(())
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
    refuse_reserved(&secret)?;
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

/// `DELETE /v1/apps/{name}/secrets/{secret}` (issue #80): removes one secret from the store.
///
/// The app need **not** exist in `apps.toml` — that is how the leftovers of a removed (or renamed)
/// instance are cleaned up, so this handler deliberately skips [`load_spec`]. A secret the app's
/// spec still binds is a 409 unless `?force=true`; the app then waits for it again on the next
/// reconcile (the removal itself never deploys).
async fn remove_secret<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path((raw, secret)): Path<(String, String)>,
    RawQuery(query): RawQuery,
) -> ApiResult<StatusCode> {
    let name = parse_name(&raw)?;
    if !valid_secret_name(&secret) {
        return Err(Fail::invalid("secret name must match [A-Za-z0-9_-]{1,64}"));
    }
    refuse_reserved(&secret)?;
    let force = volumes::flag(query.as_deref(), "force");
    mutating(d.engine.remove_secret(&name, &secret, force)).await?;
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

async fn run_doctor<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    Ok(json(doctor::run(&d).await))
}
