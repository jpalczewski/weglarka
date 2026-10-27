//! Admin endpoints for sites with environments (issue #205,
//! [`docs/decisions/0050-site-environments.md`](../../../docs/decisions/0050-site-environments.md)):
//! list/show/declare/remove a site and promote a digest into one of its environments.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use weglarka_api::{
    DeclareSiteRequest, ErrorCode, ListSitesResponse, PromoteRequest, PromoteResponse,
    SiteEnvSummary, SiteSummary, endpoints,
};
use weglarka_engine::promote::PromoteSource;
use weglarka_model::app::AppsFile;
use weglarka_model::environments::{EnvName, SiteName, instance_name};
use weglarka_model::podman::PodmanClient;
use weglarka_model::state::{self, StateFile};

use crate::admin::{Fail, deploy_result, mutating, parse_json};
use crate::app::Daemon;
use crate::volumes;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(endpoints::SITES_LIST.path, get(list_sites::<P>))
        .route(
            endpoints::SITES_SHOW.path,
            get(show_site::<P>)
                .put(declare_site::<P>)
                .delete(remove_site::<P>),
        )
        .route(endpoints::SITES_PROMOTE.path, post(promote::<P>))
}

fn parse_site(raw: &str) -> Result<SiteName, Fail> {
    SiteName::new(raw).map_err(|e| Fail(ErrorCode::InvalidRequest, e.to_string()))
}

fn parse_env(raw: &str) -> Result<EnvName, Fail> {
    EnvName::new(raw).map_err(|e| Fail(ErrorCode::InvalidRequest, e.to_string()))
}

fn summarize(apps: &AppsFile, st: &StateFile, name: &SiteName) -> Option<SiteSummary> {
    let spec = apps.sites.get(name)?;
    let envs = spec
        .env
        .iter()
        .filter_map(|(env, e)| {
            let instance = instance_name(name, env).ok()?;
            let app = st.apps.get(&instance);
            Some(SiteEnvSummary {
                env: env.clone(),
                track: e.track.clone(),
                promote_from: e.promote_from.clone(),
                domains: e.domains.clone(),
                current: app.and_then(|a| a.current.clone()),
                previous: app.and_then(|a| a.previous.clone()),
                instance,
            })
        })
        .collect();
    Some(SiteSummary {
        name: name.clone(),
        image: spec.image.clone(),
        envs,
    })
}

async fn list_sites<P: PodmanClient + 'static>(State(d): Shared<P>) -> Result<Response, Fail> {
    let apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
    let st = state::load_state(&d.paths.state.state).map_err(Fail::internal)?;
    let sites = apps
        .sites
        .keys()
        .filter_map(|n| summarize(&apps, &st, n))
        .collect();
    Ok(axum::Json(ListSitesResponse { sites }).into_response())
}

async fn show_site<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> Result<Response, Fail> {
    let name = parse_site(&raw)?;
    let apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
    let st = state::load_state(&d.paths.state.state).map_err(Fail::internal)?;
    summarize(&apps, &st, &name)
        .map(|s| axum::Json(s).into_response())
        .ok_or_else(|| Fail(ErrorCode::NotFound, format!("unknown site: {name}")))
}

async fn declare_site<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    body: Bytes,
) -> Result<StatusCode, Fail> {
    let name = parse_site(&raw)?;
    let req: DeclareSiteRequest = parse_json(&body)?;
    {
        let _g = d.desired_lock.lock().await;
        // The candidate set must be renderable (domains free, paths valid) before it is saved.
        let mut apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
        let mut sites = apps.sites.clone();
        sites.insert(name.clone(), req.spec.clone());
        apps.set_sites(sites).map_err(Fail::invalid)?;
        weglarka_ingress::Plan::build(&d.host, &apps.apps)
            .map_err(|e| Fail::invalid(e.to_string()))?;
        mutating(d.engine.declare_site(name, req.spec)).await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_site<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<StatusCode, Fail> {
    let name = parse_site(&raw)?;
    {
        let _g = d.desired_lock.lock().await;
        mutating(
            d.engine
                .remove_site(&name, volumes::flag(query.as_deref(), "purge")),
        )
        .await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/sites/{site}/envs/{env}/promote`. Like a deploy it holds the engine mutex through the
/// release, so it is deliberately not wrapped in a timeout.
async fn promote<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path((site, env)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, Fail> {
    let (site, env) = (parse_site(&site)?, parse_env(&env)?);
    let req: PromoteRequest = if body.is_empty() {
        PromoteRequest::default()
    } else {
        parse_json(&body)?
    };
    let source = match (req.digest, req.rollback) {
        (Some(_), true) => {
            return Err(Fail::invalid("--digest and --rollback exclude each other"));
        }
        (Some(digest), false) => PromoteSource::Digest(digest),
        (None, true) => PromoteSource::Rollback,
        (None, false) => PromoteSource::FromEnv,
    };
    let report = d.engine.promote(&site, &env, source, req.dry_run).await?;
    let plan = report.plan;
    let deploy = match report.outcome {
        Some(outcome) => Some(deploy_result(&d, &plan.target, outcome)?),
        None => None,
    };
    Ok(axum::Json(PromoteResponse {
        instance: plan.target,
        source: plan.source,
        source_current: plan.source_current,
        target_current: plan.target_current,
        target_previous: plan.target_previous,
        digest: plan.digest,
        deploy,
    })
    .into_response())
}
