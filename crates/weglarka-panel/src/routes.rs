//! The read-only pages. Every handler forwards the signed-in user's own token to the daemon, which
//! alone decides what that user may see: the panel never guesses a scope. A daemon refusal is
//! mapped to a page (see [`Req::problem`]), never to a bare 500 and never with the daemon's body.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use weglarka_api::endpoints::{
    APPS_LIST, APPS_SHOW, APPS_STATS, CERTIFICATES, CONFIG, DOCTOR, EVENTS_RECENT,
    NOTIFICATIONS_STATUS, SHARED_NETWORKS_LIST, SHARED_VOLUMES_LIST, SITES_LIST, STATS, STATUS,
    VOLUMES_LIST,
};
use weglarka_api::{
    AppStatsResponse, CertificatesResponse, ConfigView, DoctorReport, EventsResponse,
    ListAppsResponse, ListSharedNetworksResponse, ListSharedVolumesResponse, ListSitesResponse,
    ListVolumesResponse, NotifyStatusResponse, RuntimeState, ShowAppResponse, StatsResponse,
    StatusResponse,
};

use crate::app::AppState;
use crate::auth::{EndSession, LiveSession, signed_out};
use crate::daemon::{Call, DaemonError};
use crate::pages::{
    AppPage, AppVolumeRow, AppsPage, CertificatesPage, ConfigPage, DashboardPage, DoctorPage,
    ErrorPage, EventsPage, NetworkRow, NetworksPage, NotificationsPage, ProblemPage,
    SharedVolumeRow, Shell, SitesPage, StatsFragment, VolumesPage, respond,
};
use crate::session::{Session, SessionView};
use crate::views::{self, field, yes_no};
use weglarka_model::admin_auth::Scope;
use weglarka_model::app::InstanceName;

/// How many events the dashboard and the events page show before the live feed takes over.
const RECENT_EVENTS: usize = 50;
const DASHBOARD_EVENTS: usize = 8;
/// Certificates expiring within this many days are listed on the dashboard.
const CERT_WARN_DAYS: i64 = 30;
/// Concurrent per-app volume listings on the volumes page.
const VOLUME_CALLS_AT_ONCE: usize = 8;

/// What a handler needs from the request: the state, the session (already authenticated by
/// `require_session`, which put these in the extensions) and the address, for "try again" and
/// "sign in" links.
pub struct Req {
    pub state: AppState,
    pub view: SessionView,
    pub session: Arc<Session>,
    pub uri: Uri,
    pub headers: HeaderMap,
}

impl FromRequestParts<AppState> for Req {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Fail closed: a route without the session middleware has no session extensions.
        let (Some(view), Some(live)) = (
            parts.extensions.get::<SessionView>().cloned(),
            parts.extensions.get::<LiveSession>().cloned(),
        ) else {
            return Err(plain(StatusCode::UNAUTHORIZED));
        };
        Ok(Self {
            state: state.clone(),
            view,
            session: live.0,
            uri: parts.uri.clone(),
            headers: parts.headers.clone(),
        })
    }
}

fn plain(status: StatusCode) -> Response {
    ErrorPage {
        title: "Sign-in required",
        message: "You need to sign in to use the panel.",
        sign_in: Some("/auth/login"),
    }
    .respond(status)
}

impl Req {
    pub fn shell(&self, active: &'static str) -> Shell {
        Shell::new(&self.view, active)
    }

    /// One daemon call with the user's token; failures become the page to show.
    pub async fn get<T: DeserializeOwned>(&self, call: Call) -> Result<T, Box<Response>> {
        let result = self.state.daemon.send::<T>(&self.view.token, &call).await;
        self.ok(result, call.scope())
    }

    /// Unwraps a daemon result or turns the error into a response. `scope` is what the failed call
    /// needed (`Call::scope`).
    pub fn ok<T>(
        &self,
        result: Result<T, DaemonError>,
        scope: Option<Scope>,
    ) -> Result<T, Box<Response>> {
        result.map_err(|e| Box::new(self.problem(&e, scope)))
    }

    /// The answer for a daemon failure. The messages are fixed text: a daemon error message is
    /// shown only for 404 and other 4xx (it is the API's own, capped, and escaped by the template),
    /// never for 5xx, never a raw body.
    ///
    /// The session ends (through [`EndSession`], which `require_session` acts on) when the daemon
    /// gives this identity no access at all: a `401`, or a `403` on a call that needs only the lowest
    /// scope (`read`). A `403` on a higher-scope call, such as the logs, only means "not for you".
    pub fn problem(&self, err: &DaemonError, scope: Option<Scope>) -> Response {
        match err {
            DaemonError::Unauthorized => self.ended(),
            DaemonError::Forbidden if scope == Some(Scope::Read) => self.ended(),
            DaemonError::Forbidden => self.page(
                StatusCode::FORBIDDEN,
                "No access",
                "Your account is not allowed to see this. If you need access, ask an administrator.".into(),
                None,
            ),
            DaemonError::NotFound(message) => self.page(
                StatusCode::NOT_FOUND,
                "Not found",
                if message.is_empty() {
                    "There is nothing here.".into()
                } else {
                    message.clone()
                },
                None,
            ),
            DaemonError::InvalidRequest(_) => self.page(
                StatusCode::NOT_FOUND,
                "Not found",
                "There is nothing here.".into(),
                None,
            ),
            DaemonError::Rejected { message, .. } => self.page(
                StatusCode::BAD_GATEWAY,
                "The daemon refused the request",
                message.clone(),
                Some(self.retry_href()),
            ),
            DaemonError::Server { .. } | DaemonError::Decode { .. } => self.page(
                StatusCode::BAD_GATEWAY,
                "The daemon had a problem",
                "The daemon failed to answer this request. Try again in a moment.".into(),
                Some(self.retry_href()),
            ),
            DaemonError::Unreachable => self.page(
                StatusCode::SERVICE_UNAVAILABLE,
                "The daemon is unreachable",
                "The panel cannot reach the Węglarka daemon right now.".into(),
                Some(self.retry_href()),
            ),
            DaemonError::Timeout => self.page(
                StatusCode::GATEWAY_TIMEOUT,
                "The daemon did not answer in time",
                "The daemon is busy or stuck. Try again in a moment.".into(),
                Some(self.retry_href()),
            ),
        }
    }

    /// An application name as the API spells it; anything else is a 404 without a daemon call.
    pub fn app_name(&self, raw: &str) -> Result<String, Box<Response>> {
        match InstanceName::new(raw) {
            Ok(name) => Ok(name.to_string()),
            Err(_) => Err(Box::new(
                self.problem(&DaemonError::NotFound(String::new()), None),
            )),
        }
    }

    /// The sign-in answer that also ends the session.
    fn ended(&self) -> Response {
        let mut request = axum::extract::Request::new(Body::empty());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = self.uri.clone();
        let mut response = signed_out(&request, false);
        response.extensions_mut().insert(EndSession);
        response
    }

    fn retry_href(&self) -> String {
        self.uri
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string)
    }

    fn page(
        &self,
        status: StatusCode,
        title: &'static str,
        message: String,
        retry: Option<String>,
    ) -> Response {
        respond(
            &ProblemPage {
                shell: self.shell(""),
                title,
                message,
                retry,
            },
            status,
        )
    }
}

pub async fn dashboard(req: Req) -> Response {
    let daemon = &req.state.daemon;
    let token = &req.view.token;
    let (status_call, doctor_call, events_call, certs_call) = (
        Call::new(&STATUS),
        Call::new(&DOCTOR),
        Call::new(&EVENTS_RECENT),
        Call::new(&CERTIFICATES),
    );
    let (status, doctor, events, certs) = tokio::join!(
        daemon.send::<StatusResponse>(token, &status_call),
        daemon.send::<DoctorReport>(token, &doctor_call),
        daemon.send::<EventsResponse>(token, &events_call),
        daemon.send::<CertificatesResponse>(token, &certs_call),
    );
    let (status, doctor, events, certs) = match (
        req.ok(status, STATUS.scope),
        req.ok(doctor, DOCTOR.scope),
        req.ok(events, EVENTS_RECENT.scope),
        req.ok(certs, CERTIFICATES.scope),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d)) => (a, b, c, d),
        // A 401 anywhere ends the session; otherwise show the first problem.
        (Err(r), ..) | (_, Err(r), ..) | (_, _, Err(r), _) | (_, _, _, Err(r)) => return *r,
    };
    let (badge, text) = views::doctor_summary(&doctor.checks);
    let running = status
        .apps
        .iter()
        .filter(|a| a.runtime == RuntimeState::Running)
        .count();
    let attention = status
        .apps
        .iter()
        .filter(|a| {
            matches!(
                a.runtime,
                RuntimeState::Unhealthy | RuntimeState::Missing | RuntimeState::WaitingForSecret
            )
        })
        .count();
    respond(
        &DashboardPage {
            shell: req.shell("dashboard"),
            host: vec![
                field("Daemon", status.daemon_version.clone()),
                field("Podman", status.podman_version.clone()),
                field("API", status.api_version.clone()),
            ],
            doctor: badge,
            doctor_text: text,
            apps_total: status.apps.len(),
            apps_running: running,
            apps_attention: attention,
            certs: views::certs_soon(&certs, CERT_WARN_DAYS),
            events: events
                .events
                .iter()
                .rev()
                .take(DASHBOARD_EVENTS)
                .map(views::event_row)
                .collect(),
        },
        StatusCode::OK,
    )
}

pub async fn apps(req: Req) -> Response {
    let list = match req.get::<ListAppsResponse>(Call::new(&APPS_LIST)).await {
        Ok(list) => list,
        Err(r) => return *r,
    };
    // The usage columns are a courtesy: a failing stats call leaves them at `—`, not the page broken.
    let call = Call::new(&STATS);
    let usage = req
        .state
        .daemon
        .send::<StatsResponse>(&req.view.token, &call)
        .await
        .map(|s| views::usage_by_app(&s))
        .unwrap_or_default();
    respond(
        &AppsPage {
            shell: req.shell("apps"),
            apps: list
                .apps
                .iter()
                .map(|a| views::app_row(a, usage.get(a.name.as_str())))
                .collect(),
        },
        StatusCode::OK,
    )
}

pub async fn app(req: Req, Path(name): Path<String>) -> Response {
    let name = match req.app_name(&name) {
        Ok(name) => name,
        Err(r) => return *r,
    };
    let call = Call::new(&APPS_SHOW).param("name", name);
    let app = match req.get::<ShowAppResponse>(call).await {
        Ok(app) => app,
        Err(r) => return *r,
    };
    // `redacted` is true exactly when the token lacks `admin`, which is also what the logs stream
    // needs: a free signal, with no probe. The daemon still enforces it on the stream itself.
    let logs = !app.redacted;
    respond(
        &AppPage {
            shell: req.shell("apps"),
            app: views::app_detail(&app),
            logs,
        },
        StatusCode::OK,
    )
}

/// `GET /apps/{name}/stats`: the "Resources" fragment the app page polls every 10 s. An unknown app
/// or a refused session is the usual page; any other daemon failure is a muted line inside the
/// fragment (status 200), so one bad poll does not replace the page the user is reading.
pub async fn app_stats(req: Req, Path(name): Path<String>) -> Response {
    let name = match req.app_name(&name) {
        Ok(name) => name,
        Err(r) => return *r,
    };
    let call = Call::new(&APPS_STATS).param("name", name);
    let stats = match req
        .state
        .daemon
        .send::<AppStatsResponse>(&req.view.token, &call)
        .await
    {
        Ok(stats) => Some(views::stats_view(&stats)),
        // No access at all ends the session; a poll gets the small stop-polling fragment, not a page.
        Err(DaemonError::Unauthorized | DaemonError::Forbidden) => {
            let mut response = crate::auth::poll_ended(false);
            response.extensions_mut().insert(EndSession);
            return response;
        }
        Err(e @ (DaemonError::NotFound(_) | DaemonError::InvalidRequest(_))) => {
            return req.problem(&e, APPS_STATS.scope);
        }
        Err(_) => None,
    };
    respond(&StatsFragment { stats }, StatusCode::OK)
}

pub async fn doctor(req: Req) -> Response {
    let report = match req.get::<DoctorReport>(Call::new(&DOCTOR)).await {
        Ok(r) => r,
        Err(r) => return *r,
    };
    respond(
        &DoctorPage {
            shell: req.shell("doctor"),
            groups: views::doctor_groups(&report.checks),
        },
        StatusCode::OK,
    )
}

pub async fn volumes(req: Req) -> Response {
    let (shared, apps) = tokio::join!(
        req.get::<ListSharedVolumesResponse>(Call::new(&SHARED_VOLUMES_LIST)),
        req.get::<ListAppsResponse>(Call::new(&APPS_LIST)),
    );
    let (shared, apps) = match (shared, apps) {
        (Ok(shared), Ok(apps)) => (shared, apps),
        (Err(r), _) | (_, Err(r)) => return *r,
    };
    // TODO(#307): one call per app until the API has a host-wide volume listing.
    let mut pending = Vec::with_capacity(apps.apps.len());
    for app in &apps.apps {
        let call = Call::new(&VOLUMES_LIST).param("name", app.name.to_string());
        let daemon = req.state.daemon.clone();
        let token = req.view.token.clone();
        pending.push(async move { daemon.send::<ListVolumesResponse>(&token, &call).await });
    }
    let lists: Vec<_> = futures_util::stream::iter(pending)
        .buffered(VOLUME_CALLS_AT_ONCE)
        .collect()
        .await;
    let mut app_volumes = Vec::new();
    for (app, list) in apps.apps.iter().zip(lists) {
        let list = match req.ok(list, VOLUMES_LIST.scope) {
            Ok(l) => l,
            Err(r) => return *r,
        };
        app_volumes.extend(list.volumes.into_iter().map(|v| AppVolumeRow {
            app: app.name.to_string(),
            name: v.name,
            target: v.target,
            podman_name: v.podman_name,
            exists: yes_no(v.exists),
            shared: v.shared,
        }));
    }
    respond(
        &VolumesPage {
            shell: req.shell("volumes"),
            shared: shared
                .volumes
                .iter()
                .map(|v| SharedVolumeRow {
                    name: v.name.to_string(),
                    podman_name: v.podman_name.clone(),
                    group: v
                        .group
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                    members: members(&v.members),
                    uid_range: v
                        .uid_range
                        .map_or("—".to_owned(), |r| format!("{} + {}", r.start, r.size)),
                    exists: yes_no(v.exists),
                })
                .collect(),
            app_volumes,
        },
        StatusCode::OK,
    )
}

fn members(list: &[weglarka_model::app::InstanceName]) -> String {
    if list.is_empty() {
        "—".to_owned()
    } else {
        list.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub async fn networks(req: Req) -> Response {
    let list = match req
        .get::<ListSharedNetworksResponse>(Call::new(&SHARED_NETWORKS_LIST))
        .await
    {
        Ok(l) => l,
        Err(r) => return *r,
    };
    respond(
        &NetworksPage {
            shell: req.shell("networks"),
            networks: list
                .networks
                .iter()
                .map(|n| NetworkRow {
                    name: n.name.to_string(),
                    podman_name: n.podman_name.clone(),
                    members: members(&n.members),
                    exists: yes_no(n.exists),
                })
                .collect(),
        },
        StatusCode::OK,
    )
}

pub async fn sites(req: Req) -> Response {
    let list = match req.get::<ListSitesResponse>(Call::new(&SITES_LIST)).await {
        Ok(l) => l,
        Err(r) => return *r,
    };
    respond(
        &SitesPage {
            shell: req.shell("sites"),
            sites: list.sites.iter().map(views::site_row).collect(),
        },
        StatusCode::OK,
    )
}

pub async fn notifications(req: Req) -> Response {
    let status = match req
        .get::<NotifyStatusResponse>(Call::new(&NOTIFICATIONS_STATUS))
        .await
    {
        Ok(s) => s,
        Err(r) => return *r,
    };
    respond(
        &NotificationsPage {
            shell: req.shell("notifications"),
            notify: views::notify_view(&status),
        },
        StatusCode::OK,
    )
}

pub async fn certificates(req: Req) -> Response {
    let certs = match req
        .get::<CertificatesResponse>(Call::new(&CERTIFICATES))
        .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let mut summary = vec![field("Failures", certs.failures.to_string())];
    if let Some(days) = certs.renew_before_days {
        summary.push(field("Renew before expiry", format!("{days} days")));
    }
    if let Some(last) = &certs.last_pass {
        summary.push(field("Last pass", last.clone()));
    }
    respond(
        &CertificatesPage {
            shell: req.shell("certificates"),
            acme_enabled: certs.acme_enabled,
            summary,
            certs: views::cert_rows(&certs),
        },
        StatusCode::OK,
    )
}

pub async fn events(req: Req) -> Response {
    let recent = match req.get::<EventsResponse>(Call::new(&EVENTS_RECENT)).await {
        Ok(e) => e,
        Err(r) => return *r,
    };
    let stream = format!(
        "/events/stream?since={}&boot={}",
        recent.next_seq,
        url::form_urlencoded::byte_serialize(recent.boot_id.as_bytes()).collect::<String>()
    );
    respond(
        &EventsPage {
            shell: req.shell("events"),
            events: recent
                .events
                .iter()
                .rev()
                .take(RECENT_EVENTS)
                .map(views::event_row)
                .collect(),
            stream,
        },
        StatusCode::OK,
    )
}

pub async fn config(req: Req) -> Response {
    let config = match req.get::<ConfigView>(Call::new(&CONFIG)).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    respond(
        &ConfigPage {
            shell: req.shell("config"),
            sections: views::config_sections(&config),
        },
        StatusCode::OK,
    )
}
