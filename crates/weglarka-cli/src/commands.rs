//! Command execution. Each returns an exit code (0 or a special one, e.g. `doctor`/rollback);
//! errors are returned as [`CliError`].

use std::io::{IsTerminal, Read};
use std::path::Path;

use serde::Serialize;
use weglarka_api::endpoints;
use weglarka_api::{
    AbandonReservationRequest, AbandonReservationResponse, AddAppRequest, AppSummary,
    ConfigMountStatus, ConfigMountView, DeployOutcome, DeployRequest, DeployResponse, DoctorReport,
    HostSecretInfo, ListAppsResponse, ListHostSecretsResponse, ListReservationsResponse,
    ListSecretsResponse, NotifyStatusResponse, NotifyTestResponse, PruneImagesRequest,
    PruneImagesResponse, PrunedImage, ReloadAction, ReloadRequest, ReloadResponse, ReservationView,
    RollbackResponse, SecretInfo, SetSecretRequest, SharedServiceSummary, ShowAppResponse,
    StatusResponse,
};
use weglarka_model::app::{AppIngress, AppSpec, Digest, HealthGate, InstanceName};
use weglarka_model::secret_store::valid_secret_name;
use weglarka_model::shared_services::{RedisProfile, ServiceKind};
use weglarka_model::units::human_bytes;

use crate::cli::{
    AbandonReservationArgs, AddArgs, AppsCommand, Cli, Command, DeployArgs, DoctorArgs,
    HostSecretRemoveArgs, HostSecretSetArgs, HostSecretsCommand, ImagesCommand, NotifyCommand,
    PruneImagesArgs, ReloadArgs, RemoveArgs, ReservationsCommand, RollbackArgs, SecretRemoveArgs,
    SecretSetArgs, SecretsCommand,
};
use crate::client::{ApiClient, ApiRequest};
use crate::error::{CliError, Kind, exit};
use crate::output::{emit, table};
use crate::preflight;
use crate::settings::{Overrides, Target};

pub async fn run(cli: Cli) -> Result<i32, CliError> {
    let json = cli.json;
    let overrides = Overrides {
        config: cli.config,
        socket: cli.socket,
        host: cli.host,
    };
    match cli.command {
        Command::Apps(AppsCommand::Add(a)) => apps_add(json, &overrides, *a).await,
        Command::Apps(AppsCommand::Update(a)) => {
            crate::update::apps_update(json, &overrides, *a).await
        }
        Command::Apps(AppsCommand::Diff(a)) => crate::update::apps_diff(json, &overrides, a).await,
        Command::Apps(AppsCommand::Start(a)) => {
            crate::update::apps_start(json, &overrides, a).await
        }
        Command::Apps(AppsCommand::Stop(a)) => crate::update::apps_stop(json, &overrides, a).await,
        Command::Apps(AppsCommand::Reload(a)) => apps_reload(json, &overrides, a).await,
        Command::Apps(AppsCommand::Rollback(a)) => apps_rollback(json, &overrides, a).await,
        Command::Apps(AppsCommand::Remove(a)) => apps_remove(json, &overrides, a).await,
        Command::Apps(AppsCommand::List) => apps_list(json, &overrides).await,
        Command::Apps(AppsCommand::Show { name }) => apps_show(json, &overrides, &name).await,
        Command::Logs(a) => crate::logs::run(json, &overrides, a).await,
        Command::Access(a) => crate::access::run(json, &overrides, a).await,
        Command::Stats(a) => crate::stats::run(json, &overrides, a).await,
        Command::Run(a) => crate::run::run(json, &overrides, a).await,
        Command::Forward(a) => crate::forward::run(json, &overrides, a).await,
        Command::Deploy(a) => deploy(json, &overrides, a).await,
        Command::Push(a) => crate::push::run(json, &overrides, a).await,
        Command::Status => status(json, &overrides).await,
        Command::Secrets(SecretsCommand::Set(a)) => secrets_set(json, &overrides, a).await,
        Command::Secrets(SecretsCommand::List { app }) => {
            secrets_list(json, &overrides, &app).await
        }
        Command::Secrets(SecretsCommand::Remove(a)) => secrets_remove(json, &overrides, a).await,
        Command::Secrets(SecretsCommand::Host(HostSecretsCommand::Set(a))) => {
            host_secrets_set(json, &overrides, a).await
        }
        Command::Secrets(SecretsCommand::Host(HostSecretsCommand::List)) => {
            host_secrets_list(json, &overrides).await
        }
        Command::Secrets(SecretsCommand::Host(HostSecretsCommand::Remove(a))) => {
            host_secrets_remove(json, &overrides, a).await
        }
        Command::Doctor(a) => doctor(json, &overrides, a).await,
        Command::Volumes(c) => crate::volumes::run(json, &overrides, c).await,
        Command::Networks(c) => crate::networks::run(json, &overrides, c).await,
        Command::Oidc(c) => crate::oidc::run(json, &overrides, c).await,
        Command::Sites(c) => crate::sites::run(json, &overrides, c).await,
        Command::Promote(a) => crate::sites::promote(json, &overrides, a).await,
        Command::Images(ImagesCommand::Prune(a)) => images_prune(json, &overrides, a).await,
        Command::Images(ImagesCommand::Reservations(ReservationsCommand::List)) => {
            images_reservations_list(json, &overrides).await
        }
        Command::Images(ImagesCommand::Reservations(ReservationsCommand::Abandon(a))) => {
            images_reservations_abandon(json, &overrides, a).await
        }
        Command::Notify(NotifyCommand::Status) => notify_status(json, &overrides).await,
        Command::Notify(NotifyCommand::Test) => notify_test(json, &overrides).await,
        Command::Login(a) => crate::login::login(json, overrides.host_name()?.as_deref(), a).await,
        Command::Logout => crate::login::logout(json, overrides.host_name()?.as_deref()).await,
        Command::Whoami => crate::login::whoami(json, overrides.host_name()?.as_deref()).await,
    }
}

pub(crate) fn client(overrides: &Overrides) -> Result<ApiClient, CliError> {
    match overrides.target()? {
        Target::Socket(socket) => Ok(ApiClient::new(socket)),
        Target::Host(host) => ApiClient::remote(&host),
    }
}

pub(crate) fn instance(name: &str) -> Result<InstanceName, CliError> {
    InstanceName::new(name).map_err(|e| {
        CliError::usage(e.to_string())
            .with_hint("instance names: lowercase letters, digits and hyphens, e.g. `ntfy-zig`")
    })
}

/// The secret name ends up in a URL path, so we restrict the alphabet (no percent-encoding). The
/// rule itself is the model's, so the CLI and the daemon cannot drift apart.
pub(crate) fn secret_name(name: &str) -> Result<&str, CliError> {
    if valid_secret_name(name) {
        Ok(name)
    } else {
        Err(CliError::usage(format!("invalid secret name {name:?}"))
            .with_hint("allowed: [A-Za-z0-9_-], 1–64 characters"))
    }
}

/// The request line of every `--dry-run`: method and target (path plus query) of the request a
/// real run would send, taken from the same [`ApiRequest`].
#[derive(Debug, Serialize)]
pub(crate) struct DryRunRequest {
    dry_run: bool,
    method: &'static str,
    path: String,
}

impl DryRunRequest {
    pub(crate) fn new(req: &ApiRequest) -> Self {
        Self {
            dry_run: true,
            method: req.method(),
            path: req.target(),
        }
    }

    /// The first line of the human output.
    pub(crate) fn head(&self) -> String {
        format!("dry-run: {} {}\n", self.method, self.path)
    }
}

/// The last line of every `--dry-run`'s human output.
pub(crate) const NOTHING_SENT: &str = "nothing was sent\n";

/// Result of `--dry-run`: the request that would be sent (secret values masked).
#[derive(Debug, Serialize)]
pub(crate) struct DryRun {
    #[serde(flatten)]
    request: DryRunRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
}

impl DryRun {
    pub(crate) fn new(req: &ApiRequest, body: Option<serde_json::Value>) -> Self {
        Self {
            request: DryRunRequest::new(req),
            body,
        }
    }

    pub(crate) fn print(&self, json: bool) {
        emit(json, self, || {
            let mut s = self.request.head();
            if let Some(b) = &self.body {
                s.push_str(&format!(
                    "body: {}\n",
                    serde_json::to_string_pretty(b).unwrap_or_default()
                ));
            }
            s.push_str(NOTHING_SENT);
            s
        });
    }
}

// ---------- apps ----------

/// Builds an `AppSpec` from the flags of `apps add` (`--spec` wins when given).
pub(crate) fn build_spec(a: &AddArgs) -> Result<AppSpec, CliError> {
    if let Some(path) = &a.spec {
        return crate::update::read_spec_file(path);
    }
    let image = a
        .image
        .clone()
        .ok_or_else(|| CliError::usage("image is required unless --spec is given"))?;
    let mut spec = AppSpec {
        kind: Default::default(),
        image,
        command: Vec::new(),
        domains: a.domains.clone(),
        paths: a.paths.clone(),
        port: a.port,
        ingress: AppIngress {
            streaming: a.streaming,
            strip_prefix: a.strip_prefix,
            max_body_size: a.max_body_size,
            access_log_skip_paths: a.access_log_skip_paths.clone(),
            streaming_paths: a.streaming_paths.clone(),
            oauth_resources: a.oauth_resources.clone(),
            ..Default::default()
        },
        env: a.env_flags.env.iter().cloned().collect(),
        secrets: a.env_flags.bindings().collect(),
        health: HealthGate::default(),
        volumes: vec![],
        shared_volumes: vec![],
        configs: Vec::new(),
        host_mounts: Vec::new(),
        group_add: Vec::new(),
        ingress_logs: false,
        reload_signal: None,
        strategy: Default::default(),
        oidc: None,
        metrics_port: None,
        metrics_path: None,
        // `internal_hosts` (#303) is set in `apps.toml` or through the admin API, like `oidc`.
        internal_hosts: Vec::new(),
        shared_networks: vec![],
        shared_services: vec![],
        host_ports: Vec::new(),
        depends_on: Vec::new(),
        resources: Default::default(),
        security: Default::default(),
        auto_update: !a.no_auto_update,
        start: !a.no_start,
    };
    a.spec_flags.apply(&mut spec);
    Ok(spec)
}

async fn apps_add(json: bool, o: &Overrides, a: AddArgs) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let req = AddAppRequest {
        name,
        spec: build_spec(&a)?,
    };
    if a.dry_run {
        let body = serde_json::to_value(&req).map_err(|e| CliError::internal(e.to_string()))?;
        DryRun::new(&ApiRequest::new(endpoints::APPS_ADD, &[]), Some(body)).print(json);
        return Ok(exit::OK);
    }
    let resp: ShowAppResponse = client(o)?
        .call(endpoints::APPS_ADD, &[], Some(&req))
        .await?;
    emit(json, &resp, || render_show(&resp));
    Ok(exit::OK)
}

#[derive(Debug, Serialize)]
struct Removed {
    removed: String,
    existed: bool,
}

/// `DELETE /v1/apps/{name}`: the purge flags are independent query parameters, only sent when set.
pub(crate) fn remove_request(name: &str, a: &RemoveArgs) -> ApiRequest {
    ApiRequest::new(endpoints::APPS_REMOVE, &[("name", name)])
        .flag("purge_volumes", a.purge_volumes)
        .flag("purge_secrets", a.purge_secrets)
}

/// What `apps remove` reports it also deleted (nothing without the purge flags).
pub(crate) fn remove_suffix(a: &RemoveArgs) -> &'static str {
    match (a.purge_volumes, a.purge_secrets) {
        (true, true) => " (with its data and secrets)",
        (true, false) => " (with its data)",
        (false, true) => " (with its secrets)",
        (false, false) => "",
    }
}

pub(crate) async fn apps_remove(json: bool, o: &Overrides, a: RemoveArgs) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let params = [("name", name.as_str())];
    let req = remove_request(name.as_str(), &a);
    let client = client(o)?;
    if a.dry_run {
        match client
            .call::<ShowAppResponse>(endpoints::APPS_SHOW, &params, None::<&()>)
            .await
        {
            Ok(_) => {}
            Err(e) if e.kind == Kind::NotFound && a.ignore_missing => {}
            Err(e) => return Err(e),
        }
        DryRun::new(&req, None).print(json);
        return Ok(exit::OK);
    }
    let existed = match client.request_empty(&req, None::<&()>).await {
        Ok(()) => true,
        Err(e) if e.kind == Kind::NotFound && a.ignore_missing => false,
        Err(e) => return Err(e),
    };
    let out = Removed {
        removed: name.to_string(),
        existed,
    };
    emit(json, &out, || {
        if existed {
            format!("removed {}{}\n", out.removed, remove_suffix(&a))
        } else {
            format!("{} did not exist (nothing to do)\n", out.removed)
        }
    });
    Ok(exit::OK)
}

async fn apps_list(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: ListAppsResponse = client(o)?
        .call(endpoints::APPS_LIST, &[], None::<&()>)
        .await?;
    emit(json, &resp, || render_apps_list(&resp));
    Ok(exit::OK)
}

async fn apps_show(json: bool, o: &Overrides, name: &str) -> Result<i32, CliError> {
    let name = instance(name)?;
    let resp: ShowAppResponse = client(o)?
        .call(
            endpoints::APPS_SHOW,
            &[("name", name.as_str())],
            None::<&()>,
        )
        .await?;
    emit(json, &resp, || render_show(&resp));
    Ok(exit::OK)
}

/// `apps reload`: sends the spec's `reload_signal`, restarts the same container when the spec sets
/// none, or — with `--recreate` — recreates it from the pinned digest (needed after an editor saved a
/// single-file config mount with write-and-rename, which leaves the bind mount on the old inode).
pub(crate) async fn apps_reload(json: bool, o: &Overrides, a: ReloadArgs) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let req = ReloadRequest {
        recreate: a.recreate,
    };
    let resp: ReloadResponse = client(o)?
        .call(
            endpoints::APPS_RELOAD,
            &[("name", name.as_str())],
            Some(&req),
        )
        .await
        .map_err(|e| reload_conflict(e, &name))?;
    emit(json, &resp, || render_reload(&resp));
    Ok(exit::OK)
}

/// A 409 from `apps reload` means there is no running container to signal or restart (a busy daemon
/// is retried by the client), so point at the command that brings the app up.
fn reload_conflict(err: CliError, name: &InstanceName) -> CliError {
    if err.kind == Kind::Conflict {
        err.with_hint(format!(
            "`{name}` is not running — start it with `weglarka apps start {name}`"
        ))
    } else {
        err
    }
}

/// `apps rollback`: returns a static site to its previous release (issue #103). The daemon refuses
/// container apps and site environments; the error carries the command that applies to them.
pub(crate) async fn apps_rollback(
    json: bool,
    o: &Overrides,
    a: RollbackArgs,
) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let resp: RollbackResponse = client(o)?
        .call(
            endpoints::APPS_ROLLBACK,
            &[("name", name.as_str())],
            None::<&()>,
        )
        .await?;
    emit(json, &resp, || render_rollback(&name, &resp));
    Ok(exit::OK)
}

// ---------- deploy / status ----------

pub(crate) async fn deploy(json: bool, o: &Overrides, a: DeployArgs) -> Result<i32, CliError> {
    let name = instance(&a.app)?;
    let params = [("name", name.as_str())];
    let req = DeployRequest {
        image_ref: a.image.clone(),
    };
    let client = client(o)?;
    if a.dry_run {
        client
            .call::<ShowAppResponse>(endpoints::APPS_SHOW, &params, None::<&()>)
            .await?;
        let body = serde_json::to_value(&req).map_err(|e| CliError::internal(e.to_string()))?;
        DryRun::new(
            &ApiRequest::new(endpoints::APPS_DEPLOY, &params),
            Some(body),
        )
        .print(json);
        return Ok(exit::OK);
    }
    let resp: DeployResponse = client
        .call(endpoints::APPS_DEPLOY, &params, Some(&req))
        .await?;
    Ok(report_deploy(json, &name, &resp))
}

/// Prints what a deploy did and returns the exit code (`ROLLED_BACK` when it was rolled back); shared
/// by `deploy` and `push`.
pub(crate) fn report_deploy(json: bool, name: &InstanceName, resp: &DeployResponse) -> i32 {
    emit(json, resp, || {
        let digest = resp.digest.as_ref().map(|d| d.as_str()).unwrap_or("-");
        match resp.outcome {
            DeployOutcome::Provisioned => format!(
                "{name}: provisioned (start = false): no container started (generation {}, digest \
                 {digest}); bring it up with `weglarka apps start {name}`\n",
                resp.generation
            ),
            // An outcome from a newer daemon: named as such instead of a bare `Unknown`, and never
            // mixed up with a failure — the exit code below stays `OK`, because only a rollback is
            // reported as one.
            DeployOutcome::Unknown => format!(
                "{name}: the daemon reported a deploy outcome this CLI does not know (the daemon is \
                 newer; upgrade the CLI) (generation {}, digest {digest})\n",
                resp.generation
            ),
            outcome => format!(
                "{name}: {outcome:?} (generation {}, digest {digest})\n",
                resp.generation
            ),
        }
    });
    if resp.outcome == DeployOutcome::RolledBack {
        exit::ROLLED_BACK
    } else {
        exit::OK
    }
}

pub(crate) async fn status(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: StatusResponse = client(o)?.call(endpoints::STATUS, &[], None::<&()>).await?;
    emit(json, &resp, || {
        let logs = resp
            .log_retention
            .map(|retention| format!(", ingress logs kept: {retention}"))
            .unwrap_or_default();
        format!(
            "daemon {} (api {}), podman {}{logs}\n\n{}",
            resp.daemon_version,
            resp.api_version,
            resp.podman_version,
            render_apps(&resp.apps)
        )
    });
    Ok(exit::OK)
}

// ---------- notifications ----------

pub(crate) async fn notify_status(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: NotifyStatusResponse = client(o)?
        .call(endpoints::NOTIFICATIONS_STATUS, &[], None::<&()>)
        .await?;
    emit(json, &resp, || render_notify_status(&resp));
    Ok(exit::OK)
}

pub(crate) async fn notify_test(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: NotifyTestResponse = client(o)?
        .call(endpoints::NOTIFICATIONS_TEST, &[], None::<&()>)
        .await?;
    emit(json, &resp, || {
        if resp.delivered {
            "test notification delivered\n".to_owned()
        } else {
            format!(
                "test notification failed: {}\n",
                resp.error
                    .as_deref()
                    .unwrap_or("no answer from the channel")
            )
        }
    });
    Ok(if resp.delivered {
        exit::OK
    } else {
        exit::NOTIFY_FAILED
    })
}

pub(crate) fn render_notify_status(resp: &NotifyStatusResponse) -> String {
    if !resp.enabled {
        return "notifications: off (no [notify.ntfy] section in weglarka.toml)\n".to_owned();
    }
    let mut out = String::new();
    for channel in &resp.channels {
        let queued = match channel.pending {
            0 => String::new(),
            1 => " (1 notification queued)".to_owned(),
            n => format!(" ({n} notifications queued)"),
        };
        out.push_str(&format!(
            "{}: min severity {}{queued}\n",
            channel.name, channel.min_severity
        ));
    }
    out.push_str(&format!(
        "outbox: {} pending, {} dropped\n",
        resp.pending, resp.dropped
    ));
    if let Some(last) = &resp.last_delivered_at {
        out.push_str(&format!("last delivered: {last}\n"));
    }
    if let Some(error) = &resp.last_error {
        out.push_str(&format!("last error: {error}\n"));
    }
    out
}

// ---------- secrets ----------

/// Reads the secret value. A command-line argument is deliberately impossible (ps, shell history).
pub fn read_secret_value(
    from_file: Option<&Path>,
    stdin: &mut dyn Read,
    stdin_is_terminal: bool,
    raw: bool,
) -> Result<String, CliError> {
    let mut bytes = Vec::new();
    match from_file {
        Some(path) => {
            bytes = std::fs::read(path)
                .map_err(|e| CliError::usage(format!("cannot read {}: {e}", path.display())))?;
        }
        None => {
            if stdin_is_terminal {
                return Err(CliError::usage("refusing to read a secret from a terminal")
                    .with_hint(
                        "supply the value through a pipe (`pbpaste | weglarka secrets set …`) or with --from-file",
                    ));
            }
            stdin
                .read_to_end(&mut bytes)
                .map_err(|e| CliError::usage(format!("cannot read stdin: {e}")))?;
        }
    }
    let mut value = String::from_utf8(bytes).map_err(|_| {
        CliError::usage("secret value is not valid UTF-8")
            .with_hint("the API accepts text values (UTF-8)")
    })?;
    if !raw && value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        return Err(CliError::usage("secret value is empty")
            .with_hint("an empty value is not allowed; check the source"));
    }
    Ok(value)
}

async fn secrets_set(json: bool, o: &Overrides, a: SecretSetArgs) -> Result<i32, CliError> {
    let Some(name) = a.name.as_deref() else {
        return crate::secrets_env::set_from_env_file(json, o, a).await;
    };
    let app = instance(&a.app)?;
    let name = secret_name(name)?;
    let value = read_secret_value(
        a.from_file.as_deref(),
        &mut std::io::stdin(),
        std::io::stdin().is_terminal(),
        a.raw,
    )?;
    let params = [("name", app.as_str()), ("secret", name)];
    if a.dry_run {
        DryRun::new(
            &ApiRequest::new(endpoints::SECRETS_SET, &params),
            Some(serde_json::json!({ "value": "<redacted>" })),
        )
        .print(json);
        return Ok(exit::OK);
    }
    let info: SecretInfo = client(o)?
        .call(
            endpoints::SECRETS_SET,
            &params,
            Some(&SetSecretRequest { value }),
        )
        .await?;
    emit(json, &info, || {
        format!(
            "set {}.{} (fingerprint {}, updated {})\n",
            app, info.name, info.fingerprint, info.updated_at
        )
    });
    Ok(exit::OK)
}

async fn secrets_list(json: bool, o: &Overrides, app: &str) -> Result<i32, CliError> {
    let app = instance(app)?;
    let resp: ListSecretsResponse = client(o)?
        .call(
            endpoints::SECRETS_LIST,
            &[("name", app.as_str())],
            None::<&()>,
        )
        .await?;
    emit(json, &resp, || {
        let rows = resp
            .secrets
            .iter()
            .map(|s| vec![s.name.clone(), s.fingerprint.clone(), s.updated_at.clone()])
            .collect::<Vec<_>>();
        table(&["NAME", "FINGERPRINT", "UPDATED"], &rows)
    });
    Ok(exit::OK)
}

/// `secrets remove` output: which secret was removed (`<app>.<name>`).
#[derive(Debug, Serialize)]
struct SecretRemoved {
    removed: String,
}

/// `DELETE /v1/apps/{name}/secrets/{secret}`; `--force` is a query parameter.
pub(crate) fn secret_remove_request(app: &str, name: &str, force: bool) -> ApiRequest {
    ApiRequest::new(
        endpoints::SECRETS_REMOVE,
        &[("name", app), ("secret", name)],
    )
    .flag("force", force)
}

/// Hints for the two expected refusals; the daemon message names the binding / the stored secret.
fn secret_remove_error(e: CliError, app: &str, name: &str) -> CliError {
    match e.kind {
        Kind::Conflict => e.with_hint(format!(
            "the app's spec still binds it: `weglarka apps update {app} --unbind-secret {name}`, or \
             --force (the app then waits for the secret; a running container keeps the old value)"
        )),
        Kind::NotFound => e.with_hint(format!(
            "check the stored secrets: `weglarka secrets list {app}`"
        )),
        _ => e,
    }
}

pub(crate) async fn secrets_remove(
    json: bool,
    o: &Overrides,
    a: SecretRemoveArgs,
) -> Result<i32, CliError> {
    let app = instance(&a.app)?;
    let name = secret_name(&a.name)?;
    let req = secret_remove_request(app.as_str(), name, a.force);
    if a.dry_run {
        DryRun::new(&req, None).print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .request_empty(&req, None::<&()>)
        .await
        .map_err(|e| secret_remove_error(e, app.as_str(), name))?;
    let out = SecretRemoved {
        removed: format!("{app}.{name}"),
    };
    emit(json, &out, || {
        let mut s = format!("removed secret {}\n", out.removed);
        if a.force {
            s.push_str(
                "the app's spec still binds it: the app now waits for the secret (a running \
                 container keeps the old value)\n",
            );
        }
        s
    });
    Ok(exit::OK)
}

// ---------- host secrets (ADR 0080) ----------

pub(crate) async fn host_secrets_set(
    json: bool,
    o: &Overrides,
    a: HostSecretSetArgs,
) -> Result<i32, CliError> {
    let name = secret_name(&a.name)?;
    let value = read_secret_value(
        a.from_file.as_deref(),
        &mut std::io::stdin(),
        std::io::stdin().is_terminal(),
        a.raw,
    )?;
    let params = [("name", name)];
    if a.dry_run {
        DryRun::new(
            &ApiRequest::new(endpoints::HOST_SECRETS_SET, &params),
            Some(serde_json::json!({ "value": "<redacted>" })),
        )
        .print(json);
        return Ok(exit::OK);
    }
    let info: HostSecretInfo = client(o)?
        .call(
            endpoints::HOST_SECRETS_SET,
            &params,
            Some(&SetSecretRequest { value }),
        )
        .await?;
    emit(json, &info, || {
        format!(
            "set host secret {} (fingerprint {}, updated {})\n",
            info.name, info.fingerprint, info.updated_at
        )
    });
    Ok(exit::OK)
}

pub(crate) async fn host_secrets_list(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: ListHostSecretsResponse = client(o)?
        .call(endpoints::HOST_SECRETS_LIST, &[], None::<&()>)
        .await?;
    emit(json, &resp, || {
        let rows = resp
            .secrets
            .iter()
            .map(|s| vec![s.name.clone(), s.fingerprint.clone(), s.updated_at.clone()])
            .collect::<Vec<_>>();
        table(&["NAME", "FINGERPRINT", "UPDATED"], &rows)
    });
    Ok(exit::OK)
}

/// `secrets host remove` output: which host secret was removed.
#[derive(Debug, Serialize)]
struct HostSecretRemoved {
    removed: String,
}

pub(crate) async fn host_secrets_remove(
    json: bool,
    o: &Overrides,
    a: HostSecretRemoveArgs,
) -> Result<i32, CliError> {
    let name = secret_name(&a.name)?;
    if a.dry_run {
        DryRun::new(
            &ApiRequest::new(endpoints::HOST_SECRETS_REMOVE, &[("name", name)]),
            None,
        )
        .print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty(endpoints::HOST_SECRETS_REMOVE, &[("name", name)])
        .await?;
    let out = HostSecretRemoved {
        removed: name.to_owned(),
    };
    emit(json, &out, || {
        format!("removed host secret {}\n", out.removed)
    });
    Ok(exit::OK)
}

// ---------- doctor ----------

async fn doctor(json: bool, o: &Overrides, a: DoctorArgs) -> Result<i32, CliError> {
    let report: DoctorReport = if a.preflight {
        preflight::run_local(o, a.secrets_file)
    } else {
        client(o)?.call(endpoints::DOCTOR, &[], None::<&()>).await?
    };
    emit(json, &report, || preflight::render(&report));
    Ok(report.exit_code())
}

/// `images prune`: the daemon plans and (unless `--dry-run`) removes. Images Podman refused are
/// reported and turn the exit code into [`exit::INTERNAL`] — the operator should look at them.
pub(crate) async fn images_prune(
    json: bool,
    o: &Overrides,
    a: PruneImagesArgs,
) -> Result<i32, CliError> {
    let request = PruneImagesRequest { dry_run: a.dry_run };
    let response: PruneImagesResponse = client(o)?
        .call(endpoints::IMAGES_PRUNE, &[], Some(&request))
        .await?;
    emit(json, &response, || render_prune(&response));
    // A blocked pass (cleanup disabled by a bookkeeping problem) did not do what was asked, so it
    // fails like a refused removal does.
    Ok(if response.failed.is_empty() && !response.blocked {
        exit::OK
    } else {
        exit::INTERNAL
    })
}

/// `images reservations list`: the durable reservations, with the operation IDs `abandon` needs.
pub(crate) async fn images_reservations_list(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let response: ListReservationsResponse = client(o)?
        .call(endpoints::IMAGES_RESERVATIONS_LIST, &[], None::<&()>)
        .await?;
    emit(json, &response, || {
        render_reservations(&response, unix_now())
    });
    Ok(exit::OK)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `images reservations list` output: one row per reservation, then a capacity line. `now` is a
/// parameter so the output is reproducible.
pub(crate) fn render_reservations(r: &ListReservationsResponse, now: u64) -> String {
    for diagnostic in &r.diagnostics {
        eprintln!("warning: {diagnostic}");
    }
    if r.reservations.is_empty() {
        return format!("no image reservations (0/{})\n", r.capacity);
    }
    let rows = r
        .reservations
        .iter()
        .map(|v| {
            vec![
                v.operation_id.clone(),
                v.phase.clone(),
                format!("{}:{}", v.component, v.pid),
                age(now.saturating_sub(v.started_at)),
                reclaim_note(v).to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    let mut out = table(&["OPERATION", "PHASE", "OWNER", "AGE", "RECLAIM"], &rows);
    out.push_str(&format!(
        "{}/{} reservation(s)\n",
        r.reservations.len(),
        r.capacity
    ));
    out
}

/// What happens to a reservation without the operator: only a previous boot's reservation is
/// reclaimed (at the next daemon start), and not while a nonterminal platform transaction references
/// it.
fn reclaim_note(v: &ReservationView) -> &'static str {
    match (v.referenced, v.previous_boot) {
        (Some(true), _) => "while platform transaction runs",
        (Some(false), true) => "at next daemon start",
        // A reservation of this boot is never reclaimed, whatever the journal says.
        (_, false) => "abandon (or host reboot)",
        (None, true) => "unknown (journal unreadable)",
    }
}

fn age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

/// `images reservations abandon <id>`: the explicit operator command from the contract. It refuses
/// without `--yes`; the daemon then removes exactly that reservation record.
pub(crate) async fn images_reservations_abandon(
    json: bool,
    o: &Overrides,
    a: AbandonReservationArgs,
) -> Result<i32, CliError> {
    if !a.yes {
        return Err(CliError::usage(
            "abandoning an image reservation is irreversible; pass --yes to confirm",
        )
        .with_hint(
            "only abandon an operation whose owner is gone and whose image is not a pending platform \
             transaction",
        ));
    }
    let request = AbandonReservationRequest {
        operation_id: a.operation_id,
    };
    let response: AbandonReservationResponse = client(o)?
        .call(endpoints::IMAGES_RESERVATION_ABANDON, &[], Some(&request))
        .await?;
    emit(json, &response, || {
        if response.abandoned {
            "abandoned the reservation\n".to_owned()
        } else {
            "no such reservation\n".to_owned()
        }
    });
    Ok(if response.abandoned {
        exit::OK
    } else {
        exit::USAGE
    })
}

// ---------- render ----------

/// `images prune` output: one row per image, then a summary; failures go to stderr.
pub(crate) fn render_prune(r: &PruneImagesResponse) -> String {
    let rows = r
        .removed
        .iter()
        .map(|i| {
            vec![
                short_image_id(&i.id),
                image_names(i),
                human_bytes(i.size_bytes),
            ]
        })
        .collect::<Vec<_>>();
    let mut out = if rows.is_empty() {
        String::new()
    } else {
        table(&["ID", "IMAGE", "SIZE"], &rows)
    };
    let what = if r.dry_run { "would remove" } else { "removed" };
    let space = if r.dry_run {
        format!("{} at most", human_bytes(r.reclaimed_bytes))
    } else {
        format!("{} reclaimed", human_bytes(r.reclaimed_bytes))
    };
    if r.blocked {
        // Stdout, not just a warning: `--json` callers get the flag, people get this line.
        out.push_str(&format!(
            "image cleanup is BLOCKED: {}\n",
            if r.removed.is_empty() {
                "nothing was removed".to_owned()
            } else {
                format!(
                    "{} image(s) were removed before the failure (see below)",
                    r.removed.len()
                )
            }
        ));
    }
    out.push_str(&format!("{what} {} image(s), {space}\n", r.removed.len()));
    for failure in &r.failed {
        eprintln!("warning: could not remove {failure}");
    }
    for diagnostic in &r.diagnostics {
        eprintln!("warning: {diagnostic}");
    }
    out
}

/// The first 12 hex characters — enough to tell images apart, short enough for a table.
fn short_image_id(id: &str) -> String {
    id.get(..12).unwrap_or(id).to_owned()
}

/// Tags if the image has any, otherwise its repository digests (an untagged leftover keeps those).
fn image_names(image: &PrunedImage) -> String {
    let names: Vec<String> = if image.tags.is_empty() {
        image.digests.iter().map(|d| short_digest_name(d)).collect()
    } else {
        image.tags.clone()
    };
    if names.is_empty() {
        "-".to_owned()
    } else {
        names.join(",")
    }
}

/// `repo@sha256:<64 hex>` → `repo@sha256:<12 hex>…`.
fn short_digest_name(name: &str) -> String {
    match name.split_once('@') {
        Some((repo, digest)) => match digest.strip_prefix("sha256:") {
            Some(hex) if hex.len() > 12 => {
                format!("{repo}@sha256:{}…", hex.get(..12).unwrap_or(hex))
            }
            _ => name.to_owned(),
        },
        None => name.to_owned(),
    }
}

fn render_apps(apps: &[AppSummary]) -> String {
    let rows = apps
        .iter()
        .map(|a| {
            vec![
                a.name.to_string(),
                crate::update::runtime_label(a.runtime),
                a.image.clone(),
                a.domains.join(","),
                a.site.clone().unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect::<Vec<_>>();
    table(&["NAME", "RUNTIME", "IMAGE", "DOMAINS", "SITE"], &rows)
}

/// `apps list`: the app table, then the declared shared services (ADR 0079) when there are any, so
/// an operator sees who a service serves without opening `apps.toml`.
pub(crate) fn render_apps_list(r: &ListAppsResponse) -> String {
    let mut out = render_apps(&r.apps);
    if r.shared_services.is_empty() {
        return out;
    }
    out.push('\n');
    out.push_str("Shared services:\n");
    out.push_str(&render_shared_services(&r.shared_services));
    out
}

/// The services section of `apps list`, in the table style of `networks list`. The kind carries its
/// Redis profile (`redis/cache`); a service without members shows `-`, like an empty group does.
fn render_shared_services(services: &[SharedServiceSummary]) -> String {
    let rows: Vec<Vec<String>> = services
        .iter()
        .map(|s| {
            let kind = match (s.kind, s.profile) {
                (ServiceKind::Redis, Some(profile)) => {
                    format!("redis/{profile}", profile = redis_profile_label(profile))
                }
                (kind, _) => service_kind_label(kind).to_owned(),
            };
            let members = if s.members.is_empty() {
                "-".to_owned()
            } else {
                s.members
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            vec![s.name.to_string(), kind, s.instance.to_string(), members]
        })
        .collect();
    table(&["SERVICE", "KIND", "INSTANCE", "MEMBERS"], &rows)
}

fn service_kind_label(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Redis => "redis",
        ServiceKind::Postgres => "postgres",
    }
}

fn redis_profile_label(profile: RedisProfile) -> &'static str {
    match profile {
        RedisProfile::Durable => "durable",
        RedisProfile::Cache => "cache",
    }
}

pub(crate) fn render_show(r: &ShowAppResponse) -> String {
    let spec = toml::to_string(&r.spec).unwrap_or_default();
    let waiting = crate::update::render_waiting(r.name.as_str(), &r.state);
    let mut out = format!(
        "name:       {}\nruntime:    {}\ngeneration: {}\ndigest:     {}\nprevious:   {}\n{waiting}\n[spec]\n{spec}",
        r.name,
        crate::update::runtime_label(r.runtime),
        r.state.generation,
        r.state.current.as_ref().map_or("-", |d| d.as_str()),
        r.state.previous.as_ref().map_or("-", |d| d.as_str()),
    );
    if let Some(configs) = &r.configs
        && !configs.is_empty()
    {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&render_configs(configs));
    }
    if let Some(mounts) = &r.host_mounts
        && !mounts.is_empty()
    {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&render_host_mounts(mounts));
    }
    out
}

/// `[host_mounts]` block of `apps show` (issue #178): privileged-ish like `host_ports < 1024`, so the
/// operator sees which host paths the app reads and whether each is still allowlisted.
fn render_host_mounts(mounts: &[weglarka_api::HostMountView]) -> String {
    use weglarka_api::HostMountStatus as S;
    let mut out =
        String::from("[host_mounts] (read-only host paths, allowlisted by the operator)\n");
    for m in mounts {
        let status = match m.status {
            S::Ok => "ok",
            S::NotAllowed => "not allowlisted",
            S::Missing => "missing",
            S::Redirected => "redirected (symlink)",
            S::NotFileOrDir => "not a file or directory",
            S::Unreadable => "unreadable",
            // A status from a newer daemon: shown, but never as ok.
            S::Unknown => "unknown",
        };
        out.push_str(&format!("  {} -> {}  [{status}]\n", m.source, m.target));
        if let Some(detail) = &m.detail {
            out.push_str(&format!("    {detail}\n"));
        }
    }
    out
}

/// `apps reload` output: what happened, then what the app now sees — the same `[configs]` block as
/// `apps show`, so the operator can confirm the new fingerprint without a second call.
pub(crate) fn render_reload(r: &ReloadResponse) -> String {
    let mut out = match r.action {
        ReloadAction::Signalled => format!(
            "{}: signalled SIG{}\n",
            r.name,
            r.signal.as_deref().unwrap_or_default()
        ),
        ReloadAction::Restarted => format!("{}: restarted\n", r.name),
        ReloadAction::Recreated => format!("{}: recreated (same digest)\n", r.name),
        // A newer daemon did something this CLI has no word for; say so instead of claiming a result.
        ReloadAction::Unknown => format!(
            "{}: reloaded, but the daemon reported an action this CLI does not know \
             (the daemon is newer; upgrade the CLI)\n",
            r.name
        ),
    };
    if let Some(configs) = &r.configs
        && !configs.is_empty()
    {
        out.push_str(&render_configs(configs));
    }
    out
}

/// `apps rollback` output (issue #103): both digests and whether the release was already on disk.
pub(crate) fn render_rollback(name: &InstanceName, r: &RollbackResponse) -> String {
    let note = if r.reused_release {
        "release on disk, no image needed"
    } else {
        "release rebuilt from the image"
    };
    format!(
        "{name}: rolled back {} → {} ({note})\n",
        short_sha256(&r.from),
        short_sha256(&r.to)
    )
}

/// `sha256:<64 hex>` → `sha256:<12 hex>…`.
fn short_sha256(digest: &Digest) -> String {
    match digest.as_str().strip_prefix("sha256:") {
        Some(hex) if hex.len() > 12 => format!("sha256:{}…", hex.get(..12).unwrap_or(hex)),
        _ => digest.to_string(),
    }
}

/// `[configs]` section shared by `apps show` and `apps reload`: one line per declared mount with the
/// status and, for a source inside `config_root`, a short content fingerprint.
fn render_configs(configs: &[ConfigMountView]) -> String {
    let mut out = String::from("[configs]\n");
    for c in configs {
        out.push_str(&format!(
            "{} -> {}  {}",
            c.source,
            c.target,
            config_status_label(c.status)
        ));
        if let Some(fingerprint) = &c.fingerprint {
            out.push(' ');
            out.push_str(&short_fingerprint(fingerprint));
        }
        if let Some(detail) = &c.detail {
            out.push_str(&format!(" ({detail})"));
        }
        out.push('\n');
    }
    out
}

/// A short lowercase word for a mount status.
fn config_status_label(status: ConfigMountStatus) -> &'static str {
    match status {
        ConfigMountStatus::Ok => "ok",
        ConfigMountStatus::Missing => "missing",
        ConfigMountStatus::NoRoot => "no-config-root",
        ConfigMountStatus::OutsideRoot => "outside-root",
        ConfigMountStatus::NotFileOrDir => "not-file-or-dir",
        ConfigMountStatus::Unreadable => "unreadable",
        // A status from a newer daemon: never rendered as ok.
        ConfigMountStatus::Unknown => "unknown",
    }
}

/// The first 8 hex characters of the sha256 fingerprint — enough to compare before and after a reload.
fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.get(..8).unwrap_or(fingerprint).to_owned()
}
