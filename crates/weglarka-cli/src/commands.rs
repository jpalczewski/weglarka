//! Command execution. Each returns an exit code (0 or a special one, e.g. `doctor`/rollback);
//! errors are returned as [`CliError`].

use std::io::{IsTerminal, Read};
use std::path::Path;

use serde::Serialize;
use weglarka_api::endpoints;
use weglarka_api::{
    AddAppRequest, AppSummary, ConfigMountStatus, ConfigMountView, DeployOutcome, DeployRequest,
    DeployResponse, DoctorReport, ListAppsResponse, ListSecretsResponse, NotifyStatusResponse,
    NotifyTestResponse, PruneImagesRequest, PruneImagesResponse, PrunedImage, ReloadAction,
    ReloadRequest, ReloadResponse, SecretInfo, SetSecretRequest, ShowAppResponse, StatusResponse,
};
use weglarka_core::app::{
    AppIngress, AppSpec, HealthGate, InstanceName, SecretBinding, SecretTarget,
};
use weglarka_core::images::human_bytes;

use crate::cli::{
    AddArgs, AppsCommand, Cli, Command, DeployArgs, DoctorArgs, ImagesCommand, NotifyCommand,
    PruneImagesArgs, ReloadArgs, RemoveArgs, SecretSetArgs, SecretsCommand,
};
use crate::client::{ApiClient, append_query, request_path};
use crate::error::{CliError, Kind, exit};
use crate::output::{emit, table};
use crate::preflight;
use crate::settings::Overrides;

pub async fn run(cli: Cli) -> Result<i32, CliError> {
    let json = cli.json;
    let overrides = Overrides {
        config: cli.config,
        socket: cli.socket,
    };
    match cli.command {
        Command::Apps(AppsCommand::Add(a)) => apps_add(json, &overrides, a).await,
        Command::Apps(AppsCommand::Update(a)) => {
            crate::update::apps_update(json, &overrides, a).await
        }
        Command::Apps(AppsCommand::Start(a)) => {
            crate::update::apps_start(json, &overrides, a).await
        }
        Command::Apps(AppsCommand::Stop(a)) => crate::update::apps_stop(json, &overrides, a).await,
        Command::Apps(AppsCommand::Reload(a)) => apps_reload(json, &overrides, a).await,
        Command::Apps(AppsCommand::Remove(a)) => apps_remove(json, &overrides, a).await,
        Command::Apps(AppsCommand::List) => apps_list(json, &overrides).await,
        Command::Apps(AppsCommand::Show { name }) => apps_show(json, &overrides, &name).await,
        Command::Deploy(a) => deploy(json, &overrides, a).await,
        Command::Status => status(json, &overrides).await,
        Command::Secrets(SecretsCommand::Set(a)) => secrets_set(json, &overrides, a).await,
        Command::Secrets(SecretsCommand::List { app }) => {
            secrets_list(json, &overrides, &app).await
        }
        Command::Doctor(a) => doctor(json, &overrides, a).await,
        Command::Volumes(c) => crate::volumes::run(json, &overrides, c).await,
        Command::Images(ImagesCommand::Prune(a)) => images_prune(json, &overrides, a).await,
        Command::Notify(NotifyCommand::Status) => notify_status(json, &overrides).await,
        Command::Notify(NotifyCommand::Test) => notify_test(json, &overrides).await,
    }
}

pub(crate) fn client(overrides: &Overrides) -> Result<ApiClient, CliError> {
    Ok(ApiClient::new(overrides.admin_socket()?))
}

pub(crate) fn instance(name: &str) -> Result<InstanceName, CliError> {
    InstanceName::new(name).map_err(|e| {
        CliError::usage(e.to_string())
            .with_hint("instance names: lowercase letters, digits and hyphens, e.g. `ntfy-zig`")
    })
}

/// The secret name ends up in a URL path, so we restrict the alphabet (no percent-encoding).
fn secret_name(name: &str) -> Result<&str, CliError> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(name)
    } else {
        Err(CliError::usage(format!("invalid secret name {name:?}"))
            .with_hint("allowed: [A-Za-z0-9_-], 1–64 characters"))
    }
}

/// Result of `--dry-run`: the request that would be sent (secret values masked).
#[derive(Debug, Serialize)]
pub(crate) struct DryRun {
    dry_run: bool,
    method: &'static str,
    pub(crate) path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
}

impl DryRun {
    pub(crate) fn new(
        ep: weglarka_api::Endpoint,
        params: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> Self {
        Self {
            dry_run: true,
            method: match ep.method {
                weglarka_api::Method::Get => "GET",
                weglarka_api::Method::Post => "POST",
                weglarka_api::Method::Put => "PUT",
                weglarka_api::Method::Delete => "DELETE",
            },
            path: request_path(ep, params, ""),
            body,
        }
    }

    /// Adds the query string the request would send; it becomes part of the printed `path`, so
    /// `--dry-run --json` shows exactly what would be sent. An empty query keeps the path as is.
    pub(crate) fn with_query(mut self, query: &str) -> Self {
        self.path = append_query(self.path, query);
        self
    }

    pub(crate) fn print(&self, json: bool) {
        emit(json, self, || {
            let mut s = format!("dry-run: {} {}\n", self.method, self.path);
            if let Some(b) = &self.body {
                s.push_str(&format!(
                    "body: {}\n",
                    serde_json::to_string_pretty(b).unwrap_or_default()
                ));
            }
            s.push_str("nothing was sent\n");
            s
        });
    }
}

// ---------- apps ----------

/// Builds an `AppSpec` from the flags of `apps add` (`--spec` wins when given).
pub(crate) fn build_spec(a: &AddArgs) -> Result<AppSpec, CliError> {
    if let Some(path) = &a.spec {
        let src = if path == Path::new("-") {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| CliError::usage(format!("cannot read spec from stdin: {e}")))?;
            s
        } else {
            std::fs::read_to_string(path)
                .map_err(|e| CliError::usage(format!("cannot read spec {}: {e}", path.display())))?
        };
        return toml::from_str(&src).map_err(|e| {
            CliError::usage(format!("invalid spec: {e}")).with_hint(
                "format: AppSpec fields from apps.toml (image, domains, port, env, secrets…)",
            )
        });
    }
    let image = a
        .image
        .clone()
        .ok_or_else(|| CliError::usage("image is required unless --spec is given"))?;
    let mut secrets = Vec::new();
    for (secret, var) in &a.secret_env {
        secrets.push(SecretBinding {
            secret: secret.clone(),
            target: SecretTarget::Env { var: var.clone() },
        });
    }
    for (secret, path) in &a.secret_mount {
        secrets.push(SecretBinding {
            secret: secret.clone(),
            target: SecretTarget::Mount {
                path: path.clone(),
                mode: None,
            },
        });
    }
    let mut spec = AppSpec {
        image,
        command: Vec::new(),
        domains: a.domains.clone(),
        port: a.port,
        ingress: AppIngress {
            streaming: a.streaming,
            ..Default::default()
        },
        env: a.env.iter().cloned().collect(),
        secrets,
        health: HealthGate::default(),
        volumes: vec![],
        shared_volumes: vec![],
        configs: Vec::new(),
        reload_signal: None,
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
        DryRun::new(endpoints::APPS_ADD, &[], Some(body)).print(json);
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

/// Query of the `apps remove` request: `--purge-volumes` is the only flag that travels as a query
/// parameter, so the dry run and the real call take it from the same place.
fn remove_query(purge_volumes: bool) -> &'static str {
    if purge_volumes {
        "purge_volumes=true"
    } else {
        ""
    }
}

/// The request `apps remove --dry-run` shows; its endpoint, params and query match the real call.
pub(crate) fn remove_dry_run(name: &str, purge_volumes: bool) -> DryRun {
    let params = [("name", name)];
    DryRun::new(endpoints::APPS_REMOVE, &params, None).with_query(remove_query(purge_volumes))
}

pub(crate) async fn apps_remove(json: bool, o: &Overrides, a: RemoveArgs) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let params = [("name", name.as_str())];
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
        remove_dry_run(name.as_str(), a.purge_volumes).print(json);
        return Ok(exit::OK);
    }
    let removal = client
        .call_empty_query(
            endpoints::APPS_REMOVE,
            &params,
            remove_query(a.purge_volumes),
        )
        .await;
    let existed = match removal {
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
            format!("removed {}\n", out.removed)
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
    emit(json, &resp, || render_apps(&resp.apps));
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

// ---------- deploy / status ----------

async fn deploy(json: bool, o: &Overrides, a: DeployArgs) -> Result<i32, CliError> {
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
        DryRun::new(endpoints::APPS_DEPLOY, &params, Some(body)).print(json);
        return Ok(exit::OK);
    }
    let resp: DeployResponse = client
        .call(endpoints::APPS_DEPLOY, &params, Some(&req))
        .await?;
    emit(json, &resp, || {
        let digest = resp.digest.as_ref().map(|d| d.as_str()).unwrap_or("-");
        if resp.outcome == DeployOutcome::Provisioned {
            format!(
                "{name}: provisioned (start = false): no container started (generation {}, digest \
                 {digest}); bring it up with `weglarka apps start {name}`\n",
                resp.generation
            )
        } else {
            format!(
                "{}: {:?} (generation {}, digest {digest})\n",
                name, resp.outcome, resp.generation
            )
        }
    });
    Ok(if resp.outcome == DeployOutcome::RolledBack {
        exit::ROLLED_BACK
    } else {
        exit::OK
    })
}

async fn status(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: StatusResponse = client(o)?.call(endpoints::STATUS, &[], None::<&()>).await?;
    emit(json, &resp, || {
        format!(
            "daemon {} (api {}), podman {}\n\n{}",
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
    let app = instance(&a.app)?;
    let name = secret_name(&a.name)?;
    let value = read_secret_value(
        a.from_file.as_deref(),
        &mut std::io::stdin(),
        std::io::stdin().is_terminal(),
        a.raw,
    )?;
    let params = [("name", app.as_str()), ("secret", name)];
    if a.dry_run {
        DryRun::new(
            endpoints::SECRETS_SET,
            &params,
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
    Ok(if response.failed.is_empty() {
        exit::OK
    } else {
        exit::INTERNAL
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
    out.push_str(&format!("{what} {} image(s), {space}\n", r.removed.len()));
    for failure in &r.failed {
        eprintln!("warning: could not remove {failure}");
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
            ]
        })
        .collect::<Vec<_>>();
    table(&["NAME", "RUNTIME", "IMAGE", "DOMAINS"], &rows)
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
    };
    if let Some(configs) = &r.configs
        && !configs.is_empty()
    {
        out.push_str(&render_configs(configs));
    }
    out
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
    }
}

/// The first 8 hex characters of the sha256 fingerprint — enough to compare before and after a reload.
fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.get(..8).unwrap_or(fingerprint).to_owned()
}
