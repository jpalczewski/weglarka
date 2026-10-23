//! Command execution. Each returns an exit code (0 or a special one, e.g. `doctor`/rollback);
//! errors are returned as [`CliError`].

use std::io::{IsTerminal, Read};
use std::path::Path;

use serde::Serialize;
use weglarka_api::endpoints;
use weglarka_api::{
    AddAppRequest, AppSummary, DeployOutcome, DeployRequest, DeployResponse, DoctorReport,
    ListAppsResponse, ListSecretsResponse, SecretInfo, SetSecretRequest, ShowAppResponse,
    StatusResponse,
};
use weglarka_core::app::{AppSpec, HealthGate, InstanceName, SecretBinding, SecretTarget};

use crate::cli::{
    AddArgs, AppsCommand, Cli, Command, DeployArgs, DoctorArgs, RemoveArgs, SecretSetArgs,
    SecretsCommand,
};
use crate::client::{ApiClient, expand_path};
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
    }
}

fn client(overrides: &Overrides) -> Result<ApiClient, CliError> {
    Ok(ApiClient::new(overrides.admin_socket()?))
}

fn instance(name: &str) -> Result<InstanceName, CliError> {
    InstanceName::new(name).map_err(|e| {
        CliError::usage(e.to_string())
            .with_hint("nazwy instancji: małe litery, cyfry i myślniki, np. `ntfy-zig`")
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
            .with_hint("dozwolone: [A-Za-z0-9_-], 1–64 znaki"))
    }
}

/// Result of `--dry-run`: the request that would be sent (secret values masked).
#[derive(Debug, Serialize)]
struct DryRun {
    dry_run: bool,
    method: &'static str,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
}

impl DryRun {
    fn new(
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
            path: expand_path(ep, params),
            body,
        }
    }

    fn print(&self, json: bool) {
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

fn build_spec(a: &AddArgs) -> Result<AppSpec, CliError> {
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
            CliError::usage(format!("invalid spec: {e}"))
                .with_hint("format: pola AppSpec z apps.toml (image, domains, port, env, secrets…)")
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
    Ok(AppSpec {
        image,
        domains: a.domains.clone(),
        port: a.port,
        env: a.env.iter().cloned().collect(),
        secrets,
        health: HealthGate::default(),
        auto_update: !a.no_auto_update,
    })
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

async fn apps_remove(json: bool, o: &Overrides, a: RemoveArgs) -> Result<i32, CliError> {
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
        DryRun::new(endpoints::APPS_REMOVE, &params, None).print(json);
        return Ok(exit::OK);
    }
    let existed = match client.call_empty(endpoints::APPS_REMOVE, &params).await {
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
        format!(
            "{}: {:?} (generation {}, digest {digest})\n",
            name, resp.outcome, resp.generation
        )
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
                        "podaj wartość potokiem (`pbpaste | weglarka secrets set …`) lub przez --from-file",
                    ));
            }
            stdin
                .read_to_end(&mut bytes)
                .map_err(|e| CliError::usage(format!("cannot read stdin: {e}")))?;
        }
    }
    let mut value = String::from_utf8(bytes).map_err(|_| {
        CliError::usage("secret value is not valid UTF-8")
            .with_hint("API przyjmuje wartości tekstowe (UTF-8)")
    })?;
    if !raw && value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        return Err(CliError::usage("secret value is empty")
            .with_hint("pusta wartość nie jest dozwolona; sprawdź źródło"));
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

// ---------- render ----------

fn render_apps(apps: &[AppSummary]) -> String {
    let rows = apps
        .iter()
        .map(|a| {
            vec![
                a.name.to_string(),
                format!("{:?}", a.runtime).to_lowercase(),
                a.image.clone(),
                a.domains.join(","),
            ]
        })
        .collect::<Vec<_>>();
    table(&["NAME", "RUNTIME", "IMAGE", "DOMAINS"], &rows)
}

fn render_show(r: &ShowAppResponse) -> String {
    let spec = toml::to_string(&r.spec).unwrap_or_default();
    format!(
        "name:       {}\nruntime:    {}\ngeneration: {}\ndigest:     {}\nprevious:   {}\n\n[spec]\n{spec}",
        r.name,
        format!("{:?}", r.runtime).to_lowercase(),
        r.state.generation,
        r.state.current.as_ref().map_or("-", |d| d.as_str()),
        r.state.previous.as_ref().map_or("-", |d| d.as_str()),
    )
}
