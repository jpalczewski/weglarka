//! `weglarka oidc rotate|clients` (API: `OIDC_*`, issue #91). An app's own client comes from its
//! `oidc` section; `clients` manages the external ones (`[oidc_clients.<id>]`, apps Węglarka does
//! not run). Rendering the provider's files is the daemon's job.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::Serialize;
use weglarka_api::{ListOidcClientsResponse, OidcRotateResponse, PutOidcClientRequest, endpoints};
use weglarka_model::identity::{ClientId, ExternalClientSpec};

use crate::commands::{DryRun, client, instance};
use crate::error::{CliError, Kind, exit};
use crate::output::{emit, table};
use crate::settings::Overrides;

#[derive(Debug, Subcommand)]
pub enum OidcCommand {
    /// Replace an app's client secret: the provider learns the new digest, then the app is
    /// recreated. Logins fail between the two steps.
    Rotate(RotateArgs),
    /// Clients of apps Węglarka does not run.
    #[command(subcommand)]
    Clients(ClientsCommand),
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    pub app: String,
}

#[derive(Debug, Subcommand)]
pub enum ClientsCommand {
    /// List the external clients.
    List,
    /// Add or replace a client from a TOML file (the body of `[oidc_clients.<id>]`).
    Set(SetArgs),
    /// Remove a client; the provider drops it at the next apply.
    Remove(RemoveArgs),
}

#[derive(Debug, Args)]
pub struct SetArgs {
    /// Client id ([a-z0-9-], 1–63 characters; it must not equal an app name).
    pub id: String,
    /// TOML file with the client (`-` reads stdin).
    #[arg(long, value_name = "FILE")]
    pub spec: PathBuf,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub id: String,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(json: bool, o: &Overrides, cmd: OidcCommand) -> Result<i32, CliError> {
    match cmd {
        OidcCommand::Rotate(a) => rotate(json, o, a).await,
        OidcCommand::Clients(ClientsCommand::List) => list(json, o).await,
        OidcCommand::Clients(ClientsCommand::Set(a)) => set(json, o, a).await,
        OidcCommand::Clients(ClientsCommand::Remove(a)) => remove(json, o, a).await,
    }
}

fn client_id(raw: &str) -> Result<ClientId, CliError> {
    ClientId::new(raw).map_err(|e| CliError::usage(e).with_hint("client ids look like `forge`"))
}

async fn rotate(json: bool, o: &Overrides, a: RotateArgs) -> Result<i32, CliError> {
    let name = instance(&a.app)?;
    let resp: OidcRotateResponse = client(o)?
        .call(
            endpoints::OIDC_ROTATE,
            &[("name", name.as_str())],
            None::<&()>,
        )
        .await?;
    emit(json, &resp, || {
        if resp.recreated {
            format!("rotated the OIDC secret of {name} and recreated it\n")
        } else {
            format!("rotated the OIDC secret of {name}; it reads the new one at its next start\n")
        }
    });
    Ok(exit::OK)
}

async fn list(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: ListOidcClientsResponse = client(o)?
        .call(endpoints::OIDC_CLIENTS_LIST, &[], None::<&()>)
        .await?;
    emit(json, &resp, || {
        if resp.clients.is_empty() {
            return "no external OIDC clients (see `weglarka oidc clients set --help`)\n"
                .to_owned();
        }
        let rows: Vec<Vec<String>> = resp
            .clients
            .iter()
            .map(|(id, c)| vec![id.to_string(), c.name.clone(), c.redirect_uris.join(",")])
            .collect();
        table(&["ID", "NAME", "REDIRECT URIS"], &rows)
    });
    Ok(exit::OK)
}

async fn set(json: bool, o: &Overrides, a: SetArgs) -> Result<i32, CliError> {
    let id = client_id(&a.id)?;
    let src = if a.spec.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| CliError::usage(format!("cannot read the client from stdin: {e}")))?;
        s
    } else {
        std::fs::read_to_string(&a.spec)
            .map_err(|e| CliError::usage(format!("cannot read {}: {e}", a.spec.display())))?
    };
    let spec: ExternalClientSpec = toml::from_str(&src).map_err(|e| {
        CliError::usage(format!("invalid client: {e}")).with_hint(
            "format: the body of `[oidc_clients.<id>]` — name, redirect_uris and secret_digest \
             (a pbkdf2/argon2id digest, never the plain secret)",
        )
    })?;
    let req = PutOidcClientRequest { spec };
    let params = [("id", id.as_str())];
    if a.dry_run {
        let body = serde_json::to_value(&req).map_err(|e| CliError::internal(e.to_string()))?;
        DryRun::new(endpoints::OIDC_CLIENT_PUT, &params, Some(body)).print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty_json(endpoints::OIDC_CLIENT_PUT, &params, &req)
        .await?;
    #[derive(Serialize)]
    struct Set {
        set: String,
    }
    emit(
        json,
        &Set {
            set: id.to_string(),
        },
        || format!("set OIDC client {id}\n"),
    );
    Ok(exit::OK)
}

async fn remove(json: bool, o: &Overrides, a: RemoveArgs) -> Result<i32, CliError> {
    let id = client_id(&a.id)?;
    let params = [("id", id.as_str())];
    if a.dry_run {
        DryRun::new(endpoints::OIDC_CLIENT_REMOVE, &params, None).print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty(endpoints::OIDC_CLIENT_REMOVE, &params)
        .await
        .map_err(|e| match e.kind {
            Kind::NotFound => e.with_hint("external clients: `weglarka oidc clients list`"),
            _ => e,
        })?;
    #[derive(Serialize)]
    struct Removed {
        removed: String,
    }
    emit(
        json,
        &Removed {
            removed: id.to_string(),
        },
        || format!("removed OIDC client {id}\n"),
    );
    Ok(exit::OK)
}
