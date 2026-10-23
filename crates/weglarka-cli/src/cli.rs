//! Command definitions. The `///` docs below are user-visible `--help` text.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::error::exit;

#[derive(Debug, Parser)]
#[command(
    name = "weglarka",
    version,
    about = "Węglarka — deploy tool for rootless Podman (client of the daemon's admin API)",
    after_long_help = exit::TABLE
)]
pub struct Cli {
    /// Print the result as JSON (types from weglarka-api); errors as {"error":{...}}.
    #[arg(long, global = true)]
    pub json: bool,

    /// Host configuration file.
    #[arg(long, global = true, env = "WEGLARKA_CONFIG", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Unix socket of the admin API (defaults to `admin.socket` from weglarka.toml).
    #[arg(long, global = true, env = "WEGLARKA_SOCKET", value_name = "SOCKET")]
    pub socket: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage apps (add/remove/list/show).
    #[command(subcommand)]
    Apps(AppsCommand),
    /// Force an app deploy (pull, container swap, health gate, rollback if needed).
    Deploy(DeployArgs),
    /// Daemon and app status.
    Status,
    /// App secrets (set/list). Values are never returned by the API.
    #[command(subcommand)]
    Secrets(SecretsCommand),
    /// Self-diagnosis; `--preflight` runs locally, without the daemon.
    Doctor(DoctorArgs),
}

#[derive(Debug, Subcommand)]
pub enum AppsCommand {
    /// Add an app instance.
    Add(AddArgs),
    /// Remove an app instance.
    Remove(RemoveArgs),
    /// List apps.
    List,
    /// App details: spec, state, runtime.
    Show { name: String },
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Instance name ([a-z0-9-], 1–63 characters).
    pub name: String,
    /// Image reference, e.g. ghcr.io/jpalczewski/ntfy.zig:latest.
    #[arg(required_unless_present = "spec")]
    pub image: Option<String>,
    /// Domain routed to the app (repeatable).
    #[arg(long = "domain", conflicts_with = "spec")]
    pub domains: Vec<String>,
    /// HTTP port in the container.
    #[arg(long, conflicts_with = "spec")]
    pub port: Option<u16>,
    /// Environment variable KEY=VALUE (plain, not secret; repeatable).
    #[arg(long = "env", value_name = "K=V", value_parser = parse_pair, conflicts_with = "spec")]
    pub env: Vec<(String, String)>,
    /// Secret as an environment variable: SECRET=VARIABLE.
    #[arg(long = "secret-env", value_name = "SECRET=VARIABLE", value_parser = parse_pair, conflicts_with = "spec")]
    pub secret_env: Vec<(String, String)>,
    /// Secret as a file in the container: SECRET=PATH.
    #[arg(long = "secret-mount", value_name = "SECRET=PATH", value_parser = parse_pair, conflicts_with = "spec")]
    pub secret_mount: Vec<(String, String)>,
    /// Disable auto-update (the webhook will not swap the image on its own).
    #[arg(long, conflicts_with = "spec")]
    pub no_auto_update: bool,
    /// Whole AppSpec from a TOML file (instead of the flags above); `-` = stdin.
    #[arg(long, value_name = "FILE")]
    pub spec: Option<PathBuf>,
    /// Send nothing; show the request that would be sent.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub name: String,
    /// A missing app is not an error (idempotent removal).
    #[arg(long)]
    pub ignore_missing: bool,
    /// Remove nothing; check that the app exists and show the request.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    pub app: String,
    /// Override the image reference for this deploy only (e.g. a pinned sha-… tag).
    #[arg(long, value_name = "REF")]
    pub image: Option<String>,
    /// Deploy nothing; check that the app exists and show the request.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Set (overwrite) a secret. Value from stdin or a file — never from an argument.
    Set(SecretSetArgs),
    /// List an app's secrets (name, fingerprint, date) — without values.
    List { app: String },
}

#[derive(Debug, Args)]
pub struct SecretSetArgs {
    pub app: String,
    /// Secret name ([A-Za-z0-9_-], 1–64 characters).
    pub name: String,
    /// Read the value from a file instead of stdin.
    #[arg(long, value_name = "FILE")]
    pub from_file: Option<PathBuf>,
    /// Keep the value byte for byte (by default one trailing newline is stripped).
    #[arg(long)]
    pub raw: bool,
    /// Send nothing; validate the input and show the request (the value is masked).
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Check the host locally, without the daemon (user, subuid, cgroups, linger, Podman, ingress…).
    #[arg(long)]
    pub preflight: bool,
    /// Path of secrets.toml whose permissions to check (not in weglarka.toml;
    /// defaults to next to the configuration file).
    #[arg(
        long,
        value_name = "FILE",
        env = "WEGLARKA_SECRETS_FILE",
        requires = "preflight"
    )]
    pub secrets_file: Option<PathBuf>,
}

fn parse_pair(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("expected KEY=VALUE, got {s:?}")),
    }
}
