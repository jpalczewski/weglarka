//! Command definitions. The `///` docs below are user-visible `--help` text.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use weglarka_model::app::BodySizeLimit;

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

    /// Address of a remote host's admin panel (after `weglarka login`), e.g. `https://panel.example.com`:
    /// the commands go through the panel instead of the local socket. Also `host` in `cli.toml`.
    #[arg(
        long,
        global = true,
        env = "WEGLARKA_HOST",
        value_name = "URL",
        conflicts_with = "socket"
    )]
    pub host: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

// CLI arguments are parsed once per process; boxing the big `apps add/update` variants buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage apps (add/update/start/stop/reload/remove/list/show).
    #[command(subcommand)]
    Apps(AppsCommand),
    /// Run a command once in a fresh container of an app (its image, env, secrets, volumes, configs
    /// and networks; never its ports or routing) and print the output. For migrations and admin
    /// commands: `weglarka run <app> -- <command>`.
    Run(crate::run::RunArgs),
    /// Temporarily forward a port of an app to this machine: a short-lived relay container on the
    /// app's network plus an SSH tunnel, both removed when the command ends.
    Forward(crate::forward::ForwardArgs),
    /// Force an app deploy (pull, container swap, health gate, rollback if needed).
    Deploy(DeployArgs),
    /// Deploy an image that did not come through the webhook: an archive built on this machine
    /// (`podman save … | weglarka push <app> -`) or another tag of the app's image repository.
    Push(crate::push::PushArgs),
    /// Daemon and app status.
    Status,
    /// App secrets (set/list/remove). Values are never returned by the API.
    #[command(subcommand)]
    Secrets(SecretsCommand),
    /// Self-diagnosis; `--preflight` runs locally, without the daemon.
    Doctor(DoctorArgs),
    /// Volumes: list app volumes or declared shared volumes, export/import, declare/remove a
    /// shared volume.
    #[command(subcommand)]
    Volumes(crate::volumes::VolumesCommand),
    /// Shared networks: list, declare and remove the networks that let a group of apps reach each
    /// other.
    #[command(subcommand)]
    Networks(crate::networks::NetworksCommand),
    /// Sites with environments: list, show, declare and remove (a development and a production
    /// version of one static site).
    #[command(subcommand)]
    Sites(crate::sites::SitesCommand),
    /// OIDC clients: rotate an app's client secret, manage the clients of apps Węglarka does not run.
    #[command(subcommand)]
    Oidc(crate::oidc::OidcCommand),
    /// Promote the digest one environment of a site runs into another: `weglarka promote blog prod`.
    Promote(crate::sites::PromoteArgs),
    /// Local images: remove the ones older than each app's current and previous image.
    #[command(subcommand)]
    Images(ImagesCommand),
    /// Notifications: channel status and a test delivery.
    #[command(subcommand)]
    Notify(NotifyCommand),
    /// Sign in to a remote host with the OAuth 2.0 device authorization grant: the command prints a
    /// code, you approve it on any device, and the tokens are kept for later commands.
    Login(crate::login::LoginArgs),
    /// Sign out of a remote host: forget the tokens and ask the provider to revoke the session.
    Logout,
    /// Show the session with a remote host (refreshes the token when it is about to expire).
    Whoami,
}

#[derive(Debug, Subcommand)]
pub enum ImagesCommand {
    /// Remove images of the repositories Węglarka deploys that are neither an app's current nor its
    /// previous image and that no container uses. `--dry-run` lists them and removes nothing.
    Prune(PruneImagesArgs),
}

#[derive(Debug, Args)]
pub struct PruneImagesArgs {
    /// List the images that would be removed; remove nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum NotifyCommand {
    /// Show the configured channels, the pending outbox and the last delivery error.
    Status,
    /// Send a test notification now (bypasses the outbox and the dedup window).
    Test,
}

#[derive(Debug, Subcommand)]
pub enum AppsCommand {
    /// Add an app instance.
    Add(AddArgs),
    /// Change an app's spec (read-modify-write; domains, env, secrets, image…).
    Update(crate::update::UpdateArgs),
    /// Start the app: sets `start = true` and deploys it (a provisioned app gets its container).
    Start(StartStopArgs),
    /// Stop the app: sets `start = false` and removes the container; volumes, the uid range and the
    /// pinned image digest stay.
    Stop(StartStopArgs),
    /// Reload the app's configs without recreating the container: sends the spec's `reload_signal`,
    /// or restarts the container when the spec sets none. Changes no desired state.
    Reload(ReloadArgs),
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
    /// Path prefix of the domains served by this app, e.g. `/api` (repeatable; default `/`). Several
    /// instances may share a domain when their prefixes are disjoint.
    #[arg(long = "path", value_name = "PREFIX", conflicts_with = "spec")]
    pub paths: Vec<String>,
    /// Strip the `--path` prefix before proxying (`/api/x` reaches the app as `/x`).
    #[arg(long, conflicts_with = "spec")]
    pub strip_prefix: bool,
    /// HTTP port in the container.
    #[arg(long, conflicts_with = "spec")]
    pub port: Option<u16>,
    /// Serve streaming responses (SSE, chunked, long polling): no nginx response/request buffering
    /// and a long idle timeout. Ingress-only, so it never recreates the container; the timeout
    /// itself is set through `--spec` (`stream_timeout_secs`, default 180 s).
    #[arg(long, conflicts_with = "spec")]
    pub streaming: bool,
    /// Path that is served as a long-lived stream (SSE) with a 1 h idle timeout while the rest of
    /// the app keeps the default (repeatable; e.g. `/user/events`). Ingress-only.
    #[arg(long = "streaming-path", value_name = "PATH", conflicts_with = "spec")]
    pub streaming_paths: Vec<String>,
    /// Request body limit, e.g. `4g`, `512m` or a byte count; `0` removes the limit (default 64m).
    /// Also streams the request to the app instead of buffering it. Ingress-only.
    #[arg(long, value_name = "SIZE", value_parser = BodySizeLimit::parse, conflicts_with = "spec")]
    pub max_body_size: Option<BodySizeLimit>,
    /// Path left out of the access log while it succeeds (repeatable); a trailing `/` makes it a
    /// prefix, e.g. `/api/poll/`. Errors (status >= 400) are still logged. Ingress-only.
    #[arg(
        long = "access-log-skip-path",
        value_name = "PATH",
        conflicts_with = "spec"
    )]
    pub access_log_skip_paths: Vec<String>,
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
    /// Provision only: pull the image, create the network, the uid range and the volumes, but do
    /// not create or start the container. Bring it up later with `apps start`.
    #[arg(long, conflicts_with = "spec")]
    pub no_start: bool,
    #[command(flatten)]
    pub spec_flags: crate::spec_flags::SpecFlags,
    /// Whole AppSpec from a TOML file (instead of the flags above); `-` = stdin.
    #[arg(long, value_name = "FILE")]
    pub spec: Option<PathBuf>,
    /// Send nothing; show the request that would be sent.
    #[arg(long)]
    pub dry_run: bool,
}

/// Flags shared by `apps start` and `apps stop` (both flip `start` through `PUT /v1/apps/{name}`).
#[derive(Debug, Args)]
pub struct StartStopArgs {
    /// Instance name.
    pub name: String,
    /// Send nothing; show the request that would be sent.
    #[arg(long)]
    pub dry_run: bool,
}

/// Flags of `apps reload`: a signal-based reload, or an explicit recreate for editors that save with
/// write-and-rename (a single-file bind mount keeps pointing at the old inode).
#[derive(Debug, Args)]
pub struct ReloadArgs {
    /// Instance name.
    pub name: String,
    /// Recreate the container from the pinned digest instead of reloading in place (no pull). Needed
    /// when a single-file config mount still points at the old file: an editor saved a new inode.
    /// The `configs` list is part of the spec hash, the file content is not, so a plain reload cannot
    /// publish a renamed file.
    #[arg(long)]
    pub recreate: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub name: String,
    /// A missing app is not an error (idempotent removal).
    #[arg(long)]
    pub ignore_missing: bool,
    /// Also delete the app's volumes (its data!) and release its uid range. Without it the volumes
    /// stay, and `apps add` of the same name picks them up again.
    #[arg(long)]
    pub purge_volumes: bool,
    /// Also delete the app's stored secrets. Independent of --purge-volumes; without it the secrets
    /// survive `apps remove` + `apps add` of the same name.
    #[arg(long)]
    pub purge_secrets: bool,
    /// Remove nothing; check that the app exists and show the request.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    pub app: String,
    /// Deploy this tag or digest of the app's image repository instead of the spec's tag (e.g. a
    /// pinned sha-… tag). Its digest is pinned in the state; the spec keeps its tag, so the next
    /// deploy of that tag replaces it.
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
    /// Remove a stored secret. Refused while the app's spec still binds it (use --force); the app
    /// need not exist, so the leftovers of a removed app can be cleaned up.
    Remove(SecretRemoveArgs),
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
pub struct SecretRemoveArgs {
    pub app: String,
    /// Secret name ([A-Za-z0-9_-], 1–64 characters).
    pub name: String,
    /// Remove the secret even though the app's spec still binds it; the app then waits for the
    /// secret (a running container keeps the old value).
    #[arg(long)]
    pub force: bool,
    /// Send nothing; validate the names locally and show the request (no server lookup, so it works
    /// for a removed app too).
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

pub(crate) fn parse_pair(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("expected KEY=VALUE, got {s:?}")),
    }
}
