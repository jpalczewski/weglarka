//! The daemon binary: `run` (default) and `platform install|remove|status`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;
use weglarka_core::config::PlatformKind;
use weglarka_core::platform::{Hardening, Platform, ServiceSpec};
use weglarka_daemon::ingress::WEBHOOK_NETWORK;
use weglarka_daemon::platform::{SystemdPlatform, render, run_args};
use weglarka_daemon::{Settings, start};
use weglarka_podman::LibpodClient;

const DEFAULT_IMAGE: &str = "ghcr.io/jpalczewski/weglarka:latest";
const SERVICE_NAME: &str = "weglarka";

#[derive(Parser)]
#[command(name = "weglarka-daemon", version, about = "The Węglarka daemon")]
struct Cli {
    /// Host configuration file.
    #[arg(
        long,
        global = true,
        env = "WEGLARKA_CONFIG",
        default_value = "/etc/weglarka/weglarka.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (default).
    Run,
    /// The Węglarka service in the service manager (systemd: user quadlet).
    Platform {
        #[command(subcommand)]
        action: PlatformAction,
    },
}

#[derive(Subcommand)]
enum PlatformAction {
    /// Generate and install the service (run as the runtime user).
    Install {
        /// Only print the files, write nothing.
        #[arg(long)]
        dry_run: bool,
        /// Węglarka container image.
        #[arg(long, default_value = DEFAULT_IMAGE)]
        image: String,
    },
    /// Prints the `podman run` arguments equivalent to the quadlet (one per line) — for CI tests.
    RunArgs {
        /// Węglarka container image.
        #[arg(long, default_value = DEFAULT_IMAGE)]
        image: String,
    },
    /// Remove the service file.
    Remove,
    /// Show the service status.
    Status,
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
}

fn systemd(settings: &Settings) -> Result<SystemdPlatform> {
    match settings.host.platform.kind {
        PlatformKind::Systemd => Ok(SystemdPlatform::new(settings.host.runtime.user.clone())),
        other => bail!("platform {other:?} is not supported yet"),
    }
}

/// Env var carrying the Podman socket path resolved on the host: the (`scratch`) container has no `/etc/passwd`.
const SOCKET_ENV: &str = "WEGLARKA_PODMAN_SOCKET";

/// All paths are mounted under the same name as on the host so that `weglarka.toml` is
/// valid on both sides (the host CLI reads the same file).
fn service_spec(settings: &Settings, podman_socket: PathBuf, image: String) -> ServiceSpec {
    let s = |p: &std::path::Path| p.display().to_string();
    let same = |p: &std::path::Path| (s(p), s(p));
    let mut mounts = vec![same(&podman_socket), same(&settings.paths.state_dir)];
    if let Some(dir) = settings.host.admin.socket.parent() {
        mounts.push(same(dir));
    }
    let conf = &settings.config_path;
    mounts.push((s(conf), format!("{}:ro", s(conf))));
    if !settings
        .paths
        .nginx_conf_dir
        .starts_with(&settings.paths.state_dir)
    {
        mounts.push(same(&settings.paths.nginx_conf_dir));
    }
    if let Some(f) = &settings.host.ingress.traefik_dynamic_file {
        // A single file: an in-place write preserves the inode, so Traefik sees the change.
        mounts.push(same(f));
    }
    ServiceSpec {
        name: SERVICE_NAME.to_owned(),
        image,
        run_as_user: settings.host.runtime.user.clone(),
        env: vec![
            ("RUST_LOG".to_owned(), "info".to_owned()),
            (SOCKET_ENV.to_owned(), s(&podman_socket)),
        ],
        mounts,
        networks: vec![WEBHOOK_NETWORK.to_owned()],
        args: vec!["run".to_owned(), "--config".to_owned(), s(conf)],
        hardening: Hardening {
            memory: Some(settings.host.platform.memory.clone()),
            pids_limit: Some(settings.host.platform.pids_limit),
            ..Hardening::default()
        },
    }
}

async fn host_socket(settings: &Settings, platform: &SystemdPlatform) -> Result<PathBuf> {
    Ok(match &settings.host.runtime.socket {
        Some(s) => s.clone(),
        None => platform.runtime_socket(&settings.host.runtime.user).await?,
    })
}

async fn run_platform(settings: Settings, action: PlatformAction) -> Result<()> {
    let platform = systemd(&settings)?;
    match action {
        PlatformAction::RunArgs { image } => {
            let socket = host_socket(&settings, &platform).await?;
            for a in run_args(&service_spec(&settings, socket, image))? {
                println!("{a}");
            }
        }
        PlatformAction::Install { dry_run, image } => {
            let socket = host_socket(&settings, &platform).await?;
            let spec = service_spec(&settings, socket, image);
            if dry_run {
                for f in render(&spec)? {
                    println!("# {}\n{}", f.file_name, f.content);
                }
                return Ok(());
            }
            platform.install_service(&spec).await?;
            println!(
                "Zainstalowano. Uruchom: systemctl --user start {SERVICE_NAME}.service \
                 (wymaga `loginctl enable-linger {}`)",
                settings.host.runtime.user
            );
        }
        PlatformAction::Remove => {
            platform.remove_service(SERVICE_NAME).await?;
            println!("Usunięto plik serwisu {SERVICE_NAME}.");
        }
        PlatformAction::Status => {
            println!("{:?}", platform.service_status(SERVICE_NAME).await?);
        }
    }
    Ok(())
}

/// The daemon (usually in a `scratch` container) never guesses the socket from `/etc/passwd`: it takes it from
/// `[runtime] socket` or from the variable set by the quadlet (`platform install` resolves it on the host).
async fn run_daemon(settings: Settings) -> Result<()> {
    let socket = match (&settings.host.runtime.socket, std::env::var_os(SOCKET_ENV)) {
        (Some(s), _) => s.clone(),
        (None, Some(v)) if !v.is_empty() => PathBuf::from(v),
        (None, _) => bail!(
            "unknown Podman socket: set [runtime] socket in {} or the {SOCKET_ENV} variable \
             (`platform install` sets it in the quadlet)",
            settings.config_path.display()
        ),
    };
    let running = start(settings, LibpodClient::new(socket)).await?;

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM received"),
        _ = int.recv() => tracing::info!("SIGINT received"),
    }
    // A third signal during shutdown forces an exit.
    tokio::select! {
        () = running.stop() => {}
        _ = term.recv() => tracing::warn!("second signal, exiting immediately"),
        _ = tokio::time::sleep(Duration::from_secs(150)) => tracing::warn!("shutdown timeout"),
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();
    let settings = Settings::load(&cli.config).context("loading configuration")?;
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run_daemon(settings).await,
        Command::Platform { action } => run_platform(settings, action).await,
    }
}
