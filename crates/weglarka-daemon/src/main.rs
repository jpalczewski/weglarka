//! Binarka demona: `run` (domyślnie) oraz `platform install|remove|status`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;
use weglarka_core::config::PlatformKind;
use weglarka_core::platform::{Platform, ServiceSpec};
use weglarka_daemon::ingress::WEBHOOK_NETWORK;
use weglarka_daemon::platform::{SystemdPlatform, render};
use weglarka_daemon::{Settings, start};
use weglarka_podman::LibpodClient;

const DEFAULT_IMAGE: &str = "ghcr.io/jpalczewski/weglarka:latest";
const SERVICE_NAME: &str = "weglarka";

#[derive(Parser)]
#[command(name = "weglarka-daemon", version, about = "Demon Węglarki")]
struct Cli {
    /// Plik konfiguracji hosta.
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
    /// Uruchamia demona (domyślne).
    Run,
    /// Serwis Węglarki w menedżerze usług (systemd: quadlet usera).
    Platform {
        #[command(subcommand)]
        action: PlatformAction,
    },
}

#[derive(Subcommand)]
enum PlatformAction {
    /// Generuje i instaluje serwis (uruchamiaj jako user runtime'u).
    Install {
        /// Tylko wypisz pliki, nic nie zapisuj.
        #[arg(long)]
        dry_run: bool,
        /// Obraz kontenera Węglarki.
        #[arg(long, default_value = DEFAULT_IMAGE)]
        image: String,
    },
    /// Usuwa plik serwisu.
    Remove,
    /// Pokazuje stan serwisu.
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

/// Wszystkie ścieżki montujemy pod tą samą nazwą co na hoście, żeby `weglarka.toml` był
/// poprawny po obu stronach (CLI na hoście czyta ten sam plik).
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
        // Pojedynczy plik: zapis w miejscu zachowuje inode, więc Traefik widzi zmianę.
        mounts.push(same(f));
    }
    ServiceSpec {
        name: SERVICE_NAME.to_owned(),
        image,
        run_as_user: settings.host.runtime.user.clone(),
        env: vec![("RUST_LOG".to_owned(), "info".to_owned())],
        mounts,
        networks: vec![WEBHOOK_NETWORK.to_owned()],
        args: vec!["run".to_owned(), "--config".to_owned(), s(conf)],
    }
}

async fn run_platform(settings: Settings, action: PlatformAction) -> Result<()> {
    let platform = systemd(&settings)?;
    match action {
        PlatformAction::Install { dry_run, image } => {
            let socket = match &settings.host.runtime.socket {
                Some(s) => s.clone(),
                None => platform.runtime_socket(&settings.host.runtime.user).await?,
            };
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

async fn run_daemon(settings: Settings) -> Result<()> {
    let socket = match &settings.host.runtime.socket {
        Some(s) => s.clone(),
        None => match settings.host.platform.kind {
            PlatformKind::Systemd => {
                SystemdPlatform::new(settings.host.runtime.user.clone())
                    .runtime_socket(&settings.host.runtime.user)
                    .await?
            }
            other => bail!("platform {other:?} is not supported yet; set [runtime] socket"),
        },
    };
    let running = start(settings, LibpodClient::new(socket)).await?;

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM received"),
        _ = int.recv() => tracing::info!("SIGINT received"),
    }
    // Trzeci sygnał w trakcie zatrzymania wymusza wyjście.
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
