//! The daemon binary: `run` (default) and `platform install|remove|status`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tracing::level_filters::LevelFilter;
use weglarka_core::config::PlatformKind;
use weglarka_core::platform::Platform;
use weglarka_daemon::platform::{
    SELF_UPDATE_SERVICE, SELF_UPDATE_TIMER, SystemdPlatform, render, run_args,
};
use weglarka_daemon::service::{
    DEFAULT_IMAGE, SERVICE_NAME, SOCKET_ENV, host_socket, service_spec,
};
use weglarka_daemon::{Settings, start};
use weglarka_podman::LibpodClient;
use weglarka_registry::HttpRegistry;

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
    /// Update Węglarka's own image: pull the configured tag, verify the cosign signature, pin the
    /// digest in the service definition and restart (issue #99).
    SelfUpdate(SelfUpdateArgs),
}

#[derive(clap::Args)]
struct SelfUpdateArgs {
    /// Only report: pull, verify and check the state schema, never write the unit or restart.
    #[arg(long)]
    check: bool,
    /// Ignore the configured interval (and retry a digest that already failed).
    #[arg(long)]
    force: bool,
    /// Pin the previous digest again — the manual fallback until the automatic one (#100).
    #[arg(long)]
    rollback: bool,
    /// Follow this reference instead of `[self_update] image` (a one-shot manual update).
    #[arg(long)]
    image: Option<String>,
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

/// `RUST_LOG` is a plain level (`error|warn|info|debug|trace|off`), not a per-target directive list:
/// the `env-filter` feature pulls in the regex stack, which is not worth the build time and binary size here.
/// An unset or unparsable value means `info`.
fn init_tracing() {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::INFO);
    tracing_subscriber::fmt()
        .json()
        .with_max_level(level)
        .init();
}

fn systemd(settings: &Settings) -> Result<SystemdPlatform> {
    match settings.host.platform.kind {
        PlatformKind::Systemd => Ok(SystemdPlatform::new(settings.host.runtime.user.clone())),
        other => bail!("platform {other:?} is not supported yet"),
    }
}

/// `weglarka-daemon self-update` — the host-side switcher (issue #99). Runs from a user timer that
/// `platform install` installs; `--check`/`--force` are for a manual run from a shell.
async fn run_self_update(settings: Settings, options: SelfUpdateArgs) -> Result<()> {
    let mut settings = settings;
    if let Some(image) = options.image.as_deref() {
        // A one-shot explicit image replaces `[self_update] image`; without a section, defaults are
        // used, so a manual update works before the operator commits the section to the config.
        match settings.host.self_update.as_mut() {
            Some(config) => config.image = image.to_owned(),
            None => {
                settings.host.self_update = Some(weglarka_core::config::SelfUpdateConfig {
                    image: image.to_owned(),
                    enabled: true,
                    interval_secs: weglarka_core::config::SelfUpdateConfig::DEFAULT_INTERVAL_SECS,
                    public_key_file: None,
                });
            }
        }
    }
    let platform = systemd(&settings)?;
    let socket = host_socket(&settings, &platform).await?;
    let podman = LibpodClient::new(socket);
    let registry = HttpRegistry::new().context("setting up the registry client")?;
    let report = weglarka_daemon::self_update::run(
        &podman,
        &registry,
        &platform,
        &settings,
        weglarka_daemon::self_update::Options {
            check: options.check,
            force: options.force,
            rollback: options.rollback,
        },
        std::time::SystemTime::now(),
    )
    .await?;
    println!("{report}");
    if !report.is_success() {
        // Non-zero so the timer unit shows a failure instead of pretending everything is fine.
        bail!("{report}");
    }
    Ok(())
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
            let units = weglarka_daemon::self_update::units(&settings)?;
            if dry_run {
                for f in render(&spec)? {
                    println!("# {}\n{}", f.file_name, f.content);
                }
                for f in &units {
                    println!("# {}\n{}", f.file_name, f.content);
                }
                return Ok(());
            }
            platform.install_service(&spec).await?;
            platform.install_user_units(&units).await?;
            platform.set_timer(SELF_UPDATE_TIMER, true).await?;
            println!(
                "Installed. Start it with: systemctl --user start {SERVICE_NAME}.service \
                 (requires `loginctl enable-linger {}`); the self-update timer is enabled and does \
                 nothing until [self_update] is configured.",
                settings.host.runtime.user
            );
        }
        PlatformAction::Remove => {
            // Disable before deleting: `systemctl disable` needs the unit files.
            platform.set_timer(SELF_UPDATE_TIMER, false).await?;
            platform
                .remove_user_units(&[SELF_UPDATE_SERVICE, SELF_UPDATE_TIMER])
                .await?;
            platform.remove_service(SERVICE_NAME).await?;
            println!("Removed the {SERVICE_NAME} service file and the self-update timer.");
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
        Command::SelfUpdate(args) => run_self_update(settings, args).await,
    }
}
