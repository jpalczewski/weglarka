//! The daemon binary: `run` (default), `platform install|remove|status|bootstrap|downgrade`, the
//! host preflight and the legacy self-update/watchdog entry points.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tracing::level_filters::LevelFilter;
use weglarka_daemon::openrc::OpenRcPlatform;
use weglarka_daemon::platform::{
    SELF_UPDATE_TIMER, SystemdPlatform, WATCHDOG_TIMER, render, run_args,
};
use weglarka_daemon::service::{
    DEFAULT_IMAGE, SERVICE_NAME, SOCKET_ENV, host_socket, service_spec,
};
use weglarka_daemon::{Settings, start};
use weglarka_engine::platform::Platform;
use weglarka_launcher::host::DEFAULT_HOST_DIR;
use weglarka_model::config::PlatformKind;
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
    /// Host-only directory for the launcher, generations and host state (outside every container
    /// bind mount).
    #[arg(long, global = true, default_value = DEFAULT_HOST_DIR)]
    host_dir: PathBuf,
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
    /// Watch a switch in flight and fall back to the previous image when the new daemon does not
    /// answer the admin API within `[self_update] fallback_timeout_secs` (issue #100). Runs from
    /// `weglarka-watchdog.timer`; a manual run prints what it would do.
    Supervise,
    /// Read-only host preflight: host protocol, state schemas, journal readability and whether this
    /// binary parses the current `weglarka.toml`. Used by the launcher for candidate/recovery
    /// generations.
    HostPreflight,
    /// Recovery entry point used by the launcher's `recover` role. The decision machine is brief D.
    RecoverV1,
    /// Port forwarder of `edge` mode: relays public sockets to nginx's unix sockets with a PROXY
    /// protocol header (issue #162). Runs in its own container; needs no configuration file.
    Forward {
        /// `<address:port>=<socket path>`; repeat per public socket.
        #[arg(long = "route", required = true)]
        routes: Vec<weglarka_daemon::forwarder::Route>,
    },
}

#[derive(clap::Args)]
struct SelfUpdateArgs {
    /// Only report: pull, verify and check the state schema, never write the unit or restart.
    #[arg(long)]
    check: bool,
    /// Ignore the configured interval (and retry a digest that already failed).
    #[arg(long)]
    force: bool,
    /// Pin the previous digest again — the manual lever when the automatic fallback (issue #100)
    /// could not act.
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
    /// Remove the service, the launcher jobs (units or cron block) and the init scripts.
    Remove,
    /// Show the service status.
    Status,
    /// Install the stable launcher and generation 0, retire the legacy runner, provision jobs.
    Bootstrap(BootstrapCommand),
    /// Reverse bootstrap: remove launcher units and restore the legacy daemon-only units.
    Downgrade(BootstrapArgs),
}

#[derive(clap::Args)]
struct BootstrapCommand {
    #[command(flatten)]
    args: BootstrapArgs,
    /// Run every check, print the steps a bootstrap would take and change nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(clap::Args)]
struct BootstrapArgs {
    /// Digest of the verified image the current tools came from (generation key; required for
    /// bootstrap, defaults to the selector's active generation for downgrade).
    #[arg(long)]
    generation: Option<String>,
    /// Daemon image repository or tag; the installed selection pins it to `--generation`.
    #[arg(long, default_value = DEFAULT_IMAGE)]
    image: String,
    /// Launcher binary to install into the host-only directory.
    #[arg(long)]
    launcher: Option<PathBuf>,
    /// Daemon binary to stage as generation 0 (default: this executable).
    #[arg(long)]
    daemon_binary: Option<PathBuf>,
    /// CLI binary to stage as generation 0 (default: `weglarka` next to the daemon).
    #[arg(long)]
    cli_binary: Option<PathBuf>,
    /// Channel whose durable pointer gates coordinated updates.
    #[arg(long)]
    channel: Option<String>,
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
                settings.host.self_update = Some(weglarka_model::config::SelfUpdateConfig {
                    image: image.to_owned(),
                    enabled: true,
                    interval_secs: weglarka_model::config::SelfUpdateConfig::DEFAULT_INTERVAL_SECS,
                    fallback: true,
                    fallback_timeout_secs:
                        weglarka_model::self_update::FallbackPolicy::DEFAULT_TIMEOUT_SECS,
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

/// `weglarka-daemon supervise` — the host-side watchdog (issue #100). The timer runs it every
/// minute; `platform install` installs both units.
async fn run_supervise(settings: Settings) -> Result<()> {
    // Issue #191: needs no Podman, so a dead socket below must not skip it.
    weglarka_daemon::supervise::record_user_groups(&settings, std::time::SystemTime::now());
    let platform = systemd(&settings)?;
    let socket = host_socket(&settings, &platform).await?;
    let podman = LibpodClient::new(socket);
    let report = weglarka_daemon::supervise::run(
        &podman,
        &platform,
        &settings,
        std::time::SystemTime::now(),
    )
    .await?;
    println!("{report}");
    if !report.is_success() {
        // Non-zero so the watchdog unit shows a failure (an exhausted fallback needs the operator).
        bail!("{report}");
    }
    Ok(())
}

async fn run_platform<P: Platform>(
    platform: &P,
    settings: Settings,
    action: PlatformAction,
    host_dir: PathBuf,
) -> Result<()> {
    match action {
        PlatformAction::RunArgs { image } => {
            let socket = host_socket(&settings, platform).await?;
            for a in run_args(&service_spec(&settings, socket, image))? {
                println!("{a}");
            }
        }
        PlatformAction::Install { dry_run, image } => {
            let socket = host_socket(&settings, platform).await?;
            let spec = service_spec(&settings, socket, image);
            let mut units = weglarka_daemon::self_update::units(&settings)?;
            units.extend(weglarka_daemon::self_update::watchdog_units(&settings)?);
            if dry_run {
                for f in render(&spec)? {
                    println!("# {}\n{}", f.file_name, f.content);
                }
                if platform.kind() == PlatformKind::Systemd {
                    for f in &units {
                        println!("# {}\n{}", f.file_name, f.content);
                    }
                }
                return Ok(());
            }
            platform.install_service(&spec).await?;
            if platform.kind() == PlatformKind::Systemd {
                platform.install_user_units(&units).await?;
                platform.set_timer(SELF_UPDATE_TIMER, true).await?;
                platform.set_timer(WATCHDOG_TIMER, true).await?;
                println!(
                    "Installed. Start it with: systemctl --user start {SERVICE_NAME}.service \
                     (requires `loginctl enable-linger {}`); the self-update and watchdog timers are \
                     enabled and do nothing until [self_update] is configured.",
                    settings.host.runtime.user
                );
            } else {
                println!(
                    "Installed the OpenRC services. Enable them with `rc-update add \
                     weglarka-podman default` and `rc-update add {SERVICE_NAME} default`; \
                     coordinated updates need `platform bootstrap`."
                );
            }
        }
        PlatformAction::Remove => {
            platform.remove_launcher_setup().await?;
            platform.remove_service(SERVICE_NAME).await?;
            if platform.kind() == PlatformKind::Systemd {
                println!(
                    "Removed the {SERVICE_NAME} service file, the self-update timer, the watchdog \
                     and the launcher job units."
                );
            } else {
                println!(
                    "Removed the OpenRC init scripts and the managed cron block; the \
                     runtime user's other crontab lines are untouched."
                );
            }
        }
        PlatformAction::Status => {
            println!("{:?}", platform.service_status(SERVICE_NAME).await?);
        }
        PlatformAction::Bootstrap(BootstrapCommand { args, dry_run }) => {
            let options = bootstrap_options(&args, &settings, host_dir, true)?;
            if dry_run {
                let plan = weglarka_daemon::bootstrap::plan(platform, &options).await?;
                println!("Bootstrap plan (nothing was changed):\n{plan}");
                return Ok(());
            }
            let report = weglarka_daemon::bootstrap::bootstrap(platform, &options).await?;
            println!(
                "Bootstrapped generation {} (selector epoch {}); coordinated updates {}.",
                report.generation,
                report.selector_epoch,
                if report.coordinated_ready {
                    "enabled"
                } else {
                    "still disabled (no channel pointer or preflight not yet complete)"
                }
            );
            if !report.retired_units.is_empty() {
                println!("Retired: {}", report.retired_units.join(", "));
            }
            if platform.kind() == PlatformKind::Systemd && !report.linger_enabled {
                println!(
                    "Warning: lingering is not enabled for {}; run `loginctl enable-linger {}` \
                     as root or the user timers will not start after a reboot.",
                    settings.host.runtime.user, settings.host.runtime.user
                );
            }
        }
        PlatformAction::Downgrade(args) => {
            let options = bootstrap_options(&args, &settings, host_dir, false)?;
            weglarka_daemon::bootstrap::downgrade(platform, &options).await?;
            if platform.kind() == PlatformKind::Systemd {
                println!("Removed the launcher units and restored the legacy daemon-only units.");
            } else {
                println!(
                    "Removed the launcher init scripts and the managed cron block. OpenRC has no \
                     legacy daemon-only setup, so no daemon starts at boot until you run \
                     `platform bootstrap` again."
                );
            }
        }
    }
    Ok(())
}

fn bootstrap_options(
    args: &BootstrapArgs,
    settings: &Settings,
    host_dir: PathBuf,
    require_generation: bool,
) -> Result<weglarka_daemon::bootstrap::BootstrapOptions> {
    use weglarka_model::release_set::{Channel, StrictDigest};
    let generation = match &args.generation {
        Some(value) => StrictDigest::new(value.clone())
            .with_context(|| format!("invalid --generation {value:?}"))?,
        None if require_generation => {
            bail!("--generation is required for platform bootstrap")
        }
        None => {
            weglarka_launcher::selector::HostSelector::load(&host_dir)
                .context("reading host-tools.toml for downgrade")?
                .active
        }
    };
    let image = pin_image(&args.image, &generation)?;
    let daemon_binary = match &args.daemon_binary {
        Some(path) => path.clone(),
        None => std::env::current_exe().context("resolving the current executable")?,
    };
    let cli_binary = match &args.cli_binary {
        Some(path) => path.clone(),
        None => daemon_binary
            .parent()
            .map(|dir| dir.join("weglarka"))
            .context("the daemon binary has no parent directory")?,
    };
    let launcher_binary = match &args.launcher {
        Some(path) => path.clone(),
        None => daemon_binary
            .parent()
            .map(|dir| dir.join("weglarka-launcher"))
            .context("the daemon binary has no parent directory")?,
    };
    let channel = match &args.channel {
        Some(value) => Some(Channel::parse(value).ok_or_else(|| {
            anyhow::anyhow!("unknown --channel {value:?}; expected stable or main")
        })?),
        None => None,
    };
    let (uid, gid) = weglarka_daemon::bootstrap::lookup_user(&settings.host.runtime.user)
        .map(|(uid, gid)| (Some(uid), Some(gid)))
        .unwrap_or((None, None));
    Ok(weglarka_daemon::bootstrap::BootstrapOptions {
        host_dir,
        state_dir: settings.paths.state_dir.clone(),
        config_path: settings.config_path.clone(),
        runtime_user: settings.host.runtime.user.clone(),
        runtime_uid: uid,
        runtime_gid: gid,
        generation,
        daemon_binary,
        cli_binary,
        launcher_binary,
        image,
        channel,
        enable_linger: true,
    })
}

/// `repo:tag` or `repo` -> `repo@sha256:…`.
fn pin_image(image: &str, digest: &weglarka_model::release_set::StrictDigest) -> Result<String> {
    let repository = match image.rsplit_once('@') {
        Some((repository, _)) => repository.to_owned(),
        None => {
            let last_segment = image.rsplit('/').next().unwrap_or_default();
            if let Some(index) = last_segment.rfind(':') {
                let cut = image.len() - last_segment.len() + index;
                image[..cut].to_owned()
            } else {
                image.to_owned()
            }
        }
    };
    if repository.is_empty() {
        bail!("--image {image:?} has no repository");
    }
    Ok(format!("{repository}@{digest}"))
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
    if let Some(Command::Forward { routes }) = cli.command {
        return weglarka_daemon::forwarder::run(routes)
            .await
            .context("port forwarder");
    }
    if let Some(Command::HostPreflight) = cli.command {
        let report = weglarka_daemon::preflight::run(&cli.config);
        println!("{}", report.to_json());
        if !report.is_eligible() {
            bail!("host preflight is not eligible: {}", report.to_json());
        }
        return Ok(());
    }
    if let Some(Command::RecoverV1) = cli.command {
        bail!(
            "recover-v1 is the host recovery entry point; its decision machine is brief D              (coordinator/recovery state), while the stable launcher and its bounded attempt \
             budget are installed"
        );
    }
    let settings = match Settings::load(&cli.config) {
        Ok(settings) => settings,
        Err(e) => {
            // Issue #617: the timers run these two from host binaries a self-update does not
            // replace; leave the stop where `doctor` reads it. The parse itself stays strict.
            if matches!(
                cli.command,
                Some(Command::SelfUpdate(_) | Command::Supervise)
            ) {
                weglarka_daemon::config_stop::record_unparsable_config(
                    &cli.config,
                    &e,
                    std::time::SystemTime::now(),
                );
            }
            return Err(e).context("loading configuration");
        }
    };
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => run_daemon(settings).await,
        Command::Platform { action } => run_platform_dispatch(settings, action, cli.host_dir).await,
        Command::SelfUpdate(args) => run_self_update(settings, args).await,
        Command::Supervise => run_supervise(settings).await,
        Command::HostPreflight | Command::RecoverV1 | Command::Forward { .. } => {
            unreachable!("handled before the configuration is loaded")
        }
    }
}

async fn run_platform_dispatch(
    settings: Settings,
    action: PlatformAction,
    host_dir: PathBuf,
) -> Result<()> {
    let user = settings.host.runtime.user.clone();
    let state_dir = settings.paths.state_dir.clone();
    match settings.host.platform.kind {
        PlatformKind::Systemd => {
            let platform = SystemdPlatform::new(user)
                .with_host_dir(host_dir.clone())
                .with_state_dir(state_dir);
            run_platform(&platform, settings, action, host_dir).await
        }
        PlatformKind::Openrc => {
            let (uid, _) = weglarka_daemon::bootstrap::lookup_user(&user)
                .ok_or_else(|| anyhow::anyhow!("runtime user {user:?} is not in /etc/passwd"))?;
            let platform = OpenRcPlatform::new(user, uid)
                .with_host_dir(host_dir.clone())
                .with_state_dir(state_dir);
            run_platform(&platform, settings, action, host_dir).await
        }
    }
}
