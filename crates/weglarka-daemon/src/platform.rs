//! `Platform` for systemd: user quadlet (`~/.config/containers/systemd/<name>.container`).
//! Quadlet is an option for the period of coexistence with Coolify; the `Platform` interface stays ready for
//! OpenRC — a second implementation of the trait is all that is needed.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use weglarka_engine::platform::{
    ActivationEpoch, ActivationReceipt, JobId, ObservedService, Platform, PlatformError, Result,
    ScheduledJob, ServiceName, ServiceSpec, ServiceStatus,
};
use weglarka_launcher::host::DEFAULT_HOST_DIR;
use weglarka_launcher::selection::{
    Job, LABEL_ACTIVATION_EPOCH, LABEL_DAEMON_DIGEST, PlatformService, RuntimeJobs,
};
use weglarka_model::app::Digest;
use weglarka_model::config::PlatformKind;

pub use weglarka_engine::platform::UnitFile;

/// Wykonuje polecenia (`systemctl --user …`); podmieniany w testach.
pub trait CommandRunner: Send + Sync {
    /// `(sukces, stdout)`.
    fn run(
        &self,
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> impl Future<Output = io::Result<(bool, String)>> + Send;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TokioRunner;

impl CommandRunner for TokioRunner {
    async fn run(
        &self,
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> io::Result<(bool, String)> {
        let out = tokio::process::Command::new(program)
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .output()
            .await?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        ))
    }
}

#[derive(Debug, Clone)]
struct PasswdEntry {
    uid: u32,
    home: PathBuf,
}

fn lookup(passwd: &Path, user: &str) -> Result<PasswdEntry> {
    let text = std::fs::read_to_string(passwd)
        .map_err(|e| PlatformError::Io(format!("{}: {e}", passwd.display())))?;
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 6 && f[0] == user).then(|| {
                Some(PasswdEntry {
                    uid: f[2].parse().ok()?,
                    home: PathBuf::from(f[5]),
                })
            })?
        })
        .next()
        .ok_or_else(|| {
            PlatformError::Command(format!("user {user:?} not found in {}", passwd.display()))
        })
}

pub struct SystemdPlatform<R: CommandRunner = TokioRunner> {
    /// Runtime user under whose systemd-user the service runs.
    user: String,
    passwd: PathBuf,
    /// Override of the quadlet directory (tests); defaults to `<home>/.config/containers/systemd`.
    quadlet_dir: Option<PathBuf>,
    /// Override of the user unit directory (tests); defaults to `<home>/.config/systemd/user`.
    units_dir: Option<PathBuf>,
    /// Host-only directory with the generation selector and service selection.
    host_dir: PathBuf,
    /// Shared state directory (`runtime-jobs.toml`); `None` disables the toggle.
    state_dir: Option<PathBuf>,
    /// When bootstrap runs as root, `systemctl --user` targets this user through `runuser`.
    runuser: Option<String>,
    runner: R,
}

impl SystemdPlatform<TokioRunner> {
    pub fn new(user: impl Into<String>) -> Self {
        Self::with_runner(user, TokioRunner)
    }
}

fn check_value(what: &str, v: &str) -> Result<()> {
    if v.is_empty() || v.chars().any(char::is_control) {
        return Err(PlatformError::Command(format!("invalid {what}: {v:?}")));
    }
    Ok(())
}

/// `128M`, `1g`, `65536` — Podman's `--memory` format (number + optional b/k/m/g).
fn check_memory(v: &str) -> Result<()> {
    let digits = v.trim_end_matches(['b', 'B', 'k', 'K', 'm', 'M', 'g', 'G']);
    if digits.is_empty()
        || !digits.chars().all(|c| c.is_ascii_digit())
        || v.len() - digits.len() > 2
    {
        return Err(PlatformError::Command(format!(
            "invalid memory limit {v:?} (expected e.g. \"128M\")"
        )));
    }
    Ok(())
}

fn check_hardening(spec: &ServiceSpec) -> Result<()> {
    if let Some(m) = &spec.hardening.memory {
        check_memory(m)?;
    }
    for t in &spec.hardening.tmpfs {
        check_value("tmpfs", t)?;
    }
    Ok(())
}

/// `podman run` arguments (without `run`/`-d`/`--pull`) equivalent to the quadlet from [`render`], with the image
/// and command at the end. The CI smoke test starts the container from exactly these.
pub fn run_args(spec: &ServiceSpec) -> Result<Vec<String>> {
    run_args_with_labels(spec, &[])
}

/// [`run_args`] plus container labels. Labels are validated like every other value, so a service
/// selection cannot smuggle in a second command.
pub fn run_args_with_labels(
    spec: &ServiceSpec,
    labels: &[(String, String)],
) -> Result<Vec<String>> {
    check_value("service name", &spec.name)?;
    check_value("image", &spec.image)?;
    check_hardening(spec)?;
    let h = &spec.hardening;
    let mut a = vec!["--name".to_owned(), spec.name.clone()];
    for (k, v) in labels {
        check_value("label name", k)?;
        check_value("label value", v)?;
        a.extend(["--label".to_owned(), format!("{k}={v}")]);
    }
    for n in &spec.networks {
        check_value("network", n)?;
        a.extend(["--network".to_owned(), n.clone()]);
    }
    for (host, target) in &spec.mounts {
        check_value("mount source", host)?;
        check_value("mount target", target)?;
        a.extend(["--volume".to_owned(), format!("{host}:{target}")]);
    }
    for (k, v) in &spec.env {
        check_value("env name", k)?;
        check_value("env value", v)?;
        a.extend(["--env".to_owned(), format!("{k}={v}")]);
    }
    if h.read_only {
        a.push("--read-only".to_owned());
    }
    for t in &h.tmpfs {
        a.extend(["--tmpfs".to_owned(), t.clone()]);
    }
    if h.drop_all_capabilities {
        a.push("--cap-drop=ALL".to_owned());
    }
    if h.no_new_privileges {
        a.push("--security-opt=no-new-privileges".to_owned());
    }
    if let Some(m) = &h.memory {
        a.push(format!("--memory={m}"));
        a.push(format!("--memory-swap={m}"));
    }
    if let Some(p) = h.pids_limit {
        a.push(format!("--pids-limit={p}"));
    }
    a.push(spec.image.clone());
    for arg in &spec.args {
        check_value("argument", arg)?;
        a.push(arg.clone());
    }
    Ok(a)
}

/// Quadlet files for the service: `<name>.container` + `.network` for each network.
pub fn render(spec: &ServiceSpec) -> Result<Vec<UnitFile>> {
    render_with_labels(spec, &[])
}

/// [`render`] plus container labels (`Label=` in the quadlet).
pub fn render_with_labels(
    spec: &ServiceSpec,
    labels: &[(String, String)],
) -> Result<Vec<UnitFile>> {
    check_value("service name", &spec.name)?;
    check_value("image", &spec.image)?;
    check_hardening(spec)?;
    let h = &spec.hardening;
    let mut c = String::new();
    c.push_str("# Generated by weglarka — do not edit.\n[Unit]\n");
    let _ = writeln!(c, "Description=Węglarka ({})", spec.name);
    c.push_str("After=network-online.target\nWants=network-online.target\n\n[Container]\n");
    let _ = writeln!(c, "Image={}", spec.image);
    let _ = writeln!(c, "ContainerName={}", spec.name);
    for (k, v) in labels {
        check_value("label name", k)?;
        check_value("label value", v)?;
        let _ = writeln!(c, "Label={k}={v}");
    }
    for n in &spec.networks {
        check_value("network", n)?;
        let _ = writeln!(c, "Network={n}.network");
    }
    for (host, target) in &spec.mounts {
        check_value("mount source", host)?;
        check_value("mount target", target)?;
        let _ = writeln!(c, "Volume={host}:{target}");
    }
    for (k, v) in &spec.env {
        check_value("env name", k)?;
        check_value("env value", v)?;
        let _ = writeln!(c, "Environment={k}={v}");
    }
    if h.read_only {
        c.push_str("ReadOnly=true\n");
    }
    for t in &h.tmpfs {
        let _ = writeln!(c, "Tmpfs={t}");
    }
    if h.drop_all_capabilities {
        c.push_str("DropCapability=ALL\n");
    }
    if h.no_new_privileges {
        c.push_str("NoNewPrivileges=true\n");
    }
    if let Some(m) = &h.memory {
        // Not every quadlet version has a memory-limit key; swap = limit, because the host swaps heavily.
        let _ = writeln!(c, "PodmanArgs=--memory={m} --memory-swap={m}");
    }
    if let Some(p) = h.pids_limit {
        let _ = writeln!(c, "PidsLimit={p}");
    }
    if !spec.args.is_empty() {
        let mut quoted = Vec::new();
        for a in &spec.args {
            check_value("argument", a)?;
            quoted.push(if a.contains(char::is_whitespace) {
                format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                a.clone()
            });
        }
        let _ = writeln!(c, "Exec={}", quoted.join(" "));
    }
    c.push_str(
        "\n[Service]\nRestart=always\nTimeoutStopSec=70\n\n[Install]\nWantedBy=default.target\n",
    );

    let mut files = vec![UnitFile {
        file_name: format!("{}.container", spec.name),
        content: c,
    }];
    for n in &spec.networks {
        files.push(UnitFile {
            file_name: format!("{n}.network"),
            content: format!(
                "# Generated by weglarka — do not edit.\n[Network]\nNetworkName={n}\n"
            ),
        });
    }
    Ok(files)
}

/// Name of the user timer that wakes the self-update switcher (issue #99).
pub const SELF_UPDATE_TIMER: &str = "weglarka-self-update.timer";
/// Name of the oneshot service the timer runs.
pub const SELF_UPDATE_SERVICE: &str = "weglarka-self-update.service";
/// How often the timer wakes the switcher. `[self_update] interval_secs` decides whether a wake-up
/// really checks the registry, so this only bounds how late an update can be noticed; changing it
/// does not require touching the configuration.
pub const SELF_UPDATE_WAKE: &str = "10min";

/// A quoted systemd argument: paths with spaces have to survive `ExecStart`.
fn quote_argument(a: &str) -> String {
    if a.contains(char::is_whitespace) {
        format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        a.to_owned()
    }
}

/// The user units of the host-side self-updater: `weglarka-self-update.service` (oneshot, runs
/// `weglarka-daemon self-update`) and the timer that starts it. Rendered from the running binary and
/// the configuration file, so the installed unit keeps pointing at what `platform install` used.
pub fn render_self_update_units(binary: &Path, config: &Path) -> Result<Vec<UnitFile>> {
    let binary = binary.display().to_string();
    let config = config.display().to_string();
    check_value("self-update binary", &binary)?;
    check_value("self-update config", &config)?;
    let mut service = String::new();
    service.push_str("# Generated by weglarka — do not edit.\n[Unit]\n");
    service.push_str("Description=Węglarka self-update check\n");
    service.push_str("After=network-online.target\nWants=network-online.target\n\n[Service]\n");
    service.push_str("Type=oneshot\n");
    let _ = writeln!(
        service,
        "ExecStart={} --config {} self-update",
        quote_argument(&binary),
        quote_argument(&config)
    );
    let mut timer = String::new();
    timer.push_str("# Generated by weglarka — do not edit.\n[Unit]\n");
    timer.push_str("Description=Węglarka self-update check timer\n\n[Timer]\n");
    timer.push_str("OnBootSec=5min\n");
    let _ = writeln!(timer, "OnUnitActiveSec={SELF_UPDATE_WAKE}");
    timer.push_str("Persistent=true\n\n[Install]\nWantedBy=timers.target\n");
    Ok(vec![
        UnitFile {
            file_name: SELF_UPDATE_SERVICE.to_owned(),
            content: service,
        },
        UnitFile {
            file_name: SELF_UPDATE_TIMER.to_owned(),
            content: timer,
        },
    ])
}

/// Name of the user timer that wakes the self-update watchdog (issue #100).
pub const WATCHDOG_TIMER: &str = "weglarka-watchdog.timer";
/// Name of the oneshot service the watchdog timer runs.
pub const WATCHDOG_SERVICE: &str = "weglarka-watchdog.service";
/// How often the watchdog checks a switch in flight. The fallback deadline is in seconds; a minute is
/// the price of not running a permanent host-side process, and the switch itself is still noticed
/// immediately by the switcher's own run.
pub const WATCHDOG_WAKE: &str = "1min";

/// The user units of the self-update watchdog (issue #100, `docs/decisions/0034`): a oneshot that runs
/// `weglarka-daemon supervise` and a timer that wakes it every minute (and once a minute after boot,
/// so a switch left pending by a reboot is handled).
pub fn render_watchdog_units(binary: &Path, config: &Path) -> Result<Vec<UnitFile>> {
    let binary = binary.display().to_string();
    let config = config.display().to_string();
    check_value("watchdog binary", &binary)?;
    check_value("watchdog config", &config)?;
    let mut service = String::new();
    service.push_str("# Generated by weglarka — do not edit.\n[Unit]\n");
    service.push_str("Description=Węglarka self-update watchdog\n\n[Service]\n");
    service.push_str("Type=oneshot\n");
    // The fallback restarts the service (waiting for its graceful stop) on top of the probe, so the
    // oneshot needs more than the default start timeout.
    service.push_str("TimeoutStartSec=2min\n");
    let _ = writeln!(
        service,
        "ExecStart={} --config {} supervise",
        quote_argument(&binary),
        quote_argument(&config)
    );
    let mut timer = String::new();
    timer.push_str("# Generated by weglarka — do not edit.\n[Unit]\n");
    timer.push_str("Description=Węglarka self-update watchdog timer\n\n[Timer]\n");
    timer.push_str("OnBootSec=1min\n");
    let _ = writeln!(timer, "OnUnitActiveSec={WATCHDOG_WAKE}");
    // The deadline is measured in seconds; do not let systemd coalesce the wake-ups by a minute.
    timer.push_str("AccuracySec=10s\n\n[Install]\nWantedBy=timers.target\n");
    Ok(vec![
        UnitFile {
            file_name: WATCHDOG_SERVICE.to_owned(),
            content: service,
        },
        UnitFile {
            file_name: WATCHDOG_TIMER.to_owned(),
            content: timer,
        },
    ])
}

/// Launcher job units for the systemd adapter. The handing-off worker runs with
/// `TimeoutStartSec=infinity`: the launcher enforces its own bounded worker timeout, and systemd
/// must not kill the unit at the default start timeout.
pub fn render_job_units(host_dir: &Path, jobs: &[ScheduledJob]) -> Result<Vec<UnitFile>> {
    let launcher = host_dir
        .join(weglarka_launcher::host::LAUNCHER_FILE)
        .display()
        .to_string();
    check_value("launcher path", &launcher)?;
    let mut files = Vec::new();
    for job in jobs {
        let (service_name, timer_name) = job_unit_names(job.id);
        let mut service = String::new();
        service.push_str("# Generated by weglarka — do not edit.\n[Unit]\n");
        let _ = writeln!(
            service,
            "Description=Węglarka platform {} job",
            job.id.as_str()
        );
        service.push_str("After=network-online.target\nWants=network-online.target\n\n[Service]\n");
        service.push_str("Type=oneshot\n");
        // The launcher is the parent and owns the bounded worker timeout.
        service.push_str("TimeoutStartSec=infinity\n");
        let mut command = quote_argument(&launcher);
        for arg in &job.args {
            check_value("job argument", arg)?;
            command.push(' ');
            command.push_str(&quote_argument(arg));
        }
        let _ = writeln!(service, "ExecStart={command}");
        files.push(UnitFile {
            file_name: service_name.to_owned(),
            content: service,
        });

        let mut timer = String::new();
        timer.push_str("# Generated by weglarka — do not edit.\n[Unit]\n");
        let _ = writeln!(
            timer,
            "Description=Węglarka platform {} timer",
            job.id.as_str()
        );
        timer.push_str("\n[Timer]\nOnBootSec=1min\n");
        let _ = writeln!(timer, "OnUnitActiveSec={}s", job.cadence_secs);
        timer.push_str("AccuracySec=10s\n\n[Install]\nWantedBy=timers.target\n");
        files.push(UnitFile {
            file_name: timer_name.to_owned(),
            content: timer,
        });
    }
    Ok(files)
}

/// Unit names of a launcher job.
pub fn job_unit_names(id: JobId) -> (&'static str, &'static str) {
    match id {
        JobId::Update => (
            "weglarka-platform-update.service",
            "weglarka-platform-update.timer",
        ),
        JobId::Watchdog => (
            "weglarka-platform-watchdog.service",
            "weglarka-platform-watchdog.timer",
        ),
    }
}

impl<R: CommandRunner> SystemdPlatform<R> {
    pub fn with_runner(user: impl Into<String>, runner: R) -> Self {
        Self {
            user: user.into(),
            passwd: PathBuf::from("/etc/passwd"),
            quadlet_dir: None,
            units_dir: None,
            host_dir: PathBuf::from(DEFAULT_HOST_DIR),
            state_dir: None,
            runuser: None,
            runner,
        }
    }

    pub fn with_passwd(mut self, passwd: impl Into<PathBuf>) -> Self {
        self.passwd = passwd.into();
        self
    }

    pub fn with_quadlet_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.quadlet_dir = Some(dir.into());
        self
    }

    pub fn with_units_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.units_dir = Some(dir.into());
        self
    }

    pub fn with_host_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.host_dir = dir.into();
        self
    }

    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Bootstrap as root: manage the runtime user's manager through `runuser`.
    pub fn with_runuser(mut self, user: impl Into<String>) -> Self {
        self.runuser = Some(user.into());
        self
    }

    pub fn host_dir(&self) -> &Path {
        &self.host_dir
    }

    fn quadlet_dir(&self, entry: &PasswdEntry) -> PathBuf {
        self.quadlet_dir
            .clone()
            .unwrap_or_else(|| entry.home.join(".config/containers/systemd"))
    }

    /// Where plain user units live (the quadlet directory is separate).
    fn units_dir(&self, entry: &PasswdEntry) -> PathBuf {
        self.units_dir
            .clone()
            .unwrap_or_else(|| entry.home.join(".config/systemd/user"))
    }

    async fn systemctl(&self, entry: &PasswdEntry, args: &[&str]) -> Result<(bool, String)> {
        let runtime_dir = format!("/run/user/{}", entry.uid);
        let env = [
            ("XDG_RUNTIME_DIR".to_owned(), runtime_dir.clone()),
            (
                "DBUS_SESSION_BUS_ADDRESS".to_owned(),
                format!("unix:path={runtime_dir}/bus"),
            ),
        ];
        let mut full = vec!["--user".to_owned()];
        full.extend(args.iter().map(|a| (*a).to_owned()));
        if let Some(user) = &self.runuser {
            // Bootstrap runs as root; a user timer still belongs to the runtime user's manager.
            let mut command = vec![
                "-u".to_owned(),
                user.clone(),
                "--".to_owned(),
                "env".to_owned(),
            ];
            command.extend(env.iter().map(|(k, v)| format!("{k}={v}")));
            command.push("systemctl".to_owned());
            command.extend(full);
            self.runner
                .run("runuser", &command, &env)
                .await
                .map_err(|e| PlatformError::Command(format!("runuser systemctl: {e}")))
        } else {
            self.runner
                .run("systemctl", &full, &env)
                .await
                .map_err(|e| PlatformError::Command(format!("systemctl: {e}")))
        }
    }

    /// Installation runs as the runtime user (the owner of the quadlet directory).
    fn entry(&self) -> Result<PasswdEntry> {
        lookup(&self.passwd, &self.user)
    }
}

impl<R: CommandRunner> Platform for SystemdPlatform<R> {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Systemd
    }

    async fn runtime_socket(&self, runtime_user: &str) -> Result<PathBuf> {
        let entry = lookup(&self.passwd, runtime_user)?;
        Ok(PathBuf::from(format!(
            "/run/user/{}/podman/podman.sock",
            entry.uid
        )))
    }

    async fn install_service(&self, spec: &ServiceSpec) -> Result<()> {
        if spec.run_as_user != self.user {
            return Err(PlatformError::Command(format!(
                "service user {:?} differs from the platform user {:?}",
                spec.run_as_user, self.user
            )));
        }
        let entry = self.entry()?;
        let files = render(spec)?;
        let dir = self.quadlet_dir(&entry);
        std::fs::create_dir_all(&dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", dir.display())))?;
        for f in files {
            let path = dir.join(&f.file_name);
            std::fs::write(&path, f.content)
                .map_err(|e| PlatformError::Io(format!("{}: {e}", path.display())))?;
        }
        let (ok, _) = self.systemctl(&entry, &["daemon-reload"]).await?;
        if ok {
            Ok(())
        } else {
            Err(PlatformError::Command(
                "systemctl --user daemon-reload failed".into(),
            ))
        }
    }

    async fn remove_service(&self, name: &str) -> Result<()> {
        let entry = self.entry()?;
        let path = self.quadlet_dir(&entry).join(format!("{name}.container"));
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(PlatformError::Io(format!("{}: {e}", path.display()))),
        }
        // The `.network` files stay (they may be shared); the operator cleans them up.
        self.systemctl(&entry, &["daemon-reload"]).await.map(drop)
    }

    async fn service_status(&self, name: &str) -> Result<ServiceStatus> {
        let entry = self.entry()?;
        if !self
            .quadlet_dir(&entry)
            .join(format!("{name}.container"))
            .exists()
        {
            return Ok(ServiceStatus::NotInstalled);
        }
        let (_, out) = self
            .systemctl(&entry, &["is-active", &format!("{name}.service")])
            .await?;
        Ok(match out.as_str() {
            "active" | "activating" | "reloading" => ServiceStatus::Active,
            "failed" => ServiceStatus::Failed,
            _ => ServiceStatus::Inactive,
        })
    }

    async fn install_user_units(&self, files: &[UnitFile]) -> Result<()> {
        let entry = self.entry()?;
        let dir = self.units_dir(&entry);
        std::fs::create_dir_all(&dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", dir.display())))?;
        for f in files {
            check_value("unit name", &f.file_name)?;
            let path = dir.join(&f.file_name);
            std::fs::write(&path, &f.content)
                .map_err(|e| PlatformError::Io(format!("{}: {e}", path.display())))?;
        }
        let (ok, _) = self.systemctl(&entry, &["daemon-reload"]).await?;
        if ok {
            Ok(())
        } else {
            Err(PlatformError::Command(
                "systemctl --user daemon-reload failed".into(),
            ))
        }
    }

    async fn remove_user_units(&self, names: &[&str]) -> Result<()> {
        let entry = self.entry()?;
        let dir = self.units_dir(&entry);
        for name in names {
            check_value("unit name", name)?;
            let path = dir.join(name);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(PlatformError::Io(format!("{}: {e}", path.display()))),
            }
        }
        self.systemctl(&entry, &["daemon-reload"]).await.map(drop)
    }

    async fn restart_service(&self, name: &str) -> Result<()> {
        check_value("service name", name)?;
        let entry = self.entry()?;
        let unit = format!("{name}.service");
        let (ok, _) = self.systemctl(&entry, &["restart", &unit]).await?;
        if ok {
            Ok(())
        } else {
            Err(PlatformError::Command(format!(
                "systemctl --user restart {unit} failed"
            )))
        }
    }

    /// `systemctl --user reset-failed <name>.service`: the automatic fallback restarts an image whose
    /// predecessor crash-looped, and such a unit has exhausted its start limit (issue #100).
    async fn reset_failed(&self, name: &str) -> Result<()> {
        check_value("service name", name)?;
        let entry = self.entry()?;
        let unit = format!("{name}.service");
        let (ok, _) = self.systemctl(&entry, &["reset-failed", &unit]).await?;
        if ok {
            Ok(())
        } else {
            Err(PlatformError::Command(format!(
                "systemctl --user reset-failed {unit} failed"
            )))
        }
    }

    async fn set_timer(&self, name: &str, enabled: bool) -> Result<()> {
        check_value("timer name", name)?;
        let entry = self.entry()?;
        let (ok, _) = if enabled {
            self.systemctl(&entry, &["enable", "--now", name]).await?
        } else {
            self.systemctl(&entry, &["disable", "--now", name]).await?
        };
        if ok {
            Ok(())
        } else {
            Err(PlatformError::Command(format!(
                "systemctl --user {} {name} failed",
                if enabled { "enable" } else { "disable" }
            )))
        }
    }
    async fn install_jobs(&self, jobs: &[ScheduledJob]) -> Result<()> {
        let files = render_job_units(&self.host_dir, jobs)?;
        self.install_user_units(&files).await?;
        for job in jobs {
            let (_, timer) = job_unit_names(job.id);
            self.set_timer(timer, true).await?;
        }
        Ok(())
    }

    async fn set_job_enabled(&self, id: JobId, enabled: bool) -> Result<()> {
        let state_dir = self
            .state_dir
            .as_ref()
            .ok_or(PlatformError::NotImplemented(
                "set_job_enabled without a shared state directory",
            ))?;
        let job = match id {
            JobId::Update => Job::Update,
            JobId::Watchdog => Job::Watchdog,
        };
        RuntimeJobs::set_enabled(state_dir, job, enabled)
            .map_err(|e| PlatformError::Io(format!("runtime-jobs.toml: {e}")))
    }

    /// Persists the desired digest/epoch, renders the quadlet for that immutable spec, installs it
    /// atomically, reloads the user manager and requests a restart. The receipt is not readiness.
    async fn activate_service(
        &self,
        spec: ServiceSpec,
        epoch: ActivationEpoch,
    ) -> Result<ActivationReceipt> {
        let (_, digest) = pinned_digest(&spec.image)?;
        let labels = activation_labels(epoch, &digest);
        let argv = run_args_with_labels(&spec, &labels)?;
        let selection =
            PlatformService::build(spec.name.clone(), spec.image.clone(), digest, epoch.0, argv)
                .map_err(|e| PlatformError::Command(format!("service selection: {e}")))?;
        // Persist the intent first: if the restart fails, the next worker observes the actual
        // container and retries against the same intended activation.
        PlatformService::write_locked(&self.host_dir, &selection)
            .map_err(|e| PlatformError::Io(format!("platform-service.toml: {e}")))?;

        let files = render_with_labels(&spec, &labels)?;
        let entry = self.entry()?;
        let dir = self.quadlet_dir(&entry);
        std::fs::create_dir_all(&dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", dir.display())))?;
        for f in files {
            let path = dir.join(&f.file_name);
            weglarka_model::fsutil::write_atomic(&path, f.content.as_bytes(), 0o644)
                .map_err(|e| PlatformError::Io(format!("{}: {e}", path.display())))?;
        }
        let (ok, _) = self.systemctl(&entry, &["daemon-reload"]).await?;
        if !ok {
            return Err(PlatformError::Command(
                "systemctl --user daemon-reload failed".into(),
            ));
        }
        self.restart_service(&spec.name).await?;
        Ok(ActivationReceipt { epoch })
    }

    /// Observes the actual container and reports its digest, epoch and readiness. A healthy old
    /// container is not success.
    async fn observe_service(&self, name: ServiceName) -> Result<ObservedService> {
        let entry = self.entry()?;
        let name = name.as_str().to_owned();
        let format = "{{.Id}}|{{.State.Running}}|{{.Image}}|{{.Config.Image}}|\
                      {{index .Config.Labels \"io.weglarka.activation-epoch\"}}";
        let (ok, out) = self
            .podman(
                &entry,
                &[
                    "inspect".to_owned(),
                    "--type".to_owned(),
                    "container".to_owned(),
                    "--format".to_owned(),
                    format.to_owned(),
                    name.clone(),
                ],
            )
            .await?;
        if !ok {
            return Ok(ObservedService {
                name: ServiceName::new(name)?,
                container_id: None,
                image_id: None,
                digest: None,
                activation_epoch: None,
                ready: Some(false),
            });
        }
        let mut parts = out.split('|');
        let container_id = parts.next().unwrap_or_default().trim().to_owned();
        let running = parts.next().unwrap_or_default().trim() == "true";
        let image_id = parts.next().unwrap_or_default().trim().to_owned();
        let config_image = parts.next().unwrap_or_default().trim().to_owned();
        let activation_epoch = parts
            .next()
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .ok()
            .map(ActivationEpoch);

        let mut digest = None;
        if !image_id.is_empty() {
            let (ok, out) = self
                .podman(
                    &entry,
                    &[
                        "inspect".to_owned(),
                        "--type".to_owned(),
                        "image".to_owned(),
                        "--format".to_owned(),
                        "{{.Digest}}".to_owned(),
                        image_id.clone(),
                    ],
                )
                .await?;
            if ok {
                digest = Digest::new(out.trim().to_owned()).ok();
            }
        }
        if digest.is_none()
            && let Some((_, value)) = config_image.rsplit_once('@')
        {
            digest = Digest::new(value.to_owned()).ok();
        }
        let (active, _) = self
            .systemctl(&entry, &["is-active", &format!("{name}.service")])
            .await?;
        Ok(ObservedService {
            name: ServiceName::new(name)?,
            container_id: (!container_id.is_empty()).then_some(container_id),
            image_id: (!image_id.is_empty()).then_some(image_id),
            digest,
            activation_epoch,
            ready: Some(active && running),
        })
    }
}

/// Splits a pinned `repository@sha256:…` reference.
pub(crate) fn pinned_digest(
    image: &str,
) -> Result<(String, weglarka_model::release_set::StrictDigest)> {
    let (repository, digest) = image.rsplit_once('@').ok_or_else(|| {
        PlatformError::Command(format!("image {image:?} is not pinned by digest"))
    })?;
    if repository.is_empty() {
        return Err(PlatformError::Command(format!(
            "image {image:?} has no repository"
        )));
    }
    let digest = weglarka_model::release_set::StrictDigest::new(digest.to_owned())
        .map_err(|e| PlatformError::Command(format!("image {image:?}: {e}")))?;
    Ok((repository.to_owned(), digest))
}

pub(crate) fn activation_labels(
    epoch: ActivationEpoch,
    digest: &weglarka_model::release_set::StrictDigest,
) -> Vec<(String, String)> {
    vec![
        (LABEL_ACTIVATION_EPOCH.to_owned(), epoch.0.to_string()),
        (LABEL_DAEMON_DIGEST.to_owned(), digest.as_str().to_owned()),
    ]
}

impl<R: CommandRunner> SystemdPlatform<R> {
    /// Runs `podman` as the runtime user (through `runuser` when bootstrap is root).
    async fn podman(&self, entry: &PasswdEntry, args: &[String]) -> Result<(bool, String)> {
        let runtime_dir = format!("/run/user/{}", entry.uid);
        let env = [
            ("XDG_RUNTIME_DIR".to_owned(), runtime_dir.clone()),
            (
                "DBUS_SESSION_BUS_ADDRESS".to_owned(),
                format!("unix:path={runtime_dir}/bus"),
            ),
        ];
        if let Some(user) = &self.runuser {
            let mut command = vec![
                "-u".to_owned(),
                user.clone(),
                "--".to_owned(),
                "env".to_owned(),
            ];
            command.extend(env.iter().map(|(k, v)| format!("{k}={v}")));
            command.push("podman".to_owned());
            command.extend(args.iter().cloned());
            self.runner
                .run("runuser", &command, &[])
                .await
                .map_err(|e| PlatformError::Command(format!("runuser podman: {e}")))
        } else {
            self.runner
                .run("podman", args, &env)
                .await
                .map_err(|e| PlatformError::Command(format!("podman: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::SERVICE_NAME;
    use weglarka_engine::platform::Hardening;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            name: "weglarka".into(),
            image: "ghcr.io/jpalczewski/weglarka:latest".into(),
            run_as_user: "weglarka".into(),
            env: vec![("RUST_LOG".into(), "info".into())],
            mounts: vec![
                (
                    "/run/user/1001/podman/podman.sock".into(),
                    "/run/user/1001/podman/podman.sock".into(),
                ),
                (
                    "/etc/weglarka/weglarka.toml".into(),
                    "/etc/weglarka/weglarka.toml:ro".into(),
                ),
            ],
            networks: vec!["net-weglarka".into()],
            args: vec![
                "run".into(),
                "--config".into(),
                "/etc/weglarka/weglarka.toml".into(),
            ],
            hardening: Hardening {
                memory: Some("128M".into()),
                pids_limit: Some(256),
                ..Hardening::default()
            },
        }
    }

    #[test]
    fn run_args_snapshot() {
        insta::assert_snapshot!(run_args(&spec()).unwrap().join("\n"));
    }

    #[test]
    fn rejects_bad_memory() {
        for bad in ["", "M", "12 M", "1x", "128MBB", "1\nM"] {
            let mut s = spec();
            s.hardening.memory = Some(bad.into());
            assert!(render(&s).is_err() && run_args(&s).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn quadlet_snapshot() {
        let files = render(&spec()).unwrap();
        let text: String = files
            .iter()
            .map(|f| format!("=== {} ===\n{}", f.file_name, f.content))
            .collect();
        insta::assert_snapshot!(text);
    }

    #[test]
    fn rejects_injection() {
        let mut s = spec();
        s.env.push(("A".into(), "x\nExecStartPre=/bin/sh".into()));
        assert!(render(&s).is_err());
    }

    struct Fake(&'static str);
    impl CommandRunner for Fake {
        async fn run(
            &self,
            _: &str,
            args: &[String],
            _: &[(String, String)],
        ) -> io::Result<(bool, String)> {
            Ok((
                true,
                if args.iter().any(|a| a == "is-active") {
                    self.0.into()
                } else {
                    String::new()
                },
            ))
        }
    }

    #[tokio::test]
    async fn install_writes_files_and_resolves_socket() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/sh\nweglarka:x:1001:1001::/home/weglarka:/bin/sh\n",
        )
        .unwrap();
        let quadlets = dir.path().join("q");
        let p = SystemdPlatform::with_runner("weglarka", Fake("active"))
            .with_passwd(&passwd)
            .with_quadlet_dir(&quadlets);
        assert_eq!(
            p.runtime_socket("weglarka").await.unwrap(),
            Path::new("/run/user/1001/podman/podman.sock")
        );
        assert!(p.runtime_socket("nobody").await.is_err());
        assert_eq!(
            p.service_status("weglarka").await.unwrap(),
            ServiceStatus::NotInstalled
        );
        p.install_service(&spec()).await.unwrap();
        assert!(quadlets.join("weglarka.container").exists());
        assert!(quadlets.join("net-weglarka.network").exists());
        assert_eq!(
            p.service_status("weglarka").await.unwrap(),
            ServiceStatus::Active
        );
        p.remove_service("weglarka").await.unwrap();
        assert!(!quadlets.join("weglarka.container").exists());
    }

    #[test]
    fn self_update_units_snapshot() {
        let files = render_self_update_units(
            Path::new("/usr/local/bin/weglarka-daemon"),
            Path::new("/etc/weglarka/weglarka.toml"),
        )
        .unwrap();
        let text: String = files
            .iter()
            .map(|f| format!("=== {} ===\n{}", f.file_name, f.content))
            .collect();
        insta::assert_snapshot!(text);
    }

    #[test]
    fn watchdog_units_snapshot() {
        let files = render_watchdog_units(
            Path::new("/usr/local/bin/weglarka-daemon"),
            Path::new("/etc/weglarka/weglarka.toml"),
        )
        .unwrap();
        let text: String = files
            .iter()
            .map(|f| format!("=== {} ===\n{}", f.file_name, f.content))
            .collect();
        insta::assert_snapshot!(text);
    }

    #[tokio::test]
    async fn reset_failed_clears_the_service_failure_state() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/sh\nweglarka:x:1001:1001::/home/weglarka:/bin/sh\n",
        )
        .unwrap();
        let p = SystemdPlatform::with_runner("weglarka", Recorder::default())
            .with_passwd(&passwd)
            .with_quadlet_dir(dir.path().join("q"))
            .with_units_dir(dir.path().join("units"));
        p.reset_failed(SERVICE_NAME).await.unwrap();
        let calls = p.runner.calls();
        assert!(
            calls
                .iter()
                .any(|c| c == "systemctl reset-failed weglarka.service"),
            "{calls:?}"
        );
    }

    #[test]
    fn self_update_units_quote_paths_with_spaces() {
        let files = render_self_update_units(
            Path::new("/opt/my bin/weglarka-daemon"),
            Path::new("/etc/weglarka/weglarka.toml"),
        )
        .unwrap();
        let service = &files[0];
        assert_eq!(service.file_name, SELF_UPDATE_SERVICE);
        assert!(
            service
                .content
                .contains("ExecStart=\"/opt/my bin/weglarka-daemon\" --config "),
            "{}",
            service.content
        );
        assert_eq!(files[1].file_name, SELF_UPDATE_TIMER);
        assert!(
            files[1].content.contains("OnUnitActiveSec="),
            "{}",
            files[1].content
        );
    }

    /// Records `systemctl` invocations (`--user` stripped) so the tests can assert the exact commands.
    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<String>>);

    impl Recorder {
        fn calls(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    impl CommandRunner for Recorder {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _: &[(String, String)],
        ) -> io::Result<(bool, String)> {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let args = args.strip_prefix(&["--user"][..]).unwrap_or(&args);
            self.0
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            Ok((true, String::new()))
        }
    }

    struct InspectRunner {
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl InspectRunner {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for InspectRunner {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _: &[(String, String)],
        ) -> io::Result<(bool, String)> {
            let joined = args.join(" ");
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {joined}"));
            let out = if joined.contains("inspect --type container") {
                format!(
                    "abc|true|imgid|ghcr.io/example/weglarka@sha256:{}|5",
                    "a".repeat(64)
                )
            } else if joined.contains("inspect --type image") {
                format!("sha256:{}", "a".repeat(64))
            } else if joined.contains("is-active") {
                "active".to_owned()
            } else {
                String::new()
            };
            Ok((true, out))
        }
    }

    fn pinned_spec() -> ServiceSpec {
        let mut spec = spec();
        spec.image = format!("ghcr.io/jpalczewski/weglarka@sha256:{}", "a".repeat(64));
        spec
    }

    #[tokio::test]
    async fn activation_persists_the_selection_and_renders_labels_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/sh\nweglarka:x:1001:1001::/home/weglarka:/bin/sh\n",
        )
        .unwrap();
        let quadlets = dir.path().join("q");
        let host = dir.path().join("host");
        let p = SystemdPlatform::with_runner(
            "weglarka",
            InspectRunner {
                calls: std::sync::Mutex::new(Vec::new()),
            },
        )
        .with_passwd(&passwd)
        .with_quadlet_dir(&quadlets)
        .with_units_dir(dir.path().join("units"))
        .with_host_dir(&host)
        .with_state_dir(dir.path().join("state"));

        let receipt = p
            .activate_service(pinned_spec(), ActivationEpoch(5))
            .await
            .unwrap();
        assert_eq!(receipt.epoch, ActivationEpoch(5));
        let selection = weglarka_launcher::selection::PlatformService::load(&host)
            .unwrap()
            .unwrap();
        assert_eq!(selection.epoch, 5);
        assert!(
            selection
                .argv
                .iter()
                .any(|a| a == "io.weglarka.activation-epoch=5")
        );
        let quadlet = std::fs::read_to_string(quadlets.join("weglarka.container")).unwrap();
        assert!(
            quadlet.contains("Label=io.weglarka.activation-epoch=5"),
            "{quadlet}"
        );
        assert!(
            p.runner
                .calls()
                .iter()
                .any(|c| c.ends_with("restart weglarka.service")),
            "{:?}",
            p.runner.calls()
        );

        let observed = p
            .observe_service(ServiceName::new("weglarka").unwrap())
            .await
            .unwrap();
        assert_eq!(observed.container_id.as_deref(), Some("abc"));
        assert_eq!(observed.activation_epoch, Some(ActivationEpoch(5)));
        assert_eq!(observed.ready, Some(true));
    }

    #[tokio::test]
    async fn launcher_jobs_are_handoff_safe_and_toggle_only_the_runtime_flag() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/sh\nweglarka:x:1001:1001::/home/weglarka:/bin/sh\n",
        )
        .unwrap();
        let units = dir.path().join("units");
        let state = dir.path().join("state");
        let p = SystemdPlatform::with_runner("weglarka", Recorder::default())
            .with_passwd(&passwd)
            .with_quadlet_dir(dir.path().join("q"))
            .with_units_dir(&units)
            .with_host_dir(dir.path().join("host"))
            .with_state_dir(&state);
        let jobs = [
            ScheduledJob {
                id: weglarka_engine::platform::JobId::Update,
                args: vec![
                    "--host-dir".into(),
                    "/var/lib/weglarka-host".into(),
                    "update".into(),
                ],
                runtime_user: "weglarka".into(),
                cadence_secs: 3600,
                skip_if_running: true,
            },
            ScheduledJob {
                id: weglarka_engine::platform::JobId::Watchdog,
                args: vec!["supervise".into()],
                runtime_user: "weglarka".into(),
                cadence_secs: 60,
                skip_if_running: true,
            },
        ];
        p.install_jobs(&jobs).await.unwrap();
        let service =
            std::fs::read_to_string(units.join("weglarka-platform-update.service")).unwrap();
        assert!(service.contains("TimeoutStartSec=infinity"), "{service}");
        assert!(service.contains("weglarka-launcher"), "{service}");
        assert!(
            p.runner
                .calls()
                .iter()
                .any(|c| c == "systemctl enable --now weglarka-platform-update.timer"),
            "{:?}",
            p.runner.calls()
        );
        p.set_job_enabled(weglarka_engine::platform::JobId::Update, false)
            .await
            .unwrap();
        let jobs = weglarka_launcher::selection::RuntimeJobs::load(&state).unwrap();
        assert!(!jobs.update);
        assert!(jobs.watchdog);
    }

    #[tokio::test]
    async fn user_units_are_written_and_the_timer_is_enabled_disabled_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let passwd = dir.path().join("passwd");
        std::fs::write(
            &passwd,
            "root:x:0:0::/root:/bin/sh\nweglarka:x:1001:1001::/home/weglarka:/bin/sh\n",
        )
        .unwrap();
        let units = dir.path().join("units");
        let p = SystemdPlatform::with_runner("weglarka", Recorder::default())
            .with_passwd(&passwd)
            .with_quadlet_dir(dir.path().join("q"))
            .with_units_dir(&units);

        let files = render_self_update_units(
            Path::new("/usr/local/bin/weglarka-daemon"),
            Path::new("/etc/weglarka/weglarka.toml"),
        )
        .unwrap();
        p.install_user_units(&files).await.unwrap();
        assert!(units.join(SELF_UPDATE_SERVICE).exists());
        assert!(units.join(SELF_UPDATE_TIMER).exists());
        p.set_timer(SELF_UPDATE_TIMER, true).await.unwrap();
        p.restart_service(SERVICE_NAME).await.unwrap();
        p.remove_user_units(&[SELF_UPDATE_SERVICE, SELF_UPDATE_TIMER])
            .await
            .unwrap();
        assert!(!units.join(SELF_UPDATE_TIMER).exists());
        p.set_timer(SELF_UPDATE_TIMER, false).await.unwrap();

        let calls = p.runner.calls();
        assert!(
            calls.iter().any(|c| c == "systemctl daemon-reload"),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "systemctl enable --now weglarka-self-update.timer"),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "systemctl restart weglarka.service"),
            "{calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c == "systemctl disable --now weglarka-self-update.timer"),
            "{calls:?}"
        );
    }
}
