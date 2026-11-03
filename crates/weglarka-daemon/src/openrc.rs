//! `Platform` for Alpine/OpenRC: three root-owned services plus a runtime-user cron facility.
//!
//! Installation is the only privileged step. The installed init scripts are root-owned and contain
//! fixed, validated literals; the daemon service runs the launcher as the runtime user through
//! `supervise-daemon` with `command_user`. The launcher then starts the rootless container directly.
//! No user-owned script is ever executed as root, and a service-definition change remains an
//! explicit administrator task.
//!
//! Activation writes `platform-service.toml` (host-only, immutable argv) and stops the observed
//! container **by ID** only when its epoch matches the request. The foreground runner exits and
//! supervision starts it again with the new selection. `respawn_max=0` keeps the service usable when
//! the container crash-loops; the launcher's own per-epoch budget records the blocked state and waits
//! for a new selection instead of needing root to revive the service.

use std::io;
use std::path::{Path, PathBuf};

use weglarka_engine::platform::{
    ActivationEpoch, ActivationReceipt, JobId, ObservedService, Platform, PlatformError, Result,
    ScheduledJob, ServiceName, ServiceSpec, ServiceStatus, UnitFile,
};
use weglarka_launcher::host::{DEFAULT_HOST_DIR, LAUNCHER_FILE};
use weglarka_launcher::selection::{Job, PlatformService, RuntimeJobs};
use weglarka_model::app::Digest;
use weglarka_model::config::PlatformKind;

use crate::platform::{
    CommandRunner, TokioRunner, activation_labels, pinned_digest, run_args_with_labels,
};

/// Rootless Podman API service.
pub const PODMAN_SERVICE: &str = "weglarka-podman";
/// Daemon container service (foreground launcher).
pub const DAEMON_SERVICE: &str = "weglarka";
/// BusyBox crond system service.
pub const CRON_SERVICE: &str = "crond";
/// Managed crontab block markers.
const CRON_BEGIN: &str = "# BEGIN weglarka managed jobs";
const CRON_END: &str = "# END weglarka managed jobs";

pub struct OpenRcPlatform<R: CommandRunner = TokioRunner> {
    user: String,
    uid: u32,
    host_dir: PathBuf,
    state_dir: Option<PathBuf>,
    init_dir: Option<PathBuf>,
    crontab_dir: Option<PathBuf>,
    runner: R,
}

impl OpenRcPlatform<TokioRunner> {
    pub fn new(user: impl Into<String>, uid: u32) -> Self {
        Self {
            user: user.into(),
            uid,
            host_dir: PathBuf::from(DEFAULT_HOST_DIR),
            state_dir: None,
            init_dir: None,
            crontab_dir: None,
            runner: TokioRunner,
        }
    }
}

impl<R: CommandRunner> OpenRcPlatform<R> {
    pub fn with_runner(user: impl Into<String>, uid: u32, runner: R) -> Self {
        Self {
            user: user.into(),
            uid,
            host_dir: PathBuf::from(DEFAULT_HOST_DIR),
            state_dir: None,
            init_dir: None,
            crontab_dir: None,
            runner,
        }
    }

    pub fn with_host_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.host_dir = dir.into();
        self
    }

    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    pub fn with_init_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.init_dir = Some(dir.into());
        self
    }

    pub fn with_crontab_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.crontab_dir = Some(dir.into());
        self
    }

    pub fn host_dir(&self) -> &Path {
        &self.host_dir
    }

    pub fn runtime_dir(&self) -> PathBuf {
        PathBuf::from(format!("/run/user/{}", self.uid))
    }

    fn init_dir(&self) -> PathBuf {
        self.init_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/init.d"))
    }

    fn crontab_dir(&self) -> PathBuf {
        self.crontab_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/crontabs"))
    }

    async fn run(&self, program: &str, args: &[String]) -> Result<(bool, String)> {
        let env = [(
            "XDG_RUNTIME_DIR".to_owned(),
            self.runtime_dir().display().to_string(),
        )];
        self.runner
            .run(program, args, &env)
            .await
            .map_err(|e| PlatformError::Command(format!("{program}: {e}")))
    }

    async fn rc_service(&self, action: &str, service: &str) -> Result<(bool, String)> {
        self.run("rc-service", &[service.to_owned(), action.to_owned()])
            .await
    }

    /// Writes the two fixed init scripts. Both are root-owned and contain no user-writable input.
    fn render_init_scripts(&self, _spec: &ServiceSpec) -> Result<Vec<UnitFile>> {
        let launcher = self.host_dir.join(LAUNCHER_FILE).display().to_string();
        check_command_path(&launcher)?;
        let daemon_args = [
            "daemon-service".to_owned(),
            "--host-dir".to_owned(),
            self.host_dir.display().to_string(),
            "--runtime-dir".to_owned(),
            self.runtime_dir().display().to_string(),
            "--poll-secs".to_owned(),
            "5".to_owned(),
            "--max-attempts".to_owned(),
            "5".to_owned(),
        ];
        let daemon = format!(
            "#!/sbin/openrc-run\n\
             # Generated by weglarka — do not edit.\n\
             name=\"{DAEMON_SERVICE}\"\n\
             description=\"Węglarka daemon container (unprivileged runtime user)\"\n\
             command_user=\"{user}\"\n\
             supervisor=\"supervise-daemon\"\n\
             respawn_max=0\n\
             respawn_delay=5\n\
             respawn_period=60\n\
             command=\"{command}\"\n\
             command_args=\"{args}\"\n\
             depend() {{ need {podman}; after net; }}\n",
            user = self.user,
            command = launcher,
            args = daemon_args
                .iter()
                .map(|a| sh_quote(a))
                .collect::<Vec<_>>()
                .join(" "),
            podman = PODMAN_SERVICE,
        );

        let socket = self.runtime_dir().join("podman/podman.sock");
        let podman = format!(
            "#!/sbin/openrc-run\n\
             # Generated by weglarka — do not edit.\n\
             name=\"{PODMAN_SERVICE}\"\n\
             description=\"Rootless Podman API socket for Węglarka\"\n\
             command_user=\"{user}\"\n\
             command=\"/usr/bin/podman\"\n\
             command_args=\"system service --time=0 unix://{socket}\"\n\
             command_background=true\n\
             pidfile=\"/run/weglarka-podman.pid\"\n\
             start_pre() {{\n\
             \tcheckpath -d -m 0700 -o {user}:{user} \"{runtime}\"\n\
             \tcheckpath -d -m 0700 -o {user}:{user} \"{runtime}/podman\"\n\
             }}\n\
             depend() {{ need localmount; after net; }}\n",
            user = self.user,
            socket = socket.display(),
            runtime = self.runtime_dir().display(),
        );
        Ok(vec![
            UnitFile {
                file_name: DAEMON_SERVICE.to_owned(),
                content: daemon,
            },
            UnitFile {
                file_name: PODMAN_SERVICE.to_owned(),
                content: podman,
            },
        ])
    }

    async fn write_init_scripts(&self, files: &[UnitFile]) -> Result<()> {
        let dir = self.init_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", dir.display())))?;
        for file in files {
            check_script_value("service name", &file.file_name)?;
            let path = dir.join(&file.file_name);
            weglarka_model::fsutil::write_atomic(&path, file.content.as_bytes(), 0o755)
                .map_err(|e| PlatformError::Io(format!("{}: {e}", path.display())))?;
        }
        Ok(())
    }

    fn crontab_path(&self) -> PathBuf {
        self.crontab_dir().join(&self.user)
    }

    fn render_jobs(&self, jobs: &[ScheduledJob]) -> Result<String> {
        let launcher = self.host_dir.join(LAUNCHER_FILE).display().to_string();
        let mut lines = vec![CRON_BEGIN.to_owned()];
        for job in jobs {
            let mut command = sh_quote(&launcher);
            for arg in &job.args {
                check_script_value("job argument", arg)?;
                command.push(' ');
                command.push_str(&sh_quote(arg));
            }
            // BusyBox crond wakes every minute; the launcher enforces the configured cadence.
            lines.push(format!("* * * * * {command}"));
        }
        lines.push(CRON_END.to_owned());
        Ok(lines.join("\n"))
    }

    /// Replaces only the managed block, preserving unrelated crontab entries.
    async fn write_crontab(&self, jobs: &[ScheduledJob]) -> Result<()> {
        let dir = self.crontab_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", dir.display())))?;
        let path = self.crontab_path();
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let mut kept = Vec::new();
        let mut inside = false;
        for line in existing.lines() {
            if line.trim() == CRON_BEGIN {
                inside = true;
                continue;
            }
            if line.trim() == CRON_END {
                inside = false;
                continue;
            }
            if !inside {
                kept.push(line.to_owned());
            }
        }
        let mut text = kept.join("\n");
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&self.render_jobs(jobs)?);
        text.push('\n');
        weglarka_model::fsutil::write_atomic(&path, text.as_bytes(), 0o600)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", path.display())))?;
        Ok(())
    }

    async fn inspect(&self, service: &str) -> Result<Option<ContainerState>> {
        let format = "{{.Id}}|{{.State.Running}}|{{.Image}}|{{.Config.Image}}|\
                      {{index .Config.Labels \"io.weglarka.activation-epoch\"}}";
        let (ok, out) = self
            .run(
                "podman",
                &[
                    "inspect".to_owned(),
                    "--type".to_owned(),
                    "container".to_owned(),
                    "--format".to_owned(),
                    format.to_owned(),
                    service.to_owned(),
                ],
            )
            .await?;
        if !ok {
            return Ok(None);
        }
        let mut parts = out.split('|');
        let id = parts.next().unwrap_or_default().trim().to_owned();
        if id.is_empty() {
            return Ok(None);
        }
        Ok(Some(ContainerState {
            id,
            running: parts.next().unwrap_or_default().trim() == "true",
            image_id: parts.next().unwrap_or_default().trim().to_owned(),
            config_image: parts.next().unwrap_or_default().trim().to_owned(),
            epoch: parts.next().unwrap_or_default().trim().parse().ok(),
        }))
    }
}

struct ContainerState {
    id: String,
    running: bool,
    image_id: String,
    config_image: String,
    epoch: Option<u64>,
}

impl<R: CommandRunner> Platform for OpenRcPlatform<R> {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Openrc
    }

    async fn runtime_socket(&self, _runtime_user: &str) -> Result<PathBuf> {
        Ok(self.runtime_dir().join("podman/podman.sock"))
    }

    /// Installs the daemon and rootless-Podman services and enables them at boot. Starting is the
    /// bootstrap/restart step, like `platform install` on systemd.
    async fn install_service(&self, spec: &ServiceSpec) -> Result<()> {
        if spec.run_as_user != self.user {
            return Err(PlatformError::Command(format!(
                "service user {:?} differs from the platform user {:?}",
                spec.run_as_user, self.user
            )));
        }
        let files = self.render_init_scripts(spec)?;
        self.write_init_scripts(&files).await?;
        for service in [PODMAN_SERVICE, DAEMON_SERVICE] {
            let _ = self
                .run(
                    "rc-update",
                    &["add".to_owned(), service.to_owned(), "default".to_owned()],
                )
                .await?;
        }
        let _ = self
            .run(
                "rc-update",
                &[
                    "add".to_owned(),
                    CRON_SERVICE.to_owned(),
                    "default".to_owned(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn remove_service(&self, _name: &str) -> Result<()> {
        for service in [DAEMON_SERVICE, PODMAN_SERVICE] {
            let _ = self.rc_service("stop", service).await;
            let _ = self
                .run(
                    "rc-update",
                    &["del".to_owned(), service.to_owned(), "default".to_owned()],
                )
                .await;
            let path = self.init_dir().join(service);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(PlatformError::Io(format!("{}: {e}", path.display()))),
            }
        }
        Ok(())
    }

    async fn service_status(&self, name: &str) -> Result<ServiceStatus> {
        if !self.init_dir().join(name).exists() {
            return Ok(ServiceStatus::NotInstalled);
        }
        let (ok, out) = self.rc_service("status", name).await?;
        if ok && (out.is_empty() || out.contains("started") || out.contains("running")) {
            Ok(ServiceStatus::Active)
        } else {
            Ok(ServiceStatus::Inactive)
        }
    }

    async fn install_user_units(&self, _files: &[UnitFile]) -> Result<()> {
        Err(PlatformError::NotImplemented(
            "install_user_units on OpenRC; jobs are provisioned with install_jobs",
        ))
    }

    async fn remove_user_units(&self, _names: &[&str]) -> Result<()> {
        Err(PlatformError::NotImplemented("remove_user_units on OpenRC"))
    }

    async fn restart_service(&self, name: &str) -> Result<()> {
        let (ok, _) = self.rc_service("restart", name).await?;
        if ok {
            Ok(())
        } else {
            Err(PlatformError::Command(format!(
                "rc-service {name} restart failed"
            )))
        }
    }

    /// `supervise-daemon` restarts without a start-limit, so there is no failure state to clear.
    async fn reset_failed(&self, _name: &str) -> Result<()> {
        Ok(())
    }

    async fn set_timer(&self, _name: &str, _enabled: bool) -> Result<()> {
        Err(PlatformError::NotImplemented(
            "set_timer on OpenRC; periodic jobs use install_jobs and runtime-jobs.toml",
        ))
    }

    async fn install_jobs(&self, jobs: &[ScheduledJob]) -> Result<()> {
        for job in jobs {
            if job.cadence_secs == 0 {
                return Err(PlatformError::Command(format!(
                    "job {} has a zero cadence",
                    job.id.as_str()
                )));
            }
            if job.runtime_user != self.user {
                return Err(PlatformError::Command(format!(
                    "job {} runs as {:?}, not {:?}",
                    job.id.as_str(),
                    job.runtime_user,
                    self.user
                )));
            }
        }
        self.write_crontab(jobs).await?;
        let _ = self
            .run(
                "rc-update",
                &[
                    "add".to_owned(),
                    CRON_SERVICE.to_owned(),
                    "default".to_owned(),
                ],
            )
            .await?;
        let _ = self
            .run("rc-service", &[CRON_SERVICE.to_owned(), "start".to_owned()])
            .await;
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

    /// Writes the desired selection, then stops the observed container by ID only when its epoch
    /// matches the request. An obsolete request never stops a newer container.
    ///
    /// The service-selection lock is deliberately held across the observation and the stop: the
    /// contract requires the re-read and the stop to see the same selection, and a newer activation
    /// must not interleave between them.
    #[allow(clippy::await_holding_lock)]
    async fn activate_service(
        &self,
        spec: ServiceSpec,
        epoch: ActivationEpoch,
    ) -> Result<ActivationReceipt> {
        let (_, digest) = pinned_digest(&spec.image)?;
        let labels = activation_labels(epoch, &digest);
        let argv = run_args_with_labels(&spec, &labels)?;
        let selection = PlatformService::build(
            spec.name.clone(),
            spec.image.clone(),
            digest.clone(),
            epoch.0,
            argv,
        )
        .map_err(|e| PlatformError::Command(format!("service selection: {e}")))?;
        std::fs::create_dir_all(&self.host_dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", self.host_dir.display())))?;
        PlatformService::write_locked(&self.host_dir, &selection)
            .map_err(|e| PlatformError::Io(format!("platform-service.toml: {e}")))?;

        // Re-read under the service-selection lock and observe the container while the selection is
        // stable: an obsolete request must not stop a container confirmed at a newer epoch.
        let guard = weglarka_launcher::selection::lock_service_selection(&self.host_dir)
            .map_err(|e| PlatformError::Io(format!("platform-service.lock: {e}")))?;
        let current = PlatformService::load(&self.host_dir)
            .map_err(|e| PlatformError::Io(format!("platform-service.toml: {e}")))?;
        let obsolete =
            current.is_some_and(|current| current.epoch != epoch.0 || current.digest != digest);
        if obsolete {
            drop(guard);
            return Ok(ActivationReceipt { epoch });
        }
        let observed = self.inspect(&spec.name).await?;
        match observed {
            Some(container) if container.epoch == Some(epoch.0) => {
                let (ok, _) = self
                    .run(
                        "podman",
                        &[
                            "stop".to_owned(),
                            "--time".to_owned(),
                            "70".to_owned(),
                            container.id.clone(),
                        ],
                    )
                    .await?;
                if !ok {
                    return Err(PlatformError::Command(format!(
                        "podman stop {} failed",
                        container.id
                    )));
                }
            }
            Some(_) => {
                // A container at another epoch: supervision will replace it after reading the
                // new selection. Never stop it by ID.
            }
            None => {
                // "Already down" only when the selection still equals the request (the guard held
                // since the re-read proves it).
            }
        }
        drop(guard);
        Ok(ActivationReceipt { epoch })
    }

    async fn observe_service(&self, name: ServiceName) -> Result<ObservedService> {
        let observed = self.inspect(name.as_str()).await?;
        let Some(container) = observed else {
            return Ok(ObservedService {
                name,
                container_id: None,
                image_id: None,
                digest: None,
                activation_epoch: None,
                ready: Some(false),
            });
        };
        let mut digest = None;
        if !container.image_id.is_empty() {
            let (ok, out) = self
                .run(
                    "podman",
                    &[
                        "inspect".to_owned(),
                        "--type".to_owned(),
                        "image".to_owned(),
                        "--format".to_owned(),
                        "{{.Digest}}".to_owned(),
                        container.image_id.clone(),
                    ],
                )
                .await?;
            if ok {
                digest = Digest::new(out.trim().to_owned()).ok();
            }
        }
        if digest.is_none()
            && let Some((_, value)) = container.config_image.rsplit_once('@')
        {
            digest = Digest::new(value.to_owned()).ok();
        }
        Ok(ObservedService {
            name,
            container_id: Some(container.id),
            image_id: (!container.image_id.is_empty()).then_some(container.image_id),
            digest,
            activation_epoch: container.epoch.map(ActivationEpoch),
            ready: Some(container.running),
        })
    }
}

fn check_command_path(value: &str) -> Result<()> {
    if value.is_empty()
        || !value.starts_with('/')
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(PlatformError::Command(format!(
            "invalid launcher path {value:?}; it must be an absolute path without whitespace"
        )));
    }
    Ok(())
}

fn check_script_value(what: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(PlatformError::Command(format!("invalid {what}: {value:?}")));
    }
    Ok(())
}

/// Single-quotes a literal for an OpenRC/cron shell line. Fixed literals only.
fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use weglarka_engine::platform::Hardening;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

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
            let call = format!("{program} {}", args.join(" "));
            self.0.lock().unwrap().push(call.clone());
            let out = if call.contains("inspect --type container") {
                "abc|true|img|ghcr.io/example/weglarka@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|4".to_owned()
            } else if call.contains("inspect --type image") {
                format!("sha256:{}", "a".repeat(64))
            } else {
                String::new()
            };
            Ok((true, out))
        }
    }

    fn platform(dir: &Path) -> OpenRcPlatform<Recorder> {
        OpenRcPlatform::with_runner("weglarka", 1001, Recorder::default())
            .with_host_dir(dir.join("host"))
            .with_state_dir(dir.join("state"))
            .with_init_dir(dir.join("init.d"))
            .with_crontab_dir(dir.join("crontabs"))
    }

    fn spec() -> ServiceSpec {
        let digest = format!("sha256:{}", "a".repeat(64));
        ServiceSpec {
            name: "weglarka".into(),
            image: format!("ghcr.io/example/weglarka@{digest}"),
            run_as_user: "weglarka".into(),
            env: vec![],
            mounts: vec![],
            networks: vec![],
            args: vec!["run".into()],
            hardening: Hardening::default(),
        }
    }

    #[tokio::test]
    async fn the_daemon_service_drops_to_the_runtime_user_and_keeps_supervision_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        p.install_service(&spec()).await.unwrap();
        let script = std::fs::read_to_string(dir.path().join("init.d/weglarka")).unwrap();
        assert!(script.contains("command_user=\"weglarka\""));
        assert!(script.contains("supervisor=\"supervise-daemon\""));
        assert!(script.contains("respawn_max=0"));
        assert!(script.contains("daemon-service"));
        assert!(!script.contains("runuser"));
        let podman = std::fs::read_to_string(dir.path().join("init.d/weglarka-podman")).unwrap();
        assert!(podman.contains("unix:///run/user/1001/podman/podman.sock"));
        assert!(podman.contains("checkpath -d -m 0700 -o weglarka:weglarka"));
        assert!(
            p.runner
                .calls()
                .iter()
                .any(|c| c == "rc-update add weglarka default")
        );
        assert!(
            p.runner
                .calls()
                .iter()
                .any(|c| c == "rc-update add crond default")
        );
    }

    #[tokio::test]
    async fn cron_preserves_unrelated_entries_and_replaces_only_the_managed_block() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        std::fs::create_dir_all(dir.path().join("crontabs")).unwrap();
        std::fs::write(
            dir.path().join("crontabs/weglarka"),
            "0 3 * * * /usr/bin/backup\n# BEGIN weglarka managed jobs\nold\n# END weglarka managed jobs\n",
        )
        .unwrap();
        let jobs = [
            ScheduledJob {
                id: JobId::Update,
                args: vec![
                    "update".into(),
                    "--config".into(),
                    "/etc/weglarka/weglarka.toml".into(),
                ],
                runtime_user: "weglarka".into(),
                cadence_secs: 3600,
                skip_if_running: true,
            },
            ScheduledJob {
                id: JobId::Watchdog,
                args: vec![
                    "supervise".into(),
                    "--config".into(),
                    "/etc/weglarka/weglarka.toml".into(),
                ],
                runtime_user: "weglarka".into(),
                cadence_secs: 60,
                skip_if_running: true,
            },
        ];
        p.install_jobs(&jobs).await.unwrap();
        let text = std::fs::read_to_string(dir.path().join("crontabs/weglarka")).unwrap();
        assert!(text.contains("0 3 * * * /usr/bin/backup"));
        assert!(!text.contains("\nold\n"));
        assert_eq!(text.matches(CRON_BEGIN).count(), 1);
        assert!(text.contains(" 'update' '--config'"), "{text}");
        assert!(text.contains(" 'supervise' '--config'"), "{text}");
    }

    #[tokio::test]
    async fn activation_stops_by_id_only_at_the_requested_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        let receipt = p
            .activate_service(spec(), ActivationEpoch(4))
            .await
            .unwrap();
        assert_eq!(receipt.epoch, ActivationEpoch(4));
        assert!(
            p.runner
                .calls()
                .iter()
                .any(|c| c.contains("podman stop --time 70 abc")),
            "{:?}",
            p.runner.calls()
        );
        // A newer observed epoch is never stopped by an obsolete request.
        let p = platform(dir.path());
        let _ = p.activate_service(spec(), ActivationEpoch(3)).await;
        // The previous activation left epoch 4 in the selection, so this request is obsolete.
        assert!(
            !p.runner.calls().iter().any(|c| c.contains("podman stop")),
            "{:?}",
            p.runner.calls()
        );
    }

    #[tokio::test]
    async fn jobs_are_never_run_as_another_user() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        let jobs = [ScheduledJob {
            id: JobId::Update,
            args: vec!["update".into()],
            runtime_user: "root".into(),
            cadence_secs: 60,
            skip_if_running: true,
        }];
        assert!(p.install_jobs(&jobs).await.is_err());
    }

    #[tokio::test]
    async fn observation_reports_the_actual_image_and_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        let observed = p
            .observe_service(ServiceName::new("weglarka").unwrap())
            .await
            .unwrap();
        assert_eq!(observed.container_id.as_deref(), Some("abc"));
        assert_eq!(observed.activation_epoch, Some(ActivationEpoch(4)));
        assert!(observed.ready == Some(true));
        assert_eq!(
            observed.digest.unwrap().as_str(),
            format!("sha256:{}", "a".repeat(64))
        );
    }
}
