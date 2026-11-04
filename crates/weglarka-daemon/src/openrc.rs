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
use weglarka_launcher::inspect::{self, InspectedContainer};
use weglarka_launcher::selection::{Job, PlatformService, RuntimeJobs};
use weglarka_model::app::Digest;
use weglarka_model::config::PlatformKind;

use crate::platform::{
    CommandOutput, CommandRunner, TokioRunner, activation_labels, pinned_digest,
    run_args_with_labels,
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
        let out = self.run_output(program, args).await?;
        Ok((out.success, out.stdout))
    }

    async fn run_output(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
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
            // BusyBox crond wakes every minute; the cadence is enforced by the job's own worker (the daemon's
            // `self-update` checks `[self_update] interval_secs`), not by the launcher.
            lines.push(format!("* * * * * {command}"));
        }
        lines.push(CRON_END.to_owned());
        Ok(lines.join("\n"))
    }

    /// The crontab lines outside the managed block.
    fn unmanaged_lines(existing: &str) -> Vec<String> {
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
        kept
    }

    /// Whether the crontab has a managed block, and whether one of them is never closed.
    fn managed_blocks(existing: &str) -> (bool, bool) {
        let mut found = false;
        let mut inside = false;
        for line in existing.lines() {
            match line.trim() {
                CRON_BEGIN => {
                    found = true;
                    inside = true;
                }
                CRON_END => inside = false,
                _ => {}
            }
        }
        (found, inside)
    }

    /// Removes the managed block (markers included), preserving unrelated crontab entries. A
    /// crontab without a managed block is not ours and is left byte for byte as it is (no write, no
    /// delete); one whose block is never closed is refused, because the block's extent is unknown.
    /// A crontab left without any line is deleted.
    fn clear_crontab(&self) -> Result<()> {
        let path = self.crontab_path();
        let existing = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(PlatformError::Io(format!("{}: {e}", path.display()))),
        };
        match Self::managed_blocks(&existing) {
            (false, _) => return Ok(()),
            (true, true) => {
                return Err(PlatformError::Command(format!(
                    "{}: the managed block starting with {CRON_BEGIN:?} has no {CRON_END:?} line; \
                     remove the block by hand, nothing was changed",
                    path.display()
                )));
            }
            (true, false) => {}
        }
        let kept = Self::unmanaged_lines(&existing);
        if kept.iter().all(|line| line.trim().is_empty()) {
            return match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(PlatformError::Io(format!("{}: {e}", path.display()))),
            };
        }
        let mut text = kept.join("\n");
        text.push('\n');
        weglarka_model::fsutil::write_atomic(&path, text.as_bytes(), 0o600)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", path.display())))
    }

    /// Replaces only the managed block, preserving unrelated crontab entries.
    async fn write_crontab(&self, jobs: &[ScheduledJob]) -> Result<()> {
        let dir = self.crontab_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", dir.display())))?;
        let path = self.crontab_path();
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let kept = Self::unmanaged_lines(&existing);
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

    /// `Ok(None)` means Podman reports no such container; any other failure (for example an
    /// unreachable socket) is an error.
    async fn inspect(&self, service: &str) -> Result<Option<InspectedContainer>> {
        let args = inspect::container_args(service);
        let out = self.run_output("podman", &args).await?;
        if out.success {
            return Ok(inspect::parse_inspect(&out.stdout));
        }
        if inspect::is_absent(&out.stderr) {
            return Ok(None);
        }
        Err(PlatformError::Command(format!(
            "podman {}: {}",
            args.join(" "),
            out.stderr
        )))
    }
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

    /// Stops, disables and deletes the init scripts. A service whose script is already gone is
    /// skipped, so a repeated call (`platform remove` runs the teardown first) does no work.
    async fn remove_service(&self, _name: &str) -> Result<()> {
        for service in [DAEMON_SERVICE, PODMAN_SERVICE] {
            let path = self.init_dir().join(service);
            if !path.exists() {
                continue;
            }
            let _ = self.rc_service("stop", service).await;
            let _ = self
                .run(
                    "rc-update",
                    &["del".to_owned(), service.to_owned(), "default".to_owned()],
                )
                .await;
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

    /// Clears the cron block first, so no tick starts the launcher while its services go, then
    /// stops, disables and deletes the launcher-owned init scripts. `crond` itself stays: it is a
    /// shared system service and the operator's own crontab lines keep using it.
    async fn remove_launcher_setup(&self) -> Result<()> {
        self.clear_crontab()?;
        self.remove_service(DAEMON_SERVICE).await
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
        // One critical section for write, observation and stop. The write is forward only: a request
        // older than the stored selection is obsolete, changes nothing and never stops a container.
        weglarka_launcher::selection::create_host_dir(&self.host_dir)
            .map_err(|e| PlatformError::Io(format!("{}: {e}", self.host_dir.display())))?;
        let guard = weglarka_launcher::selection::lock_service_selection(&self.host_dir)
            .map_err(|e| PlatformError::Io(format!("platform-service.lock: {e}")))?;
        match selection.save(&self.host_dir) {
            Ok(()) => {}
            Err(weglarka_launcher::selection::SelectionError::Stale { .. }) => {
                drop(guard);
                return Ok(ActivationReceipt { epoch });
            }
            Err(e) => return Err(PlatformError::Io(format!("platform-service.toml: {e}"))),
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
        ) -> io::Result<CommandOutput> {
            let call = format!("{program} {}", args.join(" "));
            self.0.lock().unwrap().push(call.clone());
            let out = if call.contains("inspect --type container") {
                "abc|true|img|ghcr.io/example/weglarka@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|4".to_owned()
            } else if call.contains("inspect --type image") {
                format!("sha256:{}", "a".repeat(64))
            } else {
                String::new()
            };
            Ok(CommandOutput {
                success: true,
                stdout: out,
                stderr: String::new(),
            })
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

    /// Fails every `podman inspect` with a fixed stderr; everything else succeeds.
    struct FailingInspect(&'static str);

    impl CommandRunner for FailingInspect {
        async fn run(
            &self,
            _: &str,
            args: &[String],
            _: &[(String, String)],
        ) -> io::Result<CommandOutput> {
            Ok(CommandOutput {
                success: !args.iter().any(|a| a == "inspect"),
                stdout: String::new(),
                stderr: self.0.to_owned(),
            })
        }
    }

    #[tokio::test]
    async fn observe_treats_a_missing_container_as_absent() {
        let p = OpenRcPlatform::with_runner(
            "weglarka",
            1001,
            FailingInspect("Error: no such container weglarka"),
        );
        let observed = p
            .observe_service(ServiceName::new("weglarka").unwrap())
            .await
            .unwrap();
        assert_eq!(observed.container_id, None);
        assert_eq!(observed.ready, Some(false));
    }

    #[tokio::test]
    async fn observe_ignores_warnings_before_a_missing_container() {
        let p = OpenRcPlatform::with_runner(
            "weglarka",
            1001,
            FailingInspect(
                "level=warning msg=\"Failed to add pause process to systemd sandbox cgroup: dial unix \
         /run/user/1001/bus: connect: no such file or directory\"\nError: no such container \
         weglarka",
            ),
        );
        let observed = p
            .observe_service(ServiceName::new("weglarka").unwrap())
            .await
            .unwrap();
        assert_eq!(observed.container_id, None);
    }

    #[tokio::test]
    async fn observe_reports_an_unreachable_socket_as_an_error() {
        let p = OpenRcPlatform::with_runner(
            "weglarka",
            1001,
            FailingInspect(
                "Cannot connect to Podman. Please verify your connection to the Linux system using \
         `podman system connection list`, or try `podman machine init` and `podman machine \
         start` to manage a new Linux VM\nError: unable to connect to Podman socket: failed to \
         connect: dial unix /run/user/1001/podman/podman.sock: connect: no such file or \
         directory: unix:///run/user/1001/podman/podman.sock",
            ),
        );
        let error = p
            .observe_service(ServiceName::new("weglarka").unwrap())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unable to connect"), "{error}");
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

    fn update_job() -> ScheduledJob {
        ScheduledJob {
            id: JobId::Update,
            args: vec!["update".into()],
            runtime_user: "weglarka".into(),
            cadence_secs: 3600,
            skip_if_running: true,
        }
    }

    fn files_under(dir: &Path) -> Vec<String> {
        match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    #[tokio::test]
    async fn removing_the_launcher_setup_leaves_no_init_script_and_no_cron_line_for_the_launcher() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        p.install_service(&spec()).await.unwrap();
        p.install_jobs(&[update_job()]).await.unwrap();
        let crontab = dir.path().join("crontabs/weglarka");
        let managed = std::fs::read_to_string(&crontab).unwrap();
        std::fs::write(&crontab, format!("0 3 * * * /usr/bin/backup\n{managed}")).unwrap();
        assert_eq!(files_under(&dir.path().join("init.d")).len(), 2);

        p.remove_launcher_setup().await.unwrap();

        assert!(files_under(&dir.path().join("init.d")).is_empty());
        let crontab = std::fs::read_to_string(&crontab).unwrap();
        assert_eq!(crontab, "0 3 * * * /usr/bin/backup\n");
        assert!(!crontab.contains(LAUNCHER_FILE), "{crontab}");
        assert!(!crontab.contains(CRON_BEGIN), "{crontab}");
        let calls = p.runner.calls();
        for service in [DAEMON_SERVICE, PODMAN_SERVICE] {
            assert!(
                calls.contains(&format!("rc-update del {service} default")),
                "{calls:?}"
            );
            assert!(
                calls.contains(&format!("rc-service {service} stop")),
                "{calls:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_crontab_with_only_the_managed_block_is_deleted_and_teardown_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        p.install_service(&spec()).await.unwrap();
        p.install_jobs(&[update_job()]).await.unwrap();

        p.remove_launcher_setup().await.unwrap();
        p.remove_launcher_setup().await.unwrap();

        assert!(files_under(&dir.path().join("crontabs")).is_empty());
        assert!(files_under(&dir.path().join("init.d")).is_empty());
    }

    #[tokio::test]
    async fn teardown_on_a_host_without_a_crontab_does_not_create_one() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        p.remove_launcher_setup().await.unwrap();
        assert!(!dir.path().join("crontabs").exists());
    }

    #[tokio::test]
    async fn a_crontab_without_a_managed_block_keeps_its_exact_bytes_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        let crontab = dir.path().join("crontabs/weglarka");
        std::fs::create_dir_all(crontab.parent().unwrap()).unwrap();
        let original = "0 3 * * * /usr/bin/backup\r\n# no trailing newline";
        std::fs::write(&crontab, original).unwrap();
        std::fs::set_permissions(&crontab, std::fs::Permissions::from_mode(0o644)).unwrap();

        p.remove_launcher_setup().await.unwrap();

        assert_eq!(std::fs::read_to_string(&crontab).unwrap(), original);
        let mode = std::fs::metadata(&crontab).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[tokio::test]
    async fn an_unterminated_managed_block_is_refused_and_nothing_changes() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        p.install_service(&spec()).await.unwrap();
        let crontab = dir.path().join("crontabs/weglarka");
        std::fs::create_dir_all(crontab.parent().unwrap()).unwrap();
        let original = format!("{CRON_BEGIN}\n* * * * * x\n0 3 * * * /usr/bin/backup\n");
        std::fs::write(&crontab, &original).unwrap();

        let err = p.remove_launcher_setup().await.unwrap_err();

        assert!(err.to_string().contains("crontabs/weglarka"), "{err}");
        assert_eq!(std::fs::read_to_string(&crontab).unwrap(), original);
        // The cron block is checked first, so the init scripts were not touched either.
        assert_eq!(files_under(&dir.path().join("init.d")).len(), 2);
    }

    #[tokio::test]
    async fn removing_the_service_after_the_teardown_runs_no_commands() {
        let dir = tempfile::tempdir().unwrap();
        let p = platform(dir.path());
        p.install_service(&spec()).await.unwrap();
        p.remove_launcher_setup().await.unwrap();
        let before = p.runner.calls().len();

        p.remove_service("weglarka").await.unwrap();

        assert_eq!(p.runner.calls().len(), before);
    }
}
