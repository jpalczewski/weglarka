//! `platform install --check` (issue #610): render the files an install would write, compare them
//! with the installed ones and report the difference.
//!
//! Why it exists: a host is also managed by configuration management (an Ansible role), and the only
//! way to see whether `weglarka.toml` still agrees with the quadlet was to grep for the entries it
//! adds. A grep cannot see an entry that was *removed*; a comparison can.
//!
//! Read-only by construction: it renders (the renderers are pure), reads the installed files and
//! prints. It never writes a file, never creates a directory and never runs `systemctl` — the write
//! path is [`Platform::install_service`]/[`Platform::install_user_units`], which this module does not
//! call.
//!
//! Exit codes (decided in `main`): every compared file matches → 0; a file differs or is missing →
//! [`InstallNeeded`] → 1; the check itself cannot run (an unreadable file, no `/etc/passwd` entry for
//! the runtime user, an adapter without [`Platform::installed_paths`]) → an ordinary error → 2.

use std::path::{Path, PathBuf};

use weglarka_engine::platform::{Platform, PlatformError};
use weglarka_launcher::host::BOOTSTRAP_MARKER;
use weglarka_launcher::selection::{LABEL_ACTIVATION_EPOCH, LABEL_DAEMON_DIGEST};
use weglarka_model::config::PlatformKind;
use weglarka_model::diff::line_diff;

use crate::platform::render;
use crate::self_update;
use crate::service::{DEFAULT_IMAGE, service_spec};
use crate::settings::Settings;

/// Shown instead of comparing `Image=` when the operator did not pass `--image`.
pub const IMAGE_NOTE: &str = "Image= not compared (pinned by self-update; compare with --image)";

/// Why the user units are not compared on a host that `platform bootstrap` took over.
const RETIRED_NOTE: &str = "skipped: retired by `platform bootstrap` on this host";

/// Prefix of the quadlet line that names the image an install would run.
const IMAGE_PREFIX: &str = "Image=";

/// Shown when the installed reference is a digest `self-update` pinned and `--image` named a tag.
const PINNED_NOTE: &str =
    "the installed Image= is a digest pinned by self-update: only the repository was compared";

/// Shown on a host `platform bootstrap` took over.
const LAUNCHER_NOTE: &str = "launcher-managed host: `platform install` would write the retired self-update and watchdog units back";

/// Typed marker of "an install is needed", so the exit code 1 never depends on message text.
#[derive(Debug, thiserror::Error)]
#[error("the installed files differ from what `platform install` would write")]
pub struct InstallNeeded;

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The adapter cannot say where its files live, so nothing can be compared. In v1 that is OpenRC.
    #[error("`platform install --check` is implemented for systemd only (this host is {0})")]
    Unsupported(&'static str),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    Units(#[from] self_update::Error),
}

/// One file an install would write: where it belongs and its exact content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub path: PathBuf,
    pub expected: String,
    /// Set when the file is deliberately not compared; the reason goes into the report.
    pub skip: Option<&'static str>,
}

/// How one file compares to what an install would write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Matches,
    /// The `-`/`+` line diff: what an install would remove and what it would add.
    Differs(String),
    /// No such file — a missing directory means every file in it is missing.
    Missing,
    /// Deliberately not compared on this host.
    Skipped(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReport {
    pub path: PathBuf,
    pub verdict: Verdict,
}

/// The comparison result: one entry per file an install would write, plus informational notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub files: Vec<FileReport>,
    pub notes: Vec<String>,
    /// The command that would make the installed files match, e.g.
    /// `weglarka-daemon --config … platform install`.
    pub fix: String,
}

impl Report {
    /// `true` when an install would change nothing — the exit-0 case.
    pub fn is_clean(&self) -> bool {
        !self
            .files
            .iter()
            .any(|f| matches!(f.verdict, Verdict::Differs(_) | Verdict::Missing))
    }
}

/// Renders the files an install would write and compares them with the installed ones.
///
/// `socket` is the Podman socket `install` would put in the quadlet (`host_socket`), `image` is the
/// `--image` value: `Some` compares `Image=` exactly, `None` leaves it to `self-update` and says so
/// (see [`installed_view`]).
pub fn run<P: Platform>(
    platform: &P,
    settings: &Settings,
    socket: PathBuf,
    host_dir: &Path,
    image: Option<String>,
) -> Result<Report, CheckError> {
    let paths = platform.installed_paths().map_err(|e| match e {
        // A capability the adapter does not have: an unsupported host, not a failed comparison.
        PlatformError::NotImplemented(_) => CheckError::Unsupported(match platform.kind() {
            PlatformKind::Systemd => "systemd",
            PlatformKind::Openrc => "OpenRC",
        }),
        other => CheckError::Platform(other),
    })?;
    let spec = service_spec(
        settings,
        socket,
        image.clone().unwrap_or_else(|| DEFAULT_IMAGE.to_owned()),
    );
    let mut targets: Vec<Target> = render(&spec)?
        .into_iter()
        .map(|f| Target {
            path: paths.service_dir.join(&f.file_name),
            expected: f.content,
            skip: None,
        })
        .collect();
    // `platform bootstrap` retires these two units on purpose: the launcher's own jobs
    // (`weglarka-platform-*`, in the same directory but a different set) do the work, and an install
    // would write the retired pair back, so on a launcher-managed host their state is not drift
    // (#610). The report says so, and the fix line stays `platform install` because a quadlet-only
    // drift is still that command.
    let launcher_managed = host_dir.join(BOOTSTRAP_MARKER).exists();
    if platform.kind() == PlatformKind::Systemd
        && let Some(units_dir) = &paths.units_dir
    {
        let mut units = self_update::units(settings)?;
        units.extend(self_update::watchdog_units(settings)?);
        targets.extend(units.into_iter().map(|f| Target {
            path: units_dir.join(&f.file_name),
            expected: f.content,
            skip: launcher_managed.then_some(RETIRED_NOTE),
        }));
    }

    let mut files = Vec::with_capacity(targets.len());
    let mut pinned = false;
    for target in &targets {
        let (verdict, tolerated) = verdict(target, image.as_deref())?;
        pinned |= tolerated;
        files.push(FileReport {
            path: target.path.clone(),
            verdict,
        });
    }
    let mut notes = Vec::new();
    if image.is_none() {
        notes.push(IMAGE_NOTE.to_owned());
    }
    if pinned {
        notes.push(PINNED_NOTE.to_owned());
    }
    if launcher_managed {
        notes.push(LAUNCHER_NOTE.to_owned());
    }
    Ok(Report {
        files,
        notes,
        fix: fix_command(settings, image.as_deref()),
    })
}

/// The command an operator re-runs to make the files match what this check rendered.
fn fix_command(settings: &Settings, image: Option<&str>) -> String {
    let mut command = format!(
        "weglarka-daemon --config {} platform install",
        settings.config_path.display()
    );
    // The check compared a pin, so the fix has to name the same image; without `--image` the
    // installed pin stays (a bare install would reset it to `:latest`).
    if let Some(image) = image {
        command.push_str(&format!(" --image {image}"));
    }
    command
}

fn verdict(target: &Target, image: Option<&str>) -> Result<(Verdict, bool), CheckError> {
    if let Some(reason) = target.skip {
        return Ok((Verdict::Skipped(reason), false));
    }
    let installed = match std::fs::read_to_string(&target.path) {
        Ok(text) => text,
        // An install to do, not a broken check: the whole directory may be absent on a host that
        // never ran `platform install`.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Verdict::Missing, false)),
        Err(source) => {
            return Err(CheckError::Read {
                path: target.path.clone(),
                source,
            });
        }
    };
    let mut installed_lines = installed_view(&installed);
    let mut expected_lines: Vec<String> = target.expected.lines().map(str::to_owned).collect();
    let mut pinned = false;
    match image {
        // The reference belongs to `self-update`: drop the line an install writes from both sides.
        // Only the first one, so a second `Image=` an operator injected is still drift.
        None => {
            drop_first_image_line(&mut installed_lines);
            drop_first_image_line(&mut expected_lines);
        }
        Some(wanted) => {
            // A digest `self-update` pinned against a tag named for the same repository: the pin is
            // the point of self-update, and the fix line (a bare install) would reset it to `:latest`.
            // Compared by repository, and only in that direction — a digest the operator asks for, or
            // another repository, is drift.
            if let Some(line) = installed_lines
                .iter_mut()
                .find(|line| line.starts_with(IMAGE_PREFIX))
            {
                let installed_ref = line[IMAGE_PREFIX.len()..].to_owned();
                if pinned_by_self_update(&installed_ref, wanted) {
                    *line = format!("{IMAGE_PREFIX}{wanted}");
                    pinned = true;
                }
            }
        }
    }
    let diff = line_diff(&installed_lines.join("\n"), &expected_lines.join("\n"));
    Ok((
        if diff.is_empty() {
            Verdict::Matches
        } else {
            Verdict::Differs(diff)
        },
        pinned,
    ))
}

/// Is `installed` a digest `self-update` pinned while the operator named a *tag* of the same
/// repository? Comparing those exactly would report drift on every host that updates itself.
fn pinned_by_self_update(installed: &str, wanted: &str) -> bool {
    match installed.split_once('@') {
        Some((pinned_repo, _)) => !wanted.contains('@') && pinned_repo == repository(wanted),
        None => false,
    }
}

/// A reference without its tag or digest; the registry port of `localhost:5000/weglarka` stays part
/// of it. Only meaningful for a reference without a digest (see [`pinned_by_self_update`]).
fn repository(reference: &str) -> &str {
    match reference.rsplit_once(':') {
        Some((repo, tag)) if !repo.is_empty() && !tag.contains('/') => repo,
        _ => reference,
    }
}

/// Drops the `Image=` line an install writes, if there is one.
fn drop_first_image_line(lines: &mut Vec<String>) {
    if let Some(i) = lines.iter().position(|line| line.starts_with(IMAGE_PREFIX)) {
        lines.remove(i);
    }
}

/// The lines of the **installed** file that an install is allowed to disagree with. One normalization
/// rule, each of them a case that would otherwise be reported as permanent drift:
///
/// * `Label=io.weglarka.activation-epoch=` and `Label=io.weglarka.daemon-digest=` are dropped: the
///   plain renderer never writes them, `SystemdPlatform::activate_service` always does. On a
///   launcher-managed host the running service definition carries them by design.
///
/// `Image=` is handled in [`verdict`] (it is dropped when `--image` is absent and compared by
/// repository in the one self-update case). Everything else is compared strictly, extra lines
/// included — a `host_mounts` entry that was *removed* from the configuration is exactly what this
/// check exists for.
fn installed_view(text: &str) -> Vec<String> {
    let labels = [
        format!("Label={LABEL_ACTIVATION_EPOCH}="),
        format!("Label={LABEL_DAEMON_DIGEST}="),
    ];
    text.lines()
        .filter(|line| {
            !labels
                .iter()
                .any(|prefix| line.starts_with(prefix.as_str()))
        })
        .map(str::to_owned)
        .collect()
}

impl std::fmt::Display for Report {
    /// One line per file in the shape `doctor` uses (a status tag, an aligned path, the verdict), the
    /// diff of a differing file underneath it, then the notes and a summary.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let width = self
            .files
            .iter()
            .map(|c| c.path.display().to_string().len())
            .max()
            .unwrap_or(0);
        let (mut matched, mut differs, mut missing, mut skipped) = (0, 0, 0, 0);
        for file in &self.files {
            let (tag, text) = match &file.verdict {
                Verdict::Matches => {
                    matched += 1;
                    (" OK ", "matches".to_owned())
                }
                Verdict::Differs(_) => {
                    differs += 1;
                    (
                        "DIFF",
                        "differs from what an install would write".to_owned(),
                    )
                }
                Verdict::Missing => {
                    missing += 1;
                    ("MISS", "is missing".to_owned())
                }
                Verdict::Skipped(reason) => {
                    skipped += 1;
                    ("INFO", (*reason).to_owned())
                }
            };
            writeln!(f, "[{tag}] {:<width$}  {text}", file.path.display())?;
            if let Verdict::Differs(diff) = &file.verdict {
                for line in diff.lines() {
                    writeln!(f, "       {:<width$}  {line}", "")?;
                }
            }
        }
        for note in &self.notes {
            writeln!(f, "[INFO] {:<width$}  {note}", "")?;
        }
        writeln!(
            f,
            "\n{matched} match, {differs} differ, {missing} missing, {skipped} skipped"
        )?;
        if !self.is_clean() {
            writeln!(f, "re-run: {}", self.fix)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{CommandOutput, CommandRunner, SystemdPlatform};
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use weglarka_model::config::HostConfig;

    const IMAGE: &str = "ghcr.io/example/weglarka:main";
    const SOCKET: &str = "/run/user/1001/podman/podman.sock";

    /// A runner that never runs: the check must not invoke a command at all.
    struct NoCommands;

    impl CommandRunner for NoCommands {
        async fn run(
            &self,
            program: &str,
            args: &[String],
            _: &[(String, String)],
        ) -> io::Result<CommandOutput> {
            panic!("the check ran a command: {program} {}", args.join(" "));
        }
    }

    const HOST: &str = r#"
[admin]
socket = "/run/user/1001/weglarka/admin.sock"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.com"
"#;

    /// A fake host root: `/etc/passwd`, the quadlet directory, the user unit directory, the
    /// host-only directory and a `weglarka.toml` all inside one tempdir.
    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("passwd"),
                "root:x:0:0::/root:/bin/sh\nweglarka:x:1001:1001::/home/weglarka:/bin/sh\n",
            )
            .unwrap();
            std::fs::create_dir_all(dir.path().join("host")).unwrap();
            Self { dir }
        }

        fn settings(&self, host_mounts: &[&str]) -> Settings {
            let list = host_mounts
                .iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            let state = self.dir.path().join("state");
            let host = HostConfig::from_toml_str(&format!(
                "[runtime]\nsocket = \"{SOCKET}\"\nhost_mounts = [{list}]\n\
                 [state]\ndir = {:?}\n{HOST}",
                state.display().to_string()
            ))
            .unwrap();
            Settings::from_host(host, self.dir.path().join("weglarka.toml"))
        }

        fn platform(&self) -> SystemdPlatform<NoCommands> {
            SystemdPlatform::with_runner("weglarka", NoCommands)
                .with_passwd(self.dir.path().join("passwd"))
                .with_quadlet_dir(self.dir.path().join("q"))
                .with_units_dir(self.dir.path().join("units"))
                .with_host_dir(self.dir.path().join("host"))
        }

        /// What `platform install` would write, written by hand from the public renderers.
        fn install(&self, settings: &Settings, image: &str) {
            let spec = service_spec(settings, PathBuf::from(SOCKET), image.to_owned());
            let quadlet_dir = self.dir.path().join("q");
            std::fs::create_dir_all(&quadlet_dir).unwrap();
            for f in render(&spec).unwrap() {
                std::fs::write(quadlet_dir.join(f.file_name), f.content).unwrap();
            }
            let units_dir = self.dir.path().join("units");
            std::fs::create_dir_all(&units_dir).unwrap();
            let mut units = self_update::units(settings).unwrap();
            units.extend(self_update::watchdog_units(settings).unwrap());
            for f in units {
                std::fs::write(units_dir.join(f.file_name), f.content).unwrap();
            }
        }

        fn check(&self, settings: &Settings, image: Option<&str>) -> Result<Report, CheckError> {
            run(
                &self.platform(),
                settings,
                PathBuf::from(SOCKET),
                &self.dir.path().join("host"),
                image.map(str::to_owned),
            )
        }

        fn report(&self, settings: &Settings, image: Option<&str>) -> Report {
            self.check(settings, image).unwrap()
        }

        fn quadlet(&self, name: &str) -> PathBuf {
            self.dir.path().join("q").join(name)
        }

        fn unit(&self, name: &str) -> PathBuf {
            self.dir.path().join("units").join(name)
        }

        fn container(&self) -> PathBuf {
            self.quadlet("weglarka.container")
        }
    }

    fn verdict_of<'a>(report: &'a Report, path: &Path) -> &'a Verdict {
        &report
            .files
            .iter()
            .find(|f| f.path == path)
            .unwrap_or_else(|| panic!("no report for {}", path.display()))
            .verdict
    }

    #[test]
    fn identical_files_match() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        fixture.install(&settings, IMAGE);
        let report = fixture.report(&settings, Some(IMAGE));
        assert!(report.is_clean(), "{report}");
        assert!(report.notes.is_empty(), "{report}");
        // The quadlet, its network and the four self-update/watchdog units.
        assert_eq!(report.files.len(), 6, "{report}");
        for file in &report.files {
            assert_eq!(file.verdict, Verdict::Matches, "{report}");
        }
        let text = report.to_string();
        assert!(text.contains("matches"), "{text}");
        assert!(
            text.contains("6 match, 0 differ, 0 missing, 0 skipped"),
            "{text}"
        );
        assert!(!text.contains("re-run:"), "{text}");
    }

    #[test]
    fn added_host_mounts_entry_differs() {
        let fixture = Fixture::new();
        fixture.install(&fixture.settings(&[]), IMAGE);
        // The configuration gained an entry after the install: the quadlet lacks its mount.
        let settings = fixture.settings(&["/var/log/journal"]);
        let report = fixture.report(&settings, Some(IMAGE));
        assert!(!report.is_clean(), "{report}");
        let Verdict::Differs(diff) = verdict_of(&report, &fixture.container()) else {
            panic!("{report}");
        };
        assert!(
            diff.contains("+ Volume=/var/log/journal:/var/log/journal:ro"),
            "{diff}"
        );
        // Nothing else moved, so the units stay clean.
        assert_eq!(
            verdict_of(&report, &fixture.unit("weglarka-self-update.service")),
            &Verdict::Matches
        );
        assert!(report.to_string().contains("re-run: "), "{report}");
    }

    #[test]
    fn removed_host_mounts_entry_differs() {
        let fixture = Fixture::new();
        let installed = fixture.settings(&["/var/log/journal"]);
        fixture.install(&installed, IMAGE);
        // The entry is gone from `weglarka.toml`, but the installed quadlet still mounts it — the
        // case a grep for the entry cannot see.
        let report = fixture.report(&fixture.settings(&[]), Some(IMAGE));
        let Verdict::Differs(diff) = verdict_of(&report, &fixture.container()) else {
            panic!("{report}");
        };
        assert!(
            diff.contains("- Volume=/var/log/journal:/var/log/journal:ro"),
            "{diff}"
        );
        assert!(!diff.contains("+ Volume="), "{diff}");
    }

    #[test]
    fn changed_mount_option_differs() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        fixture.install(&settings, IMAGE);
        let path = fixture.container();
        let text = std::fs::read_to_string(&path).unwrap();
        // Drop `:ro` from the configuration mount by hand (options are appended to the target).
        let mount = format!("{}:ro", settings.config_path.display());
        let edited = text.replacen(&mount, &settings.config_path.display().to_string(), 1);
        assert_ne!(edited, text, "the mount is not in the quadlet");
        std::fs::write(&path, edited).unwrap();
        let report = fixture.report(&settings, Some(IMAGE));
        let Verdict::Differs(diff) = verdict_of(&report, &path) else {
            panic!("{report}");
        };
        let config = settings.config_path.display();
        assert!(
            diff.contains(&format!("- Volume={config}:{config}\n")),
            "{diff}"
        );
        assert!(
            diff.contains(&format!("+ Volume={config}:{config}:ro\n")),
            "{diff}"
        );
    }

    #[test]
    fn image_pin_is_compared_by_repository_only() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        let pinned = format!("ghcr.io/example/weglarka@sha256:{}", "a".repeat(64));
        fixture.install(&settings, &pinned);
        // Without `--image` the pin belongs to `self-update`: no drift, one note instead.
        let report = fixture.report(&settings, None);
        assert!(report.is_clean(), "{report}");
        assert_eq!(report.notes, vec![IMAGE_NOTE.to_owned()]);
        let text = report.to_string();
        assert!(text.contains("Image= not compared"), "{text}");
        assert!(!text.contains("re-run:"), "{text}");
        // `--image` naming a *tag* of the same repository: the digest is self-update's pin, so the
        // repository is what counts — otherwise every self-updating host would report drift forever,
        // and the printed fix would reset the pin to `:latest`.
        let report = fixture.report(&settings, Some(IMAGE));
        assert!(report.is_clean(), "{report}");
        assert_eq!(report.notes, vec![PINNED_NOTE.to_owned()]);
        assert!(
            report.to_string().contains("pinned by self-update"),
            "{report}"
        );
        // Another repository is drift, and the fix names the image that was asked for.
        let report = fixture.report(&settings, Some("ghcr.io/example/other:main"));
        assert!(!report.is_clean(), "{report}");
        let Verdict::Differs(diff) = verdict_of(&report, &fixture.container()) else {
            panic!("{report}");
        };
        assert!(diff.contains(&format!("- Image={pinned}")), "{diff}");
        assert!(
            diff.contains("+ Image=ghcr.io/example/other:main"),
            "{diff}"
        );
        assert!(
            report.fix.contains("--image ghcr.io/example/other:main"),
            "{}",
            report.fix
        );
        // Asking for a digest means exactly that digest: a different one is drift.
        let wanted = format!("ghcr.io/example/weglarka@sha256:{}", "c".repeat(64));
        let report = fixture.report(&settings, Some(&wanted));
        assert!(!report.is_clean(), "{report}");
        assert_eq!(report.notes, Vec::<String>::new());
    }

    #[test]
    fn a_second_image_line_is_drift() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        fixture.install(&settings, IMAGE);
        // An injected duplicate changes what the quadlet runs; dropping every `Image=` line would hide
        // it, so only the line an install writes is dropped.
        let path = fixture.container();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{text}Image=ghcr.io/example/injected:1\n")).unwrap();
        for image in [None, Some(IMAGE)] {
            let report = fixture.report(&settings, image);
            let Verdict::Differs(diff) = verdict_of(&report, &path) else {
                panic!("{image:?}: {report}");
            };
            assert!(
                diff.contains("- Image=ghcr.io/example/injected:1"),
                "{diff}"
            );
        }
    }

    #[test]
    fn a_kind_without_installed_paths_is_unsupported_not_an_error() {
        // OpenRC writes init scripts and a crontab block instead of units; nothing to compare in v1.
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        let err = run(
            &crate::openrc::OpenRcPlatform::new("weglarka", 1001),
            &settings,
            PathBuf::from(SOCKET),
            &fixture.dir.path().join("host"),
            Some(IMAGE.to_owned()),
        )
        .unwrap_err();
        assert!(matches!(err, CheckError::Unsupported("OpenRC")), "{err:?}");
        assert_eq!(
            err.to_string(),
            "`platform install --check` is implemented for systemd only (this host is OpenRC)"
        );
    }

    #[test]
    fn activation_labels_on_the_installed_side_are_not_drift() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        fixture.install(&settings, IMAGE);
        let path = fixture.container();
        let text = std::fs::read_to_string(&path).unwrap();
        let labels = format!(
            "Label={LABEL_ACTIVATION_EPOCH}=7\nLabel={LABEL_DAEMON_DIGEST}=sha256:{}\n",
            "b".repeat(64)
        );
        let text = text.replacen(
            "ContainerName=weglarka\n",
            &format!("ContainerName=weglarka\n{labels}"),
            1,
        );
        assert!(text.contains(LABEL_ACTIVATION_EPOCH));
        std::fs::write(&path, text).unwrap();
        let report = fixture.report(&settings, Some(IMAGE));
        assert!(report.is_clean(), "{report}");
    }

    #[test]
    fn missing_file_and_missing_directory_are_verdicts_not_errors() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        // Neither directory exists yet: every file is missing, which is an install to do.
        let report = fixture.report(&settings, Some(IMAGE));
        assert!(!report.is_clean(), "{report}");
        assert!(report.files.iter().all(|f| f.verdict == Verdict::Missing));
        let text = report.to_string();
        assert!(text.contains("is missing"), "{text}");
        assert!(report.fix.contains("platform install"), "{}", report.fix);

        // A single file missing from an existing directory behaves the same way.
        fixture.install(&settings, IMAGE);
        std::fs::remove_file(fixture.unit("weglarka-watchdog.timer")).unwrap();
        let report = fixture.report(&settings, Some(IMAGE));
        assert_eq!(
            verdict_of(&report, &fixture.unit("weglarka-watchdog.timer")),
            &Verdict::Missing
        );
        assert_eq!(verdict_of(&report, &fixture.container()), &Verdict::Matches);
    }

    #[test]
    fn launcher_managed_host_skips_the_user_units() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        fixture.install(&settings, IMAGE);
        // `platform bootstrap` retired the two user units and runs its own jobs.
        std::fs::remove_file(fixture.unit("weglarka-self-update.timer")).unwrap();
        std::fs::write(
            fixture.dir.path().join("host").join(BOOTSTRAP_MARKER),
            "format_version = 1\n",
        )
        .unwrap();
        let report = fixture.report(&settings, Some(IMAGE));
        assert!(report.is_clean(), "{report}");
        assert_eq!(
            verdict_of(&report, &fixture.unit("weglarka-self-update.timer")),
            &Verdict::Skipped(RETIRED_NOTE)
        );
        assert!(report.to_string().contains("skipped"), "{report}");
    }

    /// The effective uid: a `chmod 000` file is readable to root, so that case cannot run there
    /// (CI runs unprivileged).
    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
            })
            .is_some_and(|uid| uid == "0")
    }

    #[test]
    fn unreadable_file_is_an_error() {
        if is_root() {
            eprintln!("running as root: skipping the unreadable-file case");
            return;
        }
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        fixture.install(&settings, IMAGE);
        let path = fixture.container();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let error = fixture.check(&settings, Some(IMAGE)).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.starts_with("cannot read"), "{message}");
    }

    #[test]
    fn a_missing_passwd_entry_is_an_error() {
        let fixture = Fixture::new();
        let settings = fixture.settings(&[]);
        fixture.install(&settings, IMAGE);
        let empty = fixture.dir.path().join("empty-passwd");
        std::fs::write(&empty, "root:x:0:0::/root:/bin/sh\n").unwrap();
        let platform = fixture.platform().with_passwd(&empty);
        let error = run(
            &platform,
            &settings,
            PathBuf::from(SOCKET),
            &fixture.dir.path().join("host"),
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not found in"), "{error}");
    }
}
