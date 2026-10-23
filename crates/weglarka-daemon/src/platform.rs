//! `Platform` dla systemd: quadlet usera (`~/.config/containers/systemd/<nazwa>.container`).
//! Quadlet to opcja na czas współistnienia z Coolify; interfejs (`Platform`) zostaje gotowy na
//! OpenRC — wystarczy druga implementacja traitu.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use weglarka_core::config::PlatformKind;
use weglarka_core::platform::{Platform, PlatformError, Result, ServiceSpec, ServiceStatus};

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
    /// Użytkownik runtime'u, w którego systemd-user działa serwis.
    user: String,
    passwd: PathBuf,
    /// Nadpisanie katalogu quadletów (testy); domyślnie `<home>/.config/containers/systemd`.
    quadlet_dir: Option<PathBuf>,
    runner: R,
}

impl SystemdPlatform<TokioRunner> {
    pub fn new(user: impl Into<String>) -> Self {
        Self::with_runner(user, TokioRunner)
    }
}

/// Plik quadleta: nazwa pliku i treść.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFile {
    pub file_name: String,
    pub content: String,
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
    check_value("service name", &spec.name)?;
    check_value("image", &spec.image)?;
    check_hardening(spec)?;
    let h = &spec.hardening;
    let mut a = vec!["--name".to_owned(), spec.name.clone()];
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

/// Pliki quadleta dla serwisu: `<nazwa>.container` + `.network` dla każdej sieci.
pub fn render(spec: &ServiceSpec) -> Result<Vec<UnitFile>> {
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

impl<R: CommandRunner> SystemdPlatform<R> {
    pub fn with_runner(user: impl Into<String>, runner: R) -> Self {
        Self {
            user: user.into(),
            passwd: PathBuf::from("/etc/passwd"),
            quadlet_dir: None,
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

    fn quadlet_dir(&self, entry: &PasswdEntry) -> PathBuf {
        self.quadlet_dir
            .clone()
            .unwrap_or_else(|| entry.home.join(".config/containers/systemd"))
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
        self.runner
            .run("systemctl", &full, &env)
            .await
            .map_err(|e| PlatformError::Command(format!("systemctl: {e}")))
    }

    /// Instalacja przebiega jako user runtime'u (jest właścicielem katalogu quadletów).
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
        // Pliki `.network` zostają (mogą być współdzielone); sprząta je operator.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_core::platform::Hardening;

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
}
