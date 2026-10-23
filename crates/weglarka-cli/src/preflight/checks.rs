//! Concrete preflight checks. Each is a separate type behind [`Check`].

use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::Path;

use weglarka_api::DoctorCheck;
use weglarka_core::app::AppsFile;
use weglarka_core::config::{IngressMode, PlatformKind};

use super::host::{CmdOutput, FileKind, Host};
use super::parse::{
    apt_installed_from, can_write, gids_of, parse_major_minor, parse_proc_net_tcp, subid_total,
};
use super::{Check, Context, RuntimeUser, fail, ok, warn};

/// Minimum total size of the user's subuid/subgid ranges for `userns=auto`.
/// 65536 is the standard rootless Podman range (images with uid > 0 fit in it);
/// below that, `userns=auto` and ordinary images start failing.
pub const MIN_SUBID_COUNT: u64 = 65_536;

/// Recommended range size: `userns=auto` gives each container a separate block
/// (1024 ids by default, images with large uids need more), so 65536 is enough for one or two
/// apps. The Ansible role `weglarka_host` provides 2,000,000; we warn below 1,000,000.
pub const RECOMMENDED_SUBID_COUNT: u64 = 1_000_000;

// The names/paths below are a convention of the Ansible role `weglarka_host` (niechybnie repo),
// not part of Węglarka's configuration — a change there requires a change here.
/// Sync validator policy for Traefik's file (JSON, root-owned).
pub const TRAEFIK_POLICY_PATH: &str = "/etc/weglarka/traefik-policy.json";
/// systemd unit that, after Węglarka's file changes, validates it against the policy and copies
/// it to Traefik.
pub const TRAEFIK_SYNC_UNIT: &str = "weglarka-traefik-sync.path";

/// The source Podman is expected to come from (OBS repo `home:alvistack`, decision from the MVP
/// note).
pub const PINNED_PODMAN_SOURCE: &str = "alvistack";

/// Minimum Podman / libpod API version.
pub const MIN_PODMAN_MAJOR: u32 = 6;

fn runtime_user<'a>(cx: &'a Context<'_>, id: &str) -> Result<&'a RuntimeUser, DoctorCheck> {
    cx.user.as_ref().ok_or_else(|| {
        warn(
            id,
            format!("skipped: runtime user {:?} not found", cx.runtime.user),
            "najpierw napraw `runtime.user`",
        )
    })
}

/// First working program from the candidate list (`NotFound` → next).
fn run_first(host: &dyn Host, candidates: &[&str], args: &[&str]) -> Option<(String, CmdOutput)> {
    candidates.iter().find_map(|c| match host.run(c, args) {
        Ok(out) => Some(((*c).to_owned(), out)),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(_) => None,
    })
}

// ---------------------------------------------------------------------------

pub struct ConfigFile;
impl Check for ConfigFile {
    fn id(&self) -> &'static str {
        "config.file"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        match (&cx.config, &cx.config_error) {
            (Some(_), _) => ok(self.id(), format!("{} parses", cx.config_path.display())),
            (None, err) => fail(
                self.id(),
                err.clone().unwrap_or_else(|| "config not loaded".into()),
                "utwórz weglarka.toml (Ansible) albo wskaż plik przez --config / WEGLARKA_CONFIG; \
                 dalsze sprawdzenia używają wartości domyślnych",
            ),
        }
    }
}

pub struct RuntimeUserExists;
impl Check for RuntimeUserExists {
    fn id(&self) -> &'static str {
        "runtime.user"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        match &cx.user {
            Some(u) => ok(self.id(), format!("user {} exists (uid {})", u.name, u.uid)),
            None => fail(
                self.id(),
                format!("user {:?} does not exist", cx.runtime.user),
                format!(
                    "utwórz usera (`useradd --create-home --shell /usr/sbin/nologin {}`) \
                     lub popraw [runtime] user w weglarka.toml",
                    cx.runtime.user
                ),
            ),
        }
    }
}

/// `/etc/subuid` or `/etc/subgid`.
pub struct SubIds {
    id: &'static str,
    file: &'static str,
}
impl SubIds {
    pub fn uid() -> Self {
        Self {
            id: "runtime.subuid",
            file: "/etc/subuid",
        }
    }
    pub fn gid() -> Self {
        Self {
            id: "runtime.subgid",
            file: "/etc/subgid",
        }
    }
}
impl Check for SubIds {
    fn id(&self) -> &'static str {
        self.id
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let user = match runtime_user(cx, self.id) {
            Ok(u) => u,
            Err(c) => return c,
        };
        let hint = format!(
            "dodaj zakres: `usermod --add-{}s <start>-<koniec> {}` (≥ {RECOMMENDED_SUBID_COUNT} id zalecane, {MIN_SUBID_COUNT} minimum)",
            if self.file.ends_with("subuid") {
                "sub-uid"
            } else {
                "sub-gid"
            },
            user.name
        );
        match cx.host.read_to_string(Path::new(self.file)) {
            Err(e) => fail(self.id, format!("cannot read {}: {e}", self.file), hint),
            Ok(src) => match subid_total(&src, user) {
                0 => fail(
                    self.id,
                    format!("no range for {} in {}", user.name, self.file),
                    hint,
                ),
                n if n < MIN_SUBID_COUNT => fail(
                    self.id,
                    format!(
                        "only {n} ids for {} in {} (need ≥ {MIN_SUBID_COUNT})",
                        user.name, self.file
                    ),
                    hint,
                ),
                n if n < RECOMMENDED_SUBID_COUNT => warn(
                    self.id,
                    format!(
                        "{n} ids for {} in {} (recommended ≥ {RECOMMENDED_SUBID_COUNT} for userns=auto)",
                        user.name, self.file
                    ),
                    hint,
                ),
                n => ok(
                    self.id,
                    format!("{n} ids for {} in {}", user.name, self.file),
                ),
            },
        }
    }
}

pub struct CgroupsV2;
impl Check for CgroupsV2 {
    fn id(&self) -> &'static str {
        "runtime.cgroups"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        if cx
            .host
            .stat(Path::new("/sys/fs/cgroup/cgroup.controllers"))
            .is_err()
        {
            return fail(
                self.id(),
                "cgroups v2 (unified hierarchy) not detected",
                "uruchom system z `systemd.unified_cgroup_hierarchy=1` (cgroups v2 jest wymagane przez rootless Podmana)",
            );
        }
        if let Some(u) = &cx.user {
            let p = format!(
                "/sys/fs/cgroup/user.slice/user-{0}.slice/user@{0}.service/cgroup.controllers",
                u.uid
            );
            if let Ok(delegated) = cx.host.read_to_string(Path::new(&p)) {
                let missing: Vec<&str> = ["memory", "pids"]
                    .into_iter()
                    .filter(|c| !delegated.split_whitespace().any(|d| d == *c))
                    .collect();
                if !missing.is_empty() {
                    return warn(
                        self.id(),
                        format!(
                            "cgroups v2, but controllers not delegated to {}: {}",
                            u.name,
                            missing.join(", ")
                        ),
                        "utwórz /etc/systemd/system/user@.service.d/delegate.conf z `[Service]\\nDelegate=cpu cpuset io memory pids`",
                    );
                }
            }
        }
        ok(self.id(), "cgroups v2")
    }
}

pub struct Linger;
impl Check for Linger {
    fn id(&self) -> &'static str {
        "runtime.linger"
    }
    fn applies(&self, cx: &Context<'_>) -> bool {
        cx.platform == PlatformKind::Systemd
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let user = match runtime_user(cx, self.id()) {
            Ok(u) => u,
            Err(c) => return c,
        };
        let marker = format!("/var/lib/systemd/linger/{}", user.name);
        if cx.host.stat(Path::new(&marker)).is_ok() {
            ok(self.id(), format!("linger enabled for {}", user.name))
        } else {
            fail(
                self.id(),
                format!("linger disabled for {}", user.name),
                format!(
                    "`loginctl enable-linger {}` — bez tego usługi usera zatrzymają się po wylogowaniu",
                    user.name
                ),
            )
        }
    }
}

pub struct PodmanSocket;
impl Check for PodmanSocket {
    fn id(&self) -> &'static str {
        "runtime.socket"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let Some(socket) = cx.podman_socket() else {
            return warn(
                self.id(),
                "skipped: socket path unknown (no runtime user)",
                "ustaw [runtime] socket albo popraw usera",
            );
        };
        match cx.host.podman_ping(&socket) {
            Ok(p) if p.status == 200 => ok(
                self.id(),
                format!("podman socket {} responds", socket.display()),
            ),
            Ok(p) => fail(
                self.id(),
                format!(
                    "podman socket {} answered HTTP {}",
                    socket.display(),
                    p.status
                ),
                "sprawdź `systemctl --user status podman.socket` jako user runtime'u",
            ),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => warn(
                self.id(),
                format!("no permission to connect to {}", socket.display()),
                "uruchom preflight jako user runtime'u (`sudo -u <user> weglarka doctor --preflight`)",
            ),
            Err(e) => fail(
                self.id(),
                format!("cannot reach podman socket {}: {e}", socket.display()),
                "włącz socket: `systemctl --user enable --now podman.socket` (jako user runtime'u, wymaga linger)",
            ),
        }
    }
}

pub struct PodmanApiVersion;
impl Check for PodmanApiVersion {
    fn id(&self) -> &'static str {
        "runtime.podman_version"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let Some(socket) = cx.podman_socket() else {
            return warn(
                self.id(),
                "skipped: socket path unknown",
                "napraw `runtime.socket`",
            );
        };
        let ping = match cx.host.podman_ping(&socket) {
            Ok(p) => p,
            Err(e) => {
                return warn(
                    self.id(),
                    format!("skipped: podman unreachable ({e})"),
                    "napraw `runtime.socket`",
                );
            }
        };
        match ping
            .libpod_api_version
            .as_deref()
            .and_then(parse_major_minor)
        {
            Some((major, minor)) if major >= MIN_PODMAN_MAJOR => {
                ok(self.id(), format!("libpod API {major}.{minor}"))
            }
            Some((major, minor)) => fail(
                self.id(),
                format!("libpod API {major}.{minor} is too old (need ≥ {MIN_PODMAN_MAJOR}.0)"),
                "zainstaluj Podmana 6 z repo alvistack (notatka MVP, decyzja 1); v4/v5 nie są wspierane",
            ),
            None => fail(
                self.id(),
                "podman did not report Libpod-API-Version",
                "to nie wygląda na socket libpod — sprawdź ścieżkę [runtime] socket",
            ),
        }
    }
}

pub struct PodmanSource;
impl Check for PodmanSource {
    fn id(&self) -> &'static str {
        "runtime.podman_source"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let hint = format!(
            "zainstaluj podman z repo `home:alvistack` i przypnij stos Podmana w apt preferences (źródło musi zawierać „{PINNED_PODMAN_SOURCE}”)"
        );
        match cx.host.run("apt-cache", &["policy", "podman"]) {
            Err(_) => warn(
                self.id(),
                "cannot determine package origin (apt-cache unavailable)",
                hint,
            ),
            Ok(out) => match apt_installed_from(&out.stdout, PINNED_PODMAN_SOURCE) {
                Some(true) => ok(
                    self.id(),
                    format!("podman installed from {PINNED_PODMAN_SOURCE}"),
                ),
                Some(false) => warn(
                    self.id(),
                    format!("podman is not installed from {PINNED_PODMAN_SOURCE}"),
                    hint,
                ),
                None => warn(self.id(), "podman package not installed (apt)", hint),
            },
        }
    }
}

pub struct Netavark;
impl Check for Netavark {
    fn id(&self) -> &'static str {
        "runtime.netavark"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let Some((bin, out)) = run_first(
            cx.host,
            &[
                "netavark",
                "/usr/libexec/podman/netavark",
                "/usr/lib/podman/netavark",
            ],
            &["--version"],
        ) else {
            return fail(
                self.id(),
                "netavark not found",
                "zainstaluj netavark 2 (zależność Podmana 6)",
            );
        };
        let version = out.stdout.trim().to_owned();
        if parse_major_minor(&version).is_some_and(|(maj, _)| maj < 2) {
            return fail(
                self.id(),
                format!("{version} ({bin}) is too old"),
                "potrzebny netavark ≥ 2",
            );
        }
        // Firewall driver: env `NETAVARK_FW` (in the environment or containers.conf) wins over
        // autodetection.
        let mut configured = cx.host.env("NETAVARK_FW");
        if configured.is_none() {
            let mut files = vec!["/etc/containers/containers.conf".to_owned()];
            if let Some(u) = &cx.user {
                files.push(format!(
                    "{}/.config/containers/containers.conf",
                    u.home.display()
                ));
            }
            configured = files.iter().find_map(|f| {
                cx.host
                    .read_to_string(Path::new(f))
                    .ok()?
                    .lines()
                    .find_map(|l| {
                        let l = l.trim();
                        (!l.starts_with('#'))
                            .then(|| l.split_once("NETAVARK_FW="))
                            .flatten()
                            .map(|(_, v)| {
                                v.trim_matches(|c: char| {
                                    c == '"' || c == '\'' || c == ',' || c == ' ' || c == ']'
                                })
                                .to_owned()
                            })
                    })
            });
        }
        let nft = run_first(cx.host, &["nft"], &["--version"]).is_some();
        match configured.as_deref() {
            Some("nftables") => ok(
                self.id(),
                format!("{version}, firewall driver nftables (NETAVARK_FW)"),
            ),
            Some(other) => fail(
                self.id(),
                format!("{version}, firewall driver pinned to {other:?}"),
                "ustaw NETAVARK_FW=nftables (Podman 6 + nftables jest wymagany)",
            ),
            None if nft => warn(
                self.id(),
                format!(
                    "{version}, firewall driver not pinned (nft present; netavark may pick iptables)"
                ),
                "przypnij: `[engine]\\nenv = [\"NETAVARK_FW=nftables\"]` w containers.conf usera runtime'u",
            ),
            None => fail(
                self.id(),
                format!("{version}, but `nft` is missing"),
                "zainstaluj pakiet nftables i ustaw NETAVARK_FW=nftables",
            ),
        }
    }
}

pub struct Pasta;
impl Check for Pasta {
    fn id(&self) -> &'static str {
        "runtime.pasta"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        match run_first(
            cx.host,
            &[
                "pasta",
                "/usr/bin/pasta",
                "/usr/libexec/podman/pasta",
                "/usr/lib/podman/pasta",
            ],
            &["--version"],
        ) {
            Some((bin, out)) => ok(
                self.id(),
                format!(
                    "pasta available ({bin}{})",
                    out.stdout
                        .lines()
                        .next()
                        .map(|l| format!(": {l}"))
                        .unwrap_or_default()
                ),
            ),
            None => fail(
                self.id(),
                "pasta not found",
                "zainstaluj pakiet `passt` (pasta = domyślna sieć rootless w Podmanie ≥ 5)",
            ),
        }
    }
}

/// Ubuntu 24.04: with `kernel.apparmor_restrict_unprivileged_userns=1` rootless Podman
/// only works with the `podman` profile loaded (attached to the binary, with `userns,`).
pub struct AppArmorUserns;
impl AppArmorUserns {
    const SYSCTL: &'static str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
    const PROFILES: &'static str = "/sys/kernel/security/apparmor/profiles";
    const PROFILE_FILE: &'static str = "/etc/apparmor.d/podman";
}
impl Check for AppArmorUserns {
    fn id(&self) -> &'static str {
        "runtime.apparmor_userns"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        match cx.host.read_to_string(Path::new(Self::SYSCTL)) {
            Err(_) => {
                return ok(
                    self.id(),
                    "AppArmor userns restriction not present (skipped)",
                );
            }
            Ok(v) if v.trim() != "1" => {
                return ok(self.id(), "AppArmor does not restrict unprivileged userns");
            }
            Ok(_) => {}
        }
        let hint = "załaduj profil podman: `apparmor_parser -r /etc/apparmor.d/podman` (pakiet podman z alvistack/Ubuntu go dostarcza; \
                    profil musi mieć `userns,`) albo ustaw sysctl `kernel.apparmor_restrict_unprivileged_userns=0`";
        match cx.host.read_to_string(Path::new(Self::PROFILES)) {
            Ok(src) => {
                let loaded = src
                    .lines()
                    .any(|l| l.split_whitespace().next() == Some("podman"));
                if loaded {
                    ok(
                        self.id(),
                        "apparmor_restrict_unprivileged_userns=1 and profile podman is loaded",
                    )
                } else {
                    fail(
                        self.id(),
                        "apparmor_restrict_unprivileged_userns=1, but no AppArmor profile `podman` is loaded",
                        hint,
                    )
                }
            }
            // The profile list is readable only by root — we don't guess.
            Err(e) => {
                let file = cx.host.stat(Path::new(Self::PROFILE_FILE)).is_ok();
                warn(
                    self.id(),
                    format!(
                        "cannot verify AppArmor profile `podman` ({e}); profile file {}",
                        if file { "exists" } else { "is missing" }
                    ),
                    if file {
                        "uruchom preflight jako root, by potwierdzić załadowanie profilu (`aa-status`)"
                    } else {
                        hint
                    },
                )
            }
        }
    }
}

pub struct TraefikFile;
impl Check for TraefikFile {
    fn id(&self) -> &'static str {
        "ingress.traefik_file"
    }
    fn applies(&self, cx: &Context<'_>) -> bool {
        cx.config
            .as_ref()
            .is_some_and(|c| c.ingress.mode == IngressMode::Behind)
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let Some(path) = cx
            .config
            .as_ref()
            .and_then(|c| c.ingress.traefik_dynamic_file.as_ref())
        else {
            return fail(
                self.id(),
                "ingress.mode = behind, but traefik_dynamic_file is not set",
                "ustaw [ingress] traefik_dynamic_file w weglarka.toml",
            );
        };
        let st = match cx.host.stat(path) {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return fail(
                    self.id(),
                    format!("{} does not exist", path.display()),
                    "załóż plik z góry (Ansible) i oddaj go userowi runtime'u — Węglarka nadpisuje go w miejscu",
                );
            }
            Err(e) => {
                return warn(
                    self.id(),
                    format!("cannot stat {}: {e}", path.display()),
                    "uruchom preflight jako user runtime'u, by sprawdzić dostęp",
                );
            }
        };
        if st.kind != FileKind::File {
            return fail(
                self.id(),
                format!("{} is not a regular file", path.display()),
                "wskaż zwykły plik YAML",
            );
        }
        let user = match runtime_user(cx, self.id()) {
            Ok(u) => u,
            Err(c) => return c,
        };
        if can_write(&st, user.uid, &gids_of(cx.host, user)) {
            ok(
                self.id(),
                format!("{} exists and is writable by {}", path.display(), user.name),
            )
        } else {
            fail(
                self.id(),
                format!(
                    "{} is not writable by {} (mode {:04o}, uid {})",
                    path.display(),
                    user.name,
                    st.mode,
                    st.uid
                ),
                format!(
                    "`chown {0} {1}` i `chmod 0644 {1}`",
                    user.name,
                    path.display()
                ),
            )
        }
    }
}

pub struct BindAddress;
impl Check for BindAddress {
    fn id(&self) -> &'static str {
        "ingress.bind"
    }
    fn applies(&self, cx: &Context<'_>) -> bool {
        cx.config.is_some()
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let bind = cx.config.as_ref().expect("applies").ingress.bind;
        let ip = bind.ip();
        if ip.is_unspecified() {
            return ok(self.id(), format!("{bind} listens on all interfaces"));
        }
        let hint = "adres musi należeć do interfejsu hosta (dla Traefika z Coolify: gateway docker0, np. 172.17.0.1)";
        let out = match cx.host.run("ip", &["-j", "addr", "show"]) {
            Ok(o) if o.success => o,
            _ => return warn(self.id(), "cannot list interfaces (`ip` unavailable)", hint),
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&out.stdout) else {
            return warn(self.id(), "cannot parse `ip -j addr` output", hint);
        };
        let found = value
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|i| i["addr_info"].as_array().into_iter().flatten())
            .filter_map(|a| a["local"].as_str()?.parse::<IpAddr>().ok())
            .any(|a| a == ip);
        if found {
            ok(self.id(), format!("{ip} is assigned to a host interface"))
        } else {
            fail(
                self.id(),
                format!("{ip} is not assigned to any host interface"),
                hint,
            )
        }
    }
}

/// The port from `ingress.bind` must not be held by someone else's process. We read the socket
/// owner from `/proc/net/tcp*` (uid column): the runtime user's socket is Węglarka's nginx
/// (pasta/rootlessport).
pub struct BindFree;
impl Check for BindFree {
    fn id(&self) -> &'static str {
        "ingress.bind_free"
    }
    fn applies(&self, cx: &Context<'_>) -> bool {
        cx.config.is_some()
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let bind = cx.config.as_ref().expect("applies").ingress.bind;
        let IpAddr::V4(ip) = bind.ip() else {
            return ok(self.id(), format!("{bind}: IPv6 bind, port check skipped"));
        };
        let mut listeners = match cx.host.read_to_string(Path::new("/proc/net/tcp")) {
            Ok(src) => parse_proc_net_tcp(&src, false),
            Err(e) => {
                return warn(
                    self.id(),
                    format!("cannot read /proc/net/tcp: {e}"),
                    "nie można sprawdzić zajętości portu",
                );
            }
        };
        if let Ok(src) = cx.host.read_to_string(Path::new("/proc/net/tcp6")) {
            listeners.extend(parse_proc_net_tcp(&src, true));
        }
        let holders: Vec<_> = listeners
            .iter()
            .filter(|l| {
                l.port == bind.port()
                    && (l.addr.is_none() || ip.is_unspecified() || l.addr == Some(ip))
            })
            .collect();
        if holders.is_empty() {
            return ok(self.id(), format!("port {} is free on {ip}", bind.port()));
        }
        let ours = cx.user.as_ref().map(|u| u.uid);
        if holders.iter().all(|l| Some(l.uid) == ours) {
            return ok(
                self.id(),
                format!("{bind} is held by the runtime user (nginx Węglarki running)"),
            );
        }
        let other = holders
            .iter()
            .find(|l| Some(l.uid) != ours)
            .expect("non-empty");
        fail(
            self.id(),
            format!(
                "port {} is already in use by uid {}",
                bind.port(),
                other.uid
            ),
            "wybierz wolny port w [ingress] bind (np. 8088; na niechybnie 8080 zajmuje Traefik z Coolify) — sprawdź `ss -ltnp`",
        )
    }
}

/// `behind` mode on systemd: the root-owned `weglarka-traefik-sync.path` validates Węglarka's file
/// against the policy and copies it to Traefik; app domains must be on the policy's allowlist.
pub struct TraefikSync;
impl Check for TraefikSync {
    fn id(&self) -> &'static str {
        "ingress.traefik_sync"
    }
    fn applies(&self, cx: &Context<'_>) -> bool {
        cx.platform == PlatformKind::Systemd
            && cx
                .config
                .as_ref()
                .is_some_and(|c| c.ingress.mode == IngressMode::Behind)
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let policy = match cx.host.read_to_string(Path::new(TRAEFIK_POLICY_PATH)) {
            Ok(p) => p,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return ok(
                    self.id(),
                    format!("no {TRAEFIK_POLICY_PATH} — Traefik sync not in use"),
                );
            }
            Err(e) => {
                return warn(
                    self.id(),
                    format!("cannot read {TRAEFIK_POLICY_PATH}: {e}"),
                    "uruchom preflight z dostępem do pliku polityki",
                );
            }
        };
        match cx.host.run("systemctl", &["is-active", TRAEFIK_SYNC_UNIT]) {
            Ok(out) if out.stdout.trim() == "active" => {}
            Ok(out) => {
                return fail(
                    self.id(),
                    format!(
                        "{TRAEFIK_SYNC_UNIT} is {} — zmiany pliku Traefika nie będą publikowane",
                        out.stdout.trim()
                    ),
                    format!(
                        "`systemctl enable --now {TRAEFIK_SYNC_UNIT}` (rola Ansible weglarka_host)"
                    ),
                );
            }
            Err(_) => {
                return warn(
                    self.id(),
                    "cannot query systemd (`systemctl` unavailable)",
                    format!("sprawdź ręcznie `systemctl is-active {TRAEFIK_SYNC_UNIT}`"),
                );
            }
        }
        let Some(allowed) = allowed_domains(&policy) else {
            return warn(
                self.id(),
                format!(
                    "{TRAEFIK_SYNC_UNIT} active, but {TRAEFIK_POLICY_PATH} has no readable domain allowlist"
                ),
                "oczekiwana tablica stringów `allowed_domains` (albo `domains`) w polityce",
            );
        };
        let apps = match cx.host.read_to_string(&cx.apps_path) {
            Ok(src) => match toml::from_str::<AppsFile>(&src) {
                Ok(a) => a,
                Err(e) => {
                    return warn(
                        self.id(),
                        format!(
                            "{TRAEFIK_SYNC_UNIT} active; cannot parse {}: {e}",
                            cx.apps_path.display()
                        ),
                        "popraw apps.toml, by sprawdzić domeny względem polityki",
                    );
                }
            },
            Err(_) => {
                return ok(
                    self.id(),
                    format!(
                        "{TRAEFIK_SYNC_UNIT} active, policy present (apps.toml not available locally)"
                    ),
                );
            }
        };
        let mut rejected: Vec<&str> = apps
            .apps
            .values()
            .flat_map(|a| a.domains.iter().map(String::as_str))
            .filter(|d| !allowed.iter().any(|a| a.eq_ignore_ascii_case(d)))
            .collect();
        rejected.sort_unstable();
        rejected.dedup();
        if rejected.is_empty() {
            ok(
                self.id(),
                format!("{TRAEFIK_SYNC_UNIT} active; all app domains are allowed by policy"),
            )
        } else {
            warn(
                self.id(),
                format!(
                    "domains not on the policy allowlist (validator would reject them): {}",
                    rejected.join(", ")
                ),
                format!(
                    "dodaj domeny do `weglarka_allowed_domains` w roli Ansible i wdróż politykę ({TRAEFIK_POLICY_PATH})"
                ),
            )
        }
    }
}

fn allowed_domains(policy_json: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(policy_json).ok()?;
    ["allowed_domains", "domains"].iter().find_map(|k| {
        v.get(k)?
            .as_array()?
            .iter()
            .map(|d| d.as_str().map(str::to_owned))
            .collect()
    })
}

pub struct SecretsFile;
impl Check for SecretsFile {
    fn id(&self) -> &'static str {
        "state.secrets_file"
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let path = &cx.secrets_path;
        match cx.host.stat(path) {
            Err(e) if e.kind() == ErrorKind::NotFound => warn(
                self.id(),
                format!("{} not found", path.display()),
                "to normalne przed pierwszym `secrets set`; inna lokalizacja: --secrets-file / WEGLARKA_SECRETS_FILE",
            ),
            Err(e) => warn(
                self.id(),
                format!("cannot stat {}: {e}", path.display()),
                "uruchom jako user z dostępem do pliku",
            ),
            Ok(st) if st.kind != FileKind::File => fail(
                self.id(),
                format!("{} is not a regular file", path.display()),
                "usuń i załóż zwykły plik 0600",
            ),
            Ok(st) if st.mode & 0o777 != 0o600 => fail(
                self.id(),
                format!(
                    "{} has mode {:04o} (expected 0600)",
                    path.display(),
                    st.mode & 0o777
                ),
                format!("`chmod 0600 {}`", path.display()),
            ),
            Ok(_) => ok(self.id(), format!("{} has mode 0600", path.display())),
        }
    }
}
