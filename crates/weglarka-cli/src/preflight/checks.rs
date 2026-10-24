//! Concrete preflight checks. Each is a separate type behind [`Check`].

use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::Path;

use weglarka_api::DoctorCheck;
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
            "fix `runtime.user` first",
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
                "create weglarka.toml (Ansible) or point to a file with --config / WEGLARKA_CONFIG; \
                 the remaining checks use defaults",
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
                    "create the user (`useradd --create-home --shell /usr/sbin/nologin {}`) \
                     or fix [runtime] user in weglarka.toml",
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
            "add a range: `usermod --add-{}s <start>-<end> {}` (≥ {RECOMMENDED_SUBID_COUNT} ids recommended, {MIN_SUBID_COUNT} minimum)",
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
                "boot the system with `systemd.unified_cgroup_hierarchy=1` (cgroups v2 is required by rootless Podman)",
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
                        "create /etc/systemd/system/user@.service.d/delegate.conf with `[Service]\\nDelegate=cpu cpuset io memory pids`",
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
                    "`loginctl enable-linger {}` — without it the user's services stop on logout",
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
                "set [runtime] socket or fix the user",
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
                "check `systemctl --user status podman.socket` as the runtime user",
            ),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => warn(
                self.id(),
                format!("no permission to connect to {}", socket.display()),
                "run the preflight as the runtime user (`sudo -u <user> weglarka doctor --preflight`)",
            ),
            Err(e) => fail(
                self.id(),
                format!("cannot reach podman socket {}: {e}", socket.display()),
                "enable the socket: `systemctl --user enable --now podman.socket` (as the runtime user, requires linger)",
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
                "fix `runtime.socket`",
            );
        };
        let ping = match cx.host.podman_ping(&socket) {
            Ok(p) => p,
            Err(e) => {
                return warn(
                    self.id(),
                    format!("skipped: podman unreachable ({e})"),
                    "fix `runtime.socket`",
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
                "install Podman 6 from the alvistack repo (MVP note, decision 1); v4/v5 are not supported",
            ),
            None => fail(
                self.id(),
                "podman did not report Libpod-API-Version",
                "this does not look like a libpod socket — check the [runtime] socket path",
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
            "install podman from the `home:alvistack` repo and pin the Podman stack in apt preferences (the source must contain “{PINNED_PODMAN_SOURCE}”)"
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
                "install netavark 2 (a Podman 6 dependency)",
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
                "set NETAVARK_FW=nftables (Podman 6 + nftables is required)",
            ),
            None if nft => warn(
                self.id(),
                format!(
                    "{version}, firewall driver not pinned (nft present; netavark may pick iptables)"
                ),
                "pin it: `[engine]\\nenv = [\"NETAVARK_FW=nftables\"]` in the runtime user's containers.conf",
            ),
            None => fail(
                self.id(),
                format!("{version}, but `nft` is missing"),
                "install the nftables package and set NETAVARK_FW=nftables",
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
                "install the `passt` package (pasta = the default rootless network in Podman ≥ 5)",
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
        let hint = "load the podman profile: `apparmor_parser -r /etc/apparmor.d/podman` (the podman package from alvistack/Ubuntu provides it; \
                    the profile must have `userns,`) or set the sysctl `kernel.apparmor_restrict_unprivileged_userns=0`";
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
                        "run the preflight as root to confirm the profile is loaded (`aa-status`)"
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
                "set [ingress] traefik_dynamic_file in weglarka.toml",
            );
        };
        let st = match cx.host.stat(path) {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return fail(
                    self.id(),
                    format!("{} does not exist", path.display()),
                    "create the file up front (Ansible) and give it to the runtime user — Węglarka overwrites it in place",
                );
            }
            Err(e) => {
                return warn(
                    self.id(),
                    format!("cannot stat {}: {e}", path.display()),
                    "run the preflight as the runtime user to check access",
                );
            }
        };
        if st.kind != FileKind::File {
            return fail(
                self.id(),
                format!("{} is not a regular file", path.display()),
                "point to a regular YAML file",
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
                    "`chown {0} {1}` and `chmod 0644 {1}`",
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
        let hint = "the address must belong to a host interface (for Traefik from Coolify: the docker0 gateway, e.g. 172.17.0.1)";
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
                    "cannot check whether the port is in use",
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
                format!("{bind} is held by the runtime user (Węglarka's nginx running)"),
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
            "pick a free port in [ingress] bind (e.g. 8088; on niechybnie 8080 is taken by Traefik from Coolify) — check `ss -ltnp`",
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
                    "run the preflight with access to the policy file",
                );
            }
        };
        match cx.host.run("systemctl", &["is-active", TRAEFIK_SYNC_UNIT]) {
            Ok(out) if out.stdout.trim() == "active" => {}
            Ok(out) => {
                return fail(
                    self.id(),
                    format!(
                        "{TRAEFIK_SYNC_UNIT} is {} — changes to the Traefik file will not be published",
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
                    format!("check manually `systemctl is-active {TRAEFIK_SYNC_UNIT}`"),
                );
            }
        }
        let Some(allowed) = allowed_domains(&policy) else {
            return warn(
                self.id(),
                format!(
                    "{TRAEFIK_SYNC_UNIT} active, but {TRAEFIK_POLICY_PATH} has no readable domain allowlist"
                ),
                "expected a string array `allowed_domains` (or `domains`) in the policy",
            );
        };
        let apps = match cx.host.read_to_string(&cx.apps_path) {
            Ok(src) => match weglarka_core::state::parse_apps(&cx.apps_path, &src) {
                Ok(a) => a,
                Err(e) => {
                    let hint = match &e {
                        weglarka_core::state::StateError::SchemaTooNew { .. } => {
                            "apps.toml was written by a newer Węglarka: roll forward, or restore it \
                             from before the upgrade"
                        }
                        _ => "fix apps.toml to check the domains against the policy",
                    };
                    return warn(self.id(), format!("{TRAEFIK_SYNC_UNIT} active; {e}"), hint);
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
                    "add the domains to `weglarka_allowed_domains` in the Ansible role and deploy the policy ({TRAEFIK_POLICY_PATH})"
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

/// Ports published directly on the host (`host_ports`, issue #34). Two layers: the declaration must
/// pass [`weglarka_core::host_ports::validate`] (privileged ports, two apps on one socket, the
/// ingress bind) and the port must not be held by someone else's process. Like `ingress.bind_free`,
/// the socket owner comes from `/proc/net/tcp*`: sockets of the runtime user belong to Węglarka
/// (rootlessport forwarding an already running app), so they are not a collision.
pub struct HostPortsFree;
impl Check for HostPortsFree {
    fn id(&self) -> &'static str {
        "apps.host_ports_free"
    }
    fn applies(&self, cx: &Context<'_>) -> bool {
        cx.config.is_some()
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck {
        let id = self.id();
        let host = cx.config.as_ref().expect("applies");
        let apps = match cx.host.read_to_string(&cx.apps_path) {
            Ok(src) => match weglarka_core::state::parse_apps(&cx.apps_path, &src) {
                Ok(apps) => apps,
                Err(e) => {
                    let hint = match &e {
                        weglarka_core::state::StateError::SchemaTooNew { .. } => {
                            "apps.toml was written by a newer Węglarka: roll forward, or restore it \
                             from before the upgrade"
                        }
                        _ => "fix apps.toml; host ports cannot be checked until it parses",
                    };
                    return fail(id, e.to_string(), hint);
                }
            },
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return ok(
                    id,
                    format!(
                        "{} does not exist — no host ports published",
                        cx.apps_path.display()
                    ),
                );
            }
            Err(e) => {
                return warn(
                    id,
                    format!("cannot read {}: {e}", cx.apps_path.display()),
                    "run preflight as the runtime user or make apps.toml readable",
                );
            }
        };
        if let Err(e) = apps
            .apps
            .iter()
            .try_for_each(|(name, spec)| weglarka_core::state::validate_app(name, spec))
        {
            return fail(id, e, "fix apps.toml; the daemon rejects the whole file");
        }
        if let Err(e) = weglarka_core::host_ports::validate(host, &apps) {
            return fail(
                id,
                e.to_string(),
                "fix the app host_ports: no two apps may share a host socket, the [ingress] bind is \
                 reserved, and ports below 1024 need [runtime] allow_privileged_host_ports = true",
            );
        }
        let entries: Vec<_> = apps
            .apps
            .iter()
            .flat_map(|(name, spec)| spec.host_ports.iter().map(move |p| (name.as_str(), p)))
            .collect();
        if entries.is_empty() {
            return ok(
                id,
                format!("{} publishes no app host ports", cx.apps_path.display()),
            );
        }
        let mut listeners = match cx.host.read_to_string(Path::new("/proc/net/tcp")) {
            Ok(src) => parse_proc_net_tcp(&src, false),
            Err(e) => {
                return warn(
                    id,
                    format!("cannot read /proc/net/tcp: {e}"),
                    "cannot check whether the declared host ports are free",
                );
            }
        };
        if let Ok(src) = cx.host.read_to_string(Path::new("/proc/net/tcp6")) {
            listeners.extend(parse_proc_net_tcp(&src, true));
        }
        let ours = cx.user.as_ref().map(|u| u.uid);
        let mut free = Vec::new();
        let mut ipv6 = Vec::new();
        for (app, entry) in entries {
            let ip = entry
                .bind_ip()
                .parse::<IpAddr>()
                .expect("host_ports::validate checked the bind address");
            let IpAddr::V4(ip) = ip else {
                // `parse_proc_net_tcp` models IPv4 addresses and the dual-stack wildcard only.
                ipv6.push(format!("{app}:{}", entry.host));
                continue;
            };
            let foreign = listeners.iter().find(|l| {
                l.port == entry.host
                    && (l.addr.is_none() || l.addr == Some(ip))
                    && Some(l.uid) != ours
            });
            if let Some(listener) = foreign {
                return fail(
                    id,
                    format!(
                        "{app}: host port {} on {ip} is already in use by uid {}",
                        entry.host, listener.uid
                    ),
                    format!(
                        "choose another --host-port or free {} (check `ss -ltnp`)",
                        entry.host
                    ),
                );
            }
            free.push(format!("{app} {} on {ip}", entry.host));
        }
        let mut message = if free.is_empty() {
            String::new()
        } else {
            format!("host ports are free: {}", free.join(", "))
        };
        if !ipv6.is_empty() {
            if !message.is_empty() {
                message.push_str("; ");
            }
            message.push_str(&format!("IPv6 binds not checked: {}", ipv6.join(", ")));
        }
        ok(id, message)
    }
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
                "this is normal before the first `secrets set`; a different location: --secrets-file / WEGLARKA_SECRETS_FILE",
            ),
            Err(e) => warn(
                self.id(),
                format!("cannot stat {}: {e}", path.display()),
                "run as a user with access to the file",
            ),
            Ok(st) if st.kind != FileKind::File => fail(
                self.id(),
                format!("{} is not a regular file", path.display()),
                "remove it and create a regular 0600 file",
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
