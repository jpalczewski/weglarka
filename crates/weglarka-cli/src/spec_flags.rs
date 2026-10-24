//! Spec flags shared by `apps add` and `apps update`: the container command, resource limits,
//! volumes, hardening, ports published directly on the host and start dependencies. Before these
//! existed, they could only be set through `--spec <file.toml>`.

use clap::Args;
use weglarka_core::app::{
    AppSpec, CpuLimit, HostPort, InstanceName, MemoryLimit, SharedVolumeName, SharedVolumeRef,
    VolumeMount, valid_volume_name,
};

/// Value of a limit flag: a limit, or `none` to drop it (no limit is the default).
#[derive(Debug, Clone, PartialEq)]
pub enum Limit<T> {
    Set(T),
    Unset,
}

/// Value of [`SpecFlags::host_ports`]: a port entry, or `none` to clear the list (the same
/// convention as the limits and the list flags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPortFlag {
    Set(HostPort),
    Clear,
}

/// Value of [`SpecFlags::depends_on`]: an app name, or `none` to clear the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependsOnFlag {
    Set(InstanceName),
    Clear,
}

/// Spec flags shared by `apps add` and `apps update`; flattened into `AddArgs` and `UpdateArgs`.
#[derive(Debug, Default, Args)]
pub struct SpecFlags {
    /// Argument to the image's entrypoint (exec form, repeatable — one flag per argument; `none`
    /// clears it). Replaces the whole command: the argument order is significant, so unlike
    /// --tmpfs it does not append. Images with only an ENTRYPOINT need it, e.g. `--command serve`.
    /// Use `--command=<arg>` for arguments that start with a dash.
    #[arg(long = "command", value_name = "ARG|none", conflicts_with = "spec")]
    pub command: Vec<String>,
    /// Memory limit, e.g. 128m or 1g (`none` removes it). Default: no limit.
    #[arg(long, value_name = "SIZE|none", value_parser = parse_memory, conflicts_with = "spec")]
    pub memory: Option<Limit<MemoryLimit>>,
    /// Process (pids) limit (`none` removes it). Default: no limit.
    #[arg(long, value_name = "N|none", value_parser = parse_pids, conflicts_with = "spec")]
    pub pids_limit: Option<Limit<u32>>,
    /// CPU limit in CPUs, e.g. 0.5 (`none` removes it). Default: no limit.
    #[arg(long, value_name = "CPUS|none", value_parser = parse_cpus, conflicts_with = "spec")]
    pub cpus: Option<Limit<CpuLimit>>,
    /// Named volume: NAME=/PATH[:ro] (repeatable; replaces a volume of that name).
    #[arg(long = "volume", value_name = "NAME=/PATH[:ro]", value_parser = parse_volume, conflicts_with = "spec")]
    pub volumes: Vec<VolumeMount>,
    /// Shared volume mount: NAME=/PATH[:ro] (repeatable; replaces a mount of that name). The
    /// volume must be declared first (`weglarka volumes add NAME`); v1 allows at most one per app.
    #[arg(long = "shared-volume", value_name = "NAME=/PATH[:ro]", value_parser = parse_shared_volume, conflicts_with = "spec")]
    pub shared_volumes: Vec<SharedVolumeRef>,
    /// Hardening preset: read-only root, all capabilities dropped, no-new-privileges. Combine with
    /// --tmpfs for writable paths and --cap-add for what the app really needs.
    #[arg(long, conflicts_with = "spec")]
    pub hardened: bool,
    /// Read-only root filesystem (writable tmpfs on /tmp, /var/tmp, /run).
    #[arg(long, value_name = "true|false", conflicts_with = "spec")]
    pub read_only: Option<bool>,
    /// Extra writable tmpfs mount (repeatable; `none` clears the list).
    #[arg(long, value_name = "PATH|none", conflicts_with = "spec")]
    pub tmpfs: Vec<String>,
    /// Capability to drop, e.g. ALL (repeatable; `none` clears the list).
    #[arg(long, value_name = "CAP|none", conflicts_with = "spec")]
    pub cap_drop: Vec<String>,
    /// Capability to add back after --cap-drop (repeatable; `none` clears the list).
    #[arg(long, value_name = "CAP|none", conflicts_with = "spec")]
    pub cap_add: Vec<String>,
    /// Publish a container port directly on the host: `[IP:]HOST:CONTAINER` (repeatable; the bind
    /// address defaults to 127.0.0.1, `none` clears the list).
    #[arg(long = "host-port", value_name = "IP:HOST:CONTAINER", value_parser = parse_host_port, conflicts_with = "spec")]
    pub host_ports: Vec<HostPortFlag>,
    /// App that must be running before this one starts (repeatable; `none` clears the list).
    #[arg(long = "depends-on", value_name = "NAME|none", value_parser = parse_depends_on, conflicts_with = "spec")]
    pub depends_on: Vec<DependsOnFlag>,
    /// no-new-privileges (setuid and file capabilities cannot raise privileges).
    #[arg(long, value_name = "true|false", conflicts_with = "spec")]
    pub no_new_privileges: Option<bool>,
}

impl SpecFlags {
    pub fn is_empty(&self) -> bool {
        self.command.is_empty()
            && self.memory.is_none()
            && self.pids_limit.is_none()
            && self.cpus.is_none()
            && self.volumes.is_empty()
            && self.shared_volumes.is_empty()
            && !self.hardened
            && self.read_only.is_none()
            && self.tmpfs.is_empty()
            && self.cap_drop.is_empty()
            && self.cap_add.is_empty()
            && self.host_ports.is_empty()
            && self.depends_on.is_empty()
            && self.no_new_privileges.is_none()
    }

    /// Applies the flags to `spec`; everything not mentioned is kept.
    pub fn apply(&self, spec: &mut AppSpec) {
        // The command is an ordered argv, so --command replaces it as a whole instead of appending
        // (unlike the set-like --tmpfs/--cap-* lists); `none` drops it back to the image's own CMD.
        if !self.command.is_empty() {
            spec.command = self
                .command
                .iter()
                .filter(|arg| !arg.eq_ignore_ascii_case("none"))
                .cloned()
                .collect();
        }
        let r = &mut spec.resources;
        apply(&mut r.memory, &self.memory);
        apply(&mut r.pids_limit, &self.pids_limit);
        apply(&mut r.cpus, &self.cpus);
        for v in &self.volumes {
            spec.volumes.retain(|x| x.name != v.name);
            spec.volumes.push(v.clone());
        }
        for v in &self.shared_volumes {
            spec.shared_volumes.retain(|x| x.name != v.name);
            spec.shared_volumes.push(v.clone());
        }
        let sec = &mut spec.security;
        if self.hardened {
            sec.read_only = true;
            sec.no_new_privileges = true;
            if !sec.cap_drop.iter().any(|c| c == "ALL") {
                sec.cap_drop.push("ALL".into());
            }
        }
        if let Some(v) = self.read_only {
            sec.read_only = v;
        }
        if let Some(v) = self.no_new_privileges {
            sec.no_new_privileges = v;
        }
        extend_list(&mut sec.tmpfs, &self.tmpfs);
        extend_list(&mut sec.cap_drop, &upper(&self.cap_drop));
        extend_list(&mut sec.cap_add, &upper(&self.cap_add));
        apply_host_ports(&mut spec.host_ports, &self.host_ports);
        apply_depends_on(&mut spec.depends_on, &self.depends_on);
    }
}

/// `none` clears the list; other values are appended once each (the daemon validates them).
fn extend_list(list: &mut Vec<String>, values: &[String]) {
    for v in values {
        if v.eq_ignore_ascii_case("none") {
            list.clear();
        } else if !list.contains(v) {
            list.push(v.clone());
        }
    }
}

/// Capability names are case-insensitive on the command line; the spec stores them upper-case.
fn upper(caps: &[String]) -> Vec<String> {
    caps.iter()
        .map(|c| {
            if c.eq_ignore_ascii_case("none") {
                c.clone()
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect()
}

/// `none` clears the list; entries are appended once each. "Once" means the same effective socket
/// (`bind_ip()` resolves the loopback default), so `2222:22` does not duplicate an explicit
/// `127.0.0.1:2222:22`.
fn apply_host_ports(spec: &mut Vec<HostPort>, flags: &[HostPortFlag]) {
    for flag in flags {
        match flag {
            HostPortFlag::Clear => spec.clear(),
            HostPortFlag::Set(port) => {
                let duplicate = spec.iter().any(|p| {
                    p.host == port.host
                        && p.container == port.container
                        && p.bind_ip() == port.bind_ip()
                });
                if !duplicate {
                    spec.push(port.clone());
                }
            }
        }
    }
}

/// `none` clears the list; app names are appended once each and validated by the daemon
/// (an unknown target or a cycle is rejected when the spec is written, issue #35).
fn apply_depends_on(spec: &mut Vec<InstanceName>, flags: &[DependsOnFlag]) {
    for flag in flags {
        match flag {
            DependsOnFlag::Clear => spec.clear(),
            DependsOnFlag::Set(dep) => {
                if !spec.contains(dep) {
                    spec.push(dep.clone());
                }
            }
        }
    }
}

/// A known app name, or `none` to clear the list.
fn parse_depends_on(s: &str) -> Result<DependsOnFlag, String> {
    if s.eq_ignore_ascii_case("none") {
        return Ok(DependsOnFlag::Clear);
    }
    InstanceName::new(s)
        .map(DependsOnFlag::Set)
        .map_err(|e| e.to_string())
}

fn apply<T: Clone>(slot: &mut Option<T>, flag: &Option<Limit<T>>) {
    match flag {
        Some(Limit::Set(v)) => *slot = Some(v.clone()),
        Some(Limit::Unset) => *slot = None,
        None => {}
    }
}

fn limit<T>(s: &str, parse: impl FnOnce(&str) -> Result<T, String>) -> Result<Limit<T>, String> {
    if s.eq_ignore_ascii_case("none") {
        Ok(Limit::Unset)
    } else {
        parse(s).map(Limit::Set)
    }
}

fn parse_memory(s: &str) -> Result<Limit<MemoryLimit>, String> {
    limit(s, |s| MemoryLimit::parse(s).map_err(|e| e.to_string()))
}

fn parse_pids(s: &str) -> Result<Limit<u32>, String> {
    limit(s, |s| match s.parse::<u32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!(
            "invalid pids limit {s:?}: expected a positive integer"
        )),
    })
}

fn parse_cpus(s: &str) -> Result<Limit<CpuLimit>, String> {
    limit(s, |s| {
        let n: f64 = s
            .parse()
            .map_err(|_| format!("invalid cpu limit {s:?}: expected a number"))?;
        CpuLimit::try_from(n).map_err(|e| e.to_string())
    })
}

/// Splits `NAME=/PATH[:ro]` into its parts (`:ro` selects a read-only mount).
fn split_mount(s: &str) -> Result<(&str, &str, bool), String> {
    let (name, rest) = s
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=/PATH[:ro], got {s:?}"))?;
    let (target, read_only) = match rest.strip_suffix(":ro") {
        Some(t) => (t, true),
        None => (rest, false),
    };
    Ok((name, target, read_only))
}

fn parse_volume(s: &str) -> Result<VolumeMount, String> {
    let (name, target, read_only) = split_mount(s)?;
    if !valid_volume_name(name) {
        return Err(format!(
            "invalid volume name {name:?}: [a-z0-9-], 1–63 characters"
        ));
    }
    if !target.starts_with('/') {
        return Err(format!("volume path must be absolute, got {target:?}"));
    }
    Ok(VolumeMount {
        name: name.to_owned(),
        target: target.to_owned(),
        read_only,
    })
}

fn parse_shared_volume(s: &str) -> Result<SharedVolumeRef, String> {
    let (name, target, read_only) = split_mount(s)?;
    let name = SharedVolumeName::new(name).map_err(|e| e.to_string())?;
    if !target.starts_with('/') {
        return Err(format!(
            "shared volume path must be absolute, got {target:?}"
        ));
    }
    Ok(SharedVolumeRef {
        name,
        target: target.to_owned(),
        read_only,
    })
}

/// `[IP:]HOST:CONTAINER`, or `none` to clear the list. The host part is parsed from the right, so
/// unbracketed IPv6 literals also work; the spec stores a bare IP (no brackets).
fn parse_host_port(s: &str) -> Result<HostPortFlag, String> {
    if s.eq_ignore_ascii_case("none") {
        return Ok(HostPortFlag::Clear);
    }
    let syntax = || format!("invalid host port {s:?}: expected [IP:]HOST:CONTAINER");
    let (rest, container) = s.rsplit_once(':').ok_or_else(syntax)?;
    let container = port_number(container, s)?;
    let (ip, host) = match rest.rsplit_once(':') {
        Some((ip, host)) => (Some(ip), host),
        None => (None, rest),
    };
    let host = port_number(host, s)?;
    let ip = match ip {
        None => None,
        Some(raw) => {
            let bare = raw
                .strip_prefix('[')
                .and_then(|r| r.strip_suffix(']'))
                .unwrap_or(raw);
            let parsed: std::net::IpAddr = bare
                .parse()
                .map_err(|_| format!("invalid host port {s:?}: {raw:?} is not an IP literal"))?;
            Some(parsed.to_string())
        }
    };
    Ok(HostPortFlag::Set(HostPort {
        host,
        container,
        ip,
    }))
}

/// A non-zero TCP port from the flag value.
fn port_number(raw: &str, s: &str) -> Result<u16, String> {
    match raw.parse::<u16>() {
        Ok(0) => Err(format!(
            "invalid host port {s:?}: host and container ports must be non-zero"
        )),
        Ok(n) => Ok(n),
        Err(_) => Err(format!(
            "invalid host port {s:?}: {raw:?} is not a port number"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_limits_and_none() {
        assert_eq!(parse_pids("64").unwrap(), Limit::Set(64));
        assert_eq!(parse_pids("none").unwrap(), Limit::Unset);
        assert!(parse_pids("0").is_err());
        assert!(matches!(parse_memory("128m").unwrap(), Limit::Set(m) if m.bytes() == 128 << 20));
        assert!(parse_memory("lots").is_err());
        assert!(matches!(parse_cpus("0.5").unwrap(), Limit::Set(c) if c.millis() == 500));
    }

    #[test]
    fn apply_replaces_and_clears_the_command() {
        let mut spec: AppSpec = toml::from_str("image = \"i\"\ncommand = [\"serve\"]\n").unwrap();
        let flags = SpecFlags {
            command: vec!["serve".into(), "--no-log".into()],
            ..SpecFlags::default()
        };
        assert!(!flags.is_empty(), "the flag counts as an edit");
        flags.apply(&mut spec);
        assert_eq!(
            spec.command,
            ["serve", "--no-log"],
            "replaced as a whole, not appended to the existing command"
        );

        SpecFlags {
            command: vec!["none".into()],
            ..SpecFlags::default()
        }
        .apply(&mut spec);
        assert!(spec.command.is_empty(), "none restores the image's own CMD");

        // Not giving the flag keeps the spec untouched.
        SpecFlags::default().apply(&mut spec);
        assert!(spec.command.is_empty());
    }

    #[test]
    fn parses_volumes() {
        let v = parse_volume("data=/data:ro").unwrap();
        assert_eq!(
            (v.name.as_str(), v.target.as_str(), v.read_only),
            ("data", "/data", true)
        );
        assert!(!parse_volume("data=/data").unwrap().read_only);
        assert!(parse_volume("Data=/data").is_err());
        assert!(parse_volume("data=relative").is_err());
        assert!(parse_volume("/data").is_err());
    }

    #[test]
    fn parses_shared_volumes() {
        let v = parse_shared_volume("kajet-data=/data").unwrap();
        assert_eq!(
            (v.name.as_str(), v.target.as_str(), v.read_only),
            ("kajet-data", "/data", false)
        );
        let ro = parse_shared_volume("kajet-data=/data:ro").unwrap();
        assert!(ro.read_only);
        // The name has to be a valid shared volume name; the path has to be absolute.
        assert!(parse_shared_volume("Kajet_Data=/data").is_err());
        assert!(parse_shared_volume("kajet-data=relative").is_err());
        assert!(parse_shared_volume("kajet-data").is_err());
        assert!(parse_shared_volume("/data").is_err());
    }

    #[test]
    fn apply_replaces_a_shared_volume_of_the_same_name() {
        let mut spec = toml::from_str::<AppSpec>(
            "image = \"i\"\nshared_volumes = [{ name = \"kajet-data\", target = \"/old\" }]\n",
        )
        .unwrap();
        let flags = SpecFlags {
            shared_volumes: vec![parse_shared_volume("kajet-data=/data:ro").unwrap()],
            ..SpecFlags::default()
        };
        assert!(!flags.is_empty());
        flags.apply(&mut spec);
        assert_eq!(spec.shared_volumes.len(), 1);
        assert_eq!(spec.shared_volumes[0].target, "/data");
        assert!(spec.shared_volumes[0].read_only);

        // Like --volume, --shared-volume conflicts with --spec.
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Add {
            #[command(flatten)]
            _a: crate::cli::AddArgs,
        }
        assert!(
            Add::try_parse_from([
                "add",
                "ntfy",
                "ghcr.io/x/ntfy:latest",
                "--shared-volume",
                "kajet-data=/data",
                "--spec",
                "f",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_host_ports() {
        let set = |s: &str| match parse_host_port(s).unwrap() {
            HostPortFlag::Set(p) => p,
            HostPortFlag::Clear => panic!("{s}: expected an entry"),
        };
        let p = set("2222:22");
        assert_eq!((p.host, p.container, p.ip.as_deref()), (2222, 22, None));
        let p = set("0.0.0.0:2222:22");
        assert_eq!(p.ip.as_deref(), Some("0.0.0.0"));
        let p = set("[::1]:2222:22");
        assert_eq!(p.ip.as_deref(), Some("::1"));
        let p = set("::1:2222:22");
        assert_eq!(p.ip.as_deref(), Some("::1"));
        assert_eq!(parse_host_port("none").unwrap(), HostPortFlag::Clear);
        assert_eq!(parse_host_port("NONE").unwrap(), HostPortFlag::Clear);
        // zero ports, garbage and a bogus address are rejected
        assert!(parse_host_port("2222:0").is_err());
        assert!(parse_host_port("0:22").is_err());
        assert!(parse_host_port("garbage").is_err());
        assert!(parse_host_port("2222:http").is_err());
        assert!(parse_host_port("1:2:3:4").is_err());
        assert!(parse_host_port("99999:22").is_err());
    }

    #[test]
    fn apply_appends_dedupes_and_clears_host_ports() {
        let mut spec: AppSpec =
            toml::from_str("image = \"i\"\nhost_ports = [{ host = 2222, container = 22 }]\n")
                .unwrap();
        SpecFlags {
            host_ports: vec![
                parse_host_port("127.0.0.1:2222:22").unwrap(),
                parse_host_port("2223:22").unwrap(),
            ],
            ..SpecFlags::default()
        }
        .apply(&mut spec);
        assert_eq!(
            spec.host_ports.len(),
            2,
            "the explicit loopback entry duplicates the default one"
        );
        assert_eq!(spec.host_ports[1].host, 2223);
        let only_host_port = SpecFlags {
            host_ports: vec![parse_host_port("2223:22").unwrap()],
            ..SpecFlags::default()
        };
        assert!(!only_host_port.is_empty());

        SpecFlags {
            host_ports: vec![parse_host_port("none").unwrap()],
            ..SpecFlags::default()
        }
        .apply(&mut spec);
        assert!(spec.host_ports.is_empty());
    }

    #[test]
    fn apply_sets_unsets_and_replaces_volumes() {
        let mut spec: AppSpec = toml::from_str(
            r#"
image = "i"
volumes = [{ name = "data", target = "/old" }]
resources = { memory = "64m", pids_limit = 10 }
"#,
        )
        .unwrap();
        let flags = SpecFlags {
            memory: Some(Limit::Set(MemoryLimit::parse("128m").unwrap())),
            pids_limit: Some(Limit::Unset),
            volumes: vec![parse_volume("data=/data").unwrap()],
            ..SpecFlags::default()
        };
        flags.apply(&mut spec);
        assert!(
            spec.security.is_default(),
            "no hardening flags, no hardening"
        );
        assert_eq!(spec.resources.memory.unwrap().bytes(), 128 << 20);
        assert_eq!(spec.resources.pids_limit, None);
        assert_eq!(spec.volumes.len(), 1);
        assert_eq!(spec.volumes[0].target, "/data");
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn spec() -> AppSpec {
        toml::from_str("image = \"i\"").unwrap()
    }

    #[test]
    fn hardened_preset_then_adjustments() {
        let mut s = spec();
        SpecFlags {
            hardened: true,
            tmpfs: vec!["/cache".into()],
            cap_add: vec!["net_bind_service".into()],
            ..SpecFlags::default()
        }
        .apply(&mut s);
        let sec = &s.security;
        assert!(sec.read_only && sec.no_new_privileges);
        assert_eq!(sec.cap_drop, ["ALL"]);
        assert_eq!(sec.cap_add, ["NET_BIND_SERVICE"]);
        assert_eq!(sec.tmpfs, ["/cache"]);

        // Update: switch one thing off and clear a list.
        SpecFlags {
            read_only: Some(false),
            cap_add: vec!["none".into()],
            ..SpecFlags::default()
        }
        .apply(&mut s);
        assert!(!s.security.read_only && s.security.no_new_privileges);
        assert!(s.security.cap_add.is_empty());
        assert_eq!(s.security.cap_drop, ["ALL"], "untouched");
    }

    #[test]
    fn depends_on_flag_appends_once_and_none_clears() {
        let mut s = spec();
        SpecFlags {
            depends_on: vec![
                DependsOnFlag::Set(InstanceName::new("db").unwrap()),
                DependsOnFlag::Set(InstanceName::new("cache").unwrap()),
                DependsOnFlag::Set(InstanceName::new("db").unwrap()),
            ],
            ..SpecFlags::default()
        }
        .apply(&mut s);
        assert_eq!(
            s.depends_on,
            [
                InstanceName::new("db").unwrap(),
                InstanceName::new("cache").unwrap()
            ]
        );
        SpecFlags {
            depends_on: vec![DependsOnFlag::Clear],
            ..SpecFlags::default()
        }
        .apply(&mut s);
        assert!(s.depends_on.is_empty());

        assert_eq!(parse_depends_on("none").unwrap(), DependsOnFlag::Clear);
        assert_eq!(
            parse_depends_on("db").unwrap(),
            DependsOnFlag::Set(InstanceName::new("db").unwrap())
        );
        assert!(parse_depends_on("DB").is_err());
    }
}
