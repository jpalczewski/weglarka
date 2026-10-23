//! Spec flags shared by `apps add` and `apps update`: resource limits, volumes and hardening.
//! Before these existed, they could only be set through `--spec <file.toml>`.

use clap::Args;
use weglarka_core::app::{AppSpec, CpuLimit, MemoryLimit, VolumeMount, valid_volume_name};

/// Value of a limit flag: a limit, or `none` to drop it (no limit is the default).
#[derive(Debug, Clone, PartialEq)]
pub enum Limit<T> {
    Set(T),
    Unset,
}

/// Limits and volumes; flattened into `AddArgs` and `UpdateArgs`.
#[derive(Debug, Default, Args)]
pub struct SpecFlags {
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
    /// no-new-privileges (setuid and file capabilities cannot raise privileges).
    #[arg(long, value_name = "true|false", conflicts_with = "spec")]
    pub no_new_privileges: Option<bool>,
}

impl SpecFlags {
    pub fn is_empty(&self) -> bool {
        self.memory.is_none()
            && self.pids_limit.is_none()
            && self.cpus.is_none()
            && self.volumes.is_empty()
            && !self.hardened
            && self.read_only.is_none()
            && self.tmpfs.is_empty()
            && self.cap_drop.is_empty()
            && self.cap_add.is_empty()
            && self.no_new_privileges.is_none()
    }

    /// Applies the flags to `spec`; everything not mentioned is kept.
    pub fn apply(&self, spec: &mut AppSpec) {
        let r = &mut spec.resources;
        apply(&mut r.memory, &self.memory);
        apply(&mut r.pids_limit, &self.pids_limit);
        apply(&mut r.cpus, &self.cpus);
        for v in &self.volumes {
            spec.volumes.retain(|x| x.name != v.name);
            spec.volumes.push(v.clone());
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

fn parse_volume(s: &str) -> Result<VolumeMount, String> {
    let (name, rest) = s
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=/PATH[:ro], got {s:?}"))?;
    let (target, read_only) = match rest.strip_suffix(":ro") {
        Some(t) => (t, true),
        None => (rest, false),
    };
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
}
