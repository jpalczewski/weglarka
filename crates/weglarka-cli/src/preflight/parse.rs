//! Pure parsers and assessments (no I/O) — easy to test.

use std::path::Path;

use super::RuntimeUser;
use super::host::{FileStat, Host, PingInfo};

/// `getent passwd <name>`, and when it's unavailable — `/etc/passwd`.
pub fn lookup_user(host: &dyn Host, name: &str) -> Option<RuntimeUser> {
    if let Ok(out) = host.run("getent", &["passwd", name])
        && out.success
        && let Some(u) = out.stdout.lines().find_map(|l| parse_passwd_line(l, name))
    {
        return Some(u);
    }
    host.read_to_string(Path::new("/etc/passwd"))
        .ok()?
        .lines()
        .find_map(|l| parse_passwd_line(l, name))
}

pub fn parse_passwd_line(line: &str, name: &str) -> Option<RuntimeUser> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 6 || f[0] != name {
        return None;
    }
    Some(RuntimeUser {
        name: name.to_owned(),
        uid: f[2].parse().ok()?,
        gid: f[3].parse().ok()?,
        home: f[5].into(),
    })
}

/// User's GIDs: primary group + membership from `/etc/group`.
pub fn gids_of(host: &dyn Host, user: &RuntimeUser) -> Vec<u32> {
    let mut gids = vec![user.gid];
    if let Ok(src) = host.read_to_string(Path::new("/etc/group")) {
        for line in src.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 4
                && f[3].split(',').any(|m| m == user.name)
                && let Ok(g) = f[2].parse()
            {
                gids.push(g);
            }
        }
    }
    gids
}

/// Sum of range sizes from `/etc/subuid`|`/etc/subgid` for the user (by name or uid).
pub fn subid_total(src: &str, user: &RuntimeUser) -> u64 {
    let uid = user.uid.to_string();
    src.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.trim().split(':').collect();
            (f.len() == 3 && (f[0] == user.name || f[0] == uid))
                .then(|| f[2].parse::<u64>().ok())
                .flatten()
        })
        .sum()
}

pub fn parse_ping_response(raw: &str) -> Option<PingInfo> {
    let mut lines = raw.lines();
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let status = parts.next()?.parse().ok()?;
    let libpod_api_version = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("libpod-api-version")
            .then(|| v.trim().to_owned())
    });
    Some(PingInfo {
        status,
        libpod_api_version,
    })
}

/// First `X.Y[.Z]` token in the text → `(major, minor)`.
pub fn parse_major_minor(text: &str) -> Option<(u32, u32)> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find_map(|tok| {
            let mut it = tok.split('.');
            let major = it.next()?.parse().ok()?;
            let minor = it.next()?.parse().ok()?;
            Some((major, minor))
        })
}

/// Whether, in the `apt-cache policy <pkg>` output, the installed version comes from a source
/// containing `needle`. `None` — can't be determined (no installed version).
pub fn apt_installed_from(policy: &str, needle: &str) -> Option<bool> {
    let installed = policy
        .lines()
        .find_map(|l| l.trim().strip_prefix("Installed:"))?
        .trim();
    if installed == "(none)" {
        return None;
    }
    // Version lines are indented ≤ 5 (installed: ` *** …`), source lines ≥ 6.
    let mut in_installed = false;
    let mut found = false;
    for line in policy
        .lines()
        .skip_while(|l| !l.contains("Version table"))
        .skip(1)
    {
        let indent = line.len() - line.trim_start().len();
        if indent <= 5 {
            in_installed = line.contains("***");
        } else if in_installed && line.contains(needle) {
            found = true;
        }
    }
    Some(found)
}

/// Whether a process with `uid`/`gids` could write the file (classic mode bits; ACLs ignored).
pub fn can_write(stat: &FileStat, uid: u32, gids: &[u32]) -> bool {
    if uid == 0 {
        return true;
    }
    if stat.uid == uid {
        stat.mode & 0o200 != 0
    } else if gids.contains(&stat.gid) {
        stat.mode & 0o020 != 0
    } else {
        stat.mode & 0o002 != 0
    }
}

/// A listening socket (TCP LISTEN) from `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    /// `None` = unspecified address (`0.0.0.0` / `::`); IPv6 addresses other than `::` are skipped.
    pub addr: Option<std::net::Ipv4Addr>,
    pub port: u16,
    pub uid: u32,
}

/// LISTEN entries from `/proc/net/tcp` (`v6 = false`) or `/proc/net/tcp6` (`v6 = true`).
pub fn parse_proc_net_tcp(src: &str, v6: bool) -> Vec<Listener> {
    src.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 || f[3] != "0A" {
                return None;
            }
            let (host, port) = f[1].split_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            let uid = f[7].parse().ok()?;
            let addr = if v6 {
                // only `::` (dual-stack wildcard); other v6 addresses don't collide with v4
                host.bytes().all(|b| b == b'0').then_some(None)?
            } else {
                // /proc stores an IPv4 address as little-endian hex
                let raw = u32::from_str_radix(host, 16).ok()?;
                (raw != 0).then(|| std::net::Ipv4Addr::from(raw.swap_bytes()))
            };
            Some(Listener { addr, port, uid })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn major_minor() {
        assert_eq!(parse_major_minor("netavark 2.0.1"), Some((2, 0)));
        assert_eq!(parse_major_minor("6.1.0"), Some((6, 1)));
    }

    #[test]
    fn apt_policy_origin() {
        let alv = "podman:\n  Installed: 6.1.0-1\n  Candidate: 6.1.0-1\n  Version table:\n *** 6.1.0-1 1001\n       1001 https://downloadcontent.opensuse.org/repositories/home:/alvistack/xUbuntu_24.04  Packages\n        100 /var/lib/dpkg/status\n     4.9.3+ds1-1ubuntu0.2 500\n        500 http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages\n";
        assert_eq!(apt_installed_from(alv, "alvistack"), Some(true));
        let ubu = "podman:\n  Installed: 4.9.3+ds1-1ubuntu0.2\n  Candidate: 6.1.0-1\n  Version table:\n     6.1.0-1 1001\n       1001 https://downloadcontent.opensuse.org/repositories/home:/alvistack/xUbuntu_24.04  Packages\n *** 4.9.3+ds1-1ubuntu0.2 500\n        500 http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages\n        100 /var/lib/dpkg/status\n";
        assert_eq!(apt_installed_from(ubu, "alvistack"), Some(false));
        assert_eq!(
            apt_installed_from("podman:\n  Installed: (none)\n", "alvistack"),
            None
        );
    }

    #[test]
    fn subid_sums_ranges() {
        let u = RuntimeUser {
            name: "weglarka".into(),
            uid: 1001,
            gid: 1001,
            home: "/home/weglarka".into(),
        };
        let src = "erxyi:100000:65536\nweglarka:165536:65536\n1001:300000:1000\n";
        assert_eq!(subid_total(src, &u), 66536);
    }

    #[test]
    fn write_permission_by_class() {
        let s = |mode, uid, gid| FileStat {
            kind: crate::preflight::host::FileKind::File,
            mode,
            uid,
            gid,
        };
        assert!(can_write(&s(0o600, 1001, 1001), 1001, &[1001]));
        assert!(!can_write(&s(0o400, 1001, 1001), 1001, &[1001]));
        assert!(can_write(&s(0o660, 5, 77), 1001, &[1001, 77]));
        assert!(!can_write(&s(0o644, 5, 77), 1001, &[1001, 77]));
    }

    #[test]
    fn ping_response() {
        let r = "HTTP/1.1 200 OK\r\nLibpod-Api-Version: 6.1.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_ping_response(r),
            Some(PingInfo {
                status: 200,
                libpod_api_version: Some("6.1.0".into())
            })
        );
        assert_eq!(parse_ping_response("garbage"), None);
    }

    #[test]
    fn proc_net_tcp_listeners() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0\n   1: 0100007F:0050 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1000        0 2 1 0\n   2: 00000000:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1004        0 3 1 0\n";
        let l = parse_proc_net_tcp(v4, false);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].addr, Some("127.0.0.1".parse().unwrap()));
        assert_eq!((l[0].port, l[0].uid), (8080, 0));
        assert_eq!((l[1].addr, l[1].port, l[1].uid), (None, 9000, 1004));
        let v6 = "  sl  local_address rem_address st tx rx tr tm retr uid timeout inode\n   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 0 1\n   1: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 0 1\n";
        let l = parse_proc_net_tcp(v6, true);
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].addr, l[0].port), (None, 8080));
    }
}
