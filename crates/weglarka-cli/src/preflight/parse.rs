//! Czyste parsery i oceny (bez I/O) — łatwe do testowania.

use std::path::Path;

use super::RuntimeUser;
use super::host::{FileStat, Host, PingInfo};

/// `getent passwd <name>`, a gdy go nie ma — `/etc/passwd`.
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

/// GID-y użytkownika: grupa główna + członkostwo z `/etc/group`.
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

/// Suma rozmiarów zakresów z `/etc/subuid`|`/etc/subgid` dla usera (po nazwie lub uid).
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

/// Pierwszy ciąg `X.Y[.Z]` w tekście → `(major, minor)`.
pub fn parse_major_minor(text: &str) -> Option<(u32, u32)> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find_map(|tok| {
            let mut it = tok.split('.');
            let major = it.next()?.parse().ok()?;
            let minor = it.next()?.parse().ok()?;
            Some((major, minor))
        })
}

/// Czy w wyjściu `apt-cache policy <pkg>` zainstalowana wersja pochodzi ze źródła zawierającego
/// `needle`. `None` — nie da się ustalić (brak wersji zainstalowanej).
pub fn apt_installed_from(policy: &str, needle: &str) -> Option<bool> {
    let installed = policy
        .lines()
        .find_map(|l| l.trim().strip_prefix("Installed:"))?
        .trim();
    if installed == "(none)" {
        return None;
    }
    // Wiersze wersji mają wcięcie ≤ 5 (zainstalowana: ` *** …`), wiersze źródeł ≥ 6.
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

/// Czy proces z `uid`/`gids` mógłby zapisać plik (klasyczne bity; ACL-e pomijane).
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
}
