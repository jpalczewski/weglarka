//! Supplementary groups of the systemd user manager (issue #191).
//!
//! `group_add` is crun `keep-groups`: a container keeps whatever supplementary groups the runtime
//! user's processes have ([ADR 0045](../../../docs/decisions/0045-host-mounts.md)). Those processes
//! inherit their credentials from the **user manager** (`systemd --user`), so adding the runtime user
//! to a group with `usermod -aG` and restarting `podman.socket`/`podman.service` changes nothing —
//! units keep the credential set the user manager was started with. Measured on rootless Podman 6.1.3
//! (Debian 13, linger on): only `systemctl restart user@<uid>` (or a reboot) applies a new group; the
//! containers of that user stop with it.
//!
//! Checking inside the user namespace is not an option: a keep-groups container reports an unmapped
//! supplementary gid as the overflow gid, which libpod's `top … hgroups` maps back through the subgid
//! range (a group 2001 showed as 231069), so a comparison there reports false failures. Instead the
//! **host-side** watchdog (`weglarka-daemon supervise`, the only process that runs as the runtime user
//! on the host) compares the user's groups as `/etc/group` records them with the credentials its own
//! `/proc/self/status` shows, and records the difference here. `doctor` turns a recorded difference
//! into a warning.
//!
//! The finding lives in its own file in the state directory (`<state dir>/user-groups.toml`, mode
//! 0600) and is **tolerant** like `self-update.toml` and `webhook-deliveries.toml`: no
//! `schema_version` marker, unknown fields ignored, a missing file means "no finding". It is internal
//! bookkeeping, so an older or newer daemon must not be stopped by it, and it needs no schema bump
//! (ADR 0023, ADR 0035).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File in the state directory (written on the host, read by the daemon container).
pub const FILE_NAME: &str = "user-groups.toml";
/// Internal bookkeeping, like `self-update.toml` and `notifications.toml`.
pub const FILE_MODE: u32 = 0o600;

#[derive(Debug, thiserror::Error)]
pub enum UserGroupsError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

/// One group that names the user in `/etc/group`, but that the user manager's credentials lack.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MissingGroup {
    pub name: String,
    pub gid: u32,
}

/// What the last host-side check found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserGroupsState {
    /// The runtime user the check read (`[runtime] user`).
    pub user: String,
    /// Its uid: the instance of the `user@<uid>` unit the operator has to restart.
    pub uid: u32,
    /// Groups of `/etc/group` that the user manager's credentials do not hold, in file order.
    pub missing: Vec<MissingGroup>,
    /// Unix seconds of the check that recorded this finding (kept while the finding is unchanged).
    pub checked_at: u64,
}

/// One parsed `/etc/group` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    /// The supplementary members; the primary members of a group are not listed here (that is
    /// `/etc/passwd`'s gid field) and do not matter for this check.
    pub members: Vec<String>,
}

impl UserGroupsState {
    /// Whether the user manager is behind `/etc/group` at all.
    pub fn is_stale(&self) -> bool {
        !self.missing.is_empty()
    }

    /// The missing groups as names, in the recorded order.
    pub fn names(&self) -> Vec<&str> {
        self.missing
            .iter()
            .map(|group| group.name.as_str())
            .collect()
    }
}

pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join(FILE_NAME)
}

/// Reads the last finding; `None` when the host-side check has not recorded one (or the daemon has no
/// access to the state directory of the runtime user).
pub fn load(state_dir: &Path) -> Result<Option<UserGroupsState>, UserGroupsError> {
    let path = path(state_dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(UserGroupsError::Read { path, source }),
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|e| UserGroupsError::Parse {
            path,
            message: e.to_string(),
        })
}

pub fn save(state_dir: &Path, state: &UserGroupsState) -> Result<(), UserGroupsError> {
    let path = path(state_dir);
    let text = toml::to_string(state).map_err(|e| UserGroupsError::Parse {
        path: path.clone(),
        message: e.to_string(),
    })?;
    crate::fsutil::write_atomic(&path, text.as_bytes(), FILE_MODE)
        .map_err(|source| UserGroupsError::Write { path, source })
}

/// Parses `/etc/group`. Malformed lines are skipped: the file is not ours, and one odd entry must not
/// hide the others.
pub fn group_entries(group_file: &str) -> Vec<GroupEntry> {
    group_file
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.trim();
            // The password field is never used (`x` or empty) but must be skipped.
            let _password = fields.next()?;
            let gid = fields.next()?.trim().parse().ok()?;
            let members = fields
                .next()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|member| !member.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            (!name.is_empty()).then(|| GroupEntry {
                name: name.to_owned(),
                gid,
                members,
            })
        })
        .collect()
}

/// The `(uid, primary gid)` of `user` from `/etc/passwd`.
pub fn primary_ids(passwd: &str, user: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != user {
            return None;
        }
        let _password = fields.next()?;
        let uid: u32 = fields.next()?.parse().ok()?;
        let gid: u32 = fields.next()?.parse().ok()?;
        Some((uid, gid))
    })
}

/// The supplementary gids of a `/proc/<pid>/status` (`Groups:` line, space separated). `None` when the
/// line is absent — then the credentials are unknown and the check must stay silent.
pub fn status_groups(status: &str) -> Option<Vec<u32>> {
    status.lines().find_map(|line| {
        let gids = line.strip_prefix("Groups:")?;
        Some(
            gids.split_whitespace()
                .filter_map(|g| g.parse().ok())
                .collect(),
        )
    })
}

/// The groups of `/etc/group` that name `user` but are not among `have` (the `Groups:` line of the
/// process): the difference the user manager still lacks.
///
/// This is the `getgrouplist` question without libc: `/etc/group` has no nested groups, so the
/// primary gid plus every group listing the user is exactly the set every login of that user gets.
/// Groups that only exist in NSS (LDAP, SSSD) are not in the file and therefore never reported.
pub fn missing_groups(entries: &[GroupEntry], user: &str, have: &[u32]) -> Vec<MissingGroup> {
    entries
        .iter()
        .filter(|entry| entry.members.iter().any(|member| member == user))
        .filter(|entry| !have.contains(&entry.gid))
        .map(|entry| MissingGroup {
            name: entry.name.clone(),
            gid: entry.gid,
        })
        .collect()
}

/// Builds the finding from the three files the host-side check reads: `/etc/passwd`, `/etc/group` and
/// the check's own `/proc/self/status`.
///
/// `None` when the files cannot answer the question (the user is not in `/etc/passwd`, the status has
/// no `Groups:` line): a check that cannot see the facts must not invent a warning.
pub fn inspect(
    passwd: &str,
    group_file: &str,
    status: &str,
    user: &str,
    now: u64,
) -> Option<UserGroupsState> {
    let (uid, _) = primary_ids(passwd, user)?;
    let have = status_groups(status)?;
    Some(UserGroupsState {
        user: user.to_owned(),
        uid,
        missing: missing_groups(&group_entries(group_file), user, &have),
        checked_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
weglarka:x:1001:1001::/home/weglarka:/bin/sh
";

    const GROUP: &str = "\
root:x:0:
users:x:100:alice,bob
weglarka:x:1001:
systemd-journal:x:999:weglarka
docker:x:998:weglarka,alice
adm:x:4:
";

    fn status(gids: &[u32]) -> String {
        let list: Vec<String> = gids.iter().map(ToString::to_string).collect();
        format!(
            "Name:\tweglarka-daemon\nUid:\t1001\t1001\t1001\t1001\nGroups:\t{}\n",
            list.join("\t")
        )
    }

    #[test]
    fn a_group_in_etc_group_that_the_credentials_lack_is_reported() {
        // Issue #191: `usermod -aG systemd-journal` without a `user@<uid>` restart — the user
        // manager's credentials still hold only the primary and `docker`.
        let found = inspect(
            PASSWD,
            GROUP,
            &status(&[1001, 998]),
            "weglarka",
            1_770_000_000,
        )
        .expect("the files answer the question");
        assert_eq!(
            found.missing,
            vec![MissingGroup {
                name: "systemd-journal".to_owned(),
                gid: 999
            }]
        );
        assert_eq!(found.uid, 1001);
        assert_eq!(found.user, "weglarka");
        assert!(found.is_stale());
        assert_eq!(found.names(), vec!["systemd-journal"]);
    }

    #[test]
    fn credentials_that_hold_every_group_are_clean() {
        let found = inspect(
            PASSWD,
            GROUP,
            &status(&[1001, 999, 998]),
            "weglarka",
            1_770_000_000,
        )
        .expect("the files answer the question");
        assert!(found.missing.is_empty());
        assert!(!found.is_stale());
    }

    #[test]
    fn groups_of_other_users_and_the_primary_group_do_not_count() {
        // `users` names alice and bob, `adm` names nobody, and the primary gid needs no member list:
        // only groups that name the runtime user can make the credentials stale.
        let entries = group_entries(GROUP);
        assert!(missing_groups(&entries, "weglarka", &[1001]).len() == 2);
        assert!(missing_groups(&entries, "alice", &[100, 998]).is_empty());
        assert!(missing_groups(&entries, "nobody", &[]).is_empty());
    }

    #[test]
    fn an_unanswerable_host_stays_silent() {
        // No such user in `/etc/passwd` (a container, a renamed user).
        assert!(
            inspect(PASSWD, GROUP, &status(&[1001]), "ghost", 1_770_000_000).is_none(),
            "an unknown user is not a finding"
        );
        // A `/proc/<pid>/status` without a `Groups:` line.
        assert!(inspect(PASSWD, GROUP, "Name:\tsystemd\n", "weglarka", 1).is_none());
    }

    #[test]
    fn malformed_group_lines_are_skipped() {
        let entries = group_entries("garbage\n# comment\nbroken:x:notanumber:a\nok:x:7:weglarka\n");
        assert_eq!(
            entries,
            vec![GroupEntry {
                name: "ok".to_owned(),
                gid: 7,
                members: vec!["weglarka".to_owned()],
            }]
        );
    }

    #[test]
    fn the_finding_round_trips_and_ignores_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()).unwrap(), None);

        let state = UserGroupsState {
            user: "weglarka".to_owned(),
            uid: 1001,
            missing: vec![MissingGroup {
                name: "systemd-journal".to_owned(),
                gid: 999,
            }],
            checked_at: 1_770_000_000,
        };
        save(dir.path(), &state).unwrap();
        assert_eq!(load(dir.path()).unwrap(), Some(state.clone()));

        // Tolerant bookkeeping: a newer host-side check may write fields this daemon does not know.
        let text = std::fs::read_to_string(path(dir.path())).unwrap();
        std::fs::write(
            path(dir.path()),
            format!("{text}\nfuture_field = 1\n\n[[future]]\nname = \"x\"\n"),
        )
        .unwrap();
        assert_eq!(load(dir.path()).unwrap(), Some(state.clone()));
    }
}
