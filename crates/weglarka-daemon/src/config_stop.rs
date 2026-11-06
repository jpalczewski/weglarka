//! A `weglarka.toml` the host binaries cannot parse (issue #617).
//!
//! The switcher and the watchdog are host binaries that a self-update does not replace. When the
//! operator adds a key that only the newer running daemon knows, `HostConfig`'s
//! `deny_unknown_fields` stops them in `Settings::load`, before anything reaches
//! `self-update.toml`, so `doctor` (which runs in the daemon and parses the config fine) could not
//! name the cause. The parse stays strict; this module only leaves the trace: it finds the state
//! directory without the strict parse and records the stop like stale host tools.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use weglarka_model::config::StateConfig;
use weglarka_model::self_update as state;

use crate::self_update::lock_state;
use crate::settings::SettingsError;

/// The same bound the launcher uses for `weglarka.toml`.
const CONFIG_LIMIT: usize = 1024 * 1024;

/// The state directory `weglarka.toml` points at, read without the strict `HostConfig` parse:
/// `[state] dir` when it is a string, otherwise the default. `None` when the file cannot be read or
/// is not TOML at all, or `state.dir` is not a string.
///
/// The resolution is `Settings`' own (`Paths::resolve` → `StateConfig::dir_or(config_dir)`), so
/// the record lands where the daemon's `doctor` and the next working run read it.
pub fn state_dir_hint(config_path: &Path) -> Option<PathBuf> {
    let text =
        weglarka_launcher::host::read_required(config_path, "weglarka.toml", CONFIG_LIMIT).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    let dir = match table.get("state") {
        None => None,
        Some(toml::Value::Table(section)) => match section.get("dir") {
            None => None,
            Some(toml::Value::String(dir)) => Some(PathBuf::from(dir)),
            Some(_) => return None,
        },
        Some(_) => return None,
    };
    let config_dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Some(StateConfig { dir }.dir_or(config_dir))
}

/// Records in `self-update.toml` that the host binaries cannot parse `config_path`, and says
/// whether the file was written.
///
/// Only a parse error is recorded (a key this binary does not know, or any other TOML/serde
/// error); a readable config the daemon rejects for other reasons is not a host-binary problem.
/// Nothing is written when the state directory cannot be determined or does not exist (it is never
/// created), when another host-side run holds the lock, or when the same stop is already recorded —
/// the watchdog wakes every minute and must not rewrite the file each time. Failures here are only
/// logged: the caller returns the original error either way.
pub fn record_unparsable_config(
    config_path: &Path,
    error: &SettingsError,
    now: SystemTime,
) -> bool {
    let SettingsError::Parse { message, .. } = error else {
        return false;
    };
    let Some(state_dir) = state_dir_hint(config_path) else {
        return false;
    };
    if !state_dir.is_dir() {
        return false;
    }
    let _lock = match lock_state(&state_dir) {
        Ok(Some(lock)) => lock,
        Ok(None) => return false,
        Err(e) => {
            tracing::warn!(error = %e, "cannot record the unparsable configuration");
            return false;
        }
    };
    let mut st = match state::load(&state_dir) {
        Ok(st) => st,
        Err(e) => {
            tracing::warn!(error = %e, "cannot record the unparsable configuration");
            return false;
        }
    };
    let reason = state::unparsable_config_message(message);
    if st
        .error
        .as_ref()
        .is_some_and(|e| e.host_tools_stale && e.message == reason)
    {
        return false;
    }
    st.record_unparsable_config(message, now);
    match state::save(&state_dir, &st) {
        Ok(()) => {
            tracing::error!(
                "self-update stopped: the host binaries cannot parse the configuration (recorded for doctor)"
            );
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "cannot record the unparsable configuration");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{Paths, Settings};
    use std::time::Duration;
    use weglarka_model::config::HostConfig;

    const HOST: &str = r#"
[ingress]
mode = "behind"
bind = "127.0.0.1:18082"
traefik_dynamic_file = "/tmp/traefik.yml"

[admin]
socket = "/tmp/admin.sock"

[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.org"
"#;

    fn write(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("weglarka.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    /// What `Settings` resolves for the same file, parsed strictly.
    fn resolved(path: &Path) -> PathBuf {
        let host = HostConfig::from_toml_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        Paths::resolve(&host, path).state_dir
    }

    #[test]
    fn the_hint_follows_the_settings_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            &format!("{HOST}\n[state]\ndir = \"/var/lib/weglarka\"\n"),
        );
        assert_eq!(
            state_dir_hint(&path),
            Some(PathBuf::from("/var/lib/weglarka"))
        );
        assert_eq!(state_dir_hint(&path), Some(resolved(&path)));

        let path = write(dir.path(), &format!("{HOST}\n[state]\ndir = \"data\"\n"));
        assert_eq!(state_dir_hint(&path), Some(resolved(&path)), "relative");

        let path = write(dir.path(), HOST);
        assert_eq!(state_dir_hint(&path), Some(dir.path().to_owned()));
        assert_eq!(state_dir_hint(&path), Some(resolved(&path)), "default");
    }

    #[test]
    fn the_hint_needs_toml_and_a_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "this is [not toml\n");
        assert_eq!(state_dir_hint(&path), None);
        let path = write(dir.path(), "[state]\ndir = 5\n");
        assert_eq!(state_dir_hint(&path), None);
        let path = write(dir.path(), "state = \"x\"\n");
        assert_eq!(state_dir_hint(&path), None);
        assert_eq!(state_dir_hint(&dir.path().join("missing.toml")), None);
    }

    fn load_error(path: &Path) -> SettingsError {
        Settings::load(path).expect_err("the config has a key this binary does not know")
    }

    #[test]
    fn an_unknown_key_is_recorded_once() {
        let config = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let path = write(
            config.path(),
            &format!(
                "{HOST}\n[state]\ndir = \"{}\"\n\n[logs]\nfuture_key = \"a-config-value\"\n",
                state_dir.path().display()
            ),
        );
        let error = load_error(&path);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        assert!(record_unparsable_config(&path, &error, now));
        let st = state::load(state_dir.path()).unwrap();
        let recorded = st.error.clone().expect("the stop is recorded");
        assert!(recorded.host_tools_stale);
        assert_eq!(recorded.digest, None);
        assert!(
            recorded.message.contains("future_key"),
            "{}",
            recorded.message
        );
        assert!(
            !recorded.message.contains("a-config-value"),
            "{}",
            recorded.message
        );
        let saved = std::fs::read(state::path(state_dir.path())).unwrap();

        // The watchdog's next wake-up, a minute later: the same stop is not written again.
        let later = now + Duration::from_secs(60);
        assert!(!record_unparsable_config(&path, &error, later));
        assert_eq!(std::fs::read(state::path(state_dir.path())).unwrap(), saved);
    }

    #[test]
    fn a_missing_state_dir_is_not_created() {
        let config = tempfile::tempdir().unwrap();
        let state_dir = config.path().join("not-there");
        let path = write(
            config.path(),
            &format!(
                "{HOST}\n[state]\ndir = \"{}\"\nbogus = 1\n",
                state_dir.display()
            ),
        );
        let error = load_error(&path);
        assert!(!record_unparsable_config(
            &path,
            &error,
            SystemTime::UNIX_EPOCH
        ));
        assert!(!state_dir.exists());
    }

    #[test]
    fn invalid_toml_records_nothing() {
        let config = tempfile::tempdir().unwrap();
        let path = write(config.path(), "this is [not toml\n");
        let error = load_error(&path);
        assert!(!record_unparsable_config(
            &path,
            &error,
            SystemTime::UNIX_EPOCH
        ));
        assert!(!state::path(config.path()).exists());
    }
}
