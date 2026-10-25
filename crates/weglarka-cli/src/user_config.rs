//! The user-wide CLI settings file: `$XDG_CONFIG_HOME/weglarka/cli.toml` (else
//! `~/.config/weglarka/cli.toml`). Optional; a missing file is the empty configuration. It holds
//! preferences of the person at the terminal, not of the host (those are `weglarka.toml`).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{CliError, Kind};

/// Contents of `cli.toml`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// SSH destination of the Węglarka host (`host`, `user@host` or an `ssh_config` alias):
    /// `weglarka forward` tunnels through it.
    pub ssh_host: Option<String>,
}

impl UserConfig {
    pub fn parse(src: &str, origin: &Path) -> Result<Self, CliError> {
        toml::from_str(src).map_err(|e| {
            CliError::new(
                Kind::Config,
                format!("invalid CLI settings {}: {e}", origin.display()),
            )
            .with_hint("the only key is `ssh_host = \"user@host\"`")
        })
    }

    /// Loads the file at `path`; a file that does not exist is the empty configuration.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        match std::fs::read_to_string(path) {
            Ok(src) => Self::parse(&src, path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(CliError::new(
                Kind::Config,
                format!("cannot read CLI settings {}: {e}", path.display()),
            )),
        }
    }

    /// [`Self::load`] from the default location; no home directory means no file.
    pub fn load_default() -> Result<Self, CliError> {
        match default_path(
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        ) {
            Some(path) => Self::load(&path),
            None => Ok(Self::default()),
        }
    }
}

/// `$XDG_CONFIG_HOME/weglarka/cli.toml`, else `$HOME/.config/weglarka/cli.toml`. Relative or empty
/// values are ignored, as the XDG specification says.
pub fn default_path(xdg: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    let base = xdg
        .filter(|p| p.is_absolute())
        .or_else(|| home.filter(|p| p.is_absolute()).map(|h| h.join(".config")))?;
    Some(base.join("weglarka").join("cli.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_takes_ssh_host_and_nothing_else() {
        let origin = Path::new("cli.toml");
        assert_eq!(
            UserConfig::parse("ssh_host = \"me@deploy\"\n", origin).unwrap(),
            UserConfig {
                ssh_host: Some("me@deploy".into())
            }
        );
        assert_eq!(
            UserConfig::parse("", origin).unwrap(),
            UserConfig::default()
        );
        assert!(UserConfig::parse("ssh_hots = \"x\"", origin).is_err());
    }

    #[test]
    fn a_missing_file_is_the_empty_configuration() {
        let missing = std::env::temp_dir().join("wgl-no-such-dir/cli.toml");
        assert_eq!(UserConfig::load(&missing).unwrap(), UserConfig::default());
    }

    #[test]
    fn the_location_follows_xdg_then_home() {
        let p = |s: &str| Some(PathBuf::from(s));
        assert_eq!(
            default_path(p("/x"), p("/home/u")),
            p("/x/weglarka/cli.toml")
        );
        assert_eq!(
            default_path(None, p("/home/u")),
            p("/home/u/.config/weglarka/cli.toml")
        );
        assert_eq!(
            default_path(p("relative"), p("/home/u")),
            p("/home/u/.config/weglarka/cli.toml")
        );
        assert_eq!(default_path(None, None), None);
    }
}
