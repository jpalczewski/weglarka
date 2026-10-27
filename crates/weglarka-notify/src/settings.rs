//! Validated runtime configuration: the endpoint, the token and the channel list.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use weglarka_model::config::{NotifyConfig, NtfyConfig};
use weglarka_model::events::Severity;

use crate::channel::Channel;
use crate::http::Endpoint;
use crate::ntfy::NtfyChannel;

#[derive(Debug, thiserror::Error)]
pub enum NotifySettingsError {
    #[error("[notify.ntfy] url: {0}")]
    Url(#[from] crate::http::EndpointError),
    #[error("[notify.ntfy] topic {0:?}: expected [A-Za-z0-9_-]{{1,64}}")]
    Topic(String),
    #[error("cannot read the ntfy token file {path}: {source}")]
    TokenRead { path: PathBuf, source: io::Error },
    #[error("the ntfy token file {0} must not be accessible by group or others (chmod 600)")]
    TokenPermissions(PathBuf),
    #[error("the ntfy token file {0} is empty")]
    TokenEmpty(PathBuf),
    #[error("the ntfy token file {0} has characters that cannot go into an HTTP header")]
    TokenInvalid(PathBuf),
    #[error("cannot set up the ntfy client: {0}")]
    Client(String),
}

/// One delivery channel and the lowest severity it wants.
pub struct ChannelSpec {
    /// Also the name stored in the outbox (`ntfy`).
    pub name: &'static str,
    pub min_severity: Severity,
    pub channel: Arc<dyn Channel>,
}

impl std::fmt::Debug for ChannelSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelSpec")
            .field("name", &self.name)
            .field("min_severity", &self.min_severity)
            .finish_non_exhaustive()
    }
}

/// What the worker needs: the channel list and the dedup window.
#[derive(Debug)]
pub struct NotifySettings {
    pub dedup_window: Duration,
    pub channels: Vec<ChannelSpec>,
}

impl NotifySettings {
    /// Validates `[notify]`. `Ok(None)` means "nothing to deliver to" (no `[notify.ntfy]`) — the daemon
    /// then runs without notifications and says so at startup.
    pub fn load(config: &NotifyConfig) -> Result<Option<Self>, NotifySettingsError> {
        let Some(ntfy) = &config.ntfy else {
            return Ok(None);
        };
        let channel = Self::ntfy(ntfy)?;
        Ok(Some(Self {
            dedup_window: Duration::from_secs(config.dedup_window_secs),
            channels: vec![ChannelSpec {
                name: channel.name(),
                min_severity: ntfy.min_severity,
                channel: Arc::new(channel),
            }],
        }))
    }

    fn ntfy(ntfy: &NtfyConfig) -> Result<NtfyChannel, NotifySettingsError> {
        let topic = ntfy.topic.trim();
        if !valid_topic(topic) {
            return Err(NotifySettingsError::Topic(ntfy.topic.clone()));
        }
        let endpoint = Endpoint::parse(&ntfy.url, ntfy.host.as_deref())?;
        let token = match &ntfy.token_file {
            Some(path) => Some(read_token(path)?),
            None => None,
        };
        NtfyChannel::new(endpoint, topic, token)
            .map_err(|e| NotifySettingsError::Client(e.to_string()))
    }

    /// Channels that want a message of this severity (in configuration order).
    pub fn accepting(&self, severity: Severity) -> impl Iterator<Item = &ChannelSpec> {
        self.channels
            .iter()
            .filter(move |channel| severity >= channel.min_severity)
    }

    /// The channel stored in the outbox as `name` (it may be gone after a config change).
    pub fn channel(&self, name: &str) -> Option<&ChannelSpec> {
        self.channels.iter().find(|channel| channel.name == name)
    }
}

fn valid_topic(topic: &str) -> bool {
    (1..=64).contains(&topic.len())
        && topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Reads the access token: a 0600 file whose trailing newline is dropped. The value must be printable
/// ASCII — it becomes an `Authorization` header, and a CR/LF there would be a header injection.
fn read_token(path: &Path) -> Result<String, NotifySettingsError> {
    let metadata = std::fs::metadata(path).map_err(|source| NotifySettingsError::TokenRead {
        path: path.to_owned(),
        source,
    })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(NotifySettingsError::TokenPermissions(path.to_owned()));
    }
    let raw = std::fs::read_to_string(path).map_err(|source| NotifySettingsError::TokenRead {
        path: path.to_owned(),
        source,
    })?;
    let token = raw.trim_end_matches(['\r', '\n']).to_owned();
    if token.is_empty() {
        return Err(NotifySettingsError::TokenEmpty(path.to_owned()));
    }
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(NotifySettingsError::TokenInvalid(path.to_owned()));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ntfy() -> NtfyConfig {
        NtfyConfig {
            url: "https://ntfy.example.com".into(),
            host: None,
            topic: "weglarka".into(),
            token_file: None,
            min_severity: Severity::Info,
        }
    }

    fn config(ntfy: Option<NtfyConfig>) -> NotifyConfig {
        NotifyConfig {
            dedup_window_secs: 60,
            ntfy,
        }
    }

    #[test]
    fn no_channel_means_notifications_are_off() {
        assert!(NotifySettings::load(&config(None)).unwrap().is_none());
    }

    #[test]
    fn a_valid_configuration_yields_the_ntfy_channel() {
        let settings = NotifySettings::load(&config(Some(ntfy())))
            .unwrap()
            .unwrap();
        assert_eq!(settings.dedup_window, Duration::from_secs(60));
        assert_eq!(settings.channels.len(), 1);
        assert_eq!(settings.channels[0].name, "ntfy");
        assert_eq!(settings.channels[0].min_severity, Severity::Info);
        assert!(settings.channel("ntfy").is_some());
        assert!(settings.channel("mail").is_none());
    }

    #[test]
    fn severity_routing_filters_channels() {
        let mut ntfy = ntfy();
        ntfy.min_severity = Severity::Warning;
        let settings = NotifySettings::load(&config(Some(ntfy))).unwrap().unwrap();
        assert_eq!(settings.accepting(Severity::Debug).count(), 0);
        assert_eq!(settings.accepting(Severity::Info).count(), 0);
        assert_eq!(settings.accepting(Severity::Warning).count(), 1);
        assert_eq!(settings.accepting(Severity::Critical).count(), 1);
    }

    #[test]
    fn invalid_topics_and_urls_are_rejected() {
        for topic in ["", "with space", "dots.not", &"x".repeat(65)] {
            let mut ntfy = ntfy();
            ntfy.topic = topic.to_owned();
            assert!(
                matches!(
                    NotifySettings::load(&config(Some(ntfy))),
                    Err(NotifySettingsError::Topic(_))
                ),
                "{topic:?}"
            );
        }
        let mut ntfy = ntfy();
        ntfy.url = "ntfy.example.com".into();
        assert!(matches!(
            NotifySettings::load(&config(Some(ntfy))),
            Err(NotifySettingsError::Url(_))
        ));
    }

    #[test]
    fn the_token_file_is_read_tightened_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ntfy-token");
        std::fs::write(&path, "tk_secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token(&path).unwrap(), "tk_secret");
    }

    #[test]
    fn loose_token_permissions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ntfy-token");
        std::fs::write(&path, "tk_secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_token(&path),
            Err(NotifySettingsError::TokenPermissions(_))
        ));
    }

    #[test]
    fn empty_or_unsafe_tokens_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ntfy-token");
        for content in ["\n", "bad\r\nHeader: x", "tk_ok\t"] {
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_token(&path).is_err(), "{content:?} was accepted");
        }
        // A missing file is an error too (the operator pointed at the wrong path).
        assert!(read_token(&dir.path().join("nope")).is_err());
    }
}
