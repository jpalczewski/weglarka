//! Validated runtime configuration: the endpoint, the token and the channel list.

use std::sync::Arc;
use std::time::Duration;

use weglarka_model::config::{NotifyConfig, NtfyConfig};
use weglarka_model::credential::{CredentialError, check_at_startup};
use weglarka_model::events::Severity;
use weglarka_model::secret_store::SecretStore;

use crate::channel::Channel;
use crate::endpoint::Endpoint;
use crate::ntfy::NtfyChannel;

#[derive(Debug, thiserror::Error)]
pub enum NotifySettingsError {
    #[error("[notify.ntfy] url: {0}")]
    Url(#[from] crate::endpoint::EndpointError),
    #[error("[notify.ntfy] topic {0:?}: expected [A-Za-z0-9_-]{{1,64}}")]
    Topic(String),
    /// A credential that cannot be read at startup, named by `CredentialSource::describe()` — a path
    /// or a secret name, never the value (ADR 0079).
    #[error("cannot read the ntfy token from {origin}: {err}")]
    Credential {
        origin: String,
        #[source]
        err: CredentialError,
    },
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
    /// then runs without notifications and says so at startup. `host_store` serves a `token_secret`
    /// (ADR 0079).
    pub fn load(
        config: &NotifyConfig,
        host_store: &Arc<dyn SecretStore>,
    ) -> Result<Option<Self>, NotifySettingsError> {
        let Some(ntfy) = &config.ntfy else {
            return Ok(None);
        };
        let channel = Self::ntfy(ntfy, host_store)?;
        Ok(Some(Self {
            dedup_window: Duration::from_secs(config.dedup_window_secs),
            channels: vec![ChannelSpec {
                name: channel.name(),
                min_severity: ntfy.min_severity,
                channel: Arc::new(channel),
            }],
        }))
    }

    fn ntfy(
        ntfy: &NtfyConfig,
        host_store: &Arc<dyn SecretStore>,
    ) -> Result<NtfyChannel, NotifySettingsError> {
        let topic = ntfy.topic.trim();
        if !valid_topic(topic) {
            return Err(NotifySettingsError::Topic(ntfy.topic.clone()));
        }
        let endpoint = Endpoint::parse(&ntfy.url, ntfy.host.as_deref())?;
        let credential = ntfy.credential(host_store);
        // A broken token is still a startup error; afterwards the channel reads on use, so rotation
        // needs no restart (ADR 0079).
        if let Some(source) = &credential {
            check_at_startup(source.as_ref()).map_err(|err| NotifySettingsError::Credential {
                origin: source.describe(),
                err,
            })?;
        }
        NtfyChannel::new(endpoint, topic, credential)
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use weglarka_model::secret_store::SecretValue;
    use weglarka_model::secrets::FileSecretStore;

    /// A host secret store in its own temporary directory; the caller keeps the `TempDir` alive.
    fn host_store() -> (tempfile::TempDir, Arc<dyn SecretStore>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FileSecretStore::host(dir.path().join("host-secrets.toml")));
        (dir, store)
    }

    /// `[notify.ntfy]` whose `token_file` is `path`, loaded against an empty host store.
    fn load_token_file(path: &Path) -> Result<Option<NotifySettings>, NotifySettingsError> {
        let mut ntfy = ntfy();
        ntfy.token_file = Some(path.to_owned());
        let (_dir, store) = host_store();
        NotifySettings::load(&config(Some(ntfy)), &store)
    }

    fn ntfy() -> NtfyConfig {
        NtfyConfig {
            url: "https://ntfy.example.com".into(),
            host: None,
            topic: "weglarka".into(),
            token_file: None,
            token_secret: None,
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
        let (_dir, store) = host_store();
        assert!(
            NotifySettings::load(&config(None), &store)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_valid_configuration_yields_the_ntfy_channel() {
        let (_dir, store) = host_store();
        let settings = NotifySettings::load(&config(Some(ntfy())), &store)
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
        let (_dir, store) = host_store();
        let settings = NotifySettings::load(&config(Some(ntfy)), &store)
            .unwrap()
            .unwrap();
        assert_eq!(settings.accepting(Severity::Debug).count(), 0);
        assert_eq!(settings.accepting(Severity::Info).count(), 0);
        assert_eq!(settings.accepting(Severity::Warning).count(), 1);
        assert_eq!(settings.accepting(Severity::Critical).count(), 1);
    }

    #[test]
    fn invalid_topics_and_urls_are_rejected() {
        let (_dir, store) = host_store();
        for topic in ["", "with space", "dots.not", &"x".repeat(65)] {
            let mut ntfy = ntfy();
            ntfy.topic = topic.to_owned();
            assert!(
                matches!(
                    NotifySettings::load(&config(Some(ntfy)), &store),
                    Err(NotifySettingsError::Topic(_))
                ),
                "{topic:?}"
            );
        }
        let mut ntfy = ntfy();
        ntfy.url = "ntfy.example.com".into();
        assert!(matches!(
            NotifySettings::load(&config(Some(ntfy)), &store),
            Err(NotifySettingsError::Url(_))
        ));
    }

    #[test]
    fn the_token_file_is_read_tightened_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ntfy-token");
        std::fs::write(&path, "tk_secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_token_file(&path).unwrap().is_some());
    }

    #[test]
    fn loose_token_permissions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ntfy-token");
        std::fs::write(&path, "tk_secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_token_file(&path).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, NotifySettingsError::Credential { .. }),
            "{text}"
        );
        assert!(text.contains("chmod 600"), "{text}");
        assert!(!text.contains("tk_secret"), "{text}");
    }

    #[test]
    fn empty_or_unsafe_tokens_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ntfy-token");
        for content in ["\n", "bad\r\nHeader: x", "tk_ok\t"] {
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let err = load_token_file(&path).unwrap_err();
            assert!(
                matches!(err, NotifySettingsError::Credential { .. }),
                "{content:?}: {err}"
            );
            // No value reaches the message.
            let text = err.to_string();
            assert!(!text.contains("bad") && !text.contains("tk_ok"), "{text}");
        }
        // A missing file is an error too (the operator pointed at the wrong path).
        assert!(load_token_file(&dir.path().join("nope")).is_err());
    }

    #[test]
    fn a_token_secret_is_read_from_the_host_store() {
        let (_dir, store) = host_store();
        store
            .set("ntfy-token", SecretValue::new("tk_secret\n"))
            .unwrap();
        let mut ntfy = ntfy();
        ntfy.token_secret = Some("ntfy-token".into());
        assert!(
            NotifySettings::load(&config(Some(ntfy)), &store)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_host_secret_that_is_not_set_yet_does_not_stop_the_startup() {
        // It can only be set through the running daemon (ADR 0079).
        let (_dir, store) = host_store();
        let mut ntfy = ntfy();
        ntfy.token_secret = Some("ntfy-token".into());
        assert!(
            NotifySettings::load(&config(Some(ntfy)), &store)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_malformed_host_secret_is_a_startup_error_that_names_no_value() {
        let (_dir, store) = host_store();
        store
            .set("ntfy-token", SecretValue::new("two words"))
            .unwrap();
        let mut ntfy = ntfy();
        ntfy.token_secret = Some("ntfy-token".into());
        let err = NotifySettings::load(&config(Some(ntfy)), &store).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("host secret ntfy-token"), "{text}");
        assert!(!text.contains("two words"), "{text}");
    }
}
