//! Bootstrap completeness gate.
//!
//! Contract: coordinated updates are enabled only when `platform-update.toml` has a channel
//! pointer, bootstrap is marked complete, and both the active and recovery generations pass
//! preflight against the current configuration. This module is the mechanism; the coordinator
//! (brief D) decides when to call it.

use std::path::Path;

use weglarka_model::platform_update::PlatformUpdate;
use weglarka_model::release_set::Channel;

use crate::selector::{BootstrapMarker, HostSelector, SelectorError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreflightOutcome {
    pub active: bool,
    pub recovery: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("bootstrap is not complete: {0}")]
    BootstrapIncomplete(String),
    #[error("the bootstrap marker does not match the current selector: {0}")]
    MarkerMismatch(String),
    #[error(
        "no release-set channel pointer in platform-update.toml; coordinated updates stay disabled"
    )]
    NoChannelPointer,
    #[error("the active generation failed preflight against the current configuration")]
    ActivePreflightFailed,
    #[error("the recovery generation failed preflight; it is not an eligible rollback target")]
    RecoveryPreflightFailed,
    #[error("a legacy runner still exists: {0}")]
    LegacyRunner(String),
    #[error(transparent)]
    Selector(#[from] SelectorError),
    #[error("invalid {file}: {message}", file = weglarka_model::platform_update::FILE_NAME)]
    Journal { message: String },
}

/// The only gate the coordinator uses before enabling coordinated updates.
pub fn coordinated_updates_ready(
    host_dir: &Path,
    state_dir: &Path,
    channel: Option<Channel>,
    preflight: PreflightOutcome,
    legacy_clear: bool,
) -> Result<(), GateError> {
    if !legacy_clear {
        return Err(GateError::LegacyRunner(
            "a legacy self-update/watchdog unit or self-update.lock participant is still present"
                .into(),
        ));
    }
    let marker = BootstrapMarker::load(host_dir).map_err(|e| {
        GateError::BootstrapIncomplete(format!("bootstrap marker is unreadable: {e}"))
    })?;
    let Some(marker) = marker else {
        return Err(GateError::BootstrapIncomplete(
            "bootstrap-complete.toml is missing".into(),
        ));
    };
    let selector = HostSelector::load(host_dir)?;
    if marker.generation != selector.active || marker.selector_epoch != selector.epoch {
        return Err(GateError::MarkerMismatch(format!(
            "marker names {} epoch {}, selector names {} epoch {}",
            marker.generation, marker.selector_epoch, selector.active, selector.epoch
        )));
    }

    let journal_path = state_dir.join(weglarka_model::platform_update::FILE_NAME);
    let journal =
        match PlatformUpdate::parse(&std::fs::read_to_string(&journal_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                GateError::NoChannelPointer
            } else {
                GateError::Journal {
                    message: e.to_string(),
                }
            }
        })?) {
            Ok(journal) => journal,
            Err(e) => {
                return Err(GateError::Journal {
                    message: e.to_string(),
                });
            }
        };
    let has_pointer = match channel {
        Some(channel) => journal.accepted(channel).is_some(),
        None => !journal.accepted.is_empty(),
    };
    if !has_pointer {
        return Err(GateError::NoChannelPointer);
    }
    if !preflight.active {
        return Err(GateError::ActivePreflightFailed);
    }
    if !preflight.recovery {
        return Err(GateError::RecoveryPreflightFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selector::{BootstrapMarker, HostSelector};
    use weglarka_model::platform_update::AcceptedPointer;
    use weglarka_model::release_set::StrictDigest;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn ready() -> (tempfile::TempDir, tempfile::TempDir) {
        let host = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let selector = HostSelector::fresh(digest('a'));
        selector.save(host.path()).unwrap();
        BootstrapMarker {
            format_version: 1,
            generation: digest('a'),
            selector_epoch: 1,
            completed_at: 1,
        }
        .save(host.path())
        .unwrap();
        let mut journal = PlatformUpdate::default();
        journal
            .accept(
                Channel::Stable,
                AcceptedPointer {
                    sequence: 1,
                    release_set_digest: digest('c'),
                    revision: "0123456789abcdef0123456789abcdef01234567".into(),
                },
            )
            .unwrap();
        std::fs::write(
            state
                .path()
                .join(weglarka_model::platform_update::FILE_NAME),
            journal.to_toml().unwrap(),
        )
        .unwrap();
        (host, state)
    }

    fn ok() -> PreflightOutcome {
        PreflightOutcome {
            active: true,
            recovery: true,
        }
    }

    #[test]
    fn the_gate_requires_every_contract_condition() {
        let (host, state) = ready();
        coordinated_updates_ready(host.path(), state.path(), Some(Channel::Stable), ok(), true)
            .unwrap();
        assert!(matches!(
            coordinated_updates_ready(host.path(), state.path(), None, ok(), false),
            Err(GateError::LegacyRunner(_))
        ));
        assert!(matches!(
            coordinated_updates_ready(host.path(), state.path(), Some(Channel::Main), ok(), true),
            Err(GateError::NoChannelPointer)
        ));
        assert!(matches!(
            coordinated_updates_ready(
                host.path(),
                state.path(),
                None,
                PreflightOutcome {
                    active: true,
                    recovery: false
                },
                true
            ),
            Err(GateError::RecoveryPreflightFailed)
        ));
        std::fs::remove_file(BootstrapMarker::path(host.path())).unwrap();
        assert!(matches!(
            coordinated_updates_ready(host.path(), state.path(), None, ok(), true),
            Err(GateError::BootstrapIncomplete(_))
        ));
    }
}
