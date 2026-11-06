//! The engine test harness: a [`Reconciler`] over [`FakePodman`] with its state files in a temporary
//! directory, a file secret store and an event sink to assert on.

use std::sync::Arc;

use weglarka_model::events::VecSink;
use weglarka_model::secret_store::SecretStore;
use weglarka_model::secrets::FileSecretStore;
use weglarka_model::state::{StatePaths, load_state};

use super::{FakePodman, name};
use crate::crash;
use crate::reconcile::{Reconciler, ReconcilerOptions, SecretChangePolicy};

pub(crate) struct Harness {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) fake: FakePodman,
    pub(crate) store: Arc<FileSecretStore>,
    pub(crate) sink: Arc<VecSink>,
    pub(crate) rec: Arc<Reconciler<FakePodman>>,
}

impl Harness {
    pub(crate) fn new(apps_toml: &str) -> Self {
        Self::with_policy(apps_toml, SecretChangePolicy::Immediate)
    }

    pub(crate) fn with_policy(apps_toml: &str, policy: SecretChangePolicy) -> Self {
        Self::with_options(
            apps_toml,
            ReconcilerOptions {
                secret_change: policy,
                ..Default::default()
            },
        )
    }

    /// Harness with failure detection enabled at `monitor` (the crash-loop / health scenarios).
    pub(crate) fn with_monitor(apps_toml: &str, monitor: crash::Policy) -> Self {
        Self::build(apps_toml, ReconcilerOptions::default(), monitor)
    }

    /// Harness with explicit reconciler options (e.g. a `config_root`, issue #118).
    pub(crate) fn with_options(apps_toml: &str, options: ReconcilerOptions) -> Self {
        Self::build(apps_toml, options, crash::Policy::disabled())
    }

    pub(crate) fn build(
        apps_toml: &str,
        options: ReconcilerOptions,
        monitor: crash::Policy,
    ) -> Self {
        Self::build_with(apps_toml, options, monitor, None)
    }

    pub(crate) fn build_with(
        apps_toml: &str,
        options: ReconcilerOptions,
        monitor: crash::Policy,
        generated: Option<crate::generated::GeneratedWiring>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::in_dir(dir.path());
        std::fs::write(&paths.apps, apps_toml).unwrap();
        let fake = FakePodman::new();
        let store = Arc::new(FileSecretStore::new(dir.path().join("secrets.toml")));
        let sink = Arc::new(VecSink::default());
        let secrets: Arc<dyn SecretStore> = store.clone();
        let mut rec = Reconciler::new(fake.clone(), secrets, paths, options)
            .with_events(sink.clone())
            .with_monitor(monitor);
        if let Some(wiring) = generated {
            rec = rec.with_generated(wiring);
        }
        let rec = Arc::new(rec);
        Self {
            dir,
            fake,
            store,
            sink,
            rec,
        }
    }

    pub(crate) fn set_apps(&self, toml: &str) {
        std::fs::write(&self.rec.paths().apps, toml).unwrap();
    }

    pub(crate) fn state(&self, inst: &str) -> weglarka_model::state::AppState {
        load_state(&self.rec.paths().state)
            .unwrap()
            .apps
            .remove(&name(inst))
            .unwrap_or_default()
    }

    pub(crate) fn container_digest_ref(&self, cname: &str) -> String {
        self.fake
            .containers()
            .into_iter()
            .find(|c| c.name == cname)
            .unwrap()
            .image
    }
}
