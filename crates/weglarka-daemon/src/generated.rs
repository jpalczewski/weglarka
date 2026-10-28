//! The generated config worker (#212): keeps the files a consumer app reads (the identity provider's
//! access rules and OIDC clients) in step with `apps.toml`.
//!
//! The pipeline itself — render, write, validate, swap, apply, roll back — is
//! [`Reconciler::apply_generated`](weglarka_engine::reconcile::Reconciler); this module only decides
//! *when* it runs: once at daemon start (which also re-applies a swap the previous daemon never
//! finished) and after every desired-state change, with a short debounce so a burst of writes means
//! one restart of the consumer, not one per write.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, watch};
use weglarka_engine::generated::{DigestProvider, GeneratedOutcome, GeneratedWiring};
use weglarka_engine::reconcile::Reconciler;
use weglarka_model::app::{AppsFile, InstanceName};
use weglarka_model::config::HostConfig;
use weglarka_model::generated::ConfigGenerator;
use weglarka_model::podman::PodmanClient;
use weglarka_model::secret_ops::{Pbkdf2Digest, SecretOps};
use weglarka_model::state;

/// How long a change waits for more changes before the pipeline runs.
pub const DEBOUNCE: Duration = Duration::from_secs(2);

/// The generators this daemon runs: the identity provider's (#42) when `[identity]` is configured.
/// With none registered no app has a generated config and the worker is not started.
pub fn registered(host: &HostConfig) -> Vec<Arc<dyn ConfigGenerator>> {
    host.identity
        .iter()
        .map(|identity| {
            Arc::new(weglarka_identity::AutheliaGenerator::new(
                identity.instance.clone(),
                identity.issuer.clone(),
            )) as Arc<dyn ConfigGenerator>
        })
        .collect()
}

/// Credential digests for the apps that need one (#213): mints the OIDC client secret of every app
/// with an `oidc` section when absent and hands the renderers its digest — never the value. Runs
/// under the engine lock (see `apply_generated`), as minting is a read-then-write on the store.
pub fn credential_digests(ops: Arc<dyn SecretOps>) -> Arc<DigestProvider> {
    Arc::new(move |apps: &AppsFile| {
        let mut digests: BTreeMap<InstanceName, Pbkdf2Digest> = BTreeMap::new();
        for (instance, spec) in &apps.apps {
            if spec.oidc.is_none() {
                continue;
            }
            match weglarka_engine::oidc_credentials::ensure(&*ops, instance) {
                Ok(digest) => {
                    digests.insert(instance.clone(), digest);
                }
                Err(error) => {
                    tracing::warn!(%instance, %error, "cannot ensure the OIDC client credential");
                }
            }
        }
        digests
    })
}

pub struct GeneratedWorker<P: PodmanClient> {
    engine: Arc<Reconciler<P>>,
    generators: Vec<Arc<dyn ConfigGenerator>>,
    digests: Arc<DigestProvider>,
    wake: Notify,
    debounce: Duration,
}

impl<P: PodmanClient + 'static> GeneratedWorker<P> {
    pub fn new(
        engine: Arc<Reconciler<P>>,
        generators: Vec<Arc<dyn ConfigGenerator>>,
        digests: Arc<DigestProvider>,
        debounce: Duration,
    ) -> Self {
        Self {
            engine,
            generators,
            digests,
            wake: Notify::new(),
            debounce,
        }
    }

    /// What the engine needs to bootstrap a consumer's files before its first start.
    pub fn wiring(&self) -> GeneratedWiring {
        GeneratedWiring {
            generators: self.generators.clone(),
            digests: self.digests.clone(),
        }
    }

    pub fn generators(&self) -> &[Arc<dyn ConfigGenerator>] {
        &self.generators
    }

    /// The desired state changed: run a pass after the debounce (coalesces many calls into one).
    pub fn request_apply(&self) {
        self.wake.notify_one();
    }

    /// One pass over every generator. A failing generator is logged and does not stop the others.
    pub async fn pass(&self) {
        let apps = match state::load_apps(&self.engine.paths().apps) {
            Ok(apps) => apps,
            Err(error) => {
                tracing::warn!(%error, "generated config: cannot read apps.toml");
                return;
            }
        };
        for generator in &self.generators {
            // A consumer that is not (yet) declared has nothing to receive its files.
            if !apps.apps.contains_key(generator.consumer()) {
                continue;
            }
            let id = generator.id();
            match self
                .engine
                .apply_generated(&**generator, &*self.digests, false)
                .await
            {
                Ok(GeneratedOutcome::Unchanged) => {}
                Ok(outcome) => tracing::info!(generator = id, ?outcome, "generated config"),
                Err(error) => tracing::warn!(generator = id, %error, "generated config failed"),
            }
        }
    }

    /// Runs until `shutdown`: a pass at start, then one per burst of changes.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        self.pass().await;
        loop {
            tokio::select! {
                () = self.wake.notified() => {}
                _ = shutdown.changed() => return,
            }
            tokio::select! {
                () = tokio::time::sleep(self.debounce) => {}
                _ = shutdown.changed() => return,
            }
            self.pass().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use weglarka_engine::reconcile::{Reconciler, ReconcilerOptions};
    use weglarka_engine::testing::{Call, FakePodman};
    use weglarka_model::app::{AppSpec, Digest};
    use weglarka_model::generated::{FileName, GeneratedFile, RenderError, RenderInput};
    use weglarka_model::podman::HealthStatus;
    use weglarka_model::secret_store::SecretStore;
    use weglarka_model::secrets::FileSecretStore;
    use weglarka_model::state::StatePaths;

    const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";
    const APPS: &str = r#"
[apps.idp]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
port = 8085
health = { attempts = 2, window_secs = 2 }
"#;

    struct Gen {
        consumer: InstanceName,
        content: Mutex<String>,
        renders: Mutex<usize>,
    }

    impl ConfigGenerator for Gen {
        fn id(&self) -> &'static str {
            "test"
        }

        fn consumer(&self) -> &InstanceName {
            &self.consumer
        }

        fn render(&self, _: &RenderInput<'_>) -> Result<Vec<GeneratedFile>, RenderError> {
            *self.renders.lock().unwrap() += 1;
            Ok(vec![GeneratedFile::new(
                FileName::new("rules.yml").unwrap(),
                self.content.lock().unwrap().clone().into_bytes(),
            )])
        }

        fn validate_argv(&self, _: &AppSpec, _: &str) -> Option<Vec<String>> {
            None
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        fake: FakePodman,
        generator: Arc<Gen>,
        worker: Arc<GeneratedWorker<FakePodman>>,
        shutdown: watch::Sender<bool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Rig {
        async fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = StatePaths::in_dir(dir.path());
            std::fs::write(&paths.apps, APPS).unwrap();
            let fake = FakePodman::new();
            let secrets: Arc<dyn SecretStore> =
                Arc::new(FileSecretStore::new(dir.path().join("secrets.toml")));
            let engine = Arc::new(Reconciler::new(
                fake.clone(),
                secrets,
                paths,
                ReconcilerOptions::default(),
            ));
            fake.set_pull_digest(
                IMAGE,
                Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            );
            fake.script_health("idp", [HealthStatus::Healthy]);
            engine.reconcile().await.unwrap();

            let generator = Arc::new(Gen {
                consumer: InstanceName::new("idp").unwrap(),
                content: Mutex::new("v1".into()),
                renders: Mutex::new(0),
            });
            let worker = Arc::new(GeneratedWorker::new(
                engine,
                vec![generator.clone()],
                Arc::new(|_: &AppsFile| BTreeMap::new()),
                DEBOUNCE,
            ));
            let (shutdown, rx) = watch::channel(false);
            let task = tokio::spawn({
                let worker = worker.clone();
                async move { worker.run(rx).await }
            });
            Self {
                _dir: dir,
                fake,
                generator,
                worker,
                shutdown,
                task,
            }
        }

        fn restarts(&self) -> usize {
            self.fake
                .calls()
                .iter()
                .filter(|c| **c == Call::ContainerStop("idp".into()))
                .count()
        }

        async fn settle(&self, secs: u64) {
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }

        async fn stop(self) {
            self.shutdown.send(true).unwrap();
            self.task.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_pass_runs_at_start_and_applies_without_a_request() {
        let rig = Rig::start().await;
        rig.settle(1).await;
        assert_eq!(*rig.generator.renders.lock().unwrap(), 1);
        assert!(
            rig.worker
                .engine
                .generated_live_version(rig.generator.consumer())
                .is_some()
        );
        rig.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_five_writes_restarts_the_consumer_once() {
        let rig = Rig::start().await;
        rig.settle(1).await;
        let restarts = rig.restarts();

        for n in 2..=6 {
            *rig.generator.content.lock().unwrap() = format!("v{n}");
            rig.fake.script_health("idp", [HealthStatus::Healthy]);
            rig.worker.request_apply();
            rig.settle(0).await;
        }
        // Still inside the debounce window: nothing has run yet.
        assert_eq!(rig.restarts(), restarts);
        rig.settle(DEBOUNCE.as_secs() + 5).await;
        assert_eq!(rig.restarts(), restarts + 1, "one restart for five writes");
        // …and it rendered the last content.
        let live = rig
            .worker
            .engine
            .generated_live_version(rig.generator.consumer())
            .unwrap();
        let dir = rig.worker.engine.generated_dir(rig.generator.consumer());
        assert_eq!(
            std::fs::read_to_string(dir.join(&live).join("rules.yml")).unwrap(),
            "v6"
        );
        rig.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn an_unchanged_request_does_not_restart_anything() {
        let rig = Rig::start().await;
        rig.settle(1).await;
        let restarts = rig.restarts();
        rig.worker.request_apply();
        rig.settle(DEBOUNCE.as_secs() + 5).await;
        assert_eq!(rig.restarts(), restarts);
        rig.stop().await;
    }
}
