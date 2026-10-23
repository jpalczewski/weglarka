//! Volumes and file ownership of the deploy engine (iteration 2, docs/decisions/0009-volume-ownership.md).
//!
//! Every container Węglarka creates runs in its own user namespace with an explicit uid/gid range
//! (`userns: private` + `UIDMap`/`GIDMap`); plain `userns: auto` is a no-op under rootless Podman.
//! This module owns:
//!
//! * the **range policy** — an instance gets a [`DEFAULT_RANGE_SIZE`] range at its first deploy (or,
//!   for instances that predate ranges, at the first reconcile after the update) and keeps it for
//!   as long as it has data: the range is stored in `state.toml` and never changes while the instance
//!   exists. A plain `apps remove` keeps volumes, so it keeps the range too (a state entry holding
//!   only `uid_range`); the range is released when the instance has no volumes left —
//!   immediately on `apps remove --purge-volumes`, or on the reconcile pass after the last labelled
//!   volume disappeared. The ingress nginx has its own, smaller range (`StateFile::ingress_uid_range`);
//! * **volume creation** before `container_create` (Podman would create a missing volume implicitly,
//!   but without the `weglarka.instance` label that purge and list rely on);
//! * **purge** on `apps remove --purge-volumes`;
//! * **foreign tar import** through a created-but-never-started helper container, so the ids of the tar
//!   are mapped through the instance's namespace (`container_archive_put`, finding 9 of the ADR).
//!
//! All state changes happen under the engine's `lock` (the sole `state.toml` writer).

use std::collections::BTreeMap;
use std::time::Duration;

use crate::app::{AppSpec, AppsFile, InstanceName};
use crate::deploy::pinned_ref;
use crate::labels;
use crate::podman::{
    ContainerSpec, IdMapping, IdRange, PodmanClient, PodmanError, Result, RestartPolicy, TarStream,
    VolumeAttachment, VolumeFilter, VolumeSpec,
};
use crate::reconcile::{EngineError, Reconciler};
use crate::state::{self, AppState, StateFile};
use crate::uid_range::{DEFAULT_RANGE_SIZE, INFRA_RANGE_SIZE, UidRange, allocate};

/// Explicit map for a range: container ids `0..size` ↔ namespace ids `start..start+size`
/// (`start` = offset into the rootless user's subuids, 1 = the first one).
pub fn id_mapping(range: UidRange) -> IdMapping {
    let line = [IdRange {
        container_id: 0,
        host_id: range.start,
        size: range.size,
    }];
    IdMapping {
        uid_map: line.to_vec(),
        gid_map: line.to_vec(),
    }
}

/// Podman volume name and labels for an instance's volume.
fn volume_spec(instance: &InstanceName, name: &str) -> VolumeSpec {
    VolumeSpec {
        name: labels::volume_name(instance, name),
        labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.to_string())]),
    }
}

/// Creates the instance's declared volumes (idempotent, labelled `weglarka.instance`).
pub async fn ensure_volumes<P: PodmanClient>(
    podman: &P,
    instance: &InstanceName,
    spec: &AppSpec,
) -> Result<()> {
    for v in &spec.volumes {
        podman.volume_create(&volume_spec(instance, &v.name)).await?;
    }
    Ok(())
}

/// Container-side mounts for the instance's declared volumes.
pub fn attachments(instance: &InstanceName, spec: &AppSpec) -> Vec<VolumeAttachment> {
    spec.volumes
        .iter()
        .map(|v| VolumeAttachment {
            volume: labels::volume_name(instance, &v.name),
            target: v.target.clone(),
            read_only: v.read_only,
        })
        .collect()
}

/// What `launch` adds to the instance's `ContainerSpec`: ownership and volumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub range: UidRange,
    pub volumes: Vec<VolumeAttachment>,
}

impl Prepared {
    pub fn apply(self, container: &mut ContainerSpec) {
        container.userns_auto = false;
        container.id_mapping = Some(id_mapping(self.range));
        container.volumes = self.volumes;
        container
            .labels
            .insert(labels::UID_RANGE.to_owned(), labels::uid_range_label(self.range));
    }
}

impl<P: PodmanClient> Reconciler<P> {
    /// First free range of `size` among everything `state.toml` has handed out.
    async fn allocate_range(&self, st: &StateFile, size: u32) -> Result<UidRange, EngineError> {
        let used: Vec<UidRange> = st
            .apps
            .values()
            .filter_map(|s| s.uid_range)
            .chain(st.ingress_uid_range)
            .collect();
        let pool = self.podman.subuid_pool().await?;
        allocate(&used, pool, size).ok_or(EngineError::UidPoolExhausted { pool, size })
    }

    /// The instance's range; allocated and persisted on first use. Caller holds the engine lock and
    /// calls this *before* loading the state it is going to modify (it writes `state.toml` itself).
    pub(crate) async fn assign_uid_range(
        &self,
        instance: &InstanceName,
    ) -> Result<UidRange, EngineError> {
        let mut st = state::load_state(&self.paths.state)?;
        if let Some(r) = st.apps.get(instance).and_then(|s| s.uid_range) {
            return Ok(r);
        }
        let range = self.allocate_range(&st, DEFAULT_RANGE_SIZE).await?;
        st.apps.entry(instance.clone()).or_default().uid_range = Some(range);
        state::save_state(&self.paths.state, &st)?;
        tracing::info!(%instance, start = range.start, size = range.size, "assigned uid range");
        Ok(range)
    }

    /// Range of the ingress nginx container; allocated and persisted on first use.
    pub async fn ensure_ingress_range(&self) -> Result<UidRange, EngineError> {
        let _g = self.lock.lock().await;
        let mut st = state::load_state(&self.paths.state)?;
        if let Some(r) = st.ingress_uid_range {
            return Ok(r);
        }
        let range = self.allocate_range(&st, INFRA_RANGE_SIZE).await?;
        st.ingress_uid_range = Some(range);
        state::save_state(&self.paths.state, &st)?;
        tracing::info!(start = range.start, size = range.size, "assigned ingress uid range");
        Ok(range)
    }

    /// Ownership and volumes for a container about to be created. The range must already be assigned
    /// ([`Self::assign_uid_range`]); volumes are created here, before the old container is touched.
    pub(crate) async fn prepare_container(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<Prepared, EngineError> {
        let range = state::load_state(&self.paths.state)?
            .apps
            .get(instance)
            .and_then(|s| s.uid_range)
            .ok_or_else(|| EngineError::Volume(format!("{instance}: no uid range assigned")))?;
        ensure_volumes(&self.podman, instance, spec).await?;
        Ok(Prepared {
            range,
            volumes: attachments(instance, spec),
        })
    }

    /// Does a container's `weglarka.uid-range` label match the instance's range? (Part of "is the
    /// container what we would create now"; a container without the label — created by Węglarka before
    /// ranges existed — never matches.)
    pub(crate) fn uid_range_matches(
        &self,
        instance: &InstanceName,
        container_labels: &BTreeMap<String, String>,
    ) -> bool {
        let range = state::load_state(&self.paths.state)
            .ok()
            .and_then(|st| st.apps.get(instance).and_then(|s| s.uid_range));
        range.map(labels::uid_range_label).as_deref()
            == container_labels.get(labels::UID_RANGE).map(String::as_str)
    }

    /// Migration: instances that already run (pinned digest) but have no range yet get one, so the
    /// reconcile plan recreates their container once, now with an explicit map. Returns the instances
    /// that could not be assigned one (pool exhausted…), with the reason.
    pub(crate) async fn adopt_uid_ranges(&self, apps: &AppsFile) -> BTreeMap<InstanceName, String> {
        let mut failed = BTreeMap::new();
        let Ok(st) = state::load_state(&self.paths.state) else {
            return failed; // the caller loads the state again and reports the error
        };
        for name in apps.apps.keys() {
            let needs = st
                .apps
                .get(name)
                .is_some_and(|s| s.current.is_some() && s.uid_range.is_none());
            if needs && let Err(e) = self.assign_uid_range(name).await {
                failed.insert(name.clone(), e.to_string());
            }
        }
        failed
    }

    /// State of instances no longer in `apps.toml`: dropped, unless volumes of the instance remain —
    /// then only its `uid_range` is kept (reserved) so a later `apps add` finds its files owned
    /// correctly. Returns whether `st` changed.
    pub(crate) async fn settle_orphan_state(&self, st: &mut StateFile, apps: &AppsFile) -> bool {
        let orphans: Vec<InstanceName> = st
            .apps
            .keys()
            .filter(|k| !apps.apps.contains_key(*k))
            .cloned()
            .collect();
        let mut changed = false;
        for name in orphans {
            let current = st.apps[&name].clone();
            let keep = match current.uid_range {
                None => None,
                Some(range) => {
                    let filter = VolumeFilter {
                        labels: BTreeMap::from([(labels::INSTANCE.to_owned(), name.to_string())]),
                    };
                    // Cannot tell → keep: freeing a range that still owns data is the worse error.
                    let has_volumes = self
                        .podman
                        .volume_list(&filter)
                        .await
                        .map_or(true, |v| !v.is_empty());
                    has_volumes.then_some(AppState {
                        uid_range: Some(range),
                        ..AppState::default()
                    })
                }
            };
            if keep.as_ref() == Some(&current) {
                continue;
            }
            changed = true;
            match keep {
                Some(stub) => {
                    st.apps.insert(name, stub);
                }
                None => {
                    st.apps.remove(&name);
                }
            }
        }
        changed
    }

    /// `apps remove`. Without `purge_volumes` the instance's volumes (and range) stay. With it, the
    /// container and every volume labelled with the instance are deleted and the range is released.
    pub async fn remove_app_with_volumes(
        &self,
        name: &InstanceName,
        purge_volumes: bool,
    ) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if apps.apps.remove(name).is_none() {
            return Err(EngineError::UnknownInstance(name.clone()));
        }
        state::save_apps(&self.paths.apps, &apps)?;
        if !purge_volumes {
            return Ok(());
        }
        // A volume in use cannot be removed: the container goes first (desired state no longer lists it).
        match self
            .podman
            .container_remove(&labels::container_name(name), true)
            .await
        {
            Ok(()) | Err(PodmanError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        let filter = VolumeFilter {
            labels: BTreeMap::from([(labels::INSTANCE.to_owned(), name.to_string())]),
        };
        for v in self.podman.volume_list(&filter).await? {
            match self.podman.volume_remove(&v.name, true).await {
                Ok(()) | Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut st = state::load_state(&self.paths.state)?;
        if st.apps.remove(name).is_some() {
            state::save_state(&self.paths.state, &st)?;
        }
        Ok(())
    }

    /// Imports a tar made elsewhere (Coolify…) into one of the instance's volumes, mapping its uids
    /// through the instance's namespace: files owned by uid 1000 in the tar end up owned by the
    /// container's uid 1000. Do **not** use it for Węglarka's own exports — those carry namespace ids
    /// and go through `volume_import` (docs/decisions/0009, findings 8–9).
    ///
    /// The instance must have been deployed once (its image and range are needed). The tar is
    /// extracted by Podman into a created, never started helper container that mounts the volume;
    /// Węglarka unpacks nothing itself.
    pub async fn import_foreign(
        &self,
        instance: &InstanceName,
        volume: &str,
        tar: TarStream,
        lock_wait: Duration,
    ) -> Result<(), EngineError> {
        // Only the wait for the lock is bounded; the upload itself may take as long as it takes.
        let _g = tokio::time::timeout(lock_wait, self.lock.lock())
            .await
            .map_err(|_| EngineError::Busy)?;
        let spec = state::load_apps(&self.paths.apps)?
            .apps
            .remove(instance)
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        let mount = spec
            .volumes
            .iter()
            .find(|v| v.name == volume)
            .ok_or_else(|| EngineError::Volume(format!("{instance} declares no volume {volume:?}")))?;
        let st = state::load_state(&self.paths.state)?;
        let app = st.apps.get(instance);
        let (Some(digest), Some(range)) = (
            app.and_then(|s| s.current.clone()),
            app.and_then(|s| s.uid_range),
        ) else {
            return Err(EngineError::Volume(format!(
                "{instance} is not deployed yet; deploy it once before importing"
            )));
        };
        ensure_volumes(&self.podman, instance, &spec).await?;

        let reference = pinned_ref(&spec.image, &digest);
        let image = match self.podman.image_inspect(&reference).await {
            Ok(_) => reference,
            Err(PodmanError::NotFound(_)) => self
                .podman
                .container_inspect(&labels::container_name(instance))
                .await
                .ok()
                .map(|c| c.image_id)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    EngineError::Volume(format!(
                        "image of {instance} is not present locally; run `deploy` first"
                    ))
                })?,
            Err(e) => return Err(e.into()),
        };

        let name = labels::import_container_name(instance);
        match self.podman.container_remove(&name, true).await {
            Ok(()) | Err(PodmanError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        let mut helper = ContainerSpec {
            name: name.clone(),
            image,
            labels: BTreeMap::from([(labels::IMPORT_FOR.to_owned(), instance.to_string())]),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::No,
            userns_auto: false,
            mounts: vec![],
            volumes: vec![VolumeAttachment {
                volume: labels::volume_name(instance, volume),
                target: mount.target.clone(),
                read_only: false, // the spec's read_only applies to the app, not to the import
            }],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: Some(id_mapping(range)),
        };
        helper.labels.insert(
            labels::UID_RANGE.to_owned(),
            labels::uid_range_label(range),
        );
        let result = async {
            self.podman.container_create(&helper).await?;
            self.podman
                .container_archive_put(&name, &mount.target, tar)
                .await
        }
        .await;
        let _ = self.podman.container_remove(&name, true).await;
        Ok(result?)
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use futures_util::stream;

    use super::*;
    use crate::app::Digest;
    use crate::podman::ContainerState;
    use crate::reconcile::{Action, ActionOutcome, ReconcilerOptions, RecreateReason};
    use crate::secret_store::SecretStore;
    use crate::secrets::FileSecretStore;
    use crate::state::{StatePaths, load_state};
    use crate::testing::{Call, FakePodman};

    const WAIT: Duration = Duration::from_secs(1);
    const IMAGE: &str = "ghcr.io/x/szklana:latest";
    const APP: &str = r#"
[apps.szklana]
image = "ghcr.io/x/szklana:latest"
port = 8080
health = { attempts = 2, window_secs = 2 }
volumes = [{ name = "data", target = "/data" }, { name = "cache", target = "/cache", read_only = true }]
"#;
    const PLAIN: &str = r#"
[apps.ntfy]
image = "ghcr.io/x/szklana:latest"
health = { attempts = 2, window_secs = 2 }
"#;

    struct Env {
        _dir: tempfile::TempDir,
        fake: FakePodman,
        rec: Reconciler<FakePodman>,
    }

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn name(s: &str) -> InstanceName {
        InstanceName::new(s).unwrap()
    }

    fn env(apps: &str) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::in_dir(dir.path());
        std::fs::write(&paths.apps, apps).unwrap();
        let fake = FakePodman::new();
        fake.set_pull_digest(IMAGE, digest('a'));
        let store: Arc<dyn SecretStore> =
            Arc::new(FileSecretStore::new(dir.path().join("secrets.toml")));
        let rec = Reconciler::new(fake.clone(), store, paths, ReconcilerOptions::default());
        Env {
            _dir: dir,
            fake,
            rec,
        }
    }

    impl Env {
        fn set_apps(&self, toml: &str) {
            std::fs::write(&self.rec.paths().apps, toml).unwrap();
        }
        fn state(&self) -> StateFile {
            load_state(&self.rec.paths().state).unwrap()
        }
        fn range(&self, inst: &str) -> Option<UidRange> {
            self.state().apps.get(&name(inst)).and_then(|s| s.uid_range)
        }
        fn mapping(&self, container: &str) -> IdMapping {
            self.fake
                .container_spec(container)
                .unwrap()
                .id_mapping
                .expect("container created without an explicit id map")
        }
    }

    fn tar() -> TarStream {
        Box::pin(stream::iter([Ok(Bytes::from_static(b"tar"))]))
    }

    #[tokio::test(start_paused = true)]
    async fn first_deploy_assigns_a_range_and_creates_labelled_volumes() {
        let e = env(APP);
        assert!(e.rec.reconcile().await.unwrap().is_clean());

        let r = e.range("szklana").unwrap();
        assert_eq!(r, UidRange { start: 1, size: DEFAULT_RANGE_SIZE });
        assert_eq!(e.mapping("szklana"), id_mapping(r));
        let spec = e.fake.container_spec("szklana").unwrap();
        assert!(!spec.userns_auto);
        assert_eq!(spec.labels[labels::UID_RANGE], "1+65536");
        assert_eq!(
            spec.volumes,
            [
                VolumeAttachment {
                    volume: "szklana.data".into(),
                    target: "/data".into(),
                    read_only: false
                },
                VolumeAttachment {
                    volume: "szklana.cache".into(),
                    target: "/cache".into(),
                    read_only: true
                },
            ]
        );
        // Created by us (labelled), before the container, not implicitly by the container create.
        let vols = e.fake.volumes();
        assert_eq!(vols.len(), 2);
        assert!(vols.iter().all(|v| v.labels[labels::INSTANCE] == "szklana"));
        let calls = e.fake.calls();
        let first_volume = calls.iter().position(|c| matches!(c, Call::VolumeCreate(_)));
        let create = calls.iter().position(|c| matches!(c, Call::ContainerCreate(_)));
        assert!(first_volume < create);
    }

    #[tokio::test(start_paused = true)]
    async fn range_is_stable_across_redeploys_and_recreates() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let r = e.range("szklana").unwrap();

        e.rec.deploy(&name("szklana"), true).await.unwrap();
        e.fake.set_pull_digest(IMAGE, digest('b'));
        e.rec.deploy(&name("szklana"), false).await.unwrap();
        e.fake.container_remove("szklana", true).await.unwrap();
        e.rec.reconcile().await.unwrap(); // recreated from the pinned digest

        assert_eq!(e.range("szklana"), Some(r));
        assert_eq!(e.mapping("szklana"), id_mapping(r));
        assert_eq!(e.fake.volumes().len(), 2, "volumes are reused, not duplicated");
    }

    #[tokio::test(start_paused = true)]
    async fn instances_get_disjoint_ranges_and_ingress_does_too() {
        let e = env(&format!("{APP}\n{}", PLAIN));
        e.rec.reconcile().await.unwrap();
        let ingress = e.rec.ensure_ingress_range().await.unwrap();
        assert_eq!(e.rec.ensure_ingress_range().await.unwrap(), ingress, "stable");

        let (a, b) = (e.range("ntfy").unwrap(), e.range("szklana").unwrap());
        assert_eq!((a.start, b.start), (1, 65_537));
        assert_eq!(ingress.size, INFRA_RANGE_SIZE);
        assert!(!a.overlaps(b) && !a.overlaps(ingress) && !b.overlaps(ingress));
        assert_eq!(e.state().ingress_uid_range, Some(ingress));
    }

    #[tokio::test(start_paused = true)]
    async fn exhausted_pool_blocks_only_the_instance_that_does_not_fit() {
        let e = env(&format!("{APP}\n{PLAIN}"));
        e.fake.set_subuid_pool(70_000); // room for exactly one full range
        let report = e.rec.reconcile().await.unwrap();

        assert!(e.range("ntfy").is_some(), "first in alphabetical order wins");
        assert!(e.range("szklana").is_none());
        assert!(report.actions.iter().any(|a| a.result.is_err()), "{report:?}");
        assert!(e.fake.container_spec("szklana").is_none());
        assert!(e.fake.volumes().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn instance_without_range_is_migrated_with_one_recreate() {
        let e = env(PLAIN);
        e.rec.reconcile().await.unwrap();
        // Rewind to what the MVP produced: no range in state, a container on the default map.
        let mut legacy = e.fake.container_spec("ntfy").unwrap();
        legacy.id_mapping = None;
        legacy.userns_auto = true;
        legacy.labels.remove(labels::UID_RANGE);
        e.fake.container_remove("ntfy", true).await.unwrap();
        e.fake.container_create(&legacy).await.unwrap();
        e.fake.container_start("ntfy").await.unwrap();
        let mut st = e.state();
        st.apps.get_mut(&name("ntfy")).unwrap().uid_range = None;
        crate::state::save_state(&e.rec.paths().state, &st).unwrap();

        let report = e.rec.reconcile().await.unwrap();
        assert!(matches!(
            report.actions[..],
            [crate::reconcile::ActionReport {
                action: Action::Recreate { reason: RecreateReason::SpecDrift, .. },
                result: Ok(ActionOutcome::Recreated(_)),
            }]
        ));
        assert_eq!(e.mapping("ntfy"), id_mapping(e.range("ntfy").unwrap()));
        assert_eq!(e.fake.containers()[0].state, ContainerState::Running);

        let again = e.rec.reconcile().await.unwrap();
        assert!(again.actions.is_empty(), "migration happens once: {again:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn manual_deploy_of_an_unmigrated_instance_recreates_instead_of_reporting_unchanged() {
        let e = env(PLAIN);
        e.rec.reconcile().await.unwrap();
        let mut legacy = e.fake.container_spec("ntfy").unwrap();
        legacy.labels.remove(labels::UID_RANGE);
        e.fake.container_remove("ntfy", true).await.unwrap();
        e.fake.container_create(&legacy).await.unwrap();
        e.fake.container_start("ntfy").await.unwrap();

        let out = e.rec.deploy(&name("ntfy"), false).await.unwrap();
        assert!(matches!(out, crate::deploy::DeployOutcome::Deployed { .. }), "{out:?}");
        assert!(e.fake.container_spec("ntfy").unwrap().labels.contains_key(labels::UID_RANGE));
    }

    #[tokio::test(start_paused = true)]
    async fn plain_remove_keeps_volumes_and_their_range_until_purged() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let r = e.range("szklana").unwrap();

        e.rec.remove_app_with_volumes(&name("szklana"), false).await.unwrap();
        e.rec.reconcile().await.unwrap();
        assert!(e.fake.containers().is_empty(), "container pruned");
        assert_eq!(e.fake.volumes().len(), 2, "volumes survive apps remove");
        assert_eq!(e.range("szklana"), Some(r), "range stays reserved");
        let st = e.state();
        assert_eq!(st.apps[&name("szklana")], AppState { uid_range: Some(r), ..Default::default() });

        // Re-adding the app finds its files owned correctly: same range, same volumes.
        e.set_apps(APP);
        e.rec.reconcile().await.unwrap();
        assert_eq!(e.range("szklana"), Some(r));
        assert_eq!(e.mapping("szklana"), id_mapping(r));

        e.rec.remove_app_with_volumes(&name("szklana"), true).await.unwrap();
        assert!(e.fake.containers().is_empty());
        assert!(e.fake.volumes().is_empty());
        assert_eq!(e.range("szklana"), None, "purge releases the range");
        // The freed range is the first one handed out again.
        e.set_apps(PLAIN);
        e.rec.reconcile().await.unwrap();
        assert_eq!(e.range("ntfy"), Some(r));
    }

    #[tokio::test(start_paused = true)]
    async fn orphan_settling_does_not_clobber_ranges_assigned_in_the_same_pass() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        // `szklana` leaves (keeps volumes) while `ntfy` is deployed for the first time in one pass.
        e.set_apps(PLAIN);
        e.rec.reconcile().await.unwrap();
        let st = e.state();
        assert!(st.apps[&name("ntfy")].uid_range.is_some());
        assert!(st.apps[&name("szklana")].uid_range.is_some());
        assert!(!st.apps[&name("ntfy")].uid_range.unwrap().overlaps(st.apps[&name("szklana")].uid_range.unwrap()));
    }

    #[tokio::test(start_paused = true)]
    async fn removing_an_app_without_volumes_releases_its_range_on_the_next_pass() {
        let e = env(PLAIN);
        e.rec.reconcile().await.unwrap();
        assert!(e.range("ntfy").is_some());
        e.rec.remove_app_with_volumes(&name("ntfy"), false).await.unwrap();
        e.rec.reconcile().await.unwrap();
        assert!(e.state().apps.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn purge_of_unknown_app_is_an_error_and_touches_nothing() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let err = e.rec.remove_app_with_volumes(&name("nope"), true).await.unwrap_err();
        assert!(matches!(err, EngineError::UnknownInstance(_)));
        assert_eq!(e.fake.volumes().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn foreign_import_goes_through_a_unstarted_helper_container_in_the_instance_range() {
        let e = env(APP);
        assert!(e.rec.import_foreign(&name("szklana"), "data", tar(), WAIT).await.is_err(), "not deployed");
        e.rec.reconcile().await.unwrap();
        let before = e.fake.calls().len();

        e.rec.import_foreign(&name("szklana"), "data", tar(), WAIT).await.unwrap();

        let calls = e.fake.calls()[before..].to_vec();
        assert!(calls.contains(&Call::ContainerCreate("wg-import.szklana".into())));
        assert!(calls.contains(&Call::ContainerArchivePut {
            name: "wg-import.szklana".into(),
            path: "/data".into()
        }));
        assert!(!calls.iter().any(|c| matches!(c, Call::ContainerStart(n) if n == "wg-import.szklana")));
        assert!(!calls.iter().any(|c| matches!(c, Call::VolumeImport(_))), "not the raw volume import");
        assert!(e.fake.container_spec("wg-import.szklana").is_none(), "helper is cleaned up");
    }

    #[tokio::test(start_paused = true)]
    async fn foreign_import_rejects_unknown_volumes() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let err = e.rec.import_foreign(&name("szklana"), "nope", tar(), WAIT).await.unwrap_err();
        assert!(matches!(err, EngineError::Volume(_)), "{err:?}");
    }

    #[test]
    fn id_mapping_is_one_line_per_map() {
        let m = id_mapping(UidRange { start: 65_537, size: 65_536 });
        assert_eq!(m.uid_map, m.gid_map);
        assert_eq!(
            m.uid_map,
            [IdRange { container_id: 0, host_id: 65_537, size: 65_536 }]
        );
    }
}
