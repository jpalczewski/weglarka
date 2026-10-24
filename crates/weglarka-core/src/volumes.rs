//! Volumes and file ownership of the deploy engine (iteration 2, docs/decisions/0009-volume-ownership.md;
//! shared volumes: issue #33, docs/decisions/0017-shared-volumes.md).
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
//! * **shared volumes** — a declared `[shared_volumes.<name>]` volume owns one range
//!   (`StateFile::shared_volumes`), and every member instance runs in it ([`effective_range`]);
//!   the Podman volume is `wg-shared-<name>` labelled `weglarka.shared-volume`, never
//!   `weglarka.instance`, so instance purge/GC do not touch it;
//! * **volume creation** before `container_create` (Podman would create a missing volume implicitly,
//!   but without the `weglarka.instance` label that purge and list rely on);
//! * **purge** on `apps remove --purge-volumes` (refused when another member still uses a shared
//!   volume) and on `remove_shared_volume`;
//! * **foreign tar import** through a created-but-never-started helper container, so the ids of the tar
//!   are mapped through the instance's namespace (`container_archive_put`, finding 9 of the ADR).
//!
//! All state changes happen under the engine's `lock` (the sole `state.toml` writer).

use std::collections::BTreeMap;
use std::time::Duration;

use crate::app::{AppSpec, AppsFile, Digest, InstanceName, SharedVolumeName, SharedVolumeSpec};
use crate::deploy::pinned_ref;
use crate::labels;
use crate::podman::{
    ContainerSpec, ContainerState, IdMapping, IdRange, PodmanClient, PodmanError, RestartPolicy,
    Result, TarStream, VolumeAttachment, VolumeFilter, VolumeSpec,
};
use crate::reconcile::{EngineError, Reconciler, RecreateReason};
use crate::shared_volumes;
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

/// The uid/gid range a container of `instance` runs in: the range of its shared volumes' group when
/// the spec mounts any (all members share it, docs/decisions/0017 and 0029), otherwise the
/// instance's own range. `st.shared_volumes` is keyed by group name.
pub fn effective_range(
    apps: &AppsFile,
    st: &StateFile,
    instance: &InstanceName,
    spec: &AppSpec,
) -> Option<UidRange> {
    match shared_volumes::spec_group(apps, spec) {
        Some(group) => st.shared_volumes.get(&group).and_then(|s| s.uid_range),
        None => st.apps.get(instance).and_then(|s| s.uid_range),
    }
}

/// [`effective_range`] as the value of the container's `weglarka.uid-range` label.
pub fn effective_range_label(
    apps: &AppsFile,
    st: &StateFile,
    instance: &InstanceName,
    spec: &AppSpec,
) -> Option<String> {
    effective_range(apps, st, instance, spec).map(labels::uid_range_label)
}

/// Podman volume name and labels for an instance's volume.
fn volume_spec(instance: &InstanceName, name: &str) -> VolumeSpec {
    VolumeSpec {
        name: labels::volume_name(instance, name),
        labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.to_string())]),
    }
}

/// Podman volume name and labels for a shared volume (no `weglarka.instance` label on purpose).
fn shared_volume_spec(name: &SharedVolumeName, group: &SharedVolumeName) -> VolumeSpec {
    VolumeSpec {
        name: labels::shared_volume_name(name),
        labels: BTreeMap::from([
            (labels::SHARED_VOLUME.to_owned(), name.to_string()),
            (labels::SHARED_GROUP.to_owned(), group.to_string()),
        ]),
    }
}

/// Creates the instance's declared volumes (idempotent, labelled `weglarka.instance`).
pub async fn ensure_volumes<P: PodmanClient>(
    podman: &P,
    instance: &InstanceName,
    spec: &AppSpec,
) -> Result<()> {
    for v in &spec.volumes {
        podman
            .volume_create(&volume_spec(instance, &v.name))
            .await?;
    }
    Ok(())
}

/// Group recorded on an existing shared volume: the [`labels::SHARED_GROUP`] label, or — for a
/// volume created before groups existed — the volume's own name.
fn recorded_group(name: &SharedVolumeName, labels: &BTreeMap<String, String>) -> SharedVolumeName {
    labels
        .get(labels::SHARED_GROUP)
        .and_then(|g| SharedVolumeName::new(g).ok())
        .unwrap_or_else(|| name.clone())
}

/// Creates a shared volume (idempotent, labelled `weglarka.shared-volume` and
/// `weglarka.shared-group`). An existing volume keeps its labels, so a volume whose recorded group
/// differs from the declared one is refused: its files belong to the old group's uid range
/// (docs/decisions/0029).
pub async fn ensure_shared_volume<P: PodmanClient>(
    podman: &P,
    name: &SharedVolumeName,
    group: &SharedVolumeName,
) -> Result<(), EngineError> {
    match podman
        .volume_inspect(&labels::shared_volume_name(name))
        .await
    {
        Ok(info) => {
            let recorded = recorded_group(name, &info.labels);
            if recorded != *group {
                return Err(EngineError::SharedGroupChange {
                    volume: name.clone(),
                    from: recorded,
                    to: group.clone(),
                });
            }
            Ok(())
        }
        Err(PodmanError::NotFound(_)) => Ok(podman
            .volume_create(&shared_volume_spec(name, group))
            .await?),
        Err(e) => Err(e.into()),
    }
}

/// [`ensure_shared_volume`] for every shared volume the spec mounts.
pub async fn ensure_shared_volumes<P: PodmanClient>(
    podman: &P,
    apps: &AppsFile,
    spec: &AppSpec,
) -> Result<(), EngineError> {
    for mount in &spec.shared_volumes {
        let group = shared_volumes::volume_group(apps, &mount.name);
        ensure_shared_volume(podman, &mount.name, &group).await?;
    }
    Ok(())
}

/// Container-side mounts for the instance's declared private volumes and shared volumes.
pub fn attachments(instance: &InstanceName, spec: &AppSpec) -> Vec<VolumeAttachment> {
    let private = spec.volumes.iter().map(|v| VolumeAttachment {
        volume: labels::volume_name(instance, &v.name),
        target: v.target.clone(),
        read_only: v.read_only,
    });
    let shared = spec.shared_volumes.iter().map(|v| VolumeAttachment {
        volume: labels::shared_volume_name(&v.name),
        target: v.target.clone(),
        read_only: v.read_only,
    });
    private.chain(shared).collect()
}

/// Instance names joined for a user-facing error message.
fn join_names(names: &[InstanceName]) -> String {
    names
        .iter()
        .map(InstanceName::as_str)
        .collect::<Vec<_>>()
        .join(", ")
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
        container.labels.insert(
            labels::UID_RANGE.to_owned(),
            labels::uid_range_label(self.range),
        );
    }
}

/// What `apps remove` deletes besides the desired-state entry. Both are kept by default: data and
/// credentials survive `remove` + `add` under the same name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemoveAppOptions {
    /// Delete the instance's named volumes and release its uid range.
    pub purge_volumes: bool,
    /// Delete the whole `<instance>.*` scope from the secret store.
    pub purge_secrets: bool,
}

impl<P: PodmanClient> Reconciler<P> {
    /// First free range of `size` among everything `state.toml` has handed out (instances, shared
    /// volumes and the ingress nginx alike).
    async fn allocate_range(&self, st: &StateFile, size: u32) -> Result<UidRange, EngineError> {
        let used: Vec<UidRange> = st
            .apps
            .values()
            .filter_map(|s| s.uid_range)
            .chain(st.shared_volumes.values().filter_map(|s| s.uid_range))
            .chain(st.ingress_uid_range)
            .collect();
        let pool = self.podman.subuid_pool().await?;
        allocate(&used, pool, size).ok_or(EngineError::UidPoolExhausted { pool, size })
    }

    /// Range of a shared volume group; allocated and persisted on first use. Caller holds the engine
    /// lock and calls this *before* loading the state it is going to modify (it writes `state.toml`
    /// itself).
    async fn assign_shared_range(&self, name: &SharedVolumeName) -> Result<UidRange, EngineError> {
        let mut st = state::load_state(&self.paths.state)?;
        if let Some(r) = st.shared_volumes.get(name).and_then(|s| s.uid_range) {
            return Ok(r);
        }
        let range = self.allocate_range(&st, DEFAULT_RANGE_SIZE).await?;
        st.shared_volumes.entry(name.clone()).or_default().uid_range = Some(range);
        state::save_state(&self.paths.state, &st)?;
        tracing::info!(
            group = %name,
            start = range.start,
            size = range.size,
            "assigned uid range for a shared volume group"
        );
        Ok(range)
    }

    /// The range the instance's container must run in: the shared volume's range for a member,
    /// otherwise its own range ([`effective_range`]). Allocated and persisted on first use. Caller
    /// holds the engine lock and calls this *before* loading the state it is going to modify (it
    /// writes `state.toml` itself).
    pub(crate) async fn assign_range(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<UidRange, EngineError> {
        let apps = state::load_apps(&self.paths.apps)?;
        if let Some(group) = shared_volumes::spec_group(&apps, spec) {
            return self.assign_shared_range(&group).await;
        }
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
        tracing::info!(
            start = range.start,
            size = range.size,
            "assigned ingress uid range"
        );
        Ok(range)
    }

    /// Ownership and volumes for a container about to be created. The range must already be assigned
    /// ([`Self::assign_range`]) and the range-change guard must have run; volumes (private and
    /// shared) are created here, before the old container is touched. The returned
    /// [`Prepared::range`] is what the caller persists as the data owner
    /// (`AppState::effective_uid_range`, issue #75).
    pub(crate) async fn prepare_container(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<Prepared, EngineError> {
        let apps = state::load_apps(&self.paths.apps)?;
        let range = effective_range(
            &apps,
            &state::load_state(&self.paths.state)?,
            instance,
            spec,
        )
        .ok_or_else(|| EngineError::Volume(format!("{instance}: no uid range assigned")))?;
        ensure_volumes(&self.podman, instance, spec).await?;
        ensure_shared_volumes(&self.podman, &apps, spec).await?;
        // The caller persists `Prepared.range` as `AppState::effective_uid_range` together with the
        // rest of the deploy state, so the range-change guard still knows the data owner when the
        // container is gone (issue #75).
        Ok(Prepared {
            range,
            volumes: attachments(instance, spec),
        })
    }

    /// Does a container's `weglarka.uid-range` label match the range the instance would get now
    /// (its own or the shared volume's)? (Part of "is the container what we would create now"; a
    /// container without the label — created by Węglarka before ranges existed — never matches when
    /// a range is known.)
    pub(crate) fn uid_range_matches(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        container_labels: &BTreeMap<String, String>,
    ) -> bool {
        let (Ok(apps), Ok(st)) = (
            state::load_apps(&self.paths.apps),
            state::load_state(&self.paths.state),
        ) else {
            return false;
        };
        effective_range_label(&apps, &st, instance, spec).as_deref()
            == container_labels.get(labels::UID_RANGE).map(String::as_str)
    }

    /// Migration: instances that already run (pinned digest) but have no effective range yet — a
    /// member whose shared volume has not been allocated — get one, so the reconcile plan recreates
    /// their container once, now with an explicit map. Returns the instances that could not be
    /// assigned one (pool exhausted…), with the reason.
    pub(crate) async fn adopt_uid_ranges(&self, apps: &AppsFile) -> BTreeMap<InstanceName, String> {
        let mut failed = BTreeMap::new();
        let Ok(st) = state::load_state(&self.paths.state) else {
            return failed; // the caller loads the state again and reports the error
        };
        for (name, spec) in &apps.apps {
            let needs = st.apps.get(name).is_some_and(|s| s.current.is_some())
                && effective_range_label(apps, &st, name, spec).is_none();
            if needs && let Err(e) = self.assign_range(name, spec).await {
                failed.insert(name.clone(), e.to_string());
            }
        }
        failed
    }

    /// State of instances no longer in `apps.toml`: dropped, unless volumes of the instance remain —
    /// then only its `uid_range`/`effective_uid_range` are kept (reserved and remembered as the data
    /// owner) so a later `apps add` finds its files owned correctly and cannot silently move them
    /// into another range. Returns whether `st` changed.
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
            let keep = if current.uid_range.is_none() && current.effective_uid_range.is_none() {
                None
            } else {
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
                    uid_range: current.uid_range,
                    effective_uid_range: current.effective_uid_range,
                    ..AppState::default()
                })
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

    /// Whether any Podman volume still belongs to `group` (a volume labelled with the group, or a
    /// volume created before groups whose own name is the group). If Podman cannot tell, the answer
    /// is "yes": freeing a range that still owns data is the worse error.
    async fn group_has_volumes(&self, group: &SharedVolumeName) -> bool {
        for key in [labels::SHARED_GROUP, labels::SHARED_VOLUME] {
            let filter = VolumeFilter {
                labels: BTreeMap::from([(key.to_owned(), group.to_string())]),
            };
            match self.podman.volume_list(&filter).await {
                Ok(v) if v.is_empty() => {}
                Ok(_) | Err(_) => return true,
            }
        }
        false
    }

    /// State of shared volume groups whose data is gone: an entry (keyed by group) is dropped, and
    /// its range released, only when no Podman volume of the group exists **and** no member
    /// references any volume of the group. Data for an undeclared volume keeps the range reserved —
    /// freeing a range that still owns data is the worse error. Returns whether `st` changed.
    pub(crate) async fn settle_shared_volumes(&self, st: &mut StateFile, apps: &AppsFile) -> bool {
        let groups: Vec<SharedVolumeName> = st.shared_volumes.keys().cloned().collect();
        let mut changed = false;
        for group in groups {
            if !shared_volumes::group_members(apps, &group).is_empty() {
                continue; // still in use by a member
            }
            if !self.group_has_volumes(&group).await && st.shared_volumes.remove(&group).is_some() {
                changed = true;
            }
        }
        changed
    }

    /// `apps remove`. Without `purge_volumes` the instance's volumes (and range) stay; with it, the
    /// container and every volume labelled with the instance are deleted and the range is released.
    /// `purge_secrets` removes the instance's secrets **before** `apps.toml` is saved, so a store
    /// failure leaves the app intact and the removal retryable (issue #80).
    ///
    /// A member of a shared volume is refused (nothing is touched) while other members exist: their
    /// data lives in the same volume (issue #33).
    pub async fn remove_app_with_purges(
        &self,
        name: &InstanceName,
        options: RemoveAppOptions,
    ) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        // An app another app depends on cannot be removed (its `depends_on` would dangle, and with
        // `--purge-volumes` its data may still be in use). Nothing is modified on refusal.
        crate::depends::ensure_not_depended_on(&apps, name)?;
        let Some(spec) = apps.apps.get(name).cloned() else {
            return Err(EngineError::UnknownInstance(name.clone()));
        };
        if options.purge_volumes {
            for mount in &spec.shared_volumes {
                let others = shared_volumes::other_members(&apps, name, &mount.name);
                if !others.is_empty() {
                    return Err(EngineError::SharedVolumeInUse {
                        volume: mount.name.clone(),
                        members: join_names(&others),
                    });
                }
            }
        }
        if options.purge_secrets {
            let removed = crate::secrets::remove_instance_secrets(&self.secrets, name).await?;
            tracing::info!(
                instance = %name,
                count = removed.len(),
                "removed the instance's secrets"
            );
        }
        let apps_before = apps.clone();
        apps.apps.remove(name);
        state::save_apps(&self.paths.apps, &apps)?;
        if !options.purge_volumes {
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
        // The last member's purge deletes the shared volume too (the declaration stays).
        for mount in &spec.shared_volumes {
            let podman_name = labels::shared_volume_name(&mount.name);
            match self.podman.volume_remove(&podman_name, true).await {
                Ok(()) | Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut st = state::load_state(&self.paths.state)?;
        let mut changed = st.apps.remove(name).is_some();
        // The group's range is released with its last volume (and last member), not with this
        // app's mounts: other volumes of the group may still hold data in it (issue #129).
        if let Some(group) = shared_volumes::spec_group(&apps_before, &spec)
            && shared_volumes::group_members(&apps, &group).is_empty()
            && !self.group_has_volumes(&group).await
        {
            changed |= st.shared_volumes.remove(&group).is_some();
        }
        if changed {
            state::save_state(&self.paths.state, &st)?;
        }
        Ok(())
    }

    /// Declares a shared volume (idempotent, issue #33), optionally in a `group` that shares one uid
    /// range (issue #129). Apps mount it through `shared_volumes`. Declaring an existing volume again
    /// is a no-op when the group matches and refused (`SharedGroupChange`) when it does not: a
    /// volume's group is fixed while it exists, because its files belong to the group's range.
    pub async fn declare_shared_volume(
        &self,
        name: SharedVolumeName,
        group: Option<SharedVolumeName>,
    ) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        // A group equal to the volume's own name is the default, kept implicit in the file.
        let group = group.filter(|g| *g != name);
        if let Some(existing) = apps.shared_volumes.get(&name) {
            if existing.group == group {
                return Ok(());
            }
            return Err(EngineError::SharedGroupChange {
                volume: name.clone(),
                from: shared_volumes::volume_group(&apps, &name),
                to: group.unwrap_or_else(|| name.clone()),
            });
        }
        apps.shared_volumes.insert(name, SharedVolumeSpec { group });
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// Removes a shared volume declaration (issue #33). Refused while any app mounts it; without
    /// `purge` also refused while the Podman volume still holds data. `purge` deletes the data and
    /// releases the uid range.
    pub async fn remove_shared_volume(
        &self,
        name: &SharedVolumeName,
        purge: bool,
    ) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if !apps.shared_volumes.contains_key(name) {
            return Err(EngineError::UnknownSharedVolume(name.clone()));
        }
        let members = shared_volumes::members(&apps, name);
        if !members.is_empty() {
            return Err(EngineError::SharedVolumeInUse {
                volume: name.clone(),
                members: join_names(&members),
            });
        }
        let podman_name = labels::shared_volume_name(name);
        let exists = match self.podman.volume_inspect(&podman_name).await {
            Ok(_) => true,
            Err(PodmanError::NotFound(_)) => false,
            Err(e) => return Err(e.into()),
        };
        if exists && !purge {
            return Err(EngineError::SharedVolumeHasData {
                volume: name.clone(),
            });
        }
        let group = shared_volumes::volume_group(&apps, name);
        apps.shared_volumes.remove(name);
        state::save_apps(&self.paths.apps, &apps)?;
        if exists {
            match self.podman.volume_remove(&podman_name, true).await {
                Ok(()) | Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // The range goes with the group's last volume: siblings may still hold data in it.
        if shared_volumes::group_members(&apps, &group).is_empty()
            && !self.group_has_volumes(&group).await
        {
            let mut st = state::load_state(&self.paths.state)?;
            if st.shared_volumes.remove(&group).is_some() {
                state::save_state(&self.paths.state, &st)?;
            }
        }
        Ok(())
    }

    /// Refuses a uid-range change when the instance already has private volume data: the files are
    /// owned by the old range and a recreate with a new map would make them unreadable
    /// (docs/decisions/0017). `None` as the old label means "no owner known yet" (a brand-new
    /// instance) and is always allowed.
    pub(crate) async fn range_change_guard_locked(
        &self,
        instance: &InstanceName,
        new_label: Option<&str>,
    ) -> Result<(), EngineError> {
        let old = self
            .podman
            .container_inspect(&labels::container_name(instance))
            .await
            .ok()
            .and_then(|c| c.labels.get(labels::UID_RANGE).cloned())
            .or_else(|| {
                // No container (provisioned with `start = false`, or removed): the last effective
                // range recorded by `prepare_container` is the owner of the data (issue #75).
                state::load_state(&self.paths.state)
                    .ok()
                    .and_then(|st| st.apps.get(instance).and_then(|s| s.effective_uid_range))
                    .map(labels::uid_range_label)
            });
        let Some(old_label) = old else {
            return Ok(());
        };
        if Some(old_label.as_str()) == new_label {
            return Ok(());
        }
        let filter = VolumeFilter {
            labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.to_string())]),
        };
        if self.podman.volume_list(&filter).await?.is_empty() {
            return Ok(()); // no private volume data → a range change is safe
        }
        Err(EngineError::RangeChangeWithData {
            instance: instance.clone(),
            from: old_label,
            to: new_label.unwrap_or("a new range").to_owned(),
        })
    }

    /// Early range-change check for the daemon's `PUT /v1/apps/{name}`: compute the effective range
    /// the new spec would get and refuse before persisting when it differs and data exists.
    pub async fn check_range_change(
        &self,
        instance: &InstanceName,
        new_spec: &AppSpec,
    ) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let new_label = match (
            state::load_apps(&self.paths.apps),
            state::load_state(&self.paths.state),
        ) {
            (Ok(apps), Ok(st)) => effective_range_label(&apps, &st, instance, new_spec),
            _ => None,
        };
        self.range_change_guard_locked(instance, new_label.as_deref())
            .await
    }

    /// Imports a tar into one of the instance's volumes. The instance must have been deployed once
    /// (its image and range are needed). If its container is running it is stopped for the import and
    /// started again afterwards (also when the import failed): files swapped under a running app would
    /// leave it holding the old inodes. The state of the volume after a failed or interrupted import is
    /// partial — files already extracted stay.
    ///
    /// Which [`ImportMode`] fits depends on where the tar came from; see there. Węglarka unpacks
    /// nothing itself: Podman extracts the tar in its own chroot.
    pub async fn import_volume(
        &self,
        instance: &InstanceName,
        volume: &str,
        mode: ImportMode,
        tar: TarStream,
        lock_wait: Duration,
    ) -> Result<(), EngineError> {
        self.import_volume_with(instance, volume, mode, false, tar, lock_wait)
            .await
    }

    /// [`Self::import_volume`] with `replace`: the volume is emptied first (removed and created
    /// again), so files that are not in the tar do not survive the import. A plain import only
    /// overwrites the paths present in the tar — e.g. a stale SQLite `-wal`/`-shm` left in the
    /// volume by an earlier start would then be replayed onto the imported database.
    ///
    /// Emptying needs the volume free, so the app's container is removed; if it was running it is
    /// created again right after the import (even a failed one — then on an empty volume).
    pub async fn import_volume_with(
        &self,
        instance: &InstanceName,
        volume: &str,
        mode: ImportMode,
        replace: bool,
        tar: TarStream,
        lock_wait: Duration,
    ) -> Result<(), EngineError> {
        // Only the wait for the lock is bounded; the upload itself may take as long as it takes.
        let _g = tokio::time::timeout(lock_wait, self.lock.lock())
            .await
            .map_err(|_| EngineError::Busy)?;
        let apps = state::load_apps(&self.paths.apps)?;
        let spec = apps
            .apps
            .get(instance)
            .cloned()
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        // The target is either a private volume of the instance or a shared volume it mounts
        // (issue #33): `(path in the container, Podman volume name, shared volume)`.
        let (target_path, podman_name, shared) =
            if let Some(v) = spec.volumes.iter().find(|v| v.name == volume) {
                (
                    v.target.clone(),
                    labels::volume_name(instance, &v.name),
                    None,
                )
            } else if let Some(v) = spec
                .shared_volumes
                .iter()
                .find(|v| v.name.as_str() == volume)
            {
                (
                    v.target.clone(),
                    labels::shared_volume_name(&v.name),
                    Some(v.name.clone()),
                )
            } else {
                return Err(EngineError::Volume(format!(
                    "{instance} declares no volume {volume:?}"
                )));
            };
        let st = state::load_state(&self.paths.state)?;
        let app = st.apps.get(instance);
        let (Some(digest), Some(range)) = (
            app.and_then(|s| s.current.clone()),
            effective_range(&apps, &st, instance, &spec),
        ) else {
            return Err(EngineError::Volume(format!(
                "{instance} is not deployed yet; deploy it once before importing"
            )));
        };
        // A shared volume has several writers: importing while another member runs would write into
        // a live database, and `--replace` would even remove a volume that is still mounted.
        if let Some(name) = &shared {
            let mut running = Vec::new();
            for member in shared_volumes::other_members(&apps, instance, name) {
                let container = labels::container_name(&member);
                if self
                    .podman
                    .container_inspect(&container)
                    .await
                    .is_ok_and(|c| c.state == ContainerState::Running)
                {
                    running.push(member);
                }
            }
            if !running.is_empty() {
                return Err(EngineError::SharedVolumeBusy {
                    volume: name.clone(),
                    members: join_names(&running),
                });
            }
        }
        self.ensure_import_target(instance, &apps, &spec, shared.as_ref())
            .await?;

        let app_container = labels::container_name(instance);
        let was_running = self
            .podman
            .container_inspect(&app_container)
            .await
            .is_ok_and(|c| c.state == ContainerState::Running);
        if was_running {
            self.podman
                .container_stop(&app_container, self.options.stop_timeout_secs)
                .await?;
        }
        if replace {
            match self.podman.container_remove(&app_container, true).await {
                Ok(()) | Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
            match self.podman.volume_remove(&podman_name, false).await {
                Ok(()) | Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
            self.ensure_import_target(instance, &apps, &spec, shared.as_ref())
                .await?;
        }
        let result = match mode {
            ImportMode::Own => self
                .podman
                .volume_import(&podman_name, tar)
                .await
                .map_err(EngineError::from),
            ImportMode::Foreign => {
                self.import_through_helper(
                    instance,
                    &spec.image,
                    &ImportTarget {
                        path: target_path.clone(),
                        podman_name: podman_name.clone(),
                    },
                    &digest,
                    range,
                    tar,
                )
                .await
            }
        };
        if was_running {
            if replace {
                self.recreate_locked(instance, RecreateReason::Missing)
                    .await?;
            } else {
                self.podman.container_start(&app_container).await?;
            }
        }
        result
    }

    /// Creates the volume an import writes into (private or shared), idempotently.
    async fn ensure_import_target(
        &self,
        instance: &InstanceName,
        apps: &AppsFile,
        spec: &AppSpec,
        shared: Option<&SharedVolumeName>,
    ) -> Result<(), EngineError> {
        match shared {
            Some(name) => {
                let group = shared_volumes::volume_group(apps, name);
                ensure_shared_volume(&self.podman, name, &group).await?
            }
            None => ensure_volumes(&self.podman, instance, spec).await?,
        }
        Ok(())
    }

    /// Foreign mode: `container_archive_put` on a created, never started helper container of the
    /// instance's image, in the given (effective) range, with the volume mounted read-write.
    async fn import_through_helper(
        &self,
        instance: &InstanceName,
        image_ref: &str,
        target: &ImportTarget,
        digest: &Digest,
        range: UidRange,
        tar: TarStream,
    ) -> Result<(), EngineError> {
        let reference = pinned_ref(image_ref, digest);
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
        let helper = ContainerSpec {
            name: name.clone(),
            image,
            command: vec![],
            labels: BTreeMap::from([
                (labels::IMPORT_FOR.to_owned(), instance.to_string()),
                (labels::UID_RANGE.to_owned(), labels::uid_range_label(range)),
            ]),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::No,
            userns_auto: false,
            mounts: vec![],
            volumes: vec![VolumeAttachment {
                volume: target.podman_name.clone(),
                target: target.path.clone(),
                read_only: false, // the spec's read_only applies to the app, not to the import
            }],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: Some(id_mapping(range)),
            security: Default::default(),
        };
        let result = async {
            self.podman.container_create(&helper).await?;
            self.podman
                .container_archive_put(&name, &target.path, tar)
                .await
        }
        .await;
        let _ = self.podman.container_remove(&name, true).await;
        Ok(result?)
    }
}

/// Volume an import writes into: the mount path in the container and the Podman volume name
/// (a private volume of the instance or a shared volume it mounts, issue #33).
struct ImportTarget {
    path: String,
    podman_name: String,
}

/// Where a tar being imported came from — the ids inside it mean different things
/// (docs/decisions/0009, findings 8–9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportMode {
    /// Made elsewhere (Coolify, `docker cp`…): libpod chowns the extracted files to the container's configured user (the image `USER`; root if none),
    /// whatever the tar says, inside the
    /// instance's range. A Węglarka export imported this way fails loudly (ids outside the range).
    Foreign,
    /// A Węglarka export (`volume_export`) of the same range: it carries *namespace* ids and is
    /// restored verbatim. A foreign tar imported this way lands on the wrong uids **silently**.
    Own,
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
    /// `start = false`: provisioned (image, uid range, volumes) but no container — data must be
    /// importable before the first start (issue #29).
    const STOPPED_APP: &str = r#"
[apps.szklana]
image = "ghcr.io/x/szklana:latest"
start = false
volumes = [{ name = "data", target = "/data" }]
"#;
    /// The same app as [`APP`], but provisioned only: the container is removed, the data stays.
    const STOPPED_WITH_VOLUMES: &str = r#"
[apps.szklana]
image = "ghcr.io/x/szklana:latest"
start = false
volumes = [{ name = "data", target = "/data" }, { name = "cache", target = "/cache", read_only = true }]
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
        fn apps(&self) -> AppsFile {
            crate::state::load_apps(&self.rec.paths().apps).unwrap()
        }
        fn state(&self) -> StateFile {
            load_state(&self.rec.paths().state).unwrap()
        }
        fn range(&self, inst: &str) -> Option<UidRange> {
            self.state().apps.get(&name(inst)).and_then(|s| s.uid_range)
        }
        fn shared_range(&self, volume: &str) -> Option<UidRange> {
            self.state()
                .shared_volumes
                .get(&SharedVolumeName::new(volume).unwrap())
                .and_then(|s| s.uid_range)
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
        assert_eq!(
            r,
            UidRange {
                start: 1,
                size: DEFAULT_RANGE_SIZE
            }
        );
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
        let first_volume = calls
            .iter()
            .position(|c| matches!(c, Call::VolumeCreate(_)));
        let create = calls
            .iter()
            .position(|c| matches!(c, Call::ContainerCreate(_)));
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
        assert_eq!(
            e.fake.volumes().len(),
            2,
            "volumes are reused, not duplicated"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn instances_get_disjoint_ranges_and_ingress_does_too() {
        let e = env(&format!("{APP}\n{}", PLAIN));
        e.rec.reconcile().await.unwrap();
        let ingress = e.rec.ensure_ingress_range().await.unwrap();
        assert_eq!(
            e.rec.ensure_ingress_range().await.unwrap(),
            ingress,
            "stable"
        );

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

        assert!(
            e.range("ntfy").is_some(),
            "first in alphabetical order wins"
        );
        assert!(e.range("szklana").is_none());
        assert!(
            report.actions.iter().any(|a| a.result.is_err()),
            "{report:?}"
        );
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
                action: Action::Recreate {
                    reason: RecreateReason::SpecDrift,
                    ..
                },
                result: Ok(ActionOutcome::Recreated(_)),
            }]
        ));
        assert_eq!(e.mapping("ntfy"), id_mapping(e.range("ntfy").unwrap()));
        assert_eq!(e.fake.containers()[0].state, ContainerState::Running);

        let again = e.rec.reconcile().await.unwrap();
        assert!(
            again.actions.is_empty(),
            "migration happens once: {again:?}"
        );
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
        assert!(
            matches!(out, crate::deploy::DeployOutcome::Deployed { .. }),
            "{out:?}"
        );
        assert!(
            e.fake
                .container_spec("ntfy")
                .unwrap()
                .labels
                .contains_key(labels::UID_RANGE)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn plain_remove_keeps_volumes_and_their_range_until_purged() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let r = e.range("szklana").unwrap();

        e.rec
            .remove_app_with_purges(&name("szklana"), RemoveAppOptions::default())
            .await
            .unwrap();
        e.rec.reconcile().await.unwrap();
        assert!(e.fake.containers().is_empty(), "container pruned");
        assert_eq!(e.fake.volumes().len(), 2, "volumes survive apps remove");
        assert_eq!(e.range("szklana"), Some(r), "range stays reserved");
        let st = e.state();
        assert_eq!(
            st.apps[&name("szklana")],
            AppState {
                uid_range: Some(r),
                effective_uid_range: Some(r),
                ..Default::default()
            },
            "the reserved range and the data owner survive apps remove"
        );

        // Re-adding the app finds its files owned correctly: same range, same volumes.
        e.set_apps(APP);
        e.rec.reconcile().await.unwrap();
        assert_eq!(e.range("szklana"), Some(r));
        assert_eq!(e.mapping("szklana"), id_mapping(r));

        e.rec
            .remove_app_with_purges(
                &name("szklana"),
                RemoveAppOptions {
                    purge_volumes: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(e.fake.containers().is_empty());
        assert!(e.fake.volumes().is_empty());
        assert_eq!(e.range("szklana"), None, "purge releases the range");
        // The freed range is the first one handed out again.
        e.set_apps(PLAIN);
        e.rec.reconcile().await.unwrap();
        assert_eq!(e.range("ntfy"), Some(r));
    }

    #[tokio::test(start_paused = true)]
    async fn spec_update_adding_a_volume_recreates_and_creates_it_removing_one_keeps_the_data() {
        let e = env(PLAIN);
        e.rec.reconcile().await.unwrap();
        let r = e.range("ntfy").unwrap();

        // `apps update`: ntfy gains a volume → spec-hash changes → recreate, volume created and labelled.
        e.set_apps(&format!(
            "{PLAIN}volumes = [{{ name = \"data\", target = \"/data\" }}]\n"
        ));
        let report = e.rec.reconcile().await.unwrap();
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(e.fake.volumes().len(), 1);
        assert_eq!(e.fake.container_spec("ntfy").unwrap().volumes.len(), 1);
        assert_eq!(e.range("ntfy"), Some(r), "range unchanged by the update");

        // Dropping the volume from the spec unmounts it but never deletes data.
        e.set_apps(PLAIN);
        e.rec.reconcile().await.unwrap();
        assert!(e.fake.container_spec("ntfy").unwrap().volumes.is_empty());
        assert_eq!(e.fake.volumes().len(), 1);
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
        assert!(
            !st.apps[&name("ntfy")]
                .uid_range
                .unwrap()
                .overlaps(st.apps[&name("szklana")].uid_range.unwrap())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn removing_an_app_without_volumes_releases_its_range_on_the_next_pass() {
        let e = env(PLAIN);
        e.rec.reconcile().await.unwrap();
        assert!(e.range("ntfy").is_some());
        e.rec
            .remove_app_with_purges(&name("ntfy"), RemoveAppOptions::default())
            .await
            .unwrap();
        e.rec.reconcile().await.unwrap();
        assert!(e.state().apps.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn purge_of_unknown_app_is_an_error_and_touches_nothing() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let err = e
            .rec
            .remove_app_with_purges(
                &name("nope"),
                RemoveAppOptions {
                    purge_volumes: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::UnknownInstance(_)));
        assert_eq!(e.fake.volumes().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn foreign_import_goes_through_a_unstarted_helper_container_in_the_instance_range() {
        let e = env(APP);
        assert!(
            e.rec
                .import_volume(&name("szklana"), "data", ImportMode::Foreign, tar(), WAIT)
                .await
                .is_err(),
            "not deployed"
        );
        e.rec.reconcile().await.unwrap();
        let before = e.fake.calls().len();

        e.rec
            .import_volume(&name("szklana"), "data", ImportMode::Foreign, tar(), WAIT)
            .await
            .unwrap();

        let calls = e.fake.calls()[before..].to_vec();
        assert!(calls.contains(&Call::ContainerCreate("wg-import.szklana".into())));
        assert!(calls.contains(&Call::ContainerArchivePut {
            name: "wg-import.szklana".into(),
            path: "/data".into()
        }));
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Call::ContainerStart(n) if n == "wg-import.szklana"))
        );
        assert!(
            !calls.iter().any(|c| matches!(c, Call::VolumeImport(_))),
            "not the raw volume import"
        );
        assert!(
            e.fake.container_spec("wg-import.szklana").is_none(),
            "helper is cleaned up"
        );
    }

    /// Issue #29: `start = false` provisions the image, the uid range and the volumes without a
    /// container, so a foreign import works before the app's first start.
    #[tokio::test(start_paused = true)]
    async fn foreign_import_works_before_the_first_start() {
        let e = env(STOPPED_APP);
        let report = e.rec.reconcile().await.unwrap();
        assert!(
            report.actions.iter().all(|a| a.result.is_ok()),
            "{report:?}"
        );
        assert!(e.fake.containers().is_empty());
        let before = e.fake.calls().len();

        e.rec
            .import_volume(&name("szklana"), "data", ImportMode::Foreign, tar(), WAIT)
            .await
            .unwrap();

        let calls = e.fake.calls()[before..].to_vec();
        assert!(calls.contains(&Call::ContainerCreate("wg-import.szklana".into())));
        assert!(calls.contains(&Call::ContainerArchivePut {
            name: "wg-import.szklana".into(),
            path: "/data".into()
        }));
        assert!(
            e.fake.containers().is_empty(),
            "the app itself is still not started"
        );
        assert!(e.fake.container_spec("wg-import.szklana").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn replace_import_empties_the_volume_and_recreates_the_running_app() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let app = labels::container_name(&name("szklana"));
        let vol = labels::volume_name(&name("szklana"), "data");
        let before = e.fake.calls().len();

        e.rec
            .import_volume_with(
                &name("szklana"),
                "data",
                ImportMode::Foreign,
                true,
                tar(),
                WAIT,
            )
            .await
            .unwrap();

        let calls = e.fake.calls()[before..].to_vec();
        let pos = |want: &Call| calls.iter().position(|c| c == want).expect("call made");
        let removed = pos(&Call::ContainerRemove(app.clone()));
        let vol_removed = pos(&Call::VolumeRemove(vol.clone()));
        // `ensure_volumes` already ran (idempotently) before the removal; look for the re-creation.
        let vol_created = vol_removed
            + calls[vol_removed..]
                .iter()
                .position(|c| c == &Call::VolumeCreate(vol.clone()))
                .expect("volume created again");
        let put = pos(&Call::ContainerArchivePut {
            name: "wg-import.szklana".into(),
            path: "/data".into(),
        });
        let recreated = calls
            .iter()
            .rposition(|c| c == &Call::ContainerCreate(app.clone()))
            .expect("app recreated");
        assert!(removed < vol_removed && vol_removed < vol_created && vol_created < put);
        assert!(put < recreated);
        let running = e
            .fake
            .containers()
            .into_iter()
            .find(|c| c.name == app)
            .expect("app container exists");
        assert_eq!(running.state, ContainerState::Running, "the app runs again");
    }

    #[tokio::test(start_paused = true)]
    async fn own_import_restores_through_the_raw_volume_endpoint() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        e.rec
            .import_volume(&name("szklana"), "data", ImportMode::Own, tar(), WAIT)
            .await
            .unwrap();
        let calls = e.fake.calls();
        assert!(calls.contains(&Call::VolumeImport("szklana.data".into())));
        assert!(
            !calls
                .iter()
                .any(|c| matches!(c, Call::ContainerArchivePut { .. }))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn running_app_is_stopped_for_the_import_and_started_again_even_on_failure() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let before = e.fake.calls().len();
        e.rec
            .import_volume(&name("szklana"), "data", ImportMode::Own, tar(), WAIT)
            .await
            .unwrap();
        let calls = e.fake.calls()[before..].to_vec();
        let pos = |c: Call| calls.iter().position(|x| *x == c).unwrap();
        let (stop, import, start) = (
            pos(Call::ContainerStop("szklana".into())),
            pos(Call::VolumeImport("szklana.data".into())),
            pos(Call::ContainerStart("szklana".into())),
        );
        assert!(stop < import && import < start, "{calls:?}");

        // A tar that dies mid-way: the error is reported, the app is running again.
        let broken: TarStream = Box::pin(stream::iter([Err(PodmanError::Protocol("cut".into()))]));
        let err = e
            .rec
            .import_volume(&name("szklana"), "data", ImportMode::Own, broken, WAIT)
            .await;
        assert!(err.is_err());
        assert_eq!(e.fake.containers()[0].state, ContainerState::Running);
    }

    #[tokio::test(start_paused = true)]
    async fn stopped_app_stays_stopped_after_an_import() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        e.fake.container_stop("szklana", 1).await.unwrap();
        e.rec
            .import_volume(&name("szklana"), "data", ImportMode::Own, tar(), WAIT)
            .await
            .unwrap();
        assert_eq!(e.fake.containers()[0].state, ContainerState::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn foreign_import_rejects_unknown_volumes() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let err = e
            .rec
            .import_volume(&name("szklana"), "nope", ImportMode::Foreign, tar(), WAIT)
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::Volume(_)), "{err:?}");
    }

    #[test]
    fn id_mapping_is_one_line_per_map() {
        let m = id_mapping(UidRange {
            start: 65_537,
            size: 65_536,
        });
        assert_eq!(m.uid_map, m.gid_map);
        assert_eq!(
            m.uid_map,
            [IdRange {
                container_id: 0,
                host_id: 65_537,
                size: 65_536
            }]
        );
    }

    // ── Shared volumes (issue #33, docs/decisions/0017-shared-volumes.md) ──────────────────────

    const SHARED_APPS: &str = r#"
[shared_volumes.kajet-data]

[apps.kajet-api]
image = "ghcr.io/x/szklana:latest"
health = { attempts = 2, window_secs = 2 }
shared_volumes = [{ name = "kajet-data", target = "/data" }]

[apps.kajet-mcp]
image = "ghcr.io/x/szklana:latest"
health = { attempts = 2, window_secs = 2 }
shared_volumes = [{ name = "kajet-data", target = "/data", read_only = true }]
"#;

    fn shared_name(s: &str) -> SharedVolumeName {
        SharedVolumeName::new(s).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn members_create_the_shared_volume_once_and_run_in_one_range() {
        let e = env(SHARED_APPS);
        assert!(e.rec.reconcile().await.unwrap().is_clean());

        let r = e.shared_range("kajet-data").expect("group range allocated");
        assert_eq!(
            r,
            UidRange {
                start: 1,
                size: DEFAULT_RANGE_SIZE
            }
        );
        assert_eq!(e.mapping("kajet-api"), id_mapping(r));
        assert_eq!(e.mapping("kajet-mcp"), id_mapping(r));
        assert!(
            e.range("kajet-api").is_none() && e.range("kajet-mcp").is_none(),
            "members do not own a private range"
        );
        for c in ["kajet-api", "kajet-mcp"] {
            assert_eq!(
                e.fake.container_spec(c).unwrap().labels[labels::UID_RANGE],
                "1+65536"
            );
        }

        let podman_name = labels::shared_volume_name(&shared_name("kajet-data"));
        let vols = e.fake.volumes();
        assert_eq!(vols.len(), 1, "{vols:?}");
        assert_eq!(vols[0].name, podman_name);
        assert_eq!(
            vols[0]
                .labels
                .get(labels::SHARED_VOLUME)
                .map(String::as_str),
            Some("kajet-data")
        );
        assert!(
            !vols[0].labels.contains_key(labels::INSTANCE),
            "a shared volume must never carry the instance label (purge/GC)"
        );

        // Both containers mount it; the volume is created before any container.
        let api = e.fake.container_spec("kajet-api").unwrap();
        assert_eq!(
            api.volumes,
            [VolumeAttachment {
                volume: podman_name.clone(),
                target: "/data".into(),
                read_only: false
            }]
        );
        let mcp = e.fake.container_spec("kajet-mcp").unwrap();
        assert!(mcp.volumes[0].read_only);
        let calls = e.fake.calls();
        let created = calls
            .iter()
            .position(|c| matches!(c, Call::VolumeCreate(n) if n == &podman_name))
            .expect("shared volume created");
        let first_container = calls
            .iter()
            .position(|c| matches!(c, Call::ContainerCreate(_)))
            .expect("container created");
        assert!(created < first_container);
    }

    #[tokio::test(start_paused = true)]
    async fn members_share_one_range_so_the_pool_fits_them_all() {
        let e = env(SHARED_APPS);
        e.fake.set_subuid_pool(70_000); // room for exactly one full range: both members use it
        let report = e.rec.reconcile().await.unwrap();
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(e.mapping("kajet-api"), e.mapping("kajet-mcp"));
        assert!(e.shared_range("kajet-data").is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn shared_range_is_stable_across_redeploys_and_recreates() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();
        let r = e.shared_range("kajet-data").unwrap();

        e.rec.deploy(&name("kajet-api"), false).await.unwrap();
        e.fake.set_pull_digest(IMAGE, digest('b'));
        e.rec.deploy(&name("kajet-api"), false).await.unwrap();
        e.fake.container_remove("kajet-api", true).await.unwrap();
        e.rec.reconcile().await.unwrap(); // recreated from the pinned digest

        assert_eq!(e.shared_range("kajet-data"), Some(r));
        assert_eq!(e.mapping("kajet-api"), id_mapping(r));
        assert_eq!(e.fake.volumes().len(), 1, "not duplicated");
    }

    #[tokio::test(start_paused = true)]
    async fn plain_remove_of_a_member_keeps_the_group_volume_and_range() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();
        let r = e.shared_range("kajet-data").unwrap();

        e.rec
            .remove_app_with_purges(&name("kajet-api"), RemoveAppOptions::default())
            .await
            .unwrap();
        e.rec.reconcile().await.unwrap();
        assert!(
            e.fake.container_spec("kajet-api").is_none(),
            "container pruned"
        );
        assert_eq!(e.fake.volumes().len(), 1, "data survives apps remove");
        assert_eq!(
            e.shared_range("kajet-data"),
            Some(r),
            "range stays reserved"
        );

        // Re-adding the member finds the same range and the same volume.
        e.set_apps(SHARED_APPS);
        e.rec.reconcile().await.unwrap();
        assert_eq!(e.mapping("kajet-api"), id_mapping(r));
        assert_eq!(e.fake.volumes().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn purge_of_a_member_with_other_members_is_refused_and_touches_nothing() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();

        let err = e
            .rec
            .remove_app_with_purges(
                &name("kajet-api"),
                RemoveAppOptions {
                    purge_volumes: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        match err {
            EngineError::SharedVolumeInUse { members, .. } => assert_eq!(members, "kajet-mcp"),
            other => panic!("unexpected error: {other:?}"),
        }
        // Nothing was touched: the app is still desired, its container runs and the volume exists.
        assert!(e.apps().apps.contains_key(&name("kajet-api")));
        assert!(e.fake.container_spec("kajet-api").is_some());
        assert_eq!(e.fake.volumes().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn purge_of_the_last_member_deletes_the_group_volume_and_releases_the_range() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();
        let r = e.shared_range("kajet-data").unwrap();

        e.rec
            .remove_app_with_purges(&name("kajet-api"), RemoveAppOptions::default())
            .await
            .unwrap();
        e.rec
            .remove_app_with_purges(
                &name("kajet-mcp"),
                RemoveAppOptions {
                    purge_volumes: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            e.fake.volumes().is_empty(),
            "the last member's purge deletes the data"
        );
        assert!(e.state().shared_volumes.is_empty(), "the range is released");

        // The freed range is first-fit again.
        e.set_apps(PLAIN);
        e.rec.reconcile().await.unwrap();
        assert_eq!(e.range("ntfy"), Some(r));
    }

    #[tokio::test(start_paused = true)]
    async fn shared_volume_declaration_lifecycle() {
        let e = env(PLAIN);
        let volume = shared_name("kajet-data");
        e.rec
            .declare_shared_volume(volume.clone(), None)
            .await
            .unwrap();
        e.rec
            .declare_shared_volume(volume.clone(), None)
            .await
            .unwrap(); // idempotent
        assert!(e.apps().shared_volumes.contains_key(&volume));

        // The volume exists but no member uses it: dropping the declaration needs --purge.
        e.fake
            .volume_create(&shared_volume_spec(&volume, &volume))
            .await
            .unwrap();
        assert!(matches!(
            e.rec
                .remove_shared_volume(&volume, false)
                .await
                .unwrap_err(),
            EngineError::SharedVolumeHasData { .. }
        ));
        e.rec.remove_shared_volume(&volume, true).await.unwrap();
        assert!(e.fake.volumes().is_empty());
        assert!(!e.apps().shared_volumes.contains_key(&volume));
        assert!(matches!(
            e.rec.remove_shared_volume(&volume, true).await.unwrap_err(),
            EngineError::UnknownSharedVolume(_)
        ));
    }

    // ── Groups of shared volumes (issue #129, docs/decisions/0029-shared-volume-groups.md) ────

    const GROUPED_APPS: &str = r#"
[shared_volumes.kajet-data]
group = "kajet"

[shared_volumes.kajet-workspaces]
group = "kajet"

[apps.kajet-api]
image = "ghcr.io/x/szklana:latest"
health = { attempts = 2, window_secs = 2 }
shared_volumes = [
  { name = "kajet-data", target = "/data" },
  { name = "kajet-workspaces", target = "/workspaces" },
]

[apps.kajet-mcp]
image = "ghcr.io/x/szklana:latest"
health = { attempts = 2, window_secs = 2 }
shared_volumes = [{ name = "kajet-data", target = "/data" }]
"#;

    fn purge() -> RemoveAppOptions {
        RemoveAppOptions {
            purge_volumes: true,
            ..Default::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn volumes_of_one_group_share_one_range_and_one_mapping() {
        let e = env(GROUPED_APPS);
        e.fake.set_subuid_pool(70_000); // room for exactly one full range
        let report = e.rec.reconcile().await.unwrap();
        assert!(report.is_clean(), "{report:?}");

        let state = e.state();
        assert_eq!(
            state.shared_volumes.keys().collect::<Vec<_>>(),
            [&shared_name("kajet")],
            "the range is keyed by group, not by volume"
        );
        let r = e.shared_range("kajet").unwrap();
        assert_eq!(e.mapping("kajet-api"), id_mapping(r));
        assert_eq!(e.mapping("kajet-mcp"), id_mapping(r));

        let api = e.fake.container_spec("kajet-api").unwrap();
        assert_eq!(api.volumes.len(), 2, "{:?}", api.volumes);
        assert_eq!(e.fake.container_spec("kajet-mcp").unwrap().volumes.len(), 1);

        let vols = e.fake.volumes();
        assert_eq!(vols.len(), 2, "{vols:?}");
        for v in &vols {
            assert_eq!(
                v.labels.get(labels::SHARED_GROUP).map(String::as_str),
                Some("kajet")
            );
            assert!(!v.labels.contains_key(labels::INSTANCE));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn purge_keeps_the_group_range_until_the_last_volume_is_gone() {
        // api owns the data volume, worker the workspaces: purging one must not free the range.
        let e = env(r#"
[shared_volumes.kajet-data]
group = "kajet"

[shared_volumes.kajet-workspaces]
group = "kajet"

[apps.kajet-api]
image = "ghcr.io/x/szklana:latest"
health = { attempts = 2, window_secs = 2 }
shared_volumes = [{ name = "kajet-data", target = "/data" }]

[apps.kajet-worker]
image = "ghcr.io/x/szklana:latest"
health = { attempts = 2, window_secs = 2 }
shared_volumes = [{ name = "kajet-workspaces", target = "/workspaces" }]
"#);
        e.rec.reconcile().await.unwrap();
        let r = e.shared_range("kajet").unwrap();
        assert_eq!(e.fake.volumes().len(), 2);

        e.rec
            .remove_app_with_purges(&name("kajet-api"), purge())
            .await
            .unwrap();
        assert_eq!(e.fake.volumes().len(), 1, "only the data volume is purged");
        assert_eq!(
            e.shared_range("kajet"),
            Some(r),
            "the sibling volume still lives in the range"
        );

        e.rec
            .remove_app_with_purges(&name("kajet-worker"), purge())
            .await
            .unwrap();
        assert!(e.fake.volumes().is_empty());
        assert!(
            e.state().shared_volumes.is_empty(),
            "last volume → released"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn purge_is_refused_while_another_member_mounts_any_volume_of_the_mount() {
        let e = env(GROUPED_APPS);
        e.rec.reconcile().await.unwrap();
        // kajet-mcp also mounts kajet-data, so api's purge would delete data it uses.
        let err = e
            .rec
            .remove_app_with_purges(&name("kajet-api"), purge())
            .await
            .unwrap_err();
        assert!(
            matches!(err, EngineError::SharedVolumeInUse { .. }),
            "{err:?}"
        );
        assert_eq!(e.fake.volumes().len(), 2);
        assert!(e.apps().apps.contains_key(&name("kajet-api")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_volume_cannot_move_to_another_group_while_it_exists() {
        let e = env(GROUPED_APPS);
        e.rec.reconcile().await.unwrap();

        // Through the declaration API.
        let err = e
            .rec
            .declare_shared_volume(shared_name("kajet-data"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, EngineError::SharedGroupChange { .. }),
            "{err:?}"
        );
        e.rec
            .declare_shared_volume(shared_name("kajet-data"), Some(shared_name("kajet")))
            .await
            .unwrap(); // same group: idempotent

        // And through a hand-edited apps.toml: the volume keeps its recorded group.
        let err = ensure_shared_volume(&e.fake, &shared_name("kajet-data"), &shared_name("other"))
            .await
            .unwrap_err();
        match err {
            EngineError::SharedGroupChange { from, to, .. } => {
                assert_eq!((from, to), (shared_name("kajet"), shared_name("other")));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn declaring_with_a_group_is_persisted_and_the_default_group_stays_implicit() {
        let e = env(PLAIN);
        e.rec
            .declare_shared_volume(shared_name("kajet-data"), Some(shared_name("kajet")))
            .await
            .unwrap();
        e.rec
            .declare_shared_volume(shared_name("solo"), Some(shared_name("solo")))
            .await
            .unwrap();
        let apps = e.apps();
        assert_eq!(
            apps.shared_volumes[&shared_name("kajet-data")].group,
            Some(shared_name("kajet"))
        );
        assert_eq!(
            apps.shared_volumes[&shared_name("solo")].group,
            None,
            "a group equal to the volume name is the default and is not written"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn removing_a_declaration_keeps_the_range_while_a_sibling_has_data() {
        let e = env(GROUPED_APPS);
        e.rec.reconcile().await.unwrap();
        e.rec
            .remove_app_with_purges(&name("kajet-mcp"), RemoveAppOptions::default())
            .await
            .unwrap();
        e.rec
            .remove_app_with_purges(&name("kajet-api"), RemoveAppOptions::default())
            .await
            .unwrap();
        let r = e.shared_range("kajet").unwrap();
        e.rec
            .remove_shared_volume(&shared_name("kajet-data"), true)
            .await
            .unwrap();
        assert_eq!(
            e.shared_range("kajet"),
            Some(r),
            "kajet-workspaces still has data"
        );
        e.rec
            .remove_shared_volume(&shared_name("kajet-workspaces"), true)
            .await
            .unwrap();
        assert!(e.state().shared_volumes.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn declaration_cannot_be_removed_while_a_member_mounts_it() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();
        let err = e
            .rec
            .remove_shared_volume(&shared_name("kajet-data"), true)
            .await
            .unwrap_err();
        match err {
            EngineError::SharedVolumeInUse { members, .. } => {
                assert!(
                    members.contains("kajet-api") && members.contains("kajet-mcp"),
                    "{members}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(e.fake.volumes().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn joining_a_group_with_private_volume_data_is_refused() {
        let e = env(APP); // szklana owns private volumes with data
        e.rec.reconcile().await.unwrap();
        let old_range = e.range("szklana").unwrap();
        let old_map = e.mapping("szklana");

        let new_spec: AppSpec = toml::from_str(&format!(
            "image = \"{IMAGE}\"\nport = 8080\nshared_volumes = [{{ name = \"kajet-data\", target = \"/data\" }}]\n"
        ))
        .unwrap();
        let err = e
            .rec
            .check_range_change(&name("szklana"), &new_spec)
            .await
            .unwrap_err();
        assert!(
            matches!(err, EngineError::RangeChangeWithData { .. }),
            "{err:?}"
        );

        // The reconcile path fails the action and leaves the old container and its map untouched.
        e.set_apps(&format!(
            "[shared_volumes.kajet-data]\n\n[apps.szklana]\nimage = \"{IMAGE}\"\nport = 8080\n\
             shared_volumes = [{{ name = \"kajet-data\", target = \"/data\" }}]\n"
        ));
        let report = e.rec.reconcile().await.unwrap();
        assert!(
            report.actions.iter().any(|a| a.result.is_err()),
            "{report:?}"
        );
        assert_eq!(e.mapping("szklana"), old_map);
        assert_eq!(e.range("szklana"), Some(old_range));
        assert_eq!(e.fake.volumes().len(), 2, "private volumes keep their data");
    }

    #[tokio::test(start_paused = true)]
    async fn joining_a_group_after_provisioning_is_refused() {
        let e = env(APP); // szklana owns private volumes with data
        e.rec.reconcile().await.unwrap();
        let old_range = e.range("szklana").unwrap();

        // `apps stop` removes the container but keeps the data and the range (issue #75).
        e.set_apps(STOPPED_WITH_VOLUMES);
        e.rec.reconcile().await.unwrap();
        assert!(
            e.fake.containers().is_empty(),
            "provisioning removes the container"
        );
        assert_eq!(e.fake.volumes().len(), 2, "the private volumes survive");

        // The early check of `PUT /v1/apps/{name}` must still see the data owner.
        let new_spec: AppSpec = toml::from_str(&format!(
            "image = \"{IMAGE}\"\nport = 8080\nshared_volumes = [{{ name = \"kajet-data\", target = \"/data\" }}]\n"
        ))
        .unwrap();
        let err = e
            .rec
            .check_range_change(&name("szklana"), &new_spec)
            .await
            .unwrap_err();
        assert!(
            matches!(err, EngineError::RangeChangeWithData { .. }),
            "{err:?}"
        );

        // The reconcile path (a hand-edited apps.toml) must refuse too: nothing may start in the
        // group's range while the files belong to the old one.
        e.set_apps(&format!(
            "[shared_volumes.kajet-data]\n\n[apps.szklana]\nimage = \"{IMAGE}\"\nport = 8080\n\
             shared_volumes = [{{ name = \"kajet-data\", target = \"/data\" }}]\n"
        ));
        let report = e.rec.reconcile().await.unwrap();
        assert!(
            report.actions.iter().any(|a| a.result.is_err()),
            "{report:?}"
        );
        assert!(
            e.fake.containers().is_empty(),
            "no container in the shared range over files of the old range"
        );
        assert_eq!(e.range("szklana"), Some(old_range));
        assert_eq!(e.fake.volumes().len(), 2, "nothing new was created");
    }

    #[tokio::test(start_paused = true)]
    async fn provisioning_with_private_data_cannot_join_a_group() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        let old_range = e.range("szklana").unwrap();
        let old_map = e.mapping("szklana");

        // One edit (e.g. apps.toml written while the daemon was stopped): stop and join a group.
        e.set_apps(&format!(
            "[shared_volumes.kajet-data]\n\n[apps.szklana]\nimage = \"{IMAGE}\"\nport = 8080\n\
             start = false\n\
             volumes = [{{ name = \"data\", target = \"/data\" }}, \
             {{ name = \"cache\", target = \"/cache\", read_only = true }}]\n\
             shared_volumes = [{{ name = \"kajet-data\", target = \"/group\" }}]\n"
        ));
        let report = e.rec.reconcile().await.unwrap();
        assert!(
            report.actions.iter().any(|a| a.result.is_err()),
            "provisioning must refuse the range change before removing the container: {report:?}"
        );
        assert_eq!(
            e.mapping("szklana"),
            old_map,
            "the old container is untouched"
        );
        assert_eq!(e.range("szklana"), Some(old_range));
        assert_eq!(e.fake.volumes().len(), 2, "nothing new was created");
    }

    #[tokio::test(start_paused = true)]
    async fn re_adding_a_removed_app_cannot_join_a_group_over_its_data() {
        let e = env(APP);
        e.rec.reconcile().await.unwrap();
        e.rec
            .remove_app_with_purges(&name("szklana"), RemoveAppOptions::default())
            .await
            .unwrap();
        e.rec.reconcile().await.unwrap();
        assert_eq!(e.fake.volumes().len(), 2, "the data survives apps remove");

        let joining: AppSpec = toml::from_str(&format!(
            "image = \"{IMAGE}\"\nport = 8080\nshared_volumes = [{{ name = \"kajet-data\", target = \"/data\" }}]\n"
        ))
        .unwrap();
        let err = e
            .rec
            .check_range_change(&name("szklana"), &joining)
            .await
            .unwrap_err();
        assert!(
            matches!(err, EngineError::RangeChangeWithData { .. }),
            "the removed app's data owner is still known: {err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn leaving_a_group_without_private_data_is_allowed() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();

        e.set_apps(&format!(
            "[shared_volumes.kajet-data]\n\n[apps.kajet-api]\nimage = \"{IMAGE}\"\n"
        ));
        let report = e.rec.reconcile().await.unwrap();
        assert!(
            report.actions.iter().all(|a| a.result.is_ok()),
            "{report:?}"
        );
        let own = e
            .range("kajet-api")
            .expect("own range assigned on leaving the group");
        assert_eq!(e.mapping("kajet-api"), id_mapping(own));
        assert!(
            e.shared_range("kajet-data").is_some(),
            "the group keeps its range while the data exists"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn import_into_a_shared_volume_is_refused_while_another_member_runs() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();

        let err = e
            .rec
            .import_volume(
                &name("kajet-api"),
                "kajet-data",
                ImportMode::Own,
                tar(),
                WAIT,
            )
            .await
            .unwrap_err();
        match err {
            EngineError::SharedVolumeBusy { members, .. } => assert_eq!(members, "kajet-mcp"),
            other => panic!("unexpected error: {other:?}"),
        }

        // With the other member stopped the foreign import goes through the group range.
        e.fake.container_stop("kajet-mcp", 1).await.unwrap();
        e.rec
            .import_volume(
                &name("kajet-api"),
                "kajet-data",
                ImportMode::Foreign,
                tar(),
                WAIT,
            )
            .await
            .unwrap();
        let podman_name = labels::shared_volume_name(&shared_name("kajet-data"));
        let helper = e
            .fake
            .created_specs()
            .into_iter()
            .find(|s| s.name == "wg-import.kajet-api")
            .expect("helper container created");
        let group = e.shared_range("kajet-data").unwrap();
        assert_eq!(helper.id_mapping, Some(id_mapping(group)));
        assert_eq!(helper.volumes[0].volume, podman_name);
        assert_eq!(helper.volumes[0].target, "/data");
    }

    #[tokio::test(start_paused = true)]
    async fn start_false_provisioning_of_a_member_prepares_the_group_without_a_container() {
        let e = env(r#"
[shared_volumes.kajet-data]

[apps.kajet-api]
image = "ghcr.io/x/szklana:latest"
start = false
shared_volumes = [{ name = "kajet-data", target = "/data" }]
"#);
        assert!(e.rec.reconcile().await.unwrap().is_clean());
        assert!(e.fake.containers().is_empty());
        let group = e
            .shared_range("kajet-data")
            .expect("provisioning allocates the range");
        assert_eq!(e.fake.volumes().len(), 1);
        assert!(e.range("kajet-api").is_none());

        // Import works before the first start, through a helper in the group range.
        e.rec
            .import_volume(
                &name("kajet-api"),
                "kajet-data",
                ImportMode::Foreign,
                tar(),
                WAIT,
            )
            .await
            .unwrap();
        let helper = e
            .fake
            .created_specs()
            .into_iter()
            .find(|s| s.name == "wg-import.kajet-api")
            .expect("helper container created");
        assert_eq!(helper.id_mapping, Some(id_mapping(group)));
    }

    #[tokio::test(start_paused = true)]
    async fn settle_keeps_undeclared_shared_data_and_releases_dead_entries() {
        let e = env(SHARED_APPS);
        e.rec.reconcile().await.unwrap();
        let range = e.shared_range("kajet-data").unwrap();

        // The declaration disappears (hand-edited apps.toml) while the data remains.
        e.set_apps(PLAIN);
        e.rec.reconcile().await.unwrap();
        assert_eq!(
            e.shared_range("kajet-data"),
            Some(range),
            "data keeps the range reserved"
        );

        // Removing the data lets the next pass release the range.
        e.fake
            .volume_remove(
                &labels::shared_volume_name(&shared_name("kajet-data")),
                true,
            )
            .await
            .unwrap();
        e.rec.reconcile().await.unwrap();
        assert!(e.state().shared_volumes.is_empty());
    }
}
