//! Image provenance and retention (issue #442, `docs/decisions/0020` and `0067`): keep the
//! **current** and the **previous** (rollback) image of every repository Węglarka deploys and remove
//! the older ones.
//!
//! libpod records no provenance. Attribution therefore comes from a durable inventory
//! (`managed-images.toml`): an acquisition records the local ID, its manifest digests and the
//! `(owner, repository)` association before the reference can be discarded. Recording is an upsert:
//! it unions associations and never replaces another owner's. An image whose tag moved away (#442)
//! keeps its identity in the inventory even when libpod reports neither tags nor repository digests.
//!
//! Planning is pure ([`RetentionPlanner::plan`]); [`execute`] performs the removals and never forces
//! (`image_remove(id)` only, so libpod refuses an image a container uses). Protections cover every
//! owner regardless of the retention scope: containers, the durable inventory-backed associations,
//! `state.toml` current/previous, `self-update.toml`, the platform journal and durable reservations.
//! A retention pass runs under the image guard; `execute` takes the same guard, so a plan cannot be
//! applied after the lock was dropped.
//!
//! Fail-closed: a corrupt/unsupported inventory, an unreadable journal or self-update record, an
//! adoption that cannot be recorded blocks the whole pass ([`PruneReport::blocked`]: nothing is
//! removed or forgotten); a reservation still `loading` disables adoption for the pass; a host
//! without capabilities disables only the platform deletion it would need. `dry-run` and `doctor` share the same input
//! builder and planner; they never adopt images or mutate bookkeeping.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::deploy::{DeployOutcome, normalize_image};
use crate::reconcile::{EngineError, EngineGuard, Reconciler};
use weglarka_model::app::{AppsFile, Digest, InstanceName};
use weglarka_model::fsutil;
use weglarka_model::image_inventory::{
    Association, INVENTORY_FILE_NAME, ImageId, Inventory, MAX_RESERVATIONS, ManagedImage,
    OperationId, Owner, Protection, ProtectionIdentity, ProtectionReason, RESERVATIONS_FILE_NAME,
    Reservation, ReservationEntry, ReservationOwner, ReservationPhase, Reservations,
    RetentionScope,
};
use weglarka_model::platform_update::{
    CAPABILITIES_FILE_NAME, CapabilityError, CapabilityRecord, FILE_NAME as JOURNAL_FILE_NAME,
    PlatformUpdate, TransactionJournal, platform_prune_allowed,
};
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ImageInfo, PodmanClient, PodmanError, image_repo,
};
use weglarka_model::release_set::{Repository, StrictDigest};
use weglarka_model::state::{self, StateFile};

/// Test-only counter of atomic writes to `managed-images.toml`, for the "one read, one write"
/// assertion of [`InventoryStore::record_many`], and a seam that makes a chosen upcoming write fail
/// (a full disk, without depending on file permissions). Thread-local so parallel tests stay
/// independent.
#[cfg(test)]
pub(crate) mod write_count {
    use std::cell::Cell;

    thread_local! {
        static INVENTORY_WRITES: Cell<usize> = const { Cell::new(0) };
        static FAIL_IN: Cell<Option<usize>> = const { Cell::new(None) };
        static RESERVATION_FAIL_IN: Cell<Option<usize>> = const { Cell::new(None) };
    }

    /// `true` when this reservation-file write must fail (see [`fail_nth_reservation_write`]).
    pub(super) fn bump_reservation() -> bool {
        RESERVATION_FAIL_IN.with(|fail| match fail.get() {
            Some(1) => {
                fail.set(None);
                true
            }
            Some(n) => {
                fail.set(Some(n - 1));
                false
            }
            None => false,
        })
    }

    /// Makes the `n`th reservation-file write from now on (1 = the next one) fail once.
    pub(crate) fn fail_nth_reservation_write(n: usize) {
        RESERVATION_FAIL_IN.with(|fail| fail.set(Some(n)));
    }

    /// Counts one write; `true` when this write must fail (see [`fail_nth_write`]).
    pub(super) fn bump() -> bool {
        INVENTORY_WRITES.with(|count| count.set(count.get() + 1));
        FAIL_IN.with(|fail| match fail.get() {
            Some(1) => {
                fail.set(None);
                true
            }
            Some(n) => {
                fail.set(Some(n - 1));
                false
            }
            None => false,
        })
    }

    /// Returns the count since the last call and resets it to zero.
    pub(crate) fn take() -> usize {
        INVENTORY_WRITES.with(|count| count.replace(0))
    }

    /// Makes the `n`th inventory write from now on (1 = the next one) fail once.
    pub(crate) fn fail_nth_write(n: usize) {
        FAIL_IN.with(|fail| fail.set(Some(n)));
    }
}

/// Why an image is kept (reported by `doctor` and by `weglarka images prune --dry-run`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepReason {
    /// A container (any state — ours or not, app or ingress) references it.
    InUse(Vec<String>),
    /// A durable protection names it; see [`ProtectionReason`].
    Protected(ProtectionReason),
}

/// Outcome of planning. Only images with durable provenance (or, for an explicit prune, images
/// attributable through a repository an app still names) are candidates; unattributed images are
/// reported separately and never touched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Images kept, with the reason (sorted by image id).
    pub keep: Vec<(ImageInfo, KeepReason)>,
    /// Images to remove (sorted by image id).
    pub remove: Vec<ImageInfo>,
    /// Images in the store with no provenance: reported, never removed.
    pub unattributed: Vec<ImageInfo>,
}

impl Plan {
    /// Space the removals would reclaim. An upper bound: sizes of shared layers are counted per image.
    pub fn reclaimable_bytes(&self) -> u64 {
        self.remove.iter().map(|i| i.size_bytes).sum()
    }

    /// Nothing to remove.
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty()
    }
}

/// Result of [`execute`] and of [`Reconciler::prune_images`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Images actually removed; on a dry run — the images that *would* be removed.
    pub removed: Vec<ImageInfo>,
    /// `(image id, error)` of images Podman refused (e.g. still in use); the rest is still removed.
    /// Always empty on a dry run.
    pub failed: Vec<(String, String)>,
    /// Upper bound of the reclaimed space (see [`Plan::reclaimable_bytes`]).
    pub reclaimed_bytes: u64,
    /// The removals were only planned, nothing was removed.
    pub dry_run: bool,
    /// Fail-closed explanations (corrupt bookkeeping, disabled platform-image deletion). A non-empty
    /// list is a diagnostic, never permission to delete more.
    pub diagnostics: Vec<String>,
    /// Provenance could not be read or written, so **all** destructive cleanup was disabled for this
    /// pass: nothing was removed and nothing forgotten. The one exception is a failure to forget
    /// images that were already removed: `removed` then lists them and their inventory records
    /// remain. `diagnostics` says why.
    pub blocked: bool,
}

impl PruneReport {
    /// A pass that fail-closed on `reason` before removing anything.
    fn blocked(dry_run: bool, reason: String) -> Self {
        Self {
            dry_run,
            diagnostics: vec![format!("image retention is blocked: {reason}")],
            blocked: true,
            ..Self::default()
        }
    }
}

/// One durable image reservation as `weglarka images reservations list` shows it: enough to decide
/// whether `abandon` is safe, and nothing else (no protected image ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationInfo {
    pub operation_id: String,
    pub phase: ReservationPhase,
    /// The writer's component (`engine`, ...) and process id.
    pub component: String,
    pub pid: u32,
    /// Unix seconds when the operation started.
    pub started_at: u64,
    /// The writer's boot is not the current one: the next daemon start reclaims it, unless a
    /// nonterminal platform transaction references it. Always `false` while the host reports no
    /// boot identity (nothing can be reclaimed then).
    pub previous_boot: bool,
    /// A nonterminal platform transaction references it ([`references_reservation`]): it is not
    /// reclaimed automatically while that transaction runs. `None`: unknown, because the platform
    /// journal could not be read ([`ReservationList::diagnostics`] says why).
    pub referenced: Option<bool>,
    /// Number of image identities it protects (none while `loading`).
    pub protections: usize,
}

/// The answer of [`Reconciler::list_reservations`]: every reservation, plus what could not be
/// established while listing them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReservationList {
    /// Oldest first.
    pub reservations: Vec<ReservationInfo>,
    /// Human-readable warnings, e.g. an unreadable `platform-update.toml`: listing is read-only and
    /// is needed precisely when something is broken, so it degrades instead of failing.
    pub diagnostics: Vec<String>,
}

impl ReservationList {
    /// The file has no room left: acquisitions run unreserved and retention is blocked (the one
    /// definition, shared with the engine's own checks).
    pub fn is_full(&self) -> bool {
        reservation_count_is_full(self.reservations.len())
    }
}

/// Proof that the engine's image lock is held while a retention plan is executed.
///
/// [`execute`] takes a `&ImageGuard`, so a plan computed under the lock cannot be applied after the
/// lock was dropped (and a fresh observation replaced the one the plan was built from). The field is
/// private and the constructor is crate-visible: only code that already holds the engine guard can
/// produce one.
pub struct ImageGuard<'a> {
    _engine: &'a EngineGuard<'a>,
}

impl<'a> ImageGuard<'a> {
    pub(crate) fn new(engine: &'a EngineGuard<'a>) -> Self {
        Self { _engine: engine }
    }
}

/// The contract's retention input: observed images/containers, durable provenance, protections and
/// the requested scope. Planning is pure. The scope narrows which inventory records may be removed;
/// protections are never narrowed by it.
pub struct RetentionInput<'a> {
    pub images: &'a [ImageInfo],
    pub containers: &'a [ContainerInfo],
    pub inventory: &'a Inventory,
    pub protections: &'a BTreeSet<Protection>,
    pub scope: RetentionScope,
}

/// Contract signature `plan(&RetentionInput) -> Plan`.
pub trait RetentionPlanner {
    fn plan(&self, input: &RetentionInput<'_>) -> Plan;
}

/// The pure planner from the v1 contract. The caller has already resolved every protection; the
/// planner applies the scope to the inventory and compares identities. An image outside the scope is
/// neither removed nor kept: it is reported like an image without provenance.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManagedRetentionPlanner;

impl RetentionPlanner for ManagedRetentionPlanner {
    fn plan(&self, input: &RetentionInput<'_>) -> Plan {
        let by_id: BTreeMap<&str, &ImageInfo> = input
            .images
            .iter()
            .map(|image| (image.id.as_str(), image))
            .collect();
        let mut used: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for container in input.containers {
            if !container.image_id.is_empty() {
                used.entry(container.image_id.as_str())
                    .or_default()
                    .push(container.name.clone());
            }
        }
        let mut protected_ids: BTreeMap<&str, ProtectionReason> = BTreeMap::new();
        let mut protected_digests: BTreeMap<&str, ProtectionReason> = BTreeMap::new();
        for protection in input.protections {
            match &protection.identity {
                ProtectionIdentity::ImageId(id) => {
                    protected_ids
                        .entry(id.as_str())
                        .or_insert(protection.reason);
                }
                ProtectionIdentity::Digest(digest) => {
                    protected_digests
                        .entry(digest.as_str())
                        .or_insert(protection.reason);
                }
            }
        }

        let mut plan = Plan::default();
        let mut known: BTreeSet<&str> = BTreeSet::new();
        for record in input
            .inventory
            .images
            .iter()
            .filter(|record| in_scope(&input.scope, record))
        {
            known.insert(record.image_id.as_str());
            let Some(image) = by_id.get(record.image_id.as_str()) else {
                continue; // already gone: a complete observation proves absence later
            };
            let reason = if let Some(names) = used.get(record.image_id.as_str()) {
                Some(KeepReason::InUse(names.clone()))
            } else if let Some(reason) = protected_ids.get(record.image_id.as_str()) {
                Some(KeepReason::Protected(*reason))
            } else {
                let mut reason = record
                    .digests
                    .iter()
                    .find_map(|digest| protected_digests.get(digest.as_str()).copied());
                if reason.is_none() {
                    reason = image_digests(image)
                        .iter()
                        .find_map(|digest| protected_digests.get(digest).copied());
                }
                reason.map(KeepReason::Protected)
            };
            match reason {
                Some(reason) => plan.keep.push(((*image).clone(), reason)),
                None => plan.remove.push((*image).clone()),
            }
        }
        for image in input.images {
            if !known.contains(image.id.as_str()) {
                plan.unattributed.push(image.clone());
            }
        }
        plan.keep.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        plan.remove.sort_by(|a, b| a.id.cmp(&b.id));
        plan.unattributed.sort_by(|a, b| a.id.cmp(&b.id));
        plan
    }
}

/// Whether `record` belongs to the retention `scope`: every record for [`RetentionScope::AllManaged`],
/// only the records associated with that owner and repository otherwise.
fn in_scope(scope: &RetentionScope, record: &ManagedImage) -> bool {
    match scope {
        RetentionScope::AllManaged => true,
        RetentionScope::OwnerRepository { owner, repository } => record
            .associations
            .iter()
            .any(|a| &a.owner == owner && &a.repository == repository),
    }
}

/// Durable provenance store (`managed-images.toml`). `record` is an upsert that unions digests and
/// associations and rejects conflicting identities; it never replaces another owner's association.
pub trait InventoryStore {
    fn load(
        &self,
        guard: &ImageGuard<'_>,
    ) -> impl Future<Output = Result<Inventory, EngineError>> + Send;

    fn record(
        &self,
        guard: &ImageGuard<'_>,
        image: ManagedImage,
    ) -> impl Future<Output = Result<(), EngineError>> + Send;

    /// Records a batch of images with one read and one write. Returns the images that were durably
    /// recorded, in input order; an image whose digest already names another image id is skipped,
    /// never merged over another owner's association.
    fn record_many(
        &self,
        guard: &ImageGuard<'_>,
        images: Vec<ManagedImage>,
    ) -> impl Future<Output = Result<Vec<ManagedImage>, EngineError>> + Send;
}

/// Durable reservation store (`image-reservations.toml`). A reservation is published before
/// `image_load` (phase `loading`) and advanced to `loaded` before any `image_tag`.
pub trait ReservationStore {
    fn reserve(
        &self,
        guard: &ImageGuard<'_>,
        operation: OperationId,
        reservation: &Reservation,
    ) -> impl Future<Output = Result<(), EngineError>> + Send;

    fn advance(
        &self,
        guard: &ImageGuard<'_>,
        operation: OperationId,
        phase: ReservationPhase,
        protections: &BTreeSet<Protection>,
    ) -> impl Future<Output = Result<(), EngineError>> + Send;

    fn finish(
        &self,
        guard: &ImageGuard<'_>,
        operation: OperationId,
    ) -> impl Future<Output = Result<(), EngineError>> + Send;
}

/// The scoped, owned retention input the engine actually feeds the pure planner.
struct PreparedRetention {
    images: Vec<ImageInfo>,
    containers: Vec<ContainerInfo>,
    inventory: Inventory,
    protections: BTreeSet<Protection>,
    scope: RetentionScope,
    diagnostics: Vec<String>,
}

impl PreparedRetention {
    fn input(&self) -> RetentionInput<'_> {
        RetentionInput {
            images: &self.images,
            containers: &self.containers,
            inventory: &self.inventory,
            protections: &self.protections,
            scope: self.scope.clone(),
        }
    }
}

/// The host's boot identity. A reservation is reclaimable only when this differs from the owner's
/// boot; wall-clock time is never evidence.
fn current_boot_id() -> String {
    known_boot_id().unwrap_or_else(|| UNKNOWN_BOOT.to_owned())
}

/// The `boot_id` stored for a reservation written while the host reported no boot identity. It may
/// belong to the current boot, so such a reservation is never treated as a previous boot's.
const UNKNOWN_BOOT: &str = "unknown-boot";

/// Whether a reservation written by `owner_boot` provably belongs to a boot other than `boot`.
fn is_previous_boot(owner_boot: &str, boot: Option<&str>) -> bool {
    owner_boot != UNKNOWN_BOOT && boot.is_some_and(|boot| owner_boot != boot)
}

/// The boot identity when the host reports one. Reclamation needs a *proof* that the writer's boot
/// is gone, so it uses this and does nothing when it is `None` ([`current_boot_id`]'s placeholder
/// would make every reservation look like another boot's, or the same one).
fn known_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Repository of a reference in the form the inventory stores: lower-case, no tag or digest.
pub(crate) fn inventory_repository(reference: &str) -> Result<Repository, EngineError> {
    Repository::new(image_repo(reference).to_ascii_lowercase())
        .map_err(|e| EngineError::ImageBookkeeping(e.to_string()))
}

/// One operation id, unique within the process even within the same second.
fn next_operation_id(component: &str) -> Result<OperationId, EngineError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    OperationId::new(format!("{component}:{}:{nanos}:{n}", std::process::id()))
        .map_err(|e| EngineError::ImageBookkeeping(e.to_string()))
}

/// Every manifest digest an observed image reports: repository digests, the standalone `Digest` and
/// the preferred one. Used to match digest-addressed protections.
fn image_digests(image: &ImageInfo) -> BTreeSet<&str> {
    image
        .repo_digests
        .iter()
        .filter_map(|name| name.split_once('@').map(|(_, digest)| digest))
        .chain(image.digest.as_ref().map(Digest::as_str))
        .chain(image.standalone_digest.as_ref().map(Digest::as_str))
        .collect()
}

/// Removes the planned images, best effort: an image that is already gone counts as removed, any
/// other error is collected and the remaining images are still processed. Never forces.
///
/// The guard cannot be constructed without the engine lock, so a stale plan cannot be executed
/// after the lock was released.
pub async fn execute<P: PodmanClient>(
    podman: &P,
    _guard: &ImageGuard<'_>,
    plan: Plan,
) -> PruneReport {
    let mut report = PruneReport::default();
    for image in plan.remove {
        match podman.image_remove(&image.id).await {
            Ok(()) | Err(PodmanError::NotFound(_)) => {
                report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(image.size_bytes);
                report.removed.push(image);
            }
            Err(e) => report.failed.push((image.id, e.to_string())),
        }
    }
    report
}

// ── File-backed stores ──────────────────────────────────────────────────────────

impl<P: PodmanClient> Reconciler<P> {
    /// The daemon's shared state directory (inventory, reservations, journal, capabilities).
    pub(crate) fn bookkeeping_dir(&self) -> PathBuf {
        self.paths
            .state
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_owned()
    }

    fn inventory_path(&self) -> PathBuf {
        self.bookkeeping_dir().join(INVENTORY_FILE_NAME)
    }

    fn reservations_path(&self) -> PathBuf {
        self.bookkeeping_dir().join(RESERVATIONS_FILE_NAME)
    }

    /// Reads `managed-images.toml`. A missing file means no provenance is known yet; an unreadable or
    /// invalid one is an error, never an empty inventory (ADR 0067).
    fn read_inventory(&self) -> Result<Inventory, EngineError> {
        let path = self.inventory_path();
        match std::fs::read_to_string(&path) {
            Ok(text) => Inventory::parse(&text)
                .map_err(|e| EngineError::ImageBookkeeping(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Inventory::default()),
            Err(e) => Err(EngineError::ImageBookkeeping(format!(
                "{}: {e}",
                path.display()
            ))),
        }
    }

    fn write_inventory(&self, inventory: &Inventory) -> Result<(), EngineError> {
        let path = self.inventory_path();
        #[cfg(test)]
        if write_count::bump() {
            return Err(EngineError::ImageBookkeeping(format!(
                "{}: injected write failure",
                path.display()
            )));
        }
        let text = inventory
            .to_toml()
            .map_err(|e| EngineError::ImageBookkeeping(format!("{}: {e}", path.display())))?;
        fsutil::write_atomic(&path, text.as_bytes(), 0o600)
            .map_err(|e| EngineError::ImageBookkeeping(format!("{}: {e}", path.display())))
    }

    /// Reads `image-reservations.toml`. A missing file is an empty set; an invalid one is an error.
    fn read_reservations(&self) -> Result<Reservations, EngineError> {
        let path = self.reservations_path();
        match std::fs::read_to_string(&path) {
            Ok(text) => Reservations::parse(&text)
                .map_err(|e| EngineError::ImageBookkeeping(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Reservations::default()),
            Err(e) => Err(EngineError::ImageBookkeeping(format!(
                "{}: {e}",
                path.display()
            ))),
        }
    }

    fn write_reservations(&self, reservations: &Reservations) -> Result<(), EngineError> {
        let path = self.reservations_path();
        #[cfg(test)]
        if write_count::bump_reservation() {
            return Err(EngineError::ImageBookkeeping(format!(
                "{}: injected write failure",
                path.display()
            )));
        }
        let text = reservations
            .to_toml()
            .map_err(|e| EngineError::ImageBookkeeping(format!("{}: {e}", path.display())))?;
        fsutil::write_atomic(&path, text.as_bytes(), 0o600)
            .map_err(|e| EngineError::ImageBookkeeping(format!("{}: {e}", path.display())))
    }

    /// The durable reservation of `operation`, if any.
    #[cfg(test)]
    pub(crate) fn reservation(
        &self,
        operation: &OperationId,
    ) -> Result<Option<Reservation>, EngineError> {
        Ok(self
            .read_reservations()?
            .get(operation)
            .map(|entry| entry.reservation.clone()))
    }

    /// Begins an acquisition: a durable reservation in phase `loading`, published **before** any
    /// pull/load/tag mutation. While it is `loading` it protects whatever is being pulled by making
    /// retention skip adoption ([`loading_operations`]); [`Self::advance_acquisition`] replaces that
    /// with the image's identities. The caller must hold the image guard.
    ///
    /// `None` when the reservation file is full: the acquisition goes on without a reservation
    /// (a full file must not fail a deploy), and retention reports `blocked` until capacity is back
    /// ([`reservations_full`]), so nothing is removed while an unreserved image could be at risk.
    pub(crate) async fn begin_acquisition(
        &self,
        guard: &ImageGuard<'_>,
    ) -> Result<Option<OperationId>, EngineError> {
        if reservations_full(&self.read_reservations()?) {
            tracing::warn!(
                capacity = MAX_RESERVATIONS,
                "the image reservation file is full: continuing without a reservation, image cleanup \
                 is blocked until one is abandoned (`weglarka images reservations abandon`)"
            );
            return Ok(None);
        }
        let operation = next_operation_id("acquisition")?;
        let reservation = Reservation {
            owner: ReservationOwner::new(
                "engine",
                std::process::id(),
                current_boot_id(),
                now_secs(),
            )
            .map_err(|e| EngineError::ImageBookkeeping(e.to_string()))?,
            phase: ReservationPhase::Loading,
            protections: BTreeSet::new(),
            journal_ref: None,
            created_at: now_secs(),
        };
        // No image identity is known yet, so the reservation carries no protections; its `loading`
        // phase makes retention skip adoption instead (see [`loading_operations`]). The owner and repository are
        // recorded on the inventory entry by [`Self::record_acquisition`].
        ReservationStore::reserve(self, guard, operation.clone(), &reservation).await?;
        Ok(Some(operation))
    }

    /// Advances a reservation to `loaded` with the identities that are now known, before any tag.
    pub(crate) async fn advance_acquisition(
        &self,
        guard: &ImageGuard<'_>,
        operation: &OperationId,
        image_id: Option<&str>,
        digest: &Digest,
    ) -> Result<(), EngineError> {
        let mut protections = BTreeSet::new();
        if let Some(id) = image_id.and_then(|id| ImageId::new(id).ok()) {
            protections.insert(Protection {
                identity: ProtectionIdentity::ImageId(id),
                reason: ProtectionReason::AcquisitionInProgress,
                operation_id: Some(operation.clone()),
            });
        }
        if let Ok(digest) = StrictDigest::new(digest.as_str()) {
            protections.insert(Protection {
                identity: ProtectionIdentity::Digest(digest),
                reason: ProtectionReason::AcquisitionInProgress,
                operation_id: Some(operation.clone()),
            });
        }
        ReservationStore::advance(
            self,
            guard,
            operation.clone(),
            ReservationPhase::Loaded,
            &protections,
        )
        .await
    }

    /// Releases an acquisition reservation after durable commit. A failure only warns: a leaked
    /// reservation protects an image and never authorizes deletion.
    pub(crate) async fn finish_acquisition(&self, guard: &ImageGuard<'_>, operation: OperationId) {
        if let Err(e) = ReservationStore::finish(self, guard, operation.clone()).await {
            tracing::warn!(operation = %operation, error = %e, "cannot release the image reservation");
        }
    }

    /// [`Self::finish_acquisition`] for an acquisition that may have run without a reservation
    /// (`None`: the file was full). Used on the failure paths, where no provenance was committed.
    ///
    /// It only drops the reservation; it does not touch the image. When the failure came after the
    /// pull or load (a failed [`Self::advance_acquisition`]), the image is already pulled and tagged
    /// and, once released, has neither a reservation nor a record, so a later real retention pass
    /// can adopt it by repository name and remove it.
    pub(crate) async fn release_acquisition(
        &self,
        guard: &ImageGuard<'_>,
        operation: Option<OperationId>,
    ) {
        if let Some(operation) = operation {
            self.finish_acquisition(guard, operation).await;
        }
    }

    /// Records the provenance of an acquired image. An upsert: unions associations and digests.
    pub(crate) async fn record_acquisition(
        &self,
        guard: &ImageGuard<'_>,
        owner: Owner,
        repository: Repository,
        image_id: Option<&str>,
        digest: &Digest,
    ) -> Result<(), EngineError> {
        let Some(image_id) = image_id.and_then(|id| ImageId::new(id).ok()) else {
            return Err(EngineError::ImageBookkeeping(
                "the acquired image reports no usable local image id".into(),
            ));
        };
        let mut digests = BTreeSet::new();
        if let Ok(digest) = StrictDigest::new(digest.as_str()) {
            digests.insert(digest);
        }
        let image = ManagedImage {
            image_id,
            digests,
            associations: [Association { owner, repository }].into(),
        };
        InventoryStore::record(self, guard, image).await
    }

    /// Explicit operator abandonment (`weglarka images reservations abandon <id>`). Frees capacity
    /// without touching live provenance; the caller has confirmed.
    pub async fn abandon_reservation(&self, operation: &OperationId) -> Result<bool, EngineError> {
        let _guard = self.acquire().await;
        let mut reservations = self.read_reservations()?;
        let before = reservations.operations.len();
        reservations
            .operations
            .retain(|entry| &entry.operation_id != operation);
        if reservations.operations.len() == before {
            return Ok(false);
        }
        self.write_reservations(&reservations)?;
        tracing::info!(operation = %operation, "abandoned an image reservation");
        Ok(true)
    }

    /// Every durable reservation, oldest first, for `weglarka images reservations list`. Read-only
    /// and lock-free: the file is replaced atomically, so a deploy in progress never blocks it.
    ///
    /// An unreadable or corrupt platform journal does not fail the listing (it is how an operator
    /// finds the ids to `abandon` when something is broken): every reservation is returned with
    /// `referenced: None` and a diagnostic names the file and the error. Reclamation, in contrast,
    /// fails closed on the same condition ([`Self::reclaim_stale_reservations`]).
    pub fn list_reservations(&self) -> Result<ReservationList, EngineError> {
        self.list_reservations_in_boot(known_boot_id().as_deref())
    }

    pub(crate) fn list_reservations_in_boot(
        &self,
        boot: Option<&str>,
    ) -> Result<ReservationList, EngineError> {
        let reservations = self.read_reservations()?;
        let mut diagnostics = Vec::new();
        let journal = match self.read_platform_journal() {
            Ok(journal) => Some(journal),
            Err(error) => {
                diagnostics.push(format!(
                    "cannot tell which reservations a platform transaction references: {error}"
                ));
                None
            }
        };
        let transaction = journal.as_ref().and_then(|journal| {
            journal
                .transaction
                .as_ref()
                .filter(|transaction| !transaction.is_terminal())
        });
        let mut list: Vec<ReservationInfo> = reservations
            .operations
            .into_iter()
            .map(|entry| {
                let ReservationEntry {
                    operation_id,
                    reservation,
                } = entry;
                let referenced = journal
                    .is_some()
                    .then(|| references_reservation(transaction, &operation_id, &reservation));
                let Reservation {
                    owner,
                    phase,
                    protections,
                    journal_ref: _,
                    created_at: _,
                } = reservation;
                let ReservationOwner {
                    component,
                    pid,
                    boot_id,
                    started_at,
                } = owner;
                ReservationInfo {
                    operation_id: operation_id.to_string(),
                    phase,
                    component,
                    pid,
                    started_at,
                    previous_boot: is_previous_boot(&boot_id, boot),
                    referenced,
                    protections: protections.len(),
                }
            })
            .collect();
        list.sort_by(|a, b| (a.started_at, &a.operation_id).cmp(&(b.started_at, &b.operation_id)));
        Ok(ReservationList {
            reservations: list,
            diagnostics,
        })
    }

    /// Reclaims reservations whose owner boot is gone and that no nonterminal transaction
    /// references ([`references_reservation`]). Never called from a deploy path (boot change only),
    /// and never based on elapsed time. Does nothing when the host reports no boot identity: without
    /// it nothing proves a writer gone. Returns the reclaimed operation ids.
    pub async fn reclaim_stale_reservations(&self) -> Result<Vec<OperationId>, EngineError> {
        self.reclaim_stale_reservations_in_boot(known_boot_id().as_deref())
            .await
    }

    pub(crate) async fn reclaim_stale_reservations_in_boot(
        &self,
        boot: Option<&str>,
    ) -> Result<Vec<OperationId>, EngineError> {
        let Some(boot) = boot else {
            tracing::warn!(
                "the current boot identity is unknown: image reservations are not reclaimed"
            );
            return Ok(Vec::new());
        };
        // Lock first: a transaction that starts after an earlier read of the journal could reference
        // a reservation this pass is about to reclaim.
        let _guard = self.acquire().await;
        let journal = self.read_platform_journal()?;
        let transaction = journal
            .transaction
            .as_ref()
            .filter(|transaction| !transaction.is_terminal());
        let mut reservations = self.read_reservations()?;
        let mut reclaimed = Vec::new();
        reservations.operations.retain(|entry| {
            let keep = !is_previous_boot(&entry.reservation.owner.boot_id, Some(boot))
                || references_reservation(transaction, &entry.operation_id, &entry.reservation);
            if !keep {
                reclaimed.push(entry.operation_id.clone());
            }
            keep
        });
        if reclaimed.is_empty() {
            return Ok(reclaimed);
        }
        self.write_reservations(&reservations)?;
        for operation in &reclaimed {
            tracing::info!(operation = %operation, "reclaimed an image reservation of a previous boot");
        }
        Ok(reclaimed)
    }

    /// Reads the platform journal when present; a corrupt journal is an error (fail closed).
    fn read_platform_journal(&self) -> Result<PlatformUpdate, EngineError> {
        let path = self.bookkeeping_dir().join(JOURNAL_FILE_NAME);
        match std::fs::read_to_string(&path) {
            Ok(text) => PlatformUpdate::parse(&text)
                .map_err(|e| EngineError::ImageBookkeeping(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PlatformUpdate::default()),
            Err(e) => Err(EngineError::ImageBookkeeping(format!(
                "{}: {e}",
                path.display()
            ))),
        }
    }

    /// `Ok(())` only when this host may delete platform images. Absence, an older protocol or a
    /// missing feature means "disabled" — lock-file presence is never a signal.
    fn platform_prune_gate(&self) -> Result<(), CapabilityError> {
        let path = self.bookkeeping_dir().join(CAPABILITIES_FILE_NAME);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let record = CapabilityRecord::parse(&text)?;
                platform_prune_allowed(Some(&record))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => platform_prune_allowed(None),
            Err(e) => Err(CapabilityError::Invalid(format!("{}: {e}", path.display()))),
        }
    }
}

impl<P: PodmanClient> InventoryStore for Reconciler<P> {
    async fn load(&self, _guard: &ImageGuard<'_>) -> Result<Inventory, EngineError> {
        self.read_inventory()
    }

    async fn record(
        &self,
        _guard: &ImageGuard<'_>,
        image: ManagedImage,
    ) -> Result<(), EngineError> {
        let mut inventory = self.read_inventory()?;
        if let Some(error) = digest_conflict(&inventory, &image) {
            return Err(error);
        }
        upsert(&mut inventory, &image);
        self.write_inventory(&inventory)
    }

    async fn record_many(
        &self,
        _guard: &ImageGuard<'_>,
        images: Vec<ManagedImage>,
    ) -> Result<Vec<ManagedImage>, EngineError> {
        let mut inventory = self.read_inventory()?;
        let mut recorded = Vec::with_capacity(images.len());
        for image in images {
            if digest_conflict(&inventory, &image).is_some() {
                continue;
            }
            upsert(&mut inventory, &image);
            recorded.push(image);
        }
        if recorded.is_empty() {
            return Ok(recorded);
        }
        self.write_inventory(&inventory)?;
        Ok(recorded)
    }
}

impl<P: PodmanClient> ReservationStore for Reconciler<P> {
    async fn reserve(
        &self,
        _guard: &ImageGuard<'_>,
        operation: OperationId,
        reservation: &Reservation,
    ) -> Result<(), EngineError> {
        let mut reservations = self.read_reservations()?;
        if reservations.get(&operation).is_some() {
            return Err(EngineError::ImageBookkeeping(format!(
                "reservation {operation} already exists"
            )));
        }
        if reservations_full(&reservations) {
            return Err(EngineError::ImageBookkeeping(format!(
                "image reservations are full ({} operations); abandon one with \
                 `weglarka images reservations abandon <operation-id>`",
                MAX_RESERVATIONS
            )));
        }
        reservations.operations.push(ReservationEntry {
            operation_id: operation,
            reservation: reservation.clone(),
        });
        self.write_reservations(&reservations)
    }

    async fn advance(
        &self,
        _guard: &ImageGuard<'_>,
        operation: OperationId,
        phase: ReservationPhase,
        protections: &BTreeSet<Protection>,
    ) -> Result<(), EngineError> {
        let mut reservations = self.read_reservations()?;
        let entry = reservations
            .operations
            .iter_mut()
            .find(|entry| entry.operation_id == operation)
            .ok_or_else(|| {
                EngineError::ImageBookkeeping(format!("unknown reservation {operation}"))
            })?;
        entry.reservation.phase = phase;
        entry
            .reservation
            .protections
            .extend(protections.iter().cloned());
        self.write_reservations(&reservations)
    }

    async fn finish(
        &self,
        _guard: &ImageGuard<'_>,
        operation: OperationId,
    ) -> Result<(), EngineError> {
        let mut reservations = self.read_reservations()?;
        reservations
            .operations
            .retain(|entry| entry.operation_id != operation);
        self.write_reservations(&reservations)
    }
}

// ── Retention input ────────────────────────────────────────────────────────────

impl<P: PodmanClient> Reconciler<P> {
    /// Builds the contract input for `scope`: observations, scoped inventory, every protection.
    ///
    /// `adopt` is `Some(guard)` only for a real (non-dry-run) prune: it may seed provenance from a
    /// current repository name for a legacy install, and persists those records. Diagnostics never
    /// adopt.
    async fn prepare_retention(
        &self,
        scope: RetentionScope,
        adopt: Option<&ImageGuard<'_>>,
    ) -> Result<PreparedRetention, EngineError> {
        let images = self.podman.image_list().await?;
        let containers = self
            .podman
            .container_list(&ContainerFilter::default())
            .await?;
        let apps = state::load_apps(&self.paths.apps)?;
        let st = state::load_state(&self.paths.state)?;
        let inventory = self.read_inventory()?;
        let reservations = self.read_reservations()?;
        if reservations_full(&reservations) {
            // An acquisition may have run without a reservation while the file was full, so an image
            // could be unprotected: fail closed instead of narrowing the pass.
            return Err(EngineError::ImageBookkeeping(format!(
                "image reservations are full ({MAX_RESERVATIONS} operations); abandon one with \
                 `weglarka images reservations abandon <operation-id> --yes`"
            )));
        }
        let loading = loading_operations(&reservations);
        let journal = self.read_platform_journal()?;
        let self_update =
            weglarka_model::self_update::load(&self.bookkeeping_dir()).map_err(|e| {
                EngineError::ImageBookkeeping(format!("cannot read self-update.toml: {e}"))
            })?;
        let capability = self.platform_prune_gate();

        let mut protections =
            build_protections(&images, &containers, &apps, &st, &self_update, &journal);
        // Every durable reservation protects its identities until it is finished or abandoned,
        // whatever retention scope this pass uses.
        for entry in &reservations.operations {
            protections.extend(entry.reservation.protections.iter().cloned());
        }

        let mut diagnostics = Vec::new();
        if let Err(error) = &capability
            && has_platform_owner(&inventory)
        {
            diagnostics.push(error.to_string());
        }

        let mut scoped = Inventory {
            format_version: inventory.format_version,
            images: inventory.images.clone(),
        };
        // A pull that is still `loading` may have left a partly pulled image that nothing records
        // yet; the only way such an image becomes removable is adoption, so adoption is skipped.
        let requests = if loading.is_empty() {
            adopt_requests(&images, &apps, &inventory, &scope)
        } else {
            diagnostics.push(loading_diagnostic(&loading));
            Vec::new()
        };
        if let Some(guard) = adopt {
            // A real prune persists the adoptions **before** it can plan a removal from them. If the
            // batch cannot be written (full disk, read-only file) provenance is incomplete and the
            // whole pass is blocked (`ImageBookkeeping`), not narrowed: nothing is removed. One
            // read and one write for the whole batch; an image whose digest already names another
            // image id is skipped (it stays unattributed). A dry run only advertises.
            let recorded = InventoryStore::record_many(self, guard, requests.clone())
                .await
                .map_err(|e| {
                    EngineError::ImageBookkeeping(format!("cannot record image provenance: {e}"))
                })?;
            let recorded: BTreeSet<&str> = recorded
                .iter()
                .map(|image| image.image_id.as_str())
                .collect();
            for request in requests {
                if recorded.contains(request.image_id.as_str()) {
                    upsert(&mut scoped, &request);
                } else {
                    diagnostics.push(format!(
                        "cannot record image provenance for {}: a digest is already recorded \
                         for another image",
                        request.image_id
                    ));
                }
            }
        } else {
            for request in requests {
                upsert(&mut scoped, &request);
            }
        }
        // Platform-image deletion stays disabled without the capability record, whatever the scope.
        if capability.is_err() {
            scoped.images.retain(|record| {
                !record
                    .associations
                    .iter()
                    .any(|a| matches!(a.owner, Owner::PlatformDaemon))
            });
        }
        let in_scope_images = scoped
            .images
            .iter()
            .filter(|record| in_scope(&scope, record))
            .count();
        if in_scope_images > weglarka_model::image_inventory::MAX_IMAGES {
            return Err(EngineError::ImageBookkeeping(
                "the image inventory exceeds its entry limit".into(),
            ));
        }
        Ok(PreparedRetention {
            images,
            containers,
            inventory: scoped,
            protections,
            scope,
            diagnostics,
        })
    }

    /// Read-only plan for `doctor`/dry-run: identical to a real prune, mutates nothing. The
    /// diagnostics explain any fail-closed condition (corrupt bookkeeping, disabled platform-image
    /// deletion).
    pub async fn retention_preview(
        &self,
        scope: RetentionScope,
    ) -> Result<(Plan, Vec<String>), EngineError> {
        let prepared = self.prepare_retention(scope, None).await?;
        Ok((
            ManagedRetentionPlanner.plan(&prepared.input()),
            prepared.diagnostics,
        ))
    }

    /// Explicit prune (`POST /v1/images/prune`, `weglarka images prune`): every managed image.
    /// `dry_run` plans without removing anything.
    pub async fn prune_images(&self, dry_run: bool) -> Result<PruneReport, EngineError> {
        let guard = self.acquire().await;
        self.prune_images_locked(&guard, dry_run, RetentionScope::AllManaged)
            .await
    }

    /// The body of [`Self::prune_images`], under the engine lock.
    ///
    /// Fails closed on provenance: any error reading or writing the bookkeeping (inventory,
    /// reservations, journal, adoption records) ends the pass with [`PruneReport::blocked`] and no
    /// removal. A dry run adopts nothing and writes no file.
    pub(crate) async fn prune_images_locked(
        &self,
        held: &EngineGuard<'_>,
        dry_run: bool,
        scope: RetentionScope,
    ) -> Result<PruneReport, EngineError> {
        let guard = ImageGuard::new(held);
        let adopt = (!dry_run).then_some(&guard);
        let prepared = match self.prepare_retention(scope, adopt).await {
            Ok(prepared) => prepared,
            Err(EngineError::ImageBookkeeping(reason)) => {
                return Ok(PruneReport::blocked(dry_run, reason));
            }
            Err(e) => return Err(e),
        };
        let plan = ManagedRetentionPlanner.plan(&prepared.input());
        if dry_run {
            return Ok(PruneReport {
                reclaimed_bytes: plan.reclaimable_bytes(),
                removed: plan.remove,
                dry_run: true,
                diagnostics: prepared.diagnostics,
                ..PruneReport::default()
            });
        }
        // Prove the inventory can be written before the first removal: forgetting the removed
        // images is the last step, and a pass that could not record its outcome must not start.
        if !plan.is_empty()
            && let Err(e) = self.check_inventory_writable()
        {
            return Ok(PruneReport::blocked(false, e.to_string()));
        }
        let mut report = execute(&self.podman, &guard, plan).await;
        report.diagnostics = prepared.diagnostics;
        // A failed deletion keeps its record: only successfully removed images are forgotten. A
        // record that outlives its image is skipped by the planner while the image is absent, so a
        // failed write here is reported (`blocked`, with the true `removed` list) and undoes nothing.
        if let Err(e) = self.forget_removed(&guard, &report) {
            report.blocked = true;
            report.diagnostics.push(e.to_string());
        }
        Ok(report)
    }

    /// Rewrites the inventory unchanged: succeeds only when a later [`Self::forget_removed`] can.
    fn check_inventory_writable(&self) -> Result<(), EngineError> {
        let inventory = self.read_inventory()?;
        self.write_inventory(&inventory)
    }

    /// Removes the inventory records of images that were actually deleted.
    fn forget_removed(
        &self,
        _guard: &ImageGuard<'_>,
        report: &PruneReport,
    ) -> Result<(), EngineError> {
        if report.removed.is_empty() {
            return Ok(());
        }
        let ids: BTreeSet<&str> = report
            .removed
            .iter()
            .map(|image| image.id.as_str())
            .collect();
        let mut inventory = self.read_inventory()?;
        let before = inventory.images.len();
        inventory
            .images
            .retain(|record| !ids.contains(record.image_id.as_str()));
        if inventory.images.len() == before {
            return Ok(());
        }
        self.write_inventory(&inventory)
    }

    /// Best effort housekeeping after a completed operation of `owner`/`repo`: removes images of
    /// that owner/repository older than the current and previous one. Never fails the operation.
    /// The caller holds the engine/image guard (a fresh one after a deploy released its acquisition
    /// guard — this function never acquires it itself).
    pub(crate) async fn retain_images_locked(
        &self,
        held: &EngineGuard<'_>,
        owner: &Owner,
        repo: &str,
    ) {
        let Ok(repository) = inventory_repository(repo) else {
            tracing::warn!(repo, "image retention: invalid repository");
            return;
        };
        let scope = RetentionScope::OwnerRepository {
            owner: owner.clone(),
            repository,
        };
        match self.prune_images_locked(held, false, scope).await {
            Ok(report) if report.blocked => {
                for diagnostic in &report.diagnostics {
                    tracing::warn!(repo, %diagnostic, "image retention: blocked");
                }
            }
            Ok(report) if report.removed.is_empty() => {
                for diagnostic in report.diagnostics {
                    tracing::warn!(repo, %diagnostic, "image retention: disabled");
                }
                tracing::debug!(repo, "image retention: nothing to remove");
            }
            Ok(report) => {
                // A pass that removed images can still have skipped part of its work (adoption
                // during a `loading` reservation, platform deletion without capabilities).
                for diagnostic in &report.diagnostics {
                    tracing::warn!(repo, %diagnostic, "image retention: partly skipped");
                }
                tracing::info!(
                    repo,
                    removed = report.removed.len(),
                    reclaimed_bytes = report.reclaimed_bytes,
                    failed = report.failed.len(),
                    "image retention: removed older images"
                );
            }
            Err(e) => tracing::warn!(repo, error = %e, "image retention skipped"),
        }
    }

    /// The one place that decides whether a deploy outcome is followed by retention
    /// ([`DeployOutcome::needs_retention`]). `held` is the engine/image guard of a caller that still
    /// holds it (retention reuses it, never reacquires); `None` is for a caller that already dropped
    /// its acquisition guard, and retention takes a fresh one.
    pub(crate) async fn retain_for_outcome(
        &self,
        held: Option<&EngineGuard<'_>>,
        instance: &InstanceName,
        outcome: &DeployOutcome,
    ) {
        if !outcome.needs_retention() {
            return;
        }
        let Ok(spec) = self.load_spec(instance) else {
            return;
        };
        let repo = image_repo(&spec.image);
        match held {
            Some(held) => {
                let owner = Owner::App {
                    instance: instance.clone(),
                };
                self.retain_images_locked(held, &owner, repo).await;
            }
            None => self.retain_after_deploy(instance, repo).await,
        }
    }

    /// Retention with its own fresh guard, for callers that already dropped an acquisition guard.
    pub async fn retain_after_deploy(&self, instance: &InstanceName, repo: &str) {
        let owner = Owner::App {
            instance: instance.clone(),
        };
        let guard = self.acquire().await;
        self.retain_images_locked(&guard, &owner, repo).await;
    }
}

/// Whether the nonterminal platform `transaction` (if any) references a reservation: it lists the
/// operation among its `reservations`, or the reservation's `journal_ref` names it. The one
/// predicate behind both reclamation and `reservations list`, so the list never promises a
/// protection reclamation does not honour (or the other way round). Once the transaction is
/// terminal (or gone) the reservation is an ordinary one again.
fn references_reservation(
    transaction: Option<&TransactionJournal>,
    operation: &OperationId,
    reservation: &Reservation,
) -> bool {
    transaction.is_some_and(|transaction| {
        transaction.reservations.contains(operation)
            || reservation.journal_ref.as_ref() == Some(&transaction.transaction_id)
    })
}

/// Whether the reservation file has no room left: acquisitions then run unreserved
/// ([`Reconciler::begin_acquisition`]) and retention is blocked.
fn reservations_full(reservations: &Reservations) -> bool {
    reservation_count_is_full(reservations.operations.len())
}

fn reservation_count_is_full(count: usize) -> bool {
    count >= MAX_RESERVATIONS
}

/// Operation ids of the reservations still in phase `loading`.
///
/// Such a reservation has not learned its image id or digest, so it can name no protection (the file
/// has no field for the pull's target). Acquisitions and prunes serialize under the engine guard, so
/// any `loading` reservation a pass can see is orphaned (a cancelled upload, an early return); the
/// image it was pulling is at risk only if nothing records it, because an unrecorded image is
/// unattributed and becomes removable solely through repository-name **adoption**. While one exists,
/// the pass therefore skips adoption (fail closed for exactly those images) and the rest of
/// retention runs normally. The operator ends it with `weglarka images reservations abandon`; until
/// that is automated, abandonment is manual.
fn loading_operations(reservations: &Reservations) -> Vec<String> {
    reservations
        .operations
        .iter()
        .filter(|entry| entry.reservation.phase == ReservationPhase::Loading)
        .map(|entry| entry.operation_id.to_string())
        .collect()
}

fn loading_diagnostic(loading: &[String]) -> String {
    format!(
        "image acquisition {} is still loading: images without a record are not adopted until it \
         is abandoned with `weglarka images reservations abandon <operation-id> --yes` (once its \
         owner is gone)",
        loading.join(", ")
    )
}

/// The conflict an upsert rejects: one manifest digest never names two local image ids.
fn digest_conflict(inventory: &Inventory, image: &ManagedImage) -> Option<EngineError> {
    for other in &inventory.images {
        if other.image_id == image.image_id {
            continue;
        }
        if other
            .digests
            .iter()
            .any(|digest| image.digests.contains(digest))
        {
            return Some(EngineError::ImageBookkeeping(format!(
                "digest {:?} is recorded for two image ids ({} and {})",
                image
                    .digests
                    .first()
                    .map(StrictDigest::as_str)
                    .unwrap_or(""),
                other.image_id,
                image.image_id
            )));
        }
    }
    None
}

/// Unions `image` into `inventory`: an upsert that unions digests and associations and never
/// replaces another owner's association.
fn upsert(inventory: &mut Inventory, image: &ManagedImage) {
    match inventory
        .images
        .iter_mut()
        .find(|entry| entry.image_id == image.image_id)
    {
        Some(entry) => {
            entry.digests.extend(image.digests.iter().cloned());
            entry
                .associations
                .extend(image.associations.iter().cloned());
        }
        None => inventory.images.push(image.clone()),
    }
}

fn has_platform_owner(inventory: &Inventory) -> bool {
    inventory.images.iter().any(|record| {
        record
            .associations
            .iter()
            .any(|a| matches!(a.owner, Owner::PlatformDaemon))
    })
}

/// Images a legacy install names today: a spec's `repo:tag` (or the repository digest of an image
/// whose tag moved) is adoption evidence, mirroring the repository policy of ADR 0020.
fn adopt_requests(
    images: &[ImageInfo],
    apps: &AppsFile,
    inventory: &Inventory,
    scope: &RetentionScope,
) -> Vec<ManagedImage> {
    let mut requests = Vec::new();
    for image in images {
        if inventory
            .images
            .iter()
            .any(|record| record.image_id.as_str() == image.id)
        {
            continue;
        }
        let Some(image_id) = ImageId::new(image.id.clone()).ok() else {
            continue;
        };
        let mut associations = BTreeSet::new();
        for (instance, spec) in &apps.apps {
            let (repo, tag) = normalize_image(&spec.image);
            let Ok(repository) = Repository::new(repo.clone()) else {
                continue;
            };
            let matches_scope = match scope {
                RetentionScope::AllManaged => true,
                RetentionScope::OwnerRepository {
                    owner,
                    repository: scoped_repository,
                } => {
                    *owner
                        == (Owner::App {
                            instance: instance.clone(),
                        })
                        && &repository == scoped_repository
                }
            };
            if !matches_scope {
                continue;
            }
            let tag_name = format!("{repo}:{tag}");
            let named = image
                .repo_tags
                .iter()
                .any(|name| normalize_image(name) == (repo.clone(), tag.clone()))
                || image
                    .repo_digests
                    .iter()
                    .any(|name| image_repo(name).eq_ignore_ascii_case(&repo))
                || image.repo_tags.iter().any(|name| name == &tag_name);
            if named {
                associations.insert(Association {
                    owner: Owner::App {
                        instance: instance.clone(),
                    },
                    repository: repository.clone(),
                });
            }
        }
        if associations.is_empty() {
            continue;
        }
        requests.push(ManagedImage {
            image_id,
            digests: image_digests(image)
                .into_iter()
                .filter_map(|digest| StrictDigest::new(digest).ok())
                .collect(),
            associations,
        });
    }
    requests
}

/// Every durable protection, regardless of the retention scope.
fn build_protections(
    images: &[ImageInfo],
    containers: &[ContainerInfo],
    apps: &AppsFile,
    st: &StateFile,
    self_update: &weglarka_model::self_update::SelfUpdateState,
    journal: &PlatformUpdate,
) -> BTreeSet<Protection> {
    let mut protections = BTreeSet::new();
    for container in containers {
        if !container.image_id.is_empty() {
            protect_id(
                &mut protections,
                &container.image_id,
                ProtectionReason::Container,
            );
        }
    }
    for state in st.apps.values() {
        if let Some(digest) = &state.current {
            protect_digest(&mut protections, digest, ProtectionReason::AppCurrent);
        }
        if let Some(digest) = &state.previous {
            protect_digest(&mut protections, digest, ProtectionReason::AppPrevious);
        }
    }
    // The tag an app spec names is the image the next deploy would use without pulling.
    for spec in apps.apps.values() {
        let (repo, tag) = normalize_image(&spec.image);
        if let Some(image) = images.iter().find(|image| {
            image
                .repo_tags
                .iter()
                .any(|name| normalize_image(name) == (repo.clone(), tag.clone()))
        }) {
            protect_id(&mut protections, &image.id, ProtectionReason::SpecTag);
        }
    }
    for digest in [self_update.current.as_ref(), self_update.previous.as_ref()]
        .into_iter()
        .flatten()
    {
        let reason = if self_update.previous.as_ref() == Some(digest) {
            ProtectionReason::PlatformPrevious
        } else {
            ProtectionReason::PlatformCurrent
        };
        protect_digest(&mut protections, digest, reason);
    }
    for digest in [self_update.pending.as_ref(), self_update.switch_to.as_ref()]
        .into_iter()
        .flatten()
    {
        protect_digest(&mut protections, digest, ProtectionReason::PendingSwitch);
    }
    for digest in [
        self_update.switch_from.as_ref(),
        self_update.fallback_to.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        protect_digest(&mut protections, digest, ProtectionReason::Fallback);
    }
    if let Some(transaction) = journal
        .transaction
        .as_ref()
        .filter(|transaction| !transaction.is_terminal())
    {
        protect_digest(
            &mut protections,
            transaction.old.daemon_digest.as_digest(),
            ProtectionReason::PlatformCurrent,
        );
        protect_digest(
            &mut protections,
            transaction.target.daemon_digest.as_digest(),
            ProtectionReason::PendingSwitch,
        );
    } else if let Some(transaction) = journal.transaction.as_ref().filter(|transaction| {
        transaction.stage == weglarka_model::platform_update::Stage::BlockedRecovery
    }) {
        // Every recovery artifact stays protected until explicit resolution.
        for digest in [
            transaction.old.daemon_digest.as_digest(),
            transaction.target.daemon_digest.as_digest(),
            transaction.old.tools_digest.as_digest(),
            transaction.target.tools_digest.as_digest(),
        ] {
            protect_digest(&mut protections, digest, ProtectionReason::Fallback);
        }
    }
    protections
}

fn protect_id(protections: &mut BTreeSet<Protection>, id: &str, reason: ProtectionReason) {
    if let Ok(id) = ImageId::new(id) {
        protections.insert(Protection {
            identity: ProtectionIdentity::ImageId(id),
            reason,
            operation_id: None,
        });
    }
}

fn protect_digest(
    protections: &mut BTreeSet<Protection>,
    digest: &Digest,
    reason: ProtectionReason,
) {
    if let Ok(digest) = StrictDigest::new(digest.as_str()) {
        protections.insert(Protection {
            identity: ProtectionIdentity::Digest(digest),
            reason,
            operation_id: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::reconcile::ReconcilerOptions;
    use crate::testing::FakePodman;
    use weglarka_model::app::InstanceName;
    use weglarka_model::image_inventory::{FORMAT_VERSION, ImageId};
    use weglarka_model::secrets::FileSecretStore;
    use weglarka_model::state::StatePaths;

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn instance(name: &str) -> InstanceName {
        InstanceName::new(name).unwrap()
    }

    fn repo(name: &str) -> Repository {
        Repository::new(name).unwrap()
    }

    fn image(id: &str, digest: char) -> ImageInfo {
        ImageInfo {
            id: full_id(id),
            digest: Some(digest_value(digest)),
            standalone_digest: Some(digest_value(digest)),
            repo_tags: Vec::new(),
            repo_digests: Vec::new(),
            size_bytes: 100,
            labels: BTreeMap::new(),
        }
    }

    fn digest_value(c: char) -> Digest {
        digest(c)
    }

    /// A full-length image id (64 hex characters) from a short test label: libpod always reports
    /// the full id and `ImageId` accepts nothing else.
    fn full_id(label: &str) -> String {
        format!("{label:0<64}")
    }

    fn record(id: &str, owner: Owner, repository: &str, c: char) -> ManagedImage {
        ManagedImage {
            image_id: ImageId::new(full_id(id)).unwrap(),
            digests: [StrictDigest::new(digest(c).as_str()).unwrap()].into(),
            associations: [Association {
                owner,
                repository: repo(repository),
            }]
            .into(),
        }
    }

    fn protection_digest(c: char, reason: ProtectionReason) -> Protection {
        Protection {
            identity: ProtectionIdentity::Digest(StrictDigest::new(digest(c).as_str()).unwrap()),
            reason,
            operation_id: None,
        }
    }

    #[test]
    fn planner_removes_unprotected_images_and_keeps_container_references() {
        let images = [image("1", 'a'), image("2", 'b'), image("3", 'c')];
        let containers = [ContainerInfo {
            id: "c1".into(),
            name: "old".into(),
            image: String::new(),
            image_id: full_id("2"),
            labels: BTreeMap::new(),
            state: weglarka_model::podman::ContainerState::Exited,
            exit_code: Some(0),
            health: None,
            restarts: 0,
            started_at: None,
            networks: Vec::new(),
            addresses: Vec::new(),
            published_ports: Vec::new(),
            memory_limit: None,
            oom_killed: false,
            conmon_pid: None,
        }];
        let inventory = Inventory::new(vec![
            record("1", Owner::PlatformDaemon, "ghcr.io/x/y", 'a'),
            record("2", Owner::PlatformDaemon, "ghcr.io/x/y", 'b'),
            record("3", Owner::PlatformDaemon, "ghcr.io/x/y", 'c'),
        ])
        .unwrap();
        let protections =
            BTreeSet::from([protection_digest('c', ProtectionReason::PlatformCurrent)]);
        let input = RetentionInput {
            images: &images,
            containers: &containers,
            inventory: &inventory,
            protections: &protections,
            scope: RetentionScope::AllManaged,
        };
        let plan = ManagedRetentionPlanner.plan(&input);
        assert_eq!(
            plan.remove
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            [full_id("1").as_str()]
        );
        assert!(
            plan.keep
                .iter()
                .any(|(i, r)| i.id == full_id("2") && *r == KeepReason::InUse(vec!["old".into()]))
        );
        assert!(plan.keep.iter().any(|(i, _)| i.id == full_id("3")));
    }

    #[test]
    fn planner_matches_standalone_digest_and_reports_unattributed_images() {
        // The image kept a standalone `Digest` but no repository names (#442).
        let mut kept = image("1", 'a');
        kept.digest = None;
        let images = [kept, image("2", 'b')];
        let inventory =
            Inventory::new(vec![record("1", Owner::PlatformDaemon, "ghcr.io/x/y", 'a')]).unwrap();
        let protections =
            BTreeSet::from([protection_digest('a', ProtectionReason::PlatformPrevious)]);
        let input = RetentionInput {
            images: &images,
            containers: &[],
            inventory: &inventory,
            protections: &protections,
            scope: RetentionScope::AllManaged,
        };
        let plan = ManagedRetentionPlanner.plan(&input);
        assert!(plan.remove.is_empty(), "{plan:?}");
        assert_eq!(plan.keep.len(), 1);
        assert_eq!(plan.unattributed.len(), 1);
        assert_eq!(plan.unattributed[0].id, full_id("2"));
    }

    #[test]
    fn planner_applies_the_scope_to_the_inventory() {
        let images = [image("1", 'a'), image("2", 'b')];
        let inventory = Inventory::new(vec![
            record("1", Owner::PlatformDaemon, "ghcr.io/x/y", 'a'),
            record("2", Owner::PlatformDaemon, "ghcr.io/x/other", 'b'),
        ])
        .unwrap();
        let protections = BTreeSet::new();
        let plan = |scope| {
            ManagedRetentionPlanner.plan(&RetentionInput {
                images: &images,
                containers: &[],
                inventory: &inventory,
                protections: &protections,
                scope,
            })
        };

        let scoped = plan(RetentionScope::OwnerRepository {
            owner: Owner::PlatformDaemon,
            repository: repo("ghcr.io/x/y"),
        });
        assert_eq!(
            scoped.remove.iter().map(|i| &i.id).collect::<Vec<_>>(),
            [&full_id("1")],
            "only the scoped repository is a candidate"
        );
        assert_eq!(scoped.unattributed.len(), 1, "{scoped:?}");

        assert_eq!(plan(RetentionScope::AllManaged).remove.len(), 2);
    }

    fn reconciler() -> (tempfile::TempDir, Reconciler<FakePodman>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::in_dir(dir.path());
        std::fs::write(&paths.apps, "").unwrap();
        let store = Arc::new(FileSecretStore::new(dir.path().join("secrets.toml")));
        let rec = Reconciler::new(
            FakePodman::new(),
            store,
            paths,
            ReconcilerOptions::default(),
        );
        (dir, rec)
    }

    #[tokio::test]
    async fn record_unions_associations_and_digests_for_the_same_image() {
        let (_dir, rec) = reconciler();
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        InventoryStore::record(
            &rec,
            &guard,
            record("aa", Owner::PlatformDaemon, "ghcr.io/x/y", 'a'),
        )
        .await
        .unwrap();
        InventoryStore::record(
            &rec,
            &guard,
            record(
                "aa",
                Owner::App {
                    instance: instance("web"),
                },
                "ghcr.io/x/y",
                'b',
            ),
        )
        .await
        .unwrap();
        let inventory = InventoryStore::load(&rec, &guard).await.unwrap();
        assert_eq!(inventory.images.len(), 1);
        assert_eq!(
            inventory.images[0].associations.len(),
            2,
            "union, never replace"
        );
        assert_eq!(inventory.images[0].digests.len(), 2);
    }

    #[tokio::test]
    async fn a_digest_cannot_belong_to_two_image_ids() {
        let (_dir, rec) = reconciler();
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        InventoryStore::record(
            &rec,
            &guard,
            record("aa", Owner::PlatformDaemon, "ghcr.io/x/y", 'a'),
        )
        .await
        .unwrap();
        let error = InventoryStore::record(
            &rec,
            &guard,
            record("bb", Owner::PlatformDaemon, "ghcr.io/x/y", 'a'),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, EngineError::ImageBookkeeping(_)));
    }

    #[tokio::test]
    async fn corrupt_inventory_is_an_error_not_an_empty_inventory() {
        let (dir, rec) = reconciler();
        std::fs::write(dir.path().join(INVENTORY_FILE_NAME), "not toml").unwrap();
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        let error = InventoryStore::load(&rec, &guard).await.unwrap_err();
        assert!(matches!(error, EngineError::ImageBookkeeping(_)));
        // The invalid file is not replaced.
        assert_eq!(
            std::fs::read_to_string(dir.path().join(INVENTORY_FILE_NAME)).unwrap(),
            "not toml"
        );
    }

    #[tokio::test]
    async fn reservation_phases_and_duplicate_ids() {
        let (dir, rec) = reconciler();
        std::fs::write(&rec.paths.apps, "").unwrap();
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        let operation = OperationId::new("op-1").unwrap();
        let reservation = Reservation {
            owner: ReservationOwner::new("engine", 1, "boot-1", 1_700_000_000).unwrap(),
            phase: ReservationPhase::Loading,
            protections: BTreeSet::new(),
            journal_ref: None,
            created_at: 1_700_000_000,
        };
        ReservationStore::reserve(&rec, &guard, operation.clone(), &reservation)
            .await
            .unwrap();
        let error = ReservationStore::reserve(&rec, &guard, operation.clone(), &reservation)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, EngineError::ImageBookkeeping(m) if m.contains("already exists")),
            "{error:?}"
        );
        let protections = BTreeSet::from([Protection {
            identity: ProtectionIdentity::ImageId(ImageId::new(full_id("aa")).unwrap()),
            reason: ProtectionReason::AcquisitionInProgress,
            operation_id: Some(operation.clone()),
        }]);
        ReservationStore::advance(
            &rec,
            &guard,
            operation.clone(),
            ReservationPhase::Loaded,
            &protections,
        )
        .await
        .unwrap();
        let stored = rec.reservation(&operation).unwrap().unwrap();
        assert_eq!(stored.phase, ReservationPhase::Loaded);
        assert_eq!(stored.protections, protections);
        ReservationStore::finish(&rec, &guard, operation.clone())
            .await
            .unwrap();
        assert!(
            Reservations::parse(&reservations_file(&dir))
                .unwrap()
                .operations
                .is_empty()
        );
    }

    fn reservations_file(dir: &tempfile::TempDir) -> String {
        std::fs::read_to_string(dir.path().join(RESERVATIONS_FILE_NAME)).unwrap_or_default()
    }

    #[tokio::test]
    async fn the_inventory_is_written_at_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, rec) = reconciler();
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        InventoryStore::record(
            &rec,
            &guard,
            record("aa", Owner::PlatformDaemon, "ghcr.io/x/y", 'a'),
        )
        .await
        .unwrap();
        let mode = std::fs::metadata(dir.path().join(INVENTORY_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        // The file parses as the shared model and keeps the format version.
        let inventory = Inventory::parse(
            &std::fs::read_to_string(dir.path().join(INVENTORY_FILE_NAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(inventory.format_version, FORMAT_VERSION);
    }

    #[tokio::test]
    async fn record_many_writes_the_inventory_once() {
        let (dir, rec) = reconciler();
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        write_count::take();
        let images = vec![
            record("aa", Owner::PlatformDaemon, "ghcr.io/x/y", 'a'),
            record("bb", Owner::PlatformDaemon, "ghcr.io/x/y", 'b'),
            record("cc", Owner::PlatformDaemon, "ghcr.io/x/y", 'c'),
        ];
        let recorded = InventoryStore::record_many(&rec, &guard, images)
            .await
            .unwrap();
        assert_eq!(recorded.len(), 3, "all three images are recorded");
        assert_eq!(
            write_count::take(),
            1,
            "a batch records with one read and one write"
        );
        // The whole batch lands in the file, not just the last write.
        let inventory = Inventory::parse(
            &std::fs::read_to_string(dir.path().join(INVENTORY_FILE_NAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(inventory.images.len(), 3);
    }

    /// Three unmanaged images that a legacy install's specs name: each one is adoptable.
    fn legacy_adoptable_images(rec: &Reconciler<FakePodman>) {
        std::fs::write(
            &rec.paths.apps,
            "[apps.a]\nimage = \"ghcr.io/x/a:latest\"\n\
             [apps.b]\nimage = \"ghcr.io/x/b:latest\"\n\
             [apps.c]\nimage = \"ghcr.io/x/c:latest\"\n",
        )
        .unwrap();
        for (id, name, c) in [("1", "a", 'a'), ("2", "b", 'b'), ("3", "c", 'c')] {
            let mut info = image(id, c);
            info.repo_tags = vec![format!("ghcr.io/x/{name}:latest")];
            rec.podman.add_image(info);
        }
    }

    #[tokio::test]
    async fn a_retention_run_adopting_several_images_writes_the_inventory_once() {
        let (dir, rec) = reconciler();
        legacy_adoptable_images(&rec);
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        write_count::take();

        let prepared = rec
            .prepare_retention(RetentionScope::AllManaged, Some(&guard))
            .await
            .unwrap();

        assert_eq!(
            write_count::take(),
            1,
            "adopting three images records with one write"
        );
        assert!(
            prepared.diagnostics.is_empty(),
            "{:?}",
            prepared.diagnostics
        );
        assert_eq!(prepared.inventory.images.len(), 3);
        let on_disk = Inventory::parse(
            &std::fs::read_to_string(dir.path().join(INVENTORY_FILE_NAME)).unwrap(),
        )
        .unwrap();
        assert_eq!(on_disk.images.len(), 3, "every adoption lands in the file");
    }

    #[tokio::test]
    async fn a_dry_run_advertises_adoptions_without_writing() {
        let (dir, rec) = reconciler();
        legacy_adoptable_images(&rec);
        write_count::take();

        let prepared = rec
            .prepare_retention(RetentionScope::AllManaged, None)
            .await
            .unwrap();

        assert_eq!(write_count::take(), 0, "a dry run never writes");
        assert_eq!(prepared.inventory.images.len(), 3, "but it advertises");
        assert!(!dir.path().join(INVENTORY_FILE_NAME).exists());
    }

    #[tokio::test]
    async fn a_failed_adoption_write_refuses_the_whole_batch() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, rec) = reconciler();
        legacy_adoptable_images(&rec);
        let held = rec.acquire().await;
        let guard = ImageGuard::new(&held);
        let restore = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap()
        };
        restore(0o555);
        if std::fs::File::create(dir.path().join("probe")).is_ok() {
            // Permissions are not enforced (running as root): the failure cannot be provoked.
            restore(0o755);
            eprintln!("SKIPPED: file permissions are not enforced (running as root)");
            return;
        }

        let prepared = rec
            .prepare_retention(RetentionScope::AllManaged, Some(&guard))
            .await;
        restore(0o755);

        // The batch is not narrowed to what could be recorded: the whole input is refused.
        let error = prepared.err().expect("a failed batch refuses the input");
        assert!(
            matches!(&error, EngineError::ImageBookkeeping(m)
                if m.contains("cannot record image provenance")),
            "{error:?}"
        );
        assert!(!dir.path().join(INVENTORY_FILE_NAME).exists());
    }
}
