//! Container labels — the reconcile contract.

use std::collections::BTreeMap;

use crate::app::InstanceName;
use crate::hash::SpecHash;

pub const INSTANCE: &str = "weglarka.instance";
pub const GENERATION: &str = "weglarka.generation";
pub const SPEC_HASH: &str = "weglarka.spec-hash";
/// uid range the container was created with (`<start>+<size>`, [`uid_range_label`]). Part of the
/// container's identity next to `spec-hash`, but kept out of the hash: it is state, not spec.
pub const UID_RANGE: &str = "weglarka.uid-range";
/// Marks the short-lived container that carries a foreign tar into a volume (`volumes::ImportMode::Foreign`).
/// Deliberately not [`INSTANCE`], so reconcile never mistakes it for a duplicate of the app.
pub const IMPORT_FOR: &str = "weglarka.import-for";

/// Set of labels that reconcile applies to an instance's container.
pub fn container_labels(
    instance: &InstanceName,
    generation: u64,
    spec_hash: &SpecHash,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (INSTANCE.to_owned(), instance.to_string()),
        (GENERATION.to_owned(), generation.to_string()),
        (SPEC_HASH.to_owned(), spec_hash.to_string()),
    ])
}

/// Instance container name — it is the DNS host in the app's network (nginx `proxy_pass`).
pub fn container_name(instance: &InstanceName) -> String {
    instance.to_string()
}

/// Network of Węglarka itself (daemon + ingress nginx). Shaped like an app network, so network
/// cleanup must never treat it as an orphan.
pub const INGRESS_NETWORK: &str = "net-weglarka";

/// Per-app network that the instance container (and the ingress nginx) joins.
pub fn network_name(instance: &InstanceName) -> String {
    format!("net-{instance}")
}

/// Podman volume name of an instance's volume. `.` cannot occur in an instance or volume name,
/// so `<instance>.<volume>` is unambiguous.
pub fn volume_name(instance: &InstanceName, volume: &str) -> String {
    format!("{instance}.{volume}")
}

/// Label marking a volume as shared between instances (issue #33). Such a volume deliberately has
/// **no** [`INSTANCE`] label, so instance purge / orphan settling / volume filters never touch it.
pub const SHARED_VOLUME: &str = "weglarka.shared-volume";

/// Podman volume name of a shared volume. It contains no `.`, while every per-instance volume is
/// `<instance>.<volume>` (instance and volume names are `[a-z0-9-]`), so the two namespaces cannot
/// collide.
pub fn shared_volume_name(volume: &crate::app::SharedVolumeName) -> String {
    format!("wg-shared-{volume}")
}

/// Value of the [`UID_RANGE`] label.
pub fn uid_range_label(range: crate::uid_range::UidRange) -> String {
    format!("{}+{}", range.start, range.size)
}

/// Name of the helper container used to import a foreign tar into an instance's volume. The `.`
/// cannot occur in an instance name (and container names are instance names), so the helper never
/// collides with — and force-removing it never touches — another instance's container.
pub fn import_container_name(instance: &InstanceName) -> String {
    format!("wg-import.{instance}")
}
