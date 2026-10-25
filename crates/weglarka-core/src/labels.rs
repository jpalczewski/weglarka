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

/// Marks a one-off `weglarka run` container (the value is always `"true"`, so a label filter can find
/// every one of them). Deliberately not [`INSTANCE`]: reconcile, the crash watcher and ingress must
/// never mistake it for the app's container.
pub const RUN: &str = "weglarka.run";
/// The instance a one-off container was started for.
pub const RUN_FOR: &str = "weglarka.run-for";

/// Marks a `weglarka forward` relay container (the value is always `"true"`). Deliberately not
/// [`INSTANCE`], for the same reason as [`RUN`].
pub const FORWARD: &str = "weglarka.forward";
/// The instance a relay forwards to.
pub const FORWARD_FOR: &str = "weglarka.forward-for";

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

/// Label marking a network as shared by a group of instances (issue #128). Such a network has
/// deliberately **no** [`INSTANCE`] label, so network cleanup keyed on the instance never touches it.
pub const SHARED_NETWORK: &str = "weglarka.shared-network";

/// Podman network of a shared network. `net-shared-<name>` could read as the per-app network of an
/// instance called `shared-<name>`, so cleanup must go by [`SHARED_NETWORK`] and never by prefix;
/// the label is what tells the two apart.
pub fn shared_network_name(network: &crate::app::SharedNetworkName) -> String {
    format!("net-shared-{network}")
}

/// Podman volume name of an instance's volume. `.` cannot occur in an instance or volume name,
/// so `<instance>.<volume>` is unambiguous.
pub fn volume_name(instance: &InstanceName, volume: &str) -> String {
    format!("{instance}.{volume}")
}

/// Label marking a volume as shared between instances (issue #33). Such a volume deliberately has
/// **no** [`INSTANCE`] label, so instance purge / orphan settling / volume filters never touch it.
pub const SHARED_VOLUME: &str = "weglarka.shared-volume";

/// Label carrying the group of a shared volume (issue #129): the volumes of one group share a uid
/// range. Set when the volume is created; volumes created before groups only have
/// [`SHARED_VOLUME`], and their group is that volume's own name.
pub const SHARED_GROUP: &str = "weglarka.shared-group";

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

/// Name of one `weglarka run` container. `.` cannot occur in an instance name, so — like
/// [`import_container_name`] — it never collides with, and removing it never touches, an app's
/// container; `token` keeps concurrent runs of one app apart.
pub fn run_container_name(instance: &InstanceName, token: &str) -> String {
    format!("wg-run.{instance}.{token}")
}

/// Name of one `weglarka forward` relay; `.` cannot occur in an instance name, so it never collides
/// with an app's container. `token` keeps concurrent forwards of one app apart.
pub fn forward_container_name(instance: &InstanceName, token: &str) -> String {
    format!("wg-fwd.{instance}.{token}")
}
