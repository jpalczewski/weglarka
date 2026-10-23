//! Container labels — the reconcile contract (`Zasady architektury`, QlBT25G).

use std::collections::BTreeMap;

use crate::app::InstanceName;
use crate::hash::SpecHash;

pub const INSTANCE: &str = "weglarka.instance";
pub const GENERATION: &str = "weglarka.generation";
pub const SPEC_HASH: &str = "weglarka.spec-hash";

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

/// Per-app network that the instance container (and the ingress nginx) joins.
pub fn network_name(instance: &InstanceName) -> String {
    format!("net-{instance}")
}
