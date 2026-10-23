//! Etykiety kontenerów — kontrakt reconcile (`Zasady architektury`, QlBT25G).

use std::collections::BTreeMap;

use crate::app::InstanceName;
use crate::hash::SpecHash;

pub const INSTANCE: &str = "weglarka.instance";
pub const GENERATION: &str = "weglarka.generation";
pub const SPEC_HASH: &str = "weglarka.spec-hash";

/// Zestaw etykiet, który reconcile nakłada na kontener instancji.
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

/// Nazwa kontenera instancji — to ona jest hostem DNS w sieci apki (`proxy_pass` nginxa).
pub fn container_name(instance: &InstanceName) -> String {
    instance.to_string()
}

/// Sieć per apka, do której dołącza kontener instancji (i nginx ingressu).
pub fn network_name(instance: &InstanceName) -> String {
    format!("net-{instance}")
}
