//! Stan runtime'owy instancji (przypięty digest, poprzedni digest). Własność sesji b:
//! tu dojdzie atomowy zapis (tmp + `rename`) i lokalizacja pliku (do ustalenia — patrz CLAUDE.md).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::app::{Digest, InstanceName};
use crate::hash::SpecHash;

/// Stan jednej instancji. `previous` to retencja 1 do rollbacku.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppState {
    /// Numer generacji kontenera (rośnie przy każdym odtworzeniu).
    #[serde(default)]
    pub generation: u64,
    /// Aktualnie przypięty digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Digest>,
    /// Poprzedni (znany dobry) digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Digest>,
    /// Hash specyfikacji, z którym uruchomiono `current`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<SpecHash>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFile {
    #[serde(default)]
    pub apps: BTreeMap<InstanceName, AppState>,
}
