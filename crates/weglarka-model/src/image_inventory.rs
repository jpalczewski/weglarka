//! Managed image provenance and durable reservations.
//!
//! Shared domain types for `managed-images.toml` and `image-reservations.toml` from
//! [`docs/contracts/platform-update-v1`](../../../docs/contracts/platform-update-v1/README.md).
//! The engine owns acquisition, retention and planning; this module only defines the identities,
//! the files, their bounds and their validation.
//!
//! A `ManagedImage` is an **upsert** target: recording an image unions its digests and
//! associations and never replaces another owner's association. An association whose owner is an
//! app still exists after the app is removed or changes repository — provenance is not derived from
//! age, size or labels.
//!
//! A reservation is durable intent, not a TTL. It is abandoned only when its boot is gone and no
//! nonterminal journal or transaction references it, or through the explicit operator command; wall
//! time never authorizes reclamation. The file is bounded, and a full file disables cleanup rather
//! than evicting live provenance.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::InstanceName;
use crate::platform_update::TransactionId;
use crate::release_set::{Repository, StrictDigest};

/// Inventory file in the shared state directory.
pub const INVENTORY_FILE_NAME: &str = "managed-images.toml";
/// Reservations file in the shared state directory.
pub const RESERVATIONS_FILE_NAME: &str = "image-reservations.toml";
/// Version of both file formats.
pub const FORMAT_VERSION: u32 = 1;
/// Largest accepted inventory file.
pub const MAX_INVENTORY_BYTES: usize = 8 * 1024 * 1024;
/// Largest accepted reservations file.
pub const MAX_RESERVATIONS_BYTES: usize = 1024 * 1024;
/// Most images the inventory may hold.
pub const MAX_IMAGES: usize = 32_768;
/// Most operations the reservations file may hold.
pub const MAX_RESERVATIONS: usize = 1024;

/// A canonical full local image ID: 64 lowercase hex characters, as libpod reports it. A short or
/// upper-case form would never compare equal to the id libpod returns, so a protection keyed by it
/// would not protect the image.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImageId(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid image id {0:?}: expected exactly 64 lower-case hex characters")]
pub struct InvalidImageId(pub String);

impl ImageId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidImageId> {
        let value = value.into();
        let ok = value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if ok {
            Ok(Self(value))
        } else {
            Err(InvalidImageId(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ImageId {
    type Error = InvalidImageId;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ImageId> for String {
    fn from(value: ImageId) -> Self {
        value.0
    }
}

impl fmt::Display for ImageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identifier of one acquisition/retention operation, stable across process death.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid operation id {0:?}: expected 1-128 characters of [A-Za-z0-9._:-]")]
pub struct InvalidOperationId(pub String);

impl OperationId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidOperationId> {
        let value = value.into();
        let ok = (1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
        if ok {
            Ok(Self(value))
        } else {
            Err(InvalidOperationId(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = InvalidOperationId;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who an image belongs to. An enrolled panel is still an app owner: its platform role is an
/// explicit configuration binding, not a reserved instance name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Owner {
    App { instance: InstanceName },
    PlatformDaemon,
}

/// One owner/repository association of a managed image.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Association {
    pub owner: Owner,
    pub repository: Repository,
}

/// A managed image: local ID, all known manifest digests and every owner/repository association.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedImage {
    pub image_id: ImageId,
    #[serde(default)]
    pub digests: BTreeSet<StrictDigest>,
    #[serde(default)]
    pub associations: BTreeSet<Association>,
}

/// `managed-images.toml`: upsert targets, sorted by image ID on write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub format_version: u32,
    #[serde(default)]
    pub images: Vec<ManagedImage>,
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            images: Vec::new(),
        }
    }
}

impl Inventory {
    pub fn new(images: Vec<ManagedImage>) -> Result<Self, InventoryError> {
        let inventory = Self {
            format_version: FORMAT_VERSION,
            images,
        };
        inventory.canonical()
    }

    pub fn get(&self, image_id: &ImageId) -> Option<&ManagedImage> {
        self.images.iter().find(|image| &image.image_id == image_id)
    }

    pub fn parse(src: &str) -> Result<Self, InventoryError> {
        if src.len() > MAX_INVENTORY_BYTES {
            return Err(InventoryError::TooLarge {
                file: INVENTORY_FILE_NAME,
                size: src.len(),
                limit: MAX_INVENTORY_BYTES,
            });
        }
        let probe: FormatProbe = toml::from_str(src)?;
        check_format(probe.format_version)?;
        let inventory: Self = toml::from_str(src)?;
        inventory.canonical()
    }

    pub fn to_toml(&self) -> Result<String, InventoryError> {
        Ok(toml::to_string(&self.canonical()?)?)
    }

    /// Sorted, duplicate-free, within bounds.
    fn canonical(&self) -> Result<Self, InventoryError> {
        check_format(Some(self.format_version))?;
        if self.images.len() > MAX_IMAGES {
            return Err(InventoryError::TooManyImages(self.images.len()));
        }
        let mut images = self.images.clone();
        images.sort_by_key(|image| image.image_id.clone());
        for pair in images.windows(2) {
            if pair[0].image_id == pair[1].image_id {
                return Err(InventoryError::DuplicateImageId(
                    pair[0].image_id.to_string(),
                ));
            }
        }
        Ok(Self {
            format_version: FORMAT_VERSION,
            images,
        })
    }
}

/// Why an image is protected from deletion. Protections always cover every owner, regardless of the
/// retention scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionReason {
    /// A container (any state) references the image.
    Container,
    AppCurrent,
    AppPrevious,
    /// The image tag is named by an app spec: the next deploy would use it.
    SpecTag,
    PlatformCurrent,
    PlatformPrevious,
    PendingSwitch,
    Fallback,
    AcquisitionInProgress,
}

/// What a protection names: a local image ID or a manifest digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionIdentity {
    ImageId(ImageId),
    Digest(StrictDigest),
}

/// A durable reason not to delete an image.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protection {
    pub identity: ProtectionIdentity,
    pub reason: ProtectionReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
}

/// Which images an automatic retention pass may consider. Protection is never narrowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionScope {
    AllManaged,
    OwnerRepository {
        owner: Owner,
        repository: Repository,
    },
}

/// Who holds a reservation: the component, process and boot that created the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationOwner {
    /// `acquisition`, `coordinator`, `engine`, ...
    pub component: String,
    pub pid: u32,
    /// Differs per boot; a reservation is reclaimable only when this is not the current boot.
    pub boot_id: String,
    /// Unix seconds when the operation started.
    pub started_at: u64,
}

impl ReservationOwner {
    pub fn new(
        component: impl Into<String>,
        pid: u32,
        boot_id: impl Into<String>,
        started_at: u64,
    ) -> Result<Self, InventoryError> {
        let owner = Self {
            component: component.into(),
            pid,
            boot_id: boot_id.into(),
            started_at,
        };
        owner.validate()?;
        Ok(owner)
    }

    fn validate(&self) -> Result<(), InventoryError> {
        if self.component.is_empty() || self.component.len() > 64 {
            return Err(InventoryError::Invalid(
                "reservation owner component must be 1-64 characters".into(),
            ));
        }
        if self.boot_id.is_empty() || self.boot_id.len() > 128 {
            return Err(InventoryError::Invalid(
                "reservation owner boot_id must be 1-128 characters".into(),
            ));
        }
        Ok(())
    }
}

/// Acquisition phase. `loading` → `loaded` before `image_tag`; `deploying` while a deploy owns the
/// operation; `coordinating` while the platform journal drives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationPhase {
    Loading,
    Loaded,
    Deploying,
    Coordinating,
}

/// A durable reservation of protected image identities. It has no TTL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub owner: ReservationOwner,
    pub phase: ReservationPhase,
    #[serde(default)]
    pub protections: BTreeSet<Protection>,
    /// The platform transaction that references this reservation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_ref: Option<TransactionId>,
    /// Unix seconds.
    pub created_at: u64,
}

/// One operation in `image-reservations.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationEntry {
    pub operation_id: OperationId,
    pub reservation: Reservation,
}

/// `image-reservations.toml`, sorted by operation ID on write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservations {
    pub format_version: u32,
    #[serde(default)]
    pub operations: Vec<ReservationEntry>,
}

impl Default for Reservations {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            operations: Vec::new(),
        }
    }
}

impl Reservations {
    pub fn new(operations: Vec<ReservationEntry>) -> Result<Self, InventoryError> {
        let reservations = Self {
            format_version: FORMAT_VERSION,
            operations,
        };
        reservations.canonical()
    }

    pub fn get(&self, operation_id: &OperationId) -> Option<&ReservationEntry> {
        self.operations
            .iter()
            .find(|entry| &entry.operation_id == operation_id)
    }

    pub fn parse(src: &str) -> Result<Self, InventoryError> {
        if src.len() > MAX_RESERVATIONS_BYTES {
            return Err(InventoryError::TooLarge {
                file: RESERVATIONS_FILE_NAME,
                size: src.len(),
                limit: MAX_RESERVATIONS_BYTES,
            });
        }
        let probe: FormatProbe = toml::from_str(src)?;
        check_format(probe.format_version)?;
        let reservations: Self = toml::from_str(src)?;
        reservations.canonical()
    }

    pub fn to_toml(&self) -> Result<String, InventoryError> {
        Ok(toml::to_string(&self.canonical()?)?)
    }

    fn canonical(&self) -> Result<Self, InventoryError> {
        check_format(Some(self.format_version))?;
        if self.operations.len() > MAX_RESERVATIONS {
            return Err(InventoryError::TooManyReservations(self.operations.len()));
        }
        let mut operations = self.operations.clone();
        operations.sort_by_key(|entry| entry.operation_id.clone());
        for pair in operations.windows(2) {
            if pair[0].operation_id == pair[1].operation_id {
                return Err(InventoryError::DuplicateOperationId(
                    pair[0].operation_id.to_string(),
                ));
            }
        }
        for entry in &operations {
            entry.reservation.owner.validate()?;
        }
        Ok(Self {
            format_version: FORMAT_VERSION,
            operations,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InventoryError {
    #[error("{file} is {size} bytes, the limit is {limit}")]
    TooLarge {
        file: &'static str,
        size: usize,
        limit: usize,
    },
    #[error("unsupported format_version {0}")]
    UnsupportedFormat(u32),
    #[error("inventory holds {0} images, over the limit of {MAX_IMAGES}")]
    TooManyImages(usize),
    #[error("reservations file holds {0} operations, over the limit of {MAX_RESERVATIONS}")]
    TooManyReservations(usize),
    #[error("duplicate image id {0:?}")]
    DuplicateImageId(String),
    #[error("duplicate operation id {0:?}")]
    DuplicateOperationId(String),
    #[error("invalid image bookkeeping: {0}")]
    Invalid(String),
    #[error("invalid TOML: {0}")]
    TomlDe(String),
    #[error("cannot serialize TOML: {0}")]
    TomlSer(String),
}

impl From<toml::de::Error> for InventoryError {
    fn from(error: toml::de::Error) -> Self {
        Self::TomlDe(error.to_string())
    }
}

impl From<toml::ser::Error> for InventoryError {
    fn from(error: toml::ser::Error) -> Self {
        Self::TomlSer(error.to_string())
    }
}

#[derive(Deserialize)]
struct FormatProbe {
    #[serde(default)]
    format_version: Option<u32>,
}

fn check_format(value: Option<u32>) -> Result<(), InventoryError> {
    match value {
        Some(FORMAT_VERSION) => Ok(()),
        Some(other) => Err(InventoryError::UnsupportedFormat(other)),
        None => Err(InventoryError::Invalid("missing format_version".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    /// A full-length image id made of one repeated hex digit.
    fn id(digit: char) -> String {
        digit.to_string().repeat(64)
    }

    fn image(id: &str, owner: Owner, byte: char) -> ManagedImage {
        ManagedImage {
            image_id: ImageId::new(id).unwrap(),
            digests: [digest(byte)].into(),
            associations: [Association {
                owner,
                repository: Repository::new("ghcr.io/example/weglarka").unwrap(),
            }]
            .into(),
        }
    }

    #[test]
    fn image_id_is_exactly_64_lower_case_hex_characters() {
        assert!(ImageId::new(id('a')).is_ok());
        for bad in [
            "3f2a1b".to_owned(),
            String::new(),
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ] {
            assert!(ImageId::new(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn inventory_round_trips_sorted_and_rejects_duplicate_ids() {
        let web = Owner::App {
            instance: InstanceName::new("web").unwrap(),
        };
        let inventory = Inventory::new(vec![
            image(&id('f'), web.clone(), 'b'),
            image(&id('a'), Owner::PlatformDaemon, 'a'),
        ])
        .unwrap();
        assert_eq!(
            inventory
                .images
                .iter()
                .map(|i| i.image_id.as_str())
                .collect::<Vec<_>>(),
            [id('a').as_str(), id('f').as_str()]
        );
        let text = inventory.to_toml().unwrap();
        assert_eq!(Inventory::parse(&text).unwrap(), inventory);
        assert_eq!(
            Inventory::new(vec![
                image(&id('a'), web.clone(), 'a'),
                image(&id('a'), web, 'b')
            ])
            .unwrap_err(),
            InventoryError::DuplicateImageId(id('a'))
        );
    }

    #[test]
    fn reservation_round_trips_with_owner_phase_and_journal_reference() {
        let reservation = Reservation {
            owner: ReservationOwner::new("acquisition", 42, "boot-1", 1_700_000_000).unwrap(),
            phase: ReservationPhase::Loaded,
            protections: [Protection {
                identity: ProtectionIdentity::ImageId(ImageId::new(id('a')).unwrap()),
                reason: ProtectionReason::AcquisitionInProgress,
                operation_id: Some(OperationId::new("op-1").unwrap()),
            }]
            .into(),
            journal_ref: Some(TransactionId::new("tx-1").unwrap()),
            created_at: 1_700_000_001,
        };
        let entry = ReservationEntry {
            operation_id: OperationId::new("op-1").unwrap(),
            reservation,
        };
        let reservations = Reservations::new(vec![entry.clone()]).unwrap();
        let text = reservations.to_toml().unwrap();
        assert_eq!(Reservations::parse(&text).unwrap(), reservations);
        assert_eq!(
            Reservations::new(vec![entry.clone(), entry]).unwrap_err(),
            InventoryError::DuplicateOperationId("op-1".into())
        );
    }

    #[test]
    fn formats_and_bounds_are_enforced() {
        let inventory = Inventory::default();
        let text = inventory.to_toml().unwrap();
        let newer = text.replace("format_version = 1", "format_version = 2");
        assert_eq!(
            Inventory::parse(&newer).unwrap_err(),
            InventoryError::UnsupportedFormat(2)
        );
        let many = Inventory {
            format_version: FORMAT_VERSION,
            images: vec![image(&id('a'), Owner::PlatformDaemon, 'a'); MAX_IMAGES + 1],
        };
        assert!(matches!(
            many.to_toml().unwrap_err(),
            InventoryError::TooManyImages(_)
        ));
    }
}
