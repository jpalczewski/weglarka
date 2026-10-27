//! Generated config files (#212): the contract between a *generator* (renders files from
//! `apps.toml` and credential digests) and the pipeline in `weglarka-engine` that writes, validates
//! and applies them to the consumer app.
//!
//! This module is the pure half: the file and fingerprint types, the `dyn`-safe [`ConfigGenerator`]
//! trait and the on-disk layout names. A generator never sees a secret value — only references and
//! [`Pbkdf2Digest`]s (#213) — so the rendered bytes are safe to keep in a plain directory.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::app::{AppSpec, AppsFile, InstanceName};
use crate::secret_ops::Pbkdf2Digest;

/// Hex characters of the fingerprint used in a version directory name.
pub const SHORT_FINGERPRINT_LEN: usize = 12;
/// Name of the relative symlink to the live version inside a consumer's generated directory.
pub const CURRENT_LINK: &str = "current";
/// Prefix of a version directory (`v-<fingerprint12>`).
pub const VERSION_PREFIX: &str = "v-";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FileNameError {
    #[error("generated file name {0:?} must be 1-64 chars of [A-Za-z0-9._-] ending in .yml")]
    Invalid(String),
}

/// A bare file name inside the generated directory: no separators, no `..`, ends in `.yml`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileName(String);

impl FileName {
    pub fn new(name: impl Into<String>) -> Result<Self, FileNameError> {
        let name = name.into();
        let stem = name.strip_suffix(".yml");
        let ok = name.len() <= 64
            && stem.is_some_and(|s| !s.is_empty() && !s.starts_with('.'))
            && !name.contains("..")
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if ok {
            Ok(Self(name))
        } else {
            Err(FileNameError::Invalid(name))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One rendered file. `Debug` prints the name and size only: the bytes are config, not log material.
#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    name: FileName,
    bytes: Vec<u8>,
}

impl GeneratedFile {
    pub fn new(name: FileName, bytes: Vec<u8>) -> Self {
        Self { name, bytes }
    }

    pub fn name(&self) -> &FileName {
        &self.name
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for GeneratedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GeneratedFile({}, {} bytes)",
            self.name,
            self.bytes.len()
        )
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RenderError {
    #[error("generator {id} produced the file {name} twice")]
    DuplicateFile { id: &'static str, name: String },
    #[error("generator {id} cannot render: {reason}")]
    Failed { id: &'static str, reason: String },
}

/// Everything a generator may read. Digests are the public half of a credential (#213); a
/// `SecretValue` has no way in.
pub struct RenderInput<'a> {
    pub apps: &'a AppsFile,
    pub digests: &'a BTreeMap<InstanceName, Pbkdf2Digest>,
}

/// Renders the files of one consumer. Synchronous and `dyn`-safe, like `SecretStore`.
pub trait ConfigGenerator: Send + Sync {
    /// Stable id used in events, `doctor` and the state file, e.g. `"identity"`.
    fn id(&self) -> &'static str;

    /// The instance that reads the files.
    fn consumer(&self) -> &InstanceName;

    /// Pure: the same input yields the same bytes (sorted maps, no timestamps).
    fn render(&self, input: &RenderInput<'_>) -> Result<Vec<GeneratedFile>, RenderError>;

    /// The full command line (program first) that validates `dir` (a path inside the consumer's
    /// mount) together with the consumer's other config, derived from the consumer's own spec. The
    /// engine runs it in a one-off container of the consumer with `argv[0]` as the entrypoint.
    /// `None` = nothing to run.
    fn validate_argv(&self, consumer: &AppSpec, dir: &str) -> Option<Vec<String>>;
}

/// sha256 over the files, hex. Equal fingerprints mean byte-identical output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Computed over the files sorted by name, each as `name \0 length bytes` (the length keeps
    /// `a` + `bc` distinct from `ab` + `c`). Duplicate names are an error: the writer would
    /// silently keep one of them.
    pub fn of(id: &'static str, files: &[GeneratedFile]) -> Result<Self, RenderError> {
        let mut sorted: Vec<&GeneratedFile> = files.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(w) = sorted.windows(2).find(|w| w[0].name == w[1].name) {
            return Err(RenderError::DuplicateFile {
                id,
                name: w[0].name.to_string(),
            });
        }
        let mut hash = Sha256::new();
        for file in sorted {
            hash.update(file.name.as_str().as_bytes());
            hash.update([0]);
            hash.update((file.bytes.len() as u64).to_le_bytes());
            hash.update(&file.bytes);
        }
        Ok(Self(hex::encode(hash.finalize())))
    }

    /// Parses a stored fingerprint (64 lowercase hex chars); anything else is `None`.
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first [`SHORT_FINGERPRINT_LEN`] characters.
    pub fn short(&self) -> &str {
        &self.0[..SHORT_FINGERPRINT_LEN]
    }

    /// `v-<fingerprint12>`: the directory of this version.
    pub fn version_dir(&self) -> String {
        format!("{VERSION_PREFIX}{}", self.short())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, bytes: &str) -> GeneratedFile {
        GeneratedFile::new(FileName::new(name).unwrap(), bytes.as_bytes().to_vec())
    }

    #[test]
    fn file_names_are_bare_yaml_names() {
        for ok in ["access-control.yml", "a.yml", "clients_1.v2.yml"] {
            assert!(FileName::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".yml",
            ".hidden.yml",
            "a.yaml",
            "a.txt",
            "a/b.yml",
            "../a.yml",
            "a..b.yml",
            "a\\b.yml",
            "a b.yml",
            "a\0.yml",
            &format!("{}.yml", "a".repeat(64)),
        ] {
            assert!(FileName::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fingerprint_ignores_order_and_separates_names_from_bytes() {
        let a = Fingerprint::of("t", &[file("a.yml", "1"), file("b.yml", "2")]).unwrap();
        let b = Fingerprint::of("t", &[file("b.yml", "2"), file("a.yml", "1")]).unwrap();
        assert_eq!(a, b);
        assert_ne!(
            a,
            Fingerprint::of("t", &[file("a.yml", "12"), file("b.yml", "")]).unwrap()
        );
        assert_ne!(
            a,
            Fingerprint::of("t", &[file("a.yml", "1"), file("c.yml", "2")]).unwrap()
        );
        assert_eq!(a.as_str().len(), 64);
        assert_eq!(a.version_dir(), format!("v-{}", &a.as_str()[..12]));
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let err = Fingerprint::of("t", &[file("a.yml", "1"), file("a.yml", "2")]).unwrap_err();
        assert_eq!(
            err,
            RenderError::DuplicateFile {
                id: "t",
                name: "a.yml".into()
            }
        );
    }

    #[test]
    fn fingerprint_parse_accepts_only_lowercase_sha256_hex() {
        let fp = Fingerprint::of("t", &[file("a.yml", "1")]).unwrap();
        assert_eq!(Fingerprint::parse(fp.as_str()), Some(fp.clone()));
        assert_eq!(Fingerprint::parse(&fp.as_str().to_uppercase()), None);
        assert_eq!(Fingerprint::parse("abc"), None);
    }

    #[test]
    fn debug_hides_the_bytes() {
        let shown = format!("{:?}", file("a.yml", "topsecret"));
        assert!(!shown.contains("topsecret"));
        assert!(shown.contains("a.yml"));
    }
}
