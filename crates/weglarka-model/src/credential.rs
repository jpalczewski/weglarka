//! Header credentials read from a private file: the one place that decides what may become an
//! `Authorization` header. Values never reach logs, `Debug` or an error message.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::fsutil::{PrivateFileError, check_private};
use crate::secret_store::{SecretError, SecretStore, SecretValue};

#[derive(Debug, thiserror::Error)]
pub enum HeaderTokenError {
    #[error("is empty")]
    Empty,
    #[error("has characters that cannot go into an HTTP header")]
    Invalid,
}

/// Reads a file that must be private: `check_private`, then the bytes, then
/// [`parse_header_token`]. A missing file is an error ([`TokenFileError::Io`]).
pub fn read_private_token(path: &Path) -> Result<SecretValue, TokenFileError> {
    check_private(path)?;
    let raw = std::fs::read(path)?;
    Ok(parse_header_token(&raw)?)
}

/// Trims trailing `\r`/`\n`, then requires printable ASCII: a CR/LF inside a value would be a
/// header injection. Non-UTF-8 bytes are not `is_ascii_graphic`, so they fail as [`HeaderTokenError::Invalid`].
pub fn parse_header_token(raw: &[u8]) -> Result<SecretValue, HeaderTokenError> {
    let end = raw
        .iter()
        .rposition(|b| *b != b'\r' && *b != b'\n')
        .map_or(0, |i| i + 1);
    let token = &raw[..end];
    if token.is_empty() {
        return Err(HeaderTokenError::Empty);
    }
    if !token.iter().all(u8::is_ascii_graphic) {
        return Err(HeaderTokenError::Invalid);
    }
    Ok(SecretValue::new(token))
}

/// Failure of [`read_private_token`]; never carries the value.
#[derive(Debug, thiserror::Error)]
pub enum TokenFileError {
    #[error("cannot read: {0}")]
    Io(#[from] std::io::Error),
    #[error("must not be accessible by group or others (chmod 600)")]
    TooOpen,
    #[error(transparent)]
    Header(#[from] HeaderTokenError),
}

impl From<PrivateFileError> for TokenFileError {
    fn from(err: PrivateFileError) -> Self {
        match err {
            PrivateFileError::Io(e) => Self::Io(e),
            PrivateFileError::TooOpen { .. } => Self::TooOpen,
        }
    }
}

/// One read seam for a credential (ADR 0079): a synchronous, dyn-compatible source whose value is
/// read on every use (never cached by the caller), so rotation needs no restart.
pub trait CredentialSource: Send + Sync {
    fn read(&self) -> Result<SecretValue, CredentialError>;
    /// Human label naming the source (never the value), for errors and `doctor`.
    fn describe(&self) -> String;
}

/// Failure of [`CredentialSource::read`]; never carries the value.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("token file: {0}")]
    File(#[from] TokenFileError),
    #[error("host secret: {0}")]
    Secret(#[from] SecretError),
    #[error("host secret value {0}")]
    Header(#[from] HeaderTokenError),
    #[error("no host secret {0:?}")]
    Missing(String),
}

/// A `token_file`-style credential: a 0600 file read and validated on every
/// [`CredentialSource::read`].
pub struct FileCredential {
    path: PathBuf,
}

impl FileCredential {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl CredentialSource for FileCredential {
    fn read(&self) -> Result<SecretValue, CredentialError> {
        Ok(read_private_token(&self.path)?)
    }

    fn describe(&self) -> String {
        format!("file {}", self.path.display())
    }
}

impl fmt::Debug for FileCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileCredential")
            .field("path", &self.path)
            .finish()
    }
}

/// A named entry in the host secret store (`host-secrets.toml`), read and validated on every
/// [`CredentialSource::read`].
pub struct StoreCredential {
    store: Arc<dyn SecretStore>,
    name: String,
}

impl StoreCredential {
    pub fn new(store: Arc<dyn SecretStore>, name: impl Into<String>) -> Self {
        Self {
            store,
            name: name.into(),
        }
    }
}

impl CredentialSource for StoreCredential {
    fn read(&self) -> Result<SecretValue, CredentialError> {
        let value = self
            .store
            .get(&self.name)?
            .ok_or_else(|| CredentialError::Missing(self.name.clone()))?;
        Ok(parse_header_token(value.expose())?)
    }

    fn describe(&self) -> String {
        format!("host secret {}", self.name)
    }
}

impl fmt::Debug for StoreCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreCredential")
            .field("name", &self.name)
            .finish()
    }
}

/// The source named by a `token_file` / `token_secret` pair; `None` when neither is set (or both,
/// which validation rejects first).
pub fn credential_from(
    token_file: Option<&Path>,
    token_secret: Option<&str>,
    host_store: &Arc<dyn SecretStore>,
) -> Option<Arc<dyn CredentialSource>> {
    match (token_file, token_secret) {
        (Some(path), None) => Some(Arc::new(FileCredential::new(path))),
        (None, Some(name)) => Some(Arc::new(StoreCredential::new(host_store.clone(), name))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn write(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_printable_token_keeps_its_bytes() {
        let token = parse_header_token(b"tk_secret").unwrap();
        assert_eq!(token.expose(), b"tk_secret");
        assert_eq!(format!("{token:?}"), "SecretValue(<redacted>)");
    }

    #[test]
    fn one_trailing_newline_or_crlf_is_trimmed() {
        assert_eq!(parse_header_token(b"tk\n").unwrap().expose(), b"tk");
        assert_eq!(parse_header_token(b"tk\r\n").unwrap().expose(), b"tk");
        assert_eq!(parse_header_token(b"tk\r\n\n").unwrap().expose(), b"tk");
    }

    #[test]
    fn empty_and_newline_only_are_empty() {
        for raw in [&b""[..], b"\n", b"\r\n", b"\r\n\r\n"] {
            assert!(
                matches!(parse_header_token(raw), Err(HeaderTokenError::Empty)),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_cr_or_lf_inside_and_spaces_are_invalid() {
        for raw in [
            &b"bad\r\nHeader: x"[..],
            b"a\nb",
            b"a\rb",
            b"two words",
            b"tk_ok\t",
            b"tk_ok\x7f",
        ] {
            assert!(
                matches!(parse_header_token(raw), Err(HeaderTokenError::Invalid)),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn non_ascii_and_nul_are_invalid() {
        for raw in [&b"tk\xc3\xa9"[..], b"tk\x00", b"\xff\xfe"] {
            assert!(
                matches!(parse_header_token(raw), Err(HeaderTokenError::Invalid)),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn read_private_token_reads_0600_and_refuses_looser_modes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        write(&path, b"tk_secret\n", 0o600);
        assert_eq!(read_private_token(&path).unwrap().expose(), b"tk_secret");

        write(&path, b"tk_secret\n", 0o644);
        let err = read_private_token(&path).unwrap_err();
        assert!(matches!(err, TokenFileError::TooOpen));
        assert!(!err.to_string().contains("tk_secret"));
    }

    #[test]
    fn read_private_token_reports_a_missing_file_as_io() {
        let dir = tempfile::tempdir().unwrap();
        match read_private_token(&dir.path().join("nope")) {
            Err(TokenFileError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn read_private_token_maps_empty_and_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        write(&path, b"\n", 0o600);
        assert!(matches!(
            read_private_token(&path),
            Err(TokenFileError::Header(HeaderTokenError::Empty))
        ));
        write(&path, b"two words", 0o600);
        let err = read_private_token(&path).unwrap_err();
        assert!(matches!(
            err,
            TokenFileError::Header(HeaderTokenError::Invalid)
        ));
        assert!(!err.to_string().contains("two words"));
    }

    #[test]
    fn non_utf8_in_a_file_is_invalid_not_io() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        write(&path, b"\xff\xfe", 0o600);
        assert!(matches!(
            read_private_token(&path),
            Err(TokenFileError::Header(HeaderTokenError::Invalid))
        ));
    }

    #[test]
    fn file_credential_reads_rotates_and_refuses_loose_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        write(&path, b"tk_one\n", 0o600);
        let src = FileCredential::new(&path);
        assert_eq!(src.describe(), format!("file {}", path.display()));
        assert_eq!(src.read().unwrap().expose(), b"tk_one");

        // Rotation: rewriting the file is visible on the next read, no restart needed.
        write(&path, b"tk_two\n", 0o600);
        assert_eq!(src.read().unwrap().expose(), b"tk_two");

        write(&path, b"tk_three", 0o644);
        let err = src.read().unwrap_err();
        assert!(matches!(
            err,
            CredentialError::File(TokenFileError::TooOpen)
        ));
        assert!(!format!("{err:?}").contains("tk_three"));

        match FileCredential::new(dir.path().join("nope")).read() {
            Err(CredentialError::File(TokenFileError::Io(e))) => {
                assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn store_credential_reads_rotates_and_reports_missing() {
        use crate::secrets::FileSecretStore;

        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::host(dir.path().join("host-secrets.toml"));
        let store: Arc<dyn SecretStore> = Arc::new(store);
        let src = StoreCredential::new(store.clone(), "ntfy-token");
        assert_eq!(src.describe(), "host secret ntfy-token");

        assert!(matches!(
            src.read(),
            Err(CredentialError::Missing(n)) if n == "ntfy-token"
        ));

        store.set("ntfy-token", SecretValue::new("tk_one")).unwrap();
        assert_eq!(src.read().unwrap().expose(), b"tk_one");

        // Rotation via `set` is visible on the next read.
        store.set("ntfy-token", SecretValue::new("tk_two")).unwrap();
        assert_eq!(src.read().unwrap().expose(), b"tk_two");
    }

    #[test]
    fn a_cr_or_lf_inside_the_value_is_refused_by_both_adapters() {
        use crate::secrets::FileSecretStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        write(&path, b"a\nb", 0o600);
        assert!(matches!(
            FileCredential::new(&path).read(),
            Err(CredentialError::File(TokenFileError::Header(
                HeaderTokenError::Invalid
            )))
        ));

        let store = FileSecretStore::host(dir.path().join("host-secrets.toml"));
        let store: Arc<dyn SecretStore> = Arc::new(store);
        store.set("ntfy-token", SecretValue::new("a\nb")).unwrap();
        assert!(matches!(
            StoreCredential::new(store, "ntfy-token").read(),
            Err(CredentialError::Header(HeaderTokenError::Invalid))
        ));
    }

    #[test]
    fn debug_and_display_never_reveal_the_value() {
        use crate::secrets::FileSecretStore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        write(&path, b"tk_secret", 0o644);
        let file = FileCredential::new(&path);
        let err = file.read().unwrap_err();
        for text in [format!("{err}"), format!("{err:?}"), format!("{file:?}")] {
            assert!(!text.contains("tk_secret"), "{text}");
        }

        let store = FileSecretStore::host(dir.path().join("host-secrets.toml"));
        let store: Arc<dyn SecretStore> = Arc::new(store);
        store
            .set("ntfy-token", SecretValue::new("sup3r_s3cr3t"))
            .unwrap();
        let src = StoreCredential::new(store.clone(), "ntfy-token");
        assert_eq!(
            format!("{src:?}"),
            "StoreCredential { name: \"ntfy-token\" }"
        );
        assert!(!format!("{src:?}").contains("sup3r_s3cr3t"));

        // A value that fails validation is named by the error but never leaked.
        store
            .set("ntfy-token", SecretValue::new("two words"))
            .unwrap();
        let err = src.read().unwrap_err();
        assert!(!format!("{err}").contains("two words"));
        assert!(!format!("{err:?}").contains("two words"));
    }
}
