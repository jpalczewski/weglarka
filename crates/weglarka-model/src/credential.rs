//! Header credentials read from a private file: the one place that decides what may become an
//! `Authorization` header. Values never reach logs, `Debug` or an error message.

use std::path::Path;

use crate::fsutil::{PrivateFileError, check_private};
use crate::secret_store::SecretValue;

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
}
