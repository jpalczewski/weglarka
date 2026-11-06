//! Small filesystem helpers shared by every state file (and by crates that write their own files).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Why a file is not private to its owner.
#[derive(Debug, thiserror::Error)]
pub enum PrivateFileError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// The permission bits (`& 0o777`); no path, so the caller adds its own context.
    #[error("mode {mode:o}, expected 600")]
    TooOpen { mode: u32 },
}

/// Rejects a file whose group or other bits are set (`chmod 600`). A missing file is an `Io`
/// error here: callers that tolerate it (`secrets.toml` is created on first write) check for
/// `NotFound` themselves.
pub fn check_private(path: &Path) -> Result<(), PrivateFileError> {
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(PrivateFileError::TooOpen { mode: mode & 0o777 });
    }
    Ok(())
}

/// Atomic write: tmp in the same directory (created with `mode`) → `fsync` → `rename` → directory `fsync`.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), io::Error> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    let result = (|| {
        // `create_new` + always a fresh file: tmp never inherits foreign permissions/contents.
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_leaves_no_tmp_and_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.toml");
        write_atomic(&path, b"one", 0o600).unwrap();
        write_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn check_private_accepts_0600_and_rejects_lower_bits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_atomic(&path, b"v", 0o600).unwrap();
        check_private(&path).unwrap();

        for mode in [0o644, 0o640, 0o604, 0o666, 0o400 | 0o001] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            match check_private(&path) {
                Err(PrivateFileError::TooOpen { mode: got }) => assert_eq!(got, mode),
                other => panic!("{mode:o}: {other:?}"),
            }
        }
    }

    #[test]
    fn check_private_reports_a_missing_file_as_io() {
        let dir = tempfile::tempdir().unwrap();
        match check_private(&dir.path().join("nope")) {
            Err(PrivateFileError::Io(e)) => {
                assert_eq!(e.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn check_private_messages_carry_no_path() {
        let err = PrivateFileError::TooOpen { mode: 0o644 };
        assert_eq!(err.to_string(), "mode 644, expected 600");
    }
}
