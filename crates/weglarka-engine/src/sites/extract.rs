//! Static-site release extraction (docs/decisions/0049, #102).
//!
//! Takes the exported image of a site (the output of libpod `images/{name}/get`), finds its single layer and
//! unpacks it into a fresh release directory. The archive is untrusted, so extraction fails closed: every
//! entry is validated and written by this module (never by `tar`'s own unpacking), and on any error the
//! release directory is removed again.
//!
//! All I/O is blocking `std`; callers run it under `spawn_blocking`.

use std::cell::Cell;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use flate2::read::GzDecoder;
use serde::Deserialize;
use tar::EntryType;

/// Largest JSON document (index, manifest) read while locating the layer.
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
/// Slack per entry on top of `max_bytes` for the decompression cap: tar headers, padding, long-name records.
const PER_ENTRY_OVERHEAD: u64 = 8 * 1024;
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

/// Limits enforced while streaming the layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractLimits {
    /// Maximum number of created files and directories (explicit and implicit).
    pub max_files: u64,
    /// Maximum total size of file contents, counted from the bytes actually read.
    pub max_bytes: u64,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// What a successful extraction produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractReport {
    /// Regular files written.
    pub files: u64,
    /// Total bytes of file contents written.
    pub bytes: u64,
}

/// Why a release could not be extracted. Entry paths are attacker-controlled, so they are shown escaped.
#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    #[error("the image must have exactly one layer, found {0}")]
    LayerCount(usize),
    #[error("absolute path in archive: {0:?}")]
    AbsolutePath(String),
    #[error("`..` component in archive path: {0:?}")]
    ParentComponent(String),
    #[error("invalid archive path (NUL, empty or not valid UTF-8): {0:?}")]
    InvalidPath(String),
    #[error("symlink or hard link in archive: {0:?}")]
    Link(String),
    #[error("device, FIFO, socket or other special entry in archive: {0:?}")]
    SpecialEntry(String),
    #[error("whiteout entry in archive: {0:?}")]
    Whiteout(String),
    #[error("archive entry passes through a non-directory: {0:?}")]
    PathThroughNonDirectory(String),
    #[error("archive entry collides with an entry of a different type: {0:?}")]
    TypeCollision(String),
    #[error("duplicate file entry in archive: {0:?}")]
    DuplicateEntry(String),
    #[error("more than {limit} files and directories")]
    TooManyFiles { limit: u64 },
    #[error("more than {limit} bytes of content")]
    TooManyBytes { limit: u64 },
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid image archive: {0}")]
    Archive(String),
}

/// Extract the single layer of the exported image in `archive` into the new directory `dest`.
///
/// `archive` is either an `oci-archive` (`index.json` -> manifest blob -> `layers[0]` blob) or a
/// `docker-archive` (`manifest.json` -> `Layers[0]`); the layer may be gzip or plain tar. `dest` must not
/// exist yet; it is created with mode 0755 and removed again on any error. Files are written 0644 and
/// directories 0755 whatever the archive says; ownership and times are ignored.
pub fn extract_release(
    archive: &Path,
    dest: &Path,
    limits: &ExtractLimits,
) -> Result<ExtractReport, SiteError> {
    // Resolve the layer first: a bad archive must not touch the filesystem at all.
    let layer = locate_layer(archive)?;
    // Not `create_dir_all`: an existing `dest` is an error and is not ours to remove.
    fs::create_dir(dest).map_err(|source| io_err(dest, source))?;
    let result = (|| {
        set_mode(dest, DIR_MODE)?;
        with_entry(archive, &layer, |reader| {
            extract_layer(reader, dest, limits)
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(dest);
    }
    result
}

fn io_err(path: &Path, source: io::Error) -> SiteError {
    SiteError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn archive_err(e: impl std::fmt::Display) -> SiteError {
    SiteError::Archive(e.to_string())
}

fn set_mode(path: &Path, mode: u32) -> Result<(), SiteError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| io_err(path, e))
}

// ---------------------------------------------------------------------------------------------------------
// Locating the layer inside the exported image
// ---------------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(default)]
struct OciIndex {
    manifests: Vec<OciDescriptor>,
    layers: Option<Vec<OciDescriptor>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OciDescriptor {
    digest: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DockerManifestEntry {
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

/// Normalised name of the layer entry inside the outer archive.
fn locate_layer(archive: &Path) -> Result<String, SiteError> {
    if let Some(index) = read_small(archive, "index.json")? {
        let mut doc: OciIndex = serde_json::from_slice(&index).map_err(archive_err)?;
        // `index.json` -> (nested index)* -> manifest. Depth is bounded so a loop cannot spin.
        for _ in 0..4 {
            if doc.layers.is_some() {
                return oci_layer(&doc);
            }
            let first = doc
                .manifests
                .first()
                .ok_or_else(|| archive_err("index lists no manifest"))?;
            let name = blob_name(&first.digest)?;
            let bytes = read_small(archive, &name)?
                .ok_or_else(|| archive_err(format!("manifest blob {name} is missing")))?;
            doc = serde_json::from_slice(&bytes).map_err(archive_err)?;
        }
        return oci_layer(&doc);
    }
    if let Some(manifest) = read_small(archive, "manifest.json")? {
        let images: Vec<DockerManifestEntry> =
            serde_json::from_slice(&manifest).map_err(archive_err)?;
        let [image] = images.as_slice() else {
            return Err(archive_err(format!(
                "expected one image in manifest.json, found {}",
                images.len()
            )));
        };
        let [layer] = image.layers.as_slice() else {
            return Err(SiteError::LayerCount(image.layers.len()));
        };
        return normalize_name(layer);
    }
    Err(archive_err("neither index.json nor manifest.json found"))
}

fn oci_layer(manifest: &OciIndex) -> Result<String, SiteError> {
    match manifest.layers.as_deref().unwrap_or_default() {
        [layer] => blob_name(&layer.digest),
        other => Err(SiteError::LayerCount(other.len())),
    }
}

/// `sha256:<hex>` -> `blobs/sha256/<hex>`.
fn blob_name(digest: &str) -> Result<String, SiteError> {
    match digest.split_once(':') {
        Some((algo, hex))
            if !algo.is_empty()
                && !hex.is_empty()
                && algo.bytes().all(|b| b.is_ascii_alphanumeric())
                && hex.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            Ok(format!("blobs/{algo}/{hex}"))
        }
        _ => Err(archive_err(format!("malformed digest {digest:?}"))),
    }
}

/// Compare outer-archive names modulo `./`, `//` and trailing `/`.
fn normalize_name(name: &str) -> Result<String, SiteError> {
    let parts: Vec<&str> = name
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if parts.is_empty() || parts.contains(&"..") {
        return Err(archive_err(format!("bad entry name {name:?}")));
    }
    Ok(parts.join("/"))
}

fn entry_key(raw: &[u8]) -> Option<String> {
    normalize_name(std::str::from_utf8(raw).ok()?).ok()
}

/// Read the regular file `name` from the outer archive (one pass), capped at [`MAX_METADATA_BYTES`].
fn read_small(archive: &Path, name: &str) -> Result<Option<Vec<u8>>, SiteError> {
    let file = File::open(archive).map_err(|e| io_err(archive, e))?;
    let mut tar = tar::Archive::new(file);
    for entry in tar.entries().map_err(archive_err)? {
        let mut entry = entry.map_err(archive_err)?;
        if entry_key(&entry.path_bytes()).as_deref() != Some(name) {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(archive_err(format!("{name} is not a regular file")));
        }
        if entry.size() > MAX_METADATA_BYTES {
            return Err(archive_err(format!("{name} is too large")));
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(archive_err)?;
        return Ok(Some(buf));
    }
    Ok(None)
}

/// Run `f` over the contents of the regular file `name` in the outer archive.
fn with_entry<T>(
    archive: &Path,
    name: &str,
    f: impl FnOnce(&mut dyn Read) -> Result<T, SiteError>,
) -> Result<T, SiteError> {
    let file = File::open(archive).map_err(|e| io_err(archive, e))?;
    let mut tar = tar::Archive::new(file);
    for entry in tar.entries().map_err(archive_err)? {
        let mut entry = entry.map_err(archive_err)?;
        if entry_key(&entry.path_bytes()).as_deref() != Some(name) {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            return Err(archive_err(format!("layer {name} is not a regular file")));
        }
        return f(&mut entry);
    }
    Err(archive_err(format!(
        "layer {name} is missing from the archive"
    )))
}

// ---------------------------------------------------------------------------------------------------------
// Extracting the layer
// ---------------------------------------------------------------------------------------------------------

/// Caps the bytes read from the (possibly decompressed) layer; trips a flag so the caller can tell a bomb
/// from an ordinary read error.
struct CapReader<R> {
    inner: R,
    left: u64,
    tripped: Rc<Cell<bool>>,
}

impl<R: Read> Read for CapReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            // At the cap: one more byte existing means the stream is larger than allowed.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => {
                    self.tripped.set(true);
                    Err(io::Error::other("decompression cap exceeded"))
                }
            };
        }
        let max = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max])?;
        self.left -= n as u64;
        Ok(n)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
}

fn extract_layer(
    outer: &mut dyn Read,
    dest: &Path,
    limits: &ExtractLimits,
) -> Result<ExtractReport, SiteError> {
    // Sniff the compression: gzip magic -> inflate, anything else is read as a plain tar.
    let mut magic = [0u8; 2];
    let mut got = 0;
    while got < magic.len() {
        match outer.read(&mut magic[got..]).map_err(archive_err)? {
            0 => break,
            n => got += n,
        }
    }
    let head = Cursor::new(magic[..got].to_vec()).chain(outer);
    let reader: Box<dyn Read + '_> = if magic[..got] == [0x1f, 0x8b] {
        Box::new(GzDecoder::new(head))
    } else {
        Box::new(head)
    };

    let tripped = Rc::new(Cell::new(false));
    let cap = limits.max_bytes.saturating_add(
        limits
            .max_files
            .saturating_add(1)
            .saturating_mul(PER_ENTRY_OVERHEAD),
    );
    let capped = CapReader {
        inner: reader,
        left: cap,
        tripped: Rc::clone(&tripped),
    };
    let too_many_bytes = || SiteError::TooManyBytes {
        limit: limits.max_bytes,
    };
    // A failed read is a bomb if the cap tripped, otherwise a damaged archive.
    let read_err = |e: io::Error| {
        if tripped.get() {
            too_many_bytes()
        } else {
            archive_err(e)
        }
    };

    let mut tar = tar::Archive::new(capped);
    let mut seen: HashMap<String, Kind> = HashMap::new();
    let mut report = ExtractReport { files: 0, bytes: 0 };
    let mut buf = vec![0u8; 64 * 1024];

    for entry in tar.entries().map_err(read_err)? {
        let mut entry = entry.map_err(read_err)?;
        let ty = entry.header().entry_type();
        if ty == EntryType::XGlobalHeader {
            continue;
        }
        let raw = entry.path_bytes().into_owned();
        let shown = || String::from_utf8_lossy(&raw).into_owned();
        let comps = validate_path(&raw)?;

        match ty {
            EntryType::Symlink | EntryType::Link => return Err(SiteError::Link(shown())),
            EntryType::Regular | EntryType::Continuous | EntryType::Directory => {}
            _ => return Err(SiteError::SpecialEntry(shown())),
        }
        let is_dir = ty == EntryType::Directory;
        if comps.is_empty() {
            // `./` or `.`: the release directory itself.
            if is_dir {
                continue;
            }
            return Err(SiteError::InvalidPath(shown()));
        }

        // Ancestors: reuse directories we made, refuse to walk through files, create the rest.
        let mut path = dest.to_path_buf();
        let mut key = String::new();
        for (i, comp) in comps.iter().enumerate() {
            if !key.is_empty() {
                key.push('/');
            }
            key.push_str(comp);
            path.push(comp);
            let last = i + 1 == comps.len();
            match seen.get(&key) {
                Some(Kind::Dir) if !last || is_dir => continue,
                Some(Kind::Dir) => return Err(SiteError::TypeCollision(shown())),
                Some(Kind::File) if !last => {
                    return Err(SiteError::PathThroughNonDirectory(shown()));
                }
                Some(Kind::File) if is_dir => return Err(SiteError::TypeCollision(shown())),
                Some(Kind::File) => return Err(SiteError::DuplicateEntry(shown())),
                None => {}
            }
            if seen.len() as u64 >= limits.max_files {
                return Err(SiteError::TooManyFiles {
                    limit: limits.max_files,
                });
            }
            if last && !is_dir {
                let remaining = limits.max_bytes - report.bytes;
                if entry.size() > remaining {
                    return Err(too_many_bytes());
                }
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(FILE_MODE)
                    .open(&path)
                    .map_err(|e| io_err(&path, e))?;
                seen.insert(key.clone(), Kind::File);
                loop {
                    let n = entry.read(&mut buf).map_err(read_err)?;
                    if n == 0 {
                        break;
                    }
                    report.bytes += n as u64;
                    if report.bytes > limits.max_bytes {
                        return Err(too_many_bytes());
                    }
                    out.write_all(&buf[..n]).map_err(|e| io_err(&path, e))?;
                }
                drop(out);
                // The umask can only remove bits, but be explicit: the mode is a contract.
                set_mode(&path, FILE_MODE)?;
                report.files += 1;
            } else {
                fs::create_dir(&path).map_err(|e| io_err(&path, e))?;
                seen.insert(key.clone(), Kind::Dir);
                set_mode(&path, DIR_MODE)?;
            }
        }
    }
    Ok(report)
}

/// Validate a raw archive path and return its normalised components (`.` and empty ones dropped).
fn validate_path(raw: &[u8]) -> Result<Vec<&str>, SiteError> {
    let shown = || String::from_utf8_lossy(raw).into_owned();
    if raw.contains(&0) {
        return Err(SiteError::InvalidPath(shown()));
    }
    let text = std::str::from_utf8(raw).map_err(|_| SiteError::InvalidPath(shown()))?;
    if text.starts_with('/') {
        return Err(SiteError::AbsolutePath(shown()));
    }
    let mut comps = Vec::new();
    for comp in text.split('/') {
        match comp {
            "" | "." => {}
            ".." => return Err(SiteError::ParentComponent(shown())),
            c if c.starts_with(".wh.") => return Err(SiteError::Whiteout(shown())),
            c => comps.push(c),
        }
    }
    Ok(comps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, Header};

    /// One entry of a hand-built layer; `name` is written to the header verbatim (no `tar` path checks).
    struct Ent {
        name: Vec<u8>,
        ty: EntryType,
        data: Vec<u8>,
        link: Option<&'static str>,
        mode: u32,
    }

    fn file(name: &str, data: &[u8]) -> Ent {
        Ent {
            name: name.as_bytes().to_vec(),
            ty: EntryType::Regular,
            data: data.to_vec(),
            link: None,
            mode: 0o777,
        }
    }

    fn dir(name: &str) -> Ent {
        Ent {
            name: name.as_bytes().to_vec(),
            ty: EntryType::Directory,
            data: Vec::new(),
            link: None,
            mode: 0o700,
        }
    }

    fn special(name: &str, ty: EntryType, link: Option<&'static str>) -> Ent {
        Ent {
            name: name.as_bytes().to_vec(),
            ty,
            data: Vec::new(),
            link,
            mode: 0o644,
        }
    }

    fn layer_tar(entries: &[Ent]) -> Vec<u8> {
        let mut b = Builder::new(Vec::new());
        for e in entries {
            let mut h = Header::new_gnu();
            h.set_entry_type(e.ty);
            h.set_size(e.data.len() as u64);
            h.set_mode(e.mode);
            h.as_old_mut().name[..e.name.len()].copy_from_slice(&e.name);
            if let Some(l) = e.link {
                h.set_link_name(l).unwrap();
            }
            h.set_cksum();
            b.append(&h, e.data.as_slice()).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn outer(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut b = Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, name, data.as_slice()).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn oci(layers: &[Vec<u8>]) -> Vec<u8> {
        let descs: Vec<_> = (0..layers.len())
            .map(|i| format!(r#"{{"digest":"sha256:l{i}"}}"#))
            .collect();
        let manifest = format!(r#"{{"layers":[{}]}}"#, descs.join(","));
        let mut files = vec![
            (
                "index.json",
                br#"{"manifests":[{"digest":"sha256:m0"}]}"#.to_vec(),
            ),
            ("blobs/sha256/m0", manifest.into_bytes()),
        ];
        let names: Vec<String> = (0..layers.len())
            .map(|i| format!("blobs/sha256/l{i}"))
            .collect();
        for (n, l) in names.iter().zip(layers) {
            files.push((n.as_str(), l.clone()));
        }
        outer(&files)
    }

    fn docker(layers: &[Vec<u8>]) -> Vec<u8> {
        let names: Vec<String> = (0..layers.len())
            .map(|i| format!("id{i}/layer.tar"))
            .collect();
        let list: Vec<_> = names.iter().map(|n| format!("\"{n}\"")).collect();
        let manifest = format!(r#"[{{"Config":"c.json","Layers":[{}]}}]"#, list.join(","));
        let mut files = vec![("manifest.json", manifest.into_bytes())];
        for (n, l) in names.iter().zip(layers) {
            files.push((n.as_str(), l.clone()));
        }
        outer(&files)
    }

    struct Fixture {
        _tmp: tempfile::TempDir,
        archive: PathBuf,
        dest: PathBuf,
    }

    fn fixture(archive: &[u8]) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let archive_path = tmp.path().join("image.tar");
        fs::write(&archive_path, archive).unwrap();
        let dest = tmp.path().join("release");
        Fixture {
            archive: archive_path,
            dest,
            _tmp: tmp,
        }
    }

    fn run(layer: Vec<u8>, limits: &ExtractLimits) -> (Fixture, Result<ExtractReport, SiteError>) {
        let fx = fixture(&oci(&[layer]));
        let r = extract_release(&fx.archive, &fx.dest, limits);
        (fx, r)
    }

    fn rejected(layer: Vec<u8>) -> SiteError {
        let (fx, r) = run(layer, &ExtractLimits::default());
        assert!(!fx.dest.exists(), "dest must be removed after an error");
        r.unwrap_err()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn sample_layer() -> Vec<u8> {
        layer_tar(&[
            dir("./"),
            dir("assets/"),
            file("index.html", b"<h1>hi</h1>"),
            file("./assets/./app.js", b"1;"),
            file("deep/er/x.txt", b"x"),
        ])
    }

    fn check_happy(fx: &Fixture, r: ExtractReport) {
        assert_eq!(
            r,
            ExtractReport {
                files: 3,
                bytes: 14
            }
        );
        assert_eq!(
            fs::read(fx.dest.join("index.html")).unwrap(),
            b"<h1>hi</h1>"
        );
        assert_eq!(fs::read(fx.dest.join("assets/app.js")).unwrap(), b"1;");
        assert_eq!(fs::read(fx.dest.join("deep/er/x.txt")).unwrap(), b"x");
        assert_eq!(mode(&fx.dest), 0o755);
        assert_eq!(mode(&fx.dest.join("assets")), 0o755);
        assert_eq!(mode(&fx.dest.join("deep/er")), 0o755);
        assert_eq!(mode(&fx.dest.join("index.html")), 0o644);
        assert_eq!(mode(&fx.dest.join("assets/app.js")), 0o644);
    }

    #[test]
    fn oci_archive_gzip_and_plain_layers() {
        for layer in [gzip(&sample_layer()), sample_layer()] {
            let fx = fixture(&oci(&[layer]));
            let r = extract_release(&fx.archive, &fx.dest, &ExtractLimits::default()).unwrap();
            check_happy(&fx, r);
        }
    }

    #[test]
    fn docker_archive_gzip_and_plain_layers() {
        for layer in [gzip(&sample_layer()), sample_layer()] {
            let fx = fixture(&docker(&[layer]));
            let r = extract_release(&fx.archive, &fx.dest, &ExtractLimits::default()).unwrap();
            check_happy(&fx, r);
        }
    }

    #[test]
    fn existing_dest_is_an_error_and_is_left_alone() {
        let fx = fixture(&oci(&[sample_layer()]));
        fs::create_dir(&fx.dest).unwrap();
        fs::write(fx.dest.join("keep"), b"1").unwrap();
        let err = extract_release(&fx.archive, &fx.dest, &ExtractLimits::default()).unwrap_err();
        assert!(matches!(err, SiteError::Io { .. }), "{err}");
        assert!(fx.dest.join("keep").exists());
    }

    #[test]
    fn missing_archive_and_garbage_are_errors_without_dest() {
        let fx = fixture(b"not a tar at all");
        let err = extract_release(&fx.archive, &fx.dest, &ExtractLimits::default()).unwrap_err();
        assert!(matches!(err, SiteError::Archive(_)), "{err}");
        assert!(!fx.dest.exists());
        let err = extract_release(&fx.dest.join("nope"), &fx.dest, &ExtractLimits::default())
            .unwrap_err();
        assert!(matches!(err, SiteError::Io { .. }), "{err}");
        assert!(!fx.dest.exists());
    }

    #[test]
    fn layer_count_must_be_one() {
        for archive in [
            oci(&[sample_layer(), sample_layer()]),
            oci(&[]),
            docker(&[sample_layer(), sample_layer()]),
            docker(&[]),
        ] {
            let fx = fixture(&archive);
            let err =
                extract_release(&fx.archive, &fx.dest, &ExtractLimits::default()).unwrap_err();
            assert!(matches!(err, SiteError::LayerCount(n) if n != 1), "{err}");
            assert!(!fx.dest.exists());
        }
    }

    #[test]
    fn absolute_path_is_rejected() {
        let err = rejected(layer_tar(&[file("/etc/passwd", b"x")]));
        assert!(matches!(err, SiteError::AbsolutePath(_)), "{err}");
    }

    #[test]
    fn parent_component_is_rejected() {
        for name in ["../escape", "a/../../escape", "a/..", "./.."] {
            let err = rejected(layer_tar(&[file(name, b"x")]));
            assert!(
                matches!(err, SiteError::ParentComponent(_)),
                "{name}: {err}"
            );
        }
    }

    #[test]
    fn symlinks_and_hard_links_are_rejected() {
        let err = rejected(layer_tar(&[special("l", EntryType::Symlink, Some("/etc"))]));
        assert!(matches!(err, SiteError::Link(_)), "{err}");
        let err = rejected(layer_tar(&[
            file("a", b"x"),
            special("b", EntryType::Link, Some("a")),
        ]));
        assert!(matches!(err, SiteError::Link(_)), "{err}");
    }

    #[test]
    fn device_fifo_and_socket_entries_are_rejected() {
        for ty in [EntryType::Char, EntryType::Block, EntryType::Fifo] {
            let err = rejected(layer_tar(&[special("dev", ty, None)]));
            assert!(matches!(err, SiteError::SpecialEntry(_)), "{ty:?}: {err}");
        }
        // Sockets cannot be archived; other unknown type flags land in the same class.
        let err = rejected(layer_tar(&[special("s", EntryType::new(b'Z'), None)]));
        assert!(matches!(err, SiteError::SpecialEntry(_)), "{err}");
    }

    #[test]
    fn invalid_paths_are_rejected() {
        let mut bad = file("x", b"1");
        bad.name = vec![b'a', 0xff, 0xfe];
        let err = rejected(layer_tar(&[bad]));
        assert!(matches!(err, SiteError::InvalidPath(_)), "{err}");
        // A regular file cannot be the release root itself.
        let err = rejected(layer_tar(&[file("./", b"x")]));
        assert!(matches!(err, SiteError::InvalidPath(_)), "{err}");
        // NUL cannot survive the fixed-width name field, so check the validator directly.
        assert!(matches!(
            validate_path(b"a\0b"),
            Err(SiteError::InvalidPath(_))
        ));
        assert_eq!(validate_path(b"./a//b/./c/").unwrap(), ["a", "b", "c"]);
        assert!(validate_path(b".").unwrap().is_empty());
    }

    #[test]
    fn whiteouts_are_rejected() {
        let err = rejected(layer_tar(&[file("dir/.wh.gone", b"")]));
        assert!(matches!(err, SiteError::Whiteout(_)), "{err}");
        let err = rejected(layer_tar(&[file(".wh..wh..opq", b"")]));
        assert!(matches!(err, SiteError::Whiteout(_)), "{err}");
    }

    #[test]
    fn entry_through_a_file_is_rejected() {
        let err = rejected(layer_tar(&[file("a", b"x"), file("a/b", b"y")]));
        assert!(
            matches!(err, SiteError::PathThroughNonDirectory(_)),
            "{err}"
        );
    }

    #[test]
    fn type_collisions_and_duplicates_are_rejected() {
        let err = rejected(layer_tar(&[file("a", b"x"), dir("a/")]));
        assert!(matches!(err, SiteError::TypeCollision(_)), "{err}");
        let err = rejected(layer_tar(&[dir("a/"), file("a", b"x")]));
        assert!(matches!(err, SiteError::TypeCollision(_)), "{err}");
        let err = rejected(layer_tar(&[file("a/b", b"x"), file("a", b"x")]));
        assert!(matches!(err, SiteError::TypeCollision(_)), "{err}");
        let err = rejected(layer_tar(&[file("a", b"x"), file("a", b"y")]));
        assert!(matches!(err, SiteError::DuplicateEntry(_)), "{err}");
        // Repeating a directory is harmless.
        let (_fx, r) = run(
            layer_tar(&[dir("a/"), dir("a/"), file("a/f", b"1")]),
            &ExtractLimits::default(),
        );
        assert_eq!(r.unwrap().files, 1);
    }

    #[test]
    fn file_count_limit_is_enforced() {
        let limits = ExtractLimits {
            max_files: 3,
            max_bytes: 1000,
        };
        let layer = layer_tar(&[
            file("a", b""),
            file("b", b""),
            file("c", b""),
            file("d", b""),
        ]);
        let (fx, r) = run(layer, &limits);
        assert!(
            matches!(r, Err(SiteError::TooManyFiles { limit: 3 })),
            "{r:?}"
        );
        assert!(!fx.dest.exists());
        // Implicit parent directories count too.
        let (fx, r) = run(layer_tar(&[file("a/b/c/d", b"")]), &limits);
        assert!(matches!(r, Err(SiteError::TooManyFiles { .. })), "{r:?}");
        assert!(!fx.dest.exists());
        // Exactly at the limit is fine.
        let (_fx, r) = run(
            layer_tar(&[file("a", b""), file("b", b""), file("c", b"")]),
            &limits,
        );
        assert_eq!(r.unwrap().files, 3);
    }

    #[test]
    fn byte_limit_is_enforced_on_declared_and_total_size() {
        let limits = ExtractLimits {
            max_files: 10,
            max_bytes: 10,
        };
        // One entry declaring more than the limit.
        let (fx, r) = run(layer_tar(&[file("a", &[7u8; 11])]), &limits);
        assert!(
            matches!(r, Err(SiteError::TooManyBytes { limit: 10 })),
            "{r:?}"
        );
        assert!(!fx.dest.exists());
        // Many small entries adding up.
        let (fx, r) = run(
            layer_tar(&[file("a", &[1u8; 6]), file("b", &[1u8; 6])]),
            &limits,
        );
        assert!(matches!(r, Err(SiteError::TooManyBytes { .. })), "{r:?}");
        assert!(!fx.dest.exists());
        let (_fx, r) = run(
            layer_tar(&[file("a", &[1u8; 5]), file("b", &[1u8; 5])]),
            &limits,
        );
        assert_eq!(r.unwrap().bytes, 10);
    }

    #[test]
    fn decompression_bomb_trips_the_cap() {
        // Inflates far beyond `max_bytes` plus the per-entry slack, long before the end of the stream.
        let limits = ExtractLimits {
            max_files: 2,
            max_bytes: 1000,
        };
        let big = layer_tar(&[file("a", &vec![0u8; 4 * 1024 * 1024])]);
        let gz = gzip(&big);
        assert!(gz.len() < 100 * 1024, "the bomb must compress well");
        let (fx, r) = run(gz, &limits);
        assert!(
            matches!(r, Err(SiteError::TooManyBytes { limit: 1000 })),
            "{r:?}"
        );
        assert!(!fx.dest.exists());
    }
}
