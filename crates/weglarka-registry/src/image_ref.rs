//! Image reference parsing: `host[:port]/path/to/repository:tag`.
//!
//! Only the subset Węglarka needs is accepted, and it is accepted strictly: the registry host is
//! mandatory (no Docker Hub shorthand), the tag is mandatory, digest references (`@sha256:…`) are
//! rejected with a message that says why, and nothing is lowercased or otherwise normalized
//! silently. A reference describes an image whose cosign signature is looked up by tag; the digest
//! comes from the pull, not from the reference.

use std::fmt;

/// Longest accepted reference. Real ones are well under 300 bytes; the cap bounds error messages
/// and the derived URLs.
const MAX_REFERENCE_LEN: usize = 1024;
/// Longest accepted tag (OCI distribution specification: 128 characters).
const MAX_TAG_LEN: usize = 128;
/// Longest accepted repository path.
const MAX_REPOSITORY_LEN: usize = 255;
/// Longest accepted host name (matches the URI/DNS limit).
const MAX_HOST_LEN: usize = 253;

/// A parsed `registry/repository:tag` image reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageRef {
    /// Registry host with an optional port, exactly as given (`ghcr.io`, `localhost:5000`).
    pub registry: String,
    /// Repository path below `/v2/` (`jpalczewski/weglarka`), lowercase as the OCI specification
    /// requires.
    pub repository: String,
    /// Tag (`edge`, `v1.2.3`).
    pub tag: String,
}

impl ImageRef {
    /// Parses `host[:port]/path/to/repository:tag`.
    ///
    /// Accepts `ghcr.io/jpalczewski/weglarka:edge`, `localhost:5000/weglarka:edge` and
    /// `127.0.0.1:5000/weglarka:edge`; rejects a bare digest reference with
    /// [`ImageRefError::DigestRef`].
    pub fn parse(image: &str) -> Result<Self, ImageRefError> {
        let invalid = || image.to_owned();
        if image.is_empty() {
            return Err(ImageRefError::Empty);
        }
        if image.len() > MAX_REFERENCE_LEN {
            return Err(ImageRefError::TooLong(invalid()));
        }
        if !image.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ImageRefError::Control(invalid()));
        }
        if image.contains("://") {
            return Err(ImageRefError::Scheme(invalid()));
        }
        // A digest reference names a manifest by digest, so it has no tag to look a signature up
        // for. Detect it before splitting, otherwise `repo@sha256:…` would look like a tag.
        if image.contains('@') {
            return Err(ImageRefError::DigestRef(invalid()));
        }
        let (registry, rest) = image
            .split_once('/')
            .ok_or_else(|| ImageRefError::MissingRegistry(invalid()))?;
        validate_registry(registry, image)?;
        let (repository, tag) = rest
            .rsplit_once(':')
            .ok_or_else(|| ImageRefError::MissingTag(invalid()))?;
        if repository.is_empty() || repository.len() > MAX_REPOSITORY_LEN {
            return Err(ImageRefError::Repository(invalid()));
        }
        if !valid_repository(repository) {
            return Err(ImageRefError::Repository(invalid()));
        }
        if tag.is_empty() || tag.len() > MAX_TAG_LEN || !valid_tag(tag) {
            return Err(ImageRefError::Tag(invalid()));
        }
        Ok(Self {
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            tag: tag.to_owned(),
        })
    }

    /// `registry/repository` — the reference without the tag, as cosign records it in the payload
    /// identity (`Docker-reference`).
    pub fn repository_reference(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}:{}", self.registry, self.repository, self.tag)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImageRefError {
    #[error("image reference is empty")]
    Empty,
    #[error("image reference {0:?} is longer than {MAX_REFERENCE_LEN} bytes")]
    TooLong(String),
    #[error("image reference {0:?} contains whitespace or control characters")]
    Control(String),
    #[error("image reference {0:?} starts with a URL scheme; pass host/repository:tag")]
    Scheme(String),
    #[error(
        "image reference {0:?} pins a digest; pass host/repository:tag, the digest comes from the pull"
    )]
    DigestRef(String),
    #[error("image reference {0:?} has no registry host; pass host[:port]/repository:tag")]
    MissingRegistry(String),
    #[error("image reference {0:?} has an invalid registry host")]
    Registry(String),
    #[error("image reference {0:?} has an invalid repository path (expected lowercase OCI path)")]
    Repository(String),
    #[error("image reference {0:?} has no tag; pass host/repository:tag")]
    MissingTag(String),
    #[error("image reference {0:?} has an invalid tag")]
    Tag(String),
}

impl ImageRefError {
    /// The offending reference, for callers that want to log or retry it.
    pub fn image(&self) -> &str {
        match self {
            Self::Empty => "",
            Self::TooLong(image)
            | Self::Control(image)
            | Self::Scheme(image)
            | Self::DigestRef(image)
            | Self::MissingRegistry(image)
            | Self::Registry(image)
            | Self::Repository(image)
            | Self::MissingTag(image)
            | Self::Tag(image) => image,
        }
    }
}

/// `host`, `host:port` or `[v6]:port`; the registry must look like a host, so a bare
/// `jpalczewski/weglarka:edge` is rejected instead of being guessed as Docker Hub.
fn validate_registry(registry: &str, image: &str) -> Result<(), ImageRefError> {
    let invalid = || ImageRefError::Registry(image.to_owned());
    if registry.is_empty() {
        return Err(invalid());
    }
    if let Some(inner) = registry.strip_prefix('[') {
        let (node, rest) = inner.split_once(']').ok_or_else(invalid)?;
        if node.is_empty()
            || !node
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        {
            return Err(invalid());
        }
        match rest {
            "" => return Ok(()),
            _ => {
                let port = rest.strip_prefix(':').ok_or_else(invalid)?;
                return validate_port(port, image);
            }
        }
    }
    let (host, port) = match registry.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (registry, None),
    };
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(invalid());
    }
    // Host names are ASCII and case-insensitive; nothing is normalized, but uppercase is legal.
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err(invalid());
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return Err(invalid());
        }
    }
    if let Some(port) = port {
        validate_port(port, image)?;
    }
    // A registry host must be distinguishable from a repository path, otherwise a Docker Hub
    // shortcut would be accepted silently.
    let looks_like_host = registry.contains(['.', ':']) || host.eq_ignore_ascii_case("localhost");
    if !looks_like_host {
        return Err(invalid());
    }
    Ok(())
}

fn validate_port(port: &str, image: &str) -> Result<(), ImageRefError> {
    let invalid = || ImageRefError::Registry(image.to_owned());
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(invalid()),
        Ok(_) => Ok(()),
    }
}

/// OCI repository path: lowercase alphanumeric components with `.`, `_` and `-` separators; each
/// component starts and ends with an alphanumeric character.
fn valid_repository(repository: &str) -> bool {
    repository.split('/').all(|component| {
        !component.is_empty()
            && component.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            && component.starts_with(|c: char| c.is_ascii_alphanumeric())
            && component.ends_with(|c: char| c.is_ascii_alphanumeric())
    })
}

/// OCI tag: alphanumeric with `.`, `_` and `-`, up to 128 characters, starting with alphanumeric
/// or `_`.
fn valid_tag(tag: &str) -> bool {
    tag.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registry_port_and_tag() {
        let image = ImageRef::parse("ghcr.io/jpalczewski/weglarka:edge").unwrap();
        assert_eq!(image.registry, "ghcr.io");
        assert_eq!(image.repository, "jpalczewski/weglarka");
        assert_eq!(image.tag, "edge");
        assert_eq!(image.repository_reference(), "ghcr.io/jpalczewski/weglarka");
        assert_eq!(image.to_string(), "ghcr.io/jpalczewski/weglarka:edge");

        let image = ImageRef::parse("localhost:5000/weglarka:v1.2.3-rc.1").unwrap();
        assert_eq!(image.registry, "localhost:5000");
        assert_eq!(image.repository, "weglarka");
        assert_eq!(image.tag, "v1.2.3-rc.1");

        let image = ImageRef::parse("127.0.0.1:5000/a/b/c:x").unwrap();
        assert_eq!(image.repository, "a/b/c");

        let image = ImageRef::parse("[::1]:5000/weglarka:x").unwrap();
        assert_eq!(image.registry, "[::1]:5000");
    }

    #[test]
    fn rejects_digests_schemes_and_missing_parts() {
        for (image, expected) in [
            ("", ImageRefError::Empty),
            (
                "ghcr.io/jpalczewski/weglarka@sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ImageRefError::DigestRef(
                    "ghcr.io/jpalczewski/weglarka@sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
                ),
            ),
            (
                "https://ghcr.io/jpalczewski/weglarka:edge",
                ImageRefError::Scheme("https://ghcr.io/jpalczewski/weglarka:edge".into()),
            ),
            (
                "jpalczewski/weglarka:edge",
                ImageRefError::Registry("jpalczewski/weglarka:edge".into()),
            ),
            (
                "ghcr.io/jpalczewski/weglarka",
                ImageRefError::MissingTag("ghcr.io/jpalczewski/weglarka".into()),
            ),
            (
                "ghcr.io/jpalczewski/weglarka:",
                ImageRefError::Tag("ghcr.io/jpalczewski/weglarka:".into()),
            ),
            (
                "ghcr.io//weglarka:edge",
                ImageRefError::Repository("ghcr.io//weglarka:edge".into()),
            ),
            (
                "ghcr.io/weglarka:v1@sha256:abcd",
                ImageRefError::DigestRef("ghcr.io/weglarka:v1@sha256:abcd".into()),
            ),
        ] {
            assert_eq!(ImageRef::parse(image).unwrap_err(), expected, "{image:?}");
        }
        // A whitespace or control character anywhere is a control error, not a parse error.
        assert_eq!(
            ImageRef::parse("ghcr.io/weglarka :edge").unwrap_err(),
            ImageRefError::Control("ghcr.io/weglarka :edge".into())
        );
    }

    #[test]
    fn rejects_uppercase_repository_and_bad_hosts_and_ports() {
        assert!(matches!(
            ImageRef::parse("ghcr.io/JPalczewski/weglarka:edge").unwrap_err(),
            ImageRefError::Repository(_)
        ));
        for image in [
            "ghcr.io:0/weglarka:edge",
            "ghcr.io:99999/weglarka:edge",
            "ghcr.io:abc/weglarka:edge",
            "ghcr..io/weglarka:edge",
            "-ghcr.io/weglarka:edge",
            "[::1/weglarka:edge",
            "[zz]:5000/weglarka:edge",
        ] {
            assert_eq!(
                ImageRef::parse(image).unwrap_err(),
                ImageRefError::Registry(image.to_owned()),
                "{image:?}"
            );
        }
        assert!(matches!(
            ImageRef::parse("ghcr.io/weglarka:-edge").unwrap_err(),
            ImageRefError::Tag(_)
        ));
        assert_eq!(
            ImageRef::parse(&format!("ghcr.io/weglarka:{}", "x".repeat(129))).unwrap_err(),
            ImageRefError::Tag(format!("ghcr.io/weglarka:{}", "x".repeat(129)))
        );
    }

    #[test]
    fn rejects_oversized_references() {
        let image = format!("ghcr.io/{}/weglarka:edge", "a".repeat(1200));
        assert_eq!(
            ImageRef::parse(&image).unwrap_err(),
            ImageRefError::TooLong(image.clone())
        );
        // A long repository below the reference cap is a repository error, not a length error.
        let image = format!("ghcr.io/{}/weglarka:edge", "a".repeat(300));
        assert!(matches!(
            ImageRef::parse(&image).unwrap_err(),
            ImageRefError::Repository(_)
        ));
        assert_eq!(ImageRefError::Empty.image(), "");
    }
}
