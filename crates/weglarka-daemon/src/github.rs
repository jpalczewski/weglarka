//! GitHub adapter behind the `WebhookSource` trait: HMAC-SHA256 (`X-Hub-Signature-256`, constant time)
//! and normalization of `registry_package`/`package` events to `{image_ref}`.
//! The choice of event will be confirmed on a real push (docs/decisions/0004).

use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use weglarka_model::podman::image_repo;
use weglarka_model::webhook::{
    WebhookError, WebhookEvent, WebhookRequest, WebhookSource, valid_ref,
};

type HmacSha256 = Hmac<Sha256>;

pub const SIGNATURE_HEADER: &str = "x-hub-signature-256";
pub const EVENT_HEADER: &str = "x-github-event";
pub const DELIVERY_HEADER: &str = "x-github-delivery";

#[derive(Debug, Default, Clone, Copy)]
pub struct GitHub;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Payload {
    action: String,
    registry_package: Option<Package>,
    package: Option<Package>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Package {
    name: String,
    namespace: String,
    package_type: String,
    package_version: PackageVersion,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PackageVersion {
    package_url: String,
    container_metadata: ContainerMetadata,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ContainerMetadata {
    tag: Tag,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Tag {
    name: String,
}

impl Package {
    fn image_ref(&self) -> Result<Option<String>, WebhookError> {
        if !self.package_type.is_empty() && !self.package_type.eq_ignore_ascii_case("container") {
            return Ok(None);
        }
        // A version without a tag (bare manifest) — it cannot be tracked by tag.
        let tag = self.package_version.container_metadata.tag.name.trim();
        if tag.is_empty() {
            return Ok(None);
        }
        let url = self.package_version.package_url.trim();
        let repo = if url.is_empty() {
            if self.name.is_empty() || self.namespace.is_empty() {
                return Err(WebhookError::BadPayload("package without name".into()));
            }
            format!("ghcr.io/{}/{}", self.namespace, self.name)
        } else {
            image_repo(url).to_owned()
        };
        let image_ref = format!("{repo}:{tag}").to_ascii_lowercase();
        if !valid_ref(&image_ref) {
            return Err(WebhookError::BadPayload("invalid image reference".into()));
        }
        Ok(Some(image_ref))
    }
}

impl WebhookSource for GitHub {
    fn name(&self) -> &'static str {
        "github"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[SIGNATURE_HEADER, EVENT_HEADER, DELIVERY_HEADER]
    }

    fn delivery_header(&self) -> &'static str {
        DELIVERY_HEADER
    }

    fn verify(&self, request: &WebhookRequest, secret: &[u8]) -> Result<(), WebhookError> {
        let header = request
            .header(SIGNATURE_HEADER)
            .ok_or(WebhookError::BadSignature)?;
        let hex_sig = header
            .strip_prefix("sha256=")
            .ok_or(WebhookError::BadSignature)?;
        let sig = hex::decode(hex_sig).map_err(|_| WebhookError::BadSignature)?;
        let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WebhookError::BadSignature)?;
        mac.update(&request.body);
        // `verify_slice` compares in constant time.
        mac.verify_slice(&sig)
            .map_err(|_| WebhookError::BadSignature)
    }

    fn normalize(&self, request: &WebhookRequest) -> Result<Option<WebhookEvent>, WebhookError> {
        match request.header(EVENT_HEADER) {
            Some("registry_package" | "package") => {}
            _ => return Ok(None),
        }
        let payload: Payload = serde_json::from_slice(&request.body)
            .map_err(|e| WebhookError::BadPayload(e.to_string()))?;
        if payload.action != "published" {
            return Ok(None);
        }
        let Some(package) = payload.registry_package.or(payload.package) else {
            return Err(WebhookError::BadPayload("missing package object".into()));
        };
        Ok(package.image_ref()?.map(|image_ref| WebhookEvent {
            // Only a short identifier from a safe alphabet goes into the dedup set.
            delivery_id: request
                .header(DELIVERY_HEADER)
                .filter(|v| {
                    !v.is_empty()
                        && v.len() <= 64
                        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
                .map(str::to_owned),
            image_ref,
        }))
    }
}

/// Signature in GitHub's format — for tests (and future tooling).
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(event: &str, body: &str) -> WebhookRequest {
        WebhookRequest {
            headers: vec![
                (EVENT_HEADER.into(), event.into()),
                (DELIVERY_HEADER.into(), "d-1".into()),
                (SIGNATURE_HEADER.into(), sign(b"s3cret", body.as_bytes())),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    const PUBLISHED: &str = r#"{"action":"published","registry_package":{"name":"ntfy.zig","namespace":"jpalczewski","package_type":"CONTAINER","package_version":{"package_url":"ghcr.io/jpalczewski/ntfy.zig:latest","container_metadata":{"tag":{"name":"latest"}}}}}"#;

    #[test]
    fn verifies_signature() {
        let r = req("registry_package", PUBLISHED);
        assert!(GitHub.verify(&r, b"s3cret").is_ok());
        assert!(GitHub.verify(&r, b"other").is_err());
    }

    #[test]
    fn rejects_malformed_signatures() {
        let mut r = req("registry_package", PUBLISHED);
        for bad in ["", "sha256=", "sha256=zz", "sha1=abcd", "abcd"] {
            r.headers.retain(|(k, _)| k != SIGNATURE_HEADER);
            r.headers.push((SIGNATURE_HEADER.into(), bad.into()));
            assert!(GitHub.verify(&r, b"s3cret").is_err(), "{bad:?}");
        }
        r.headers.retain(|(k, _)| k != SIGNATURE_HEADER);
        assert!(GitHub.verify(&r, b"s3cret").is_err());
    }

    #[test]
    fn normalizes_registry_package_and_package() {
        let want = Some(WebhookEvent {
            delivery_id: Some("d-1".into()),
            image_ref: "ghcr.io/jpalczewski/ntfy.zig:latest".into(),
        });
        assert_eq!(
            GitHub
                .normalize(&req("registry_package", PUBLISHED))
                .unwrap(),
            want
        );
        let pkg = PUBLISHED.replace("registry_package", "package");
        assert_eq!(GitHub.normalize(&req("package", &pkg)).unwrap(), want);
    }

    #[test]
    fn builds_ref_without_package_url() {
        let body = r#"{"action":"published","package":{"name":"Blog","namespace":"Me","package_version":{"container_metadata":{"tag":{"name":"v1"}}}}}"#;
        let e = GitHub.normalize(&req("package", body)).unwrap().unwrap();
        assert_eq!(e.image_ref, "ghcr.io/me/blog:v1");
    }

    #[test]
    fn ignores_irrelevant_events() {
        assert_eq!(GitHub.normalize(&req("ping", "{}")).unwrap(), None);
        assert_eq!(GitHub.normalize(&req("push", "{}")).unwrap(), None);
        let updated = PUBLISHED.replace("published", "updated");
        assert_eq!(
            GitHub
                .normalize(&req("registry_package", &updated))
                .unwrap(),
            None
        );
        let npm = PUBLISHED.replace("CONTAINER", "npm");
        assert_eq!(
            GitHub.normalize(&req("registry_package", &npm)).unwrap(),
            None
        );
        let untagged = PUBLISHED.replace("\"latest\"}}", "\"\"}}");
        assert_eq!(
            GitHub
                .normalize(&req("registry_package", &untagged))
                .unwrap(),
            None
        );
    }

    #[test]
    fn rejects_garbage_payload() {
        assert!(GitHub.normalize(&req("registry_package", "nope")).is_err());
        let no_pkg = r#"{"action":"published"}"#;
        assert!(GitHub.normalize(&req("registry_package", no_pkg)).is_err());
    }
}
