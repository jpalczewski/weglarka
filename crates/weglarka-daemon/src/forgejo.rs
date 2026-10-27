//! Forgejo adapter behind the `WebhookSource` trait: HMAC-SHA256 (`X-Forgejo-Signature`, hex,
//! constant time) and normalization of `package` events (`action == "created"`) to `{image_ref}`.
//! The registry host comes from `[webhook.forgejo]`, never from the payload (docs/decisions/0025).

use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use weglarka_model::config::ForgejoWebhookConfig;
use weglarka_model::webhook::{
    WebhookError, WebhookEvent, WebhookRequest, WebhookSource, valid_ref,
};

type HmacSha256 = Hmac<Sha256>;

pub const SIGNATURE_HEADER: &str = "x-forgejo-signature";
/// Forgejo 16 puts the event name here for package events and leaves `X-Forgejo-Event` empty.
pub const EVENT_TYPE_HEADER: &str = "x-forgejo-event-type";
pub const EVENT_HEADER: &str = "x-forgejo-event";
pub const DELIVERY_HEADER: &str = "x-forgejo-delivery";

#[derive(Debug, Clone)]
pub struct Forgejo {
    /// Lower-case `host[:port]` of the registry the images are pulled from.
    registry: String,
}

impl Forgejo {
    pub fn new(config: &ForgejoWebhookConfig) -> Result<Self, String> {
        Ok(Self {
            registry: config.registry_host()?,
        })
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Payload {
    action: String,
    package: Option<Package>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Package {
    name: String,
    #[serde(rename = "type")]
    package_type: String,
    /// For container packages the version is the tag (untagged manifests show up as `sha256:…`).
    version: String,
    owner: Owner,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Owner {
    login: String,
}

impl Forgejo {
    fn image_ref(&self, package: &Package) -> Result<Option<String>, WebhookError> {
        if !package.package_type.eq_ignore_ascii_case("container") {
            return Ok(None);
        }
        // A bare manifest has no tag and cannot be tracked by tag.
        let tag = package.version.trim();
        if tag.is_empty() || tag.starts_with("sha256:") {
            return Ok(None);
        }
        let (owner, name) = (package.owner.login.trim(), package.name.trim());
        if owner.is_empty() || name.is_empty() {
            return Err(WebhookError::BadPayload(
                "package without owner or name".into(),
            ));
        }
        let image_ref = format!("{}/{owner}/{name}:{tag}", self.registry).to_ascii_lowercase();
        if !valid_ref(&image_ref) {
            return Err(WebhookError::BadPayload("invalid image reference".into()));
        }
        Ok(Some(image_ref))
    }
}

impl WebhookSource for Forgejo {
    fn name(&self) -> &'static str {
        "forgejo"
    }

    fn headers(&self) -> &'static [&'static str] {
        &[
            SIGNATURE_HEADER,
            EVENT_TYPE_HEADER,
            EVENT_HEADER,
            DELIVERY_HEADER,
        ]
    }

    fn delivery_header(&self) -> &'static str {
        DELIVERY_HEADER
    }

    fn verify(&self, request: &WebhookRequest, secret: &[u8]) -> Result<(), WebhookError> {
        let header = request
            .header(SIGNATURE_HEADER)
            .ok_or(WebhookError::BadSignature)?;
        // Plain hex, without GitHub's `sha256=` prefix.
        let sig = hex::decode(header.trim()).map_err(|_| WebhookError::BadSignature)?;
        let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WebhookError::BadSignature)?;
        mac.update(&request.body);
        // `verify_slice` compares in constant time.
        mac.verify_slice(&sig)
            .map_err(|_| WebhookError::BadSignature)
    }

    fn normalize(&self, request: &WebhookRequest) -> Result<Option<WebhookEvent>, WebhookError> {
        // `X-Forgejo-Event` may be present but empty, so an empty value falls through to the other one.
        let event = [EVENT_TYPE_HEADER, EVENT_HEADER]
            .into_iter()
            .filter_map(|h| request.header(h))
            .find(|v| !v.is_empty());
        if event != Some("package") {
            return Ok(None);
        }
        let payload: Payload = serde_json::from_slice(&request.body)
            .map_err(|e| WebhookError::BadPayload(e.to_string()))?;
        if payload.action != "created" {
            return Ok(None);
        }
        let Some(package) = payload.package else {
            return Err(WebhookError::BadPayload("missing package object".into()));
        };
        Ok(self.image_ref(&package)?.map(|image_ref| WebhookEvent {
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

/// Signature in Forgejo's format — for tests (and future tooling).
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> Forgejo {
        Forgejo::new(&ForgejoWebhookConfig {
            registry: "Git.Example.eu".into(),
        })
        .unwrap()
    }

    fn req(event: &str, body: &str) -> WebhookRequest {
        WebhookRequest {
            headers: vec![
                (EVENT_HEADER.into(), event.into()),
                (
                    DELIVERY_HEADER.into(),
                    "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".into(),
                ),
                (SIGNATURE_HEADER.into(), sign(b"s3cret", body.as_bytes())),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    // Trimmed from a real Forgejo 16 delivery (org-level package, so `repository` is null; ADR 0025).
    const CREATED: &str = r#"{"action":"created","package":{"id":7,"owner":{"login":"Acme"},"type":"container","name":"Shop","version":"main"},"repository":null,"sender":{"login":"ci"}}"#;

    #[test]
    fn verifies_signature() {
        let r = req("package", CREATED);
        assert!(adapter().verify(&r, b"s3cret").is_ok());
        assert!(adapter().verify(&r, b"other").is_err());
    }

    #[test]
    fn rejects_malformed_signatures() {
        let mut r = req("package", CREATED);
        for bad in ["", "zz", "sha256=abcd", "abcd"] {
            r.headers.retain(|(k, _)| k != SIGNATURE_HEADER);
            r.headers.push((SIGNATURE_HEADER.into(), bad.into()));
            assert!(adapter().verify(&r, b"s3cret").is_err(), "{bad:?}");
        }
        r.headers.retain(|(k, _)| k != SIGNATURE_HEADER);
        assert!(adapter().verify(&r, b"s3cret").is_err());
    }

    #[test]
    fn normalizes_created_with_the_registry_from_config() {
        let e = adapter()
            .normalize(&req("package", CREATED))
            .unwrap()
            .unwrap();
        assert_eq!(e.image_ref, "git.example.eu/acme/shop:main");
        assert_eq!(
            e.delivery_id.as_deref(),
            Some("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed")
        );
    }

    #[test]
    fn reads_the_event_name_from_event_type_when_event_is_empty() {
        // As sent by Forgejo 16: `X-Forgejo-Event` empty, `X-Forgejo-Event-Type: package`.
        let mut r = req("", CREATED);
        r.headers.push((EVENT_TYPE_HEADER.into(), "package".into()));
        let e = adapter().normalize(&r).unwrap().unwrap();
        assert_eq!(e.image_ref, "git.example.eu/acme/shop:main");

        // The empty legacy header alone is still "not a package event".
        assert_eq!(adapter().normalize(&req("", CREATED)).unwrap(), None);

        // A non-package `-Type` is not rescued by a `package` in the legacy header.
        let mut r = req("package", CREATED);
        r.headers.push((EVENT_TYPE_HEADER.into(), "push".into()));
        assert_eq!(adapter().normalize(&r).unwrap(), None);
    }

    #[test]
    fn a_registry_host_in_the_payload_is_ignored() {
        let body = CREATED.replace(
            r#""version":"main""#,
            r#""version":"main","html_url":"https://evil.example/acme/-/packages/container/shop/main","registry":"evil.example""#,
        );
        let e = adapter()
            .normalize(&req("package", &body))
            .unwrap()
            .unwrap();
        assert_eq!(e.image_ref, "git.example.eu/acme/shop:main");
    }

    #[test]
    fn ignores_irrelevant_events() {
        let a = adapter();
        assert_eq!(a.normalize(&req("push", "{}")).unwrap(), None);
        assert_eq!(a.normalize(&req("ping", "{}")).unwrap(), None);
        let deleted = CREATED.replace("created", "deleted");
        assert_eq!(a.normalize(&req("package", &deleted)).unwrap(), None);
        let npm = CREATED.replace("container", "npm");
        assert_eq!(a.normalize(&req("package", &npm)).unwrap(), None);
        let untagged = CREATED.replace(r#""main""#, r#""sha256:0123abcd""#);
        assert_eq!(a.normalize(&req("package", &untagged)).unwrap(), None);
        let empty = CREATED.replace(r#""main""#, r#""""#);
        assert_eq!(a.normalize(&req("package", &empty)).unwrap(), None);
    }

    #[test]
    fn rejects_garbage_payload() {
        let a = adapter();
        assert!(a.normalize(&req("package", "nope")).is_err());
        assert!(
            a.normalize(&req("package", r#"{"action":"created"}"#))
                .is_err()
        );
        let no_owner = CREATED.replace(r#""owner":{"login":"Acme"},"#, "");
        assert!(a.normalize(&req("package", &no_owner)).is_err());
        let spaced = CREATED.replace("shop:main", "x").replace("Shop", "a b");
        assert!(a.normalize(&req("package", &spaced)).is_err());
    }
}
