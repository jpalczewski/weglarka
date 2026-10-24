//! The `X-Registry-Auth` header of `POST /images/pull`: base64url of the JSON credentials.
//! The value is marked sensitive, so hyper's `Debug` output never shows it.

use hyper::header::{HeaderName, HeaderValue};
use serde::Serialize;
use weglarka_core::podman::{PodmanError, RegistryAuth, Result};

const HEADER: &str = "x-registry-auth";

/// libpod accepts the Docker `AuthConfig` shape; unknown fields are ignored on its side.
#[derive(Serialize)]
struct AuthConfig<'a> {
    username: &'a str,
    password: &'a str,
    serveraddress: &'a str,
}

/// Registry host of an image reference: the first path component when it looks like a host
/// (`.`, `:` or `localhost`), Docker Hub otherwise — the same rule as the reference parser.
pub(crate) fn registry_host(reference: &str) -> &str {
    match reference.split_once('/') {
        Some((first, _)) if first.contains(['.', ':']) || first == "localhost" => first,
        _ => "docker.io",
    }
}

pub(crate) fn header(reference: &str, auth: &RegistryAuth) -> Result<(HeaderName, HeaderValue)> {
    let json = serde_json::to_vec(&AuthConfig {
        username: auth.username(),
        password: auth.password(),
        serveraddress: registry_host(reference),
    })
    // The error text of a failed serialization of this struct carries no values; keep it generic anyway.
    .map_err(|_| PodmanError::Protocol("encoding registry credentials".into()))?;
    let mut value = HeaderValue::from_str(&base64url(&json))
        .map_err(|_| PodmanError::Protocol("encoding registry credentials".into()))?;
    value.set_sensitive(true);
    Ok((HeaderName::from_static(HEADER), value))
}

/// Base64 with the URL-safe alphabet (`-_`), padded — what Docker/Podman clients send.
fn base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(plain.as_bytes()), encoded);
        }
        // URL-safe alphabet: 0xfb 0xff → "-_8=" (the standard one gives "+/8=").
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8=");
    }

    #[test]
    fn registry_host_follows_the_reference_rules() {
        assert_eq!(registry_host("ghcr.io/x/y:latest"), "ghcr.io");
        assert_eq!(registry_host("localhost:5000/y"), "localhost:5000");
        assert_eq!(registry_host("localhost/y"), "localhost");
        assert_eq!(registry_host("library/nginx"), "docker.io");
        assert_eq!(registry_host("nginx"), "docker.io");
    }

    #[test]
    fn header_is_sensitive_and_decodes_to_the_credentials() {
        let auth = RegistryAuth::new("ci", "p:ss");
        let (name, value) = header("ghcr.io/x/y", &auth).unwrap();
        assert_eq!(name, "x-registry-auth");
        assert!(value.is_sensitive());
        assert_eq!(format!("{value:?}"), "Sensitive");
        let expected =
            base64url(br#"{"username":"ci","password":"p:ss","serveraddress":"ghcr.io"}"#);
        assert_eq!(value.to_str().unwrap(), expected);
    }
}
