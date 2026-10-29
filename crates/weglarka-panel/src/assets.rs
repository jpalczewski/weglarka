//! Static files embedded in the binary. Serving is a lookup in a fixed table, so no request value
//! ever reaches the filesystem. The vendored libraries (htmx, its SSE extension, Alpine's CSP build)
//! carry their version in the file name and are recorded with their SHA-256 in
//! `assets/vendor/VENDORED.md`; a unit test checks the table against that file.

use axum::extract::Path;
use std::sync::OnceLock;

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ring::digest::{SHA256, digest};

struct Asset {
    name: &'static str,
    content_type: &'static str,
    bytes: &'static [u8],
    /// Vendored files are named after their version, so they never change under a name.
    immutable: bool,
}

const JS: &str = "text/javascript; charset=utf-8";

const ASSETS: &[Asset] = &[
    Asset {
        name: "app.css",
        content_type: "text/css; charset=utf-8",
        bytes: include_bytes!("../assets/app.css"),
        immutable: false,
    },
    Asset {
        name: "favicon.svg",
        content_type: "image/svg+xml",
        bytes: include_bytes!("../assets/favicon.svg"),
        immutable: false,
    },
    Asset {
        name: "htmx-2.0.11.min.js",
        content_type: JS,
        bytes: include_bytes!("../assets/vendor/htmx-2.0.11.min.js"),
        immutable: true,
    },
    Asset {
        name: "htmx-ext-sse-2.2.4.min.js",
        content_type: JS,
        bytes: include_bytes!("../assets/vendor/htmx-ext-sse-2.2.4.min.js"),
        immutable: true,
    },
    Asset {
        name: "alpine-csp-3.17.4.min.js",
        content_type: JS,
        bytes: include_bytes!("../assets/vendor/alpine-csp-3.17.4.min.js"),
        immutable: true,
    },
    // The panel's own script: tiny, behind Alpine's CSP build (no inline handlers anywhere).
    Asset {
        name: "app.js",
        content_type: JS,
        bytes: include_bytes!("../assets/app.js"),
        immutable: false,
    },
];

/// The panel's own files are revalidated; versioned vendor files are cached for a year.
const REVALIDATE: &str = "public, no-cache";
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// Strong validators: the SHA-256 of each embedded file, computed once. The panel's own files are
/// revalidated with them (`If-None-Match` → 304); the versioned vendor files are also immutable.
fn etags() -> &'static [String] {
    static ETAGS: OnceLock<Vec<String>> = OnceLock::new();
    ETAGS.get_or_init(|| {
        ASSETS
            .iter()
            .map(|a| {
                let hash = digest(&SHA256, a.bytes);
                let hex: String = hash
                    .as_ref()
                    .iter()
                    .take(16)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                format!("\"{hex}\"")
            })
            .collect()
    })
}

/// `GET /static/{file}`.
pub async fn serve(Path(file): Path<String>, headers: HeaderMap) -> Response {
    let Some(index) = ASSETS.iter().position(|a| a.name == file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let asset = &ASSETS[index];
    let etag = &etags()[index];
    let cache = HeaderValue::from_static(if asset.immutable {
        IMMUTABLE
    } else {
        REVALIDATE
    });
    let etag_value = HeaderValue::from_str(etag).expect("hex digits and quotes");
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().trim_start_matches("W/") == etag)
        });
    if unchanged {
        return (
            StatusCode::NOT_MODIFIED,
            [(header::CACHE_CONTROL, cache), (header::ETAG, etag_value)],
        )
            .into_response();
    }
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(asset.content_type),
            ),
            (header::CACHE_CONTROL, cache),
            (header::ETAG, etag_value),
        ],
        asset.bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        digest(&SHA256, bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Every immutable (vendored) asset is listed in `VENDORED.md` with the hash of the bytes we
    /// embed, and every row of that file names an embedded asset.
    #[test]
    fn vendored_files_match_the_recorded_hashes() {
        let record = include_str!("../assets/vendor/VENDORED.md");
        let mut rows = 0;
        for line in record.lines().filter(|l| l.starts_with("| `")) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let name = cells[1].trim_matches('`');
            let hash = cells
                .iter()
                .find(|c| c.len() == 64 && c.chars().all(|ch| ch.is_ascii_hexdigit()));
            let asset = ASSETS
                .iter()
                .find(|a| a.name == name)
                .unwrap_or_else(|| panic!("{name} is recorded but not embedded"));
            assert!(asset.immutable, "{name}");
            assert_eq!(Some(&sha256_hex(asset.bytes).as_str()), hash, "{name}");
            rows += 1;
        }
        let vendored = ASSETS.iter().filter(|a| a.immutable).count();
        assert_eq!(rows, vendored, "VENDORED.md must list every vendored asset");
    }
}
