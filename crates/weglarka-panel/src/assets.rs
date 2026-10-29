//! Static files embedded in the binary. Serving is a lookup in a fixed table, so no request value
//! ever reaches the filesystem. Real htmx and Alpine builds are vendored here by a later change.

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

struct Asset {
    name: &'static str,
    content_type: &'static str,
    bytes: &'static [u8],
}

const ASSETS: &[Asset] = &[
    Asset {
        name: "panel.css",
        content_type: "text/css; charset=utf-8",
        bytes: include_bytes!("../assets/panel.css"),
    },
    Asset {
        name: "favicon.svg",
        content_type: "image/svg+xml",
        bytes: include_bytes!("../assets/favicon.svg"),
    },
];

/// Files are not content-hashed yet, so they are revalidated rather than cached for long.
const CACHE_CONTROL: &str = "public, no-cache";

/// `GET /static/{file}`.
pub async fn serve(Path(file): Path<String>) -> Response {
    match ASSETS.iter().find(|a| a.name == file) {
        Some(asset) => (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(asset.content_type),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(CACHE_CONTROL),
                ),
            ],
            asset.bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
