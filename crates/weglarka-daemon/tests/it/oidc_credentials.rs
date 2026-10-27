//! Reserved OIDC credential secrets (#213): `secrets set`/`remove` refuse them, `--purge-secrets`
//! still clears the whole scope (ADR 0024).

use crate::common::*;

use hyper::StatusCode;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

/// What `weglarka oidc rotate` will write later (P4); seeded by hand because no API path may.
fn seed_pair(h: &Harness, app: &str) {
    let path = h.root.join("state/secrets.toml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let entry = |n: &str| {
        format!("[secrets.\"{app}.{n}\"]\nvalue = \"x\"\nupdated_at = \"2026-10-27T00:00:00Z\"\n")
    };
    let text = format!(
        "{}{}",
        entry("oidc-client-secret"),
        entry("oidc-client-digest")
    );
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn store(h: &Harness) -> String {
    read(&h.root.join("state/secrets.toml"))
}

#[tokio::test]
async fn set_and_remove_of_reserved_names_are_refused() {
    let h = harness().await;
    add(&h, "blog", spec("blog.example.eu")).await;
    seed_pair(&h, "blog");
    for name in ["oidc-client-secret", "oidc-client-digest"] {
        let (s, v) = admin(
            &h,
            "PUT",
            &format!("/v1/apps/blog/secrets/{name}"),
            Some(json!({"value": "v"})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or_default()
                .contains("oidc rotate"),
            "{v}"
        );
        for query in ["", "?force=true"] {
            let (s, v) = admin(
                &h,
                "DELETE",
                &format!("/v1/apps/blog/secrets/{name}{query}"),
                None,
            )
            .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
            assert!(
                v["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("oidc rotate"),
                "{v}"
            );
        }
    }
    let kept = store(&h);
    assert!(kept.contains("blog.oidc-client-secret") && kept.contains("blog.oidc-client-digest"));
    // `secrets list` still shows them (metadata only).
    let (_, list) = admin(&h, "GET", "/v1/apps/blog/secrets", None).await;
    assert_eq!(list["secrets"].as_array().map(Vec::len), Some(2), "{list}");
    h.running.stop().await;
}

#[tokio::test]
async fn purge_secrets_removes_both_reserved_names() {
    let h = harness().await;
    add(&h, "blog", spec("blog.example.eu")).await;
    seed_pair(&h, "blog");
    let (s, v) = admin(&h, "DELETE", "/v1/apps/blog?purge_secrets=true", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert!(!store(&h).contains("blog."), "{}", store(&h));
    h.running.stop().await;
}
