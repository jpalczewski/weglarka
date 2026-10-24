//! Forgejo webhook flow on `FakePodman`: `/webhook/forgejo/{instance}` over TCP.

mod common;

use common::*;
use std::net::SocketAddr;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use serde_json::json;
use tokio::net::TcpStream;
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::forgejo::{
    DELIVERY_HEADER, EVENT_HEADER, EVENT_TYPE_HEADER, SIGNATURE_HEADER, sign,
};

const SECRET: &str = "hunter2-webhook";
const IMAGE: &str = "git.example.eu/acme/shop:main";

async fn harness(forgejo: bool) -> Harness {
    let sections = if forgejo {
        "\n[webhook.forgejo]\nregistry = \"git.example.eu\"\n"
    } else {
        ""
    };
    Builder::new().sections(sections).build().await
}

async fn hook(
    addr: SocketAddr,
    source: &str,
    instance: &str,
    event: &str,
    delivery: &str,
    body: &[u8],
    signature: Option<String>,
) -> StatusCode {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/webhook/{source}/{instance}"))
        .header("host", "hooks.example.eu")
        // As Forgejo 16 sends it: the legacy header empty, the name in `-Type`.
        .header(EVENT_HEADER, "")
        .header(EVENT_TYPE_HEADER, event)
        .header(DELIVERY_HEADER, delivery);
    if let Some(sig) = signature {
        req = req.header(SIGNATURE_HEADER, sig);
    }
    send(
        stream,
        req.body(Full::new(Bytes::from(body.to_vec()))).unwrap(),
    )
    .await
    .0
}

fn created(tag: &str) -> Vec<u8> {
    json!({
        "action": "created",
        "package": {
            "owner": { "login": "acme" }, "type": "container", "name": "shop", "version": tag
        }
    })
    .to_string()
    .into_bytes()
}

fn pulls(fake: &FakePodman) -> usize {
    fake.calls()
        .iter()
        .filter(|c| matches!(c, Call::ImagePull(r) if r == IMAGE))
        .count()
}

async fn forgejo_hook(
    addr: SocketAddr,
    instance: &str,
    event: &str,
    delivery: &str,
    body: &[u8],
    sig: Option<String>,
) -> StatusCode {
    hook(addr, "forgejo", instance, event, delivery, body, sig).await
}

async fn add_app(h: &Harness) {
    let (s, v) = admin(
        h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "shop",
            "spec": {
                "image": IMAGE,
                "domains": ["shop.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 }
            }
        })),
    )
    .await;
    assert!(s.is_success(), "{v}");
    eventually("first deploy", || async {
        let (_, v) = admin(h, "GET", "/v1/apps/shop", None).await;
        v["state"]["current"].is_string()
    })
    .await;
    let (s, _) = admin(
        h,
        "PUT",
        "/v1/apps/shop/secrets/webhook-hmac",
        Some(json!({"value": SECRET})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn forgejo_webhook_flow() {
    let h = harness(true).await;
    let addr = h.running.webhook_addr;
    add_app(&h).await;
    let body = created("main");
    let good = Some(sign(SECRET.as_bytes(), &body));

    // Bad / missing signature and an unknown app are indistinguishable → 401.
    let bad = Some(sign(b"wrong", &body));
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d0", &body, bad).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d0", &body, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        forgejo_hook(addr, "ghost", "package", "d0", &body, good.clone()).await,
        StatusCode::UNAUTHORIZED
    );

    // A GitHub-style `sha256=` prefix is not accepted.
    let prefixed = Some(format!("sha256={}", sign(SECRET.as_bytes(), &body)));
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d0", &body, prefixed).await,
        StatusCode::UNAUTHORIZED
    );

    // Irrelevant events and the sibling `sha-…` tag (the app tracks `:main`) → 204.
    let ping = b"{}".to_vec();
    let ping_sig = Some(sign(SECRET.as_bytes(), &ping));
    assert_eq!(
        forgejo_hook(addr, "shop", "push", "d1", &ping, ping_sig).await,
        StatusCode::NO_CONTENT
    );
    let sha = created("sha-abc123");
    let sha_sig = Some(sign(SECRET.as_bytes(), &sha));
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d2", &sha, sha_sig).await,
        StatusCode::NO_CONTENT
    );
    let untagged = created("sha256:0123abcd");
    let untagged_sig = Some(sign(SECRET.as_bytes(), &untagged));
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d3", &untagged, untagged_sig).await,
        StatusCode::NO_CONTENT
    );

    // Malformed body (valid signature) → 400.
    let junk = b"nope".to_vec();
    let junk_sig = Some(sign(SECRET.as_bytes(), &junk));
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d4", &junk, junk_sig).await,
        StatusCode::BAD_REQUEST
    );

    // Good signature → 202 and a deploy.
    let before = pulls(&h.fake);
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d5", &body, good.clone()).await,
        StatusCode::ACCEPTED
    );
    eventually("webhook deploy pulled", || async {
        pulls(&h.fake) > before
    })
    .await;
    let after_first = pulls(&h.fake);

    // Duplicate delivery (same X-Forgejo-Delivery) → 202, no second deploy.
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d5", &body, good.clone()).await,
        StatusCode::ACCEPTED
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(pulls(&h.fake), after_first);

    // Body over the limit → 413.
    let huge = vec![b'x'; 1024 * 1024 + 1];
    let huge_sig = Some(sign(SECRET.as_bytes(), &huge));
    assert_eq!(
        forgejo_hook(addr, "shop", "package", "d6", &huge, huge_sig).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    h.running.stop().await;
}

#[tokio::test]
async fn forgejo_route_is_404_without_configuration() {
    let h = harness(false).await;
    let body = created("main");
    let sig = Some(sign(SECRET.as_bytes(), &body));
    assert_eq!(
        hook(
            h.running.webhook_addr,
            "forgejo",
            "shop",
            "package",
            "d0",
            &body,
            sig
        )
        .await,
        StatusCode::NOT_FOUND
    );
    let _ = &h.root;
    h.running.stop().await;
}
