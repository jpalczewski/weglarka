//! `GET /v1/certificates` and `GET /v1/config` (docs/decisions/0057) over the unix socket and over
//! the token listener with a `read` bearer.

use crate::common::*;
use crate::token_api::{call, setup, setup_with};

use hyper::StatusCode;
use serde_json::json;

#[tokio::test]
async fn certificates_are_an_empty_list_with_a_flag_without_acme() {
    let h = harness().await;
    let (status, body) = admin(&h, "GET", "/v1/certificates", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({ "acme_enabled": false, "failures": 0, "certificates": [] })
    );
    h.running.stop().await;
}

#[tokio::test]
async fn the_config_view_shows_the_allow_listed_settings_and_no_host_layout() {
    let h = harness().await;
    let (status, body) = admin(&h, "GET", "/v1/config", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ingress"]["mode"], "behind");
    assert_eq!(body["ingress"]["bind"], "127.0.0.1:18080");
    assert_eq!(body["webhook"]["domain"], "hooks.example.eu");
    assert_eq!(body["host_configs"], false);
    assert!(body["monitor"]["crash_loop_restarts"].is_u64(), "{body}");
    for absent in ["notify", "acme", "identity", "self_update"] {
        assert!(body.get(absent).is_none(), "{absent} is off: {body}");
    }
    // The root of the test's data layout appears nowhere: no socket, state or file path.
    let text = body.to_string();
    let root = h.root.display().to_string();
    assert!(!text.contains(&root), "{text}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_read_token_may_read_both_views_and_a_missing_one_may_not() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    for path in ["/v1/certificates", "/v1/config"] {
        let (status, _, body) = call(sock, "GET", path, Some(&reader), None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        let (status, _, _) = call(sock, "GET", path, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }

    let (_, _, config) = call(sock, "GET", "/v1/config", Some(&reader), None).await;
    let http = &config["admin"]["http"];
    assert_eq!(http["clients"], json!(["panel"]));
    assert_eq!(http["audience"], "https://admin.example.com/api/");
    // The group names are authorization policy: only their number is shown.
    assert_eq!(http["read_groups"], 1);
    assert_eq!(http["admin_groups"], 1);
    let text = config.to_string();
    assert!(
        !text.contains("viewers") && !text.contains("admins"),
        "{text}"
    );
    assert_eq!(config["identity"]["issuer"], "https://auth.example.com");
    s.h.running.stop().await;
}

const VALID_CHAIN: &str = include_str!("fixtures/valid-until-2200.pem");
const EXPIRED_CHAIN: &str = include_str!("fixtures/expired-2021.pem");

#[tokio::test]
async fn certificates_list_rows_failures_and_wildcard_cover_over_both_listeners() {
    use std::os::unix::fs::PermissionsExt as _;
    let builder = Builder::new();
    let token = builder.root().join("cf-token");
    std::fs::write(&token, "cf-secret-token\n").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let builder = builder
        .ingress(
            "[ingress]\nmode = \"edge\"\nbind = \"127.0.0.1:18080\"\nhttps_bind = \"127.0.0.1:18443\"\n",
        )
        .sections(&format!(
            "{}\n[acme]\naccept_terms = true\ndirectory_url = \"https://acme.invalid/directory\"\n\n\
             [acme.dns]\nprovider = \"cloudflare\"\ntoken_file = \"{}\"\nwildcards = [\"example.eu\"]\n",
            crate::token_api::SECTIONS,
            token.display()
        ));
    let s = setup_with(builder).await;
    for (name, domain) in [
        ("shop", "shop.example.eu"),
        ("old", "old.example.net"),
        ("new", "new.example.net"),
    ] {
        add(&s.h, name, spec(domain)).await;
    }

    // `tls/`: an expired chain of its own, a valid wildcard (which serves `*.example.eu`), a chain
    // without its key (treated as absent) and nothing for `new.example.net`.
    let tls = s.h.running.daemon.ingress.tls_dir();
    std::fs::create_dir_all(&tls).unwrap();
    let seed = |stem: &str, chain: &str, key: bool| {
        std::fs::write(tls.join(format!("{stem}.crt")), chain).unwrap();
        if key {
            std::fs::write(tls.join(format!("{stem}.key")), "key").unwrap();
        }
    };
    seed("old.example.net", EXPIRED_CHAIN, true);
    seed("_wildcard.example.eu", VALID_CHAIN, true);
    seed("keyless.example.net", VALID_CHAIN, false);
    // What the worker records after a pass that failed on one certificate.
    let last_pass = std::time::SystemTime::now();
    s.h.running
        .daemon
        .acme
        .as_ref()
        .expect("the ACME worker's status")
        .record(
            last_pass,
            vec![("new.example.net".to_owned(), "rate limited".to_owned())],
        );

    let reader = s.issuer.token("rita", &["viewers"]);
    let (status, _, over_token) = call(
        &s.token_socket,
        "GET",
        "/v1/certificates",
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{over_token}");
    let (status, over_socket) = admin(&s.h, "GET", "/v1/certificates", None).await;
    assert_eq!(status, StatusCode::OK, "{over_socket}");
    assert_eq!(over_socket, over_token);

    let body = over_socket;
    assert_eq!(body["acme_enabled"], true, "{body}");
    assert!(body["last_pass"].is_string(), "{body}");
    assert_eq!(body["failures"], 1, "{body}");
    let row = |id: &str| {
        body["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no row {id} in {body}"))
            .clone()
    };
    let old = row("old.example.net");
    assert_eq!(old["status"], "expired", "{old}");
    assert!(old["days_left"].as_i64().unwrap() < 0, "{old}");
    assert_eq!(old["failed"], false);
    let new = row("new.example.net");
    assert_eq!(new["status"], "missing", "{new}");
    assert_eq!(new["failed"], true, "{new}");
    let shop = row("shop.example.eu");
    assert_eq!(shop["status"], "covered", "{shop}");
    assert_eq!(shop["covered_by"], "*.example.eu", "{shop}");
    let wildcard = row("_wildcard.example.eu");
    assert_eq!(wildcard["status"], "valid", "{wildcard}");
    assert_eq!(wildcard["wildcard"], true);
    assert!(
        wildcard["not_after"]
            .as_str()
            .unwrap()
            .starts_with("2200-01-01"),
        "{wildcard}"
    );
    // A chain without its key is no certificate, and the key file is never opened.
    assert!(
        body["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["id"] != "keyless.example.net"),
        "{body}"
    );
    s.h.running.stop().await;
}
