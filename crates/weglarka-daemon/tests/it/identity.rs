//! The identity integration end to end (#91, #88): an `oidc` app gets its client in the provider's
//! generated files and its credentials in the container, removal drops the client, rotation changes
//! the digest, external clients live in `apps.toml`, and the provider is guarded.

use crate::common::*;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_engine::testing::RunScript;

const IDENTITY: &str = "[identity]\nprovider = \"authelia\"\ninstance = \"authelia\"\nissuer = \"https://auth.example.com\"\n";

fn provider() -> Value {
    let mut s = spec("auth.example.com");
    s["auto_update"] = json!(false);
    s["command"] = json!([
        "authelia",
        "--config=/config/configuration.yml",
        "--config=/weglarka/generated/current"
    ]);
    s
}

fn panel() -> Value {
    let mut s = spec("app.example.com");
    s["oidc"] = json!({
        "redirect_uris": ["https://app.example.com/mcp/callback"],
        "audience": ["https://app.example.com/mcp/"],
        "client_secret": { "kind": "env", "var": "OIDC_CLIENT_SECRET" }
    });
    s
}

fn clients_file(h: &Harness) -> String {
    read(
        &h.root
            .join("state/generated/authelia/current/oidc-clients.yml"),
    )
}

async fn with_provider() -> Harness {
    let h = Builder::new().sections(IDENTITY).build().await;
    add(&h, "authelia", provider()).await;
    deployed(&h, "authelia").await;
    h
}

#[tokio::test]
async fn an_oidc_app_gets_a_client_credentials_and_loses_the_client_on_removal() {
    let h = with_provider().await;
    add(&h, "panel", panel()).await;
    deployed(&h, "panel").await;

    // The container carries the client id, the issuer and the secret binding.
    let specs = h.fake.created_specs();
    let container = specs
        .iter()
        .find(|s| s.env.contains_key("OIDC_CLIENT_ID"))
        .expect("the oidc app's container");
    assert_eq!(container.env["OIDC_CLIENT_ID"], "panel");
    assert_eq!(container.env["OIDC_ISSUER"], "https://auth.example.com");
    assert!(
        !container.secrets.is_empty(),
        "the client secret is attached"
    );

    // The provider's file has the client with the audience, the digest and no plaintext.
    eventually("the client in the generated file", || async {
        clients_file(&h).contains("\"panel\"")
    })
    .await;
    let file = clients_file(&h);
    assert!(file.contains("https://app.example.com/mcp/"), "{file}");
    assert!(file.contains("$pbkdf2-sha512$"), "{file}");
    let store = weglarka_model::secrets::FileSecretStore::new(h.root.join("state/secrets.toml"));
    let secret = weglarka_model::secret_store::SecretStore::get(&store, "panel.oidc-client-secret")
        .unwrap()
        .expect("the minted secret");
    let plain = std::str::from_utf8(secret.expose()).unwrap();
    assert!(
        !file.contains(plain),
        "the plain secret never reaches the file"
    );

    // Removing the app removes its client at the next apply.
    let (s, v) = admin(&h, "DELETE", "/v1/apps/panel", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    eventually("the client gone from the generated file", || async {
        !clients_file(&h).contains("\"panel\"")
    })
    .await;
    h.running.stop().await;
}

#[tokio::test]
async fn rotation_changes_the_digest_and_recreates_the_app() {
    let h = with_provider().await;
    add(&h, "panel", panel()).await;
    deployed(&h, "panel").await;
    eventually("the client in the generated file", || async {
        clients_file(&h).contains("\"panel\"")
    })
    .await;
    let before = clients_file(&h);
    let creates = h.fake.created_specs().len();

    let (s, v) = admin(&h, "POST", "/v1/apps/panel/oidc/rotate", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["recreated"], true, "{v}");
    // The provider's files were applied before the response, not after a debounce.
    assert_ne!(clients_file(&h), before);
    assert!(
        h.fake.created_specs().len() > creates,
        "the app was recreated"
    );
    h.running.stop().await;
}

fn secrets_file(h: &Harness) -> String {
    read(&h.root.join("state/secrets.toml"))
}

#[tokio::test]
async fn a_rotation_the_provider_rejects_changes_nothing() {
    let h = with_provider().await;
    add(&h, "panel", panel()).await;
    deployed(&h, "panel").await;
    eventually("the client in the generated file", || async {
        clients_file(&h).contains("\"panel\"")
    })
    .await;
    let (files, secrets) = (clients_file(&h), secrets_file(&h));

    // The provider's validation fails, so the new files are not applied.
    h.fake.script_next_run(RunScript {
        exit_code: 1,
        ..Default::default()
    });
    let (s, v) = admin(&h, "POST", "/v1/apps/panel/oidc/rotate", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap_or_default()
            .contains("nothing was rotated"),
        "{v}"
    );
    assert_eq!(clients_file(&h), files, "the provider keeps the old digest");
    assert_eq!(
        secrets_file(&h),
        secrets,
        "the live pair and the store are untouched"
    );

    // Once the provider is back, the same command succeeds and leaves no pending pair behind.
    let (s, v) = admin(&h, "POST", "/v1/apps/panel/oidc/rotate", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_ne!(clients_file(&h), files);
    assert_ne!(secrets_file(&h), secrets);
    assert!(!secrets_file(&h).contains("pending"));
    h.running.stop().await;
}

#[tokio::test]
async fn external_clients_live_in_apps_toml_and_the_list_survives_app_churn() {
    let h = with_provider().await;
    let client = json!({ "spec": {
        "name": "Forge",
        "redirect_uris": ["https://git.example.com/user/oauth2/authelia/callback"],
        "secret_digest": "$pbkdf2-sha512$310000$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo"
    }});
    let (s, v) = admin(&h, "PUT", "/v1/oidc-clients/forge", Some(client)).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (_, list) = admin(&h, "GET", "/v1/oidc-clients", None).await;
    assert!(list["clients"]["forge"].is_object(), "{list}");
    eventually("the external client in the generated file", || async {
        clients_file(&h).contains("\"forge\"")
    })
    .await;

    add(&h, "panel", panel()).await;
    let (s, _) = admin(&h, "DELETE", "/v1/apps/panel", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(clients_file(&h).contains("\"forge\""));

    let (s, _) = admin(&h, "DELETE", "/v1/oidc-clients/forge", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = admin(&h, "DELETE", "/v1/oidc-clients/forge", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    h.running.stop().await;
}

#[tokio::test]
async fn the_provider_cannot_be_removed_or_misconfigured() {
    let h = with_provider().await;
    let (s, v) = admin(&h, "DELETE", "/v1/apps/authelia", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");

    // Generated config not last is refused on a write of the provider itself.
    let mut bad = provider();
    bad["command"] = json!([
        "authelia",
        "--config=/weglarka/generated/current",
        "--config=/late.yml"
    ]);
    let (s, v) = admin(&h, "PUT", "/v1/apps/authelia", Some(json!({ "spec": bad }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("last config source"),
        "{v}"
    );
    // ... and so is the default `auto_update = true`.
    let mut auto = provider();
    auto["auto_update"] = json!(true);
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/authelia",
        Some(json!({ "spec": auto })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    h.running.stop().await;
}

#[tokio::test]
async fn oidc_needs_the_identity_section() {
    let h = harness().await;
    let (s, v) = post_app(&h, "panel", panel()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["message"].as_str().unwrap().contains("[identity]"), "{v}");
    h.running.stop().await;
}

fn acl_file(h: &Harness) -> String {
    read(
        &h.root
            .join("state/generated/authelia/current/access-control.yml"),
    )
}

fn forward_app(groups: &[&str]) -> Value {
    let mut s = spec("admin.example.com");
    s["ingress"] = json!({ "auth": "forward", "auth_policy": "one_factor", "auth_groups": groups });
    s
}

#[tokio::test]
async fn forward_auth_policy_and_groups_become_access_rules() {
    let h = with_provider().await;
    // Before any forward app the file is the constant portal rule under a default deny.
    eventually("the access rules file", || async {
        acl_file(&h).contains("auth.example.com")
    })
    .await;
    let empty = acl_file(&h);
    assert!(empty.contains("\"default_policy\": \"deny\""), "{empty}");
    assert!(!empty.contains("admin.example.com"), "{empty}");

    add(&h, "panel", forward_app(&["weglarka-admins"])).await;
    deployed(&h, "panel").await;
    eventually("the app's rule", || async {
        acl_file(&h).contains("admin.example.com")
    })
    .await;
    let file = acl_file(&h);
    assert!(file.contains("group:weglarka-admins"), "{file}");
    assert!(file.contains("\"one_factor\""), "{file}");

    // Tightening the groups re-renders the rules and leaves the OIDC clients file alone.
    let clients = clients_file(&h);
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/panel",
        Some(json!({ "spec": forward_app(&["ops"]) })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    eventually("the tightened rule", || async {
        acl_file(&h).contains("group:ops")
    })
    .await;
    let file = acl_file(&h);
    assert!(!file.contains("weglarka-admins"), "{file}");
    assert_eq!(clients_file(&h), clients);
    h.running.stop().await;
}

fn base_config_check(report: &Value) -> Vec<&Value> {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["id"] == "identity.base_config")
        .collect()
}

#[tokio::test]
async fn doctor_warns_about_sections_a_base_config_would_lose() {
    let builder = Builder::new();
    let config_root = builder.root().join("config");
    std::fs::create_dir_all(config_root.join("authelia")).unwrap();
    let file = config_root.join("authelia/configuration.yml");
    std::fs::write(&file, "server:\n  address: tcp://:9091\n").unwrap();
    let h = builder
        .top_level(&format!(
            "config_root = {:?}\n",
            config_root.display().to_string()
        ))
        .sections(IDENTITY)
        .build()
        .await;
    let mut p = provider();
    p["configs"] = json!([{
        "source": "authelia/configuration.yml",
        "target": "/config/configuration.yml"
    }]);
    add(&h, "authelia", p).await;
    deployed(&h, "authelia").await;

    // A clean base file adds no line.
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert!(base_config_check(&report).is_empty(), "{report}");

    std::fs::write(
        &file,
        "access_control:\n  default_policy: one_factor\nidentity_providers:\n  oidc:\n    clients: []\n",
    )
    .unwrap();
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let found = base_config_check(&report);
    assert_eq!(found.len(), 1, "{report}");
    assert_eq!(found[0]["status"], "warn");
    let message = found[0]["message"].as_str().unwrap();
    assert!(
        message.contains("access_control") && message.contains("oidc.clients"),
        "{message}"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn a_base_config_delivered_as_a_secret_cannot_be_verified() {
    let h = Builder::new().sections(IDENTITY).build().await;
    let mut p = provider();
    p["secrets"] = json!([{
        "secret": "base",
        "kind": "mount",
        "path": "/config/configuration.yml"
    }]);
    add(&h, "authelia", p).await;
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let found = base_config_check(&report);
    assert_eq!(found.len(), 1, "{report}");
    assert_eq!(found[0]["status"], "info");
    assert!(
        found[0]["message"]
            .as_str()
            .unwrap()
            .contains("cannot verify")
    );
    h.running.stop().await;
}

#[tokio::test]
async fn the_base_config_scan_stays_inside_the_mount() {
    let builder = Builder::new();
    let config_root = builder.root().join("config");
    std::fs::create_dir_all(config_root.join("authelia")).unwrap();
    let outside = config_root.join("other.yml");
    std::fs::write(&outside, "access_control:\n  default_policy: deny\n").unwrap();
    std::fs::write(config_root.join("authelia/base.yml"), "server: {}\n").unwrap();
    // A symlink inside the mount that points out of it.
    std::os::unix::fs::symlink(&outside, config_root.join("authelia/escape.yml")).unwrap();
    let h = builder
        .top_level(&format!(
            "config_root = {:?}\n",
            config_root.display().to_string()
        ))
        .sections(IDENTITY)
        .build()
        .await;
    let mut p = provider();
    p["command"] = json!([
        "authelia",
        "--config=/config/../other.yml",
        "--config=/config/escape.yml",
        "--config=/config/base.yml",
        "--config=/weglarka/generated/current"
    ]);
    // The mount is a directory, so `escape.yml` is a path inside it.
    p["configs"] = json!([{ "source": "authelia", "target": "/config" }]);
    add(&h, "authelia", p).await;
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert!(base_config_check(&report).is_empty(), "{report}");
    h.running.stop().await;
}
