mod fixtures;

use fixtures::*;
use weglarka_identity::{AppClient, RenderError, render_access_control, render_oidc_clients};

fn clients_only(names: &[&str]) -> String {
    let c = clients();
    let all = c.app_clients();
    let picked: Vec<AppClient<'_>> = all
        .into_iter()
        .filter(|a| names.contains(&a.instance.as_str()))
        .collect();
    let external = if names.contains(&"forge") {
        c.external.clone()
    } else {
        Default::default()
    };
    render_oidc_clients(&picked, &external).unwrap()
}

#[test]
fn oidc_all_flavours() {
    let c = clients();
    let text = render_oidc_clients(&c.app_clients(), &c.external).unwrap();
    insta::assert_snapshot!("oidc_all", text);
    serde_json::from_str::<serde_json::Value>(&text).unwrap();
}

#[test]
fn oidc_confidential_client() {
    insta::assert_snapshot!(clients_only(&["panel"]));
}

#[test]
fn oidc_public_client_has_no_secret_and_forces_pkce() {
    let text = clients_only(&["spa"]);
    insta::assert_snapshot!(text);
    assert!(!text.contains("client_secret\""));
}

#[test]
fn oidc_pkce_off_and_post_auth() {
    insta::assert_snapshot!(clients_only(&["legacy"]));
}

#[test]
fn oidc_jwt_access_token_with_groups_and_audience() {
    insta::assert_snapshot!(clients_only(&["api"]));
}

#[test]
fn oidc_external_client() {
    insta::assert_snapshot!(clients_only(&["forge"]));
}

#[test]
fn oidc_empty() {
    insta::assert_snapshot!(render_oidc_clients(&[], &Default::default()).unwrap());
}

#[test]
fn oidc_output_does_not_depend_on_input_order() {
    let c = clients();
    let mut reversed = c.app_clients();
    reversed.reverse();
    assert_eq!(
        render_oidc_clients(&c.app_clients(), &c.external).unwrap(),
        render_oidc_clients(&reversed, &c.external).unwrap()
    );
}

#[test]
fn oidc_secrets_are_only_digests() {
    let c = clients();
    let text = render_oidc_clients(&c.app_clients(), &c.external).unwrap();
    assert!(!text.contains("OIDC_CLIENT_SECRET"));
    assert_eq!(text.matches(DIGEST).count(), 4);
}

#[test]
fn oidc_rejects_bad_digests_and_collisions() {
    let c = clients();
    let panel = &c.apps[0];
    let one = |digest| {
        render_oidc_clients(
            &[AppClient {
                instance: &panel.0,
                spec: &panel.1,
                secret_digest: digest,
            }],
            &Default::default(),
        )
    };
    assert_eq!(one(None), Err(RenderError::MissingDigest("panel".into())));
    assert_eq!(
        one(Some("$plaintext$hunter2")),
        Err(RenderError::InvalidDigest("panel".into()))
    );
    let spa = &c.apps[1];
    assert_eq!(
        render_oidc_clients(
            &[AppClient {
                instance: &spa.0,
                spec: &spa.1,
                secret_digest: Some(DIGEST),
            }],
            &Default::default()
        ),
        Err(RenderError::UnexpectedDigest("spa".into()))
    );
    let mut dup = c.external.clone();
    dup.insert(
        weglarka_model::identity::ClientId::new("panel").unwrap(),
        c.external.values().next().unwrap().clone(),
    );
    assert_eq!(
        render_oidc_clients(&c.app_clients(), &dup),
        Err(RenderError::DuplicateClient("panel".into()))
    );
}

#[test]
fn access_control_portal_only() {
    insta::assert_snapshot!(render_access_control(ISSUER, &[]).unwrap());
}

#[test]
fn access_control_policies_groups_and_prefixes() {
    let apps = forward_apps();
    let forward: Vec<_> = apps
        .iter()
        .filter(|a| !a.spec.ingress.auth.is_none())
        .map(Forward::forward)
        .collect();
    insta::assert_snapshot!(render_access_control(ISSUER, &forward).unwrap());
}

#[test]
fn access_control_never_opens_a_domain_by_accident() {
    let apps = forward_apps();
    let forward: Vec<_> = apps.iter().map(Forward::forward).collect();
    let text = render_access_control(ISSUER, &forward).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let ac = &doc["access_control"];
    assert_eq!(ac["default_policy"], "deny");
    let rules = ac["rules"].as_array().unwrap();
    assert_eq!(rules[0]["domain"], serde_json::json!(["auth.example.com"]));
    assert_eq!(rules[0]["policy"], "bypass");
    for rule in &rules[1..] {
        assert_ne!(rule["policy"], "bypass");
    }
    // Prefix rules come before the whole-domain rule of the same domain, or the latter would shadow them.
    let tools: Vec<_> = rules
        .iter()
        .filter(|r| r["domain"] == serde_json::json!(["tools.example.com"]))
        .collect();
    assert!(tools[0].get("resources").is_some());
    assert!(tools[1].get("resources").is_none());
}

#[test]
fn access_control_prefix_regex_is_anchored() {
    let apps = forward_apps();
    let docs = apps.iter().find(|a| a.name.as_str() == "docs").unwrap();
    let text = render_access_control(ISSUER, &[docs.forward()]).unwrap();
    assert!(text.contains(r#""^/docs([/?].*)?$""#));
    assert!(text.contains(r#""^/v1\\.2/ref([/?].*)?$""#));
}

#[test]
fn access_control_rejects_unsafe_input() {
    let apps = vec![
        Forward::new("a", "image = \"x\"\ndomains = []\n"),
        Forward::new("b", "image = \"x\"\ndomains = [\"a b.example.com\"]\n"),
        Forward::new(
            "c",
            "image = \"x\"\ndomains = [\"c.example.com\"]\n[ingress]\nauth_groups = [\"x y\"]\n",
        ),
        Forward::new(
            "d",
            "image = \"x\"\ndomains = [\"d.example.com\"]\npaths = [\"/a/../b\"]\n",
        ),
    ];
    for app in &apps {
        assert!(render_access_control(ISSUER, &[app.forward()]).is_err());
    }
    assert!(render_access_control("https://auth.example.com/x", &[]).is_err());
}
