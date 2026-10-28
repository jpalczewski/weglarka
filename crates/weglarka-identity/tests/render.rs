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
        .filter(|r| r["policy"] != "deny")
        .collect();
    assert!(tools[0].get("resources").is_some());
    assert!(tools[1].get("resources").is_none());
}

/// The provider skips a rule whose `subject` the user does not match and tries the next one, so every
/// group rule must be followed at once by a `deny` over the same domain and resources.
#[test]
fn access_control_group_rules_are_closed_by_a_deny() {
    let apps = forward_apps();
    let forward: Vec<_> = apps.iter().map(Forward::forward).collect();
    let text = render_access_control(ISSUER, &forward).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let rules = doc["access_control"]["rules"].as_array().unwrap();
    let mut with_groups = 0;
    for (i, rule) in rules.iter().enumerate() {
        if rule.get("subject").is_some() {
            with_groups += 1;
            let next = &rules[i + 1];
            assert_eq!(next["policy"], "deny", "{rule}");
            assert!(next.get("subject").is_none(), "{next}");
            assert_eq!(next["domain"], rule["domain"]);
            assert_eq!(next.get("resources"), rule.get("resources"));
        }
    }
    assert!(with_groups > 0, "the fixture has no group rule");
    let denies = rules.iter().filter(|r| r["policy"] == "deny").count();
    assert_eq!(denies, with_groups, "a deny without a group rule before it");
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

#[test]
fn oidc_pkce_off_renders_neither_pkce_field() {
    let text = clients_only(&["legacy"]);
    assert!(text.contains("\"require_pkce\": false"));
    assert!(!text.contains("pkce_challenge_method"));
}

#[test]
fn oidc_offline_access_gets_refresh_grants() {
    let text = clients_only(&["api"]);
    assert!(text.contains("\"refresh_token\""));
    assert!(text.contains("\"response_types\""));
    assert!(!clients_only(&["panel"]).contains("grant_types"));
}

#[test]
fn oidc_rejects_groups_in_opaque_access_token() {
    let spec = oidc(
        r#"
        redirect_uris = ["https://x.example.com/cb"]
        scopes = ["openid", "groups"]
        groups_in_access_token = true
        client_secret = { kind = "env", var = "S" }
        "#,
    );
    let n = name("x");
    assert_eq!(
        render_oidc_clients(
            &[AppClient {
                instance: &n,
                spec: &spec,
                secret_digest: Some(DIGEST)
            }],
            &Default::default()
        ),
        Err(RenderError::GroupsInOpaqueToken("x".into()))
    );
}

#[test]
fn access_control_rejects_app_on_the_portal_host() {
    for domain in ["auth.example.com", "*.example.com"] {
        let app = Forward::new(
            "p",
            &format!("image = \"x\"\ndomains = [\"{domain}\"]\npaths = [\"/admin\"]\n"),
        );
        assert!(matches!(
            render_access_control(ISSUER, &[app.forward()]),
            Err(RenderError::PortalDomain(..))
        ));
    }
    let other = Forward::new("o", "image = \"x\"\ndomains = [\"*.example.org\"]\n");
    assert!(render_access_control(ISSUER, &[other.forward()]).is_ok());
}

#[test]
fn access_control_nested_prefixes_most_specific_first() {
    let outer = Forward::new(
        "a-outer",
        "image = \"x\"\ndomains = [\"t.example.com\"]\npaths = [\"/docs\"]\n",
    );
    let inner = Forward::new(
        "z-inner",
        "image = \"x\"\ndomains = [\"t.example.com\"]\npaths = [\"/docs/internal\"]\n",
    );
    let text = render_access_control(ISSUER, &[outer.forward(), inner.forward()]).unwrap();
    assert!(text.find("docs/internal").unwrap() < text.find("^/docs(").unwrap());
}
