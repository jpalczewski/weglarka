use std::path::Path;

use super::*;
use crate::config::HostConfig;
use crate::hash::spec_hash;
use crate::state::{self, SCHEMA_VERSION};

fn name(s: &str) -> InstanceName {
    InstanceName::new(s).unwrap()
}

fn spec(extra: &str) -> AppSpec {
    toml::from_str(&format!(
        "image = \"i\"\nport = 80\ndomains = [\"app.example.com\"]\n{extra}"
    ))
    .unwrap()
}

const OIDC: &str = r#"
[oidc]
redirect_uris = ["https://app.example.com/auth/callback"]
client_secret = { kind = "env", var = "OIDC_CLIENT_SECRET" }
"#;

fn oidc(extra: &str) -> AppSpec {
    spec(&format!("{OIDC}{extra}"))
}

fn lexical(spec: &AppSpec) -> Result<(), String> {
    validate_app(&name("a"), spec)
}

fn lexical_err(spec: &AppSpec) -> String {
    lexical(spec).unwrap_err()
}

// --- round trips and the hash -------------------------------------------------------------------

#[test]
fn a_file_without_the_new_fields_round_trips_byte_for_byte() {
    let src = format!(
        "schema_version = {SCHEMA_VERSION}\n\n[apps.a]\nimage = \"x:1\"\nauto_update = true\n"
    );
    let parsed: AppsFile = toml::from_str(&src).unwrap();
    let out = toml::to_string(&parsed).unwrap();
    for field in ["oidc", "auth", "identity"] {
        assert!(!out.contains(field), "{out}");
    }
    assert_eq!(
        toml::to_string(&toml::from_str::<AppsFile>(&out).unwrap()).unwrap(),
        out
    );
}

#[test]
fn the_new_fields_round_trip() {
    let src = r#"
[oidc_clients.forge]
name = "Forge"
redirect_uris = ["https://git.example.com/callback"]
secret_digest = "$pbkdf2-sha512$310000$c2FsdA$aGFzaA"

[apps.panel]
image = "x:1"
domains = ["app.example.com"]
auto_update = true

[apps.panel.oidc]
redirect_uris = ["https://app.example.com/cb"]
scopes = ["openid", "groups"]
groups_in_id_token = true
client_secret = { kind = "mount", path = "/run/secrets/oidc", mode = 256, uid = 1000 }

[apps.panel.ingress]
auth = "forward"
auth_policy = "one_factor"
auth_groups = ["admins"]
auth_exempt_paths = ["/mcp/"]
"#;
    let parsed: AppsFile = toml::from_str(src).unwrap();
    let out = toml::to_string(&parsed).unwrap();
    assert_eq!(toml::from_str::<AppsFile>(&out).unwrap(), parsed);
    assert_eq!(parsed.oidc_clients.len(), 1);
    assert_eq!(toml::to_string(&parsed).unwrap(), out);
}

#[test]
fn unknown_fields_are_rejected() {
    toml::from_str::<AppSpec>(&format!("image = \"i\"\n{OIDC}typo = 1")).unwrap_err();
    toml::from_str::<AppsFile>("[oidc_clients.x]\nname = \"X\"\nredirect_uris = []\nbogus = 1")
        .unwrap_err();
}

#[test]
fn the_new_fields_are_outside_the_spec_hash() {
    let digest = crate::app::Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    let plain = spec("");
    let rich = oidc(
        "[ingress]\nauth = \"forward\"\nauth_policy = \"one_factor\"\nauth_groups = [\"g\"]\nauth_exempt_paths = [\"/p/\"]\n",
    );
    assert!(rich.oidc.is_some() && !rich.ingress.auth.is_none());
    assert_eq!(spec_hash(&plain, &digest), spec_hash(&rich, &digest));
}

// --- lexical validation: OIDC ------------------------------------------------------------------

#[test]
fn a_minimal_oidc_client_is_valid() {
    lexical(&oidc("")).unwrap();
}

#[test]
fn redirect_uris_are_https_on_the_apps_own_hosts() {
    for (uri, why) in [
        ("http://app.example.com/cb", "https"),
        ("https://app.example.com/cb#frag", "fragment"),
        (
            "https://other.example.com/cb",
            "not one of the app's domains",
        ),
        ("https://user@app.example.com/cb", "userinfo"),
        ("https://app.example.com:0/cb", "port"),
        ("https://app.example.com:80x/cb", "port"),
        ("https://app.example.com /cb", "whitespace"),
        ("https://[::1]/cb", "host"),
        ("HTTPS://app.example.com/cb", "https"),
        ("/cb", "https"),
    ] {
        let s = spec(&format!(
            "[oidc]\nredirect_uris = [{uri:?}]\nclient_secret = {{ kind = \"env\", var = \"S\" }}"
        ));
        assert!(lexical_err(&s).contains(why), "{uri}: {}", lexical_err(&s));
    }
    // Case and an explicit port are fine.
    lexical(&spec(
        "[oidc]\nredirect_uris = [\"https://APP.example.com:8443/cb?x=1\"]\nclient_secret = { kind = \"env\", var = \"S\" }",
    ))
    .unwrap();
    assert!(
        lexical_err(&spec(
            "[oidc]\nredirect_uris = []\nclient_secret = { kind = \"env\", var = \"S\" }"
        ))
        .contains("at least one")
    );
}

#[test]
fn oidc_needs_domains() {
    let s: AppSpec = toml::from_str(&format!("image = \"i\"\n{OIDC}")).unwrap();
    assert!(lexical_err(&s).contains("domain"));
}

#[test]
fn scopes_come_from_the_allowlist() {
    for (scopes, why) in [
        ("[\"openid\", \"admin\"]", "not allowed"),
        ("[\"profile\"]", "openid"),
        ("[\"openid\", \"openid\"]", "duplicate"),
    ] {
        let s = spec(&format!(
            "[oidc]\nscopes = {scopes}\nredirect_uris = [\"https://app.example.com/cb\"]\nclient_secret = {{ kind = \"env\", var = \"S\" }}"
        ));
        assert!(
            lexical_err(&s).contains(why),
            "{scopes}: {}",
            lexical_err(&s)
        );
    }
    lexical(&spec(
        "[oidc]\nscopes = [\"openid\", \"groups\", \"offline_access\"]\nredirect_uris = [\"https://app.example.com/cb\"]\nclient_secret = { kind = \"env\", var = \"S\" }",
    ))
    .unwrap();
}

#[test]
fn groups_claims_need_the_groups_scope() {
    let with = |scopes: &str, claim: &str| {
        spec(&format!(
            "[oidc]\naccess_token = \"jwt\"\nscopes = {scopes}\n{claim} = true\nredirect_uris = [\"https://app.example.com/cb\"]\nclient_secret = {{ kind = \"env\", var = \"S\" }}"
        ))
    };
    for claim in ["groups_in_id_token", "groups_in_access_token"] {
        assert!(lexical_err(&with("[\"openid\"]", claim)).contains("groups"));
        lexical(&with("[\"openid\", \"groups\"]", claim)).unwrap();
    }
}

#[test]
fn groups_in_access_token_needs_a_jwt() {
    let text = "[oidc]\nscopes = [\"openid\", \"groups\"]\ngroups_in_access_token = true\nredirect_uris = [\"https://app.example.com/cb\"]\nclient_secret = { kind = \"env\", var = \"S\" }";
    assert!(lexical_err(&spec(text)).contains("jwt"));
    lexical(&spec(&format!("{text}\naccess_token = \"jwt\""))).unwrap();
}

#[test]
fn audience_entries_are_absolute_https_urls() {
    let with = |aud: &str| {
        spec(&format!(
            "[oidc]\naudience = [{aud:?}]\nredirect_uris = [\"https://app.example.com/cb\"]\nclient_secret = {{ kind = \"env\", var = \"S\" }}"
        ))
    };
    lexical(&with("https://app.example.com/api/")).unwrap();
    for bad in ["app.example.com", "http://app.example.com/", "https://x/#f"] {
        assert!(lexical_err(&with(bad)).contains("audience"), "{bad}");
    }
}

#[test]
fn client_secret_rules() {
    let with = |extra: &str| {
        spec(&format!(
            "[oidc]\nredirect_uris = [\"https://app.example.com/cb\"]\n{extra}"
        ))
    };
    assert!(lexical_err(&with("")).contains("client_secret is required"));
    assert!(
        lexical_err(&with(
            "public = true\nclient_secret = { kind = \"env\", var = \"S\" }"
        ))
        .contains("public client must not")
    );
    lexical(&with("public = true")).unwrap();
    assert!(lexical_err(&with("public = true\npkce = \"off\"")).contains("PKCE"));
    assert!(
        lexical_err(&with(
            "public = true\ntoken_endpoint_auth_method = \"client_secret_post\""
        ))
        .contains("token_endpoint_auth_method")
    );
    assert!(
        lexical_err(&with("client_secret = { kind = \"env\", var = \"1BAD\" }"))
            .contains("environment variable")
    );
    assert!(
        lexical_err(&with(
            "client_secret = { kind = \"env\", var = \"OIDC_ISSUER\" }"
        ))
        .contains("collides")
    );
    assert!(
        lexical_err(&with(
            "client_secret = { kind = \"mount\", path = \"rel\" }"
        ))
        .contains("absolute")
    );
    assert!(
        lexical_err(&with(
            "client_secret = { kind = \"mount\", path = \"/s\", uid = 70000 }"
        ))
        .contains("uid")
    );
}

#[test]
fn injected_env_names_are_checked() {
    let with = |extra: &str| {
        spec(&format!(
            "[oidc]\nredirect_uris = [\"https://app.example.com/cb\"]\nclient_secret = {{ kind = \"env\", var = \"S\" }}\n{extra}"
        ))
    };
    lexical(&with("client_id_env = \"CID\"\nissuer_env = \"ISS\"")).unwrap();
    assert!(lexical_err(&with("client_id_env = \"a-b\"")).contains("client_id_env"));
    assert!(lexical_err(&with("issuer_env = \"OIDC_CLIENT_ID\"")).contains("differ"));
}

// --- lexical validation: forward auth ----------------------------------------------------------

#[test]
fn auth_fields_need_forward() {
    for extra in [
        "auth_policy = \"one_factor\"",
        "auth_groups = [\"g\"]",
        "auth_exempt_paths = [\"/x/\"]",
    ] {
        let s = spec(&format!("[ingress]\n{extra}"));
        assert!(lexical_err(&s).contains("requires ingress.auth"), "{extra}");
    }
    lexical(&spec("[ingress]\nauth = \"none\"")).unwrap();
}

#[test]
fn auth_groups_and_exempt_paths_syntax() {
    let fwd = |extra: &str| spec(&format!("[ingress]\nauth = \"forward\"\n{extra}"));
    lexical(&fwd("auth_exempt_paths = [\"/.well-known/\", \"/mcp/\"]")).unwrap();
    lexical(&fwd(
        "auth_groups = [\"weglarka-admins\", \"a.b_c\"]\nauth_exempt_paths = [\"/mcp\", \"/mcp/\"]",
    ))
    .unwrap();
    for bad in ["", "has space", "a/b", "a:b", "ł"] {
        let s = fwd(&format!("auth_groups = [{bad:?}]"));
        assert!(lexical_err(&s).contains("auth_groups"), "{bad:?}");
    }
    assert!(lexical_err(&fwd("auth_groups = [\"g\", \"g\"]")).contains("duplicate"));
    for bad in ["/", "mcp/", "/a//b", "/a/../b", "/a b/", "/a;b"] {
        let s = fwd(&format!("auth_exempt_paths = [{bad:?}]"));
        assert!(lexical_err(&s).contains("auth_exempt_paths"), "{bad:?}");
    }
}

#[test]
fn a_probed_path_needs_no_exemption() {
    // The daemon probes over the probe socket, which the authz location lets through.
    lexical(&spec(
        "[health.http]\npath = \"/healthz\"\n\n[ingress]\nauth = \"forward\"",
    ))
    .unwrap();
}

#[test]
fn exempt_paths_do_not_combine_with_path_prefixes() {
    let s = spec("paths = [\"/p\"]\n[ingress]\nauth = \"forward\"\nauth_exempt_paths = [\"/x/\"]");
    assert!(lexical_err(&s).contains("auth_exempt_paths"));
    lexical(&spec("paths = [\"/p\"]\n[ingress]\nauth = \"forward\"")).unwrap();
}

#[test]
fn forward_auth_needs_identity_domains_and_a_different_instance() {
    use crate::config::HostConfig;
    let host = |identity: &str| {
        HostConfig::from_toml_str(&format!(
            "[ingress]\nmode = \"behind\"\nbind = \"127.0.0.1:8080\"\ntraefik_dynamic_file = \"/d.yml\"\n\
             [admin]\nsocket = \"/a.sock\"\n[webhook]\nlisten = \"127.0.0.1:9180\"\ndomain = \"hook.example.com\"\n{identity}"
        ))
        .unwrap()
    };
    let identity = "[identity]\nprovider = \"authelia\"\ninstance = \"authelia\"\nissuer = \"https://auth.example.com\"\n";
    let forward = spec("[ingress]\nauth = \"forward\"");
    let check = |h: &HostConfig, n: &str, s: &AppSpec| validate_host_app(h, &name(n), s);
    check(&host(""), "a", &spec("")).unwrap();
    assert!(
        check(&host(""), "a", &forward)
            .unwrap_err()
            .contains("[identity]")
    );
    check(&host(identity), "a", &forward).unwrap();
    let mut no_domains = forward.clone();
    no_domains.domains.clear();
    assert!(
        check(&host(identity), "a", &no_domains)
            .unwrap_err()
            .contains("domains")
    );
    assert!(
        check(&host(identity), "authelia", &forward)
            .unwrap_err()
            .contains("provider")
    );
}

// --- external clients --------------------------------------------------------------------------

fn external() -> ExternalClientSpec {
    toml::from_str(
        "name = \"Forge\"\nredirect_uris = [\"https://git.example.com/cb\"]\nsecret_digest = \"$pbkdf2-sha512$310000$c2FsdA$aGFzaA\"",
    )
    .unwrap()
}

fn id(s: &str) -> ClientId {
    ClientId::new(s).unwrap()
}

#[test]
fn client_ids_use_the_instance_charset() {
    for bad in ["", "-a", "a-", "A", "a_b", "a.b", &"x".repeat(64)] {
        assert!(ClientId::new(bad).is_err(), "{bad:?}");
    }
    assert!(toml::from_str::<AppsFile>("[oidc_clients.\"Bad_Id\"]\nname=\"x\"").is_err());
}

#[test]
fn secret_digests_must_look_like_authelia_digests() {
    for good in [
        "$pbkdf2-sha512$310000$c2FsdA$aGFzaA",
        "$pbkdf2-sha256$310000$c2FsdA.x$aGFzaA/+",
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
    ] {
        assert!(valid_secret_digest(good), "{good}");
    }
    for bad in [
        "",
        "plain-secret",
        "$plaintext$hunter2",
        "$argon2id$",
        "$pbkdf2-sha512$310000",
        "$bcrypt$12$abc",
        "$pbkdf2-sha512$310000$sa lt$hash",
        "$pbkdf2-sha512$$salt$hash",
    ] {
        assert!(!valid_secret_digest(bad), "{bad}");
    }
}

#[test]
fn external_client_rules() {
    validate_external_client(&id("forge"), &external()).unwrap();
    let err = |edit: fn(&mut ExternalClientSpec)| {
        let mut c = external();
        edit(&mut c);
        validate_external_client(&id("forge"), &c).unwrap_err()
    };
    assert!(err(|c| c.secret_digest = Some("hunter2".into())).contains("secret_digest"));
    assert!(err(|c| c.secret_digest = Some("$plaintext$x".into())).contains("secret_digest"));
    assert!(err(|c| c.public = true).contains("must not set secret_digest"));
    assert!(err(|c| c.secret_digest = None).contains("required"));
    let mut public = external();
    public.secret_digest = None;
    public.public = true;
    validate_external_client(&id("forge"), &public).unwrap();
    assert!(err(|c| c.name = " ".into()).contains("name"));
    assert!(err(|c| c.redirect_uris = vec!["http://git.example.com/cb".into()]).contains("https"));
    assert!(err(|c| c.scopes = Some(vec!["profile".into()])).contains("openid"));
    // Unlike an app's client, an external one may use any host: the operator vouches.
    let mut other = external();
    other.redirect_uris = vec!["https://elsewhere.example.org/cb".into()];
    validate_external_client(&id("forge"), &other).unwrap();
}

#[test]
fn an_external_client_id_must_not_equal_any_instance() {
    let mut file = AppsFile::default();
    file.apps.insert(name("forge"), spec(""));
    file.oidc_clients.insert(id("forge"), external());
    assert!(
        validate_file(&file)
            .unwrap_err()
            .contains("equals the instance")
    );
    file.oidc_clients.clear();
    file.oidc_clients.insert(id("other"), external());
    validate_file(&file).unwrap();
}

// --- issuer and upstream -----------------------------------------------------------------------

#[test]
fn issuer_is_https_without_a_path() {
    for good in ["https://auth.example.com", "https://auth.example.com:9091"] {
        check_issuer(good).unwrap();
    }
    for bad in [
        "http://auth.example.com",
        "https://auth.example.com/",
        "https://auth.example.com/sub",
        "https://auth.example.com?x=1",
        "https://auth.example.com#f",
        "auth.example.com",
        "https://",
        "https://..",
        "https://-",
        "https://a..b",
        "https://-x.example.com",
        "https://x-.example.com",
        "https://example.com.",
        "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
    ] {
        assert!(check_issuer(bad).is_err(), "{bad}");
    }
}

#[test]
fn upstream_is_host_and_port() {
    check_upstream("authelia:9091").unwrap();
    for bad in [
        "authelia",
        "authelia:0",
        ":9091",
        "http://a:1",
        "a b:1",
        "a;b:1",
        "a:99999",
        "a:+1",
    ] {
        assert!(check_upstream(bad).is_err(), "{bad}");
    }
}

// --- the gate: one test per field ---------------------------------------------------------------

fn gated(spec: &AppSpec) -> String {
    state::validate_app(&name("a"), spec).unwrap_err()
}

#[test]
fn the_gate_rejects_oidc() {
    assert!(
        gated(&oidc("")).ends_with("is not enabled in this release"),
        "{}",
        gated(&oidc(""))
    );
    assert!(gated(&oidc("")).contains("OIDC"));
}

#[test]
fn forward_auth_and_exempt_paths_are_not_gated() {
    for extra in [
        "auth = \"forward\"",
        "auth = \"forward\"\nauth_exempt_paths = [\"/p/\"]",
    ] {
        let s = spec(&format!("[ingress]\n{extra}"));
        state::validate_app(&name("a"), &s).unwrap();
        gate::app(&name("a"), &s).unwrap();
    }
}

#[test]
fn the_gate_still_rejects_policy_and_groups_until_the_provider_enforces_them() {
    for extra in ["auth_policy = \"one_factor\"", "auth_groups = [\"g\"]"] {
        let s = spec(&format!("[ingress]\nauth = \"forward\"\n{extra}"));
        let err = gated(&s);
        assert!(err.contains("access control"), "{err}");
        assert!(err.ends_with("is not enabled in this release"), "{err}");
    }
}

#[test]
fn the_gate_rejects_oidc_clients_on_load_and_save() {
    let src = format!(
        "schema_version = {SCHEMA_VERSION}\n[oidc_clients.forge]\nname = \"Forge\"\nredirect_uris = [\"https://git.example.com/cb\"]\nsecret_digest = \"$pbkdf2-sha512$310000$c2FsdA$aGFzaA\"\n"
    );
    let path = Path::new("apps.toml");
    let err = state::parse_apps(path, &src).unwrap_err().to_string();
    assert!(
        err.contains("`[oidc_clients]` is not enabled in this release"),
        "{err}"
    );

    let mut file = AppsFile::default();
    file.oidc_clients.insert(id("forge"), external());
    let dir = std::env::temp_dir().join(format!("weglarka-identity-gate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let err = state::save_apps(&dir.join("apps.toml"), &file)
        .unwrap_err()
        .to_string();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(err.contains("not enabled in this release"), "{err}");
}

#[test]
fn the_gate_rejects_oidc_apps_on_load() {
    let src = format!(
        "schema_version = {SCHEMA_VERSION}\n[apps.a]\nimage = \"x:1\"\ndomains = [\"app.example.com\"]\n[apps.a.oidc]\nredirect_uris = [\"https://app.example.com/cb\"]\npublic = true\n"
    );
    let err = state::parse_apps(Path::new("apps.toml"), &src)
        .unwrap_err()
        .to_string();
    assert!(err.contains("not enabled in this release"), "{err}");
}

#[test]
fn the_gate_rejects_identity_in_the_host_config() {
    let base = r#"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
[admin]
socket = "/run/user/1001/weglarka/admin.sock"
[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.com"
"#;
    HostConfig::from_toml_str(base).unwrap().validate().unwrap();
    let with = |identity: &str| HostConfig::from_toml_str(&format!("{base}\n{identity}")).unwrap();
    let ok = "[identity]\nprovider = \"authelia\"\ninstance = \"authelia\"\nissuer = \"https://auth.example.com\"\n";
    let err = with(ok).validate().unwrap_err();
    assert_eq!(err, "`[identity]` is not enabled in this release");
    // Lexical errors come first.
    let err = with(&ok.replace("https://auth.example.com", "http://auth.example.com"))
        .validate()
        .unwrap_err();
    assert!(err.contains("issuer"), "{err}");
    // The section is closed.
    assert!(HostConfig::from_toml_str(&format!("{base}\n{ok}extra = 1\n")).is_err());
    assert!(HostConfig::from_toml_str(&format!("{base}\n[identity]\nprovider = \"keycloak\"\ninstance = \"a\"\nissuer = \"https://a.example.com\"\n")).is_err());
}

#[test]
fn static_sites_do_not_take_oidc() {
    let s = toml::from_str::<AppSpec>(&format!(
        "image = \"a.tar\"\nkind = \"static\"\ndomains = [\"app.example.com\"]\n{OIDC}"
    ))
    .unwrap();
    // The static-site rule (state.rs) and the gate both refuse it; the gate speaks first.
    assert!(gated(&s).contains("oidc"), "{}", gated(&s));
}

const BAD_HOSTS: &[&str] = &[
    "https://..",
    "https://-",
    "https://a..b/cb",
    "https://-x.example.com/cb",
    "https://x-.example.com/cb",
];

#[test]
fn malformed_dns_hosts_are_rejected_in_redirect_uris_and_audiences() {
    for bad in BAD_HOSTS {
        let mut c = external();
        c.redirect_uris = vec![(*bad).into()];
        assert!(
            validate_external_client(&id("forge"), &c)
                .unwrap_err()
                .contains("host"),
            "{bad}"
        );
        let mut c = external();
        c.audience = vec![(*bad).into()];
        assert!(
            validate_external_client(&id("forge"), &c)
                .unwrap_err()
                .contains("host"),
            "{bad}"
        );
    }
}

#[test]
fn injected_names_must_not_clash_with_the_apps_own_config() {
    let with = |extra: &str, secret: &str| {
        toml::from_str::<AppSpec>(&format!(
            "image = \"i\"\ndomains = [\"app.example.com\"]\n{extra}\n[oidc]\nredirect_uris = [\"https://app.example.com/cb\"]\nclient_secret = {secret}\n"
        ))
        .unwrap()
    };
    let env_secret = "{ kind = \"env\", var = \"OIDC_CLIENT_SECRET\" }";
    let mount_secret = "{ kind = \"mount\", path = \"/run/secrets/oidc\" }";
    lexical(&with("", env_secret)).unwrap();
    // The app's own env.
    for key in ["OIDC_CLIENT_ID", "OIDC_ISSUER", "OIDC_CLIENT_SECRET"] {
        let s = with(&format!("env = {{ {key} = \"x\" }}"), env_secret);
        assert!(
            lexical_err(&s).contains("env"),
            "{key}: {}",
            lexical_err(&s)
        );
    }
    // The app's own env-secret bindings.
    for var in ["OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"] {
        let s = with(
            &format!("secrets = [{{ secret = \"s\", kind = \"env\", var = \"{var}\" }}]"),
            env_secret,
        );
        assert!(
            lexical_err(&s).contains("environment secret"),
            "{var}: {}",
            lexical_err(&s)
        );
    }
    // The app's own mounted secret at the same path.
    let s = with(
        "secrets = [{ secret = \"s\", kind = \"mount\", path = \"/run/secrets/oidc/\" }]",
        mount_secret,
    );
    assert!(
        lexical_err(&s).contains("mounted secret"),
        "{}",
        lexical_err(&s)
    );
    // A different path is fine.
    lexical(&with(
        "secrets = [{ secret = \"s\", kind = \"mount\", path = \"/run/secrets/other\" }]",
        mount_secret,
    ))
    .unwrap();
}

#[test]
fn the_gate_speaks_before_the_lexical_rules() {
    // Lexically invalid (a bad redirect URI) and not enabled: the answer is the gate's.
    let s = spec(
        "[oidc]\nredirect_uris = [\"http://x/cb\"]\nclient_secret = { kind = \"env\", var = \"S\" }",
    );
    assert!(
        gated(&s).ends_with("is not enabled in this release"),
        "{}",
        gated(&s)
    );
}

#[test]
fn static_sites_do_not_take_forward_auth() {
    let s = spec("kind = \"static\"\n[ingress]\nauth = \"forward\"");
    assert!(lexical_err(&s).contains("static"), "{}", lexical_err(&s));
}
