//! HTTP Basic auth in the ingress (issue #169, `docs/decisions/0081`): the daemon turns a named secret
//! into the `0600` credential `map` file of a protected instance, deletes the files of instances that
//! are no longer protected, reloads nginx when a credential changes (never recreates it) and reports a
//! missing or malformed secret instead of serving the app.
//!
//! `state::load_apps` still refuses `ingress.auth = "basic"` — the rollout gate of ADR 0081, lifted by a
//! later PR — so the app set goes in through `IngressManager::apply_apps` (the crate's `testing`
//! feature, dev-dependencies only) instead of `apps.toml`. Everything after the app set is the
//! production path: the same `apply`, the same renderer, the same reload.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hyper::StatusCode;
use weglarka_daemon::ingress::{ApplyReport, BasicAuthStatus, IngressManager, NginxAction};
use weglarka_engine::reconcile::{Reconciler, ReconcilerOptions};
use weglarka_engine::testing::FakePodman;
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::basic_auth;
use weglarka_model::config::HostConfig;
use weglarka_model::podman::PodmanClient;
use weglarka_model::secret_store::{SecretStore, SecretValue, scoped_name};
use weglarka_model::secrets::FileSecretStore;
use weglarka_model::state::StatePaths;

use crate::common::{Harness, admin, eventually, harness};

/// The deliberately fake credentials of the tests: never a real password, and the only value allowed
/// in a fixture. No test may show them in a log line, `nginx.conf` or a `doctor` report.
const ALICE: &str = "alice:correct-horse-battery";
const BOB: &str = "bob:hunter2-hunter2-hunter2";
/// The `ingress.auth_secret` name both apps use.
const SECRET: &str = "basic-auth";
const HOST: &str = "hooks.example.eu";

/// An app protected by a shared credential (ADR 0081).
fn protected(domain: &str, secret: &str) -> AppSpec {
    toml::from_str(&format!(
        "image = \"ghcr.io/x/y:latest\"\ndomains = [\"{domain}\"]\nport = 8080\n\n\
         [ingress]\nauth = \"basic\"\nauth_secret = \"{secret}\"\n"
    ))
    .unwrap()
}

/// An app without auth: unprotecting one must delete its map file.
fn plain(domain: &str) -> AppSpec {
    toml::from_str(&format!(
        "image = \"ghcr.io/x/y:latest\"\ndomains = [\"{domain}\"]\nport = 8080\n"
    ))
    .unwrap()
}

fn apps(specs: Vec<(&str, AppSpec)>) -> BTreeMap<InstanceName, AppSpec> {
    specs
        .into_iter()
        .map(|(name, spec)| (InstanceName::new(name).unwrap(), spec))
        .collect()
}

fn name(instance: &str) -> InstanceName {
    InstanceName::new(instance).unwrap()
}

/// An `IngressManager` on a temp dir, with the store it was built with (so a test can set the secret
/// the daemon reads) and no daemon around it.
struct Fixture {
    _dir: tempfile::TempDir,
    fake: FakePodman,
    secrets: Arc<FileSecretStore>,
    manager: IngressManager<FakePodman>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        let host = HostConfig::from_toml_str(&format!(
            "[ingress]\nmode=\"behind\"\nbind=\"127.0.0.1:18080\"\n[admin]\nsocket=\"{root}/a.sock\"\n\
             [webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"{HOST}\"\n",
            root = root.display()
        ))
        .unwrap();
        let fake = FakePodman::new();
        // One store for the engine and the ingress manager, as in `start_with`.
        let secrets = Arc::new(FileSecretStore::new(root.join("secrets.toml")));
        let engine = Arc::new(Reconciler::new(
            fake.clone(),
            secrets.clone(),
            StatePaths::in_dir(&root),
            ReconcilerOptions::default(),
        ));
        let manager = IngressManager::new(
            engine,
            host,
            root.join("nginx"),
            root.join("ingress-logs"),
            secrets.clone(),
        );
        Self {
            _dir: dir,
            fake,
            secrets,
            manager,
        }
    }

    fn set_secret(&self, instance: &str, value: &str) {
        self.secrets
            .set(
                &scoped_name(&name(instance), SECRET),
                SecretValue::new(value),
            )
            .unwrap();
    }

    fn auth_dir(&self) -> PathBuf {
        self.manager.auth_dir()
    }

    fn map(&self, instance: &str) -> PathBuf {
        self.auth_dir().join(format!("{instance}.map"))
    }

    /// A map file of an earlier run, private like the real one.
    fn write_stale_map(&self, instance: &str) {
        let dir = self.auth_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(self.map(instance), "\"Basic c3RhbGU=\" 1;\n").unwrap();
        std::fs::set_permissions(self.map(instance), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    fn conf(&self) -> String {
        std::fs::read_to_string(self.manager.conf_path()).unwrap_or_default()
    }

    /// Applies twice, so the nginx addresses and the container are settled, and returns the third
    /// (stable) report.
    async fn settle(&self, apps: &BTreeMap<InstanceName, AppSpec>) -> ApplyReport {
        self.manager.apply_apps(apps.clone()).await.unwrap();
        self.manager.apply_apps(apps.clone()).await.unwrap();
        self.manager.apply_apps(apps.clone()).await.unwrap()
    }

    fn hups(&self) -> usize {
        use weglarka_engine::testing::Call;
        self.fake
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::ContainerKill { signal, .. } if signal == "HUP"))
            .count()
    }
}

fn action(report: ApplyReport) -> Option<NginxAction> {
    match report {
        ApplyReport::Changed { nginx, .. } => Some(nginx),
        ApplyReport::Unchanged => None,
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The base64 payloads of the map file's `"~^Basic <base64>$"` keys, i.e. the password-equivalent
/// material that must never leave it.
fn payloads(map_lines: &str) -> Vec<String> {
    map_lines
        .lines()
        .map(|line| {
            line.trim_start_matches("\"~^Basic ")
                .trim_end_matches("$\" 1;")
                .replace("[+]", "+")
        })
        .collect()
}

fn map_lines(value: &str) -> String {
    basic_auth::parse(value.as_bytes())
        .expect("valid credentials")
        .nginx_map_lines()
}

#[tokio::test]
async fn writes_a_private_map_file_with_every_credential() {
    let f = Fixture::new();
    let credentials = format!("{ALICE}\n{BOB}\n");
    f.set_secret("blog", &credentials);
    let apps = apps(vec![("blog", protected("blog.example.org", SECRET))]);

    assert_eq!(
        action(f.manager.apply_apps(apps.clone()).await.unwrap()),
        Some(NginxAction::Created)
    );
    assert_eq!(
        mode(&f.auth_dir()),
        0o700,
        "the map directory is the master's alone"
    );
    assert_eq!(
        mode(&f.map("blog")),
        0o600,
        "credentials are not world-readable"
    );
    let expected = map_lines(&credentials);
    assert_eq!(std::fs::read_to_string(f.map("blog")).unwrap(), expected);

    let conf = f.conf();
    assert!(
        conf.contains("include /etc/nginx/auth/blog.map;"),
        "the include names the file, never a credential: {conf}"
    );
    assert!(conf.contains("if ($weglarka_basic_ok_"), "{conf}");
    assert!(!conf.contains("return 503;"), "the route is served: {conf}");
    // Neither the password nor the base64 it becomes is rendered into the 0644 config.
    assert!(!conf.contains("correct-horse-battery"), "{conf}");
    for payload in payloads(&expected) {
        assert!(!conf.contains(&payload), "{conf}");
    }

    // The same secret twice writes nothing and reloads nothing.
    assert_eq!(f.settle(&apps).await, ApplyReport::Unchanged);
}

#[tokio::test]
async fn a_missing_secret_fails_closed_and_deletes_the_stale_file() {
    let f = Fixture::new();
    f.write_stale_map("blog");
    let apps = apps(vec![("blog", protected("blog.example.org", SECRET))]);

    f.manager.apply_apps(apps).await.unwrap();

    assert!(
        !f.map("blog").exists(),
        "a file from an earlier run must not survive a missing secret"
    );
    let conf = f.conf();
    assert!(conf.contains("return 503;"), "{conf}");
    assert!(!conf.contains("/etc/nginx/auth/"), "{conf}");

    let status = f.manager.basic_auth_status();
    assert_eq!(status.protected, BTreeSet::from([name("blog")]));
    let problem = &status.problems[&name("blog")];
    assert_eq!(problem.secret, SECRET, "the name, never the value");
    assert!(
        problem.reason.contains("not set"),
        "the reason says the secret is missing: {problem:?}"
    );
}

#[tokio::test]
async fn an_empty_or_malformed_secret_behaves_like_a_missing_one() {
    let f = Fixture::new();
    let apps = apps(vec![("blog", protected("blog.example.org", SECRET))]);

    // An empty value parses to no credential at all: the route must not go live for nobody.
    f.set_secret("blog", "");
    f.manager.apply_apps(apps.clone()).await.unwrap();
    assert!(!f.map("blog").exists());
    assert!(f.conf().contains("return 503;"), "{}", f.conf());
    assert_eq!(
        f.manager.basic_auth_status().problems[&name("blog")].reason,
        "the secret declares no credential"
    );

    // A malformed line is a parse error naming the line and nothing else.
    f.set_secret("blog", "alice:short\n");
    f.manager.apply_apps(apps).await.unwrap();
    assert!(!f.map("blog").exists());
    let problem = f.manager.basic_auth_status().problems[&name("blog")].clone();
    assert!(problem.reason.starts_with("line 1:"), "{problem:?}");
    assert!(!problem.reason.contains("short"), "{problem:?}");
}

#[tokio::test]
async fn a_changed_credential_reloads_nginx_without_recreating_it() {
    let f = Fixture::new();
    f.set_secret("blog", ALICE);
    let apps = apps(vec![("blog", protected("blog.example.org", SECRET))]);
    f.settle(&apps).await;
    assert_eq!(
        std::fs::read_to_string(f.map("blog")).unwrap(),
        map_lines(ALICE)
    );
    let conf_before = f.conf();
    let id_before = f.fake.container_inspect("weglarka-nginx").await.unwrap().id;
    let hups_before = f.hups();

    let changed = format!("{ALICE}\n{BOB}\n");
    f.set_secret("blog", &changed);
    let report = f.manager.apply_apps(apps).await.unwrap();

    // `nginx.conf` is byte for byte the same — the credentials are never fingerprinted into a 0644
    // file — so the reload has to come from the map file itself.
    match report {
        ApplyReport::Changed {
            conf_written,
            nginx,
            ..
        } => {
            assert!(!conf_written, "nginx.conf must not change");
            assert_eq!(nginx, NginxAction::Reloaded);
        }
        other => panic!("expected a reload, got {other:?}"),
    }
    assert_eq!(f.conf(), conf_before, "no credential in nginx.conf");
    assert_eq!(
        f.fake.container_inspect("weglarka-nginx").await.unwrap().id,
        id_before,
        "a credential change never recreates the container"
    );
    assert_eq!(f.hups(), hups_before + 1, "nginx -t + SIGHUP");
    assert_eq!(
        std::fs::read_to_string(f.map("blog")).unwrap(),
        map_lines(&changed)
    );
    assert_eq!(mode(&f.map("blog")), 0o600);
}

#[tokio::test]
async fn unprotecting_the_app_deletes_its_map_file() {
    let f = Fixture::new();
    f.set_secret("blog", ALICE);
    // A second protected app keeps its own file: only the unprotected one goes.
    f.set_secret("docs", BOB);
    let both = apps(vec![
        ("blog", protected("blog.example.org", SECRET)),
        ("docs", protected("docs.example.org", SECRET)),
    ]);
    f.settle(&both).await;
    assert!(f.map("blog").exists() && f.map("docs").exists());

    let unprotected = apps(vec![
        ("blog", plain("blog.example.org")),
        ("docs", protected("docs.example.org", SECRET)),
    ]);
    assert_eq!(
        action(f.manager.apply_apps(unprotected).await.unwrap()),
        Some(NginxAction::Reloaded)
    );
    assert!(
        !f.map("blog").exists(),
        "stale credentials must not survive"
    );
    assert!(f.map("docs").exists());
    let conf = f.conf();
    assert!(!conf.contains("/etc/nginx/auth/blog.map;"), "{conf}");
    assert!(conf.contains("/etc/nginx/auth/docs.map;"), "{conf}");

    // Removing the last protected app leaves no map file behind either.
    let none = apps(vec![("blog", plain("blog.example.org"))]);
    f.manager.apply_apps(none).await.unwrap();
    assert!(!f.map("docs").exists());
    assert_eq!(f.manager.basic_auth_status(), BasicAuthStatus::default());
}

/// A tracing sink that collects everything the daemon logs, to search it for credentials.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap_or_default()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

#[tokio::test]
async fn no_credential_reaches_a_log_line_or_the_config() {
    let logs = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );
    let f = Fixture::new();
    let credentials = format!("{ALICE}\n{BOB}\n");
    f.set_secret("blog", &credentials);
    let apps = apps(vec![
        ("blog", protected("blog.example.org", SECRET)),
        // A second protected app without its secret: the failure path logs too.
        ("docs", protected("docs.example.org", "docs-auth")),
    ]);
    f.manager.apply_apps(apps.clone()).await.unwrap();
    f.set_secret("blog", ALICE);
    f.manager.apply_apps(apps).await.unwrap();

    let logged = logs.text();
    let conf = f.conf();
    // The failure path is logged, naming the instance and the secret **name** only.
    assert!(
        logged.contains("docs") && logged.contains("docs.docs-auth"),
        "{logged}"
    );
    assert!(
        logged.contains("no basic auth credentials"),
        "the missing credential is logged: {logged}"
    );
    for payload in payloads(&map_lines(&credentials))
        .into_iter()
        .chain(payloads(&map_lines(ALICE)))
    {
        assert!(
            !logged.contains(&payload),
            "a credential in a log line: {logged}"
        );
        assert!(
            !conf.contains(&payload),
            "a credential in nginx.conf: {conf}"
        );
    }
    for password in ["correct-horse-battery", "hunter2-hunter2-hunter2"] {
        assert!(
            !logged.contains(password),
            "a password in a log line: {logged}"
        );
    }
    assert_eq!(
        f.manager.basic_auth_status().problems[&name("docs")].secret,
        "docs-auth"
    );
}

/// The daemon's doctor check `ingress.basic_auth` (ADR 0081): absent without basic auth, failing (and
/// naming the secret) when the credential is missing, ok once every protected app has its file.
#[tokio::test]
async fn doctor_reports_the_basic_auth_state_of_every_protected_app() {
    let h = harness().await;
    // Nothing uses `auth = "basic"`: no check at all.
    assert!(doctor_check(&h).await.is_none(), "{}", doctor(&h).await);

    // The daemon's own first ingress pass must be the one before the test's, so the status below is
    // the last word on the subject (the loop then sleeps for 60 s).
    eventually("the daemon's ingress pass", || async {
        h.fake.container_inspect("weglarka-nginx").await.is_ok()
    })
    .await;
    let protected_apps = apps(vec![("docs", protected("docs.example.org", SECRET))]);
    h.running
        .daemon
        .ingress
        .apply_apps(protected_apps.clone())
        .await
        .unwrap();

    let missing = doctor_check(&h)
        .await
        .expect("a check for the protected app");
    assert_eq!(missing["status"], "fail", "{missing}");
    let message = missing["message"].as_str().unwrap();
    assert!(message.contains("docs"), "{message}");
    assert!(
        message.contains(SECRET),
        "the secret is named, not valued: {message}"
    );
    assert!(message.contains("not set"), "{message}");
    assert!(
        missing["hint"]
            .as_str()
            .unwrap()
            .contains("weglarka secrets set"),
        "{missing}"
    );

    // The operator sets the secret: the same apply path now has a map file for every app.
    h.running
        .daemon
        .secrets
        .set(
            &scoped_name(&name("docs"), SECRET),
            SecretValue::new(format!("{ALICE}\n")),
        )
        .unwrap();
    h.running
        .daemon
        .ingress
        .apply_apps(protected_apps)
        .await
        .unwrap();
    let ready = doctor_check(&h)
        .await
        .expect("a check for the protected app");
    assert_eq!(ready["status"], "ok", "{ready}");
    assert!(
        ready["message"].as_str().unwrap().contains("docs"),
        "{ready}"
    );
    h.running.stop().await;
}

async fn doctor(h: &Harness) -> serde_json::Value {
    let (status, report) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    report
}

/// The `ingress.basic_auth` check of a `GET /v1/doctor` answer.
async fn doctor_check(h: &Harness) -> Option<serde_json::Value> {
    let report = doctor(h).await;
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "ingress.basic_auth")
        .cloned()
}
