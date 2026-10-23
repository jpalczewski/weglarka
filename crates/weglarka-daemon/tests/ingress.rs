//! `IngressManager::apply`: when nginx is created, recreated, reloaded (HUP).

use std::sync::Arc;

use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::config::HostConfig;
use weglarka_core::podman::PodmanClient;
use weglarka_core::reconcile::{Reconciler, ReconcilerOptions};
use weglarka_core::secrets::FileSecretStore;
use weglarka_core::state::{self, StatePaths};
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::ingress::{ApplyReport, IngressManager, NginxAction};

fn spec(domain: &str) -> AppSpec {
    toml::from_str(&format!(
        "image = \"ghcr.io/x/y:latest\"\ndomains = [\"{domain}\"]\nport = 8080\n"
    ))
    .unwrap()
}

#[tokio::test]
async fn nginx_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let traefik = root.join("traefik.yml");
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"behind\"\nbind=\"127.0.0.1:18080\"\ntraefik_dynamic_file=\"{}\"\n[admin]\nsocket=\"{}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n",
        traefik.display(),
        root.display()
    ))
    .unwrap();
    let paths = StatePaths::in_dir(root);
    let fake = FakePodman::new();
    let engine = Arc::new(Reconciler::new(
        fake.clone(),
        Arc::new(FileSecretStore::new(root.join("secrets.toml"))),
        paths.clone(),
        ReconcilerOptions::default(),
    ));
    let manager = IngressManager::new(engine, host, root.join("nginx"));
    let set_apps = |apps: &[(&str, &str)]| {
        let mut file = state::load_apps(&paths.apps).unwrap();
        file.apps.clear();
        for (n, d) in apps {
            file.apps.insert(InstanceName::new(*n).unwrap(), spec(d));
        }
        state::save_apps(&paths.apps, &file).unwrap();
    };
    let kills = |f: &FakePodman| {
        f.calls()
            .iter()
            .filter(|c| matches!(c, Call::ContainerKill { signal, .. } if signal == "HUP"))
            .count()
    };
    let nginx_action = |r: Result<ApplyReport, _>| match r.unwrap() {
        ApplyReport::Changed { nginx, .. } => Some(nginx),
        ApplyReport::Unchanged => None,
    };

    // Empty app set: nginx is created anyway (webhooks).
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Created)
    );
    assert!(
        std::fs::read_to_string(&traefik)
            .unwrap()
            .contains("h.example.eu")
    );
    assert_eq!(nginx_action(manager.apply().await), None);

    // A new app with a domain = a new network = container recreation (no `network_disconnect`).
    set_apps(&[("blog", "blog.example.eu")]);
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Recreated)
    );
    assert_eq!(kills(&fake), 0);
    assert_eq!(nginx_action(manager.apply().await), None);

    // Domain change only: same set of networks → reload via HUP.
    set_apps(&[("blog", "new.example.eu")]);
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Reloaded)
    );
    assert_eq!(kills(&fake), 1);
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    assert!(conf.contains("new.example.eu") && !conf.contains("blog.example.eu"));
    assert!(
        std::fs::read_to_string(&traefik)
            .unwrap()
            .contains("new.example.eu")
    );

    // Container died → start (without touching the config).
    fake.crash_container("weglarka-nginx", 1);
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Started)
    );
    assert!(fake.container_inspect("weglarka-nginx").await.is_ok());
    assert!(manager.last_error().is_none());
}
