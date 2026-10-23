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
    let manager_host = || {
        HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"behind\"\nbind=\"127.0.0.1:18080\"\ntraefik_dynamic_file=\"{}\"\n[admin]\nsocket=\"{}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n",
        traefik.display(),
        root.display()
    ))
    .unwrap()
    };
    let host = manager_host();
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
    // Default trust = the webhook network only, never an app network.
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    assert!(conf.contains("set_real_ip_from 10.89.0.0/24;"));
    assert_eq!(conf.matches("set_real_ip_from").count(), 1);

    // A new app with a domain: its network is connected to the running container and the config
    // is validated and reloaded — the container is NOT recreated.
    let id_before = fake.container_inspect("weglarka-nginx").await.unwrap().id;
    set_apps(&[("blog", "blog.example.eu")]);
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Reloaded)
    );
    let nginx = fake.container_inspect("weglarka-nginx").await.unwrap();
    assert_eq!(nginx.id, id_before);
    assert!(nginx.networks.contains(&"net-blog".to_owned()));
    assert_eq!(kills(&fake), 1);
    let calls = fake.calls();
    let pos = |pred: &dyn Fn(&Call) -> bool| calls.iter().position(pred).unwrap();
    let connect =
        pos(&|c| matches!(c, Call::NetworkConnect { network, .. } if network == "net-blog"));
    let test =
        pos(&|c| matches!(c, Call::ContainerExec { cmd, .. } if cmd[..2] == ["nginx", "-t"]));
    let hup = pos(&|c| matches!(c, Call::ContainerKill { signal, .. } if signal == "HUP"));
    assert!(
        connect < test && test < hup,
        "connect, then nginx -t, then HUP"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|c| matches!(c, Call::ContainerCreate(n) if n == "weglarka-nginx"))
            .count(),
        1
    );
    assert_eq!(nginx_action(manager.apply().await), None);

    // Domain change only: same set of networks → reload via HUP.
    set_apps(&[("blog", "new.example.eu")]);
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Reloaded)
    );
    assert_eq!(kills(&fake), 2);
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    assert!(conf.contains("new.example.eu") && !conf.contains("blog.example.eu"));
    assert!(
        std::fs::read_to_string(&traefik)
            .unwrap()
            .contains("new.example.eu")
    );

    // A config nginx rejects: not reloaded, previous config restored, error reported, Traefik untouched.
    let good_conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    let good_traefik = std::fs::read_to_string(&traefik).unwrap();
    fake.set_exec_exit_code("weglarka-nginx", 1);
    set_apps(&[("blog", "newer.example.eu")]);
    let err = manager.apply().await.unwrap_err();
    assert!(err.to_string().contains("nginx -t"), "{err}");
    assert_eq!(kills(&fake), 2);
    assert_eq!(
        std::fs::read_to_string(manager.conf_path()).unwrap(),
        good_conf
    );
    assert_eq!(std::fs::read_to_string(&traefik).unwrap(), good_traefik);
    assert!(manager.last_error().is_some());
    fake.set_exec_exit_code("weglarka-nginx", 0);
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Reloaded)
    );
    assert!(manager.last_error().is_none());

    // Removing the app disconnects its network, again without recreating the container.
    set_apps(&[]);
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Reloaded)
    );
    let nginx = fake.container_inspect("weglarka-nginx").await.unwrap();
    assert_eq!(nginx.id, id_before);
    assert_eq!(nginx.networks, ["net-weglarka"]);
    assert!(
        fake.calls()
            .iter()
            .any(|c| matches!(c, Call::NetworkDisconnect { network, .. } if network == "net-blog"))
    );

    // Changing the nginx image is something a live container cannot do: recreate.
    let mut host2 = manager_host();
    host2.ingress.nginx_image = "docker.io/library/nginx:2-alpine".to_owned();
    let engine2 = Arc::new(Reconciler::new(
        fake.clone(),
        Arc::new(FileSecretStore::new(root.join("secrets.toml"))),
        paths.clone(),
        ReconcilerOptions::default(),
    ));
    let manager2 = IngressManager::new(engine2, host2, root.join("nginx"));
    assert_eq!(
        nginx_action(manager2.apply().await),
        Some(NginxAction::Recreated)
    );
    assert_ne!(
        fake.container_inspect("weglarka-nginx").await.unwrap().id,
        id_before
    );

    // Container died → start (without touching the config).
    fake.crash_container("weglarka-nginx", 1);
    assert_eq!(
        nginx_action(manager2.apply().await),
        Some(NginxAction::Started)
    );
    assert!(fake.container_inspect("weglarka-nginx").await.is_ok());
    assert!(manager2.last_error().is_none());
}
