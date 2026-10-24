//! `IngressManager::apply`: when nginx is created, recreated, reloaded (HUP).

use std::sync::Arc;

use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::config::HostConfig;
use weglarka_core::podman::{PodmanClient, PodmanError};
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
    // The one container facing outside traffic is hardened (docs/decisions/0014).
    let assert_hardened = |f: &FakePodman| {
        let spec = f.container_spec("weglarka-nginx").expect("nginx container");
        assert!(spec.security.read_only, "rootfs must be read-only");
        assert_eq!(spec.security.cap_drop, ["ALL"]);
        assert_eq!(
            spec.security.cap_add,
            ["CHOWN", "SETGID", "SETUID"],
            "worker-uid drop and temp-dir chown, nothing more"
        );
        assert!(spec.security.no_new_privileges);
        assert!(spec.security.tmpfs.is_empty(), "libpod's /tmp suffices");
    };

    // Empty app set: nginx is created anyway (webhooks).
    assert_eq!(
        nginx_action(manager.apply().await),
        Some(NginxAction::Created)
    );
    assert_hardened(&fake);
    assert!(
        std::fs::read_to_string(&traefik)
            .unwrap()
            .contains("h.example.eu")
    );
    // The config rendered before the container existed could not know its addresses (bootstrap: the
    // webhook network); the same pass regenerated it and reloaded, so nothing stale is left behind.
    assert_eq!(kills(&fake), 1);
    assert_eq!(nginx_action(manager.apply().await), None);
    // Default trust = nginx's own addresses (/32), never a whole network (docs/decisions/0032).
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    let own = fake
        .container_inspect("weglarka-nginx")
        .await
        .unwrap()
        .addresses;
    assert_eq!(own.len(), 1);
    assert!(conf.contains(&format!("set_real_ip_from {}/32;", own[0])));
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
    assert_eq!(
        kills(&fake),
        3,
        "bootstrap swap + the new app (config, then its new address)"
    );
    let calls = fake.calls();
    let pos = |from: usize, pred: &dyn Fn(&Call) -> bool| {
        from + calls[from..].iter().position(pred).unwrap()
    };
    let connect = pos(
        0,
        &|c| matches!(c, Call::NetworkConnect { network, .. } if network == "net-blog"),
    );
    let test = pos(
        connect,
        &|c| matches!(c, Call::ContainerExec { cmd, .. } if cmd[..2] == ["nginx", "-t"]),
    );
    let hup = pos(
        connect,
        &|c| matches!(c, Call::ContainerKill { signal, .. } if signal == "HUP"),
    );
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
    assert_eq!(kills(&fake), 4);
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
    assert_eq!(kills(&fake), 4);
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
    // ...and the recreated container is hardened as well.
    assert_hardened(&fake);

    // Container died → start (without touching the config).
    fake.crash_container("weglarka-nginx", 1);
    assert_eq!(
        nginx_action(manager2.apply().await),
        Some(NginxAction::Started)
    );
    assert!(fake.container_inspect("weglarka-nginx").await.is_ok());
    assert!(manager2.last_error().is_none());
}

/// Regression: `apps remove` raced with `apply` — libpod failed the stale-network disconnect with
/// "no container with ID …" and the whole apply aborted before the Traefik file dropped the router.
#[tokio::test]
async fn failed_network_detach_does_not_block_traefik_file() {
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
    let mut file = state::load_apps(&paths.apps).unwrap();
    file.apps
        .insert(InstanceName::new("blog").unwrap(), spec("blog.example.eu"));
    state::save_apps(&paths.apps, &file).unwrap();
    manager.apply().await.unwrap();
    assert!(
        std::fs::read_to_string(&traefik)
            .unwrap()
            .contains("blog.example.eu")
    );

    // Remove the app while libpod fails the disconnect with a 500, as observed in CI.
    fake.fail_next_disconnect(
        "net-blog",
        PodmanError::Api {
            status: 500,
            message: "no container with ID \"abc\" found in database: no such container".into(),
        },
    );
    file.apps.clear();
    state::save_apps(&paths.apps, &file).unwrap();
    manager
        .apply()
        .await
        .expect("apply succeeds despite the failed detach");
    assert!(
        !std::fs::read_to_string(&traefik)
            .unwrap()
            .contains("blog.example.eu")
    );
    assert!(
        !std::fs::read_to_string(manager.conf_path())
            .unwrap()
            .contains("blog.example.eu")
    );
    let nginx = fake.container_inspect("weglarka-nginx").await.unwrap();
    assert!(
        nginx.networks.contains(&"net-blog".to_owned()),
        "still attached"
    );

    // The next apply (scheduled shortly by `run`) finishes the detach.
    manager.apply().await.unwrap();
    let nginx = fake.container_inspect("weglarka-nginx").await.unwrap();
    assert_eq!(nginx.networks, ["net-weglarka"]);
}

/// Regression: the rootless port forwarder dials from inside nginx's network namespace, so its source
/// is nginx's own address on *any* attached network (measured: the address on an app network, not
/// `net-weglarka`). That address must be trusted; an app container's address on the same network, and
/// the networks themselves, must not (docs/decisions/0032).
#[tokio::test]
async fn trusts_nginx_own_addresses_on_app_networks_but_not_app_containers() {
    use futures_util::StreamExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"behind\"\nbind=\"127.0.0.1:18080\"\n[admin]\nsocket=\"{}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n",
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
    let mut file = state::load_apps(&paths.apps).unwrap();
    file.apps
        .insert(InstanceName::new("blog").unwrap(), spec("blog.example.eu"));
    state::save_apps(&paths.apps, &file).unwrap();

    // The app container shares `net-blog` with nginx.
    manager.apply().await.unwrap();
    let mut pull = std::pin::pin!(fake.image_pull("ghcr.io/x/y:latest"));
    while let Some(event) = pull.next().await {
        event.unwrap();
    }
    fake.add_foreign_container("blog", "ghcr.io/x/y:latest");
    fake.network_connect("net-blog", "blog").await.unwrap();
    // The pass that joined the app network re-renders with nginx's new address in the same run.
    manager.apply().await.unwrap();
    assert_eq!(
        manager.apply().await.unwrap(),
        ApplyReport::Unchanged,
        "stable once the addresses are known"
    );

    let nginx = fake.container_inspect("weglarka-nginx").await.unwrap();
    let app = fake.container_inspect("blog").await.unwrap();
    assert_eq!(nginx.networks, ["net-blog", "net-weglarka"]);
    assert_eq!(nginx.addresses.len(), 2, "one address per attached network");
    assert_eq!(app.addresses.len(), 1);

    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    for addr in &nginx.addresses {
        assert!(
            conf.contains(&format!("set_real_ip_from {addr}/32;")),
            "{conf}"
        );
        assert!(conf.contains(&format!("{addr}/32 1;")), "{conf}");
    }
    assert_eq!(conf.matches("set_real_ip_from").count(), 2);
    let forged = app.addresses[0];
    assert!(
        !conf.contains(&forged.to_string()),
        "app container trusted: {conf}"
    );
    assert!(!conf.contains("/24"), "whole network trusted: {conf}");
}
