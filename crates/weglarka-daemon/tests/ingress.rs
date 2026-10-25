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

/// `edge` (issue #95): two publishes on the host (8080/8443 inside), the ingress uid map that lets the
/// TLS master read the daemon's `0600` keys, certificates rescanned on every pass and a renewal that
/// only reloads nginx.
#[tokio::test]
async fn edge_publishes_tls_and_reloads_on_a_certificate_change() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"edge\"\nbind=\"127.0.0.1:18080\"\nhttps_bind=\"127.0.0.1:18443\"\n[admin]\nsocket=\"{}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n",
        root.display()
    ))
    .unwrap();
    // The same validation the daemon runs at startup.
    host.validate().unwrap();
    let paths = StatePaths::in_dir(root);
    let fake = FakePodman::new();
    seed_own_container(&fake).await;
    let engine = Arc::new(Reconciler::new(
        fake.clone(),
        Arc::new(FileSecretStore::new(root.join("secrets.toml"))),
        paths.clone(),
        ReconcilerOptions::default(),
    ));
    let manager = IngressManager::new(engine, host, root.join("nginx"));
    let action = |r: Result<ApplyReport, _>| match r.unwrap() {
        ApplyReport::Changed { nginx, .. } => Some(nginx),
        ApplyReport::Unchanged => None,
    };
    let id = |f: &FakePodman| f.container_spec("weglarka-nginx").unwrap();

    // Webhook only: nginx still publishes both ports and starts with a TLS listener that refuses
    // every SNI, because no certificate exists yet.
    assert_eq!(action(manager.apply().await), Some(NginxAction::Created));
    let spec = id(&fake);
    // The forwarder owns the public sockets (issue #162); nginx publishes nothing.
    assert!(spec.publish.is_empty(), "{:?}", spec.publish);
    let publishes: Vec<(u16, u16)> = fake
        .container_spec("weglarka-forwarder")
        .unwrap()
        .publish
        .iter()
        .map(|p| (p.host_port, p.container_port))
        .collect();
    assert_eq!(publishes, [(18080, 8080), (18443, 8443)]);
    let map = spec.id_mapping.as_ref().expect("explicit ingress map");
    assert_eq!(map.uid_map[0].container_id, 0);
    assert_eq!(map.uid_map[0].host_id, 0, "container root is the host user");
    assert_eq!(map.uid_map[1].container_id, 1);
    assert!(
        map.uid_map[1].host_id > 0,
        "worker stays in the ingress range"
    );
    // No Traefik file in edge, and the certificate directories exist with the documented modes.
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    assert!(conf.contains("listen 8443 ssl default_server;"), "{conf}");
    assert!(conf.contains("ssl_reject_handshake on;"), "{conf}");
    assert!(!conf.contains("ssl_certificate "), "{conf}");
    // Only the forwarder's unix socket is trusted to announce the client (PROXY protocol).
    assert!(conf.contains("set_real_ip_from unix:;"), "{conf}");
    assert_eq!(conf.matches("set_real_ip_from").count(), 1, "{conf}");
    assert!(
        conf.contains(
            "listen unix:/run/weglarka-ingress/https.sock ssl default_server proxy_protocol;"
        ),
        "{conf}"
    );
    let tls = manager.tls_dir();
    let acme = manager.acme_dir();
    assert_eq!(
        std::fs::metadata(&tls).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&acme).unwrap().permissions().mode() & 0o777,
        0o755
    );

    // A certificate for the webhook domain: the config gains its TLS server and nginx reloads
    // (`nginx -t` + SIGHUP), the container is not recreated.
    let nginx_id = fake.container_inspect("weglarka-nginx").await.unwrap().id;
    let write_pair = |domain: &str, body: &str| {
        std::fs::write(tls.join(format!("{domain}.crt")), body).unwrap();
        std::fs::write(tls.join(format!("{domain}.key")), body).unwrap();
        for suffix in ["crt", "key"] {
            std::fs::set_permissions(
                tls.join(format!("{domain}.{suffix}")),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
    };
    write_pair("h.example.eu", "cert-1\n");
    assert_eq!(action(manager.apply().await), Some(NginxAction::Reloaded));
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    assert!(
        conf.contains("ssl_certificate /etc/nginx/tls/h.example.eu.crt;"),
        "{conf}"
    );
    assert_eq!(
        fake.container_inspect("weglarka-nginx").await.unwrap().id,
        nginx_id
    );

    // Renewal changes the material only: the fingerprint comment makes the config differ, so the same
    // reload path runs (no recreate, no manual step for #96).
    let old = conf
        .lines()
        .find(|l| l.starts_with("# tls material: fingerprint "))
        .expect("fingerprint comment")
        .to_owned();
    write_pair("h.example.eu", "cert-2-renewed\n");
    assert_eq!(action(manager.apply().await), Some(NginxAction::Reloaded));
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    let new = conf
        .lines()
        .find(|l| l.starts_with("# tls material: fingerprint "))
        .expect("fingerprint comment")
        .to_owned();
    assert_ne!(old, new, "a renewed certificate must re-render the config");
    assert_eq!(
        fake.container_inspect("weglarka-nginx").await.unwrap().id,
        nginx_id
    );

    // A certificate without its key is ignored; the domain keeps its redirect and loses TLS.
    std::fs::remove_file(tls.join("h.example.eu.key")).unwrap();
    assert_eq!(action(manager.apply().await), Some(NginxAction::Reloaded));
    let conf = std::fs::read_to_string(manager.conf_path()).unwrap();
    assert!(!conf.contains("ssl_certificate "), "{conf}");
    assert!(
        conf.contains("return 301 https://$host$request_uri;"),
        "{conf}"
    );
    // Removing the stray file is not a change.
    std::fs::remove_file(tls.join("h.example.eu.crt")).unwrap();
    assert_eq!(action(manager.apply().await), None);
}

/// `edge` (issue #97): a wildcard pair (`_wildcard.<apex>.crt|key`) in the TLS directory serves the
/// covered domains; it is picked up like any certificate (reload, never a recreate), and a stray or
/// half-present pair serves nothing.
#[tokio::test]
async fn edge_serves_covered_domains_with_a_wildcard_pair() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"edge\"\nbind=\"127.0.0.1:18080\"\nhttps_bind=\"127.0.0.1:18443\"\n[admin]\nsocket=\"{}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n",
        root.display()
    ))
    .unwrap();
    host.validate().unwrap();
    let paths = StatePaths::in_dir(root);
    let fake = FakePodman::new();
    seed_own_container(&fake).await;
    let engine = Arc::new(Reconciler::new(
        fake.clone(),
        Arc::new(FileSecretStore::new(root.join("secrets.toml"))),
        paths.clone(),
        ReconcilerOptions::default(),
    ));
    let manager = IngressManager::new(engine, host, root.join("nginx"));
    let reloaded = |r: Result<ApplyReport, _>| {
        matches!(
            r.unwrap(),
            ApplyReport::Changed {
                nginx: NginxAction::Reloaded,
                ..
            }
        )
    };
    manager.apply().await.unwrap();
    let nginx_id = fake.container_inspect("weglarka-nginx").await.unwrap().id;
    let tls = manager.tls_dir();
    let write_file = |name: &str| {
        let path = tls.join(name);
        std::fs::write(&path, "pem\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    let conf = || std::fs::read_to_string(manager.conf_path()).unwrap();

    // A wildcard for another apex covers nothing; so do half a pair and names that are no apex.
    write_file("_wildcard.example.org.crt");
    write_file("_wildcard.example.org.key");
    write_file("_wildcard.example.eu.crt"); // no key yet
    write_file("_wildcard..crt");
    write_file("_wildcard.Not A Domain.crt");
    write_file("_wildcard.Not A Domain.key");
    manager.apply().await.unwrap();
    assert!(!conf().contains("h.example.eu.crt"), "{}", conf());
    assert!(
        !conf().contains("ssl_certificate /etc/nginx/tls/h.example.eu"),
        "{}",
        conf()
    );

    // The matching pair appears: the webhook domain (one label below the apex) is served with it.
    write_file("_wildcard.example.eu.key");
    assert!(reloaded(manager.apply().await));
    let c = conf();
    assert!(
        c.contains("ssl_certificate /etc/nginx/tls/_wildcard.example.eu.crt;"),
        "{c}"
    );
    assert!(
        c.contains("ssl_certificate_key /etc/nginx/tls/_wildcard.example.eu.key;"),
        "{c}"
    );
    assert!(!c.contains("example.org"), "{c}");
    assert_eq!(
        fake.container_inspect("weglarka-nginx").await.unwrap().id,
        nginx_id,
        "a wildcard never recreates the container"
    );
    assert_eq!(manager.apply().await.unwrap(), ApplyReport::Unchanged);

    // The domain's own pair wins over the wildcard.
    write_file("h.example.eu.crt");
    write_file("h.example.eu.key");
    assert!(reloaded(manager.apply().await));
    let c = conf();
    assert!(
        c.contains("ssl_certificate /etc/nginx/tls/h.example.eu.crt;"),
        "{c}"
    );
    assert!(!c.contains("_wildcard.example.eu.crt"), "{c}");

    // Without the wildcard key the (own-pair-less) domain loses TLS again.
    std::fs::remove_file(tls.join("h.example.eu.crt")).unwrap();
    std::fs::remove_file(tls.join("h.example.eu.key")).unwrap();
    std::fs::remove_file(tls.join("_wildcard.example.eu.key")).unwrap();
    assert!(reloaded(manager.apply().await));
    assert!(!conf().contains("ssl_certificate "), "{}", conf());
}

/// `edge` behind a CDN (issue #159): the refreshed range list is rendered with its etag, a new etag
/// takes the reload path and never recreates nginx, and a rejected refresh leaves the config alone.
#[tokio::test]
async fn edge_cdn_ranges_refresh_reloads_and_never_recreates() {
    use weglarka_daemon::cdn::{CdnRanges, Fetched, RangeFetcher};

    struct Scripted(std::sync::Mutex<Vec<Result<Fetched, String>>>);
    impl RangeFetcher for Scripted {
        async fn fetch(&self) -> Result<Fetched, String> {
            self.0.lock().unwrap().remove(0)
        }
    }
    let list = |extra: &str| -> Vec<String> {
        weglarka_ingress::CLOUDFLARE_RANGES
            .iter()
            .map(|r| (*r).to_owned())
            .chain(std::iter::once(extra.to_owned()))
            .collect()
    };

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"edge\"\nbind=\"127.0.0.1:18080\"\nhttps_bind=\"127.0.0.1:18443\"\n\
         [ingress.cdn]\nprovider=\"cloudflare\"\n\
         [admin]\nsocket=\"{}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n",
        root.display()
    ))
    .unwrap();
    host.validate().unwrap();
    let fake = FakePodman::new();
    seed_own_container(&fake).await;
    let engine = Arc::new(Reconciler::new(
        fake.clone(),
        Arc::new(FileSecretStore::new(root.join("secrets.toml"))),
        StatePaths::in_dir(root),
        ReconcilerOptions::default(),
    ));
    let manager = IngressManager::new(engine, host, root.join("nginx"));
    let ranges = Arc::new(CdnRanges::load(
        weglarka_core::config::CdnProvider::Cloudflare,
        root.join("cdn-ranges.toml"),
    ));
    manager.set_cdn_ranges(ranges.clone());
    let conf = || std::fs::read_to_string(manager.conf_path()).unwrap();

    manager.apply().await.unwrap();
    assert!(conf().contains("# CDN peers (bundled etag "), "{}", conf());
    let nginx_id = fake.container_inspect("weglarka-nginx").await.unwrap().id;

    let fetcher = Scripted(std::sync::Mutex::new(vec![
        Ok(("new1".into(), list("198.51.100.0/24"))),
        Ok(("bad".into(), vec!["198.51.100.0/24".into()])),
    ]));
    assert_eq!(ranges.refresh(&fetcher).await, Ok(true));
    assert!(matches!(
        manager.apply().await.unwrap(),
        ApplyReport::Changed {
            nginx: NginxAction::Reloaded,
            ..
        }
    ));
    let c = conf();
    assert!(c.contains("# CDN peers (refreshed etag new1)"), "{c}");
    assert!(c.contains("198.51.100.0/24 1;"), "{c}");
    assert_eq!(
        fake.container_inspect("weglarka-nginx").await.unwrap().id,
        nginx_id,
        "a new list never recreates the container"
    );

    // An implausible list is refused: the config stays as it is.
    assert!(ranges.refresh(&fetcher).await.is_err());
    assert_eq!(manager.apply().await.unwrap(), ApplyReport::Unchanged);
}

/// The daemon's own container: the `edge` forwarder runs from its image (issue #162).
async fn seed_own_container(fake: &FakePodman) {
    let mut pull = std::pin::pin!(fake.image_pull("ghcr.io/jpalczewski/weglarka:test"));
    while let Some(event) = futures_util::StreamExt::next(&mut pull).await {
        event.unwrap();
    }
    fake.add_foreign_container("weglarka", "ghcr.io/jpalczewski/weglarka:test");
}

/// Issue #183: a daemon self-update changes the image the forwarder could run from, but the forwarder
/// owns the public ports, so it must not be recreated for that; a real identity change (here the
/// published address) still recreates it and records the spec it was built from.
#[tokio::test]
async fn edge_self_update_keeps_the_forwarder_and_a_changed_publish_replaces_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let host_for = |https: &str| {
        let host = HostConfig::from_toml_str(&format!(
            "[ingress]\nmode=\"edge\"\nbind=\"127.0.0.1:18080\"\nhttps_bind=\"{https}\"\n[admin]\nsocket=\"{}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n",
            root.display()
        ))
        .unwrap();
        host.validate().unwrap();
        host
    };
    let fake = FakePodman::new();
    seed_own_container(&fake).await;
    let manager_for = |host: HostConfig| {
        let engine = Arc::new(Reconciler::new(
            fake.clone(),
            Arc::new(FileSecretStore::new(root.join("secrets.toml"))),
            StatePaths::in_dir(root),
            ReconcilerOptions::default(),
        ));
        IngressManager::new(engine, host, root.join("nginx"))
    };
    let manager = manager_for(host_for("127.0.0.1:18443"));
    manager.apply().await.unwrap();
    let forwarder = fake.container_inspect("weglarka-forwarder").await.unwrap();
    let spec = fake.container_spec("weglarka-forwarder").unwrap();
    assert!(spec.labels.contains_key("weglarka.ingress-spec"));

    // Self-update: the daemon's own container now runs another image.
    fake.container_remove("weglarka", true).await.unwrap();
    let mut pull = std::pin::pin!(fake.image_pull("ghcr.io/jpalczewski/weglarka:next"));
    while let Some(event) = futures_util::StreamExt::next(&mut pull).await {
        event.unwrap();
    }
    fake.add_foreign_container("weglarka", "ghcr.io/jpalczewski/weglarka:next");
    manager.apply().await.unwrap();
    assert_eq!(
        fake.container_inspect("weglarka-forwarder")
            .await
            .unwrap()
            .id,
        forwarder.id,
        "a self-update must not close the public ports"
    );

    // A changed publish is a real identity change.
    let manager = manager_for(host_for("127.0.0.1:18444"));
    manager.apply().await.unwrap();
    assert_ne!(
        fake.container_inspect("weglarka-forwarder")
            .await
            .unwrap()
            .id,
        forwarder.id
    );
}
