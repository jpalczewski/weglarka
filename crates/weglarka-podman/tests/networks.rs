//! Shared networks against a real rootless Podman 6 (CI job `integration-podman`, issue #128,
//! `docs/decisions/0030-shared-networks.md`). Requires `WEGLARKA_PODMAN_SOCKET`; skipped without it
//! (docs/decisions/0002-podman-in-ci.md).
//!
//! Acceptance of the issue: two containers in the same group resolve each other by name (and by an
//! alias) and connect over TCP, a container outside the group cannot reach them, and removing one
//! member leaves the others working. The group network is `internal`, which must not break the
//! aardvark DNS of a rootless netavark network — that is what this test pins down.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use weglarka_core::app::Resources;
use weglarka_core::labels;
use weglarka_core::podman::{ContainerSpec, NetworkSpec, PodmanClient, RestartPolicy};
use weglarka_podman::LibpodClient;

const BUSYBOX: &str = "docker.io/library/busybox:latest";

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{}", std::process::id(), nanos % 1_000_000_000)
}

fn raw(socket: &str, method: &str, path: &str) {
    let _ = Command::new("curl")
        .args(["-sS", "--unix-socket", socket, "-X", method])
        .arg(format!("http://d/v6.0.0/libpod{path}"))
        .output();
}

struct Cleanup {
    socket: String,
    containers: Vec<String>,
    networks: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &self.containers {
            raw(
                &self.socket,
                "DELETE",
                &format!("/containers/{c}?force=true&v=true"),
            );
        }
        for n in &self.networks {
            raw(&self.socket, "DELETE", &format!("/networks/{n}?force=true"));
        }
    }
}

fn spec(
    name: &str,
    networks: &[&str],
    aliases: &[(&str, &[&str])],
    command: &[&str],
) -> ContainerSpec {
    ContainerSpec {
        name: name.into(),
        image: BUSYBOX.into(),
        command: command.iter().map(|s| (*s).to_owned()).collect(),
        entrypoint: None,
        labels: BTreeMap::new(),
        env: BTreeMap::new(),
        networks: networks.iter().map(|s| (*s).to_owned()).collect(),
        network_aliases: aliases
            .iter()
            .map(|(n, a)| ((*n).to_owned(), a.iter().map(|s| (*s).to_owned()).collect()))
            .collect(),
        secrets: vec![],
        publish: vec![],
        restart: RestartPolicy::No,
        userns_auto: true,
        mounts: vec![],
        volumes: vec![],
        resources: Resources::default(),
        healthcheck: None,
        id_mapping: None,
        keep_groups: false,
        security: Default::default(),
    }
}

fn network(name: &str, internal: bool) -> NetworkSpec {
    NetworkSpec {
        name: name.into(),
        internal,
        labels: BTreeMap::from([(labels::SHARED_NETWORK.into(), "it".into())]),
    }
}

/// Exit code of `nc -w 2 <host> 8080` run inside `from`: 0 = connected.
async fn connect(client: &LibpodClient, from: &str, host: &str) -> i32 {
    let cmd = ["nc", "-w", "2", host, "8080"].map(str::to_owned);
    client.container_exec(from, &cmd).await.unwrap()
}

/// Retries until the listener of `server` answers (it starts asynchronously).
async fn wait_for_listener(client: &LibpodClient, from: &str, host: &str) {
    for _ in 0..20 {
        if connect(client, from, host).await == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{from} never reached {host}:8080");
}

#[tokio::test]
async fn group_members_resolve_each_other_and_outsiders_cannot() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let group = format!("net-shared-it-{id}");
    let own = |n: &str| format!("net-it-{n}-{id}");
    let (srv, peer, outsider) = (
        format!("it-srv-{id}"),
        format!("it-peer-{id}"),
        format!("it-out-{id}"),
    );
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![srv.clone(), peer.clone(), outsider.clone()],
        networks: vec![group.clone(), own("srv"), own("peer"), own("out")],
    };
    let events: Vec<_> = client.image_pull(BUSYBOX).collect().await;
    assert!(events.last().is_some_and(Result::is_ok), "{events:?}");

    // The group network is internal, exactly as the deploy creates it; each member also keeps a
    // normal per-app network of its own.
    client.network_create(&network(&group, true)).await.unwrap();
    for n in ["srv", "peer", "out"] {
        client
            .network_create(&network(&own(n), false))
            .await
            .unwrap();
    }

    let alias = format!("gateway-{id}");
    let server_cmd = ["sh", "-c", "while true; do echo hi | nc -l -p 8080; done"];
    client
        .container_create(&spec(
            &srv,
            &[&own("srv"), &group],
            &[(&group, &[&alias])],
            &server_cmd,
        ))
        .await
        .unwrap();
    client
        .container_create(&spec(
            &peer,
            &[&own("peer"), &group],
            &[],
            &["sleep", "300"],
        ))
        .await
        .unwrap();
    client
        .container_create(&spec(&outsider, &[&own("out")], &[], &["sleep", "300"]))
        .await
        .unwrap();
    for c in [&srv, &peer, &outsider] {
        client.container_start(c).await.unwrap();
    }

    // Same group: by the container name and by the declared alias.
    wait_for_listener(&client, &peer, &srv).await;
    assert_eq!(connect(&client, &peer, &alias).await, 0, "alias resolves");

    // Outside the group: the name does not resolve, so there is no connection.
    assert_ne!(connect(&client, &outsider, &srv).await, 0);
    assert_ne!(connect(&client, &outsider, &alias).await, 0);

    // Removing one member leaves the others working.
    client.container_stop(&peer, 1).await.unwrap();
    client.container_remove(&peer, true).await.unwrap();
    client
        .container_create(&spec(
            &peer,
            &[&own("peer"), &group],
            &[],
            &["sleep", "300"],
        ))
        .await
        .unwrap();
    client.container_start(&peer).await.unwrap();
    wait_for_listener(&client, &peer, &srv).await;
}
