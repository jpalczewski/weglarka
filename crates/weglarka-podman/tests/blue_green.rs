//! The Podman-level assumptions of a blue-green swap (issue #39, `docs/decisions/0046-blue-green-deploy.md`)
//! against a real rootless Podman 6. Requires `WEGLARKA_PODMAN_SOCKET`; skipped without it
//! (docs/decisions/0002-podman-in-ci.md).
//!
//! The sequence under test is the engine's: the challenger starts on a staging network, joins the app
//! network with the instance alias, the names are swapped, and the old container stops.

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
        keep_groups: false,
        volumes: vec![],
        resources: Resources::default(),
        healthcheck: None,
        id_mapping: None,
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
async fn the_alias_moves_to_the_challenger_and_survives_the_swap() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let (app_net, staging) = (format!("net-bg-{id}"), format!("net-bg-{id}.next"));
    let (old, next, retiring, probe) = (
        format!("bg-{id}"),
        format!("bg-{id}.next"),
        format!("bg-{id}.prev"),
        format!("bg-probe-{id}"),
    );
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![old.clone(), next.clone(), retiring.clone(), probe.clone()],
        networks: vec![app_net.clone(), staging.clone()],
    };
    let events: Vec<_> = client.image_pull(BUSYBOX).collect().await;
    assert!(events.last().is_some_and(Result::is_ok), "{events:?}");
    client
        .network_create(&network(&app_net, false))
        .await
        .unwrap();
    client
        .network_create(&network(&staging, false))
        .await
        .unwrap();

    let server_cmd = ["sh", "-c", "while true; do echo hi | nc -l -p 8080; done"];
    // The serving container answers to its own name; the probe stands in for nginx.
    client
        .container_create(&spec(&old, &[&app_net], &[], &server_cmd))
        .await
        .unwrap();
    client
        .container_create(&spec(&probe, &[&app_net], &[], &["sleep", "300"]))
        .await
        .unwrap();
    // The challenger starts on the staging network only, so the app network never sees it yet.
    client
        .container_create(&spec(&next, &[&staging], &[], &server_cmd))
        .await
        .unwrap();
    for c in [&old, &probe, &next] {
        client.container_start(c).await.unwrap();
    }
    wait_for_listener(&client, &probe, &old).await;
    assert_ne!(connect(&client, &probe, &next).await, 0, "staging is apart");

    // Joining the app network with the alias works from the staging network ...
    client
        .network_connect_aliased(&app_net, &next, std::slice::from_ref(&old))
        .await
        .unwrap();
    // ... but not for a network the container is already on.
    assert!(
        client
            .network_connect_aliased(&app_net, &next, std::slice::from_ref(&old))
            .await
            .is_err()
    );
    wait_for_listener(&client, &probe, &old).await;

    // Names are bookkeeping: renaming works on running containers, and the instance name keeps resolving.
    client.container_rename(&old, &retiring).await.unwrap();
    client.container_rename(&next, &old).await.unwrap();
    assert_eq!(client.container_inspect(&old).await.unwrap().name, old);
    assert_eq!(connect(&client, &probe, &old).await, 0);

    // The old container leaves; the alias alone carries the name now.
    client.container_stop(&retiring, 1).await.unwrap();
    client.container_remove(&retiring, true).await.unwrap();
    client.network_disconnect(&staging, &old).await.unwrap();
    client.network_remove(&staging).await.unwrap();
    wait_for_listener(&client, &probe, &old).await;

    // The alias survives a restart of the renamed container (restart = always after a reboot).
    client.container_stop(&old, 1).await.unwrap();
    client.container_start(&old).await.unwrap();
    wait_for_listener(&client, &probe, &old).await;
}
