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
use weglarka_model::app::Resources;
use weglarka_model::labels;
use weglarka_model::podman::{ContainerSpec, NetworkSpec, PodmanClient};
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
        command: command.iter().map(|s| (*s).to_owned()).collect(),
        networks: networks.iter().map(|s| (*s).to_owned()).collect(),
        network_aliases: aliases
            .iter()
            .map(|(n, a)| ((*n).to_owned(), a.iter().map(|s| (*s).to_owned()).collect()))
            .collect(),
        userns_auto: true,
        resources: Resources::default(),
        ..ContainerSpec::new(name, BUSYBOX)
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

/// The metrics network (ADR 0061) is `internal`, and the daemon joins it with a live `network_connect`
/// while it already runs on another network: a scraper on the metrics network must still resolve the
/// daemon's container by name and connect to it.
#[tokio::test]
async fn live_join_of_an_internal_network_resolves_by_container_name() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let metrics = format!("it-metrics-{id}");
    let own = format!("net-it-daemon-{id}");
    let (daemon, scraper) = (format!("it-daemon-{id}"), format!("it-scraper-{id}"));
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![daemon.clone(), scraper.clone()],
        networks: vec![metrics.clone(), own.clone()],
    };
    let events: Vec<_> = client.image_pull(BUSYBOX).collect().await;
    assert!(events.last().is_some_and(Result::is_ok), "{events:?}");

    client
        .network_create(&network(&metrics, true))
        .await
        .unwrap();
    // Idempotent, as the daemon calls it at every start.
    client
        .network_create(&network(&metrics, true))
        .await
        .unwrap();
    client.network_create(&network(&own, false)).await.unwrap();

    let server_cmd = ["sh", "-c", "while true; do echo hi | nc -l -p 8080; done"];
    client
        .container_create(&spec(&daemon, &[&own], &[], &server_cmd))
        .await
        .unwrap();
    client
        .container_create(&spec(&scraper, &[&metrics], &[], &["sleep", "300"]))
        .await
        .unwrap();
    for c in [&daemon, &scraper] {
        client.container_start(c).await.unwrap();
    }

    // Before the join the scraper cannot find the daemon; after it, it can.
    assert_ne!(connect(&client, &scraper, &daemon).await, 0);
    client.network_connect(&metrics, &daemon).await.unwrap();
    wait_for_listener(&client, &scraper, &daemon).await;
}

/// Per-app metrics networks (issue #364): each opted-in app is on its own internal `metrics-<app>`,
/// a scraper that joins both reaches both by name, and the two apps cannot reach each other there. The
/// first network carries the longest name an instance can produce (63 + `metrics-` = 71 bytes), which
/// libpod must accept.
#[tokio::test]
async fn per_app_metrics_networks_isolate_apps_from_each_other() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let mut long = format!("it-ma-{id}-");
    long.extend(std::iter::repeat_n('x', 63 - long.len()));
    let instance = |n: &str| weglarka_model::app::InstanceName::new(n).unwrap();
    let (a, b) = (format!("it-ma-{id}"), format!("it-mb-{id}"));
    let net_a = labels::metrics_network_name(&instance(&long));
    let net_b = labels::metrics_network_name(&instance(&b));
    assert_eq!(net_a.len(), 71);
    let scraper = format!("it-ms-{id}");
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![a.clone(), b.clone(), scraper.clone()],
        networks: vec![net_a.clone(), net_b.clone()],
    };
    let events: Vec<_> = client.image_pull(BUSYBOX).collect().await;
    assert!(events.last().is_some_and(Result::is_ok), "{events:?}");

    for net in [&net_a, &net_b] {
        client.network_create(&network(net, true)).await.unwrap();
    }
    let server_cmd = ["sh", "-c", "while true; do echo hi | nc -l -p 8080; done"];
    client
        .container_create(&spec(&a, &[&net_a], &[], &server_cmd))
        .await
        .unwrap();
    client
        .container_create(&spec(&b, &[&net_b], &[], &server_cmd))
        .await
        .unwrap();
    client
        .container_create(&spec(&scraper, &[&net_a], &[], &["sleep", "300"]))
        .await
        .unwrap();
    for c in [&a, &b, &scraper] {
        client.container_start(c).await.unwrap();
    }
    // The scraper joins the second network live, as it will for an app that opts in later.
    client.network_connect(&net_b, &scraper).await.unwrap();
    wait_for_listener(&client, &scraper, &a).await;
    wait_for_listener(&client, &scraper, &b).await;
    // Opted-in apps do not share a network, so neither finds the other.
    assert_ne!(connect(&client, &a, &b).await, 0);
    assert_ne!(connect(&client, &b, &a).await, 0);
}

/// A free loopback port on the host (released before the container takes it).
fn free_host_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback port");
    listener.local_addr().expect("local addr").port()
}

/// What the published port answers from the host side, retried while the listener starts. `None` if
/// it never answered.
async fn host_answer(port: u16) -> Option<String> {
    use std::io::Read;
    for _ in 0..20 {
        let got = tokio::task::spawn_blocking(move || {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let mut stream =
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
            // The first chunk is enough: busybox `nc -l` need not close after its greeting.
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).ok()?;
            (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
        })
        .await
        .unwrap();
        if got.is_some() {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    None
}

/// An app with `host_ports` that opts into metrics (issue #364) is created on its normal network
/// **and** an internal `metrics-<app>` (in that order, as `launch` does it), and an app that opts in
/// later, or the scraper (issue #365), joins an internal network live. Either way the published
/// loopback port must keep answering from the host: which network rootless Podman forwards a
/// published port through is not something Węglarka chooses, and an internal network has no route
/// out. Published on `127.0.0.1`, the default of `host_ports`.
#[tokio::test]
async fn a_published_port_still_answers_next_to_an_internal_network() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let (created, joined) = (format!("it-pc-{id}"), format!("it-pj-{id}"));
    let own = |n: &str| format!("net-it-{n}-{id}");
    let instance = |n: &str| weglarka_model::app::InstanceName::new(n).unwrap();
    let metrics_created = labels::metrics_network_name(&instance(&created));
    let metrics_joined = labels::metrics_network_name(&instance(&joined));
    let _cleanup = Cleanup {
        socket: socket.clone(),
        containers: vec![created.clone(), joined.clone()],
        networks: vec![
            own("pc"),
            own("pj"),
            metrics_created.clone(),
            metrics_joined.clone(),
        ],
    };
    let events: Vec<_> = client.image_pull(BUSYBOX).collect().await;
    assert!(events.last().is_some_and(Result::is_ok), "{events:?}");

    for n in ["pc", "pj"] {
        client
            .network_create(&network(&own(n), false))
            .await
            .unwrap();
    }
    for net in [&metrics_created, &metrics_joined] {
        client.network_create(&network(net, true)).await.unwrap();
    }

    let server_cmd = ["sh", "-c", "while true; do echo hi | nc -l -p 8080; done"];
    let published = |name: &str, networks: &[&str], port: u16| {
        let mut s = spec(name, networks, &[], &server_cmd);
        s.publish = vec![weglarka_model::podman::PortMapping {
            host_ip: Some("127.0.0.1".into()),
            host_port: port,
            container_port: 8080,
        }];
        s
    };
    let (port_created, port_joined) = (free_host_port(), free_host_port());
    client
        .container_create(&published(
            &created,
            &[&own("pc"), &metrics_created],
            port_created,
        ))
        .await
        .unwrap();
    client
        .container_create(&published(&joined, &[&own("pj")], port_joined))
        .await
        .unwrap();
    for c in [&created, &joined] {
        client.container_start(c).await.unwrap();
    }

    assert_eq!(
        host_answer(port_created).await.as_deref(),
        Some("hi\n"),
        "created on a normal and an internal network: the published port must answer"
    );
    assert_eq!(
        host_answer(port_joined).await.as_deref(),
        Some("hi\n"),
        "before the live join"
    );
    client
        .network_connect(&metrics_joined, &joined)
        .await
        .unwrap();
    assert_eq!(
        host_answer(port_joined).await.as_deref(),
        Some("hi\n"),
        "after joining an internal network live: the published port must still answer"
    );
}
