//! The log driver and size bound (`ContainerSpec::log`, ADR 0074) against a real rootless Podman 6
//! (CI job `podman-tests`). Requires `WEGLARKA_PODMAN_SOCKET`; skipped without it
//! (docs/decisions/0002-podman-in-ci.md). The assertions check what libpod *stored* (`inspect`),
//! because it ignores unknown create-body fields silently.

use futures_util::StreamExt;
use serde_json::Value;
use weglarka_model::podman::{ContainerLog, ContainerSpec, LogDriver, PodmanClient};
use weglarka_podman::LibpodClient;

mod common;
use common::{Cleanup, raw_get, run_id, socket};

/// The pause image has no HEALTHCHECK of its own; `/pause -v` prints its version and exits 0.
const IMAGE: &str = "registry.k8s.io/pause:3.9";

fn spec(name: &str, log: Option<ContainerLog>) -> ContainerSpec {
    ContainerSpec {
        userns_auto: true,
        log,
        ..ContainerSpec::new(name, IMAGE)
    }
}

async fn pull(client: &LibpodClient) {
    let events: Vec<_> = client.image_pull(IMAGE).collect().await;
    assert!(events.last().is_some_and(Result::is_ok), "{events:?}");
}

fn inspect(socket: &str, name: &str) -> Value {
    let body = raw_get(socket, &format!("/containers/{name}/json")).expect("inspect");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn k8s_file_driver_and_size_reach_inspect() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let id = run_id();
    let (bounded, unbounded) = (
        format!("weglarka-it-log-{id}"),
        format!("weglarka-it-nolog-{id}"),
    );
    let _cleanup = Cleanup::new(&socket).containers([bounded.clone(), unbounded.clone()]);
    pull(&client).await;

    let log = ContainerLog {
        driver: LogDriver::K8sFile,
        max_size: Some(10 << 20),
    };
    client
        .container_create(&spec(&bounded, Some(log)))
        .await
        .unwrap();
    client
        .container_create(&spec(
            &unbounded,
            Some(ContainerLog {
                max_size: None,
                ..log
            }),
        ))
        .await
        .unwrap();

    let info = client.container_inspect(&bounded).await.unwrap();
    assert_eq!(info.log_driver.as_deref(), Some("k8s-file"));
    let with_size = inspect(&socket, &bounded)["HostConfig"]["LogConfig"].clone();
    let without_size = inspect(&socket, &unbounded)["HostConfig"]["LogConfig"].clone();
    eprintln!("LogConfig with size: {with_size}\nLogConfig without size: {without_size}");
    assert_eq!(with_size["Type"], "k8s-file", "{with_size}");
    assert_ne!(
        with_size["Size"], without_size["Size"],
        "max_size did not reach libpod: {with_size} vs {without_size}"
    );
}

#[tokio::test]
async fn unset_log_keeps_the_host_default() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let name = format!("weglarka-it-deflog-{}", run_id());
    let _cleanup = Cleanup::new(&socket).containers([name.clone()]);
    pull(&client).await;
    client.container_create(&spec(&name, None)).await.unwrap();
    // Whatever `containers.conf` says (journald or k8s-file); the point is that libpod reports it.
    let info = client.container_inspect(&name).await.unwrap();
    assert!(info.log_driver.is_some(), "{info:?}");
}
