//! Helpers shared by the real-Podman integration tests: the socket switch, unique names, raw libpod
//! calls via `curl` and cleanup on drop. Each test file is its own crate and uses a subset.

#![allow(dead_code)]

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// The libpod socket from `WEGLARKA_PODMAN_SOCKET`; `None` (with a message) skips the test
/// (docs/decisions/0002-podman-in-ci.md).
pub fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

/// Unique per-run suffix so that parallel/repeated runs do not collide.
pub fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}-{}", std::process::id(), nanos % 1_000_000_000)
}

fn curl(socket: &str, method: &str, path: &str) -> Command {
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "--unix-socket", socket, "-X", method]);
    cmd.arg(format!("http://d/v6.0.0/libpod{path}"));
    cmd
}

/// Raw API call via `curl` — for things outside the client contract (inspect fields the client
/// does not map, a container `ContainerSpec` cannot describe). Returns `(2xx, body)`; an optional
/// `body` is sent as JSON.
pub fn raw(socket: &str, method: &str, path: &str, body: Option<&str>) -> (bool, String) {
    let mut cmd = curl(socket, method, path);
    cmd.arg("--fail-with-body");
    if let Some(body) = body {
        cmd.args(["-H", "content-type: application/json", "-d", body]);
    }
    let out = cmd
        .output()
        .expect("curl is required for integration tests");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// `GET` whose body is returned only on success.
pub fn raw_get(socket: &str, path: &str) -> Option<String> {
    let (ok, body) = raw(socket, "GET", path, None);
    ok.then_some(body)
}

/// A kind of libpod object [`Cleanup`] removes, in removal order (containers before the networks
/// they are attached to).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Container,
    Network,
    Secret,
    Image,
}

impl Kind {
    /// `DELETE` path for `name`, with the query each kind needs.
    fn delete_path(self, name: &str) -> String {
        match self {
            Kind::Container => format!("/containers/{name}?force=true&v=true"),
            Kind::Network => format!("/networks/{name}?force=true"),
            Kind::Secret => format!("/secrets/{name}"),
            Kind::Image => format!("/images/{name}"),
        }
    }
}

/// Removes the listed objects after the test, even on panic (`Drop`). Failures are ignored and
/// never panic (a panic while unwinding would abort).
pub struct Cleanup {
    socket: String,
    objects: Vec<(Kind, String)>,
}

impl Cleanup {
    pub fn new(socket: &str) -> Self {
        Self {
            socket: socket.to_owned(),
            objects: Vec::new(),
        }
    }

    fn with<I>(mut self, kind: Kind, names: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        self.objects
            .extend(names.into_iter().map(|n| (kind, n.into())));
        self
    }

    pub fn containers<I: IntoIterator<Item: Into<String>>>(self, names: I) -> Self {
        self.with(Kind::Container, names)
    }

    pub fn networks<I: IntoIterator<Item: Into<String>>>(self, names: I) -> Self {
        self.with(Kind::Network, names)
    }

    pub fn secrets<I: IntoIterator<Item: Into<String>>>(self, names: I) -> Self {
        self.with(Kind::Secret, names)
    }

    pub fn images<I: IntoIterator<Item: Into<String>>>(self, names: I) -> Self {
        self.with(Kind::Image, names)
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.objects.sort_by_key(|(kind, _)| *kind);
        for (kind, name) in &self.objects {
            let _ = curl(&self.socket, "DELETE", &kind.delete_path(name)).output();
        }
    }
}
