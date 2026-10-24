//! Daemon-side `doctor`: what makes sense to check from inside the running process.
//! Host checks (subuid, linger, cgroups…) are done by `weglarka doctor --preflight`.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

use weglarka_api::{CheckStatus, DoctorCheck, DoctorReport};
use weglarka_core::config::IngressMode;
use weglarka_core::labels;
use weglarka_core::podman::{ContainerFilter, ContainerState, PodmanClient};
use weglarka_core::secret_store::{SecretStore, scoped_name};
use weglarka_core::state;

use crate::app::{Daemon, WEBHOOK_SECRET};
use crate::ingress::NGINX_CONTAINER;

fn check(
    id: &str,
    status: CheckStatus,
    message: impl Into<String>,
    hint: Option<&str>,
) -> DoctorCheck {
    DoctorCheck {
        id: id.to_owned(),
        status,
        message: message.into(),
        hint: hint.map(str::to_owned),
    }
}

fn ok(id: &str, message: impl Into<String>) -> DoctorCheck {
    check(id, CheckStatus::Ok, message, None)
}

pub async fn run<P: PodmanClient + 'static>(d: &Daemon<P>) -> DoctorReport {
    let mut checks = Vec::new();
    checks.push(ok(
        "daemon.version",
        format!("weglarka-daemon {}", env!("CARGO_PKG_VERSION")),
    ));
    podman(d, &mut checks).await;
    desired_state(d, &mut checks).await;
    secrets(d, &mut checks);
    crate::update::doctor_check(d, &mut checks);
    ingress(d, &mut checks).await;
    webhook(d, &mut checks).await;
    DoctorReport { checks }
}

async fn podman<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    out.push(match d.engine.podman().version().await {
        Ok(v) => {
            let major = v
                .api_version
                .split('.')
                .next()
                .and_then(|m| m.parse::<u32>().ok());
            if major.is_some_and(|m| m >= 6) {
                ok(
                    "runtime.socket",
                    format!("podman {} (libpod API {})", v.version, v.api_version),
                )
            } else {
                check(
                    "runtime.api_version",
                    CheckStatus::Fail,
                    format!("libpod API {} (requires ≥ 6.0)", v.api_version),
                    Some("install Podman 6 (alvistack repo)"),
                )
            }
        }
        Err(e) => check(
            "runtime.socket",
            CheckStatus::Fail,
            format!("Podman socket unavailable: {e}"),
            Some("check the runtime user's `podman.socket` and that the socket is mounted into the container"),
        ),
    });
}

async fn desired_state<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let apps = state::load_apps(&d.paths.state.apps);
    let st = state::load_state(&d.paths.state.state);
    out.push(match &apps {
        Ok(a) => ok(
            "state.apps_file",
            format!("apps.toml: {} apps", a.apps.len()),
        ),
        Err(e) => check(
            "state.apps_file",
            CheckStatus::Fail,
            e.to_string(),
            Some("fix or remove apps.toml"),
        ),
    });
    out.push(match &st {
        Ok(_) => ok("state.state_file", "state.toml is valid"),
        Err(e) => check(
            "state.state_file",
            CheckStatus::Fail,
            e.to_string(),
            Some("removing state.toml is safe (instances get a fresh deploy)"),
        ),
    });
    let (Ok(apps), Ok(st)) = (apps, st) else {
        return;
    };

    let containers = match d
        .engine
        .podman()
        .container_list(&ContainerFilter::default())
        .await
    {
        Ok(c) => c,
        Err(_) => return, // missing Podman already reported above
    };
    // A deploy writes `state.toml` only after the new container passes the health gate; until then
    // the instance is reported as in progress, not as drift (issue #30).
    let in_flight = d.engine.in_flight();
    let mut problems = Vec::new();
    let mut active = Vec::new();
    for name in apps.apps.keys() {
        if let Some(a) = in_flight.as_ref()
            && &a.instance == name
        {
            active.push(format!("{name} ({})", a.kind.label()));
            continue;
        }
        let app_state = st.apps.get(name);
        let container = containers
            .iter()
            .find(|c| c.name == labels::container_name(name));
        match (app_state.and_then(|s| s.current.as_ref()), container) {
            (None, _) => match app_state.and_then(|s| s.failed.as_ref()) {
                Some(f) => problems.push(format!("{name}: first deploy failed ({})", f.reason)),
                None => problems.push(format!("{name}: not deployed yet")),
            },
            (Some(_), None) => problems.push(format!("{name}: missing container")),
            (Some(_), Some(c)) => {
                if c.state != ContainerState::Running {
                    problems.push(format!("{name}: container not running ({:?})", c.state));
                }
                let want = app_state
                    .and_then(|s| s.spec_hash.as_ref())
                    .map(|h| h.to_string());
                if want.is_some() && c.labels.get(labels::SPEC_HASH) != want.as_ref() {
                    problems.push(format!("{name}: spec-hash drift"));
                }
            }
        }
    }
    let known: BTreeSet<String> = apps.apps.keys().map(ToString::to_string).collect();
    for c in &containers {
        if let Some(i) = c.labels.get(labels::INSTANCE)
            && !known.contains(i)
        {
            problems.push(format!("{}: orphan (not in apps.toml)", c.name));
        }
    }
    if !active.is_empty() {
        out.push(check(
            "state.deploying",
            CheckStatus::Info,
            format!(
                "deploy in progress: {} — skipped in the drift assessment",
                active.join(", ")
            ),
            None,
        ));
    }
    out.push(if problems.is_empty() {
        ok("state.drift", "actual state matches the desired state")
    } else {
        check(
            "state.drift",
            CheckStatus::Warn,
            problems.join("; "),
            Some("reconcile fixes drift on the next pass; `weglarka deploy <app>` forces a deploy"),
        )
    });
}

fn secrets<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    out.push(match d.secrets.check_permissions() {
        Ok(()) => ok(
            "state.secrets_file",
            "secrets.toml: permissions 0600 (or the file does not exist yet)",
        ),
        Err(e) => check(
            "state.secrets_file",
            CheckStatus::Fail,
            e.to_string(),
            Some("chmod 600 secrets.toml"),
        ),
    });
    let (Ok(apps), Ok(list)) = (state::load_apps(&d.paths.state.apps), d.secrets.list()) else {
        return;
    };
    let have: BTreeSet<String> = list.into_iter().map(|m| m.name).collect();
    let missing: Vec<String> = apps
        .apps
        .iter()
        .filter(|(_, s)| s.auto_update)
        .filter(|(n, _)| !have.contains(&scoped_name(n, WEBHOOK_SECRET)))
        .map(|(n, _)| n.to_string())
        .collect();
    out.push(if missing.is_empty() {
        ok("state.webhook_secrets", "every app with auto_update has an HMAC secret")
    } else {
        check(
            "state.webhook_secrets",
            CheckStatus::Warn,
            format!("missing `{WEBHOOK_SECRET}` secret for: {}", missing.join(", ")),
            Some("`weglarka secrets set <app> webhook-hmac` (use the same secret in the GitHub webhook)"),
        )
    });
}

async fn ingress<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    if d.host.ingress.mode == IngressMode::Behind
        && let Some(path) = &d.host.ingress.traefik_dynamic_file
    {
        let writable = std::fs::OpenOptions::new().write(true).open(path);
        out.push(match writable {
            Ok(_) => ok("ingress.traefik_file", format!("{} is writable", path.display())),
            Err(e) => check(
                "ingress.traefik_file",
                CheckStatus::Fail,
                format!("{}: {e}", path.display()),
                Some("the file must exist and belong to the runtime user (ACL only for traversing the directory)"),
            ),
        });
    }
    out.push(match d.ingress.last_error() {
        None => ok("ingress.apply", "last ingress generation had no errors"),
        Some(e) => check(
            "ingress.apply",
            CheckStatus::Fail,
            e,
            Some("fix the cause; ingress will be recomputed on the next change or in the loop"),
        ),
    });
    if let Ok(c) = d.engine.podman().container_inspect(NGINX_CONTAINER).await {
        out.push(if c.state == ContainerState::Running {
            ok("ingress.nginx", "nginx container is running")
        } else {
            check(
                "ingress.nginx",
                CheckStatus::Fail,
                format!("nginx container: {:?}", c.state),
                Some("it will be started on the next ingress recompute"),
            )
        });
    } else {
        out.push(check(
            "ingress.nginx",
            CheckStatus::Warn,
            "nginx container does not exist (yet)",
            Some("it is created on the first ingress recompute"),
        ));
    }
    // Admin socket: mode 0600.
    if let Ok(m) = std::fs::metadata(&d.host.admin.socket) {
        let mode = m.permissions().mode() & 0o777;
        out.push(if mode & 0o077 == 0 {
            ok(
                "admin.socket",
                format!("{} ({mode:o})", d.host.admin.socket.display()),
            )
        } else {
            check(
                "admin.socket",
                CheckStatus::Fail,
                format!("permissions {mode:o}, expected 600"),
                Some("chmod 600"),
            )
        });
    }
}

async fn webhook<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Some(mut addr) = d.webhook_addr() else {
        out.push(check(
            "webhook.listener",
            CheckStatus::Fail,
            "listener did not start",
            None,
        ));
        return;
    };
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    let connect = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(addr),
    );
    out.push(match connect.await {
        Ok(Ok(_)) => ok(
            "webhook.listener",
            format!("webhook listener responds ({addr})"),
        ),
        _ => check(
            "webhook.listener",
            CheckStatus::Fail,
            format!("no response on {addr}"),
            None,
        ),
    });
}
