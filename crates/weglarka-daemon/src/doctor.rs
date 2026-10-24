//! Daemon-side `doctor`: what makes sense to check from inside the running process.
//! Host checks (subuid, linger, cgroups…) are done by `weglarka doctor --preflight`.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

use weglarka_api::{CheckStatus, DoctorCheck, DoctorReport};
use weglarka_core::app::{AppsFile, InstanceName};
use weglarka_core::config::IngressMode;
use weglarka_core::labels;
use weglarka_core::podman::{
    ContainerFilter, ContainerInfo, ContainerState, PodmanClient, VolumeFilter,
};
use weglarka_core::secret_store::{SecretStore, scoped_name};
use weglarka_core::shared_volumes;
use weglarka_core::state::{self, StateFile};

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

/// A state file written by a newer Węglarka needs a different remedy than a malformed one
/// (issue #98): do not tell the operator to delete it.
fn state_hint(error: &state::StateError, malformed: &'static str) -> &'static str {
    match error {
        state::StateError::SchemaTooNew { .. } => {
            "written by a newer Węglarka: roll forward, or restore this file from before the upgrade"
        }
        _ => malformed,
    }
}

pub async fn run<P: PodmanClient + 'static>(d: &Daemon<P>) -> DoctorReport {
    let mut checks = Vec::new();
    checks.push(ok(
        "daemon.version",
        format!("weglarka-daemon {}", env!("CARGO_PKG_VERSION")),
    ));
    podman(d, &mut checks).await;
    let observed = desired_state(d, &mut checks).await;
    if let Some(observed) = &observed {
        image_retention(d, observed, &mut checks).await;
    }
    shared_volume_state(d, &mut checks).await;
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

/// What `desired_state` loaded once and hands to the later checks (image retention needs all three).
struct Observed {
    apps: AppsFile,
    st: StateFile,
    containers: Vec<ContainerInfo>,
}

async fn desired_state<P: PodmanClient>(
    d: &Daemon<P>,
    out: &mut Vec<DoctorCheck>,
) -> Option<Observed> {
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
            Some(state_hint(e, "fix or remove apps.toml")),
        ),
    });
    out.push(match &st {
        Ok(_) => ok("state.state_file", "state.toml is valid"),
        Err(e) => check(
            "state.state_file",
            CheckStatus::Fail,
            e.to_string(),
            Some(state_hint(
                e,
                "removing state.toml is safe (instances get a fresh deploy)",
            )),
        ),
    });
    let (Ok(apps), Ok(st)) = (apps, st) else {
        return None;
    };

    let containers = match d
        .engine
        .podman()
        .container_list(&ContainerFilter::default())
        .await
    {
        Ok(c) => c,
        Err(_) => return None, // missing Podman already reported above
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
    dependencies(&apps, &st, &containers, out);
    Some(Observed {
        apps,
        st,
        containers,
    })
}

/// Image retention (issue #40): images of a repository Węglarka deploys that are neither an app's
/// current nor its previous image and that no container uses. Reports only — `weglarka images prune`
/// removes them. While a deploy runs the check is informational: the freshly pulled image is not in
/// `state.toml` yet, so it would look unused (the same reason as [`CheckStatus::Info`] for drift).
async fn image_retention<P: PodmanClient>(
    d: &Daemon<P>,
    observed: &Observed,
    out: &mut Vec<DoctorCheck>,
) {
    if let Some(activity) = d.engine.in_flight() {
        out.push(check(
            "runtime.images",
            CheckStatus::Info,
            format!(
                "{} in progress for {} — image cleanup check skipped",
                activity.kind.label(),
                activity.instance
            ),
            None,
        ));
        return;
    }
    let Ok(images) = d.engine.podman().image_list().await else {
        return; // missing Podman already reported by `runtime.socket`
    };
    let plan = weglarka_core::images::plan(
        &images,
        &observed.containers,
        &observed.apps,
        &observed.st,
        None,
    );
    if plan.is_empty() {
        out.push(ok(
            "runtime.images",
            "no unused images from earlier deploys",
        ));
        return;
    }
    out.push(check(
        "runtime.images",
        CheckStatus::Warn,
        format!(
            "{} unused image(s) from earlier deploys ({} at most)",
            plan.remove.len(),
            weglarka_core::images::human_bytes(plan.reclaimable_bytes())
        ),
        Some("`weglarka images prune` removes them (`--dry-run` first to see the list)"),
    ));
}

/// `depends_on` (issue #35): a **running** app whose dependency is down is a real problem, while an
/// app that has not started yet and waits for its dependencies is expected (the next reconcile
/// retries). A dependency with `start = false` can never satisfy a dependent, so it is always a
/// warning. The check only appears when at least one app declares dependencies.
fn dependencies(
    apps: &AppsFile,
    st: &StateFile,
    containers: &[ContainerInfo],
    out: &mut Vec<DoctorCheck>,
) {
    if apps.apps.values().all(|spec| spec.depends_on.is_empty()) {
        return;
    }
    let running = |name: &InstanceName| {
        containers
            .iter()
            .any(|c| c.name == labels::container_name(name) && c.state == ContainerState::Running)
    };
    let mut problems = Vec::new();
    let mut waiting = Vec::new();
    for (name, spec) in &apps.apps {
        if spec.depends_on.is_empty() {
            continue;
        }
        let mut down = Vec::new();
        for dep in &spec.depends_on {
            if apps.apps.get(dep).is_some_and(|s| !s.start) {
                down.push(format!("{dep} (start = false)"));
            } else if !running(dep) {
                down.push(dep.to_string());
            }
        }
        if down.is_empty() {
            continue;
        }
        let down = down.join(", ");
        let deployed = st.apps.get(name).and_then(|s| s.current.as_ref()).is_some();
        if running(name) || (deployed && spec.start) {
            problems.push(format!("{name} depends on {down} (not running)"));
        } else {
            waiting.push(format!("{name}: {down}"));
        }
    }
    out.push(if !problems.is_empty() {
        check(
            "state.dependencies",
            CheckStatus::Warn,
            problems.join("; "),
            Some("start the dependency first: `weglarka apps start <app>`"),
        )
    } else if !waiting.is_empty() {
        check(
            "state.dependencies",
            CheckStatus::Info,
            format!(
                "waiting for dependencies (not started yet): {}",
                waiting.join("; ")
            ),
            None,
        )
    } else {
        ok("state.dependencies", "every dependency is running")
    });
}

/// `state.shared_volumes` (issue #33): `apps.toml` declarations vs `state.toml` ranges vs the
/// Podman volumes vs the ranges the member containers actually run in.
async fn shared_volume_state<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let (Ok(apps), Ok(st)) = (
        state::load_apps(&d.paths.state.apps),
        state::load_state(&d.paths.state.state),
    ) else {
        return; // already reported as `state.apps_file` / `state.state_file`
    };
    let volumes = match d
        .engine
        .podman()
        .volume_list(&VolumeFilter::default())
        .await
    {
        Ok(v) => v,
        Err(e) => {
            out.push(check(
                "state.shared_volumes",
                CheckStatus::Warn,
                format!("cannot list Podman volumes: {e}"),
                None,
            ));
            return;
        }
    };
    let containers = d
        .engine
        .podman()
        .container_list(&ContainerFilter::default())
        .await
        .ok();
    let mut warnings = Vec::new();
    let mut notes = Vec::new();
    let mut hints = Vec::new();

    // (a) Data without a declaration: nothing will ever create, purge or reclaim that volume, so the
    // operator has to decide (the engine deliberately keeps the range reserved, ADR 0017).
    for volume in &volumes {
        let Some(shared) = volume.labels.get(labels::SHARED_VOLUME) else {
            continue;
        };
        if apps.shared_volumes.keys().any(|n| n.as_str() == shared) {
            continue;
        }
        warnings.push(format!(
            "Podman volume {} is labelled as shared volume {shared:?} but apps.toml does not declare it",
            volume.name
        ));
        hints.push(format!(
            "declare it again to delete the data (`weglarka volumes add {shared}`, then \
             `weglarka volumes remove {shared} --purge`), or remove it by hand: `podman volume rm {}`",
            volume.name
        ));
    }

    let podman_names: BTreeSet<&str> = volumes.iter().map(|v| v.name.as_str()).collect();
    for name in apps.shared_volumes.keys() {
        // (b) The declaration owns a range but Podman does not know the volume yet.
        if let Some(label) = st
            .shared_volumes
            .get(name)
            .and_then(|s| s.uid_range)
            .map(labels::uid_range_label)
            && !podman_names.contains(labels::shared_volume_name(name).as_str())
        {
            notes.push(format!(
                "shared volume {name} has range {label} but no Podman volume; the next deploy or \
                 reconcile creates it"
            ));
        }
        // (d) The shared range aligns host owners only when every member process uses the same
        // container uid; Węglarka does not override the image's USER, so this is a documented
        // requirement (ADR 0017) and the comparison itself is a follow-up.
        let members = shared_volumes::members(&apps, name);
        if members.len() > 1 {
            notes.push(format!(
                "shared volume {name} is mounted by {}: every member image must run the same \
                 container USER (Węglarka does not override it)",
                members
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            hints.push(
                "check with `podman inspect <container> --format '{{.Config.User}}'`".to_owned(),
            );
        }
    }

    // (c) A member whose container runs in another range than the group's cannot read its data.
    for (name, spec) in &apps.apps {
        let Some(mount) = shared_volumes::mount(spec) else {
            continue;
        };
        let want = st
            .shared_volumes
            .get(&mount.name)
            .and_then(|s| s.uid_range)
            .map(labels::uid_range_label);
        let Some(container) = containers
            .as_ref()
            .and_then(|all| all.iter().find(|c| c.name == labels::container_name(name)))
        else {
            continue;
        };
        let got = container.labels.get(labels::UID_RANGE);
        if got != want.as_ref() {
            warnings.push(format!(
                "{name}: container uid-range {} but shared volume {} is {}",
                got.map_or("unset", String::as_str),
                mount.name,
                want.as_deref().unwrap_or("not allocated"),
            ));
        }
    }

    let (status, message) = if !warnings.is_empty() {
        let mut message = warnings.join("; ");
        if !notes.is_empty() {
            message.push_str("; notes: ");
            message.push_str(&notes.join("; "));
        }
        (CheckStatus::Warn, message)
    } else if !notes.is_empty() {
        (CheckStatus::Info, notes.join("; "))
    } else if apps.shared_volumes.is_empty() {
        (CheckStatus::Ok, "no shared volumes are declared".to_owned())
    } else {
        (CheckStatus::Ok, "shared volumes are consistent".to_owned())
    };
    let hint = (!hints.is_empty()).then(|| hints.join("; "));
    out.push(check(
        "state.shared_volumes",
        status,
        message,
        hint.as_deref(),
    ));
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
