//! Daemon-side `doctor`: what makes sense to check from inside the running process.
//! Host checks (subuid, linger, cgroups…) are done by `weglarka doctor --preflight`.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;

use weglarka_api::{CheckStatus, DoctorCheck, DoctorReport};
use weglarka_core::app::{AppSpec, AppsFile, InstanceName};
use weglarka_core::config::IngressMode;
use weglarka_core::config_mounts::{self, MountStatus};
use weglarka_core::labels;
use weglarka_core::podman::{
    ContainerFilter, ContainerInfo, ContainerState, PodmanClient, VolumeFilter,
};
use weglarka_core::secret_store::{SecretStore, scoped_name, split_scoped};
use weglarka_core::shared_networks;
use weglarka_core::shared_volumes;
use weglarka_core::state::{self, StateFile};

use crate::app::{Daemon, WEBHOOK_SECRET};
use crate::ingress::{FORWARDER_CONTAINER, NGINX_CONTAINER};

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
    configs(d, &mut checks);
    host_mounts(d, &mut checks);
    shared_volume_state(d, &mut checks).await;
    shared_network_state(d, &mut checks).await;
    secrets(d, &mut checks);
    crate::update::doctor_check(d, &mut checks);
    self_update(d, &mut checks);
    ingress(d, &mut checks).await;
    acme(d, &mut checks);
    webhook(d, &mut checks).await;
    DoctorReport { checks }
}

/// Self-update (issue #99): configured or not, the digest the switcher pinned, and whether the
/// checks still run — a configured `[self_update]` with no recent check means the timer is missing.
fn self_update<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Some(config) = d.host.self_update.as_ref() else {
        out.push(ok(
            "self_update",
            "off ([self_update] absent): no automatic update of Węglarka",
        ));
        return;
    };
    if !config.enabled {
        out.push(ok("self_update", "paused by [self_update] enabled = false"));
        return;
    }
    let state_path = weglarka_core::self_update::path(&d.paths.state_dir);
    let state = match weglarka_core::self_update::load(&d.paths.state_dir) {
        Ok(state) => state,
        Err(e) => {
            out.push(check(
                "self_update",
                CheckStatus::Warn,
                e.to_string(),
                Some("the switcher will not run until the file is valid or removed"),
            ));
            return;
        }
    };
    let mut parts = Vec::new();
    match &state.current {
        Some(digest) => parts.push(format!("running {}", short(digest))),
        None => parts.push("running digest unknown".to_owned()),
    }
    match &state.previous {
        Some(digest) => parts.push(format!("previous {} (--rollback)", short(digest))),
        None => parts.push("no previous image yet".to_owned()),
    }
    let now = weglarka_core::self_update::secs(std::time::SystemTime::now());
    if let Some(pending) = &state.pending {
        let age = state.pending_at.map_or(0, |at| now.saturating_sub(at));
        parts.push(format!("pending {} for {age}s", short(pending)));
    }
    if let Some(error) = &state.error {
        let age = now.saturating_sub(error.at);
        parts.push(format!("last attempt failed {age}s ago: {}", error.message));
    }
    // Issue #100: a switch in flight (the watchdog is waiting for the new daemon's health) and the
    // last automatic fallback.
    let switch = state.active_switch();
    if let Some(switch) = &switch {
        let age = now.saturating_sub(switch.at);
        parts.push(format!(
            "supervising the switch to {} for {age}s of {}s",
            short(&switch.to),
            config.fallback_timeout_secs
        ));
    }
    if let Some(fallback) = state.last_fallback() {
        let age = now.saturating_sub(fallback.at);
        parts.push(format!(
            "automatic fallback {} → {} {age}s ago",
            short(&fallback.from),
            short(&fallback.to)
        ));
    }
    // The watchdog runs once a minute, so being a little past the deadline is normal; only a whole
    // extra tick means the timer is not running (or the fallback gave up).
    let switch_overdue = switch.is_some_and(|switch| {
        now.saturating_sub(switch.at) > config.fallback_timeout_secs.saturating_add(120)
    });
    let stale_after = config.interval_secs.saturating_mul(3);
    let stale = state
        .checked_at
        .is_none_or(|at| now.saturating_sub(at) > stale_after);
    let (status, hint) = if state.error.is_some() {
        (
            CheckStatus::Warn,
            Some(
                "see the state file and `journalctl --user -u weglarka-self-update.service -u weglarka-watchdog.service`",
            ),
        )
    } else if switch_overdue {
        (
            CheckStatus::Warn,
            Some(
                "the switch is past its fallback deadline and was not reverted — is weglarka-watchdog.timer enabled? (re-run `platform install`)",
            ),
        )
    } else if state.pending.is_some() {
        (
            CheckStatus::Warn,
            Some(
                "the pinned image did not take effect; `weglarka-daemon self-update --rollback` returns to the previous one",
            ),
        )
    } else if stale {
        (
            CheckStatus::Warn,
            Some(
                "the switcher has not run recently — is weglarka-self-update.timer enabled? (re-run `platform install`)",
            ),
        )
    } else {
        (CheckStatus::Ok, None)
    };
    out.push(check(
        "self_update",
        status,
        format!("{} ({})", parts.join("; "), state_path.display()),
        hint,
    ));
}

/// First 12 hex digits of a digest, for a readable check.
fn short(digest: &weglarka_core::app::Digest) -> &str {
    &digest.as_str()[7..19]
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

/// `configs.root` / `configs.mounts` (issue #118, ADR 0022). The feature is off when neither
/// `config_root` nor an app's `configs` exists, in which case nothing is reported. Otherwise:
///
/// * the root is set (an app declaring configs without it is an error at startup/write time, so this
///   is a hand-edited `apps.toml`), is visible in the daemon container (`platform install` mounts it
///   read-only), is a readable directory and is not group/world-writable — anyone who can write the
///   root decides what the apps mount;
/// * every declared source resolves inside it and the app's uid range can read it. The app runs in
///   its own uid range, so a runtime-user file appears there as `nobody` (ADR 0009): files need the
///   "other read" bit (0644) and directories "other execute" (0755).
///
/// Report-only, like the rest of doctor: nothing here touches the files or the containers.
/// Host mounts (issue #178): which apps read which host paths, and whether each is still allowlisted,
/// present and unredirected. Silent while no app uses them.
fn host_mounts<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use weglarka_core::host_mounts::{HostMountStatus, describe};
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // reported by `state.apps_file`
    };
    let allowlist = &d.host.runtime.host_mounts;
    let mut used = Vec::new();
    let mut broken = Vec::new();
    for (name, spec) in &apps.apps {
        for view in describe(allowlist, spec) {
            used.push(format!("{name}: {}", view.source));
            if view.status != HostMountStatus::Ok {
                broken.push(format!(
                    "{name}: {}",
                    view.detail.unwrap_or_else(|| view.source.clone())
                ));
            }
        }
    }
    for (name, spec) in &apps.apps {
        if spec.group_add.is_empty() {
            continue;
        }
        used.push(format!("{name}: groups {}", spec.group_add.join(",")));
        if let Err(e) = weglarka_core::host_mounts::check_groups(&d.host.runtime.group_add, spec) {
            broken.push(format!("{name}: {e}"));
        }
    }
    if used.is_empty() {
        return;
    }
    out.push(if broken.is_empty() {
        check(
            "host_mounts.apps",
            CheckStatus::Ok,
            format!("read-only host paths in use ({})", used.join("; ")),
            None,
        )
    } else {
        check(
            "host_mounts.apps",
            CheckStatus::Warn,
            format!("host mounts cannot be mounted: {}", broken.join("; ")),
            Some(
                "list the path in `[runtime] host_mounts` of weglarka.toml (then re-run `weglarka \
                 platform install` so the daemon container sees it), or fix the path on the host",
            ),
        )
    });
}

fn configs<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // reported by `state.apps_file`
    };
    let users: Vec<(&InstanceName, &AppSpec)> = apps
        .apps
        .iter()
        .filter(|(_, spec)| !spec.configs.is_empty())
        .collect();
    let root = d.paths.config_root.as_deref();
    if root.is_none() && users.is_empty() {
        return; // config mounts are off
    }

    let mut canonical_root = None;
    out.push(match root {
        None => check(
            "configs.root",
            CheckStatus::Warn,
            format!(
                "config_root is not set, but {} declare configs: {}",
                users.len(),
                users
                    .iter()
                    .map(|(name, _)| name.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Some(
                "set `config_root` in weglarka.toml and re-run `weglarka platform install` so the \
                 daemon container mounts it read-only",
            ),
        ),
        Some(root) => match std::fs::metadata(root) {
            Err(e) => check(
                "configs.root",
                CheckStatus::Warn,
                format!("config_root {} is not available: {e}", root.display()),
                Some(
                    "the daemon container must mount config_root read-only: set it in weglarka.toml \
                     and re-run `weglarka platform install`",
                ),
            ),
            Ok(meta) if !meta.is_dir() => check(
                "configs.root",
                CheckStatus::Warn,
                format!("config_root {} is not a directory", root.display()),
                Some("point `config_root` at the directory holding the app config files"),
            ),
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                match std::fs::read_dir(root) {
                    Err(e) => check(
                        "configs.root",
                        CheckStatus::Warn,
                        format!("cannot read config_root {}: {e}", root.display()),
                        Some("the runtime user needs r+x on config_root"),
                    ),
                    Ok(_) => {
                        canonical_root = root.canonicalize().ok();
                        if mode & 0o022 != 0 {
                            let hint = format!(
                                "chmod -R go-w {}: anyone who can write the root decides what the \
                                 apps mount",
                                root.display()
                            );
                            check(
                                "configs.root",
                                CheckStatus::Warn,
                                format!(
                                    "config_root {} is group/world-writable ({mode:o})",
                                    root.display()
                                ),
                                Some(&hint),
                            )
                        } else {
                            ok(
                                "configs.root",
                                format!("config_root {} ({mode:o})", root.display()),
                            )
                        }
                    }
                }
            }
        },
    });

    if users.is_empty() {
        return;
    }
    let mut problems = Vec::new();
    let mut unreadable = Vec::new();
    let mut mounts = 0usize;
    for (name, spec) in users {
        for view in config_mounts::describe(root, spec) {
            mounts += 1;
            match view.status {
                MountStatus::Ok => {
                    let Some(path) = canonical_root
                        .as_ref()
                        .map(|canonical| canonical.join(&view.source))
                    else {
                        continue;
                    };
                    let Ok(meta) = std::fs::metadata(&path) else {
                        continue;
                    };
                    let mode = meta.permissions().mode() & 0o777;
                    // The app runs in its own uid range, so only the "other" bits apply (ADR 0009).
                    let needed = if meta.is_dir() { 0o001 } else { 0o004 };
                    if mode & needed == 0 {
                        unreadable.push(format!("{name}: {} ({mode:o})", view.source));
                    }
                }
                _ => problems.push(format!(
                    "{name}: {}",
                    view.detail
                        .unwrap_or_else(|| "config mount is not usable".to_owned())
                )),
            }
        }
    }
    let mut hints = Vec::new();
    let mut message = problems;
    if !message.is_empty() {
        hints.push(
            "fix the listed sources under config_root; `weglarka apps show <app>` reports every mount",
        );
    }
    if !unreadable.is_empty() {
        message.push(format!(
            "not readable by the app's uid range: {}",
            unreadable.join(", ")
        ));
        hints.push(
            "`chmod -R u=rwX,go=rX <config_root>` gives 0644 files / 0755 directories; files owned \
             by the runtime user appear as nobody in the app's uid range (ADR 0009)",
        );
    }
    out.push(if message.is_empty() {
        ok(
            "configs.mounts",
            format!("{mounts} config mount(s) resolve and are readable"),
        )
    } else {
        check(
            "configs.mounts",
            CheckStatus::Warn,
            message.join("; "),
            Some(&hints.join("; ")),
        )
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
        let group = shared_volumes::volume_group(&apps, name);
        // (b) The group owns a range but Podman does not know the volume yet.
        if let Some(label) = st
            .shared_volumes
            .get(&group)
            .and_then(|s| s.uid_range)
            .map(labels::uid_range_label)
            && !podman_names.contains(labels::shared_volume_name(name).as_str())
        {
            notes.push(format!(
                "shared volume {name} (group {group}) has range {label} but no Podman volume; the \
                 next deploy or reconcile creates it"
            ));
        }
        // (e) The volume exists in another group than the declared one (hand-edited apps.toml):
        // its files belong to the recorded group's range (ADR 0029).
        if let Some(info) = volumes
            .iter()
            .find(|v| v.name == labels::shared_volume_name(name))
        {
            let recorded = info
                .labels
                .get(labels::SHARED_GROUP)
                .map_or(name.as_str(), String::as_str);
            if recorded != group.as_str() {
                warnings.push(format!(
                    "shared volume {name} is declared in group {group} but its data belongs to \
                     group {recorded}"
                ));
                hints.push(format!(
                    "restore `group` in apps.toml, or `weglarka volumes remove {name} --purge` and \
                     declare it again"
                ));
            }
        }
    }
    // (d) The shared range aligns host owners only when every member process uses the same
    // container uid; Węglarka does not override the image's USER, so this is a documented
    // requirement (ADR 0017) and the comparison itself is a follow-up. Reported per group, which
    // also shows the group membership (issue #129).
    let groups: BTreeSet<_> = apps
        .shared_volumes
        .keys()
        .map(|v| shared_volumes::volume_group(&apps, v))
        .collect();
    for group in &groups {
        let group_volumes = shared_volumes::group_volumes(&apps, group);
        let members = shared_volumes::group_members(&apps, group);
        if group_volumes.len() > 1 {
            notes.push(format!(
                "group {group}: volumes {}; members {}",
                join_display(&group_volumes),
                if members.is_empty() {
                    "none".to_owned()
                } else {
                    join_display(&members)
                }
            ));
        }
        if members.len() > 1 {
            notes.push(format!(
                "group {group} is mounted by {}: every member image must run the same container \
                 USER (Węglarka does not override it)",
                join_display(&members)
            ));
            hints.push(
                "check with `podman inspect <container> --format '{{.Config.User}}'`".to_owned(),
            );
        }
    }

    // (c) A member whose container runs in another range than the group's cannot read its data.
    for (name, spec) in &apps.apps {
        let Some(group) = shared_volumes::spec_group(&apps, spec) else {
            continue;
        };
        let want = st
            .shared_volumes
            .get(&group)
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
                "{name}: container uid-range {} but shared volume group {} is {}",
                got.map_or("unset", String::as_str),
                group,
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

/// `a, b, c` for a doctor message.
fn join_display<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `state.shared_networks` (issue #128): declarations vs Podman networks vs the networks the member
/// containers are really attached to. Everything here is a warning or a note: a broken group
/// isolates its members from each other, it does not endanger anything else.
async fn shared_network_state<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // already reported as `state.apps_file`
    };
    let networks = match d.engine.podman().network_list().await {
        Ok(n) => n,
        Err(e) => {
            out.push(check(
                "state.shared_networks",
                CheckStatus::Warn,
                format!("cannot list Podman networks: {e}"),
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

    // (a) A labelled network nobody declares: reconcile removes it once it is empty, so one that
    // lingers still has containers attached.
    for net in &networks {
        let Some(group) = net.labels.get(labels::SHARED_NETWORK) else {
            continue;
        };
        if apps.shared_networks.keys().any(|n| n.as_str() == group) {
            continue;
        }
        warnings.push(format!(
            "Podman network {} belongs to shared network {group:?} but apps.toml does not declare it",
            net.name
        ));
        hints.push(format!(
            "declare it again (`weglarka networks add {group}`) or detach what is left and remove it: \
             `podman network rm {}`",
            net.name
        ));
    }

    for name in apps.shared_networks.keys() {
        // (b) A group nobody joined: harmless, but usually a forgotten `--shared-network`.
        let members = shared_networks::members(&apps, name);
        if members.is_empty() {
            notes.push(format!("shared network {name} has no members"));
            continue;
        }
        // (c) A member whose running container is not on the group network (the spec changed and
        // the recreate has not happened yet, or the container was created by hand).
        let want = labels::shared_network_name(name);
        for member in &members {
            let Some(container) = containers.as_ref().and_then(|all| {
                all.iter()
                    .find(|c| c.name == labels::container_name(member))
            }) else {
                continue;
            };
            if !container.networks.contains(&want) {
                warnings.push(format!(
                    "{member} should be on shared network {name} but its container is not attached to {want}"
                ));
                hints.push(
                    "`weglarka deploy <app>` recreates the container with its networks".to_owned(),
                );
            }
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
    } else if apps.shared_networks.is_empty() {
        (
            CheckStatus::Ok,
            "no shared networks are declared".to_owned(),
        )
    } else {
        (CheckStatus::Ok, "shared networks are consistent".to_owned())
    };
    hints.dedup();
    let hint = (!hints.is_empty()).then(|| hints.join("; "));
    out.push(check(
        "state.shared_networks",
        status,
        message,
        hint.as_deref(),
    ));
}

/// The effective route table (issue #130, ADR 0031): every `(domain, path)` and where it goes, built
/// from the same plan the generators use, so what is listed is what nginx is given.
fn ingress_routes<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // `state.apps` already reports this
    };
    let plan = match weglarka_ingress::Plan::build(&d.host, &apps.apps) {
        Ok(plan) => plan,
        Err(e) => {
            out.push(check(
                "ingress.routes",
                CheckStatus::Fail,
                e.to_string(),
                Some("fix domains/paths in apps.toml; overlapping paths on a shared domain are refused"),
            ));
            return;
        }
    };
    let rows = plan.route_table();
    if rows.is_empty() {
        out.push(ok("ingress.routes", "no app is routed by ingress"));
        return;
    }
    let lines: Vec<String> = rows
        .iter()
        .map(|r| {
            let mut line = format!("{}{} -> {}:{}", r.domain, r.path, r.instance, r.port);
            if r.strip_prefix && !r.path.is_root() {
                line.push_str(" (strip prefix)");
            }
            if r.streaming {
                line.push_str(" (streaming)");
            }
            if !r.active {
                line.push_str(" (not started)");
            }
            line
        })
        .collect();
    out.push(check(
        "ingress.routes",
        CheckStatus::Info,
        lines.join("; "),
        None,
    ));
}

/// The domains the ingress routes: the webhook domain plus every app domain, sorted and unique.
/// `None` when `apps.toml` cannot be read (`state.apps` reports that).
fn routed_domains<P: PodmanClient>(d: &Daemon<P>) -> Option<Vec<String>> {
    let apps = state::load_apps(&d.paths.state.apps).ok()?;
    let mut domains: Vec<String> = vec![d.host.webhook.domain.clone()];
    for spec in apps.apps.values() {
        domains.extend(spec.domains.iter().cloned());
    }
    domains.sort();
    domains.dedup();
    Some(domains)
}

/// `[acme]` (issue #96): the configuration, the account key and the state of every certificate.
/// `acme.certs` is a failure only for a certificate that has already expired; a missing one or one
/// inside the renewal window is a warning (the worker is expected to deal with it on its next pass),
/// and so is a failure the last pass recorded.
fn acme<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Some(config) = &d.host.acme else {
        return;
    };
    if !config.enabled {
        out.push(check(
            "acme.config",
            CheckStatus::Info,
            "paused ([acme] enabled = false)",
            None,
        ));
        return;
    }
    let staging = config.directory_url == weglarka_core::config::AcmeConfig::LETS_ENCRYPT_STAGING;
    out.push(check(
        "acme.config",
        if staging {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        },
        format!(
            "{}{}, renew {} days before expiry, pass every {} s",
            if staging { "staging " } else { "" },
            config.directory_url,
            config.renew_before_days,
            config.check_interval_secs
        ),
        staging.then_some(
            "staging certificates are not trusted by browsers: remove directory_url (or set the \
             production one) once the setup works",
        ),
    ));

    let key = &d.paths.acme_account_key;
    match std::fs::metadata(key) {
        Ok(m) if m.permissions().mode() & 0o077 == 0 => {
            out.push(ok("acme.account", key.display().to_string()));
        }
        Ok(m) => out.push(check(
            "acme.account",
            CheckStatus::Fail,
            format!(
                "{} has permissions {:o}, expected 600",
                key.display(),
                m.permissions().mode() & 0o777
            ),
            Some("chmod 600; the daemon refuses a group/other-accessible account key"),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => out.push(check(
            "acme.account",
            CheckStatus::Info,
            "no account yet; it is created at the first issuance",
            None,
        )),
        Err(e) => out.push(check(
            "acme.account",
            CheckStatus::Warn,
            format!("{}: {e}", key.display()),
            None,
        )),
    }

    if let Some(dns) = &config.dns {
        acme_dns(d, config, dns, out);
    }

    let Some(domains) = routed_domains(d) else {
        return; // `state.apps` already reports this
    };
    let tls = d.ingress.tls_dir();
    let now = std::time::SystemTime::now();
    let window = std::time::Duration::from_secs(config.renew_before_days * 24 * 3600);
    let (mut missing, mut expired, mut due) = (Vec::new(), Vec::new(), Vec::new());
    let mut soonest: Option<u64> = None;
    let wildcards: &[String] = config.dns.as_ref().map_or(&[], |dns| &dns.wildcards);
    let mut covered = 0usize;
    for domain in &domains {
        let Ok(chain) = std::fs::read(tls.join(format!("{domain}.crt"))) else {
            // No certificate of its own: fine when a valid wildcard serves it (issue #97).
            if crate::acme::valid_covering_wildcard(&tls, wildcards, domain, now) {
                covered += 1;
            } else {
                missing.push(domain.as_str());
            }
            continue;
        };
        match weglarka_acme::chain_not_after(&chain) {
            Err(_) => missing.push(domain.as_str()),
            Ok(not_after) => match not_after.duration_since(now) {
                Err(_) => expired.push(domain.as_str()),
                Ok(left) => {
                    let days = left.as_secs() / (24 * 3600);
                    soonest = Some(soonest.map_or(days, |s| s.min(days)));
                    if left <= window {
                        due.push(domain.as_str());
                    }
                }
            },
        }
    }
    let status = d.acme.as_ref().map(|s| s.snapshot()).unwrap_or_default();
    let mut problems = Vec::new();
    if !expired.is_empty() {
        problems.push(format!("expired: {}", expired.join(", ")));
    }
    if !missing.is_empty() {
        problems.push(format!("none yet: {}", missing.join(", ")));
    }
    if !due.is_empty() {
        problems.push(format!("renewal due: {}", due.join(", ")));
    }
    for (cert, reason) in &status.failures {
        problems.push(format!("last pass failed for {cert}: {reason}"));
    }
    if problems.is_empty() {
        out.push(ok(
            "acme.certs",
            match soonest {
                Some(days) => format!(
                    "{} certificate(s){}, the nearest expires in {days} days",
                    domains.len() - covered,
                    if covered > 0 {
                        format!(" and {covered} domain(s) served by a wildcard")
                    } else {
                        String::new()
                    }
                ),
                None if covered > 0 => format!("{covered} domain(s) served by a wildcard"),
                None => "no routed domains".to_owned(),
            },
        ));
    } else {
        out.push(check(
            "acme.certs",
            if expired.is_empty() {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            },
            problems.join("; "),
            Some(
                "HTTP-01 needs the plain-HTTP port reachable from the internet as port 80 and the \
                 domain's DNS pointing at this host; the worker retries every 30 minutes after a failure",
            ),
        ));
    }
}

/// `[acme.dns]` (issue #97): the provider, the token file and the state of every wildcard
/// certificate (`tls/_wildcard.<apex>.crt`). The ingress does not serve the wildcard certificates
/// yet, so a missing one is a warning like a missing domain certificate.
fn acme_dns<P: PodmanClient>(
    d: &Daemon<P>,
    config: &weglarka_core::config::AcmeConfig,
    dns: &weglarka_core::config::AcmeDnsConfig,
    out: &mut Vec<DoctorCheck>,
) {
    let token = &dns.token_file;
    match std::fs::metadata(token) {
        Ok(m) if m.permissions().mode() & 0o077 == 0 => out.push(ok(
            "acme.dns",
            format!(
                "{:?}, token {}, wildcards for {}",
                dns.provider,
                token.display(),
                dns.wildcards.join(", ")
            ),
        )),
        Ok(m) => out.push(check(
            "acme.dns",
            CheckStatus::Fail,
            format!(
                "{} has permissions {:o}, expected 600",
                token.display(),
                m.permissions().mode() & 0o777
            ),
            Some("chmod 600; the daemon refuses a group/other-accessible DNS token"),
        )),
        Err(e) => out.push(check(
            "acme.dns",
            CheckStatus::Fail,
            format!("{}: {e}", token.display()),
            Some(
                "put the DNS provider's API token (scoped to the wildcard zones only) in this \
                 file with mode 600",
            ),
        )),
    }

    let tls = d.ingress.tls_dir();
    let now = std::time::SystemTime::now();
    let window = std::time::Duration::from_secs(config.renew_before_days * 24 * 3600);
    let (mut missing, mut expired, mut due) = (Vec::new(), Vec::new(), Vec::new());
    let mut soonest: Option<u64> = None;
    for apex in &dns.wildcards {
        let name = format!("*.{apex}");
        let Ok(chain) = std::fs::read(tls.join(format!("_wildcard.{apex}.crt"))) else {
            missing.push(name);
            continue;
        };
        match weglarka_acme::chain_not_after(&chain) {
            Err(_) => missing.push(name),
            Ok(not_after) => match not_after.duration_since(now) {
                Err(_) => expired.push(name),
                Ok(left) => {
                    let days = left.as_secs() / (24 * 3600);
                    soonest = Some(soonest.map_or(days, |s| s.min(days)));
                    if left <= window {
                        due.push(name);
                    }
                }
            },
        }
    }
    let mut problems = Vec::new();
    if !expired.is_empty() {
        problems.push(format!("expired: {}", expired.join(", ")));
    }
    if !missing.is_empty() {
        problems.push(format!("none yet: {}", missing.join(", ")));
    }
    if !due.is_empty() {
        problems.push(format!("renewal due: {}", due.join(", ")));
    }
    if problems.is_empty() {
        out.push(ok(
            "acme.wildcards",
            format!(
                "{} wildcard certificate(s), the nearest expires in {} days",
                dns.wildcards.len(),
                soonest.unwrap_or(0)
            ),
        ));
    } else {
        out.push(check(
            "acme.wildcards",
            if expired.is_empty() {
                CheckStatus::Warn
            } else {
                CheckStatus::Fail
            },
            problems.join("; "),
            Some(
                "DNS-01 needs the API token to reach the zone and a CAA record (if any) that allows \
                 the CA; the worker retries every 30 minutes after a failure (see acme.certs for the \
                 last error)",
            ),
        ));
    }
}

/// `edge` (issue #95): every routed domain needs `<domain>.crt` + `<domain>.key` in the TLS
/// directory, otherwise its HTTPS handshake is refused (the plain-HTTP redirect still works). A
/// warning, not a failure: without `[acme]` the operator places the files, and a host without any
/// app domain legitimately has an empty directory.
fn ingress_tls<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let tls = d.ingress.tls_dir();
    let Some(domains) = routed_domains(d) else {
        return; // `state.apps` already reports this
    };
    // A wildcard pair on disk (`_wildcard.<apex>.crt|key`) serves the apex and one label below it.
    let wildcards = wildcard_apexes_on_disk(&tls);
    let missing: Vec<&str> = domains
        .iter()
        .filter(|domain| {
            let own = tls.join(format!("{domain}.crt")).is_file()
                && tls.join(format!("{domain}.key")).is_file();
            !own && !wildcards
                .iter()
                .any(|apex| weglarka_core::config::wildcard_covers(apex, domain))
        })
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        out.push(ok(
            "ingress.tls",
            format!("every routed domain has a certificate in {}", tls.display()),
        ));
    } else {
        out.push(check(
            "ingress.tls",
            CheckStatus::Warn,
            format!(
                "no certificate pair for: {} (in {})",
                missing.join(", "),
                tls.display()
            ),
            Some(if d.acme.is_some() {
                "the ACME worker orders it on its next pass (see acme.certs)"
            } else {
                "put <domain>.crt (PEM chain) and <domain>.key (0600) there, or enable [acme] in \
                 weglarka.toml to have them issued"
            }),
        ));
    }
}

/// `edge` (issue #162, ADR 0043): the client address survives only through the port forwarder
/// (pasta network + PROXY protocol). Without a running forwarder nothing is published at all.
async fn ingress_client_ip<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    match d
        .engine
        .podman()
        .container_inspect(FORWARDER_CONTAINER)
        .await
    {
        Ok(c) if c.state == ContainerState::Running => out.push(ok(
            "ingress.client_ip",
            "the port forwarder runs: nginx sees the real client address (PROXY protocol)",
        )),
        Ok(c) => out.push(check(
            "ingress.client_ip",
            CheckStatus::Fail,
            format!(
                "port forwarder {FORWARDER_CONTAINER} is {:?}: nothing is published",
                c.state
            ),
            Some("the next ingress pass restarts it; see `podman logs weglarka-forwarder`"),
        )),
        Err(_) => out.push(check(
            "ingress.client_ip",
            CheckStatus::Fail,
            format!("port forwarder {FORWARDER_CONTAINER} does not exist: nothing is published"),
            Some("it is created by the next ingress pass; check ingress.apply for the error"),
        )),
    }
}

/// `edge` behind a CDN (issue #159, ADR 0044): which range list nginx trusts for the visitor header.
fn ingress_cdn<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Some(cdn) = &d.host.ingress.cdn else {
        return;
    };
    let status = d.ingress.cdn_status();
    let trust = match crate::ingress::cdn_trust(&d.host, None) {
        Ok(Some(trust)) => trust,
        Ok(None) => return,
        Err(e) => {
            out.push(check(
                "ingress.cdn",
                CheckStatus::Fail,
                e.to_string(),
                Some("fix [ingress.cdn] ranges in weglarka.toml"),
            ));
            return;
        }
    };
    let source = if !cdn.ranges.is_empty() {
        format!("pinned, {} ranges", trust.ranges.len())
    } else {
        match status.as_ref().and_then(|s| s.refreshed.as_ref()) {
            Some((etag, age)) => format!("refreshed {} ago, etag {etag}", human_age(*age)),
            None => match &trust.source {
                weglarka_ingress::RangeSource::Bundled { etag } => format!("bundled etag {etag}"),
                _ => "bundled".to_owned(),
            },
        }
    };
    let message = format!(
        "{:?}: the visitor is read from {} for peers in the list ({source})",
        cdn.provider,
        cdn.provider.client_ip_header()
    );
    let stale = status
        .as_ref()
        .and_then(|s| s.refreshed.as_ref())
        .is_some_and(|(_, age)| *age > crate::cdn::STALE_AFTER);
    let error = status.as_ref().and_then(|s| s.last_error.clone());
    out.push(match (error, stale) {
        (Some(error), _) => check(
            "ingress.cdn",
            CheckStatus::Warn,
            format!("{message}; the last refresh was not applied: {error}"),
            Some("the last good list stays in use; the refresh is retried hourly"),
        ),
        (None, true) => check(
            "ingress.cdn",
            CheckStatus::Warn,
            format!("{message}; the last successful refresh is older than 7 days"),
            Some("check the daemon's outbound HTTPS to api.cloudflare.com"),
        ),
        (None, false) => ok("ingress.cdn", message),
    });
}

/// `acme.cdn` (issue #159): a routed domain whose address lies in the CDN ranges is validated through
/// the proxy, and unless a wildcard covers it (DNS-01 does not care about the proxy) its HTTP-01
/// depends on the zone settings (`docs/guides/acme-behind-cdn.md`). A hint, not a failure.
async fn acme_cdn<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use weglarka_ingress::Cidr;

    if d.host.ingress.cdn.is_none() || !d.host.acme.as_ref().is_some_and(|a| a.enabled) {
        return;
    }
    let (Ok(Some(trust)), Some(domains)) = (d.ingress.cdn_trust(), routed_domains(d)) else {
        return;
    };
    let wildcards = wildcard_apexes_on_disk(&d.ingress.tls_dir());
    let mut proxied = Vec::new();
    for domain in domains {
        if wildcards
            .iter()
            .any(|apex| weglarka_core::config::wildcard_covers(apex, &domain))
        {
            continue;
        }
        let resolve = async {
            tokio::net::lookup_host((domain.as_str(), 443))
                .await
                .map(Iterator::collect::<Vec<_>>)
        };
        let Ok(Ok(addresses)) =
            tokio::time::timeout(std::time::Duration::from_secs(3), resolve).await
        else {
            continue; // unresolvable here is `acme.certs`' business, not this hint's
        };
        let behind_cdn = addresses.into_iter().any(|a| {
            a.ip()
                .to_string()
                .parse::<Cidr>()
                .is_ok_and(|ip| trust.ranges.iter().any(|r| r.covers(&ip)))
        });
        if behind_cdn {
            proxied.push(domain);
        }
    }
    if proxied.is_empty() {
        out.push(ok(
            "acme.cdn",
            "no routed domain without wildcard coverage resolves into the CDN ranges",
        ));
    } else {
        out.push(check(
            "acme.cdn",
            CheckStatus::Warn,
            format!(
                "{} resolve{} into the CDN ranges and {} no wildcard certificate: HTTP-01 goes through the proxy",
                proxied.join(", "),
                if proxied.len() == 1 { "s" } else { "" },
                if proxied.len() == 1 { "has" } else { "have" },
            ),
            Some(
                "cover them with [acme.dns] wildcards, or follow docs/guides/acme-behind-cdn.md for the zone settings",
            ),
        ));
    }
}

fn human_age(age: std::time::Duration) -> String {
    let hours = age.as_secs() / 3600;
    if hours >= 48 {
        format!("{}d", hours / 24)
    } else {
        format!("{hours}h")
    }
}

/// Apexes with a wildcard pair (`_wildcard.<apex>.crt` + `.key`, regular files) in `tls`.
fn wildcard_apexes_on_disk(tls: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(tls) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let apex = name
                .strip_suffix(".crt")?
                .strip_prefix(weglarka_core::config::WILDCARD_CERT_PREFIX)?
                .to_owned();
            let key = tls.join(format!(
                "{}{apex}.key",
                weglarka_core::config::WILDCARD_CERT_PREFIX
            ));
            (entry.path().is_file() && key.is_file()).then_some(apex)
        })
        .collect()
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
    let have: BTreeSet<String> = list.iter().map(|m| m.name.clone()).collect();
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
    // Orphans (issue #80): secrets of an instance that is no longer in `apps.toml` — the leftovers of
    // a removed or renamed app. A warning, not a failure: they break nothing at runtime, they are a
    // hygiene problem (the store is never written by the removal unless `--purge-secrets` is used).
    let mut orphans: BTreeMap<InstanceName, Vec<&str>> = BTreeMap::new();
    for meta in &list {
        let Ok((instance, name)) = split_scoped(&meta.name) else {
            continue; // a malformed key is reported by the store itself (`state.secrets_file`)
        };
        if apps.apps.contains_key(&instance) {
            continue;
        }
        orphans.entry(instance).or_default().push(name);
    }
    if !orphans.is_empty() {
        let listed = orphans
            .iter()
            .map(|(app, names)| format!("{app} ({})", names.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        out.push(check(
            "state.orphan_secrets",
            CheckStatus::Warn,
            format!("secrets of apps not in apps.toml: {listed}"),
            Some(
                "`weglarka secrets remove <app> <name>`; `weglarka apps remove <app> --purge-secrets` \
                 deletes the whole scope next time",
            ),
        ));
    }
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
    ingress_routes(d, out);
    if d.host.ingress.mode == IngressMode::Edge {
        ingress_tls(d, out);
        ingress_client_ip(d, out).await;
        ingress_cdn(d, out);
        acme_cdn(d, out).await;
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
