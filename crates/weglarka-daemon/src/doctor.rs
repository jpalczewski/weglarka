//! Daemon-side `doctor`: what makes sense to check from inside the running process.
//! Host checks (subuid, linger, cgroups…) are done by `weglarka doctor --preflight`.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;

use weglarka_api::{CertStatus, CheckStatus, DoctorCheck, DoctorReport};
use weglarka_engine::config_mounts::{self, MountStatus};
use weglarka_model::app::{AppSpec, AppsFile, InstanceName};
use weglarka_model::config::IngressMode;
use weglarka_model::labels;
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ContainerState, PodmanClient, VolumeFilter,
};
use weglarka_model::secret_store::{SecretStore, scoped_name, split_scoped};
use weglarka_model::shared_networks;
use weglarka_model::shared_volumes;
use weglarka_model::state::{self, StateFile};

use crate::app::{Daemon, WEBHOOK_SECRET};
use crate::app_view::Access;
use crate::certificates::{self, routed_domains};
use crate::ingress::{FORWARDER_CONTAINER, NGINX_CONTAINER};

fn check(
    id: &str,
    status: CheckStatus,
    message: impl Into<String>,
    hint: Option<&str>,
) -> DoctorCheck {
    let check = DoctorCheck::new(id, status, message);
    match hint {
        Some(hint) => check.with_hint(hint),
        None => check,
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

/// Delimits free-form failure text (engine, Podman and I/O errors) inside a check message; see
/// [`detail`] and [`apply_access`].
const DETAIL_OPEN: char = '\u{1}';
const DETAIL_CLOSE: char = '\u{2}';
/// Stands in for [`detail`] text in a report served to a caller that may not see it.
const WITHHELD: &str = "<details withheld>";

/// Marks `text` as free-form failure text. Checks interpolate every error they do not author
/// themselves through this, so [`apply_access`] is the single place that decides who sees it: the
/// report is also served at the `read` scope, and engine/Podman error text can name paths, images or
/// secrets. The markers never reach the wire, and `text` cannot forge or close one.
fn detail(text: impl std::fmt::Display) -> String {
    let text: String = text
        .to_string()
        .chars()
        .filter(|c| *c != DETAIL_OPEN && *c != DETAIL_CLOSE)
        .collect();
    format!("{DETAIL_OPEN}{text}{DETAIL_CLOSE}")
}

/// Resolves the [`detail`] markers in every message: kept for [`Access::Full`] callers, replaced by
/// [`WITHHELD`] for [`Access::Redacted`] ones.
fn apply_access(access: Access, checks: &mut [DoctorCheck]) {
    for c in checks {
        let mut out = String::with_capacity(c.message.len());
        let mut rest = c.message.as_str();
        while let Some(start) = rest.find(DETAIL_OPEN) {
            out.push_str(&rest[..start]);
            let after = &rest[start + DETAIL_OPEN.len_utf8()..];
            // A missing close marker cannot happen, but then withhold the remainder.
            let (text, tail) = after.split_once(DETAIL_CLOSE).unwrap_or(("", ""));
            match access {
                Access::Full => out.push_str(text),
                Access::Redacted => out.push_str(WITHHELD),
            }
            rest = tail;
        }
        out.push_str(rest);
        c.message = out;
    }
}

pub(crate) async fn run<P: PodmanClient + 'static>(d: &Daemon<P>, access: Access) -> DoctorReport {
    let mut checks = Vec::new();
    checks.push(ok(
        "daemon.version",
        format!("weglarka-daemon {}", env!("CARGO_PKG_VERSION")),
    ));
    podman(d, &mut checks).await;
    let observed = desired_state(d, &mut checks).await;
    if let Some(observed) = &observed {
        image_retention(d, observed, &mut checks).await;
        memory_use(d, observed, &mut checks).await;
    }
    configs(d, &mut checks);
    host_mounts(d, &mut checks);
    sites(d, &mut checks);
    shared_volume_state(d, &mut checks).await;
    shared_network_state(d, &mut checks).await;
    orphan_networks(d, &mut checks).await;
    secrets(d, &mut checks);
    crate::update::doctor_check(d, &mut checks);
    self_update(d, &mut checks);
    ingress(d, &mut checks).await;
    acme(d, scan_certificates(d).await.as_deref(), &mut checks);
    generated(d, &mut checks);
    identity_provider(d, &mut checks).await;
    identity_base_config(d, &mut checks);
    oidc_credentials(d, &mut checks);
    identity_forward(d, &mut checks).await;
    admin_http(d, &mut checks).await;
    webhook(d, &mut checks).await;
    metrics(d, &mut checks);
    metrics_scraper(d, &mut checks).await;
    apply_access(access, &mut checks);
    DoctorReport { checks }
}

/// `metrics.listener` (issue #350): only with `[metrics]`; a feature that is off adds no line.
fn metrics<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use crate::metrics::ListenerStatus;
    if d.host.metrics.is_none() {
        return;
    }
    out.push(match d.metrics.get() {
        Some(ListenerStatus::Listening { addr, network }) => ok(
            "metrics.listener",
            format!("serving /metrics on {addr}, reachable on network {network}"),
        ),
        Some(ListenerStatus::Joining {
            addr,
            network,
            last_error,
        }) => check(
            "metrics.listener",
            CheckStatus::Warn,
            match last_error {
                Some(error) => format!(
                    "serving /metrics on {addr}, but not on network {network} yet: {}", detail(&error)
                ),
                None => format!("serving /metrics on {addr}, joining network {network}"),
            },
            Some("the daemon keeps retrying every few seconds; no restart is needed once Podman works"),
        ),
        Some(ListenerStatus::Failed(error)) => check(
            "metrics.listener",
            CheckStatus::Fail,
            format!("not started: {}", detail(&error)),
            Some("fix [metrics] listen (the address must be free) and restart the daemon"),
        ),
        None => check("metrics.listener", CheckStatus::Warn, "starting", None),
    });
}

/// `metrics.scraper` (issue #365): only with `[metrics] scraper`. Never `fail`: an unknown or stopped
/// scraper or a missing network membership is a `warn`, since the daemon itself keeps working.
async fn metrics_scraper<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    const ID: &str = "metrics.scraper";
    let Some((instance, network, listen)) = d
        .host
        .metrics
        .as_ref()
        .and_then(|m| m.scraper.as_ref().map(|s| (s, &m.network, m.listen)))
    else {
        return;
    };
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // already reported as `state.apps_file`
    };
    if !apps.apps.contains_key(instance) {
        out.push(check(
            ID,
            CheckStatus::Warn,
            format!("[metrics] scraper {instance} is not an app in apps.toml"),
            Some(
                "add the app, or point [metrics] scraper at an existing one and restart the daemon",
            ),
        ));
        return;
    }
    let podman = d.engine.podman();
    let (networks, containers) = match (
        podman.network_list().await,
        podman.container_list(&ContainerFilter::default()).await,
    ) {
        (Ok(n), Ok(c)) => (n, c),
        (Err(e), _) | (_, Err(e)) => {
            out.push(check(
                ID,
                CheckStatus::Warn,
                format!("cannot list Podman networks or containers: {e}"),
                None,
            ));
            return;
        }
    };
    let name = labels::container_name(instance);
    let running = containers
        .iter()
        .any(|c| c.name == name && c.state == ContainerState::Running);
    if !running {
        out.push(check(
            ID,
            CheckStatus::Warn,
            format!("scraper {instance} has no running container"),
            Some("start or deploy it (`weglarka apps start <app>`); it joins its networks when it runs"),
        ));
        return;
    }
    let scraper = weglarka_engine::scraper::MetricsScraper {
        instance: instance.clone(),
        network: network.clone(),
    };
    let wanted = weglarka_engine::scraper::wanted_networks(&scraper, &apps, &networks);
    let mut missing: Vec<String> =
        weglarka_engine::scraper::plan_membership(Some(&scraper), &apps, &networks, &containers)
            .into_iter()
            .filter_map(|change| match change {
                weglarka_engine::scraper::MembershipChange::Connect { network, container }
                    if container == name =>
                {
                    Some(network)
                }
                _ => None,
            })
            .collect();
    // The daemon's own network is created by the listener; until it exists nothing can join it.
    if !networks.iter().any(|n| &n.name == network) {
        missing.insert(0, network.clone());
    }
    if missing.is_empty() && listen.ip().is_loopback() {
        // Joined, but a loopback listener only answers inside the daemon's own container.
        out.push(check(
            ID,
            CheckStatus::Warn,
            format!(
                "scraper {instance} is on its networks, but [metrics] listen {listen} is a loopback \
                 address: the scraper can never reach the daemon's /metrics"
            ),
            Some("listen on 0.0.0.0 (nothing is published on the host) and restart the daemon"),
        ));
    } else if missing.is_empty() {
        out.push(ok(
            ID,
            format!(
                "scraper {instance} is on {} metrics network(s): {}",
                wanted.len(),
                wanted.join(", ")
            ),
        ));
    } else {
        out.push(check(
            ID,
            CheckStatus::Warn,
            format!(
                "scraper {instance} is not on network(s): {}",
                missing.join(", ")
            ),
            Some("the next reconcile pass connects it; if this persists, see the daemon log (and `metrics.listener` for the daemon's network)"),
        ));
    }
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
    let state_path = weglarka_model::self_update::path(&d.paths.state_dir);
    let state = match weglarka_model::self_update::load(&d.paths.state_dir) {
        Ok(state) => state,
        Err(e) => {
            out.push(check(
                "self_update",
                CheckStatus::Warn,
                detail(e),
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
    let now = weglarka_model::self_update::secs(std::time::SystemTime::now());
    if let Some(pending) = &state.pending {
        let age = state.pending_at.map_or(0, |at| now.saturating_sub(at));
        parts.push(format!("pending {} for {age}s", short(pending)));
    }
    if let Some(error) = &state.error {
        let age = now.saturating_sub(error.at);
        parts.push(format!(
            "last attempt failed {age}s ago: {}",
            detail(&error.message)
        ));
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
fn short(digest: &weglarka_model::app::Digest) -> &str {
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
            format!("Podman socket unavailable: {}", detail(&e)),
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
            detail(e),
            Some(state_hint(e, "fix or remove apps.toml")),
        ),
    });
    out.push(match &st {
        Ok(_) => ok("state.state_file", "state.toml is valid"),
        Err(e) => check(
            "state.state_file",
            CheckStatus::Fail,
            detail(e),
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
                Some(failed) => problems.push(format!(
                    "{name}: first deploy failed: {}",
                    detail(&failed.reason)
                )),
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

/// Share of its memory limit (in percent) at which a container is reported as nearly full.
const MEMORY_WARN_PERCENT: u64 = 80;

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

/// Memory use of the running containers (issue #208): one libpod stats call, matched to the container
/// list by name. Never `fail`: the numbers are advice, and a missing stats answer must not hide the
/// rest of the report. The nginx container has no limit setting yet, so its missing limit is `info`.
async fn memory_use<P: PodmanClient>(
    d: &Daemon<P>,
    observed: &Observed,
    out: &mut Vec<DoctorCheck>,
) {
    const ID: &str = "runtime.memory";
    let running: Vec<&ContainerInfo> = observed
        .containers
        .iter()
        .filter(|c| c.state == ContainerState::Running)
        .collect();
    let stats = match d.engine.podman().container_stats().await {
        Ok(stats) => stats,
        Err(e) => {
            out.push(check(
                ID,
                CheckStatus::Info,
                format!("memory use unavailable: {}", detail(&e)),
                None,
            ));
            return;
        }
    };
    let usage: BTreeMap<&str, u64> = stats
        .iter()
        .map(|s| (s.name.as_str(), s.memory_usage))
        .collect();

    let mut total = 0u64;
    let mut highest: Option<(&str, u64, u64)> = None; // name, usage, limit
    let mut near_limit = Vec::new();
    let mut no_data = Vec::new();
    let mut nginx_unlimited = false;
    for c in &running {
        // No stats entry is "no data" just like a reported 0: never idle.
        let used = usage.get(c.name.as_str()).copied().unwrap_or(0);
        if used == 0 {
            no_data.push(c.name.as_str());
            continue;
        }
        total += used;
        match c.memory_limit {
            Some(limit) => {
                let percent = used.saturating_mul(100) / limit;
                if percent >= MEMORY_WARN_PERCENT {
                    near_limit.push(format!("{} ({percent}%)", c.name));
                }
                if highest.is_none_or(|(_, u, l)| used as f64 / limit as f64 > u as f64 / l as f64)
                {
                    highest = Some((&c.name, used, limit));
                }
            }
            None => nginx_unlimited |= c.name == NGINX_CONTAINER,
        }
    }

    let mut summary = format!(
        "{} running container(s), {} in use",
        running.len(),
        mib(total)
    );
    if let Some((name, used, limit)) = highest {
        summary.push_str(&format!(
            ", highest against a limit: {name} {} of {}",
            mib(used),
            mib(limit)
        ));
    }
    let mut parts = vec![summary];
    let mut status = CheckStatus::Ok;
    let mut hint = None;
    if !near_limit.is_empty() {
        status = CheckStatus::Warn;
        parts.push(format!(
            "at {MEMORY_WARN_PERCENT}% or more of the memory limit: {}",
            near_limit.join(", ")
        ));
        hint = Some(
            "raise `resources.memory` of the app (blue-green `.next`/`.prev` share it), or `[platform] memory` in weglarka.toml for the daemon itself; or find out why it uses more",
        );
    }
    if nginx_unlimited {
        status = status.max(CheckStatus::Info);
        parts.push(format!("{NGINX_CONTAINER} has no memory limit"));
    }
    if !no_data.is_empty() {
        status = status.max(CheckStatus::Info);
        parts.push(format!(
            "no memory data for {} (probably no cgroup controller delegation to the runtime user)",
            no_data.join(", ")
        ));
    }
    out.push(check(ID, status, parts.join("; "), hint));
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
    let plan = weglarka_engine::images::plan(
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
            weglarka_engine::images::human_bytes(plan.reclaimable_bytes())
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
/// Sites with environments (issue #205): a promote-only environment that has never been promoted
/// into answers 503 on its domain. Nothing is emitted while no site is declared.
fn sites<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // reported by `state.apps_file`
    };
    if apps.sites.is_empty() {
        return;
    }
    let st = state::load_state(&d.paths.state.state).unwrap_or_default();
    let unpromoted: Vec<String> = apps
        .origins
        .iter()
        .filter(|(name, o)| {
            o.promote_from.is_some() && st.apps.get(*name).is_none_or(|s| s.current.is_none())
        })
        .map(|(_, o)| format!("{}/{}", o.site, o.env))
        .collect();
    out.push(if unpromoted.is_empty() {
        ok(
            "sites.unpromoted",
            "every promote-only environment has a release",
        )
    } else {
        check(
            "sites.unpromoted",
            CheckStatus::Warn,
            format!(
                "promote-only environments without a release (their domains answer 503): {}",
                unpromoted.join(", ")
            ),
            Some("`weglarka promote <site> <env>` after the source environment has a release"),
        )
    });
}

fn host_mounts<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use weglarka_engine::host_mounts::{HostMountStatus, describe};
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
        if let Err(e) = weglarka_engine::host_mounts::check_groups(&d.host.runtime.group_add, spec)
        {
            broken.push(format!("{name}: {}", detail(&e)));
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
                format!("config_root {} is not available: {}", root.display(), detail(&e)),
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
                        format!("cannot read config_root {}: {}", root.display(), detail(&e)),
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
                format!("cannot list Podman volumes: {}", detail(&e)),
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
                format!("cannot list Podman networks: {}", detail(&e)),
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

/// `state.orphan_networks` (issue #53): Węglarka-labelled `net-<instance>` networks without an app.
/// Reconcile removes them best effort, so one that lingers means the cleanup keeps failing (a
/// container is still attached) or it is a leftover from an older version. Silent when there are none.
async fn orphan_networks<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // already reported as `state.apps_file`
    };
    // A listing failure is already reported by `state.shared_networks`.
    let Ok(networks) = d.engine.podman().network_list().await else {
        return;
    };
    let orphans: Vec<&str> = networks
        .iter()
        .filter(|n| weglarka_engine::reconcile::is_orphaned_app_network(n, &apps))
        .map(|n| n.name.as_str())
        .collect();
    if orphans.is_empty() {
        return;
    }
    out.push(check(
        "state.orphan_networks",
        CheckStatus::Warn,
        format!(
            "Podman networks of apps that no longer exist: {}",
            orphans.join(", ")
        ),
        Some("detach what is still attached and remove them: `podman network rm <name>`"),
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
                detail(e),
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
            let mut line = format!("{}{} -> {}:{}", r.domain, r.path, r.instance, r.backend);
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

/// `[acme]` (issue #96): the configuration, the account key and the state of every certificate.
/// `acme.certs` is a failure only for a certificate that has already expired; a missing one or one
/// inside the renewal window is a warning (the worker is expected to deal with it on its next pass),
/// and so is a failure the last pass recorded.
/// Generated config (#212), one check per generator: the live and the applied version, whether the
/// version was applied without validation (a first start), and what the last failed attempt said.
fn generated<P: PodmanClient + 'static>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use weglarka_model::generated_state::{FILE_NAME, GeneratedState, LastResult};
    let Some(worker) = &d.generated else {
        return;
    };
    let recorded = GeneratedState::load(&d.paths.state_dir.join(FILE_NAME));
    let short = |fingerprint: &str| fingerprint.chars().take(12).collect::<String>();
    for generator in worker.generators() {
        let id = format!("generated.{}", generator.id());
        let consumer = generator.consumer();
        let live = d.engine.generated_live_version(consumer);
        let Some(record) = recorded.get(generator.id()) else {
            out.push(check(
                &id,
                CheckStatus::Info,
                format!("nothing rendered yet for {consumer}"),
                None,
            ));
            continue;
        };
        let applied = record.applied.as_deref().map(short);
        let state = format!(
            "{consumer}: live {}, applied {}",
            live.as_deref().unwrap_or("none"),
            applied
                .as_deref()
                .map_or("none".to_owned(), |a| format!("v-{a}")),
        );
        let failed = matches!(
            record.last_result,
            LastResult::Invalid | LastResult::RolledBack | LastResult::Failed
        );
        if failed {
            let what = match record.last_result {
                LastResult::Invalid => "the validator rejected the last render",
                LastResult::RolledBack => "the consumer failed its health gate on the last render",
                _ => "the last render could not be applied",
            };
            out.push(check(
                &id,
                CheckStatus::Warn,
                format!(
                    "{state}; {what}: {}",
                    detail(record.last_error.as_deref().unwrap_or("no output"))
                ),
                Some(
                    "the previous version is still live, so what it contains (OIDC clients, access \
                     rules: a tightened `auth_groups` is not enforced until a render applies) stays \
                     as it was; the render is tried again when it changes",
                ),
            ));
        } else if live.as_deref() != applied.map(|a| format!("v-{a}")).as_deref() {
            out.push(check(
                &id,
                CheckStatus::Warn,
                format!("{state}; the live version is not the applied one"),
                Some("the next pass applies it; if this persists, check the daemon log"),
            ));
        } else if !record.validated {
            out.push(check(
                &id,
                CheckStatus::Info,
                format!(
                    "{state}; unvalidated (applied before the consumer could run the validator)"
                ),
                None,
            ));
        } else {
            out.push(ok(&id, state));
        }
    }
}

/// One scan of `tls/` for the whole run, on the blocking pool, shared by `acme` and `acme_dns`.
/// `None` when ACME is off or the scan failed (`acme` then skips the certificate rows).
async fn scan_certificates<P: PodmanClient>(d: &Daemon<P>) -> Option<Vec<certificates::Cert>> {
    let config = d.host.acme.as_ref().filter(|c| c.enabled)?;
    // Without a readable `apps.toml` only the wildcard rows (no routed domains) are of use.
    let domains = routed_domains(d).unwrap_or_default();
    certificates::collect_blocking(
        d.ingress.tls_dir(),
        config.clone(),
        domains,
        std::time::SystemTime::now(),
    )
    .await
}

fn acme<P: PodmanClient>(
    d: &Daemon<P>,
    certs: Option<&[certificates::Cert]>,
    out: &mut Vec<DoctorCheck>,
) {
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
    let staging = config.directory_url == weglarka_model::config::AcmeConfig::LETS_ENCRYPT_STAGING;
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
            format!("{}: {}", key.display(), detail(&e)),
            None,
        )),
    }

    if let Some(dns) = &config.dns {
        acme_dns(config, dns, certs, out);
    }

    let Some(domains) = routed_domains(d) else {
        return; // `state.apps` already reports this
    };
    let Some(certs) = certs else {
        return; // the scan failed and was logged
    };
    let now = std::time::SystemTime::now();
    let window = certificates::window(config);
    let (mut missing, mut expired, mut due) = (Vec::new(), Vec::new(), Vec::new());
    let mut soonest: Option<u64> = None;
    let mut covered = 0usize;
    for cert in certs.iter().filter(|c| !c.wildcard) {
        let status = cert.status(now, window);
        let days = cert.days_left(now).and_then(|d| u64::try_from(d).ok());
        match status {
            CertStatus::Covered => covered += 1,
            CertStatus::Missing => missing.push(cert.label()),
            CertStatus::Expired => expired.push(cert.label()),
            CertStatus::RenewalDue | CertStatus::Valid => {
                if let Some(days) = days {
                    soonest = Some(soonest.map_or(days, |s| s.min(days)));
                }
                if status == CertStatus::RenewalDue {
                    due.push(cert.label());
                }
            }
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
        problems.push(format!("last pass failed for {cert}: {}", detail(reason)));
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
fn acme_dns(
    config: &weglarka_model::config::AcmeConfig,
    dns: &weglarka_model::config::AcmeDnsConfig,
    certs: Option<&[certificates::Cert]>,
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
            format!("{}: {}", token.display(), detail(&e)),
            Some(
                "put the DNS provider's API token (scoped to the wildcard zones only) in this \
                 file with mode 600",
            ),
        )),
    }

    let now = std::time::SystemTime::now();
    let window = certificates::window(config);
    let (mut missing, mut expired, mut due) = (Vec::new(), Vec::new(), Vec::new());
    let mut soonest: Option<u64> = None;
    let Some(certs) = certs else {
        return; // the scan failed and was logged
    };
    for cert in certs.iter().filter(|c| c.wildcard) {
        let status = cert.status(now, window);
        let days = cert.days_left(now).and_then(|d| u64::try_from(d).ok());
        let name = cert.label().to_owned();
        match status {
            CertStatus::Missing | CertStatus::Covered => missing.push(name),
            CertStatus::Expired => expired.push(name),
            CertStatus::RenewalDue | CertStatus::Valid => {
                if let Some(days) = days {
                    soonest = Some(soonest.map_or(days, |s| s.min(days)));
                }
                if status == CertStatus::RenewalDue {
                    due.push(name);
                }
            }
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
                .any(|apex| weglarka_model::config::wildcard_covers(apex, domain))
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
                detail(e),
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
            format!(
                "{message}; the last refresh was not applied: {}",
                detail(&error)
            ),
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
            .any(|apex| weglarka_model::config::wildcard_covers(apex, &domain))
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
                .strip_prefix(weglarka_model::config::WILDCARD_CERT_PREFIX)?
                .to_owned();
            let key = tls.join(format!(
                "{}{apex}.key",
                weglarka_model::config::WILDCARD_CERT_PREFIX
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
            detail(e),
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
                format!("{}: {}", path.display(), detail(&e)),
                Some("the file must exist and belong to the runtime user (ACL only for traversing the directory)"),
            ),
        });
    }
    out.push(match d.ingress.last_error() {
        None => ok("ingress.apply", "last ingress generation had no errors"),
        Some(e) => check(
            "ingress.apply",
            CheckStatus::Fail,
            detail(e),
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

/// `identity.provider` (#88): the instance `[identity]` names exists, satisfies the provider rules
/// (issuer host among its domains, generated config loaded last, no auto-update), runs, and answers
/// its health endpoint over the probe socket. A wrong provider degrades the integration instead of
/// stopping the daemon, so this is where the operator hears about it.
async fn identity_provider<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use weglarka_model::podman::ContainerState;
    let Some(identity) = &d.host.identity else {
        return;
    };
    let id = "identity.provider";
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // `state.apps` already reports this
    };
    let name = &identity.instance;
    let Some(spec) = apps.apps.get(name) else {
        out.push(check(
            id,
            CheckStatus::Fail,
            format!("[identity] names {name}, which is not in apps.toml"),
            Some("add the provider as an ordinary app; protected apps are refused meanwhile"),
        ));
        return;
    };
    if let Err(message) = weglarka_model::identity::validate_provider(&d.host, name, spec) {
        out.push(check(
            id,
            CheckStatus::Fail,
            message,
            Some("see docs/guides/identity-provider.md"),
        ));
        return;
    }
    let running = matches!(
        d.engine
            .podman()
            .container_inspect(&weglarka_model::labels::container_name(name))
            .await,
        Ok(info) if info.state == ContainerState::Running
    );
    if !running {
        out.push(check(
            id,
            CheckStatus::Fail,
            format!("{name} is not running"),
            Some("`weglarka apps start` it; apps that depend on it wait and forward-auth apps answer 500"),
        ));
        return;
    }
    let issuer_host = identity
        .issuer
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or_default();
    let socket = crate::ingress::probe_socket_path(&d.paths.nginx_conf_dir);
    out.push(
        match crate::health_probe::get_over_probe(&socket, issuer_host, "/api/health").await {
            Ok(200) => ok(id, format!("{name} runs and answers /api/health")),
            Ok(status) => check(
                id,
                CheckStatus::Fail,
                format!("{name}: /api/health answered {status}"),
                Some("check the provider's logs; it must be routed by ingress on the issuer host"),
            ),
            Err(e) => check(
                id,
                CheckStatus::Fail,
                format!("{name}: {}", detail(&e)),
                Some("the provider must run and have the issuer host routed by ingress"),
            ),
        },
    );
}

/// Largest base config file `identity.base_config` reads.
const BASE_CONFIG_MAX_BYTES: u64 = 1024 * 1024;

/// The file's text when it is a regular file of at most `cap` bytes (read bounded, whatever the
/// metadata claimed), else `None`.
fn read_capped(path: &std::path::Path, cap: u64) -> Option<String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(cap + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= cap).then_some(text)
}

/// `identity.base_config` (#242): sections of the provider's own base config that the generated config
/// silently replaces (`access_control`, `identity_providers.oidc.clients`; ADR 0055). Scans only host
/// files delivered through the provider's `configs` (never a secret's value); a base file delivered
/// as a secret can only be flagged as unverifiable. Silent when nothing is wrong.
fn identity_base_config<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use weglarka_model::app::SecretTarget;
    use weglarka_model::identity::{GENERATED_CONFIG, config_sources, owned_sections_in};
    let Some(identity) = &d.host.identity else {
        return;
    };
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // `state.apps` already reports this
    };
    let Some(spec) = apps.apps.get(&identity.instance) else {
        return; // `identity.provider` reports it
    };
    // An unresolvable mount is `configs.mounts`' business.
    let Ok(mounts) = config_mounts::resolve_all(d.host.config_root.as_deref(), spec) else {
        return;
    };
    let mut found = Vec::new();
    let mut unverifiable = Vec::new();
    for source in config_sources(&spec.command)
        .into_iter()
        .filter(|s| s != GENERATED_CONFIG)
    {
        // `source` comes from the provider's command: never follow a `..` out of the mount.
        if source.split('/').any(|seg| seg == "..") {
            continue;
        }
        // The mount whose target is `source` or a directory holding it.
        let host = mounts.iter().find_map(|m| {
            let rest = source.strip_prefix(m.target.as_str())?;
            match rest {
                "" => Some(m.source.clone()),
                r if r.starts_with('/') => Some(m.source.join(r.trim_start_matches('/'))),
                _ => None,
            }
        });
        let Some(host) = host else {
            let is_secret = spec
                .secrets
                .iter()
                .any(|b| matches!(&b.target, SecretTarget::Mount { path, .. } if *path == source));
            if is_secret {
                unverifiable.push(source);
            }
            continue; // otherwise part of the image
        };
        let files = if host.is_dir() {
            std::fs::read_dir(&host)
                .map(|rd| {
                    rd.filter_map(Result::ok)
                        .map(|e| e.path())
                        .filter(|p| {
                            matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml"))
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![host]
        };
        for file in files {
            // A symlink must not lead out of the mount either.
            let (Ok(real), Some(mount)) = (
                file.canonicalize(),
                mounts.iter().find(|m| file.starts_with(&m.source)),
            ) else {
                continue;
            };
            if !real.starts_with(&mount.source) {
                continue;
            }
            let Some(text) = read_capped(&real, BASE_CONFIG_MAX_BYTES) else {
                continue;
            };
            for section in owned_sections_in(&text) {
                let entry = format!("{section} in {}", detail(&source));
                if !found.contains(&entry) {
                    found.push(entry);
                }
            }
        }
    }
    if !found.is_empty() {
        out.push(check(
            "identity.base_config",
            CheckStatus::Warn,
            format!(
                "the base config sets sections that the generated config replaces: {}",
                found.join(", ")
            ),
            Some("delete them from the base file (see docs/guides/identity-provider.md, \"What Węglarka owns\")"),
        ));
    }
    if !unverifiable.is_empty() {
        out.push(check(
            "identity.base_config",
            CheckStatus::Info,
            format!(
                "cannot verify {} (delivered as a secret): make sure it has no access_control or identity_providers.oidc.clients",
                detail(unverifiable.join(", "))
            ),
            Some("see docs/guides/identity-provider.md"),
        ));
    }
}

/// `admin.http` (ADR 0056): the token listener runs, its clients exist, and the provider's signing keys
/// can be fetched over the probe socket — the three things a token holder would otherwise discover as
/// a bare 401.
async fn admin_http<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let (Some(http), Some(identity)) = (&d.host.admin.http, &d.host.identity) else {
        return;
    };
    let id = "admin.http";
    if !d.paths.admin_token_socket().exists() {
        out.push(check(
            id,
            CheckStatus::Fail,
            format!(
                "the token socket {} does not exist",
                d.paths.admin_token_socket().display()
            ),
            Some("restart the daemon: [admin.http] is read at startup"),
        ));
        return;
    }
    if let Ok(apps) = state::load_apps(&d.paths.state.apps) {
        let missing: Vec<String> = http
            .clients
            .iter()
            .filter(|c| !apps.apps.contains_key(*c))
            .map(ToString::to_string)
            .collect();
        if !missing.is_empty() {
            out.push(check(
                id,
                CheckStatus::Warn,
                format!(
                    "[admin.http] clients not in apps.toml: {}",
                    missing.join(", ")
                ),
                Some("add the apps or drop them from `clients`; none of them gets the socket"),
            ));
        }
    }
    let Ok(issuer_host) = weglarka_model::identity::issuer_host(&identity.issuer) else {
        return; // `[identity]` validation already refused this
    };
    let fetcher = crate::admin_token::ProbeJwks {
        socket: crate::ingress::probe_socket_path(&d.paths.nginx_conf_dir),
        issuer_host: issuer_host.to_owned(),
    };
    let fetched = crate::admin_token::JwksFetcher::fetch(&fetcher)
        .await
        .and_then(|body| {
            weglarka_model::admin_auth::JwkSet::from_json(&body).map_err(|e| e.to_string())
        });
    out.push(match fetched {
        Ok(keys) if !keys.is_empty() => ok(
            id,
            format!(
                "token listener up; the provider publishes signing keys; {} client(s) get the socket",
                http.clients.len()
            ),
        ),
        Ok(_) => check(
            id,
            CheckStatus::Fail,
            "the provider's JWKS has no RS256 or ES256 signing key".to_owned(),
            Some("every token would be refused; see docs/guides/admin-api-tokens.md"),
        ),
        Err(e) => check(
            id,
            CheckStatus::Fail,
            format!("cannot fetch the provider's JWKS: {}", detail(&e)),
            Some("the provider must run and have the issuer host routed by ingress"),
        ),
    });
}

/// `oidc.credentials` (#213): an app with a confidential `oidc` client needs both halves of its
/// credential (the secret and the digest the provider's file is rendered from); one without the other
/// means a hand edit of the store that `weglarka oidc rotate <app>` repairs.
fn oidc_credentials<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    use weglarka_model::secret_store::{OIDC_CLIENT_DIGEST, OIDC_CLIENT_SECRET, scoped_name};
    if d.host.identity.is_none() {
        return;
    }
    let (Ok(apps), Ok(list)) = (state::load_apps(&d.paths.state.apps), d.secrets.list()) else {
        return;
    };
    let has = |name: String| list.iter().any(|m| m.name == name);
    let broken: Vec<String> = apps
        .apps
        .iter()
        .filter(|(_, spec)| spec.oidc.as_ref().is_some_and(|o| !o.public))
        .filter(|(name, _)| {
            has(scoped_name(name, OIDC_CLIENT_SECRET)) != has(scoped_name(name, OIDC_CLIENT_DIGEST))
        })
        .map(|(name, _)| name.to_string())
        .collect();
    if broken.is_empty() {
        return;
    }
    out.push(check(
        "oidc.credentials",
        CheckStatus::Fail,
        format!(
            "secret and digest of the OIDC client do not match for: {}",
            broken.join(", ")
        ),
        Some("`weglarka oidc rotate <app>` mints a fresh pair"),
    ));
}

/// `identity.forward` (#89): for each domain with forward auth, ask the provider the question nginx
/// asks, over the probe socket. 401 + `Location` is the healthy answer; 400 means the domain is not
/// under any `session.cookies[].domain` of the provider (nginx would answer 500 for every request).
async fn identity_forward<P: PodmanClient>(d: &Daemon<P>, out: &mut Vec<DoctorCheck>) {
    let Some(identity) = &d.host.identity else {
        return;
    };
    let Ok(apps) = state::load_apps(&d.paths.state.apps) else {
        return; // `state.apps` already reports this
    };
    let mut domains: Vec<&str> = apps
        .apps
        .values()
        .filter(|spec| spec.start && !spec.ingress.auth.is_none())
        .flat_map(|spec| spec.domains.iter().map(String::as_str))
        .collect();
    domains.sort_unstable();
    domains.dedup();
    if domains.is_empty() {
        return;
    }
    // `IdentityConfig::validate` guarantees the `https://` prefix.
    let issuer_host = identity.issuer.trim_start_matches("https://");
    let socket = crate::ingress::probe_socket_path(&d.paths.nginx_conf_dir);
    for domain in domains {
        let id = "identity.forward";
        let url = format!("https://{domain}/");
        out.push(
            match crate::health_probe::authz_probe(&socket, issuer_host, &url).await {
                Ok(a) if a.status == 401 && a.has_location => {
                    ok(id, format!("{domain}: the provider asks for a login"))
                }
                Ok(a) if a.status == 400 => check(
                    id,
                    CheckStatus::Fail,
                    format!("{domain}: the provider rejects the target URL (400)"),
                    Some("the domain must lie under a session.cookies[].domain of the provider; until then every request to it fails with 500"),
                ),
                Ok(a) => check(
                    id,
                    CheckStatus::Fail,
                    format!("{domain}: unexpected answer {} (location: {})", a.status, a.has_location),
                    Some("expected 401 with a Location; check that the provider runs and is routed by ingress"),
                ),
                Err(e) => check(
                    id,
                    CheckStatus::Fail,
                    format!("{domain}: {}", detail(&e)),
                    Some("the provider must run and have a domain routed by ingress; protected apps answer 500 meanwhile"),
                ),
            },
        );
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

#[cfg(test)]
mod access_tests {
    use super::*;

    fn msg(text: String) -> Vec<DoctorCheck> {
        vec![ok("x", text)]
    }

    #[test]
    fn detail_is_kept_for_full_and_withheld_for_redacted() {
        let text = format!("a: {} b: {}!", detail("secret one"), detail("two"));
        let mut full = msg(text.clone());
        apply_access(Access::Full, &mut full);
        assert_eq!(full[0].message, "a: secret one b: two!");
        let mut redacted = msg(text);
        apply_access(Access::Redacted, &mut redacted);
        assert_eq!(
            redacted[0].message,
            "a: <details withheld> b: <details withheld>!"
        );
    }

    #[test]
    fn detail_text_cannot_forge_or_close_a_marker() {
        let hostile = format!("x{DETAIL_CLOSE} leaked {DETAIL_OPEN}");
        let mut checks = msg(format!("e: {}", detail(&hostile)));
        apply_access(Access::Redacted, &mut checks);
        assert_eq!(checks[0].message, "e: <details withheld>");
    }

    #[test]
    fn a_message_without_detail_is_untouched() {
        let mut checks = msg("plain".into());
        apply_access(Access::Redacted, &mut checks);
        assert_eq!(checks[0].message, "plain");
    }
}
