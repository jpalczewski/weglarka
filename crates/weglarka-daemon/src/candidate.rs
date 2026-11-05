//! One validation of a candidate `apps.toml` (issue #461, item of tracking issue #77).
//!
//! Every daemon path that is about to persist an app set — `apps add`, `apps update` and
//! `sites declare` — runs the same list here instead of its own subset, so a cross-app rule cannot
//! be enforced on one path and silently missed on another (an update skipped
//! `shared_networks::validate`, which turned a user error into a `500` from `save_apps`). The rules
//! and their order:
//!
//! 1. the changed app on its own ([`state::validate_app`]),
//! 2. the host-aware rules of that app (host mounts, forward auth, the identity provider, `configs`),
//! 3. the whole candidate set ([`state::validate_apps`]: identity clients, `depends_on`, shared
//!    volumes, shared networks),
//! 4. the host-wide rules over that set (`host_ports`, `internal_hosts`) and whether the ingress can
//!    render it ([`weglarka_ingress::Plan::build`]).
//!
//! Nothing here writes: a failure means the candidate was refused and the file on disk is untouched.

use weglarka_api::ErrorCode;
use weglarka_model::app::{AppSpec, AppsFile, InstanceName};
use weglarka_model::podman::PodmanClient;
use weglarka_model::state;

use crate::admin::{ApiResult, Fail};
use crate::app::Daemon;

/// Validates a candidate set in which `name`/`spec` is the one app that changed (`apps add`,
/// `apps update`). `apps` must already contain the candidate spec under `name`.
pub(crate) fn validate_app<P: PodmanClient>(
    d: &Daemon<P>,
    name: &InstanceName,
    spec: &AppSpec,
    apps: &AppsFile,
) -> ApiResult<()> {
    state::validate_app(name, spec).map_err(Fail::invalid)?;
    validate_host_rules(d, name, spec)?;
    validate_set(d, apps)
}

/// Validates a candidate set whose instances were re-derived rather than supplied one by one
/// (`sites declare` → `AppsFile::set_sites`). The per-app rules apply too: an environment expanded
/// from a site is an instance like any other.
pub(crate) fn validate_set<P: PodmanClient>(d: &Daemon<P>, apps: &AppsFile) -> ApiResult<()> {
    state::validate_apps(apps).map_err(|message| classify(apps, message))?;
    weglarka_model::host_ports::validate(&d.host, apps)
        .map_err(|e| Fail::invalid(e.to_string()))?;
    weglarka_model::internal_hosts::validate(&d.host, apps)
        .map_err(|e| Fail::invalid(e.to_string()))?;
    weglarka_ingress::Plan::build(&d.host, &apps.apps).map_err(|e| Fail::invalid(e.to_string()))?;
    Ok(())
}

/// An `[oidc_clients.<id>]` whose id equals an instance name is two valid declarations that cannot
/// coexist (#461); the fix is to rename or remove one of them, so it is a `409`. Everything else the
/// candidate set fails on is a malformed request (`400`). The per-app rules already passed by the
/// time the set is checked, so a shadow here is what `message` is about.
fn classify(apps: &AppsFile, message: String) -> Fail {
    let shadowed = apps
        .oidc_clients
        .keys()
        .any(|id| weglarka_model::identity::shadowed_instance(apps, id).is_some());
    if shadowed {
        return Fail(ErrorCode::Conflict, message);
    }
    Fail::invalid(message)
}

/// `apps add`/`apps update`: an app with `configs` needs `config_root` in `weglarka.toml`. The
/// sources themselves are not checked here — a file that does not exist yet must not block adding
/// the app; reconcile blocks the instance and `doctor` warns until the source appears. The lexical
/// rules (`relative`, no `..`, unique `target`) are already enforced by `state::validate_app`.
pub(crate) fn validate_host_rules<P: PodmanClient>(
    d: &Daemon<P>,
    name: &InstanceName,
    spec: &AppSpec,
) -> ApiResult<()> {
    // Host mounts (issue #178): the source must be an exact entry of the operator's allowlist, so a
    // bad one is a 400 now instead of a blocked app later.
    weglarka_engine::host_mounts::check_allowed(&d.host.runtime.host_mounts, spec)
        .map_err(|e| Fail::invalid(e.to_string()))?;
    weglarka_engine::host_mounts::check_groups(&d.host.runtime.group_add, spec)
        .map_err(|e| Fail::invalid(e.to_string()))?;
    // Forward auth needs `[identity]` and domains, and the provider cannot protect itself.
    weglarka_model::identity::validate_host_app(&d.host, name, spec).map_err(Fail::invalid)?;
    // The provider's own spec: issuer host, generated config loaded last, no auto-update (#88).
    weglarka_model::identity::validate_provider(&d.host, name, spec).map_err(Fail::invalid)?;
    if spec.configs.is_empty() || d.paths.config_root.is_some() {
        return Ok(());
    }
    Err(Fail::invalid(
        "the app declares `configs`, but weglarka.toml sets no `config_root`; set it to the host \
         directory with the config files, then re-run `weglarka platform install` so the daemon \
         container mounts it read-only",
    ))
}
