//! `weglarka apps update/start/stop <name>` (API: `APPS_UPDATE`, full spec replacement) and
//! rendering of the "waiting for secret" state. **Owner: session 3 (iteration 2).**
//!
//! Read-modify-write: `GET` the current spec, apply the flags (or take a whole spec from `--spec`),
//! `PUT` the result. The daemon replaces the spec as a whole; the diff in `--dry-run` is therefore
//! exactly what will change.

use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;
use serde::Serialize;
use weglarka_api::endpoints;
use weglarka_api::{
    DeployOutcome, RuntimeState, ShowAppResponse, UpdateAppRequest, UpdateAppResponse,
};
use weglarka_core::app::{
    AppIngress, AppSpec, BodySizeLimit, InstanceName, SecretBinding, SecretTarget,
    SharedVolumeName, valid_volume_name,
};
use weglarka_core::state::AppState;

use crate::cli::{StartStopArgs, parse_pair};
use crate::client::expand_path;
use crate::commands::{client, instance, render_show};
use crate::error::{CliError, exit};
use crate::output::emit;
use crate::settings::Overrides;

/// Flags of `apps update`. Without `--spec` they edit the app's current spec; everything not
/// mentioned is kept (volumes, resources, health…).
#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Instance name.
    pub name: String,
    /// New image reference. Re-pins the app: the update deploys it right away (health gate,
    /// rollback to the previous version on failure).
    #[arg(conflicts_with = "spec")]
    pub image: Option<String>,
    /// Add a domain (repeatable). To replace one: `--remove-domain old --domain new`.
    #[arg(long = "domain", value_name = "DOMAIN", conflicts_with = "spec")]
    pub domains: Vec<String>,
    /// Remove a domain (repeatable).
    #[arg(long = "remove-domain", value_name = "DOMAIN", conflicts_with = "spec")]
    pub remove_domains: Vec<String>,
    /// Add a path prefix of the app's domains (repeatable), e.g. `/api`. Ingress-only: nginx reload,
    /// the container is not recreated.
    #[arg(long = "path", value_name = "PREFIX", conflicts_with = "spec")]
    pub paths: Vec<String>,
    /// Remove a path prefix (repeatable); with none left the app serves `/` again.
    #[arg(long = "remove-path", value_name = "PREFIX", conflicts_with = "spec")]
    pub remove_paths: Vec<String>,
    /// Strip the path prefix before proxying.
    #[arg(long, conflicts_with_all = ["spec", "no_strip_prefix"])]
    pub strip_prefix: bool,
    /// Stop stripping the path prefix.
    #[arg(long, conflicts_with = "spec")]
    pub no_strip_prefix: bool,
    /// HTTP port in the container.
    #[arg(long, conflicts_with_all = ["spec", "unset_port"])]
    pub port: Option<u16>,
    /// Remove the port (the app is no longer routed by ingress).
    #[arg(long, conflicts_with = "spec")]
    pub unset_port: bool,
    /// Serve streaming responses (SSE, chunked, long polling): no nginx buffering and a long idle
    /// timeout. Ingress-only: nginx reload, the container is not recreated.
    #[arg(long, conflicts_with_all = ["spec", "no_streaming"])]
    pub streaming: bool,
    /// Stop streaming: resets the streaming settings, a custom `stream_timeout_secs` included.
    #[arg(long, conflicts_with = "spec")]
    pub no_streaming: bool,
    /// Request body limit, e.g. `4g`, `512m` or a byte count; `0` removes the limit (default 64m).
    /// Also streams the request to the app instead of buffering it. Ingress-only: nginx reload.
    #[arg(long, value_name = "SIZE", value_parser = BodySizeLimit::parse,
        conflicts_with_all = ["spec", "unset_max_body_size"])]
    pub max_body_size: Option<BodySizeLimit>,
    /// Back to the default request body limit (64m) and buffering.
    #[arg(long, conflicts_with = "spec")]
    pub unset_max_body_size: bool,
    /// Leave a path out of the access log while it succeeds (repeatable); a trailing `/` makes it a
    /// prefix. Errors are still logged. Ingress-only: nginx reload.
    #[arg(
        long = "access-log-skip-path",
        value_name = "PATH",
        conflicts_with = "spec"
    )]
    pub access_log_skip_paths: Vec<String>,
    /// Log this path again (repeatable).
    #[arg(
        long = "remove-access-log-skip-path",
        value_name = "PATH",
        conflicts_with = "spec"
    )]
    pub remove_access_log_skip_paths: Vec<String>,
    /// Set an environment variable KEY=VALUE (plain, not secret; repeatable).
    #[arg(long = "env", value_name = "K=V", value_parser = parse_pair, conflicts_with = "spec")]
    pub env: Vec<(String, String)>,
    /// Remove an environment variable (repeatable).
    #[arg(long = "unset-env", value_name = "KEY", conflicts_with = "spec")]
    pub unset_env: Vec<String>,
    /// Bind a secret as an environment variable: SECRET=VARIABLE (replaces a binding of that secret).
    #[arg(long = "secret-env", value_name = "SECRET=VARIABLE", value_parser = parse_pair, conflicts_with = "spec")]
    pub secret_env: Vec<(String, String)>,
    /// Bind a secret as a file in the container: SECRET=PATH (replaces a binding of that secret).
    #[arg(long = "secret-mount", value_name = "SECRET=PATH", value_parser = parse_pair, conflicts_with = "spec")]
    pub secret_mount: Vec<(String, String)>,
    /// Remove the binding of a secret (repeatable). The stored value is kept.
    #[arg(long = "unbind-secret", value_name = "SECRET", conflicts_with = "spec")]
    pub unbind_secrets: Vec<String>,
    /// Detach a private volume from the spec (repeatable). No data is deleted: the flag only
    /// unmounts the volume, its Podman volume stays until `apps remove --purge-volumes` or an
    /// explicit purge. An unknown name is a usage error; conflicts with `--spec`.
    #[arg(long = "remove-volume", value_name = "NAME", value_parser = parse_volume_name,
        conflicts_with = "spec")]
    pub remove_volumes: Vec<String>,
    /// Detach the app from a shared volume (repeatable). No data is deleted either: detaching the
    /// last member keeps both the `[shared_volumes.<name>]` declaration and the `wg-shared-<name>`
    /// volume (with its uid range). An unknown name is a usage error; conflicts with `--spec`.
    #[arg(long = "remove-shared-volume", value_name = "NAME", value_parser = parse_shared_volume_name,
        conflicts_with = "spec")]
    pub remove_shared_volumes: Vec<SharedVolumeName>,
    /// Remove a dependency (repeatable); the dependency itself is not touched.
    #[arg(long = "remove-depends-on", value_name = "NAME", value_parser = parse_instance, conflicts_with = "spec")]
    pub remove_depends_on: Vec<InstanceName>,
    /// Enable auto-update (the webhook swaps the image on its own).
    #[arg(long, conflicts_with_all = ["spec", "no_auto_update"])]
    pub auto_update: bool,
    /// Disable auto-update.
    #[arg(long, conflicts_with = "spec")]
    pub no_auto_update: bool,
    /// Set `start = true` and deploy the app now (a provisioned app gets its container).
    #[arg(long, conflicts_with_all = ["spec", "no_start"])]
    pub start: bool,
    /// Set `start = false`: remove the container; volumes, the uid range and the pinned image digest stay.
    #[arg(long, conflicts_with = "spec")]
    pub no_start: bool,
    #[command(flatten)]
    pub spec_flags: crate::spec_flags::SpecFlags,
    /// Replace the whole spec with an AppSpec TOML file (instead of the flags above); `-` = stdin.
    #[arg(long, value_name = "FILE")]
    pub spec: Option<PathBuf>,
    /// Send nothing; show the diff of the spec and the request that would be sent.
    #[arg(long)]
    pub dry_run: bool,
}

impl UpdateArgs {
    fn has_edits(&self) -> bool {
        self.image.is_some()
            || !self.domains.is_empty()
            || !self.remove_domains.is_empty()
            || !self.paths.is_empty()
            || !self.remove_paths.is_empty()
            || self.strip_prefix
            || self.no_strip_prefix
            || self.port.is_some()
            || self.unset_port
            || self.streaming
            || self.no_streaming
            || self.max_body_size.is_some()
            || self.unset_max_body_size
            || !self.access_log_skip_paths.is_empty()
            || !self.remove_access_log_skip_paths.is_empty()
            || !self.env.is_empty()
            || !self.unset_env.is_empty()
            || !self.secret_env.is_empty()
            || !self.secret_mount.is_empty()
            || !self.unbind_secrets.is_empty()
            || !self.remove_volumes.is_empty()
            || !self.remove_shared_volumes.is_empty()
            || !self.remove_depends_on.is_empty()
            || self.auto_update
            || self.no_auto_update
            || self.start
            || self.no_start
            || !self.spec_flags.is_empty()
    }
}

fn missing(what: &str, value: &str) -> CliError {
    CliError::usage(format!("{what} {value:?} is not in the app's spec"))
        .with_hint("check the current spec with `weglarka apps show <name>`")
}

/// An app name used by the flag (the strong type has no `FromStr`, and the message is nicer).
fn parse_instance(s: &str) -> Result<InstanceName, String> {
    InstanceName::new(s).map_err(|e| e.to_string())
}

/// A private volume name from a flag value; validated locally, like the `--volume` flag, so a typo
/// is a usage error instead of a request.
fn parse_volume_name(s: &str) -> Result<String, String> {
    if valid_volume_name(s) {
        Ok(s.to_owned())
    } else {
        Err(format!(
            "invalid volume name {s:?}: [a-z0-9-], 1–63 characters"
        ))
    }
}

/// A shared volume name from a flag value; [`SharedVolumeName`] does the validation itself.
fn parse_shared_volume_name(s: &str) -> Result<SharedVolumeName, String> {
    SharedVolumeName::new(s).map_err(|e| e.to_string())
}

/// Applies the flags to the current spec (pure; the order is: removals, then additions).
pub fn apply_flags(mut spec: AppSpec, a: &UpdateArgs) -> Result<AppSpec, CliError> {
    if let Some(image) = &a.image {
        spec.image = image.clone();
    }
    for d in &a.remove_domains {
        let before = spec.domains.len();
        spec.domains.retain(|x| x != d);
        if spec.domains.len() == before {
            return Err(missing("domain", d));
        }
    }
    for d in &a.domains {
        if !spec.domains.contains(d) {
            spec.domains.push(d.clone());
        }
    }
    for p in &a.remove_paths {
        let before = spec.paths.len();
        spec.paths.retain(|x| x != p);
        if spec.paths.len() == before {
            return Err(missing("path", p));
        }
    }
    for p in &a.paths {
        if !spec.paths.contains(p) {
            spec.paths.push(p.clone());
        }
    }
    if a.unset_port {
        spec.port = None;
    }
    if a.port.is_some() {
        spec.port = a.port;
    }
    // Ingress-only (issue #64): `--no-streaming` resets the streaming settings, a custom timeout
    // included, and leaves `strip_prefix` (issue #130) and `max_body_size` (ADR 0033) alone.
    if a.streaming {
        spec.ingress.streaming = true;
    }
    if a.no_streaming {
        spec.ingress = AppIngress {
            strip_prefix: spec.ingress.strip_prefix,
            max_body_size: spec.ingress.max_body_size,
            access_log_skip_paths: std::mem::take(&mut spec.ingress.access_log_skip_paths),
            ..AppIngress::default()
        };
    }
    if a.max_body_size.is_some() {
        spec.ingress.max_body_size = a.max_body_size;
    }
    if a.unset_max_body_size {
        spec.ingress.max_body_size = None;
    }
    for p in &a.access_log_skip_paths {
        if !spec.ingress.access_log_skip_paths.contains(p) {
            spec.ingress.access_log_skip_paths.push(p.clone());
        }
    }
    for p in &a.remove_access_log_skip_paths {
        if !spec.ingress.access_log_skip_paths.contains(p) {
            return Err(missing("access log skip path", p));
        }
        spec.ingress.access_log_skip_paths.retain(|x| x != p);
    }
    if a.strip_prefix {
        spec.ingress.strip_prefix = true;
    }
    if a.no_strip_prefix {
        spec.ingress.strip_prefix = false;
    }
    for k in &a.unset_env {
        if spec.env.remove(k).is_none() {
            return Err(missing("env variable", k));
        }
    }
    spec.env.extend(a.env.iter().cloned());
    for s in &a.unbind_secrets {
        let before = spec.secrets.len();
        spec.secrets.retain(|b| &b.secret != s);
        if spec.secrets.len() == before {
            return Err(missing("secret binding", s));
        }
    }
    // Re-binding replaces the whole binding, so it also resets the mount options (`mode`, `uid`,
    // `gid`) to their defaults — same as before this flag existed, there is no flag for them.
    let bindings = a
        .secret_env
        .iter()
        .map(|(s, var)| (s, SecretTarget::Env { var: var.clone() }))
        .chain(a.secret_mount.iter().map(|(s, path)| {
            (
                s,
                SecretTarget::Mount {
                    path: path.clone(),
                    mode: None,
                    uid: None,
                    gid: None,
                },
            )
        }));
    for (secret, target) in bindings {
        spec.secrets.retain(|b| &b.secret != secret);
        spec.secrets.push(SecretBinding {
            secret: secret.clone(),
            target,
        });
    }
    for dep in &a.remove_depends_on {
        let before = spec.depends_on.len();
        spec.depends_on.retain(|x| x != dep);
        if spec.depends_on.len() == before {
            return Err(missing("dependency", dep.as_str()));
        }
    }
    if a.auto_update {
        spec.auto_update = true;
    }
    if a.no_auto_update {
        spec.auto_update = false;
    }
    // Detaching volumes happens before `spec_flags.apply`, so `--remove-volume data --volume
    // data=/new` means "unmount, then mount the same volume elsewhere" in one call.
    for v in &a.remove_volumes {
        let before = spec.volumes.len();
        spec.volumes.retain(|x| &x.name != v);
        if spec.volumes.len() == before {
            return Err(missing("volume", v));
        }
    }
    for v in &a.remove_shared_volumes {
        let before = spec.shared_volumes.len();
        spec.shared_volumes.retain(|x| &x.name != v);
        if spec.shared_volumes.len() == before {
            return Err(missing("shared volume", v.as_str()));
        }
    }
    a.spec_flags.apply(&mut spec);
    if a.start {
        spec.start = true;
    }
    if a.no_start {
        spec.start = false;
    }
    Ok(spec)
}

fn read_spec_file(path: &Path) -> Result<AppSpec, CliError> {
    let src = if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| CliError::usage(format!("cannot read spec from stdin: {e}")))?;
        s
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| CliError::usage(format!("cannot read spec {}: {e}", path.display())))?
    };
    toml::from_str(&src).map_err(|e| {
        CliError::usage(format!("invalid spec: {e}")).with_hint(
            "format: the AppSpec fields from apps.toml (image, domains, port, env, secrets…)",
        )
    })
}

/// Line diff of two specs rendered as TOML: `-` removed, `+` added, unchanged lines omitted.
/// Empty string = the specs are identical.
pub fn spec_diff(old: &AppSpec, new: &AppSpec) -> String {
    let render = |s: &AppSpec| toml::to_string(s).unwrap_or_default();
    let (a, b) = (render(old), render(new));
    let (a, b): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    // Longest common subsequence; specs are a few dozen lines.
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, String::new());
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            (i, j) = (i + 1, j + 1);
        } else if i < a.len() && (j == b.len() || lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    out
}

#[derive(Debug, Serialize)]
struct UpdateDryRun {
    dry_run: bool,
    method: &'static str,
    path: String,
    /// `false` = the new spec equals the current one (a real run would send nothing).
    changed: bool,
    diff: String,
    body: UpdateAppRequest,
}

#[derive(Debug, Serialize)]
struct NoChange {
    changed: bool,
    app: ShowAppResponse,
}

/// Prints the `PUT /v1/apps/{name}` a real run would send (`--dry-run` of update/start/stop).
fn emit_update_dry_run(json: bool, params: &[(&str, &str)], diff: String, req: UpdateAppRequest) {
    let out = UpdateDryRun {
        dry_run: true,
        method: "PUT",
        path: expand_path(endpoints::APPS_UPDATE, params),
        changed: !diff.is_empty(),
        diff,
        body: req,
    };
    emit(json, &out, || {
        let mut s = format!("dry-run: {} {}\n", out.method, out.path);
        s.push_str(&if out.changed {
            format!("spec changes:\n{}", out.diff)
        } else {
            "no changes to the spec\n".to_owned()
        });
        s.push_str("nothing was sent\n");
        s
    });
}

pub async fn apps_update(json: bool, o: &Overrides, a: UpdateArgs) -> Result<i32, CliError> {
    if a.spec.is_none() && !a.has_edits() {
        return Err(CliError::usage("nothing to change").with_hint(
            "pass what to change (e.g. `--domain`, `--env`, an image) or `--spec FILE`",
        ));
    }
    let name = instance(&a.name)?;
    let params = [("name", name.as_str())];
    let client = client(o)?;
    let current: ShowAppResponse = client
        .call(endpoints::APPS_SHOW, &params, None::<&()>)
        .await?;
    let new_spec = match &a.spec {
        Some(path) => read_spec_file(path)?,
        None => apply_flags(current.spec.clone(), &a)?,
    };
    let diff = spec_diff(&current.spec, &new_spec);
    let req = UpdateAppRequest { spec: new_spec };

    if a.dry_run {
        emit_update_dry_run(json, &params, diff, req);
        return Ok(exit::OK);
    }
    if diff.is_empty() {
        let out = NoChange {
            changed: false,
            app: current,
        };
        emit(json, &out, || format!("{name}: no changes to the spec\n"));
        return Ok(exit::OK);
    }

    let resp: UpdateAppResponse = client
        .call(endpoints::APPS_UPDATE, &params, Some(&req))
        .await?;
    emit(json, &resp, || render_update(&resp, &diff));
    Ok(match &resp.deploy {
        Some(d) if d.outcome == DeployOutcome::RolledBack => exit::ROLLED_BACK,
        _ => exit::OK,
    })
}

fn render_update(r: &UpdateAppResponse, diff: &str) -> String {
    render_change(
        "updated",
        r,
        diff,
        "container changes (env, port, secrets, volumes, limits) are applied by the daemon's next \
         reconcile; domains only reload ingress\n",
    )
}

/// Human output of a successful `PUT`: the diff, the deploy outcome and the fresh app view.
pub(crate) fn render_change(
    verb: &str,
    r: &UpdateAppResponse,
    diff: &str,
    no_deploy: &str,
) -> String {
    let mut s = format!("{verb} {}\n{diff}", r.app.name);
    match &r.deploy {
        Some(d) if d.outcome == DeployOutcome::Provisioned => s.push_str(&format!(
            "deploy: provisioned (start = false): no container started (generation {})\n",
            d.generation
        )),
        Some(d) => s.push_str(&format!(
            "deploy: {:?} (generation {})\n",
            d.outcome, d.generation
        )),
        None => s.push_str(no_deploy),
    }
    s.push('\n');
    s.push_str(&render_show(&r.app));
    s
}

// ---------- apps start / apps stop ----------

/// Shared body of `apps start` / `apps stop`: read the spec, flip `start`, `PUT` it back.
///
/// The flip is a spec change like any other (that is why `start` is a field, not a one-shot flag),
/// so `--json` reuses the `apps update` shapes: `UpdateDryRun`, `UpdateAppResponse`, and
/// `{"changed":false,"app":…}` when there is nothing to do (the flag already has the target value).
async fn set_start(
    json: bool,
    o: &Overrides,
    a: StartStopArgs,
    start: bool,
    verb: &str,
    noop: &str,
) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let params = [("name", name.as_str())];
    let client = client(o)?;
    let current: ShowAppResponse = client
        .call(endpoints::APPS_SHOW, &params, None::<&()>)
        .await?;
    if current.spec.start == start {
        let out = NoChange {
            changed: false,
            app: current,
        };
        emit(json, &out, || format!("{name}: {noop}\n"));
        return Ok(exit::OK);
    }
    let mut new_spec = current.spec.clone();
    new_spec.start = start;
    let diff = spec_diff(&current.spec, &new_spec);
    let req = UpdateAppRequest { spec: new_spec };
    if a.dry_run {
        emit_update_dry_run(json, &params, diff, req);
        return Ok(exit::OK);
    }
    let resp: UpdateAppResponse = client
        .call(endpoints::APPS_UPDATE, &params, Some(&req))
        .await?;
    emit(json, &resp, || {
        render_change(
            verb,
            &resp,
            &diff,
            "deploy: none (the flag is saved; the daemon deploys on its next reconcile, e.g. once \
             the missing secrets are set)\n",
        )
    });
    Ok(match &resp.deploy {
        Some(d) if d.outcome == DeployOutcome::RolledBack => exit::ROLLED_BACK,
        _ => exit::OK,
    })
}

/// `apps start`: `start = true` and a deploy (a provisioned app gets its container).
pub async fn apps_start(json: bool, o: &Overrides, a: StartStopArgs) -> Result<i32, CliError> {
    set_start(
        json,
        o,
        a,
        true,
        "started",
        "already running (start = true)",
    )
    .await
}

/// `apps stop`: `start = false` — the container goes away, volumes, the uid range and the pinned
/// image digest stay (`apps start` brings the app back).
pub async fn apps_stop(json: bool, o: &Overrides, a: StartStopArgs) -> Result<i32, CliError> {
    set_start(
        json,
        o,
        a,
        false,
        "stopped",
        "already stopped (start = false)",
    )
    .await
}

// ---------- "waiting for secret" rendering ----------

/// Runtime label for tables and `show` (`WaitingForSecret` → `waiting-for-secret`,
/// `NotStarted` → `not-started`).
pub fn runtime_label(r: RuntimeState) -> String {
    match r {
        RuntimeState::WaitingForSecret => "waiting-for-secret".to_owned(),
        RuntimeState::NotStarted => "not-started".to_owned(),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// Extra lines for `apps show` when the app waits for secrets (empty otherwise).
pub fn render_waiting(app: &str, state: &AppState) -> String {
    if state.waiting_for_secrets.is_empty() {
        return String::new();
    }
    let mut s = format!("waiting:    {}\n", state.waiting_for_secrets.join(", "));
    for secret in &state.waiting_for_secrets {
        s.push_str(&format!(
            "            set it: weglarka secrets set {app} {secret} < file\n"
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mock;
    use clap::Parser;
    use weglarka_api::DeployResponse;
    use weglarka_core::app::{InstanceName, SharedVolumeRef, VolumeMount};

    fn args(extra: &[&str]) -> UpdateArgs {
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            a: UpdateArgs,
        }
        let mut argv = vec!["w", "ntfy"];
        argv.extend_from_slice(extra);
        W::try_parse_from(argv).unwrap().a
    }

    fn spec() -> AppSpec {
        toml::from_str(
            r#"
image = "ghcr.io/x/ntfy:latest"
domains = ["old.example.eu"]
port = 8085
env = { A = "1", B = "2" }
secrets = [{ secret = "token", kind = "env", var = "TOKEN" }]
volumes = [{ name = "data", target = "/var/lib/ntfy" }]
"#,
        )
        .unwrap()
    }

    /// [`spec`] plus a second private volume, a shared volume mount and two fields a volume detach
    /// must not touch (`start`, `[ingress] streaming`).
    fn spec_with_volumes() -> AppSpec {
        let mut s = spec();
        s.volumes.push(VolumeMount {
            name: "cache".into(),
            target: "/cache".into(),
            read_only: true,
        });
        s.shared_volumes.push(SharedVolumeRef {
            name: SharedVolumeName::new("kajet-data").unwrap(),
            target: "/data".into(),
            read_only: false,
        });
        s.start = false;
        s.ingress.streaming = true;
        s
    }

    #[test]
    fn flags_edit_only_what_they_name() {
        let a = args(&[
            "--remove-domain",
            "old.example.eu",
            "--domain",
            "new.example.eu",
            "--unset-env",
            "A",
            "--env",
            "C=3",
            "--secret-mount",
            "token=/run/token",
            "--no-auto-update",
        ]);
        let s = apply_flags(spec(), &a).unwrap();
        assert_eq!(s.domains, ["new.example.eu"]);
        assert_eq!(s.env.keys().collect::<Vec<_>>(), ["B", "C"]);
        assert_eq!(s.secrets.len(), 1);
        assert!(
            matches!(&s.secrets[0].target, SecretTarget::Mount { path, .. } if path == "/run/token")
        );
        assert!(!s.auto_update);
        // Untouched: image, port, and the iteration 2 fields.
        assert_eq!(
            (s.image.as_str(), s.port),
            ("ghcr.io/x/ntfy:latest", Some(8085))
        );
        assert_eq!(s.volumes, spec().volumes);
    }

    #[test]
    fn shared_volume_flag_keeps_the_private_volumes() {
        let before = spec();
        let s = apply_flags(
            before.clone(),
            &args(&["--shared-volume", "kajet-data=/data"]),
        )
        .unwrap();
        assert_eq!(s.volumes, before.volumes, "private volumes are untouched");
        assert_eq!(s.shared_volumes.len(), 1);
        assert_eq!(s.shared_volumes[0].name.as_str(), "kajet-data");
        assert!(!s.shared_volumes[0].read_only);
        // A second mount of the same volume replaces the first; `:ro` is parsed.
        let s = apply_flags(s, &args(&["--shared-volume", "kajet-data=/mnt/data:ro"])).unwrap();
        assert_eq!(s.shared_volumes.len(), 1);
        assert_eq!(s.shared_volumes[0].target, "/mnt/data");
        assert!(s.shared_volumes[0].read_only);
        assert_eq!(s.volumes, before.volumes);
    }

    #[test]
    fn remove_volume_flag_detaches_one_private_volume_and_keeps_everything_else() {
        let before = spec_with_volumes();
        let s = apply_flags(before.clone(), &args(&["--remove-volume", "data"])).unwrap();
        // Only `data` is gone; `cache` stays mounted.
        assert_eq!(
            s.volumes,
            [VolumeMount {
                name: "cache".into(),
                target: "/cache".into(),
                read_only: true,
            }]
        );
        // A volume detach is not a spec reset: every other field survives.
        assert_eq!(
            s.shared_volumes, before.shared_volumes,
            "shared mounts stay"
        );
        assert_eq!(s.env, before.env);
        assert_eq!(s.domains, before.domains);
        assert_eq!(s.secrets, before.secrets);
        assert_eq!(s.ingress, before.ingress);
        assert_eq!(
            (s.image.as_str(), s.port, s.start, s.auto_update),
            (
                before.image.as_str(),
                before.port,
                before.start,
                before.auto_update
            )
        );
    }

    #[test]
    fn remove_shared_volume_flag_detaches_the_mount_and_keeps_the_private_volumes() {
        let before = spec_with_volumes();
        let s = apply_flags(
            before.clone(),
            &args(&["--remove-shared-volume", "kajet-data"]),
        )
        .unwrap();
        assert!(s.shared_volumes.is_empty(), "the shared mount is gone");
        assert_eq!(s.volumes, before.volumes, "private volumes stay mounted");
        assert_eq!(s.env, before.env);
        assert_eq!(s.secrets, before.secrets);
    }

    #[test]
    fn removing_an_unknown_volume_is_a_usage_error() {
        let before = spec_with_volumes();
        // The names that are in the spec can be detached...
        for flags in [
            ["--remove-volume", "cache"],
            ["--remove-shared-volume", "kajet-data"],
        ] {
            assert!(
                apply_flags(before.clone(), &args(&flags)).is_ok(),
                "{flags:?}"
            );
        }
        // ...while an unknown one is the same usage error as the other removals (nothing is sent).
        for flags in [
            ["--remove-volume", "nope"],
            ["--remove-shared-volume", "nope"],
        ] {
            let err = apply_flags(before.clone(), &args(&flags)).unwrap_err();
            assert_eq!(err.exit_code(), exit::USAGE, "{flags:?}");
        }
    }

    #[test]
    fn volume_removal_flags_count_as_edits_and_conflict_with_spec() {
        assert!(args(&["--remove-volume", "data"]).has_edits());
        assert!(args(&["--remove-shared-volume", "kajet-data"]).has_edits());

        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        for bad in [
            vec!["w", "ntfy", "--remove-volume", "data", "--spec", "f"],
            vec![
                "w",
                "ntfy",
                "--remove-shared-volume",
                "kajet-data",
                "--spec",
                "f",
            ],
            // Names are validated before anything is sent.
            vec!["w", "ntfy", "--remove-volume", "Data"],
            vec!["w", "ntfy", "--remove-shared-volume", "Kajet_Data"],
        ] {
            assert!(W::try_parse_from(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn remove_and_re_add_in_one_call_moves_the_mount() {
        let before = spec_with_volumes();
        let s = apply_flags(
            before.clone(),
            &args(&["--remove-volume", "data", "--volume", "data=/mnt/data:ro"]),
        )
        .unwrap();
        assert_eq!(
            s.volumes.len(),
            before.volumes.len(),
            "the mount is replaced, not duplicated"
        );
        let data = s.volumes.iter().find(|v| v.name == "data").unwrap();
        assert_eq!((data.target.as_str(), data.read_only), ("/mnt/data", true));
    }

    #[test]
    fn diff_shows_the_detached_volumes() {
        let before = spec_with_volumes();
        let s = apply_flags(
            before.clone(),
            &args(&[
                "--remove-volume",
                "data",
                "--remove-shared-volume",
                "kajet-data",
            ]),
        )
        .unwrap();
        let d = spec_diff(&before, &s);
        let removed: Vec<&str> = d.lines().filter(|l| l.starts_with("- ")).collect();
        assert!(
            removed.iter().any(|l| l.contains("\"data\"")),
            "the private volume line is shown as removed: {d}"
        );
        assert!(
            removed.iter().any(|l| l.contains("\"kajet-data\"")),
            "the shared volume line is shown as removed: {d}"
        );
        assert!(
            !d.lines().any(|l| l.starts_with("+ ")),
            "nothing is added by a detach: {d}"
        );
    }

    #[test]
    fn host_port_flag_appends_and_none_clears() {
        let s = apply_flags(spec(), &args(&["--host-port", "2222:22"])).unwrap();
        assert_eq!(s.host_ports.len(), 1);
        assert_eq!(
            (s.host_ports[0].host, s.host_ports[0].container),
            (2222, 22)
        );
        let s = apply_flags(s, &args(&["--host-port", "none"])).unwrap();
        assert!(s.host_ports.is_empty());
        // Same rules as the other spec flags: incompatible with --spec.
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        assert!(W::try_parse_from(["w", "ntfy", "--host-port", "2222:22", "--spec", "f"]).is_err());
    }

    #[test]
    fn config_and_reload_signal_flags_flow_through_read_modify_write() {
        let a = args(&[
            "--config-mount",
            "prometheus/prometheus.yml:/etc/prometheus/prometheus.yml",
            "--config-mount",
            "prometheus/rules:/etc/prometheus/rules",
            "--reload-signal",
            "SIGHUP",
        ]);
        assert!(a.has_edits(), "the flags count as an edit");
        let s = apply_flags(spec(), &a).unwrap();
        assert_eq!(s.configs.len(), 2);
        assert_eq!(s.configs[0].source, "prometheus/prometheus.yml");
        assert_eq!(
            s.reload_signal.as_deref(),
            Some("HUP"),
            "stored normalized, without the SIG prefix"
        );
        // A second pass naming one source replaces that mount only.
        let s = apply_flags(
            s,
            &args(&["--config-mount", "prometheus/prometheus.yml:/etc/prom.yml"]),
        )
        .unwrap();
        assert_eq!(s.configs.len(), 2);
        assert_eq!(
            s.configs
                .iter()
                .find(|m| m.source == "prometheus/prometheus.yml")
                .unwrap()
                .target,
            "/etc/prom.yml",
            "the named source was replaced"
        );
        assert_eq!(
            s.configs
                .iter()
                .find(|m| m.source == "prometheus/rules")
                .unwrap()
                .target,
            "/etc/prometheus/rules",
            "the other mount is untouched"
        );
        // `none` clears both, restoring a spec that looks like the input one.
        let s = apply_flags(
            s,
            &args(&["--config-mount", "none", "--reload-signal", "none"]),
        )
        .unwrap();
        assert!(s.configs.is_empty());
        assert_eq!(s.reload_signal, None);
        assert_eq!(s, spec(), "everything else stays untouched");

        // `--dry-run` shows the new lines (the whole spec travels, so the diff is the request).
        let new = apply_flags(
            spec(),
            &args(&["--config-mount", "app/config.yml:/etc/app.yml"]),
        )
        .unwrap();
        let diff = spec_diff(&spec(), &new);
        assert!(diff.contains("app/config.yml"), "{diff}");
        assert!(diff.contains("configs"), "{diff}");

        // Without a flag the fields are not touched, and they conflict with `--spec`.
        let untouched = apply_flags(spec(), &args(&["--domain", "x.example.eu"])).unwrap();
        assert!(untouched.configs.is_empty() && untouched.reload_signal.is_none());
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        assert!(
            W::try_parse_from([
                "w",
                "ntfy",
                "--config-mount",
                "app/config.yml:/etc/app.yml",
                "--spec",
                "f"
            ])
            .is_err()
        );
        assert!(
            W::try_parse_from(["w", "ntfy", "--reload-signal", "SIGHUP", "--spec", "f"]).is_err()
        );
    }

    #[test]
    fn host_config_flag_stays_global_and_the_mount_flag_is_separate() {
        use crate::cli::{AppsCommand, Cli, Command};
        // `--config FILE` is the global host configuration flag (also after the subcommand), while
        // `--config-mount SOURCE:TARGET` edits the app's config mounts, so both work side by side.
        let cli = Cli::try_parse_from([
            "weglarka",
            "apps",
            "update",
            "prometheus",
            "--config",
            "/etc/weglarka/weglarka.toml",
            "--config-mount",
            "prometheus/prometheus.yml:/etc/prometheus/prometheus.yml",
        ])
        .unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(Path::new("/etc/weglarka/weglarka.toml"))
        );
        match cli.command {
            Command::Apps(AppsCommand::Update(a)) => {
                assert_eq!(a.spec_flags.configs.len(), 1);
            }
            other => panic!("expected apps update, got {other:?}"),
        }
    }

    #[test]
    fn host_config_flag_is_global_for_every_subcommand() {
        use crate::cli::{Cli, Command};
        // `global = true` again: `status --config FILE` and the documented
        // `doctor --preflight --config FILE` (docs/install.md) both set the host configuration file.
        let cli = Cli::try_parse_from([
            "weglarka",
            "status",
            "--config",
            "/etc/weglarka/weglarka.toml",
        ])
        .unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(Path::new("/etc/weglarka/weglarka.toml"))
        );
        assert!(matches!(cli.command, Command::Status));

        let cli = Cli::try_parse_from([
            "weglarka",
            "doctor",
            "--preflight",
            "--config",
            "/etc/weglarka/weglarka.toml",
        ])
        .unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(Path::new("/etc/weglarka/weglarka.toml"))
        );
        assert!(matches!(cli.command, Command::Doctor(_)));
    }

    #[test]
    fn path_flags_edit_prefixes_and_strip_without_touching_streaming() {
        let s = apply_flags(
            spec(),
            &args(&[
                "--path",
                "/api",
                "--path",
                "/mcp",
                "--path",
                "/api",
                "--strip-prefix",
            ]),
        )
        .unwrap();
        assert_eq!(s.paths, ["/api", "/mcp"]);
        assert!(s.ingress.strip_prefix);
        let s = apply_flags(s, &args(&["--remove-path", "/mcp", "--streaming"])).unwrap();
        assert_eq!(s.paths, ["/api"]);
        // `--no-streaming` resets streaming only; the prefix handling survives.
        let s = apply_flags(s, &args(&["--no-streaming"])).unwrap();
        assert!(!s.ingress.streaming && s.ingress.strip_prefix);
        let s = apply_flags(s, &args(&["--no-strip-prefix"])).unwrap();
        assert!(s.ingress.is_default());
        assert!(args(&["--path", "/a"]).has_edits());
        assert!(args(&["--strip-prefix"]).has_edits());
        assert!(apply_flags(spec(), &args(&["--remove-path", "/nope"])).is_err());
    }

    #[test]
    fn command_flag_replaces_and_none_clears() {
        let mut before = spec();
        before.command = vec!["serve".into()];
        // The whole argv is replaced, so no duplicated arguments (unlike the set-like list flags).
        let s = apply_flags(before, &args(&["--command", "serve", "--command=--no-log"])).unwrap();
        assert_eq!(s.command, ["serve", "--no-log"]);
        // Everything else stays as it was.
        assert_eq!(s.volumes, spec().volumes);
        assert_eq!(s.domains, spec().domains);
        // `none` restores the image's own CMD.
        let s = apply_flags(s, &args(&["--command", "none"])).unwrap();
        assert!(s.command.is_empty());
        // Same rules as the other spec flags: incompatible with --spec.
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        assert!(W::try_parse_from(["w", "ntfy", "--command", "serve", "--spec", "f"]).is_err());
    }

    #[test]
    fn max_body_size_flag_sets_clears_and_survives_no_streaming() {
        let s = apply_flags(spec(), &args(&["--max-body-size", "4g"])).unwrap();
        assert_eq!(
            s.ingress.max_body_size,
            Some(BodySizeLimit::parse("4g").unwrap())
        );
        assert!(!s.ingress.streaming, "the limit does not imply streaming");
        assert!(args(&["--max-body-size", "0"]).has_edits());
        assert!(args(&["--unset-max-body-size"]).has_edits());

        // `0` is a value (no limit), not "unset".
        let open = apply_flags(spec(), &args(&["--max-body-size", "0"])).unwrap();
        assert_eq!(open.ingress.max_body_size, Some(BodySizeLimit::UNLIMITED));

        // `--no-streaming` resets the streaming knobs only.
        let both = apply_flags(s, &args(&["--streaming"])).unwrap();
        let s = apply_flags(both, &args(&["--no-streaming"])).unwrap();
        assert!(!s.ingress.streaming && s.ingress.max_body_size.is_some());

        let s = apply_flags(s, &args(&["--unset-max-body-size"])).unwrap();
        assert!(s.ingress.is_default());

        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        for bad in [
            vec!["w", "n", "--max-body-size", "1.5g"],
            vec!["w", "n", "--max-body-size", "4g", "--unset-max-body-size"],
            vec!["w", "n", "--max-body-size", "4g", "--spec", "f"],
        ] {
            assert!(W::try_parse_from(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn streaming_flag_sets_and_clears_the_ingress_block() {
        // `--streaming` opts in and leaves everything else untouched.
        let s = apply_flags(spec(), &args(&["--streaming"])).unwrap();
        assert!(s.ingress.streaming);
        assert_eq!(
            s.ingress.stream_timeout_secs,
            AppIngress::DEFAULT_STREAM_TIMEOUT_SECS
        );
        assert_eq!(s.domains, spec().domains);

        // A custom timeout survives a read-modify-write that names only the flag.
        let mut custom = spec();
        custom.ingress = AppIngress {
            strip_prefix: false,
            streaming: true,
            stream_timeout_secs: 600,
            max_body_size: None,
            access_log_skip_paths: Vec::new(),
        };
        let s = apply_flags(custom.clone(), &args(&["--streaming"])).unwrap();
        assert_eq!(s.ingress, custom.ingress);

        // `--no-streaming` clears the whole block, the custom timeout included.
        let s = apply_flags(custom, &args(&["--no-streaming"])).unwrap();
        assert!(s.ingress.is_default());

        // It is an ordinary spec edit: counted as one and visible in the dry-run diff.
        assert!(args(&["--streaming"]).has_edits());
        assert!(args(&["--no-streaming"]).has_edits());
        let streamed = apply_flags(spec(), &args(&["--streaming"])).unwrap();
        assert!(spec_diff(&spec(), &streamed).contains("streaming = true"));

        // On an app that is not streaming, `--no-streaming` is a no-op (nothing is sent).
        let plain = apply_flags(spec(), &args(&["--no-streaming"])).unwrap();
        assert!(spec_diff(&spec(), &plain).is_empty());

        // Mutually exclusive, and neither combines with `--spec`.
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        assert!(W::try_parse_from(["w", "ntfy", "--streaming", "--no-streaming"]).is_err());
        assert!(W::try_parse_from(["w", "ntfy", "--streaming", "--spec", "f"]).is_err());
        assert!(W::try_parse_from(["w", "ntfy", "--no-streaming", "--spec", "f"]).is_err());
    }

    #[test]
    fn removing_something_absent_is_a_usage_error() {
        for flags in [
            ["--remove-domain", "nope.example.eu"],
            ["--unset-env", "NOPE"],
            ["--unbind-secret", "nope"],
        ] {
            let err = apply_flags(spec(), &args(&flags)).unwrap_err();
            assert_eq!(err.exit_code(), exit::USAGE, "{flags:?}");
        }
        // Adding an existing domain is a no-op, not a duplicate.
        let s = apply_flags(spec(), &args(&["--domain", "old.example.eu"])).unwrap();
        assert_eq!(s.domains, ["old.example.eu"]);
    }

    #[test]
    fn depends_on_flags_add_and_remove() {
        let mut with_deps = spec();
        with_deps.depends_on = vec![InstanceName::new("db").unwrap()];
        let s = apply_flags(with_deps.clone(), &args(&["--depends-on", "cache"])).unwrap();
        assert_eq!(
            s.depends_on,
            [
                InstanceName::new("db").unwrap(),
                InstanceName::new("cache").unwrap()
            ]
        );
        let s = apply_flags(with_deps, &args(&["--remove-depends-on", "db"])).unwrap();
        assert!(s.depends_on.is_empty());
        // Removing an absent dependency is a usage error, like the other removals.
        let err = apply_flags(spec(), &args(&["--remove-depends-on", "db"])).unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
        // `--depends-on` conflicts with `--spec`, like every other spec flag.
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        assert!(W::try_parse_from(["w", "ntfy", "--depends-on", "db", "--spec", "f"]).is_err());
    }

    #[test]
    fn diff_shows_only_changed_lines() {
        let new = apply_flags(
            spec(),
            &args(&[
                "--remove-domain",
                "old.example.eu",
                "--domain",
                "new.example.eu",
            ]),
        )
        .unwrap();
        let d = spec_diff(&spec(), &new);
        assert!(d.contains("- domains = [\"old.example.eu\"]"), "{d}");
        assert!(d.contains("+ domains = [\"new.example.eu\"]"), "{d}");
        assert_eq!(d.lines().count(), 2, "{d}");
        assert!(spec_diff(&spec(), &spec()).is_empty());
    }

    #[test]
    fn spec_conflicts_with_edit_flags() {
        use clap::CommandFactory as _;
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            _a: UpdateArgs,
        }
        assert!(
            W::command()
                .try_get_matches_from(["w", "x", "--spec", "f", "--domain", "d"])
                .is_err()
        );
    }

    fn show_json() -> String {
        serde_json::to_string(&ShowAppResponse {
            name: InstanceName::new("ntfy").unwrap(),
            spec: spec(),
            state: Default::default(),
            runtime: RuntimeState::Running,
            configs: None,
            host_mounts: None,
        })
        .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn update_reads_then_puts_the_full_spec() {
        let show = show_json();
        let m = mock(move |method, _| match method {
            "GET" => (200, show.clone()),
            _ => (
                200,
                serde_json::to_string(&UpdateAppResponse {
                    app: serde_json::from_str(&show_json()).unwrap(),
                    deploy: Some(DeployResponse {
                        outcome: DeployOutcome::RolledBack,
                        generation: 2,
                        digest: None,
                    }),
                })
                .unwrap(),
            ),
        })
        .await;
        let o = Overrides {
            config: None,
            socket: Some(m.socket.clone()),
        };
        let code = apps_update(true, &o, args(&["--domain", "new.example.eu"]))
            .await
            .unwrap();
        assert_eq!(code, exit::ROLLED_BACK);
        let seen = m.seen.lock().unwrap();
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("GET", "/v1/apps/ntfy")
        );
        assert_eq!(
            (seen[1].method.as_str(), seen[1].path.as_str()),
            ("PUT", "/v1/apps/ntfy")
        );
        let body: serde_json::Value = serde_json::from_str(&seen[1].body).unwrap();
        assert_eq!(
            body["spec"]["domains"],
            serde_json::json!(["old.example.eu", "new.example.eu"])
        );
        // The whole spec travels, including fields the flags never mention.
        assert_eq!(body["spec"]["volumes"][0]["name"], "data");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dry_run_and_no_change_send_nothing() {
        let show = show_json();
        let m = mock(move |_, _| (200, show.clone())).await;
        let o = Overrides {
            config: None,
            socket: Some(m.socket.clone()),
        };
        let mut a = args(&["--domain", "new.example.eu"]);
        a.dry_run = true;
        assert_eq!(apps_update(true, &o, a).await.unwrap(), exit::OK);
        assert_eq!(
            apps_update(true, &o, args(&["--env", "A=1"]))
                .await
                .unwrap(),
            exit::OK
        );
        assert!(m.seen.lock().unwrap().iter().all(|s| s.method == "GET"));
        assert_eq!(
            apps_update(true, &o, args(&[]))
                .await
                .unwrap_err()
                .exit_code(),
            exit::USAGE
        );
    }

    #[test]
    fn waiting_state_rendering() {
        assert_eq!(
            runtime_label(RuntimeState::WaitingForSecret),
            "waiting-for-secret"
        );
        assert_eq!(runtime_label(RuntimeState::Running), "running");
        let st = AppState {
            waiting_for_secrets: vec!["config".into(), "token".into()],
            ..Default::default()
        };
        let r = render_waiting("ntfy", &st);
        assert!(r.contains("waiting:    config, token"), "{r}");
        assert!(r.contains("weglarka secrets set ntfy token < file"), "{r}");
        assert!(render_waiting("ntfy", &AppState::default()).is_empty());
    }
}
