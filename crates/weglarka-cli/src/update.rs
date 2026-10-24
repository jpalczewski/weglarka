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
use weglarka_core::app::{AppSpec, SecretBinding, SecretTarget};
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
    /// HTTP port in the container.
    #[arg(long, conflicts_with_all = ["spec", "unset_port"])]
    pub port: Option<u16>,
    /// Remove the port (the app is no longer routed by ingress).
    #[arg(long, conflicts_with = "spec")]
    pub unset_port: bool,
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
            || self.port.is_some()
            || self.unset_port
            || !self.env.is_empty()
            || !self.unset_env.is_empty()
            || !self.secret_env.is_empty()
            || !self.secret_mount.is_empty()
            || !self.unbind_secrets.is_empty()
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
    if a.unset_port {
        spec.port = None;
    }
    if a.port.is_some() {
        spec.port = a.port;
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
    if a.auto_update {
        spec.auto_update = true;
    }
    if a.no_auto_update {
        spec.auto_update = false;
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
    use weglarka_core::app::InstanceName;

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
