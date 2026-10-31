//! `weglarka secrets set <app> --env-file FILE` (issue #131): many secrets from one dotenv-style file.
//!
//! Every `NAME=value` becomes a stored secret and, when the app does not bind that secret yet, the
//! binding `NAME=NAME` (environment variable). `--plain` names go to the app's plain `env`
//! instead. Values never reach an argument, a log line, `Debug` or the printed output: everything
//! the command prints is a name or a fingerprint.

use std::fmt;
use std::io::Read;
use std::path::Path;

use serde::Serialize;
use weglarka_api::endpoints;
use weglarka_api::{SecretInfo, SetSecretRequest, UpdateAppRequest, UpdateAppResponse};
use weglarka_model::app::{AppSpec, SecretBinding, SecretTarget};

use crate::cli::SecretSetArgs;
use crate::commands::{client, instance, secret_name};
use crate::error::{CliError, exit};
use crate::output::emit;
use crate::settings::Overrides;
use crate::update::{deploy_exit, ensure_writable, fetch_app, spec_diff};

/// The entries of an env file, in file order (a repeated name keeps its last value).
struct EnvEntries(Vec<(String, String)>);

impl fmt::Debug for EnvEntries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(n, _)| n))
            .finish()
    }
}

/// What the file says, split by the `--only`/`--except`/`--plain` flags.
struct Plan {
    secrets: Vec<(String, String)>,
    plain: Vec<(String, String)>,
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan")
            .field("secrets", &EnvEntries(self.secrets.clone()))
            .field(
                "plain",
                &self.plain.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn bad_line(line: usize, what: &str) -> CliError {
    // Only the line number: a malformed line may be half a secret.
    CliError::usage(format!("env file line {line}: {what}"))
        .with_hint("format: NAME=value, optionally quoted; one assignment per line")
}

/// Parses dotenv-style text: blank lines and `#` comments are skipped, `export ` is accepted,
/// a value is bare (trailing ` # comment` cut), `'single'` (literal) or `"double"` (`\n`, `\t`,
/// `\"`, `\\` unescaped). A quoted value must close on its own line.
fn parse_env(src: &str) -> Result<EnvEntries, CliError> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (i, raw) in src.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((name, rest)) = line.split_once('=') else {
            return Err(bad_line(n, "expected NAME=value"));
        };
        let name = name.trim();
        secret_name(name)
            .map_err(|_| bad_line(n, "invalid name (allowed: [A-Za-z0-9_-], 1–64)"))?;
        let value = parse_value(rest.trim_start()).map_err(|m| bad_line(n, m))?;
        match out.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = value,
            None => out.push((name.to_owned(), value)),
        }
    }
    Ok(EnvEntries(out))
}

fn parse_value(rest: &str) -> Result<String, &'static str> {
    let mut chars = rest.chars();
    match chars.next() {
        Some(q @ ('"' | '\'')) => {
            let mut value = String::new();
            let mut closed = false;
            while let Some(c) = chars.next() {
                match c {
                    c if c == q => {
                        closed = true;
                        break;
                    }
                    '\\' if q == '"' => match chars.next() {
                        Some('n') => value.push('\n'),
                        Some('t') => value.push('\t'),
                        Some(e @ ('"' | '\\')) => value.push(e),
                        Some(other) => {
                            value.push('\\');
                            value.push(other);
                        }
                        None => return Err("unterminated quote"),
                    },
                    c => value.push(c),
                }
            }
            if !closed {
                return Err("unterminated quote");
            }
            let tail = chars.as_str().trim_start();
            if tail.is_empty() || tail.starts_with('#') {
                Ok(value)
            } else {
                Err("unexpected text after the closing quote")
            }
        }
        _ => {
            let cut = rest
                .match_indices('#')
                .find(|(i, _)| rest[..*i].ends_with(char::is_whitespace))
                .map_or(rest.len(), |(i, _)| i);
            Ok(rest[..cut].trim_end().to_owned())
        }
    }
}

fn names(list: &[String], what: &str, known: &EnvEntries) -> Result<(), CliError> {
    match list.iter().find(|n| !known.0.iter().any(|(k, _)| k == *n)) {
        Some(n) => Err(CliError::usage(format!(
            "{what} names {n:?}, which is not in the env file"
        ))),
        None => Ok(()),
    }
}

fn plan(entries: EnvEntries, a: &SecretSetArgs) -> Result<Plan, CliError> {
    names(&a.only, "--only", &entries)?;
    names(&a.except, "--except", &entries)?;
    names(&a.plain, "--plain", &entries)?;
    let mut plan = Plan {
        secrets: Vec::new(),
        plain: Vec::new(),
    };
    for (name, value) in entries.0 {
        let wanted = (a.only.is_empty() || a.only.contains(&name)) && !a.except.contains(&name);
        if !wanted {
            continue;
        }
        if a.plain.contains(&name) {
            plan.plain.push((name, value));
        } else if value.is_empty() {
            return Err(
                CliError::usage(format!("secret {name} has an empty value")).with_hint(
                    "an empty secret is not allowed: drop it with --except or list it in --plain",
                ),
            );
        } else {
            secret_name(&name)?;
            plan.secrets.push((name, value));
        }
    }
    if plan.secrets.is_empty() && plan.plain.is_empty() {
        return Err(CliError::usage(
            "nothing to set: the env file has no usable assignment",
        ));
    }
    Ok(plan)
}

/// Adds what the plan needs to the spec: a `NAME=NAME` binding for each secret nothing binds yet,
/// the plain values in `env`. Returns the names that got a new binding. A name that is already a
/// plain `env` key cannot become a secret (and the other way round): that is the user's conflict
/// to resolve, not ours to guess.
fn bind(spec: &mut AppSpec, plan: &Plan) -> Result<Vec<String>, CliError> {
    let env_var_of_binding = |spec: &AppSpec, name: &str| {
        spec.secrets
            .iter()
            .any(|b| matches!(&b.target, SecretTarget::Env { var } if var == name))
    };
    for (name, _) in &plan.secrets {
        if spec.env.contains_key(name) {
            return Err(CliError::usage(format!(
                "{name} is already a plain env variable of the app"
            ))
            .with_hint(
                "remove it with `weglarka apps update --unset-env`, or list it in --plain",
            ));
        }
    }
    for (name, _) in &plan.plain {
        if env_var_of_binding(spec, name) {
            return Err(CliError::usage(format!("{name} is already bound to a secret in the app"))
                .with_hint("unbind it with `weglarka apps update --unbind-secret`, or drop it from --plain"));
        }
    }
    let mut bound = Vec::new();
    for (name, _) in &plan.secrets {
        if !spec.secrets.iter().any(|b| &b.secret == name) {
            spec.secrets.push(SecretBinding {
                secret: name.clone(),
                target: SecretTarget::Env { var: name.clone() },
            });
            bound.push(name.clone());
        }
    }
    for (name, value) in &plan.plain {
        spec.env.insert(name.clone(), value.clone());
    }
    Ok(bound)
}

fn read_source(path: &Path, stdin: &mut dyn Read) -> Result<String, CliError> {
    let mut src = String::new();
    if path == Path::new("-") {
        stdin
            .read_to_string(&mut src)
            .map_err(|e| CliError::usage(format!("cannot read the env file from stdin: {e}")))?;
    } else {
        src = std::fs::read_to_string(path)
            .map_err(|e| CliError::usage(format!("cannot read {}: {e}", path.display())))?;
    }
    Ok(src)
}

#[derive(Debug, Serialize)]
struct EnvFileResult {
    /// The secrets stored, with their fingerprints (never values).
    secrets: Vec<SecretInfo>,
    /// Names that got a new `NAME=NAME` binding.
    bound: Vec<String>,
    /// Names set as plain `env`.
    plain: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EnvFileDryRun {
    dry_run: bool,
    secrets: Vec<String>,
    bound: Vec<String>,
    plain: Vec<String>,
}

pub(crate) async fn set_from_env_file(
    json: bool,
    o: &Overrides,
    a: SecretSetArgs,
) -> Result<i32, CliError> {
    let app = instance(&a.app)?;
    let path = a.env_file.as_deref().expect("clap: env_file or name");
    let src = read_source(path, &mut std::io::stdin())?;
    let plan = plan(parse_env(&src)?, &a)?;
    let params = [("name", app.as_str())];
    let client = client(o)?;
    let current = fetch_app(&client, &params).await?;
    ensure_writable(&current)?;
    let mut spec = current.spec.clone();
    let bound = bind(&mut spec, &plan)?;
    let secret_names = || {
        plan.secrets
            .iter()
            .map(|(n, _)| n.clone())
            .collect::<Vec<_>>()
    };
    let plain_names = plan
        .plain
        .iter()
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>();

    if a.dry_run {
        let out = EnvFileDryRun {
            dry_run: true,
            secrets: secret_names(),
            bound,
            plain: plain_names,
        };
        emit(json, &out, || {
            format!(
                "dry-run: would store {} secret(s): {}\nbind: {}\nplain env: {}\nnothing was sent\n",
                out.secrets.len(),
                out.secrets.join(", "),
                list_or_none(&out.bound),
                list_or_none(&out.plain),
            )
        });
        return Ok(exit::OK);
    }

    // Secrets first, so the deploy the binding triggers finds them; a rerun repeats both steps
    // harmlessly (same values, same fingerprints, an unchanged spec is not sent).
    let mut stored = Vec::with_capacity(plan.secrets.len());
    for (name, value) in plan.secrets {
        let info: SecretInfo = client
            .call(
                endpoints::SECRETS_SET,
                &[("name", app.as_str()), ("secret", name.as_str())],
                Some(&SetSecretRequest { value }),
            )
            .await?;
        stored.push(info);
    }
    let mut code = exit::OK;
    if !spec_diff(&current.spec, &spec).is_empty() {
        let resp: UpdateAppResponse = client
            .call(
                endpoints::APPS_UPDATE,
                &params,
                Some(&UpdateAppRequest { spec }),
            )
            .await?;
        code = deploy_exit(&resp);
    }
    let out = EnvFileResult {
        secrets: stored,
        bound,
        plain: plain_names,
    };
    emit(json, &out, || {
        let mut s = String::new();
        for i in &out.secrets {
            s.push_str(&format!(
                "set {}.{} (fingerprint {})\n",
                app, i.name, i.fingerprint
            ));
        }
        s.push_str(&format!(
            "bound: {}\nplain env: {}\n",
            list_or_none(&out.bound),
            list_or_none(&out.plain)
        ));
        s
    });
    Ok(code)
}

fn list_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "-".to_owned()
    } else {
        v.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(src: &str) -> Vec<(String, String)> {
        parse_env(src).unwrap().0
    }

    #[test]
    fn dotenv_syntax() {
        let got = kv(
            "# c\n\nA=1\nexport B = two words # note\nC=\"x\\ny\\\"#z\" # n\nD='a #b\\n'\nA=3\nE=a#b\n",
        );
        let want = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        assert_eq!(
            got,
            vec![
                want("A", "3"),
                want("B", "two words"),
                want("C", "x\ny\"#z"),
                want("D", "a #b\\n"),
                want("E", "a#b"),
            ]
        );
    }

    #[test]
    fn malformed_lines_name_the_line_never_the_content() {
        for (src, line) in [
            ("A=1\nTOPSECRET\n", 2),
            ("A=\"LEAKME\n", 1),
            ("A='x' y\n", 1),
            ("a b=1\n", 1),
        ] {
            let e = parse_env(src).unwrap_err();
            assert_eq!(e.exit_code(), exit::USAGE);
            assert!(e.message.contains(&format!("line {line}")), "{}", e.message);
            assert!(
                !e.message.contains("TOPSECRET") && !e.message.contains("LEAKME"),
                "{}",
                e.message
            );
        }
    }

    fn args(extra: &[&str]) -> SecretSetArgs {
        use clap::Parser;
        #[derive(Parser)]
        struct W {
            #[command(flatten)]
            a: SecretSetArgs,
        }
        let mut v = vec!["x", "web", "--env-file", "-"];
        v.extend_from_slice(extra);
        W::try_parse_from(v).unwrap().a
    }

    #[test]
    fn only_except_plain_split_the_file() {
        let e = || parse_env("A=1\nB=2\nC=3\nD=4\n").unwrap();
        let p = plan(e(), &args(&["--except", "D", "--plain", "C"])).unwrap();
        assert_eq!(
            p.secrets,
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
        assert_eq!(p.plain, vec![("C".into(), "3".into())]);
        let p = plan(e(), &args(&["--only", "B,D"])).unwrap();
        assert_eq!(p.secrets.len(), 2);
        assert!(plan(e(), &args(&["--only", "NOPE"])).is_err());
        // The values stay out of Debug.
        let shown = format!("{p:?}");
        assert!(
            shown.contains('B') && !shown.contains('2') && !shown.contains('4'),
            "{shown}"
        );
    }

    #[test]
    fn an_empty_secret_value_is_refused_unless_plain() {
        let e = || parse_env("A=\nB=1\n").unwrap();
        assert!(plan(e(), &args(&[])).is_err());
        assert!(plan(e(), &args(&["--plain", "A"])).is_ok());
    }

    #[test]
    fn binding_is_idempotent_and_conflicts_are_refused() {
        let mut spec: AppSpec = toml::from_str("image = \"i\"\n").unwrap();
        let p = plan(parse_env("A=1\nB=2\n").unwrap(), &args(&["--plain", "B"])).unwrap();
        assert_eq!(bind(&mut spec, &p).unwrap(), vec!["A".to_owned()]);
        assert_eq!(spec.env.get("B").map(String::as_str), Some("2"));
        // Second run: nothing new to bind, the spec is unchanged.
        let before = spec.clone();
        assert!(bind(&mut spec, &p).unwrap().is_empty());
        assert_eq!(spec, before);
        // A plain env key cannot become a secret, a bound variable cannot become plain.
        let p = plan(parse_env("B=2\n").unwrap(), &args(&[])).unwrap();
        assert!(bind(&mut spec, &p).is_err());
        let p = plan(parse_env("A=1\n").unwrap(), &args(&["--plain", "A"])).unwrap();
        assert!(bind(&mut spec, &p).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn env_file_stores_secrets_then_binds_once() {
        use crate::tests::mock;
        let live: AppSpec = toml::from_str("image = \"i\"\n").unwrap();
        let show = serde_json::json!({
            "name": "web", "spec": live, "state": {}, "runtime": "running",
        })
        .to_string();
        let info =
            r#"{"name":"A","updated_at":"2026-10-31T00:00:00Z","fingerprint":"fp"}"#.to_owned();
        let m = mock({
            let show = show.clone();
            move |method, path| match (method, path) {
                ("GET", _) => (200, show.clone()),
                ("PUT", p) if p.contains("/secrets/") => (200, info.clone()),
                _ => (200, format!(r#"{{"app":{show}}}"#)),
            }
        })
        .await;
        let o = Overrides {
            config: None,
            socket: Some(m.socket.clone()),
            host: None,
        };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("prod.env");
        std::fs::write(&file, "A=sekret-one\nB=sekret-two\nLEVEL=debug\n").unwrap();
        let mut a = args(&["--plain", "LEVEL"]);
        a.env_file = Some(file);
        assert_eq!(set_from_env_file(true, &o, a).await.unwrap(), exit::OK);
        let seen = m.seen.lock().unwrap();
        let puts: Vec<_> = seen.iter().filter(|s| s.method == "PUT").collect();
        assert_eq!(puts.len(), 3, "two secrets and one spec");
        assert!(puts[0].path.ends_with("/secrets/A") && puts[1].path.ends_with("/secrets/B"));
        assert!(puts[0].body.contains("sekret-one"));
        let spec: serde_json::Value = serde_json::from_str(&puts[2].body).unwrap();
        assert_eq!(spec["spec"]["env"]["LEVEL"], "debug");
        assert_eq!(spec["spec"]["secrets"].as_array().unwrap().len(), 2);
        // No value travels in the spec.
        assert!(!puts[2].body.contains("sekret"));
    }
}
