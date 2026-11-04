//! End-to-end checks of the fixed launcher roles with fake generation binaries.
//!
//! These exercise the real binary (argument parsing, selector validation, generation verification,
//! direct execution, timeouts and the persisted recovery budget) without an init system or Podman.
//! The real systemd/OpenRC tests are separate and marked ignored.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use weglarka_launcher::generation::{ExpectedFile, GenerationStore};
use weglarka_launcher::host::{HOST_CLI_FILE, HOST_DAEMON_FILE};
use weglarka_launcher::selector::HostSelector;
use weglarka_model::release_set::StrictDigest;

fn digest(bytes: &[u8]) -> StrictDigest {
    StrictDigest::new(format!("sha256:{}", hex::encode(Sha256::digest(bytes)))).unwrap()
}

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

struct Fixture {
    _dir: TempDir,
    root: PathBuf,
    host: PathBuf,
    config: PathBuf,
    state: PathBuf,
}

fn fixture(daemon_body: &str, cli_body: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_owned();
    let host = root.join("host");
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let config = root.join("weglarka.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[ingress]
mode = "behind"
bind = "127.0.0.1:8080"
[admin]
socket = "{}/admin.sock"
[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.org"
[state]
dir = "{}"
[self_update]
image = "ghcr.io/example/weglarka:latest"
"#,
            root.display(),
            state.display()
        ),
    )
    .unwrap();

    let store = GenerationStore::new(&host);
    let staging = store.staging_dir().unwrap();
    let daemon = script(&staging, HOST_DAEMON_FILE, daemon_body);
    let cli = script(&staging, HOST_CLI_FILE, cli_body);
    let expected = [
        ExpectedFile::new(
            HOST_DAEMON_FILE,
            std::fs::metadata(&daemon).unwrap().len(),
            digest(daemon_body.as_bytes()),
        ),
        ExpectedFile::new(
            HOST_CLI_FILE,
            std::fs::metadata(&cli).unwrap().len(),
            digest(cli_body.as_bytes()),
        ),
    ];
    let generation = StrictDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    let installed = store.install(&staging, &generation, &expected).unwrap();
    HostSelector::fresh(installed.digest().clone())
        .save(&host)
        .unwrap();

    Fixture {
        _dir: dir,
        root,
        host,
        config,
        state,
    }
}

fn launcher() -> Command {
    Command::new(env!("CARGO_BIN_EXE_weglarka-launcher"))
}

#[test]
fn preflight_runs_the_selected_generation_and_rejects_a_missing_candidate() {
    let fixture = fixture(
        "#!/bin/sh\necho '{\"host_protocol\":1}'\nexit 0\n",
        "#!/bin/sh\nexit 0\n",
    );
    let output = launcher()
        .args([
            "--host-dir",
            fixture.host.to_str().unwrap(),
            "preflight",
            "--config",
            fixture.config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let output = launcher()
        .args([
            "--host-dir",
            fixture.host.to_str().unwrap(),
            "preflight",
            "--config",
            fixture.config.to_str().unwrap(),
            "--selector",
            "candidate",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no candidate"));
}

#[test]
fn a_failing_preflight_exits_non_zero_and_does_not_hide_the_failure() {
    let fixture = fixture("#!/bin/sh\nexit 3\n", "#!/bin/sh\nexit 0\n");
    let output = launcher()
        .args([
            "--host-dir",
            fixture.host.to_str().unwrap(),
            "preflight",
            "--config",
            fixture.config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("preflight active failed"));
}

#[test]
fn update_respects_runtime_jobs_without_executing_the_generation() {
    let marker = std::env::temp_dir().join(format!("weglarka-update-ran-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let fixture = fixture(
        &format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
        "#!/bin/sh\nexit 0\n",
    );
    std::fs::write(
        fixture.state.join("runtime-jobs.toml"),
        "format_version = 1\nupdate = false\nwatchdog = true\n",
    )
    .unwrap();
    let output = launcher()
        .args([
            "--host-dir",
            fixture.host.to_str().unwrap(),
            "--config",
            fixture.config.to_str().unwrap(),
            "update",
            "--worker-timeout-secs",
            "5",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(!marker.exists(), "the disabled job must not execute");
}

#[test]
fn the_recovery_budget_is_persisted_across_processes_and_stops_the_exec() {
    let fixture = fixture("#!/bin/sh\nexit 9\n", "#!/bin/sh\nexit 0\n");
    let args = [
        "--host-dir",
        fixture.host.to_str().unwrap(),
        "recover",
        "--config",
        fixture.config.to_str().unwrap(),
        "--transaction",
        "tx-1",
        "--max-attempts",
        "2",
    ];
    for _ in 0..2 {
        let output = launcher().args(args).output().unwrap();
        assert!(!output.status.success());
    }
    let output = launcher().args(args).output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("budget is exhausted"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The recovery generation did not run a third time; a new transaction resets the budget.
    let state = std::fs::read_to_string(fixture.host.join("recovery-state.toml")).unwrap();
    assert!(state.contains("blocked = true"), "{state}");
}

#[test]
fn cli_passes_arguments_directly_without_a_shell() {
    let fixture = fixture(
        "#!/bin/sh\nexit 0\n",
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$WEGLARKA_TEST_OUT\"\n",
    );
    let out = fixture.root.join("cli-args.txt");
    let output = launcher()
        .env("WEGLARKA_TEST_OUT", &out)
        .args([
            "--host-dir",
            fixture.host.to_str().unwrap(),
            "cli",
            "--",
            "apps",
            "show",
            "a;b",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let args = std::fs::read_to_string(out).unwrap();
    assert_eq!(args.lines().collect::<Vec<_>>(), ["apps", "show", "a;b"]);
}

#[test]
fn the_cli_role_keeps_the_cli_exit_code() {
    let fixture = fixture("#!/bin/sh\nexit 0\n", "#!/bin/sh\nexit 7\n");
    let output = launcher()
        .args(["--host-dir", fixture.host.to_str().unwrap(), "cli"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
}

#[test]
fn the_cli_role_passes_stdin_through_to_the_cli() {
    let fixture = fixture("#!/bin/sh\nexit 0\n", "#!/bin/sh\ncat\n");
    let mut child = launcher()
        .args(["--host-dir", fixture.host.to_str().unwrap(), "cli"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello from stdin\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "hello from stdin\n"
    );
}
