//! Real init-system acceptance checks.
//!
//! They are ignored by default because they need a prepared host: a bootstrapped installation,
//! rootless Podman, and (for the systemd case) a live user manager / (for the OpenRC case) Alpine
//! with BusyBox crond. The fake-adapter suite in `src/` covers the state machine; these checks are
//! the real-system evidence the brief asks for. Run them explicitly on the target host:
//!
//! ```sh
//! WEGLARKA_HOST_DIR=/var/lib/weglarka-host \
//! WEGLARKA_CONFIG=/etc/weglarka/weglarka.toml \
//!   cargo test -p weglarka-launcher --test real_init -- --ignored --nocapture
//! ```
//!
//! Full reboot/crash-loop scenarios are operator-run: stop the container as the runtime user,
//! reboot, and watch `platform-service.toml`/the observed container. They are not automated here
//! because they destroy the host's running daemon.

use std::path::Path;
use std::process::Command;

fn host_dir() -> String {
    std::env::var("WEGLARKA_HOST_DIR").expect("set WEGLARKA_HOST_DIR to the host-only directory")
}

fn config() -> String {
    std::env::var("WEGLARKA_CONFIG").unwrap_or_else(|_| "/etc/weglarka/weglarka.toml".to_owned())
}

fn launcher() -> Command {
    Command::new(env!("CARGO_BIN_EXE_weglarka-launcher"))
}

#[test]
#[ignore = "needs a bootstrapped systemd host with a live user manager and rootless Podman"]
fn systemd_units_are_handoff_safe_and_both_generations_pass_preflight() {
    for unit in [
        "weglarka-platform-update.timer",
        "weglarka-platform-watchdog.timer",
    ] {
        let status = Command::new("systemctl")
            .args(["--user", "is-enabled", unit])
            .status()
            .expect("systemctl");
        assert!(status.success(), "{unit} is not enabled");
    }
    let output = launcher()
        .args([
            "--host-dir",
            &host_dir(),
            "preflight",
            "--config",
            &config(),
            "--all",
        ])
        .status()
        .expect("launcher preflight");
    assert!(output.success(), "active/recovery preflight failed");

    // After a reboot the installed quadlet and the selection must agree. The actual digest is
    // checked by the coordinator; here we only assert the launcher can resolve both generations.
    assert!(
        Path::new(&host_dir()).join("host-tools.toml").is_file(),
        "host-tools.toml is missing"
    );
}

#[test]
#[ignore = "needs Alpine/OpenRC with BusyBox crond and a bootstrapped installation"]
fn alpine_openrc_services_drop_privileges_and_cron_is_installed() {
    assert!(
        Path::new("/sbin/openrc-run").exists(),
        "this is not an OpenRC host"
    );
    let daemon =
        std::fs::read_to_string("/etc/init.d/weglarka").expect("/etc/init.d/weglarka is missing");
    assert!(daemon.contains("command_user="), "{daemon}");
    assert!(daemon.contains("respawn_max=0"), "{daemon}");
    assert!(!daemon.contains("runuser"), "{daemon}");
    let podman = std::fs::read_to_string("/etc/init.d/weglarka-podman")
        .expect("/etc/init.d/weglarka-podman is missing");
    assert!(podman.contains("checkpath"), "{podman}");

    let cron = Command::new("rc-service")
        .args(["crond", "status"])
        .status()
        .expect("rc-service");
    assert!(cron.success(), "crond is not running");

    let output = launcher()
        .args([
            "--host-dir",
            &host_dir(),
            "preflight",
            "--config",
            &config(),
            "--all",
        ])
        .status()
        .expect("launcher preflight");
    assert!(output.success(), "active/recovery preflight failed");
}
