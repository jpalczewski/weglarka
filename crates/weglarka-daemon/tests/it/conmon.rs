//! `podman.conmon` through the real admin socket (issue #470): the host-side watchdog records what it
//! saw in the state directory, and `doctor` reports it — absent, fresh, stale and with dead conmons.
//!
//! The liveness probe itself is unit-tested in `weglarka_daemon::conmon` (injected, no real `/proc`);
//! this module covers the file the daemon reads and the check it produces.

use crate::common::*;

use serde_json::Value;
use weglarka_daemon::conmon::{self, Report};

fn check(report: &Value) -> &Value {
    report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["id"] == "podman.conmon")
        .unwrap_or_else(|| panic!("no podman.conmon check in {report}"))
}

#[tokio::test]
async fn doctor_reports_the_host_side_conmon_check() {
    let h = harness().await;
    let state_dir = h.root.join("state");

    // Before the watchdog ever ran: advice, not a failure (the timer may not be installed yet).
    let (status, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, 200);
    let absent = check(&report);
    assert_eq!(absent["status"], "info", "{absent}");
    assert!(
        absent["message"]
            .as_str()
            .unwrap()
            .contains("no host-side conmon check yet"),
        "{absent}"
    );
    assert!(
        absent["hint"]
            .as_str()
            .unwrap()
            .contains("weglarka-watchdog")
    );

    // A watchdog run with no affected instance (FakePodman reports no conmon PIDs): a fresh empty
    // report is an `ok`.
    let now = weglarka_model::self_update::secs(std::time::SystemTime::now());
    let summary = conmon::check(&h.fake, &conmon::ProcConmon::host(), &state_dir, now).await;
    assert_eq!(summary, conmon::Summary::Ok { checked: 0 }, "{summary}");
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let clean = check(&report);
    assert_eq!(clean["status"], "ok", "{clean}");

    // Two containers libpod still calls `running` without a live conmon: the operator has to act, and
    // the fix is the reload of each app.
    conmon::record(
        &state_dir,
        &Report {
            checked_at: Some(now),
            affected: vec!["blog".to_owned(), "ntfy".to_owned()],
        },
    )
    .unwrap();
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let dead = check(&report);
    assert_eq!(dead["status"], "fail", "{dead}");
    assert_eq!(
        dead["hint"],
        "restart each one: `weglarka apps reload blog`, `weglarka apps reload ntfy`"
    );
    assert!(
        dead["message"].as_str().unwrap().contains("blog, ntfy"),
        "{dead}"
    );

    // An old report is not an "all clear": the watchdog timer stopped.
    conmon::record(
        &state_dir,
        &Report {
            checked_at: Some(now.saturating_sub(3_600)),
            affected: Vec::new(),
        },
    )
    .unwrap();
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let stale = check(&report);
    assert_eq!(stale["status"], "warn", "{stale}");
    assert!(
        stale["message"]
            .as_str()
            .unwrap()
            .contains("old (it runs every minute)"),
        "{stale}"
    );
    h.running.stop().await;
}
