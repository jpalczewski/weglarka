//! Image retention through the admin API (issue #40): `POST /v1/images/prune` and the `doctor`
//! warning. Real unix socket, `FakePodman`.

use crate::common::*;

use futures_util::StreamExt;
use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_engine::testing::DEFAULT_IMAGE_SIZE_BYTES;
use weglarka_model::app::Digest;
use weglarka_model::podman::PodmanClient;

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

fn digest(c: char) -> Digest {
    Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
}

/// The `runtime.images` check of a `GET /v1/doctor`.
async fn image_check(h: &Harness) -> Value {
    let (status, report) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["id"] == "runtime.images")
        .cloned()
        .expect("every report carries the image check")
}

#[tokio::test]
async fn prune_dry_run_then_removes_and_doctor_reports_it() {
    let h = harness().await;
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let (status, value) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "ntfy",
            "spec": {
                "image": IMAGE,
                "domains": ["nz.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    eventually("first deploy", || async {
        let (_, app) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
        app["state"]["current"].is_string()
    })
    .await;

    // What an earlier deploy left behind: an image of the app's repository that `state.toml` does
    // not know (the daemon used to keep every pulled image).
    // The ingress nginx image sits in the same store, so counts are relative to it.
    let seeded = h.fake.images().len() + 1;
    let stale = format!("ghcr.io/jpalczewski/ntfy.zig@{}", digest('e'));
    h.fake.set_pull_digest(&stale, digest('e'));
    h.fake.image_pull(&stale).collect::<Vec<_>>().await;
    assert_eq!(h.fake.images().len(), seeded);

    let check = image_check(&h).await;
    assert_eq!(check["status"], "warn", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("1 unused image(s)"),
        "{check}"
    );
    assert!(
        check["hint"]
            .as_str()
            .unwrap()
            .contains("weglarka images prune"),
        "{check}"
    );

    let (status, value) = admin(
        &h,
        "POST",
        "/v1/images/prune",
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["removed"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["reclaimed_bytes"], json!(DEFAULT_IMAGE_SIZE_BYTES));
    assert_eq!(h.fake.images().len(), seeded, "a dry run removes nothing");

    // No body = an actual prune.
    let (status, value) = admin(&h, "POST", "/v1/images/prune", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["dry_run"], false);
    assert_eq!(value["removed"][0]["digests"], json!([stale]));
    assert_eq!(value["reclaimed_bytes"], json!(DEFAULT_IMAGE_SIZE_BYTES));
    assert!(value.get("failed").is_none(), "nothing failed: {value}");
    assert_eq!(h.fake.images().len(), seeded - 1, "the leftover is gone");

    let check = image_check(&h).await;
    assert_eq!(check["status"], "ok", "{check}");
}

/// An image a container still uses is never removed, not even when nothing in `state.toml` protects
/// it: the planner only removes what is provably dead weight, and Podman is the backstop.
#[tokio::test]
async fn an_image_used_by_a_container_survives_a_prune() {
    let h = harness().await;
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let (status, value) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "ntfy",
            "spec": {
                "image": IMAGE,
                "domains": ["nz.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    eventually("first deploy", || async {
        let (_, app) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
        app["state"]["current"].is_string()
    })
    .await;

    // The ingress nginx image lives in the same store; only the app image is interesting here.
    let before = h.fake.images().len();
    let (status, value) = admin(&h, "POST", "/v1/images/prune", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["removed"], json!([]), "{value}");
    assert_eq!(h.fake.images().len(), before);

    // Nothing was removed, so the doctor reports no leftovers either.
    let check = image_check(&h).await;
    assert_eq!(check["status"], "ok", "{check}");
}

/// `image-reservations.toml` under `root` with `operations` as `(operation id, boot id)`, all
/// `loading`: what a daemon leaves behind when it stops mid-acquisition.
fn write_reservations(root: &std::path::Path, operations: &[(String, String)]) {
    use weglarka_model::image_inventory::{
        OperationId, RESERVATIONS_FILE_NAME, Reservation, ReservationEntry, ReservationOwner,
        ReservationPhase, Reservations,
    };
    let entries = operations
        .iter()
        .enumerate()
        .map(|(n, (id, boot))| ReservationEntry {
            operation_id: OperationId::new(id).unwrap(),
            reservation: Reservation {
                owner: ReservationOwner::new("engine", 7, boot, 1_700_000_000 + n as u64).unwrap(),
                phase: ReservationPhase::Loading,
                protections: Default::default(),
                journal_ref: None,
                created_at: 1_700_000_000,
            },
        })
        .collect();
    let text = Reservations::new(entries).unwrap().to_toml().unwrap();
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state").join(RESERVATIONS_FILE_NAME), text).unwrap();
}

fn this_boot() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|id| id.trim().to_owned())
        .unwrap_or_else(|_| "unknown-boot".to_owned())
}

/// Starting the daemon reclaims the reservations a previous boot left (their `boot_id` differs from
/// the current one) and leaves one of this boot alone; `GET /v1/images/reservations` shows the rest.
#[tokio::test]
async fn startup_reclaims_reservations_of_a_previous_boot() {
    let builder = Builder::new();
    write_reservations(
        builder.root(),
        &[
            ("stale-1".into(), "boot-gone".into()),
            ("live".into(), this_boot()),
            ("stale-2".into(), "boot-gone".into()),
        ],
    );
    let h = builder.build().await;

    let (status, list) = admin(&h, "GET", "/v1/images/reservations", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let ids: Vec<&str> = list["reservations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["operation_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["live"], "{list}");
    assert_eq!(list["reservations"][0]["phase"], "loading");
    assert_eq!(list["reservations"][0]["previous_boot"], false);
    assert_eq!(list["reservations"][0]["component"], "engine");
    assert_eq!(list["reservations"][0]["pid"], 7);
    assert_eq!(list["capacity"], 1024);
    assert!(
        list["reservations"][0].get("protections").is_some(),
        "{list}"
    );
}

/// With nothing stale there is nothing to reclaim and the list is empty.
#[tokio::test]
async fn an_empty_reservation_list_is_an_empty_array() {
    let h = harness().await;
    let (status, list) = admin(&h, "GET", "/v1/images/reservations", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["reservations"], json!([]), "{list}");
}

/// A full reservation file blocks cleanup without failing the request: `POST /v1/images/prune` is a
/// 200 with `blocked: true` and the reason, nothing is removed, and `doctor` warns. Reservations of
/// the current boot, so startup does not reclaim them.
#[tokio::test]
async fn a_full_reservation_file_answers_prune_as_blocked_and_doctor_warns() {
    let builder = Builder::new();
    let boot = this_boot();
    let operations: Vec<(String, String)> = (0..1024)
        .map(|n| (format!("stuck-{n}"), boot.clone()))
        .collect();
    write_reservations(builder.root(), &operations);
    let h = builder.build().await;
    // The ingress image is pulled by the first reconcile; wait for it so the count is stable.
    eventually("ingress image", || async { !h.fake.images().is_empty() }).await;
    let before = h.fake.images().len();

    for body in [Some(json!({ "dry_run": true })), None] {
        let (status, value) = admin(&h, "POST", "/v1/images/prune", body).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value["blocked"], true, "{value}");
        assert!(
            value["removed"].is_null() || value["removed"] == json!([]),
            "{value}"
        );
        let diagnostics = value["diagnostics"].to_string();
        assert!(diagnostics.contains("full"), "{value}");
        assert!(
            diagnostics.contains("weglarka images reservations abandon"),
            "{value}"
        );
    }
    assert_eq!(h.fake.images().len(), before, "nothing was removed");

    let check = image_check(&h).await;
    assert_eq!(check["status"], "warn", "{check}");
    assert!(
        check["message"].as_str().unwrap().contains("full"),
        "{check}"
    );
    assert!(
        check["hint"]
            .as_str()
            .unwrap()
            .contains("weglarka images reservations list"),
        "{check}"
    );

    // Abandoning one brings the normal pass back.
    let (status, value) = admin(
        &h,
        "POST",
        "/v1/images/reservations/abandon",
        Some(json!({ "operation_id": "stuck-0" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let (status, value) = admin(&h, "POST", "/v1/images/prune", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert!(value.get("blocked").is_none(), "{value}");
}

/// A previous-boot reservation that a nonterminal platform transaction lists survives the startup
/// reclaim (and the list says it is referenced); an unreferenced one next to it is reclaimed.
#[tokio::test]
async fn startup_spares_a_reservation_a_platform_transaction_references() {
    use weglarka_model::platform_update::{
        FILE_NAME, JournalEndpoint, OwnerIdentity, PlatformUpdate, Stage, TransactionId,
        TransactionJournal,
    };
    use weglarka_model::release_set::{Repository, StrictDigest};
    let builder = Builder::new();
    write_reservations(
        builder.root(),
        &[
            ("held".into(), "boot-gone".into()),
            ("free".into(), "boot-gone".into()),
        ],
    );
    let digest = StrictDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap();
    let endpoint = JournalEndpoint {
        daemon_repository: Repository::new("ghcr.io/example/weglarka").unwrap(),
        daemon_digest: digest.clone(),
        tools_digest: digest.clone(),
        state_read: vec![17],
        state_write: 17,
        host_protocol: 1,
    };
    let journal = PlatformUpdate {
        transaction: Some(TransactionJournal {
            transaction_id: TransactionId::new("tx-1").unwrap(),
            stage: Stage::Prepared,
            owner: OwnerIdentity {
                pid: 1,
                boot_id: "boot-gone".into(),
                started_at: 1,
                handoff_deadline: None,
            },
            old: endpoint.clone(),
            target: endpoint,
            release_set_digest: digest,
            reservations: vec![weglarka_model::image_inventory::OperationId::new("held").unwrap()],
            candidate: None,
            ack: None,
            selected_generation: None,
            reason: None,
            updated_at: 1,
        }),
        ..PlatformUpdate::default()
    };
    std::fs::write(
        builder.root().join("state").join(FILE_NAME),
        journal.to_toml().unwrap(),
    )
    .unwrap();
    let h = builder.build().await;

    let (status, list) = admin(&h, "GET", "/v1/images/reservations", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["reservations"].as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list["reservations"][0]["operation_id"], "held");
    assert_eq!(list["reservations"][0]["previous_boot"], true);
    assert_eq!(list["reservations"][0]["referenced"], true);
    assert!(list.get("diagnostics").is_none(), "{list}");
}

/// A corrupt `platform-update.toml` leaves startup reclaim with nothing to go on (fail closed: no
/// reservation is reclaimed, the daemon still starts), and the list degrades: every id is there,
/// `referenced` is `null` and a diagnostic names the file.
#[tokio::test]
async fn a_corrupt_platform_journal_keeps_every_reservation_and_degrades_the_list() {
    let builder = Builder::new();
    write_reservations(
        builder.root(),
        &[
            ("old-1".into(), "boot-gone".into()),
            ("old-2".into(), "boot-gone".into()),
        ],
    );
    std::fs::write(
        builder
            .root()
            .join("state")
            .join(weglarka_model::platform_update::FILE_NAME),
        "this is [not valid toml",
    )
    .unwrap();
    let h = builder.build().await;

    let (status, list) = admin(&h, "GET", "/v1/images/reservations", None).await;

    assert_eq!(status, StatusCode::OK, "{list}");
    let rows = list["reservations"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "nothing was reclaimed: {list}");
    for row in rows {
        assert!(row["referenced"].is_null(), "{row}");
        assert_eq!(row["previous_boot"], true);
    }
    let diagnostics = list["diagnostics"].to_string();
    assert!(diagnostics.contains("platform-update.toml"), "{list}");
}
