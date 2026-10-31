//! `weglarka stats [APP]`: container resource use without Prometheus (`GET /v1/stats`,
//! `GET /v1/apps/{name}/stats`, docs/decisions/0065).
//!
//! The daemon serves a cached snapshot; this side only prints it. A number the daemon does not know
//! is `null` and shows as `—`, never as `0`. `--json` prints the response as is.

use clap::Args;
use weglarka_api::{AppStatsResponse, ContainerStatsView, StatsResponse, StatsRole, endpoints};
use weglarka_model::units::human_bytes;

use crate::commands::{client, instance};
use crate::error::{CliError, exit};
use crate::output::{emit, table};
use crate::settings::Overrides;

/// A value that is not known.
const NONE: &str = "—";

#[derive(Debug, Args)]
#[command(after_help = "\
Examples:
  weglarka stats
  weglarka stats ntfy
  weglarka --json stats ntfy | jq '.containers[].memory_bytes'")]
pub struct StatsArgs {
    /// Show only this app. Default: every app that has a reported container.
    #[arg(value_name = "APP")]
    pub app: Option<String>,
}

pub async fn run(json: bool, o: &Overrides, a: StatsArgs) -> Result<i32, CliError> {
    match a.app {
        None => {
            let resp: StatsResponse = client(o)?.call(endpoints::STATS, &[], None::<&()>).await?;
            emit(json, &resp, || render_all(&resp));
            if !json && let Some(warning) = warning(resp.available) {
                eprintln!("{warning}");
            }
        }
        Some(app) => {
            let name = instance(&app)?;
            let resp: AppStatsResponse = client(o)?
                .call(
                    endpoints::APPS_STATS,
                    &[("name", name.as_str())],
                    None::<&()>,
                )
                .await?;
            emit(json, &resp, || render_app(&resp));
            if !json && let Some(warning) = warning(resp.available) {
                eprintln!("{warning}");
            }
        }
    }
    Ok(exit::OK)
}

/// `available: false` means libpod did not answer, which is not "no containers". Exit code stays 0.
fn warning(available: bool) -> Option<&'static str> {
    (!available).then_some(
        "warning: container stats are unavailable right now (Podman did not answer); try again in a moment",
    )
}

const HEADER: [&str; 13] = [
    "APP",
    "ROLE",
    "MEMORY",
    "LIMIT",
    "% LIMIT",
    "CPU",
    "PIDS",
    "NET RX",
    "NET TX",
    "BLK READ",
    "BLK WRITE",
    "RESTARTS",
    "OOM",
];

fn render_all(resp: &StatsResponse) -> String {
    let rows: Vec<Vec<String>> = resp
        .apps
        .iter()
        .flat_map(|app| app.containers.iter().map(|c| row(&app.app, c)))
        .collect();
    render_rows(&rows, resp.available, "no containers reported")
}

fn render_app(resp: &AppStatsResponse) -> String {
    let rows: Vec<Vec<String>> = resp.containers.iter().map(|c| row(&resp.app, c)).collect();
    render_rows(
        &rows,
        resp.available,
        &format!("no containers reported for {}", resp.app),
    )
}

fn render_rows(rows: &[Vec<String>], available: bool, empty: &str) -> String {
    // With `available: false` there are no rows; the warning says why, so no misleading "none" line.
    if rows.is_empty() {
        return if available {
            format!("{empty}\n")
        } else {
            String::new()
        };
    }
    table(&HEADER, rows)
}

fn row(app: &str, c: &ContainerStatsView) -> Vec<String> {
    let bytes = |v: Option<u64>| v.map_or_else(|| NONE.to_owned(), human_bytes);
    vec![
        app.to_owned(),
        role(c.role).to_owned(),
        bytes(c.memory_bytes),
        bytes(c.memory_limit_bytes),
        percent_of_limit(c.memory_bytes, c.memory_limit_bytes),
        c.cpu_ratio
            .map_or_else(|| NONE.to_owned(), |r| format!("{:.1}%", r * 100.0)),
        c.pids.map_or_else(|| NONE.to_owned(), |p| p.to_string()),
        bytes(c.net_rx_bytes),
        bytes(c.net_tx_bytes),
        bytes(c.block_read_bytes),
        bytes(c.block_write_bytes),
        c.restarts.to_string(),
        if c.oom_killed { "yes" } else { "no" }.to_owned(),
    ]
}

fn role(role: StatsRole) -> &'static str {
    match role {
        StatsRole::Active => "active",
        StatsRole::Challenger => "challenger",
        StatsRole::Retiring => "retiring",
    }
}

/// Memory as a share of the container's own limit; unknown without both numbers or with a zero limit.
fn percent_of_limit(used: Option<u64>, limit: Option<u64>) -> String {
    match (used, limit) {
        (Some(used), Some(limit)) if limit > 0 => {
            format!("{:.1}%", used as f64 / limit as f64 * 100.0)
        }
        _ => NONE.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use weglarka_api::{ApiError, ErrorCode};
    use weglarka_unix_http::testing::{Mock, mock};

    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn overrides(m: &Mock) -> Overrides {
        Overrides {
            config: None,
            socket: Some(m.socket.clone()),
            host: None,
        }
    }

    fn full(role: StatsRole) -> ContainerStatsView {
        ContainerStatsView {
            role,
            restarts: 2,
            oom_killed: true,
            memory_bytes: Some(64 * MIB),
            memory_limit_bytes: Some(256 * MIB),
            cpu_ratio: Some(0.0537),
            cpu_window_secs: Some(10.0),
            cpu_seconds_total: Some(12.5),
            pids: Some(7),
            block_read_bytes: Some(3 * MIB),
            block_write_bytes: Some(1024),
            net_rx_bytes: Some(5 * 1024 * MIB),
            net_tx_bytes: Some(512),
        }
    }

    fn empty(role: StatsRole) -> ContainerStatsView {
        ContainerStatsView {
            role,
            restarts: 0,
            oom_killed: false,
            memory_bytes: None,
            memory_limit_bytes: None,
            cpu_ratio: None,
            cpu_window_secs: None,
            cpu_seconds_total: None,
            pids: None,
            block_read_bytes: None,
            block_write_bytes: None,
            net_rx_bytes: None,
            net_tx_bytes: None,
        }
    }

    fn app(name: &str, containers: Vec<ContainerStatsView>) -> AppStatsResponse {
        AppStatsResponse {
            app: name.to_owned(),
            sampled_at: Some("2026-10-31T10:00:00Z".to_owned()),
            available: true,
            containers,
        }
    }

    #[test]
    fn renders_every_value() {
        let resp = StatsResponse {
            sampled_at: Some("2026-10-31T10:00:00Z".to_owned()),
            available: true,
            apps: vec![
                app(
                    "ntfy",
                    vec![full(StatsRole::Active), full(StatsRole::Retiring)],
                ),
                app("web", vec![full(StatsRole::Challenger)]),
            ],
        };
        insta::assert_snapshot!(render_all(&resp));
    }

    #[test]
    fn renders_null_as_a_dash() {
        let resp = app("ntfy", vec![empty(StatsRole::Active)]);
        insta::assert_snapshot!(render_app(&resp));
    }

    #[test]
    fn unavailable_prints_a_warning_and_no_table() {
        let resp = StatsResponse {
            sampled_at: None,
            available: false,
            apps: Vec::new(),
        };
        let text = format!(
            "{}{}\n",
            render_all(&resp),
            warning(resp.available).unwrap()
        );
        insta::assert_snapshot!(text);
        assert_eq!(warning(true), None);
    }

    #[test]
    fn no_containers_is_not_the_same_as_unavailable() {
        let resp = app("ntfy", Vec::new());
        assert_eq!(render_app(&resp), "no containers reported for ntfy\n");
    }

    #[test]
    fn percent_of_limit_needs_both_numbers_and_a_nonzero_limit() {
        assert_eq!(percent_of_limit(Some(64), Some(256)), "25.0%");
        assert_eq!(percent_of_limit(Some(64), None), NONE);
        assert_eq!(percent_of_limit(None, Some(256)), NONE);
        assert_eq!(percent_of_limit(Some(64), Some(0)), NONE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stats_requests_the_endpoints_and_json_round_trips() {
        let all = StatsResponse {
            sampled_at: Some("2026-10-31T10:00:00Z".to_owned()),
            available: true,
            apps: vec![app("ntfy", vec![full(StatsRole::Active)])],
        };
        let body = serde_json::to_string(&all).unwrap();
        let m = mock(move |_, _| (200, body.clone())).await;
        let code = run(true, &overrides(&m), StatsArgs { app: None })
            .await
            .unwrap();
        assert_eq!(code, exit::OK);
        {
            let seen = m.seen.lock().unwrap();
            assert_eq!(
                (seen[0].method.as_str(), seen[0].path.as_str()),
                ("GET", "/v1/stats")
            );
        }
        // What `--json` prints is the response itself.
        let printed = serde_json::to_string_pretty(&all).unwrap();
        assert_eq!(
            serde_json::from_str::<StatsResponse>(&printed).unwrap(),
            all
        );

        let one = app("ntfy", vec![full(StatsRole::Active)]);
        let body = serde_json::to_string(&one).unwrap();
        let m = mock(move |_, _| (200, body.clone())).await;
        let code = run(
            false,
            &overrides(&m),
            StatsArgs {
                app: Some("ntfy".to_owned()),
            },
        )
        .await
        .unwrap();
        assert_eq!(code, exit::OK);
        let seen = m.seen.lock().unwrap();
        assert_eq!(
            (seen[0].method.as_str(), seen[0].path.as_str()),
            ("GET", "/v1/apps/ntfy/stats")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_app_is_the_usual_not_found() {
        let body = serde_json::to_string(&ApiError {
            code: ErrorCode::NotFound,
            message: "no such app: nope".into(),
        })
        .unwrap();
        let m = mock(move |_, _| (404, body.clone())).await;
        let err = run(
            false,
            &overrides(&m),
            StatsArgs {
                app: Some("nope".to_owned()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::NOT_FOUND);
        assert_eq!(err.message, "no such app: nope");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_invalid_app_name_is_a_usage_error_before_any_request() {
        let m = mock(|_, _| (200, String::new())).await;
        let err = run(
            false,
            &overrides(&m),
            StatsArgs {
                app: Some("../x".to_owned()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
        assert!(m.seen.lock().unwrap().is_empty());
    }
}
