//! Container resource use (`GET /v1/stats`, `GET /v1/apps/{name}/stats`, docs/decisions/0065).
//!
//! Every number is an `Option`: `None` (JSON `null`) means "no data", never zero. The views carry no
//! container id, image, command or label.

use serde::{Deserialize, Serialize};

/// Which of an app's containers a row describes (the ADR 0061 label contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatsRole {
    /// The serving container.
    Active,
    /// The new container of a blue/green switch that has not taken over yet.
    Challenger,
    /// The old container that a switch is about to remove.
    Retiring,
    /// A role this client does not know, produced by a newer daemon than the one it expects. The
    /// daemon never sends it: it only keeps a client parsing an answer it cannot name instead of
    /// failing the whole response.
    #[serde(other)]
    Unknown,
}

/// Resource use of one container of an app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerStatsView {
    pub role: StatsRole,
    /// Restarts counted by Podman.
    pub restarts: u32,
    /// Podman recorded an out-of-memory kill at least once.
    pub oom_killed: bool,
    pub memory_bytes: Option<u64>,
    /// From the container's own limit; `null` when it has none (never the host's RAM).
    pub memory_limit_bytes: Option<u64>,
    /// Cores used on average over `cpu_window_secs` (`1.0` = one fully used core).
    pub cpu_ratio: Option<f64>,
    /// The wall-clock window `cpu_ratio` is computed over.
    pub cpu_window_secs: Option<f64>,
    /// The raw CPU counter, in seconds.
    pub cpu_seconds_total: Option<f64>,
    pub pids: Option<u64>,
    pub block_read_bytes: Option<u64>,
    pub block_write_bytes: Option<u64>,
    pub net_rx_bytes: Option<u64>,
    pub net_tx_bytes: Option<u64>,
}

/// `GET /v1/apps/{name}/stats`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppStatsResponse {
    pub app: String,
    /// When the snapshot was taken (RFC 3339, UTC); `null` when `available` is false.
    pub sampled_at: Option<String>,
    /// False when libpod failed or timed out: there are no rows then, which is not "no containers".
    pub available: bool,
    pub containers: Vec<ContainerStatsView>,
}

/// `GET /v1/stats`: every app that has a reported container, sorted by name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatsResponse {
    pub sampled_at: Option<String>,
    pub available: bool,
    pub apps: Vec<AppStatsResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row from a newer daemon: a role this client does not know parses to `Unknown` instead of
    /// failing the whole `GET /v1/stats` answer.
    #[test]
    fn a_stats_role_from_a_newer_daemon_deserializes_to_unknown() {
        let body = r#"{
            "sampled_at": "2026-10-31T12:00:00Z",
            "available": true,
            "apps": [
                {
                    "app": "gitea",
                    "sampled_at": "2026-10-31T12:00:00Z",
                    "available": true,
                    "containers": [
                        {
                            "role": "made_up_by_a_newer_daemon",
                            "restarts": 0,
                            "oom_killed": false,
                            "memory_bytes": 1024,
                            "memory_limit_bytes": null,
                            "cpu_ratio": 0.5,
                            "cpu_window_secs": 1.0,
                            "cpu_seconds_total": 1.0,
                            "pids": 3,
                            "block_read_bytes": 0,
                            "block_write_bytes": 0,
                            "net_rx_bytes": 0,
                            "net_tx_bytes": 0
                        }
                    ]
                }
            ]
        }"#;
        let parsed: StatsResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.apps[0].containers[0].role, StatsRole::Unknown);
        assert_eq!(serde_json::to_value(StatsRole::Unknown).unwrap(), "unknown");

        // Every role a daemon may send still round-trips through its exact wire spelling.
        for (wire, role) in [
            ("active", StatsRole::Active),
            ("challenger", StatsRole::Challenger),
            ("retiring", StatsRole::Retiring),
        ] {
            assert_eq!(serde_json::to_value(role).unwrap(), wire);
            let parsed: StatsRole = serde_json::from_value(wire.into()).unwrap();
            assert_eq!(parsed, role, "{wire}");
        }
    }
}
