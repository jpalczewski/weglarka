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
