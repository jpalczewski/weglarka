//! View models: the daemon's API types turned into plain strings and flags for the templates.
//! Nothing here renders HTML; escaping is askama's job. Every status is a word as well as a
//! style, so colour is never the only signal.

use serde::Serialize;
use weglarka_api::{
    AppStatsResponse, AppSummary, CertStatus, CertificateRecord, CertificatesResponse, CheckStatus,
    ConfigMountStatus, ConfigView, ContainerHealth, ContainerStatsView, DoctorCheck, EventRecord,
    HostMountStatus, NotifyStatusResponse, RuntimeState, ShowAppResponse, SiteSummary,
    StatsResponse, StatsRole,
};
use weglarka_model::events::Severity;
use weglarka_model::units::human_bytes;

/// A status label: `class` picks the style, `text` is always shown.
#[derive(Debug, Clone)]
pub struct Badge {
    pub class: &'static str,
    pub text: String,
}

impl Badge {
    fn new(class: &'static str, text: impl Into<String>) -> Self {
        Self {
            class,
            text: text.into(),
        }
    }
}

/// Serde's snake_case name of an enum value (`waiting_for_secret`), as the API spells it.
fn name_of<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

fn humanize(name: &str) -> String {
    name.replace('_', " ")
}

pub fn runtime_badge(state: RuntimeState) -> Badge {
    let class = match state {
        RuntimeState::Running => "ok",
        RuntimeState::Unhealthy => "fail",
        RuntimeState::Missing => "fail",
        RuntimeState::Stopped | RuntimeState::NotStarted => "muted",
        RuntimeState::WaitingForSecret => "warn",
    };
    Badge::new(class, humanize(&name_of(&state)))
}

pub fn health_badge(health: ContainerHealth) -> Badge {
    let class = match health {
        ContainerHealth::Healthy => "ok",
        ContainerHealth::Starting => "warn",
        ContainerHealth::Unhealthy => "fail",
    };
    Badge::new(class, name_of(&health))
}

pub fn check_badge(status: CheckStatus) -> Badge {
    let (class, text) = match status {
        CheckStatus::Ok => ("ok", "OK"),
        CheckStatus::Info => ("info", "Info"),
        CheckStatus::Warn => ("warn", "Warning"),
        CheckStatus::Fail => ("fail", "Failing"),
    };
    Badge::new(class, text)
}

pub fn severity_badge(severity: Severity) -> Badge {
    let class = match severity {
        Severity::Debug => "muted",
        Severity::Info => "info",
        Severity::Warning => "warn",
        Severity::Critical => "fail",
    };
    Badge::new(class, severity.as_str())
}

/// `sha256:0123456789ab…` for a long digest.
pub fn short_digest(digest: &str) -> String {
    match digest.split_once(':') {
        Some((algo, hex)) => match hex.get(..12) {
            Some(head) if hex.len() > 12 => format!("{algo}:{head}…"),
            _ => digest.to_owned(),
        },
        None => digest.to_owned(),
    }
}

#[derive(Debug)]
pub struct AppRow {
    pub name: String,
    pub image: String,
    pub domains: Vec<String>,
    pub runtime: Badge,
    pub digest: String,
    pub site: String,
    pub memory: String,
    pub cpu: String,
}

pub fn app_row(app: &AppSummary, usage: Option<&Usage>) -> AppRow {
    AppRow {
        memory: usage.map_or_else(|| NONE.to_owned(), |u| u.memory.clone()),
        cpu: usage.map_or_else(|| NONE.to_owned(), |u| u.cpu.clone()),
        name: app.name.to_string(),
        image: app.image.clone(),
        domains: app.domains.clone(),
        runtime: runtime_badge(app.runtime),
        digest: app
            .digest
            .as_ref()
            .map(|d| short_digest(&d.to_string()))
            .unwrap_or_default(),
        site: app.site.clone().unwrap_or_default(),
    }
}

/// A label with a value, for definition lists.
#[derive(Debug)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
}

pub fn field(label: &'static str, value: impl Into<String>) -> Field {
    Field {
        label,
        value: value.into(),
    }
}

#[derive(Debug)]
pub struct MountRow {
    pub source: String,
    pub target: String,
    pub status: Badge,
    pub detail: String,
}

#[derive(Debug)]
pub struct AppDetail {
    pub name: String,
    pub redacted: bool,
    pub runtime: Badge,
    pub health: Option<Badge>,
    pub runtime_fields: Vec<Field>,
    pub spec_fields: Vec<Field>,
    /// Env variable *names* only: values never reach a page, whoever asks.
    pub env_keys: Vec<String>,
    pub secrets: Vec<String>,
    pub volumes: Vec<String>,
    pub configs: Vec<MountRow>,
    pub host_mounts: Vec<MountRow>,
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "—".to_owned()
    } else {
        items.join(", ")
    }
}

pub fn app_detail(app: &ShowAppResponse) -> AppDetail {
    let spec = &app.spec;
    let state = &app.state;
    let mut runtime_fields = vec![
        field(
            "Restarts",
            app.restarts.map_or("—".to_owned(), |n| n.to_string()),
        ),
        field(
            "Started at",
            app.started_at.clone().unwrap_or_else(|| "—".to_owned()),
        ),
        field(
            "Current digest",
            state
                .current
                .as_ref()
                .map_or("—".to_owned(), ToString::to_string),
        ),
        field(
            "Previous digest",
            state
                .previous
                .as_ref()
                .map_or("—".to_owned(), ToString::to_string),
        ),
        field("Generation", state.generation.to_string()),
    ];
    if let Some(failed) = &state.failed {
        runtime_fields.push(field(
            "Last failed deploy",
            format!("{} — {}", failed.digest, failed.reason),
        ));
    }
    if !state.waiting_for_secrets.is_empty() {
        runtime_fields.push(field(
            "Waiting for secrets",
            state.waiting_for_secrets.join(", "),
        ));
    }

    let mut spec_fields = vec![
        field("Image", spec.image.clone()),
        field("Kind", name_of(&spec.kind)),
        field("Domains", join_or_dash(&spec.domains)),
    ];
    if !spec.paths.is_empty() {
        spec_fields.push(field("Paths", spec.paths.join(", ")));
    }
    if let Some(port) = spec.port {
        spec_fields.push(field("Port", port.to_string()));
    }
    // Arguments can carry credentials (the daemon redacts them for `read`), so even for an admin
    // the page names only the program, never the rest of the argv.
    if let Some(program) = spec.command.first() {
        let extra = spec.command.len() - 1;
        let tail = if extra == 0 {
            String::new()
        } else {
            format!(" (+{extra} arguments, not shown)")
        };
        spec_fields.push(field("Command", format!("{program}{tail}")));
    }
    let gate = &spec.health;
    let probe = match (&gate.http, &gate.command) {
        (Some(http), _) => format!("HTTP {} → {}", http.path, http.expect_status),
        (None, Some(_)) => "command".to_owned(),
        (None, None) => "container running".to_owned(),
    };
    spec_fields.push(field(
        "Health gate",
        format!(
            "{probe}, {} attempts within {} s",
            gate.attempts, gate.window_secs
        ),
    ));
    spec_fields.push(field("Strategy", name_of(&spec.strategy)));
    spec_fields.push(field("Auto-update", yes_no(spec.auto_update)));
    spec_fields.push(field("Start on deploy", yes_no(spec.start)));
    if !spec.depends_on.is_empty() {
        let deps: Vec<String> = spec.depends_on.iter().map(ToString::to_string).collect();
        spec_fields.push(field("Depends on", deps.join(", ")));
    }
    if !spec.host_ports.is_empty() {
        let ports: Vec<String> = spec
            .host_ports
            .iter()
            .map(|p| {
                format!(
                    "{}:{} → {}",
                    p.ip.as_deref()
                        .unwrap_or(weglarka_model::app::HostPort::DEFAULT_IP),
                    p.host,
                    p.container
                )
            })
            .collect();
        spec_fields.push(field("Host ports", ports.join(", ")));
    }
    if !spec.shared_networks.is_empty() {
        let nets: Vec<String> = spec
            .shared_networks
            .iter()
            .map(|n| n.name.to_string())
            .collect();
        spec_fields.push(field("Shared networks", nets.join(", ")));
    }

    let secrets = spec
        .secrets
        .iter()
        .map(|b| match &b.target {
            weglarka_model::app::SecretTarget::Env { var } => {
                format!("{} → env {var}", b.secret)
            }
            weglarka_model::app::SecretTarget::Mount { path, .. } => {
                format!("{} → file {path}", b.secret)
            }
        })
        .collect();

    let mut volumes: Vec<String> = spec
        .volumes
        .iter()
        .map(|v| mount_line(&v.name, &v.target, v.read_only))
        .collect();
    volumes.extend(spec.shared_volumes.iter().map(|v| {
        format!(
            "shared {}",
            mount_line(v.name.as_str(), &v.target, v.read_only)
        )
    }));

    AppDetail {
        name: app.name.to_string(),
        redacted: app.redacted,
        runtime: runtime_badge(app.runtime),
        health: app.health.map(health_badge),
        runtime_fields,
        spec_fields,
        env_keys: spec.env.keys().cloned().collect(),
        secrets,
        volumes,
        configs: app
            .configs
            .iter()
            .flatten()
            .map(|c| MountRow {
                source: c.source.clone(),
                target: c.target.clone(),
                status: config_mount_badge(c.status),
                detail: c.detail.clone().unwrap_or_default(),
            })
            .collect(),
        host_mounts: app
            .host_mounts
            .iter()
            .flatten()
            .map(|m| MountRow {
                source: m.source.clone(),
                target: m.target.clone(),
                status: host_mount_badge(m.status),
                detail: m.detail.clone().unwrap_or_default(),
            })
            .collect(),
    }
}

pub fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn mount_line(name: &str, target: &str, read_only: bool) -> String {
    let mode = if read_only { " (read-only)" } else { "" };
    format!("{name} → {target}{mode}")
}

fn config_mount_badge(status: ConfigMountStatus) -> Badge {
    let class = if status == ConfigMountStatus::Ok {
        "ok"
    } else {
        "fail"
    };
    Badge::new(class, humanize(&name_of(&status)))
}

fn host_mount_badge(status: HostMountStatus) -> Badge {
    let class = if status == HostMountStatus::Ok {
        "ok"
    } else {
        "fail"
    };
    Badge::new(class, humanize(&name_of(&status)))
}

#[derive(Debug)]
pub struct CheckRow {
    pub id: String,
    pub message: String,
    pub hint: String,
}

/// Doctor checks grouped by status, worst first; empty groups are left out.
#[derive(Debug)]
pub struct CheckGroup {
    pub badge: Badge,
    pub checks: Vec<CheckRow>,
}

pub fn doctor_groups(checks: &[DoctorCheck]) -> Vec<CheckGroup> {
    [
        CheckStatus::Fail,
        CheckStatus::Warn,
        CheckStatus::Info,
        CheckStatus::Ok,
    ]
    .into_iter()
    .filter_map(|status| {
        let rows: Vec<CheckRow> = checks
            .iter()
            .filter(|c| c.status == status)
            .map(|c| CheckRow {
                id: c.id.clone(),
                message: c.message.clone(),
                hint: c.hint.clone().unwrap_or_default(),
            })
            .collect();
        (!rows.is_empty()).then(|| CheckGroup {
            badge: check_badge(status),
            checks: rows,
        })
    })
    .collect()
}

/// `n problems` style summary of a doctor report for the dashboard.
pub fn doctor_summary(checks: &[DoctorCheck]) -> (Badge, String) {
    let count = |s| checks.iter().filter(|c| c.status == s).count();
    let worst = checks
        .iter()
        .map(|c| c.status)
        .max()
        .unwrap_or(CheckStatus::Ok);
    (
        check_badge(worst),
        format!(
            "{} failing, {} warnings, {} total",
            count(CheckStatus::Fail),
            count(CheckStatus::Warn),
            checks.len()
        ),
    )
}

#[derive(Debug, Clone)]
pub struct EventRow {
    pub seq: u64,
    pub ts: String,
    pub severity: Badge,
    pub kind: String,
    pub app: String,
    pub message: String,
    pub detail: String,
}

pub fn event_row(event: &EventRecord) -> EventRow {
    EventRow {
        seq: event.seq,
        ts: event.ts.clone(),
        severity: severity_badge(event.severity),
        kind: humanize(&event.kind),
        app: event
            .app
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        message: event.message.clone(),
        detail: event.detail.clone(),
    }
}

#[derive(Debug)]
pub struct CertRow {
    pub id: String,
    pub names: String,
    pub status: Badge,
    pub expires: String,
    pub days_left: String,
    pub coverage: String,
}

/// Certificates by urgency: missing ones first, then the fewest days left.
fn by_urgency(certs: &CertificatesResponse) -> Vec<&CertificateRecord> {
    let mut sorted: Vec<&CertificateRecord> = certs.certificates.iter().collect();
    sorted.sort_by_key(|c| {
        (
            c.status != CertStatus::Missing,
            c.days_left.unwrap_or(i64::MAX),
        )
    });
    sorted
}

pub fn cert_rows(certs: &CertificatesResponse) -> Vec<CertRow> {
    by_urgency(certs).into_iter().map(cert_row).collect()
}

fn cert_row(c: &CertificateRecord) -> CertRow {
    let (class, text) = match c.status {
        CertStatus::Valid => ("ok", "valid"),
        CertStatus::RenewalDue => ("warn", "renewal due"),
        CertStatus::Expired => ("fail", "expired"),
        CertStatus::Missing => ("fail", "missing key or certificate"),
        CertStatus::Covered => ("info", "covered by wildcard"),
    };
    let coverage = match (&c.covered_by, c.wildcard) {
        (Some(by), _) => format!("covered by {by}"),
        (None, true) => "wildcard".to_owned(),
        (None, false) => String::new(),
    };
    CertRow {
        id: c.id.clone(),
        names: c.names.join(", "),
        status: Badge::new(class, text),
        expires: c.not_after.clone().unwrap_or_else(|| "—".to_owned()),
        days_left: c.days_left.map_or("—".to_owned(), |d| d.to_string()),
        coverage: if c.failed {
            format!("{coverage} · last renewal failed")
                .trim_start_matches(" · ")
                .to_owned()
        } else {
            coverage
        },
    }
}

/// Certificates that need attention soon, for the dashboard.
pub fn certs_soon(certs: &CertificatesResponse, within_days: i64) -> Vec<CertRow> {
    by_urgency(certs)
        .into_iter()
        .filter(|c| {
            matches!(
                c.status,
                CertStatus::Missing | CertStatus::Expired | CertStatus::RenewalDue
            ) || c.days_left.is_some_and(|d| d <= within_days)
        })
        .map(cert_row)
        .collect()
}

#[derive(Debug)]
pub struct SiteRow {
    pub name: String,
    pub image: String,
    pub envs: Vec<SiteEnvRow>,
}

#[derive(Debug)]
pub struct SiteEnvRow {
    pub env: String,
    pub instance: String,
    pub follows: String,
    pub domains: String,
    pub current: String,
    pub previous: String,
}

pub fn site_row(site: &SiteSummary) -> SiteRow {
    SiteRow {
        name: site.name.to_string(),
        image: site.image.clone(),
        envs: site
            .envs
            .iter()
            .map(|e| SiteEnvRow {
                env: e.env.to_string(),
                instance: e.instance.to_string(),
                follows: match (&e.track, &e.promote_from) {
                    (Some(tag), _) => format!("tag {tag}"),
                    (None, Some(from)) => format!("promoted from {from}"),
                    (None, None) => "—".to_owned(),
                },
                domains: join_or_dash(&e.domains),
                current: e
                    .current
                    .as_ref()
                    .map_or("not released".to_owned(), |d| short_digest(&d.to_string())),
                previous: e
                    .previous
                    .as_ref()
                    .map_or("—".to_owned(), |d| short_digest(&d.to_string())),
            })
            .collect(),
    }
}

#[derive(Debug)]
pub struct NotifyView {
    pub enabled: bool,
    pub fields: Vec<Field>,
    pub channels: Vec<Field>,
}

pub fn notify_view(status: &NotifyStatusResponse) -> NotifyView {
    let mut fields = vec![
        field("Pending", status.pending.to_string()),
        field("Dropped", status.dropped.to_string()),
    ];
    if let Some(at) = &status.last_delivered_at {
        fields.push(field("Last delivered", at.clone()));
    }
    if let Some(error) = &status.last_error {
        fields.push(field("Last error", error.clone()));
    }
    NotifyView {
        enabled: status.enabled,
        fields,
        channels: status
            .channels
            .iter()
            .map(|c| {
                field(
                    "",
                    format!(
                        "{} · from severity {} · {} pending",
                        c.name,
                        c.min_severity.as_str(),
                        c.pending
                    ),
                )
            })
            .collect(),
    }
}

/// One titled group of settings on the host config page.
#[derive(Debug)]
pub struct ConfigSection {
    pub title: &'static str,
    pub fields: Vec<Field>,
}

pub fn config_sections(config: &ConfigView) -> Vec<ConfigSection> {
    let mut sections = Vec::new();
    let rt = &config.runtime;
    sections.push(ConfigSection {
        title: "Runtime",
        fields: vec![
            field(
                "Reconcile interval",
                format!("{} s", rt.reconcile_interval_secs),
            ),
            field(
                "Privileged host ports",
                yes_no(rt.allow_privileged_host_ports),
            ),
            field(
                "Dependency wait",
                rt.dependency_wait_secs
                    .map_or("default".to_owned(), |s| format!("{s} s")),
            ),
            field(
                "Host mounts",
                join_or_dash(
                    &rt.host_mounts
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>(),
                ),
            ),
            field("Group add", join_or_dash(&rt.group_add)),
            field("Host configs", yes_no(config.host_configs)),
        ],
    });
    let ing = &config.ingress;
    let mut ingress = vec![
        field("Mode", name_of(&ing.mode)),
        field("Bind", ing.bind.to_string()),
        field("nginx image", ing.nginx_image.clone()),
        field("Custom trusted proxies", yes_no(ing.custom_trusted_proxies)),
    ];
    if let Some(https) = ing.https_bind {
        ingress.push(field("HTTPS bind", https.to_string()));
    }
    if let Some(cdn) = &ing.cdn {
        ingress.push(field(
            "CDN",
            format!(
                "{} ({} pinned ranges)",
                name_of(&cdn.provider),
                cdn.pinned_ranges
            ),
        ));
    }
    sections.push(ConfigSection {
        title: "Ingress",
        fields: ingress,
    });
    let admin = match &config.admin.http {
        Some(http) => vec![
            field("Token listener", "enabled"),
            field("Audience", http.audience.clone()),
            field(
                "Clients",
                join_or_dash(
                    &http
                        .clients
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                ),
            ),
            field("Read groups", http.read_groups.to_string()),
            field("Admin groups", http.admin_groups.to_string()),
        ],
        None => vec![field("Token listener", "disabled")],
    };
    sections.push(ConfigSection {
        title: "Admin API",
        fields: admin,
    });
    let mut webhook = vec![field("Domain", config.webhook.domain.clone())];
    if let Some(registry) = &config.webhook.forgejo_registry {
        webhook.push(field("Forgejo registry", registry.clone()));
    }
    sections.push(ConfigSection {
        title: "Webhook",
        fields: webhook,
    });
    sections.push(ConfigSection {
        title: "Platform",
        fields: vec![
            field("Kind", name_of(&config.platform.kind)),
            field("Memory", config.platform.memory.clone()),
            field("PIDs limit", config.platform.pids_limit.to_string()),
        ],
    });
    let m = &config.monitor;
    sections.push(ConfigSection {
        title: "Crash monitor",
        fields: vec![
            field("Crash-loop restarts", m.crash_loop_restarts.to_string()),
            field(
                "Crash-loop window",
                format!("{} s", m.crash_loop_window_secs),
            ),
            field(
                "Unhealthy observations",
                m.unhealthy_observations.to_string(),
            ),
        ],
    });
    if let Some(n) = &config.notify {
        let mut fields = vec![field("Dedup window", format!("{} s", n.dedup_window_secs))];
        if let Some(ntfy) = &n.ntfy {
            fields.push(field(
                "ntfy",
                format!(
                    "from severity {}, {}",
                    ntfy.min_severity.as_str(),
                    if ntfy.authenticated {
                        "authenticated"
                    } else {
                        "anonymous"
                    }
                ),
            ));
        }
        sections.push(ConfigSection {
            title: "Notifications",
            fields,
        });
    }
    if let Some(s) = &config.self_update {
        sections.push(ConfigSection {
            title: "Self-update",
            fields: vec![
                field("Image", s.image.clone()),
                field("Enabled", yes_no(s.enabled)),
                field("Interval", format!("{} s", s.interval_secs)),
                field("Fallback", yes_no(s.fallback)),
                field("Fallback timeout", format!("{} s", s.fallback_timeout_secs)),
                field("Custom public key", yes_no(s.custom_public_key)),
            ],
        });
    }
    if let Some(a) = &config.acme {
        let mut fields = vec![
            field("Enabled", yes_no(a.enabled)),
            field("Directory", a.directory_url.clone()),
            field("Renew before", format!("{} days", a.renew_before_days)),
            field("Check interval", format!("{} s", a.check_interval_secs)),
            field("Contact set", yes_no(a.has_contact)),
        ];
        if let Some(dns) = &a.dns {
            fields.push(field(
                "DNS-01",
                format!(
                    "{} · wildcards: {}",
                    name_of(&dns.provider),
                    join_or_dash(&dns.wildcards)
                ),
            ));
        }
        sections.push(ConfigSection {
            title: "ACME",
            fields,
        });
    }
    if let Some(i) = &config.identity {
        sections.push(ConfigSection {
            title: "Identity provider",
            fields: vec![
                field("Provider", name_of(&i.provider)),
                field("Instance", i.instance.to_string()),
                field("Issuer", i.issuer.clone()),
                field("Custom upstream", yes_no(i.custom_upstream)),
            ],
        });
    }
    sections
}

// ---- resource use ---------------------------------------------------------------------------

/// A value the daemon does not know (the CLI prints the same character).
pub const NONE: &str = "—";

/// One container's resource use, preformatted like `weglarka stats`.
#[derive(Debug)]
pub struct StatsRow {
    pub role: &'static str,
    pub memory: String,
    pub limit: String,
    pub percent: String,
    /// `value`/`max` of the `<meter>`; only when the container has a limit.
    pub meter: Option<(u64, u64)>,
    pub cpu: String,
    pub pids: String,
    pub net_rx: String,
    pub net_tx: String,
    pub block_read: String,
    pub block_write: String,
    pub restarts: u32,
    pub oom_killed: bool,
}

/// The "Resources" fragment: rows, or the reason there are none.
#[derive(Debug)]
pub struct StatsView {
    pub sampled_at: String,
    pub available: bool,
    pub rows: Vec<StatsRow>,
}

fn bytes(v: Option<u64>) -> String {
    v.map_or_else(|| NONE.to_owned(), human_bytes)
}

fn cpu_percent(ratio: Option<f64>) -> String {
    ratio.map_or_else(|| NONE.to_owned(), |r| format!("{:.1}%", r * 100.0))
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

fn stats_role(role: StatsRole) -> &'static str {
    match role {
        StatsRole::Active => "active",
        StatsRole::Challenger => "challenger",
        StatsRole::Retiring => "retiring",
    }
}

fn stats_row(c: &ContainerStatsView) -> StatsRow {
    StatsRow {
        role: stats_role(c.role),
        memory: bytes(c.memory_bytes),
        limit: bytes(c.memory_limit_bytes),
        percent: percent_of_limit(c.memory_bytes, c.memory_limit_bytes),
        meter: match (c.memory_bytes, c.memory_limit_bytes) {
            (Some(used), Some(limit)) if limit > 0 => Some((used.min(limit), limit)),
            _ => None,
        },
        cpu: cpu_percent(c.cpu_ratio),
        pids: c.pids.map_or_else(|| NONE.to_owned(), |p| p.to_string()),
        net_rx: bytes(c.net_rx_bytes),
        net_tx: bytes(c.net_tx_bytes),
        block_read: bytes(c.block_read_bytes),
        block_write: bytes(c.block_write_bytes),
        restarts: c.restarts,
        oom_killed: c.oom_killed,
    }
}

pub fn stats_view(resp: &AppStatsResponse) -> StatsView {
    StatsView {
        sampled_at: resp.sampled_at.clone().unwrap_or_default(),
        available: resp.available,
        rows: resp.containers.iter().map(stats_row).collect(),
    }
}

/// An app's memory and CPU for the apps list: the sum over its containers (two during a
/// blue/green switch); a column is `—` when no container reports it.
#[derive(Debug, Clone)]
pub struct Usage {
    pub memory: String,
    pub cpu: String,
}

pub fn usage_by_app(resp: &StatsResponse) -> std::collections::HashMap<String, Usage> {
    fn sum<T: Copy + std::iter::Sum<T>>(
        rows: &[ContainerStatsView],
        f: impl Fn(&ContainerStatsView) -> Option<T>,
    ) -> Option<T> {
        let mut seen = rows.iter().filter_map(f).peekable();
        seen.peek()?;
        Some(seen.sum())
    }
    resp.apps
        .iter()
        .map(|a| {
            (
                a.app.clone(),
                Usage {
                    memory: bytes(sum(&a.containers, |c| c.memory_bytes)),
                    cpu: cpu_percent(sum(&a.containers, |c| c.cpu_ratio)),
                },
            )
        })
        .collect()
}
