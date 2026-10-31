//! The metrics scraper's network membership (issue #365, design on #36).
//!
//! `[metrics] scraper` in `weglarka.toml` names one managed app (Prometheus, say). Its container is
//! kept on the daemon's metrics network (`[metrics] network`) and on the per-app `metrics-<app>`
//! network of every opted-in app, with live `network_connect`/`network_disconnect`: opting an app
//! in never restarts the scraper. The role is host policy, never an `AppSpec` field, so an app cannot
//! grant it to itself (like `[admin.http] clients`).
//!
//! The engine owns the membership of **managed app containers** (labelled `weglarka.instance`) on
//! those networks: an app's own containers stay on its own `metrics-<app>`, the scraper's containers
//! stay on the networks it should be on, and any other managed container is disconnected. That is
//! what makes removing or moving the role take effect, and what lets an opted-out app's network go
//! in the same pass. Containers the engine does not manage (no instance label, such as a hand-run
//! `podman run --network metrics …`) are never touched, and one-off `weglarka run`/`forward`
//! containers carry no instance label, so they never join.

use std::collections::BTreeSet;

use weglarka_model::app::{AppsFile, InstanceName};
use weglarka_model::labels;
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ContainerState, NetworkSummary, PodmanClient, PodmanError,
};
use weglarka_model::state;

use crate::reconcile::Reconciler;

/// `[metrics] scraper` with the network the daemon's listener is on (`[metrics] network`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsScraper {
    pub instance: InstanceName,
    /// The daemon's metrics network, `[metrics] network`.
    pub network: String,
}

/// One live membership change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MembershipChange {
    Connect { network: String, container: String },
    Disconnect { network: String, container: String },
}

/// Whether `net` is one of the metrics networks the engine manages membership on: a per-app network
/// (labelled [`labels::METRICS_FOR`]) or the daemon's own (labelled [`labels::MANAGED_METRICS`]).
fn is_metrics_network(net: &NetworkSummary) -> bool {
    net.labels.contains_key(labels::METRICS_FOR)
        || net.labels.get(labels::MANAGED).map(String::as_str) == Some(labels::MANAGED_METRICS)
}

/// The existing networks the scraper should be on: the configured daemon network and the
/// `metrics-<app>` network of every app that sets `metrics_port`. A network that does not exist yet
/// is not listed (the next pass picks it up once it does). The scraper's **own** metrics network, if
/// it is opted in itself, is left out: it is on that one as its owner, which deploy handles.
pub fn wanted_networks(
    scraper: &MetricsScraper,
    apps: &AppsFile,
    networks: &[NetworkSummary],
) -> Vec<String> {
    let mut out = Vec::new();
    for net in networks {
        if let Some(owner) = net.labels.get(labels::METRICS_FOR) {
            let wanted = owner.as_str() != scraper.instance.as_str()
                && InstanceName::new(owner.as_str())
                    .ok()
                    .and_then(|o| apps.apps.get(&o))
                    .is_some_and(|spec| spec.metrics_port.is_some());
            if wanted {
                out.push(net.name.clone());
            }
        } else if net.name == scraper.network {
            out.push(net.name.clone());
        }
    }
    out
}

/// Pure plan of the membership changes that bring the metrics networks to the state described in the
/// module docs. `containers` is a full container list (with networks); `scraper = None` only removes.
pub fn plan_membership(
    scraper: Option<&MetricsScraper>,
    apps: &AppsFile,
    networks: &[NetworkSummary],
    containers: &[ContainerInfo],
) -> Vec<MembershipChange> {
    let wanted: BTreeSet<String> = scraper
        .map(|s| wanted_networks(s, apps, networks).into_iter().collect())
        .unwrap_or_default();
    let is_scraper = |c: &ContainerInfo| {
        scraper.is_some_and(|s| {
            c.labels.get(labels::INSTANCE).map(String::as_str) == Some(s.instance.as_str())
        })
    };
    let mut changes = Vec::new();
    for c in containers {
        let Some(instance) = c.labels.get(labels::INSTANCE) else {
            continue; // not a managed app container: never ours to move
        };
        for net in networks.iter().filter(|n| is_metrics_network(n)) {
            if !c.networks.contains(&net.name) {
                continue;
            }
            let owner = net.labels.get(labels::METRICS_FOR) == Some(instance);
            let as_scraper = is_scraper(c) && wanted.contains(&net.name);
            if !owner && !as_scraper {
                changes.push(MembershipChange::Disconnect {
                    network: net.name.clone(),
                    container: c.name.clone(),
                });
            }
        }
        // A stopped container is left alone: it joins when it is recreated or started and the next
        // pass sees it running.
        if is_scraper(c) && c.state == ContainerState::Running {
            for net in &wanted {
                if !c.networks.contains(net) {
                    changes.push(MembershipChange::Connect {
                        network: net.clone(),
                        container: c.name.clone(),
                    });
                }
            }
        }
    }
    changes.sort();
    changes
}

impl<P: PodmanClient> Reconciler<P> {
    fn metrics_scraper(&self) -> Option<&MetricsScraper> {
        self.options.metrics_scraper.as_ref()
    }

    /// The networks a new container of `instance` is created on because it is the scraper (none for
    /// any other instance), so a recreated scraper — and a blue-green challenger of it, which only
    /// reads — is on its networks from its first second. Best effort: an error yields fewer networks
    /// and the reconcile pass connects the rest live.
    pub(crate) async fn scraper_networks(&self, instance: &InstanceName) -> Vec<String> {
        let Some(scraper) = self.metrics_scraper().filter(|s| &s.instance == instance) else {
            return Vec::new();
        };
        let Ok(apps) = state::load_apps(&self.paths.apps) else {
            return Vec::new();
        };
        match self.podman.network_list().await {
            Ok(networks) => wanted_networks(scraper, &apps, &networks),
            Err(e) => {
                tracing::debug!(error = %e, "cannot list networks for the scraper's container");
                Vec::new()
            }
        }
    }

    /// Connects the running scraper to a metrics network that was just created (an app opted in), so
    /// it can scrape the app without waiting for the next reconcile pass. Best effort: the pass
    /// converges anyway.
    pub(crate) async fn join_scraper(&self, owner: &InstanceName, network: &str) {
        let Some(scraper) = self.metrics_scraper().filter(|s| &s.instance != owner) else {
            return;
        };
        let name = labels::container_name(&scraper.instance);
        let Ok(info) = self.podman.container_inspect(&name).await else {
            return;
        };
        if info.state != ContainerState::Running || info.networks.iter().any(|n| n == network) {
            return;
        }
        self.apply_membership(MembershipChange::Connect {
            network: network.to_owned(),
            container: name,
        })
        .await;
    }

    /// Brings the scraper's membership to the plan ([`plan_membership`]). Called by `prune_networks`
    /// before it removes networks, so a scraper still attached to an opted-out app's network is
    /// detached first and the network goes in the same pass. Costs one container list, and only when
    /// a metrics network exists at all.
    pub(crate) async fn sync_metrics_networks(&self, apps: &AppsFile, networks: &[NetworkSummary]) {
        if !networks.iter().any(is_metrics_network) {
            return;
        }
        let containers = match self
            .podman
            .container_list(&ContainerFilter::default())
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "cannot list containers; skipping scraper networks");
                return;
            }
        };
        for change in plan_membership(self.metrics_scraper(), apps, networks, &containers) {
            self.apply_membership(change).await;
        }
    }

    async fn apply_membership(&self, change: MembershipChange) {
        match &change {
            MembershipChange::Connect { network, container } => {
                match self.podman.network_connect(network, container).await {
                    // Already connected (a concurrent join): the goal is reached.
                    Ok(()) | Err(PodmanError::Conflict(_)) => {
                        tracing::info!(%network, %container, "metrics scraper joined network");
                    }
                    Err(e) => {
                        tracing::debug!(%network, %container, error = %e, "scraper not joined yet");
                    }
                }
            }
            MembershipChange::Disconnect { network, container } => {
                match self.podman.network_disconnect(network, container).await {
                    Ok(()) | Err(PodmanError::NotFound(_)) => {
                        tracing::info!(%network, %container, "detached from metrics network");
                    }
                    Err(e) => {
                        tracing::debug!(%network, %container, error = %e, "not detached yet");
                    }
                }
            }
        }
    }
}
