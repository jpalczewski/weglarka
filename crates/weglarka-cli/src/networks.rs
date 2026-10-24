//! `weglarka networks list|add|remove` (API: `SHARED_NETWORKS_*`, issue #128,
//! `docs/decisions/0030-shared-networks.md`). A shared network is declared here and joined by apps
//! through `apps add/update --shared-network NAME[:ALIAS,..]` or `shared_networks` in the spec.

use clap::{Args, Subcommand};
use serde::Serialize;
use weglarka_api::{ListSharedNetworksResponse, endpoints};
use weglarka_core::app::SharedNetworkName;

use crate::commands::{DryRun, client};
use crate::error::{CliError, Kind, exit};
use crate::output::{emit, table};
use crate::settings::Overrides;

#[derive(Debug, Subcommand)]
pub enum NetworksCommand {
    /// List the declared shared networks with their members.
    List,
    /// Declare a shared network. Apps join it with `apps add/update --shared-network NAME` or
    /// `shared_networks` in the spec; members reach each other by name on every port.
    Add(NetworkArgs),
    /// Remove a declared shared network. Refused while an app still joins it.
    Remove(NetworkArgs),
}

#[derive(Debug, Args)]
pub struct NetworkArgs {
    /// Shared network name ([a-z0-9-], 1–63 characters).
    pub name: String,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(json: bool, o: &Overrides, cmd: NetworksCommand) -> Result<i32, CliError> {
    match cmd {
        NetworksCommand::List => list(json, o).await,
        NetworksCommand::Add(a) => declare(json, o, a).await,
        NetworksCommand::Remove(a) => remove(json, o, a).await,
    }
}

/// The name is also a URL path segment, so validation is mandatory.
fn network_name(name: &str) -> Result<SharedNetworkName, CliError> {
    SharedNetworkName::new(name).map_err(|e| {
        CliError::usage(e.to_string())
            .with_hint("shared network names: lowercase letters, digits and hyphens, e.g. `kajet`")
    })
}

async fn list(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: ListSharedNetworksResponse = client(o)?
        .call(endpoints::SHARED_NETWORKS_LIST, &[], None::<&()>)
        .await?;
    emit(json, &resp, || networks_table(&resp));
    Ok(exit::OK)
}

/// Table of the declared shared networks; `EXISTS` is `no` until the first member is deployed.
fn networks_table(resp: &ListSharedNetworksResponse) -> String {
    if resp.networks.is_empty() {
        return "no shared networks declared (add one with `weglarka networks add <name>`)\n"
            .to_owned();
    }
    let rows: Vec<Vec<String>> = resp
        .networks
        .iter()
        .map(|n| {
            let members = if n.members.is_empty() {
                "-".to_owned()
            } else {
                n.members
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            vec![
                n.name.to_string(),
                n.podman_name.clone(),
                members,
                if n.exists { "yes" } else { "not yet" }.to_owned(),
            ]
        })
        .collect();
    table(&["NAME", "PODMAN NAME", "MEMBERS", "EXISTS"], &rows)
}

#[derive(Debug, Serialize)]
struct Declared {
    declared: String,
}

async fn declare(json: bool, o: &Overrides, a: NetworkArgs) -> Result<i32, CliError> {
    let name = network_name(&a.name)?;
    let params = [("network", name.as_str())];
    if a.dry_run {
        DryRun::new(endpoints::SHARED_NETWORKS_DECLARE, &params, None).print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty(endpoints::SHARED_NETWORKS_DECLARE, &params)
        .await?;
    let out = Declared {
        declared: name.to_string(),
    };
    emit(json, &out, || {
        format!(
            "declared shared network {name}; join it with `weglarka apps add/update <app> \
             --shared-network {name}` (members reach each other on every port)\n"
        )
    });
    Ok(exit::OK)
}

#[derive(Debug, Serialize)]
struct Removed {
    removed: String,
}

async fn remove(json: bool, o: &Overrides, a: NetworkArgs) -> Result<i32, CliError> {
    let name = network_name(&a.name)?;
    let params = [("network", name.as_str())];
    if a.dry_run {
        DryRun::new(endpoints::SHARED_NETWORKS_REMOVE, &params, None).print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty(endpoints::SHARED_NETWORKS_REMOVE, &params)
        .await
        .map_err(|e| match e.kind {
            Kind::NotFound => e.with_hint("declared shared networks: `weglarka networks list`"),
            Kind::Conflict => e.with_hint(
                "apps still join it: leave first with `weglarka apps update <app> \
                 --shared-network none`",
            ),
            _ => e,
        })?;
    let out = Removed {
        removed: name.to_string(),
    };
    emit(json, &out, || {
        format!("removed shared network {}\n", out.removed)
    });
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_api::SharedNetworkSummary;
    use weglarka_core::app::InstanceName;

    #[test]
    fn table_renders_members_and_existence() {
        let resp = ListSharedNetworksResponse {
            networks: vec![
                SharedNetworkSummary {
                    name: SharedNetworkName::new("kajet").unwrap(),
                    podman_name: "net-shared-kajet".into(),
                    members: vec![
                        InstanceName::new("kajet-api").unwrap(),
                        InstanceName::new("kajet-proxy").unwrap(),
                    ],
                    exists: true,
                },
                SharedNetworkSummary {
                    name: SharedNetworkName::new("future").unwrap(),
                    podman_name: "net-shared-future".into(),
                    members: vec![],
                    exists: false,
                },
            ],
        };
        let t = networks_table(&resp);
        assert!(t.contains("kajet-api, kajet-proxy"), "{t}");
        assert!(t.contains("net-shared-kajet"), "{t}");
        let future = t.lines().find(|l| l.contains("future")).unwrap();
        assert!(future.contains("not yet"), "{future}");
        assert!(
            networks_table(&ListSharedNetworksResponse::default())
                .contains("no shared networks declared")
        );
    }

    #[test]
    fn invalid_names_are_usage_errors() {
        assert!(network_name("Kajet_Net").is_err());
        assert!(network_name("kajet").is_ok());
    }
}
