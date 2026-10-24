//! `LibpodClient` — `PodmanClient` implementation on the libpod API v6.

use std::path::PathBuf;

use futures_core::Stream;
use futures_util::stream;
use hyper::Method;
use weglarka_core::podman::{
    ContainerFilter, ContainerInfo, ContainerSpec, EventFilter, HealthStatus, ImageInfo,
    NetworkInfo, NetworkSpec, NetworkSummary, PodmanClient, PodmanError, PodmanEvent, PullEvent,
    RegistryAuth, Result, TarStream, VersionInfo, VolumeFilter, VolumeInfo, VolumeSpec,
};

use crate::registry_auth;
use crate::transport::{Lines, Transport, encode_component, name_conflict, path_name};
use crate::wire::{
    ConnectNetwork, CreateContainer, CreateExec, CreateNetwork, CreateVolume, CreatedContainer,
    CreatedExec, DisconnectNetwork, HealthReport, Info, InspectContainer, InspectExec,
    InspectImage, InspectNetwork, ListedContainer, ListedImage, ListedNetwork, NetworkRmReport,
    PullLine, PullReport, StartExec, Version, WireEvent, WireVolume, decode, health_status,
};

/// libpod client over a unix socket. Cheap to clone (shares only the socket path);
/// it does not connect on creation — a missing socket surfaces as `PodmanError::Unreachable`
/// on the first call (e.g. [`PodmanClient::version`]).
/// Exec polling: up to `EXEC_POLLS * EXEC_POLL_INTERVAL` (30 s).
const EXEC_POLLS: u32 = 600;
const EXEC_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct LibpodClient {
    transport: Transport,
}

impl LibpodClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            transport: Transport::new(socket),
        }
    }

    async fn inspect_container(&self, name: &str) -> Result<ContainerInfo> {
        let path = format!("/containers/{}/json", path_name(name)?);
        let body = self.transport.call(Method::GET, &path, None).await?;
        Ok(decode::<InspectContainer>(&body)?.into_domain())
    }
}

fn label_filters(labels: &std::collections::BTreeMap<String, String>) -> Option<String> {
    if labels.is_empty() {
        return None;
    }
    let label: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
    Some(encode_component(
        &serde_json::json!({ "label": label }).to_string(),
    ))
}

impl PodmanClient for LibpodClient {
    async fn version(&self) -> Result<VersionInfo> {
        let body = self.transport.call(Method::GET, "/version", None).await?;
        Ok(decode::<Version>(&body)?.into_domain())
    }

    async fn subuid_pool(&self) -> Result<u64> {
        let body = self.transport.call(Method::GET, "/info", None).await?;
        Ok(decode::<Info>(&body)?.subuid_pool())
    }

    async fn container_create(&self, spec: &ContainerSpec) -> Result<String> {
        let body = self
            .transport
            .call_json(
                Method::POST,
                "/containers/create",
                &CreateContainer::new(spec),
            )
            .await
            .map_err(name_conflict)?;
        Ok(decode::<CreatedContainer>(&body)?.id)
    }

    async fn container_start(&self, name: &str) -> Result<()> {
        let path = format!("/containers/{}/start", path_name(name)?);
        self.transport.call(Method::POST, &path, None).await?;
        Ok(())
    }

    async fn container_stop(&self, name: &str, timeout_secs: u32) -> Result<()> {
        let path = format!(
            "/containers/{}/stop?timeout={timeout_secs}",
            path_name(name)?
        );
        self.transport.call(Method::POST, &path, None).await?;
        Ok(())
    }

    async fn container_remove(&self, name: &str, force: bool) -> Result<()> {
        let path = format!("/containers/{}?force={force}", path_name(name)?);
        self.transport.call(Method::DELETE, &path, None).await?;
        Ok(())
    }

    async fn container_kill(&self, name: &str, signal: &str) -> Result<()> {
        let path = format!(
            "/containers/{}/kill?signal={}",
            path_name(name)?,
            encode_component(signal)
        );
        self.transport.call(Method::POST, &path, None).await?;
        Ok(())
    }

    async fn container_exec(&self, name: &str, cmd: &[String]) -> Result<i32> {
        let path = format!("/containers/{}/exec", path_name(name)?);
        let body = self
            .transport
            .call_json(Method::POST, &path, &CreateExec { cmd })
            .await?;
        let id = decode::<CreatedExec>(&body)?.id;
        let id = path_name(&id)?;
        // Detached start + polling: avoids parsing the hijacked multiplexed stream; output is not needed.
        self.transport
            .call_json(
                Method::POST,
                &format!("/exec/{id}/start"),
                &StartExec { detach: true },
            )
            .await?;
        for _ in 0..EXEC_POLLS {
            let body = self
                .transport
                .call(Method::GET, &format!("/exec/{id}/json"), None)
                .await?;
            let exec = decode::<InspectExec>(&body)?;
            if !exec.running {
                return Ok(exec.exit_code);
            }
            tokio::time::sleep(EXEC_POLL_INTERVAL).await;
        }
        Err(PodmanError::Protocol(format!(
            "exec in {name} did not finish in time"
        )))
    }

    async fn container_archive_put(&self, name: &str, path: &str, tar: TarStream) -> Result<()> {
        let path = format!(
            "/containers/{}/archive?path={}",
            path_name(name)?,
            encode_component(path)
        );
        self.transport
            .call_streaming_body(Method::PUT, &path, "application/x-tar", tar)
            .await?;
        Ok(())
    }

    async fn container_inspect(&self, name: &str) -> Result<ContainerInfo> {
        self.inspect_container(name).await
    }

    async fn container_list(&self, filter: &ContainerFilter) -> Result<Vec<ContainerInfo>> {
        let mut path = String::from("/containers/json?all=true");
        if let Some(filters) = label_filters(&filter.labels) {
            path.push_str("&filters=");
            path.push_str(&filters);
        }
        let body = self.transport.call(Method::GET, &path, None).await?;
        let listed: Vec<ListedContainer> = decode(&body)?;
        // The list carries neither health state nor exit code in a stable form — we fetch them via inspect.
        let mut containers = Vec::with_capacity(listed.len());
        for entry in listed {
            match self.inspect_container(&entry.id).await {
                Ok(info) => containers.push(info),
                // Removed between the list and the inspect.
                Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(containers)
    }

    fn image_pull_with(
        &self,
        reference: &str,
        auth: Option<&RegistryAuth>,
    ) -> impl Stream<Item = Result<PullEvent>> + Send {
        let state = PullState {
            client: self.clone(),
            reference: reference.to_owned(),
            auth: auth.cloned(),
            lines: None,
            image_id: None,
            finished: false,
        };
        stream::unfold(state, |mut state| async move {
            let item = state.step().await?;
            Some((item, state))
        })
    }

    async fn image_inspect(&self, reference: &str) -> Result<ImageInfo> {
        let path = format!("/images/{}/json", path_name(reference)?);
        let body = self.transport.call(Method::GET, &path, None).await?;
        Ok(decode::<InspectImage>(&body)?.into_domain(reference))
    }

    async fn image_list(&self) -> Result<Vec<ImageInfo>> {
        // No `all=true`: intermediate layers are not ours to reason about (docs/decisions/0020).
        let body = self
            .transport
            .call(Method::GET, "/images/json", None)
            .await?;
        Ok(decode::<Vec<ListedImage>>(&body)?
            .into_iter()
            .map(ListedImage::into_domain)
            .collect())
    }

    async fn image_tag(&self, id: &str, repo: &str, tag: &str) -> Result<()> {
        let path = format!(
            "/images/{}/tag?repo={}&tag={}",
            path_name(id)?,
            encode_component(repo),
            encode_component(tag)
        );
        self.transport.call(Method::POST, &path, None).await?;
        Ok(())
    }

    async fn image_remove(&self, reference: &str) -> Result<()> {
        let path = format!("/images/{}", path_name(reference)?);
        self.transport.call(Method::DELETE, &path, None).await?;
        Ok(())
    }

    async fn network_create(&self, spec: &NetworkSpec) -> Result<()> {
        match self
            .transport
            .call_json(Method::POST, "/networks/create", &CreateNetwork::new(spec))
            .await
            .map_err(name_conflict)
        {
            // Idempotent — the trait contract.
            Ok(_) | Err(PodmanError::Conflict(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn network_connect(&self, network: &str, container: &str) -> Result<()> {
        let path = format!("/networks/{}/connect", path_name(network)?);
        self.transport
            .call_json(Method::POST, &path, &ConnectNetwork { container })
            .await?;
        Ok(())
    }

    async fn network_disconnect(&self, network: &str, container: &str) -> Result<()> {
        let path = format!("/networks/{}/disconnect", path_name(network)?);
        let result = self
            .transport
            .call_json(
                Method::POST,
                &path,
                &DisconnectNetwork {
                    container,
                    force: false,
                },
            )
            .await;
        match result {
            Ok(_) => Ok(()),
            // Not attached (libpod answers 500 "is not connected to network") — idempotent.
            Err(PodmanError::Api { message, .. }) if message.contains("not connected") => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn network_inspect(&self, name: &str) -> Result<NetworkInfo> {
        let path = format!("/networks/{}/json", path_name(name)?);
        let body = self.transport.call(Method::GET, &path, None).await?;
        Ok(decode::<InspectNetwork>(&body)?.into_domain())
    }

    async fn network_list(&self) -> Result<Vec<NetworkSummary>> {
        let body = self
            .transport
            .call(Method::GET, "/networks/json", None)
            .await?;
        Ok(decode::<Vec<ListedNetwork>>(&body)?
            .into_iter()
            .map(ListedNetwork::into_domain)
            .collect())
    }

    async fn network_remove(&self, name: &str) -> Result<()> {
        let path = format!("/networks/{}", path_name(name)?);
        match self.transport.call(Method::DELETE, &path, None).await {
            // libpod may report a failure inside a 200 body.
            Ok(body) => match decode::<Vec<NetworkRmReport>>(&body)
                .unwrap_or_default()
                .into_iter()
                .find_map(|r| r.err.filter(|e| !e.is_empty()))
            {
                None => Ok(()),
                Some(message) => Err(PodmanError::Api {
                    status: 200,
                    message,
                }),
            },
            Err(PodmanError::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn secret_create(&self, name: &str, data: &[u8]) -> Result<()> {
        // Secret data goes only into the request body and never into logs/errors.
        let path = format!(
            "/secrets/create?name={}&driver=file&replace=true",
            encode_component(name)
        );
        let body = Some(("application/octet-stream", data.to_vec().into()));
        self.transport.call(Method::POST, &path, body).await?;
        Ok(())
    }

    async fn secret_remove(&self, name: &str) -> Result<()> {
        let path = format!("/secrets/{}", path_name(name)?);
        self.transport.call(Method::DELETE, &path, None).await?;
        Ok(())
    }

    async fn volume_create(&self, spec: &VolumeSpec) -> Result<()> {
        match self
            .transport
            .call_json(Method::POST, "/volumes/create", &CreateVolume::new(spec))
            .await
            .map_err(name_conflict)
        {
            // Idempotent — the trait contract.
            Ok(_) | Err(PodmanError::Conflict(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn volume_inspect(&self, name: &str) -> Result<VolumeInfo> {
        let path = format!("/volumes/{}/json", path_name(name)?);
        let body = self.transport.call(Method::GET, &path, None).await?;
        Ok(decode::<WireVolume>(&body)?.into_domain())
    }

    async fn volume_list(&self, filter: &VolumeFilter) -> Result<Vec<VolumeInfo>> {
        let mut path = String::from("/volumes/json");
        if let Some(filters) = label_filters(&filter.labels) {
            path.push_str("?filters=");
            path.push_str(&filters);
        }
        let body = self.transport.call(Method::GET, &path, None).await?;
        let volumes: Vec<WireVolume> = decode(&body)?;
        Ok(volumes.into_iter().map(WireVolume::into_domain).collect())
    }

    async fn volume_import(&self, name: &str, tar: TarStream) -> Result<()> {
        let path = format!("/volumes/{}/import", path_name(name)?);
        self.transport
            .call_streaming_body(Method::POST, &path, "application/x-tar", tar)
            .await?;
        Ok(())
    }

    async fn volume_export(&self, name: &str) -> Result<TarStream> {
        let path = format!("/volumes/{}/export", path_name(name)?);
        self.transport.bytes_stream(Method::GET, &path).await
    }

    async fn volume_remove(&self, name: &str, force: bool) -> Result<()> {
        let path = format!("/volumes/{}?force={force}", path_name(name)?);
        self.transport.call(Method::DELETE, &path, None).await?;
        Ok(())
    }

    async fn healthcheck_run(&self, container: &str) -> Result<HealthStatus> {
        let path = format!("/containers/{}/healthcheck", path_name(container)?);
        let body = self.transport.call(Method::GET, &path, None).await?;
        let report: HealthReport = decode(&body)?;
        health_status(&report.status).ok_or_else(|| {
            PodmanError::Protocol(format!("unknown health status {:?}", report.status))
        })
    }

    fn events(&self, filter: &EventFilter) -> impl Stream<Item = Result<PodmanEvent>> + Send {
        let mut path = String::from("/events?stream=true");
        if let Some(filters) = label_filters(&filter.labels) {
            path.push_str("&filters=");
            path.push_str(&filters);
        }
        if let Some(since) = filter.since {
            path.push_str(&format!("&since={since}"));
        }
        let state = EventsState {
            transport: self.transport.clone(),
            path,
            lines: None,
            finished: false,
        };
        stream::unfold(state, |mut state| async move {
            let item = state.step().await?;
            Some((item, state))
        })
    }
}

struct PullState {
    client: LibpodClient,
    reference: String,
    /// Sent as `X-Registry-Auth`; never logged (`RegistryAuth`'s `Debug` redacts the password).
    auth: Option<RegistryAuth>,
    lines: Option<Lines>,
    image_id: Option<String>,
    finished: bool,
}

impl PullState {
    /// Next stream item; `None` ends the stream. Every error is the last item.
    async fn step(&mut self) -> Option<Result<PullEvent>> {
        if self.finished {
            return None;
        }
        let item = self.next_event().await;
        if !matches!(item, Ok(Some(PullEvent::Progress { .. }))) {
            self.finished = true;
        }
        item.transpose()
    }

    async fn next_event(&mut self) -> Result<Option<PullEvent>> {
        if self.lines.is_none() {
            let path = format!(
                "/images/pull?reference={}",
                encode_component(&self.reference)
            );
            let header = self
                .auth
                .as_ref()
                .map(|auth| registry_auth::header(&self.reference, auth))
                .transpose()?;
            self.lines = Some(
                self.client
                    .transport
                    .lines(Method::POST, &path, header)
                    .await?,
            );
        }
        let lines = self.lines.as_mut().expect("opened above");
        loop {
            let Some(line) = lines.next_line().await? else {
                // End of stream: without an image ID the pull failed (rather than reporting an error).
                let image_id = self.image_id.take().ok_or_else(|| {
                    PodmanError::Protocol("pull stream ended without an image id".into())
                })?;
                // Prefer the digest for the repository from `reference`; the image may have got another name
                // (e.g. a pull by digest), in which case we query by ID.
                let digest = match self.client.image_inspect(&self.reference).await {
                    Ok(image) => image.digest,
                    Err(PodmanError::NotFound(_)) => {
                        self.client.image_inspect(&image_id).await?.digest
                    }
                    Err(e) => return Err(e),
                };
                return Ok(Some(PullEvent::Complete { image_id, digest }));
            };
            match decode::<PullReport>(&line)?.classify()? {
                PullLine::Progress(event) => return Ok(Some(event)),
                PullLine::Image(id) => self.image_id = Some(id),
                PullLine::Nothing => {}
            }
        }
    }
}

struct EventsState {
    transport: Transport,
    path: String,
    lines: Option<Lines>,
    finished: bool,
}

impl EventsState {
    async fn step(&mut self) -> Option<Result<PodmanEvent>> {
        if self.finished {
            return None;
        }
        let item = self.next_event().await;
        if item.is_err() {
            self.finished = true;
        }
        item.transpose()
    }

    async fn next_event(&mut self) -> Result<Option<PodmanEvent>> {
        if self.lines.is_none() {
            self.lines = Some(self.transport.lines(Method::GET, &self.path, None).await?);
        }
        let lines = self.lines.as_mut().expect("opened above");
        match lines.next_line().await? {
            Some(line) => Ok(Some(decode::<WireEvent>(&line)?.into_domain())),
            // The event stream should never end — for the caller that means a lost connection.
            None => Err(PodmanError::Unreachable("event stream closed".into())),
        }
    }
}
