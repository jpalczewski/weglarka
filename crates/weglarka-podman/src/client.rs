//! `LibpodClient` — implementacja `PodmanClient` na libpod API v6.

use std::path::PathBuf;

use futures_core::Stream;
use futures_util::stream;
use hyper::Method;
use weglarka_core::podman::{
    ContainerFilter, ContainerInfo, ContainerSpec, EventFilter, HealthStatus, ImageInfo,
    NetworkInfo, NetworkSpec, PodmanClient, PodmanError, PodmanEvent, PullEvent, Result,
    VersionInfo,
};

use crate::transport::{Lines, Transport, encode_component, name_conflict, path_name};
use crate::wire::{
    ConnectNetwork, CreateContainer, CreateNetwork, CreatedContainer, HealthReport,
    InspectContainer, InspectImage, InspectNetwork, ListedContainer, PullLine, PullReport, Version,
    WireEvent, decode, health_status,
};

/// Klient libpod po unix sockecie. Tani w klonowaniu (współdzieli tylko ścieżkę socketu);
/// nie łączy się przy tworzeniu — brak socketu wychodzi jako `PodmanError::Unreachable`
/// przy pierwszym wywołaniu (np. [`PodmanClient::version`]).
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
        // Lista nie niesie stanu zdrowia ani kodu wyjścia w stabilnej postaci — dociągamy inspectem.
        let mut containers = Vec::with_capacity(listed.len());
        for entry in listed {
            match self.inspect_container(&entry.id).await {
                Ok(info) => containers.push(info),
                // Usunięty między listą a inspectem.
                Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(containers)
    }

    fn image_pull(&self, reference: &str) -> impl Stream<Item = Result<PullEvent>> + Send {
        let state = PullState {
            client: self.clone(),
            reference: reference.to_owned(),
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
            // Idempotentne — kontrakt traitu.
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

    async fn network_inspect(&self, name: &str) -> Result<NetworkInfo> {
        let path = format!("/networks/{}/json", path_name(name)?);
        let body = self.transport.call(Method::GET, &path, None).await?;
        Ok(decode::<InspectNetwork>(&body)?.into_domain())
    }

    async fn secret_create(&self, name: &str, data: &[u8]) -> Result<()> {
        // Dane sekretu idą wyłącznie w ciele żądania i nigdy do logów/błędów.
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
    lines: Option<Lines>,
    image_id: Option<String>,
    finished: bool,
}

impl PullState {
    /// Następny element strumienia; `None` kończy strumień. Każdy błąd jest ostatnim elementem.
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
            self.lines = Some(self.client.transport.lines(Method::POST, &path).await?);
        }
        let lines = self.lines.as_mut().expect("opened above");
        loop {
            let Some(line) = lines.next_line().await? else {
                // Koniec strumienia: bez ID obrazu pull się nie udał (a nie zgłosił błędu).
                let image_id = self.image_id.take().ok_or_else(|| {
                    PodmanError::Protocol("pull stream ended without an image id".into())
                })?;
                // Digest preferowany dla repozytorium z `reference`; obraz mógł dostać inną nazwę
                // (np. pull po digeście), wtedy pytamy po ID.
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
            self.lines = Some(self.transport.lines(Method::GET, &self.path).await?);
        }
        let lines = self.lines.as_mut().expect("opened above");
        match lines.next_line().await? {
            Some(line) => Ok(Some(decode::<WireEvent>(&line)?.into_domain())),
            // Strumień zdarzeń nie powinien się kończyć — dla wywołującego to utrata połączenia.
            None => Err(PodmanError::Unreachable("event stream closed".into())),
        }
    }
}
