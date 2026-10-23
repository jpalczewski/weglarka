//! Klient admin API: HTTP/1.1 po sockecie unix (hyper, jedno połączenie na żądanie).
//! Ścieżki i metody pochodzą z `weglarka_api::endpoints`, więc nie rozjadą się z kontraktem.

use std::path::PathBuf;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;
use weglarka_api::{ApiError, Endpoint, Method};

use crate::error::{CliError, Kind};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Deploy czeka na pull obrazu i bramkę zdrowia, więc ogólny limit jest długi.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

pub struct ApiClient {
    socket: PathBuf,
}

/// Podstawia `{param}` w ścieżce endpointu. Wartości muszą być już zwalidowane
/// (`InstanceName`, nazwa sekretu) — tu nie ma kodowania procentowego.
pub fn expand_path(endpoint: Endpoint, params: &[(&str, &str)]) -> String {
    let mut path = endpoint.path.to_owned();
    for (key, value) in params {
        path = path.replace(&format!("{{{key}}}"), value);
    }
    path
}

fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
    }
}

impl ApiClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// Wywołanie z ciałem JSON odpowiedzi.
    pub async fn call<Res: DeserializeOwned>(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<Res, CliError> {
        let bytes = self.send(endpoint, params, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| {
            CliError::internal(format!("unexpected response from daemon: {e}"))
                .with_hint("wersja CLI i demona może się różnić — sprawdź `weglarka status`")
        })
    }

    /// Wywołanie bez ciała odpowiedzi (204).
    pub async fn call_empty(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
    ) -> Result<(), CliError> {
        self.send(endpoint, params, None::<&()>).await.map(drop)
    }

    async fn send(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<Vec<u8>, CliError> {
        let payload = match body {
            Some(b) => serde_json::to_vec(b)
                .map_err(|e| CliError::internal(format!("cannot encode request: {e}")))?,
            None => Vec::new(),
        };
        let mut req = Request::builder()
            .method(method_str(endpoint.method))
            .uri(expand_path(endpoint, params))
            .header(HOST, "weglarka");
        if body.is_some() {
            req = req.header(CONTENT_TYPE, "application/json");
        }
        let req = req
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;

        let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| self.unreachable("connection timed out"))?
            .map_err(|e| self.unreachable(&e.to_string()))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| self.unreachable(&e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let exchange = async {
            let resp = sender.send_request(req).await?;
            let status = resp.status();
            let bytes = resp.into_body().collect().await?.to_bytes();
            Ok::<_, hyper::Error>((status, bytes))
        };
        let (status, bytes) = tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| CliError::internal("request to daemon timed out"))?
            .map_err(|e| CliError::internal(format!("request to daemon failed: {e}")))?;

        if status.is_success() {
            Ok(bytes.to_vec())
        } else {
            Err(error_from_response(status, &bytes))
        }
    }

    fn unreachable(&self, cause: &str) -> CliError {
        CliError::new(
            Kind::Unreachable,
            format!("cannot connect to {}: {cause}", self.socket.display()),
        )
        .with_hint(
            "czy demon działa i czy masz prawa do socketu? \
             Ścieżkę zmienisz przez --socket / WEGLARKA_SOCKET; diagnoza bez demona: `weglarka doctor --preflight`",
        )
    }
}

fn error_from_response(status: StatusCode, body: &[u8]) -> CliError {
    match serde_json::from_slice::<ApiError>(body) {
        Ok(e) => CliError::from_api(e.code, e.message),
        Err(_) => CliError::internal(format!(
            "daemon returned HTTP {status} with an unrecognised body"
        ))
        .with_hint("wersja CLI i demona może się różnić"),
    }
}
