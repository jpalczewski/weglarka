//! `instant_acme::HttpClient` over the shared `reqwest` client of `weglarka-http`.
//!
//! The ACME client talks to the CA through this adapter, so TLS (`ring`, bundled roots), timeouts and the
//! no-redirect policy are decided in one place for every outbound HTTP client of the daemon.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use weglarka_http::reqwest::{self, Url};
use weglarka_http::{Purpose, read_capped, transport_allowed};

use crate::error::AcmeError;

/// Upper bound for one ACME response (directory, order, a certificate chain are a few KB).
const MAX_RESPONSE: usize = 1024 * 1024;

pub(crate) struct ReqwestClient(reqwest::Client);

impl ReqwestClient {
    pub(crate) fn new() -> Result<Self, AcmeError> {
        weglarka_http::client(Purpose::Acme)
            .map(Self)
            .map_err(|e| AcmeError::Order(format!("HTTP client: {e}")))
    }
}

fn other(e: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Other(Box::new(e))
}

fn refused(why: &'static str) -> Error {
    Error::Other(why.into())
}

impl HttpClient for ReqwestClient {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let url = Url::parse(&parts.uri.to_string()).map_err(other)?;
            if !transport_allowed(&url) {
                return Err(refused("the ACME server URL is neither https nor loopback"));
            }
            let body = body.collect().await.map_err(other)?.to_bytes();
            let response = client
                .request(parts.method, url)
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|e| Error::Other(weglarka_http::error_chain(&e).into()))?;
            let (status, headers) = (response.status(), response.headers().clone());
            let body = read_capped(response, MAX_RESPONSE).await.map_err(other)?;
            let mut out = http::Response::new(Full::new(Bytes::from(body)));
            *out.status_mut() = status;
            *out.headers_mut() = headers;
            Ok(BytesResponse::from(out))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serves `reply` once on a loopback port and returns the URL plus the request it received.
    async fn serve_once(reply: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/dir", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(reply.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (url, handle)
    }

    fn request(url: &str, body: &[u8]) -> http::Request<BodyWrapper<Bytes>> {
        http::Request::post(url)
            .header("content-type", "application/jose+json")
            .body(BodyWrapper::from(body.to_vec()))
            .unwrap()
    }

    async fn collect(response: BytesResponse) -> (http::StatusCode, http::HeaderMap, Vec<u8>) {
        let BytesResponse { parts, mut body } = response;
        let bytes = body.into_bytes().await.unwrap();
        (parts.status, parts.headers, bytes.to_vec())
    }

    #[tokio::test]
    async fn passes_method_headers_body_and_returns_status_headers_body() {
        let (url, seen) = serve_once(
            "HTTP/1.1 201 Created\r\nreplay-nonce: abc\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        )
        .await;
        let client = ReqwestClient::new().unwrap();
        let (status, headers, body) =
            collect(client.request(request(&url, b"{}")).await.unwrap()).await;
        assert_eq!(status, 201);
        assert_eq!(headers["replay-nonce"], "abc");
        assert_eq!(body, b"ok");
        let sent = seen.await.unwrap().to_lowercase();
        assert!(sent.starts_with("post /dir "), "{sent}");
        assert!(sent.contains("application/jose+json"), "{sent}");
        assert!(sent.ends_with("{}"), "{sent}");
    }

    #[tokio::test]
    async fn a_redirect_is_returned_not_followed() {
        let (url, _seen) = serve_once(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:9/elsewhere\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
        let client = ReqwestClient::new().unwrap();
        let (status, headers, _) =
            collect(client.request(request(&url, b"{}")).await.unwrap()).await;
        assert_eq!(status, 302);
        assert!(headers.contains_key("location"));
    }

    #[tokio::test]
    async fn plain_http_to_a_remote_host_is_refused() {
        let client = ReqwestClient::new().unwrap();
        let result = client
            .request(request("http://ca.example.com/dir", b"{}"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_oversized_response_is_refused() {
        let (url, _seen) =
            serve_once("HTTP/1.1 200 OK\r\ncontent-length: 99999999\r\nconnection: close\r\n\r\n")
                .await;
        let client = ReqwestClient::new().unwrap();
        assert!(client.request(request(&url, b"{}")).await.is_err());
    }
}
