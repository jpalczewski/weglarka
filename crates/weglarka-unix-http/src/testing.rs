//! A mock server on a unix socket for tests of clients built on this crate (feature `testing`).
//! It records what it receives and answers from a closure.

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

/// One request as the mock received it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// Query string without the leading `?` (`None` when the request had none).
    pub query: Option<String>,
    pub host: Option<String>,
    /// All request headers, names lower-cased, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Seen {
    /// The value of the first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Mock {
    pub socket: PathBuf,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

static N: AtomicU32 = AtomicU32::new(0);

/// Starts the mock; `reply(method, path) -> (status, body)`.
pub async fn mock(reply: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static) -> Mock {
    // Short path: the sun_path limit (~104 B on macOS).
    let socket = std::env::temp_dir().join(format!(
        "wgl-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let reply = Arc::new(reply);
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (reply, seen) = (reply.clone(), seen2.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (reply, seen) = (reply.clone(), seen.clone());
                    async move {
                        let method = req.method().to_string();
                        let path = req.uri().path().to_owned();
                        let query = req.uri().query().map(str::to_owned);
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(n, v)| {
                                (
                                    n.as_str().to_owned(),
                                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                                )
                            })
                            .collect();
                        let host = headers
                            .iter()
                            .find(|(n, _)| n == "host")
                            .map(|(_, v)| v.clone());
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        seen.lock().unwrap().push(Seen {
                            method: method.clone(),
                            path: path.clone(),
                            query,
                            host,
                            headers,
                            body: String::from_utf8_lossy(&body).into_owned(),
                        });
                        let (status, body) = reply(&method, &path);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Mock { socket, seen }
}
