//! A mock server on a unix socket for tests of clients built on this crate (feature `testing`).
//! It records what it receives and answers from a closure.

use std::convert::Infallible;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
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
    /// The body, lossily decoded as UTF-8.
    pub body: String,
    /// The body exactly as received (uploads).
    pub raw_body: Vec<u8>,
}

impl Seen {
    /// The value of the first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The request target: `path`, plus `?query` when there is one.
    pub fn uri(&self) -> String {
        match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        }
    }
}

/// What the mock answers. The body goes out as separate frames, one per chunk.
#[derive(Debug, Clone)]
pub struct Reply {
    status: u16,
    content_type: Option<String>,
    chunks: Vec<Bytes>,
    head_delay: Option<Duration>,
    fail_body: bool,
    hold: bool,
}

impl Reply {
    pub fn new(status: u16, body: impl Into<Bytes>) -> Self {
        Self::chunks(status, [body.into()])
    }

    pub fn chunks(status: u16, chunks: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            status,
            content_type: None,
            chunks: chunks.into_iter().collect(),
            head_delay: None,
            fail_body: false,
            hold: false,
        }
    }

    pub fn content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(content_type.to_owned());
        self
    }

    /// Waits this long before answering (a server that accepts but stalls).
    pub fn head_delay(mut self, delay: Duration) -> Self {
        self.head_delay = Some(delay);
        self
    }

    /// Keeps the response open after the chunks (a stream that has nothing more to say yet). It is
    /// counted in [`Mock::held`] until the client drops the connection.
    pub fn hold_open(mut self) -> Self {
        self.hold = true;
        self
    }

    /// Breaks the connection after the chunks, mid-body (the head has already been sent).
    pub fn fail_body(mut self) -> Self {
        self.fail_body = true;
        self
    }
}

pub struct Mock {
    pub socket: PathBuf,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    /// Responses made with [`Reply::hold_open`] that the client has not dropped yet.
    pub held: Arc<AtomicU32>,
}

/// The socket path, so a `Mock` can be passed where a `&Path` is wanted.
impl Deref for Mock {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.socket
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

static N: AtomicU32 = AtomicU32::new(0);

/// Starts the mock; `reply(method, path) -> (status, body)`.
pub async fn mock(reply: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static) -> Mock {
    mock_with(move |method, path| {
        let (status, body) = reply(method, path);
        Reply::new(status, body)
    })
    .await
}

/// [`mock`] with full control of the answer (content type, chunked or stalled or broken body).
pub async fn mock_with(reply: impl Fn(&str, &str) -> Reply + Send + Sync + 'static) -> Mock {
    mock_seen(move |seen| reply(&seen.method, &seen.path)).await
}

/// [`mock_with`] with the whole request to decide on (headers, query), not just method and path.
pub async fn mock_seen(reply: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Mock {
    // Short path: the sun_path limit (~104 B on macOS).
    let socket = std::env::temp_dir().join(format!(
        "wgl-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let held = Arc::new(AtomicU32::new(0));
    let reply = Arc::new(reply);
    let seen2 = seen.clone();
    let held2 = held.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (reply, seen, held) = (reply.clone(), seen2.clone(), held2.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (reply, seen, held) = (reply.clone(), seen.clone(), held.clone());
                    async move { Ok::<_, Infallible>(answer(req, &*reply, &seen, &held).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Mock { socket, seen, held }
}

type Body = StreamBody<
    std::pin::Pin<Box<dyn futures_util::Stream<Item = std::io::Result<Frame<Bytes>>> + Send>>,
>;

async fn answer(
    req: Request<Incoming>,
    reply: &(impl Fn(&Seen) -> Reply + ?Sized),
    seen: &Mutex<Vec<Seen>>,
    held: &Arc<AtomicU32>,
) -> Response<Body> {
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
    let this = Seen {
        method: method.clone(),
        path: path.clone(),
        query,
        host,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
        raw_body: body.to_vec(),
    };
    let reply = reply(&this);
    seen.lock().unwrap().push(this);
    if let Some(delay) = reply.head_delay {
        tokio::time::sleep(delay).await;
    }
    use futures_util::StreamExt;
    let mut frames = futures_util::stream::iter(
        reply
            .chunks
            .into_iter()
            .map(|c| Ok(Frame::data(c)))
            .collect::<Vec<_>>(),
    )
    .boxed();
    if reply.fail_body {
        // Later than the head, so the client has the head before the break.
        let broken = futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Err(std::io::Error::other("mock: body broken"))
        });
        frames = frames.chain(broken).boxed();
    }
    if reply.hold {
        // Counted from now until the client drops the connection (and with it this stream).
        held.fetch_add(1, Ordering::SeqCst);
        let guard = HeldGuard(held.clone());
        frames = frames
            .chain(futures_util::stream::pending())
            .map(move |frame| {
                let _keep = &guard;
                frame
            })
            .boxed();
    }
    let mut resp = Response::builder().status(reply.status);
    if let Some(ct) = reply.content_type {
        resp = resp.header("content-type", ct);
    }
    resp.body(StreamBody::new(frames)).unwrap()
}

struct HeldGuard(Arc<AtomicU32>);

impl Drop for HeldGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
