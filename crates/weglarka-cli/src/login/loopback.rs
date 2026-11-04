//! The RFC 8252 loopback listener of `weglarka login --browser` (docs/decisions/0068).
//!
//! Any local process can reach the port, so the listener trusts nothing in a request until `state`
//! matches (256 random bits): until then it answers, notes on stderr and keeps waiting. Only the
//! 5-minute timeout ends a wait without a matching callback; counting bad attempts would let a
//! local process abort the login.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use weglarka_oidc::Url;

/// How long the person has to finish in the browser.
pub(super) const WAIT: Duration = Duration::from_secs(5 * 60);
/// The path registered (without the port) as the client's `redirect_uris` entry.
const CALLBACK_PATH: &str = "/callback";
/// Time given to the connection of the accepted callback to flush the "you can close this tab" page.
const FLUSH_GRACE: Duration = Duration::from_secs(1);

/// Pause after a failed `accept` (e.g. fd exhaustion), so a persistent error cannot spin the CPU.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

const DONE_PAGE: &str = "<!doctype html><meta charset=utf-8><title>weglarka</title>\
<p>You can close this tab and return to the terminal.</p>";
const REJECTED_PAGE: &str = "<!doctype html><meta charset=utf-8><title>weglarka</title>\
<p>This request does not belong to the running sign-in.</p>";

/// What ended the wait. `Code` is the authorization code of a callback whose `state` matched.
pub(super) enum Outcome {
    Code(String),
    /// The provider reported an error (with the right `state`); its description is never shown.
    Denied,
    TimedOut,
}

pub(super) struct Listener {
    inner: TcpListener,
}

impl Listener {
    /// Binds `127.0.0.1` on a port the system picks; nothing else is ever listened on.
    pub(super) async fn bind() -> std::io::Result<Self> {
        let inner = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        Ok(Self { inner })
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.inner
            .local_addr()
            .expect("a bound socket has an address")
    }

    /// The `redirect_uri` of the authorization request.
    pub(super) fn redirect_uri(&self) -> String {
        format!(
            "http://127.0.0.1:{}{CALLBACK_PATH}",
            self.local_addr().port()
        )
    }

    /// Serves until a callback with the right `state` arrives or `timeout` passes, then closes the
    /// listener. `note` hears about every callback that was refused.
    pub(super) async fn wait(
        self,
        state: &str,
        timeout: Duration,
        note: impl Fn(&str) + Send + Sync + 'static,
    ) -> Outcome {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let state: Arc<str> = state.into();
        let note: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(note);
        let mut connections = JoinSet::new();
        let serve = async {
            loop {
                let Ok((stream, _)) = self.inner.accept().await else {
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                };
                let (state, note, tx) = (state.clone(), note.clone(), tx.clone());
                connections.spawn(async move {
                    let service = service_fn(move |req| {
                        let answer = respond(&req, &state, &*note, &tx);
                        async move { Ok::<_, Infallible>(answer) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        };
        let outcome = tokio::select! {
            () = serve => unreachable!("the accept loop never ends"),
            got = rx.recv() => got.unwrap_or(Outcome::TimedOut),
            () = tokio::time::sleep(timeout) => Outcome::TimedOut,
        };
        // The listener is dropped with `self`; the accepted callback's connection gets a moment
        // to deliver its page, every other connection is cut.
        let _ = tokio::time::timeout(FLUSH_GRACE, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        outcome
    }
}

fn respond(
    req: &Request<Incoming>,
    state: &str,
    note: &(dyn Fn(&str) + Send + Sync),
    tx: &mpsc::UnboundedSender<Outcome>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::GET || req.uri().path() != CALLBACK_PATH {
        return page(StatusCode::NOT_FOUND, "");
    }
    // `state` comes first, for an error callback as much as for a code: nobody but the provider's
    // redirect knows it.
    let params = Url::parse("http://127.0.0.1/")
        .map(|mut base| {
            base.set_query(req.uri().query());
            base
        })
        .ok();
    let param = |key: &str| {
        params.as_ref().and_then(|url| {
            url.query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        })
    };
    if param("state").as_deref() != Some(state) {
        note(
            "Ignored a request to the sign-in callback that did not carry the expected state; still waiting.",
        );
        return page(StatusCode::BAD_REQUEST, REJECTED_PAGE);
    }
    let outcome = if param("error").is_some() {
        Outcome::Denied
    } else if let Some(code) = param("code").filter(|c| !c.is_empty()) {
        Outcome::Code(code)
    } else {
        note("Ignored a callback without a code; still waiting.");
        return page(StatusCode::BAD_REQUEST, REJECTED_PAGE);
    };
    let _ = tx.send(outcome);
    page(StatusCode::OK, DONE_PAGE)
}

/// A static page; it never echoes anything from the request.
fn page(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert("cache-control", "no-store".parse().expect("static header"));
    headers.insert("connection", "close".parse().expect("static header"));
    headers.insert(
        "content-type",
        "text/html; charset=utf-8".parse().expect("static header"),
    );
    headers.insert(
        "referrer-policy",
        "no-referrer".parse().expect("static header"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    const STATE: &str = "STATE123";

    /// One raw HTTP/1.1 request; returns the whole response text.
    async fn get(addr: SocketAddr, target: &str) -> String {
        request(addr, "GET", target).await
    }

    async fn request(addr: SocketAddr, method: &str, target: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!(
                    "{method} {target} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut text = String::new();
        stream.read_to_string(&mut text).await.unwrap();
        text
    }

    fn notes() -> (
        Arc<Mutex<Vec<String>>>,
        impl Fn(&str) + Send + Sync + 'static,
    ) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        (seen, move |line: &str| {
            sink.lock().unwrap().push(line.to_owned())
        })
    }

    #[tokio::test]
    async fn it_binds_loopback_only_and_names_the_port_in_the_redirect_uri() {
        let listener = Listener::bind().await.unwrap();
        let addr = listener.local_addr();
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);
        assert_eq!(
            listener.redirect_uri(),
            format!("http://127.0.0.1:{}/callback", addr.port())
        );
    }

    #[tokio::test]
    async fn a_matching_callback_hands_over_the_code_and_the_page_echoes_nothing() {
        let listener = Listener::bind().await.unwrap();
        let addr = listener.local_addr();
        let (_seen, note) = notes();
        let waiting = tokio::spawn(listener.wait(STATE, Duration::from_secs(10), note));
        let response = get(addr, "/callback?code=THECODE&state=STATE123&x=%3Cscript%3E").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(
            response
                .to_ascii_lowercase()
                .contains("cache-control: no-store")
        );
        assert!(response.contains("You can close this tab"));
        assert!(!response.contains("THECODE") && !response.contains("script"));
        assert!(matches!(waiting.await.unwrap(), Outcome::Code(c) if c == "THECODE"));
    }

    #[tokio::test]
    async fn a_wrong_state_gets_400_and_the_listener_keeps_waiting() {
        let listener = Listener::bind().await.unwrap();
        let addr = listener.local_addr();
        let (seen, note) = notes();
        let waiting = tokio::spawn(listener.wait(STATE, Duration::from_secs(10), note));
        for target in [
            "/callback?code=EVIL&state=other",
            "/callback?code=EVIL",
            "/callback?error=access_denied&state=other",
            "/callback?error=access_denied",
        ] {
            let response = get(addr, target).await;
            assert!(response.starts_with("HTTP/1.1 400"), "{target}: {response}");
            assert!(!response.contains("EVIL"));
        }
        assert_eq!(seen.lock().unwrap().len(), 4);
        assert!(!waiting.is_finished(), "a stranger ended the wait");
        // The real callback still goes through afterwards.
        get(addr, "/callback?code=GOOD&state=STATE123").await;
        assert!(matches!(waiting.await.unwrap(), Outcome::Code(c) if c == "GOOD"));
    }

    #[tokio::test]
    async fn an_error_with_the_right_state_ends_the_login_as_denied() {
        let listener = Listener::bind().await.unwrap();
        let addr = listener.local_addr();
        let (_seen, note) = notes();
        let waiting = tokio::spawn(listener.wait(STATE, Duration::from_secs(10), note));
        let response = get(
            addr,
            "/callback?error=access_denied&error_description=secret+words&state=STATE123",
        )
        .await;
        assert!(!response.contains("secret"));
        assert!(matches!(waiting.await.unwrap(), Outcome::Denied));
    }

    #[tokio::test]
    async fn other_paths_and_methods_get_404_and_the_wait_goes_on() {
        let listener = Listener::bind().await.unwrap();
        let addr = listener.local_addr();
        let (seen, note) = notes();
        let waiting = tokio::spawn(listener.wait(STATE, Duration::from_secs(10), note));
        for target in ["/", "/callback/x?code=C&state=STATE123", "/favicon.ico"] {
            let response = get(addr, target).await;
            assert!(response.starts_with("HTTP/1.1 404"), "{target}: {response}");
        }
        let response = request(addr, "POST", "/callback?code=C&state=STATE123").await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        assert!(seen.lock().unwrap().is_empty());
        assert!(!waiting.is_finished());
        get(addr, "/callback?code=C&state=STATE123").await;
        assert!(matches!(waiting.await.unwrap(), Outcome::Code(_)));
    }

    #[tokio::test]
    async fn the_wait_times_out() {
        let listener = Listener::bind().await.unwrap();
        let (_seen, note) = notes();
        let outcome = listener.wait(STATE, Duration::from_millis(50), note).await;
        assert!(matches!(outcome, Outcome::TimedOut));
    }

    #[tokio::test]
    async fn the_port_is_closed_once_the_wait_is_over() {
        let listener = Listener::bind().await.unwrap();
        let addr = listener.local_addr();
        let (_seen, note) = notes();
        let _ = listener.wait(STATE, Duration::from_millis(10), note).await;
        assert!(TcpStream::connect(addr).await.is_err());
    }
}
