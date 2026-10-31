//! The real binary: startup, flags and environment, bad configuration, signals.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use weglarka_panel::config::{
    ENV_API_AUDIENCE, ENV_CLIENT_SECRET, ENV_CLIENT_SECRET_FILE, ENV_ISSUER, ENV_LISTEN, ENV_SOCKET,
};
use weglarka_panel::headers::CONTENT_SECURITY_POLICY_VALUE;
use weglarka_unix_http::testing::{Mock, Reply, mock, mock_with};

use crate::harness::{FAKE_SECRET, Panel, TIMEOUT, command, free_port, get, run_to_exit};

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_healthz_with_security_headers() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let panel = Panel::start(&daemon.socket);
    let response = get(panel.addr, "/healthz").unwrap();
    assert_eq!(response.status, 200);
    assert!(!response.body.is_empty());
    assert_eq!(
        response.header("content-security-policy"),
        Some(CONTENT_SECURITY_POLICY_VALUE)
    );
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(response.header("referrer-policy"), Some("no-referrer"));

    // Anything else is refused, with the same headers.
    let denied = get(panel.addr, "/").unwrap();
    assert_eq!(denied.status, 401);
    assert!(denied.header("content-security-policy").is_some());
    assert!(daemon.seen.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loopback_http_issuer_and_a_secret_file_are_accepted() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let secret_file = std::env::temp_dir().join(format!("wgl-panel-secret-{}", free_port()));
    std::fs::write(&secret_file, format!("{FAKE_SECRET}\n")).unwrap();
    // Discovery is lazy: the provider need not be up for the panel to start.
    let panel = Panel::start_with(&daemon.socket, |cmd| {
        cmd.env(ENV_ISSUER, "http://127.0.0.1:9")
            .env_remove(ENV_CLIENT_SECRET)
            .env(ENV_CLIENT_SECRET_FILE, &secret_file);
    });
    assert_eq!(get(panel.addr, "/healthz").unwrap().status, 200);
    // Login cannot start (no provider), and says so without leaking anything.
    let login = get(panel.addr, "/auth/login").unwrap();
    assert_eq!(login.status, 502);
    assert!(!login.body.contains(FAKE_SECRET));
    drop(panel);
    std::fs::remove_file(secret_file).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flag_wins_over_the_variable_of_the_same_setting() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let (flag_addr, env_addr) = (loopback(free_port()), loopback(free_port()));
    let mut cmd = command(env_addr, &daemon.socket);
    // The socket variable is invalid (relative); only the flag makes the start succeed.
    cmd.env(ENV_SOCKET, "relative.sock")
        .arg("--listen")
        .arg(flag_addr.to_string())
        .arg("--socket")
        .arg(&*daemon.socket);
    let panel = Panel::spawn(cmd, flag_addr);
    assert_eq!(get(flag_addr, "/healthz").unwrap().status, 200);
    assert!(
        get(env_addr, "/healthz").is_none(),
        "the variable's address must not be bound"
    );
    drop(panel);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_variable_is_used_without_a_flag_and_blank_counts_as_unset() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let addr = loopback(free_port());
    // Blank PANEL_LISTEN would fall back to the default 0.0.0.0:8080, so only the socket is blank.
    let mut cmd = command(addr, &daemon.socket);
    cmd.env(ENV_SOCKET, "  ");
    let panel = Panel::spawn(cmd, addr);
    assert_eq!(get(panel.addr, "/healthz").unwrap().status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_configuration_exits_non_zero_without_leaking_the_secret() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let addr = loopback(free_port());
    type Break = Box<dyn Fn(&mut std::process::Command)>;
    let cases: Vec<(&str, Break, &str)> = vec![
        (
            "missing issuer",
            Box::new(|c| {
                c.env_remove(ENV_ISSUER);
            }),
            ENV_ISSUER,
        ),
        (
            "plain http issuer",
            Box::new(|c| {
                c.env(ENV_ISSUER, "http://auth.example.com");
            }),
            ENV_ISSUER,
        ),
        (
            "missing api audience",
            Box::new(|c| {
                c.env_remove(ENV_API_AUDIENCE);
            }),
            ENV_API_AUDIENCE,
        ),
        (
            "http issuer that is not loopback",
            Box::new(|c| {
                c.env(ENV_ISSUER, "http://127.0.0.1.example.com");
            }),
            ENV_ISSUER,
        ),
        (
            "secret and secret file",
            Box::new(|c| {
                c.env(ENV_CLIENT_SECRET_FILE, "/nonexistent");
            }),
            ENV_CLIENT_SECRET_FILE,
        ),
        (
            "a secret with a control character",
            Box::new(|c| {
                c.env(ENV_CLIENT_SECRET, format!("{FAKE_SECRET}\u{7}tail"));
            }),
            ENV_CLIENT_SECRET,
        ),
        (
            "bad listen address",
            Box::new(|c| {
                c.env(ENV_LISTEN, "everywhere");
            }),
            ENV_LISTEN,
        ),
        (
            "relative socket",
            Box::new(|c| {
                c.env(ENV_SOCKET, "relative.sock");
            }),
            ENV_SOCKET,
        ),
        (
            "bad listen flag",
            Box::new(|c| {
                c.args(["--listen", "everywhere"]);
            }),
            "--listen",
        ),
    ];
    for (name, break_it, expected) in cases {
        let mut cmd = command(addr, &daemon.socket);
        break_it(&mut cmd);
        let outcome = run_to_exit(cmd);
        assert!(!outcome.status.success(), "{name}: {:?}", outcome.status);
        assert_ne!(outcome.status.code(), Some(0), "{name}");
        let output = outcome.output();
        assert!(output.contains(expected), "{name}: {output}");
        assert!(
            !output.contains(FAKE_SECRET),
            "{name} leaked the secret: {output}"
        );
    }

    // The secret itself missing: named, nothing to leak, still non-zero.
    let mut cmd = command(addr, &daemon.socket);
    cmd.env_remove(ENV_CLIENT_SECRET);
    let outcome = run_to_exit(cmd);
    assert!(!outcome.status.success());
    assert!(outcome.output().contains(ENV_CLIENT_SECRET));
}

#[test]
fn output_larger_than_a_pipe_buffer_does_not_stall_the_child() {
    // 256 KiB on each stream is four times a typical pipe buffer; undrained, `sh` blocks on the
    // first write and never exits.
    let mut cmd = std::process::Command::new("sh");
    cmd.args([
        "-c",
        "head -c 262144 /dev/zero | tr '\\0' o; head -c 262144 /dev/zero | tr '\\0' e >&2",
    ])
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    let outcome = run_to_exit(cmd);
    assert!(outcome.status.success(), "{:?}", outcome.status);
    assert_eq!(outcome.stdout.len(), 262_144);
    assert_eq!(outcome.stderr.len(), 262_144);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_instance_on_the_same_port_fails_cleanly() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let first = Panel::start(&daemon.socket);
    let outcome = run_to_exit(command(first.addr, &daemon.socket));
    assert!(!outcome.status.success(), "{:?}", outcome.status);
    let output = outcome.output();
    assert!(output.contains("cannot listen on"), "{output}");
    assert!(!output.contains(FAKE_SECRET), "{output}");
    // The first instance is unaffected.
    assert_eq!(get(first.addr, "/healthz").unwrap().status, 200);
}

/// How long the mock daemon sits on the relayed request. The signal is sent as soon as the
/// request has reached the daemon, so this only has to outlast a `kill(1)`; it is not a guess
/// about how long the server takes to read anything.
const SLOW_DAEMON: Duration = Duration::from_secs(2);

/// Sends a complete request through the relay to a daemon that answers slowly, and returns once
/// the daemon has received it: from then on the panel is certainly holding a request in flight.
fn start_request(addr: SocketAddr, daemon: &Mock) -> TcpStream {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .write_all(
            b"GET /_weglarka/api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    let deadline = Instant::now() + TIMEOUT;
    while daemon.seen.lock().unwrap().is_empty() {
        assert!(
            Instant::now() < deadline,
            "the request never reached the daemon"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    stream
}

async fn exits_cleanly_on(signal: &str) {
    let daemon =
        mock_with(|_, _| Reply::new(200, r#"{"status":"ok"}"#).head_delay(SLOW_DAEMON)).await;
    let panel = Panel::start(&daemon.socket);
    let mut in_flight = start_request(panel.addr, &daemon);

    panel.signal(signal);
    let started = Instant::now();
    // The request in progress completes even though the signal arrived while it was open.
    let mut answer = String::new();
    let _ = in_flight.read_to_string(&mut answer);
    assert!(
        answer.starts_with("HTTP/1.1 200"),
        "in-flight request: {answer:?}"
    );

    let outcome = panel.wait_exit();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "shutdown took too long"
    );
    assert_eq!(
        outcome.status.code(),
        Some(0),
        "SIG{signal}: {:?}",
        outcome.status
    );
    let output = outcome.output();
    assert!(output.contains("shutting down"), "{output}");
    assert!(output.contains("panel stopped"), "{output}");
    assert!(!output.contains(FAKE_SECRET));
}

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_exits_cleanly_with_a_request_in_flight() {
    exits_cleanly_on("TERM").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sigint_exits_cleanly_with_a_request_in_flight() {
    exits_cleanly_on("INT").await;
}
