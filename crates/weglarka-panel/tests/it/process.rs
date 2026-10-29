//! The real binary: startup, flags and environment, bad configuration, signals.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use weglarka_panel::config::{ENV_CLIENT_SECRET, ENV_ISSUER, ENV_LISTEN, ENV_SOCKET};
use weglarka_panel::headers::CONTENT_SECURITY_POLICY_VALUE;
use weglarka_unix_http::testing::mock;

use crate::harness::{FAKE_SECRET, Panel, command, free_port, get, run_to_exit};

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

/// Opens a keep-alive connection and sends only part of a request, so the server holds a
/// connection with a request in progress when the signal arrives.
fn start_request(addr: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
        .unwrap();
    stream.flush().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    stream
}

fn exits_cleanly_on(signal: &str) {
    let daemon_socket = std::env::temp_dir().join(format!("wgl-panel-{}.sock", free_port()));
    let panel = Panel::start(&daemon_socket);
    let mut in_flight = start_request(panel.addr);

    panel.signal(signal);
    let started = Instant::now();
    // The request in progress completes: the rest of it arrives after the signal.
    let _ = in_flight.write_all(b"Connection: close\r\n\r\n");
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

#[test]
fn sigterm_exits_cleanly_with_a_request_in_flight() {
    exits_cleanly_on("TERM");
}

#[test]
fn sigint_exits_cleanly_with_a_request_in_flight() {
    exits_cleanly_on("INT");
}
