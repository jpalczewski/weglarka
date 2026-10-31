//! Runs the real `weglarka-panel` binary: spawn with a controlled environment, wait until it
//! answers, kill on drop. Cases that need other settings (an API audience, a loopback `http://`
//! issuer, a bad client secret) add variables with [`Panel::env`] and read the outcome with
//! [`Panel::start_failing`].

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use weglarka_panel::config::{
    ENV_API_AUDIENCE, ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_ISSUER, ENV_LISTEN, ENV_PUBLIC_URL,
    ENV_SOCKET,
};

/// Recognizable, so a test can search the output for it.
pub const FAKE_SECRET: &str = "fake-client-secret-7f3a9c";
/// Generous for a loaded CI runner; a healthy start or stop takes milliseconds.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// A port that was free a moment ago. The binary cannot report an OS-assigned port, so the test
/// picks one; the small window before the binary binds it is the price.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// What a finished process left behind.
pub struct Outcome {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl Outcome {
    /// Everything the process printed.
    pub fn output(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

pub struct Panel {
    child: Child,
    pub addr: SocketAddr,
    stdout: Drain,
    stderr: Drain,
}

/// Reads a child's pipe on a background thread from the start, so a chatty child never blocks
/// on a full pipe buffer (~64 KiB) while the test is busy elsewhere. Without it a burst of logs
/// stalls the panel and the test fails with a misleading timeout.
struct Drain {
    buffer: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl Drain {
    fn start(pipe: Option<impl Read + Send + 'static>) -> Self {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let reader = pipe.map(|mut pipe| {
            let buffer = Arc::clone(&buffer);
            std::thread::spawn(move || {
                let mut chunk = [0u8; 8192];
                // EOF (the child closed the pipe) or an error ends the thread.
                while let Ok(n @ 1..) = pipe.read(&mut chunk) {
                    buffer.lock().unwrap().extend_from_slice(&chunk[..n]);
                }
            })
        });
        Self { buffer, reader }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().unwrap()).into_owned()
    }

    /// Waits for end of stream (the child exited), then returns the whole text.
    fn finish(&mut self) -> String {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.text()
    }
}

/// The command for a valid configuration listening on `addr`; callers override with `.env(..)`
/// or `.arg(..)`.
pub fn command(addr: SocketAddr, socket: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_weglarka-panel"));
    cmd.env_clear()
        .env(ENV_CLIENT_ID, "panel")
        .env(ENV_CLIENT_SECRET, FAKE_SECRET)
        .env(ENV_ISSUER, "https://auth.example.com")
        .env(ENV_PUBLIC_URL, "https://panel.example.com")
        .env(ENV_API_AUDIENCE, "https://admin.example.com/api/")
        .env(ENV_SOCKET, socket)
        .env(ENV_LISTEN, addr.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

impl Panel {
    /// Starts the panel on a free loopback port and waits until `/healthz` answers.
    pub fn start(socket: &Path) -> Self {
        Self::start_with(socket, |_| {})
    }

    /// [`Panel::start`] with the command adjusted first (extra variables, flags).
    pub fn start_with(socket: &Path, adjust: impl FnOnce(&mut Command)) -> Self {
        let addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
        let mut cmd = command(addr, socket);
        adjust(&mut cmd);
        Self::spawn(cmd, addr)
    }

    /// Spawns `cmd` and waits for it to serve on `addr`; panics if it exits or stays silent.
    pub fn spawn(cmd: Command, addr: SocketAddr) -> Self {
        let mut panel = Self::launch(cmd, addr);
        panel.wait_ready();
        panel
    }

    /// Spawns `cmd` and starts draining its output, without waiting for it to serve.
    fn launch(mut cmd: Command, addr: SocketAddr) -> Self {
        let mut child = cmd.spawn().expect("cannot spawn weglarka-panel");
        Self {
            stdout: Drain::start(child.stdout.take()),
            stderr: Drain::start(child.stderr.take()),
            child,
            addr,
        }
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("weglarka-panel exited before it was ready: {status}");
            }
            if get(self.addr, "/healthz").is_some_and(|r| r.status == 200) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "weglarka-panel was not ready in time"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends `signal` (`TERM`, `INT`, ...) with `kill(1)`; the crate forbids `unsafe`, so no libc.
    pub fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.pid().to_string())
            .status()
            .expect("cannot run kill");
        assert!(status.success(), "kill -{signal} failed");
    }

    /// Waits for the process to exit by itself; kills it and panics after [`TIMEOUT`].
    pub fn wait_exit(mut self) -> Outcome {
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "weglarka-panel did not exit in time"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        self.collect(status)
    }

    fn collect(&mut self, status: ExitStatus) -> Outcome {
        Outcome {
            status,
            stdout: self.stdout.finish(),
            stderr: self.stderr.finish(),
        }
    }
}

impl Drop for Panel {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Runs `cmd` expecting it to stop on its own (bad configuration, port taken).
pub fn run_to_exit(cmd: Command) -> Outcome {
    let mut panel = Panel::launch(cmd, SocketAddr::from(([127, 0, 0, 1], 0)));
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = panel.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "weglarka-panel did not exit in time"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    panel.collect(status)
}

/// A parsed response; header names are lower-cased.
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// `GET path` over a fresh connection; `None` if it cannot connect or the answer is unreadable.
pub fn get(addr: SocketAddr, path: &str) -> Option<Response> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    parse(&raw)
}

fn parse(raw: &str) -> Option<Response> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Some(Response {
        status,
        headers,
        body: body.to_owned(),
    })
}
