//! Host boundary: the only place in preflight that touches the system.

use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
    Socket,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    pub kind: FileKind,
    /// Permission bits (`0o600`), without the file type.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Response to `HEAD /libpod/_ping`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingInfo {
    pub status: u16,
    /// The `Libpod-API-Version` header.
    pub libpod_api_version: Option<String>,
}

pub trait Host {
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    fn stat(&self, path: &Path) -> io::Result<FileStat>;
    /// Runs a program (no shell). `ErrorKind::NotFound` when the program doesn't exist.
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput>;
    fn env(&self, key: &str) -> Option<String>;
    /// `HEAD /libpod/_ping` over Podman's unix socket.
    fn podman_ping(&self, socket: &Path) -> io::Result<PingInfo>;
}

pub struct RealHost;

const SOCKET_TIMEOUT: Duration = Duration::from_secs(3);

impl Host for RealHost {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn stat(&self, path: &Path) -> io::Result<FileStat> {
        let m = std::fs::metadata(path)?;
        let ft = m.file_type();
        let kind = if ft.is_file() {
            FileKind::File
        } else if ft.is_dir() {
            FileKind::Dir
        } else if ft.is_socket() {
            FileKind::Socket
        } else {
            FileKind::Other
        };
        Ok(FileStat {
            kind,
            mode: m.mode() & 0o7777,
            uid: m.uid(),
            gid: m.gid(),
        })
    }

    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
        let out = Command::new(program).args(args).output()?;
        Ok(CmdOutput {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn env(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn podman_ping(&self, socket: &Path) -> io::Result<PingInfo> {
        let mut stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        stream.write_all(b"HEAD /libpod/_ping HTTP/1.1\r\nHost: d\r\nConnection: close\r\n\r\n")?;
        // HEAD → response without a body; read to the end of the headers (or until close).
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        super::parse::parse_ping_response(&String::from_utf8_lossy(&buf))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not an HTTP response"))
    }
}
