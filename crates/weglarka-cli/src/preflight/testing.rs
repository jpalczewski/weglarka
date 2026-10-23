//! Fake host for testing the checks (without touching the real system).

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use super::host::{CmdOutput, FileKind, FileStat, Host, PingInfo};

pub const PROC_NET_TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

#[derive(Default)]
pub struct FakeHost {
    pub files: HashMap<PathBuf, String>,
    pub stats: HashMap<PathBuf, FileStat>,
    /// Key: `program arg1 arg2`. No entry = the program doesn't exist.
    pub commands: HashMap<String, CmdOutput>,
    pub env: HashMap<String, String>,
    pub ping: Option<PingInfo>,
}

impl FakeHost {
    pub fn file(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.into(), content.into());
        self.stats.entry(path.into()).or_insert(FileStat {
            kind: FileKind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
        });
        self
    }

    pub fn stat(mut self, path: &str, kind: FileKind, mode: u32, uid: u32, gid: u32) -> Self {
        self.stats.insert(
            path.into(),
            FileStat {
                kind,
                mode,
                uid,
                gid,
            },
        );
        self
    }

    pub fn cmd(mut self, line: &str, stdout: &str) -> Self {
        self.commands.insert(
            line.into(),
            CmdOutput {
                success: true,
                stdout: stdout.into(),
                stderr: String::new(),
            },
        );
        self
    }

    pub fn ping(mut self, version: Option<&str>) -> Self {
        self.ping = Some(PingInfo {
            status: 200,
            libpod_api_version: version.map(str::to_owned),
        });
        self
    }

    /// A host where everything is fine (config from the MVP example, user uid 1001).
    pub fn healthy() -> Self {
        Self::default()
            .file("/etc/passwd", "weglarka:x:1001:1001::/home/weglarka:/usr/sbin/nologin\n")
            .file("/etc/subuid", "weglarka:165536:2000000\n")
            .file("/etc/subgid", "weglarka:165536:2000000\n")
            .file(
                "/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/cgroup.controllers",
                "cpu memory pids\n",
            )
            .stat("/sys/fs/cgroup/cgroup.controllers", FileKind::File, 0o444, 0, 0)
            .stat("/var/lib/systemd/linger/weglarka", FileKind::File, 0o644, 0, 0)
            .ping(Some("6.1.0"))
            .cmd(
                "apt-cache policy podman",
                "podman:\n  Installed: 6.1.0-1\n  Version table:\n *** 6.1.0-1 1001\n       1001 https://downloadcontent.opensuse.org/repositories/home:/alvistack/xUbuntu_24.04  Packages\n",
            )
            .cmd("netavark --version", "netavark 2.0.1\n")
            .cmd("nft --version", "nftables v1.0.9\n")
            .cmd("pasta --version", "pasta 2025_01_21\n")
            .file("/etc/containers/containers.conf", "[engine]\nenv = [\"NETAVARK_FW=nftables\"]\n")
            .stat("/data/traefik/weglarka.yml", FileKind::File, 0o644, 1001, 1001)
            .cmd(
                "ip -j addr show",
                r#"[{"ifname":"docker0","addr_info":[{"local":"172.17.0.1"}]}]"#,
            )
            .file("/proc/net/tcp", PROC_NET_TCP_HEADER)
            .file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "1\n")
            .file(
                "/sys/kernel/security/apparmor/profiles",
                "podman (enforce)\ncrun (enforce)\n",
            )
            .stat("/etc/weglarka/secrets.toml", FileKind::File, 0o600, 0, 0)
    }
}

impl Host for FakeHost {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        self.files
            .get(path)
            .cloned()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "not found"))
    }

    fn stat(&self, path: &Path) -> io::Result<FileStat> {
        self.stats
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "not found"))
    }

    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
        let key = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.commands
            .get(&key)
            .cloned()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no such program"))
    }

    fn env(&self, key: &str) -> Option<String> {
        self.env.get(key).cloned()
    }

    fn podman_ping(&self, _socket: &Path) -> io::Result<PingInfo> {
        self.ping
            .clone()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "no such socket"))
    }
}
