//! Port forwarder of `edge` mode (issue #162, docs/decisions/0043): `weglarka-daemon forward`.
//!
//! Rootless Podman publishes a bridge container's ports through `rootlessport`, which reconnects
//! from inside the container's netns — nginx would see its own address as the client. This process
//! runs in a container on the default (pasta) network, which keeps the real peer address for remote
//! clients, publishes the public sockets and relays each connection to nginx over a unix socket,
//! prefixed with a PROXY protocol v2 header that carries the client's address. nginx listens on the
//! socket with `proxy_protocol` and trusts only that socket (`set_real_ip_from unix:`).
//!
//! The relay is deliberately dumb: no TLS, no parsing, no buffering beyond the copy loop. The security
//! boundary is the socket directory (`0700`, owned by the runtime user): a local user who cannot
//! open the socket cannot forge a PROXY header.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// PROXY protocol v2 signature.
const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Connections relayed at once per route; further clients wait in the kernel's accept queue.
const MAX_CONNECTIONS: usize = 4096;
/// nginx is local, so a connect that takes longer means it is down: drop the client fast.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// One public socket relayed to one nginx unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub listen: SocketAddr,
    pub socket: PathBuf,
}

impl std::str::FromStr for Route {
    type Err = String;

    /// `<listen address>=<socket path>`, e.g. `0.0.0.0:8080=/run/weglarka-ingress/http.sock`.
    fn from_str(s: &str) -> Result<Self, String> {
        let (listen, socket) = s
            .split_once('=')
            .ok_or_else(|| format!("{s:?}: expected <address:port>=<socket path>"))?;
        let listen = listen
            .parse()
            .map_err(|e| format!("{listen:?}: invalid listen address: {e}"))?;
        if !socket.starts_with('/') {
            return Err(format!("{socket:?}: socket path must be absolute"));
        }
        Ok(Self {
            listen,
            socket: PathBuf::from(socket),
        })
    }
}

/// PROXY protocol v2 header announcing a TCP connection from `src` to `dst`.
pub fn proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut header = SIGNATURE.to_vec();
    header.push(0x21); // version 2, command PROXY
    match (unmap(src), unmap(dst)) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            header.push(0x11); // AF_INET, STREAM
            header.extend_from_slice(&12u16.to_be_bytes());
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        (src, dst) => {
            header.push(0x21); // AF_INET6, STREAM
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&v6(src.ip()).octets());
            header.extend_from_slice(&v6(dst.ip()).octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
    }
    header
}

/// `::ffff:a.b.c.d` → `a.b.c.d`, so a dual-stack listener still announces IPv4 clients as IPv4.
fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

fn v6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Binds every route and relays until the process is stopped; an error is a bind failure at start.
pub async fn run(routes: Vec<Route>) -> std::io::Result<()> {
    let mut tasks = JoinSet::new();
    for route in routes {
        let listener = TcpListener::bind(route.listen).await?;
        tracing::info!(listen = %route.listen, socket = %route.socket.display(), "forwarding");
        tasks.spawn(accept_loop(listener, route.socket));
    }
    // The loops never end; a panicked one ends the process so the restart policy brings it back.
    while let Some(done) = tasks.join_next().await {
        done.map_err(std::io::Error::other)?;
    }
    Ok(())
}

async fn accept_loop(listener: TcpListener, socket: PathBuf) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let socket = Arc::new(socket);
    loop {
        let Ok(permit) = limit.clone().acquire_owned().await else {
            return;
        };
        match listener.accept().await {
            Ok((client, peer)) => {
                let socket = socket.clone();
                tokio::spawn(async move {
                    if let Err(e) = relay(client, peer, &socket).await {
                        tracing::debug!(%peer, error = %e, "connection ended with an error");
                    }
                    drop(permit);
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                drop(permit);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn relay(
    mut client: TcpStream,
    peer: SocketAddr,
    socket: &std::path::Path,
) -> std::io::Result<()> {
    let local = client.local_addr()?;
    client.set_nodelay(true)?;
    let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "nginx socket timeout"))??;
    upstream.write_all(&proxy_v2_header(peer, local)).await?;
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_parses_and_rejects() {
        let r: Route = "0.0.0.0:8080=/run/x/http.sock".parse().unwrap();
        assert_eq!(r.listen.port(), 8080);
        assert_eq!(r.socket, PathBuf::from("/run/x/http.sock"));
        assert!("0.0.0.0:8080".parse::<Route>().is_err());
        assert!("nonsense=/a".parse::<Route>().is_err());
        assert!("0.0.0.0:80=relative.sock".parse::<Route>().is_err());
    }

    #[test]
    fn v4_header_layout() {
        let h = proxy_v2_header(
            "37.8.250.28:51000".parse().unwrap(),
            "10.0.0.5:8080".parse().unwrap(),
        );
        assert_eq!(&h[..12], &SIGNATURE);
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x11);
        assert_eq!(&h[14..16], &12u16.to_be_bytes());
        assert_eq!(&h[16..20], &[37, 8, 250, 28]);
        assert_eq!(&h[20..24], &[10, 0, 0, 5]);
        assert_eq!(&h[24..26], &51000u16.to_be_bytes());
        assert_eq!(&h[26..28], &8080u16.to_be_bytes());
        assert_eq!(h.len(), 28);
    }

    #[test]
    fn v6_header_layout_and_mapped_clients_stay_v4() {
        let h = proxy_v2_header(
            "[2001:db8::1]:40000".parse().unwrap(),
            "[2001:db8::2]:8443".parse().unwrap(),
        );
        assert_eq!(h[13], 0x21);
        assert_eq!(&h[14..16], &36u16.to_be_bytes());
        assert_eq!(h.len(), 16 + 36);
        let mapped = proxy_v2_header(
            "[::ffff:37.8.250.28]:1".parse().unwrap(),
            "[::ffff:10.0.0.5]:2".parse().unwrap(),
        );
        assert_eq!(mapped[13], 0x11);
        assert_eq!(&mapped[16..20], &[37, 8, 250, 28]);
    }

    #[tokio::test]
    async fn relays_with_the_real_peer_in_the_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("n.sock");
        let nginx = tokio::net::UnixListener::bind(&sock).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(accept_loop(tcp, sock));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let me = client.local_addr().unwrap();
        client.write_all(b"ping").await.unwrap();

        let (mut conn, _) = nginx.accept().await.unwrap();
        let mut got = vec![0u8; 28 + 4];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(got[..28], proxy_v2_header(me, addr)[..]);
        assert_eq!(&got[28..], b"ping");
        conn.write_all(b"pong").await.unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
    }
}
