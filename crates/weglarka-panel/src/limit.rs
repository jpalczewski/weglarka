//! A per-client-address limit on login callbacks, and how the client address is found (#308).
//!
//! `PendingLogins::open` records every genuine cookie it opens, before the provider has accepted
//! anything, so without a limit one address could fill that set with fake callbacks. The limit is a
//! sliding window per address, applied before `open`.
//!
//! The client address is the connection's peer, except when the peer is a configured trusted proxy:
//! then `X-Forwarded-For` is read from the right, skipping trusted hops, and the first other entry
//! is the client. The left-most entry is whatever the client wrote and is never used.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

use crate::session::Clock;

/// Callbacks one address may make per [`CALLBACK_WINDOW`].
pub const CALLBACK_LIMIT: usize = 20;
pub const CALLBACK_WINDOW: Duration = Duration::from_secs(60);
/// Addresses tracked at once; past it the least recently active one is dropped.
pub const MAX_TRACKED: usize = 4096;

/// An address or a CIDR range of proxies whose `X-Forwarded-For` is believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyNet {
    addr: IpAddr,
    prefix: u8,
}

impl ProxyNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => mask(
                u128::from(u32::from(net)),
                u128::from(u32::from(ip)),
                32,
                self.prefix,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask(u128::from(net), u128::from(ip), 128, self.prefix)
            }
            _ => false,
        }
    }
}

fn mask(net: u128, ip: u128, bits: u32, prefix: u8) -> bool {
    let shift = bits - u32::from(prefix);
    shift == bits || (net >> shift) == (ip >> shift)
}

/// `::ffff:a.b.c.d` is the IPv4 address `a.b.c.d` (a dual-stack listener reports it so).
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

impl FromStr for ProxyNet {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, String> {
        let (addr, prefix) = match raw.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (raw, None),
        };
        let addr = normalize(
            addr.parse::<IpAddr>()
                .map_err(|_| "not an IP address or CIDR range")?,
        );
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or("prefix length out of range")?,
        };
        Ok(Self { addr, prefix })
    }
}

/// The client behind a request: the peer, or the forwarded address when the peer is trusted.
pub fn client_addr(peer: IpAddr, headers: &HeaderMap, trusted: &[ProxyNet]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(peer) {
        return peer;
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    for hop in hops.iter().rev() {
        match hop.parse::<IpAddr>() {
            Ok(ip) if is_trusted(ip) => continue,
            Ok(ip) => return ip,
            // Garbage from the proxy's side of the chain: believe nothing in the header.
            Err(_) => return peer,
        }
    }
    peer
}

/// One bucket per address; an IPv6 address counts as its /64, which is what one subscriber holds.
fn bucket(ip: IpAddr) -> IpAddr {
    match normalize(ip) {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
        v4 => v4,
    }
}

/// A sliding-window counter per client address. Only admitted attempts are recorded, so a refused
/// flood neither grows memory nor extends its own lockout.
pub struct AddressLimiter {
    limit: usize,
    window: Duration,
    seen: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    clock: Clock,
}

impl AddressLimiter {
    pub fn new(clock: Clock) -> Self {
        Self::with_limits(clock, CALLBACK_LIMIT, CALLBACK_WINDOW)
    }

    pub fn with_limits(clock: Clock, limit: usize, window: Duration) -> Self {
        Self {
            limit,
            window,
            seen: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Records an attempt from `ip`; `false` if it already made `limit` within the window.
    pub fn admit(&self, ip: IpAddr) -> bool {
        let now = self.clock.now();
        let key = bucket(ip);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let live = |t: &Instant| now.saturating_duration_since(*t) < self.window;
        if !seen.contains_key(&key) && seen.len() >= MAX_TRACKED {
            seen.retain(|_, times| times.back().is_some_and(live));
            if seen.len() >= MAX_TRACKED
                && let Some(idle) = seen
                    .iter()
                    .min_by_key(|(_, times)| times.back().copied())
                    .map(|(k, _)| *k)
            {
                seen.remove(&idle);
            }
        }
        let times = seen.entry(key).or_default();
        while times.front().is_some_and(|t| !live(t)) {
            times.pop_front();
        }
        if times.len() >= self.limit {
            return false;
        }
        times.push_back(now);
        true
    }

    /// Addresses currently tracked.
    pub fn tracked(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nets(list: &[&str]) -> Vec<ProxyNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn proxy_nets_parse_and_match() {
        let n: ProxyNet = "10.89.0.0/24".parse().unwrap();
        assert!(n.contains(ip("10.89.0.7")) && !n.contains(ip("10.89.1.7")));
        assert!(n.contains(ip("::ffff:10.89.0.7")));
        let one: ProxyNet = "127.0.0.1".parse().unwrap();
        assert!(one.contains(ip("127.0.0.1")) && !one.contains(ip("127.0.0.2")));
        let v6: ProxyNet = "fd00::/8".parse().unwrap();
        assert!(v6.contains(ip("fd12::1")) && !v6.contains(ip("fe80::1")));
        let all: ProxyNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("8.8.8.8")) && !all.contains(ip("::1")));
        for bad in [
            "",
            "nope",
            "10.0.0.0/33",
            "10.0.0.0/x",
            "::/129",
            "10.0.0.0/",
        ] {
            assert!(bad.parse::<ProxyNet>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn forwarded_for_from_an_untrusted_peer_is_ignored() {
        let h = xff(&["203.0.113.9"]);
        assert_eq!(client_addr(ip("198.51.100.1"), &h, &[]), ip("198.51.100.1"));
        let t = nets(&["10.0.0.0/8"]);
        assert_eq!(client_addr(ip("198.51.100.1"), &h, &t), ip("198.51.100.1"));
    }

    #[test]
    fn a_trusted_peer_is_believed_from_the_right() {
        let t = nets(&["10.0.0.0/8"]);
        let peer = ip("10.0.0.2");
        // The client prepended a forged value; the proxy appended the real peer.
        let h = xff(&["1.2.3.4, 198.51.100.7"]);
        assert_eq!(client_addr(peer, &h, &t), ip("198.51.100.7"));
        // Trusted hops on the right are skipped; several header lines count as one list.
        let h = xff(&["1.2.3.4", "198.51.100.7, 10.0.0.9"]);
        assert_eq!(client_addr(peer, &h, &t), ip("198.51.100.7"));
        // No header, only trusted hops, or garbage: the peer.
        assert_eq!(client_addr(peer, &HeaderMap::new(), &t), peer);
        assert_eq!(client_addr(peer, &xff(&["10.0.0.9"]), &t), peer);
        assert_eq!(client_addr(peer, &xff(&["198.51.100.7, junk"]), &t), peer);
    }

    #[test]
    fn the_window_slides_per_address() {
        let clock = Clock::default();
        let l = AddressLimiter::with_limits(clock.clone(), 3, Duration::from_secs(60));
        let a = ip("198.51.100.1");
        for _ in 0..3 {
            assert!(l.admit(a));
            clock.advance(Duration::from_secs(10));
        }
        assert!(!l.admit(a), "fourth within the window");
        assert!(l.admit(ip("198.51.100.2")), "another address is unaffected");
        // The first attempt (t=0) leaves the window at t=60; refusals were not recorded.
        clock.advance(Duration::from_secs(30));
        assert!(l.admit(a));
        assert!(!l.admit(a));
    }

    #[test]
    fn an_ipv6_subscriber_is_one_bucket() {
        let l = AddressLimiter::with_limits(Clock::default(), 1, Duration::from_secs(60));
        assert!(l.admit(ip("2001:db8:1:2::1")));
        assert!(!l.admit(ip("2001:db8:1:2::ffff")));
        assert!(l.admit(ip("2001:db8:1:3::1")));
    }

    #[test]
    fn memory_is_bounded() {
        let clock = Clock::default();
        let l = AddressLimiter::with_limits(clock.clone(), 1, Duration::from_secs(60));
        for n in 0..(MAX_TRACKED as u32 + 50) {
            assert!(l.admit(IpAddr::from(n.to_be_bytes())));
        }
        assert_eq!(l.tracked(), MAX_TRACKED);
        // Idle entries are swept rather than evicting live ones.
        clock.advance(Duration::from_secs(61));
        assert!(l.admit(ip("203.0.113.1")));
        assert_eq!(l.tracked(), 1);
    }
}
