//! The contract suites against a real registry (`HttpRegistry` over loopback HTTP).
//!
//! Needs `WEGLARKA_REGISTRY_URL` (`host:port` of a plain-HTTP loopback registry, e.g. `127.0.0.1:5000`
//! from `docker.io/library/registry:2`; CI starts one in the `podman-tests` job). Without it the test
//! prints a note and passes, like the Podman tests without `WEGLARKA_PODMAN_SOCKET`.

use weglarka_registry::HttpRegistry;
use weglarka_registry::contract::release_registry_suite;

#[tokio::test]
async fn http_registry_meets_the_contract() {
    let Ok(host) = std::env::var("WEGLARKA_REGISTRY_URL") else {
        eprintln!("skipped: WEGLARKA_REGISTRY_URL is not set");
        return;
    };
    let registry = HttpRegistry::new().expect("the HTTP client builds");
    release_registry_suite(&registry, &host).await;
}
