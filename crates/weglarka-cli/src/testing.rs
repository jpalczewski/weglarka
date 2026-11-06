//! Test helpers shared by the CLI's test modules: the mock daemon, the overrides that point a
//! command at it, error bodies and the app fixtures the commands read back.
//!
//! The mock unix-socket server itself lives in `weglarka-unix-http` (feature `testing`): it records
//! each request's method, path and query (`Seen`) and answers from a closure.

use std::path::Path;

use bytes::Bytes;
use clap::Parser as _;
use weglarka_api::{ApiError, ErrorCode, RuntimeState, ShowAppResponse};
use weglarka_model::app::{AppSpec, InstanceName};
pub(crate) use weglarka_unix_http::testing::mock;
use weglarka_unix_http::testing::{Mock, Reply, mock_with};

use crate::settings::Overrides;
use crate::update::UpdateArgs;

/// Overrides that send a command's requests to the mock on `socket` (a [`Mock`] derefs to it).
pub(crate) fn overrides(socket: &Path) -> Overrides {
    Overrides {
        config: None,
        socket: Some(socket.to_owned()),
        host: None,
    }
}

/// A mock daemon answering every request with `status` and `body`.
pub(crate) async fn mock_fixed(status: u16, body: impl Into<Bytes>) -> Mock {
    let body = body.into();
    mock_with(move |_, _| Reply::new(status, body.clone())).await
}

/// The JSON error envelope the daemon answers a refusal with.
pub(crate) fn api_err(code: ErrorCode, message: &str) -> String {
    serde_json::to_string(&ApiError {
        code,
        message: message.into(),
    })
    .unwrap()
}

/// `GET /v1/apps/ntfy` as an `admin` caller sees it: `spec`, `runtime`, a fresh state and nothing
/// else reported.
pub(crate) fn show_response(spec: AppSpec, runtime: RuntimeState) -> ShowAppResponse {
    ShowAppResponse {
        name: InstanceName::new("ntfy").unwrap(),
        spec,
        state: Default::default(),
        runtime,
        configs: None,
        host_mounts: None,
        ingress_logs: None,
        restarts: None,
        health: None,
        started_at: None,
        redacted: false,
        reconciled: None,
    }
}

/// `apps update ntfy <extra…>` flags as parsed from the command line.
pub(crate) fn try_update_args(extra: &[&str]) -> Result<UpdateArgs, clap::Error> {
    #[derive(clap::Parser)]
    struct Up {
        #[command(flatten)]
        a: UpdateArgs,
    }
    let argv = ["update", "ntfy"].iter().chain(extra);
    Up::try_parse_from(argv).map(|up| up.a)
}

/// [`try_update_args`] for flags that must parse.
pub(crate) fn update_args(extra: &[&str]) -> UpdateArgs {
    try_update_args(extra).unwrap()
}
