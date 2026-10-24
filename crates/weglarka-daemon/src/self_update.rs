//! `weglarka-daemon self-update` — the host-side switcher (issue #99, `docs/decisions/0027`).
//!
//! The daemon runs in a `scratch` container: no `systemctl`, no `/etc/passwd`, no write access to its
//! own unit. Replacing its image therefore happens from the host, in this order:
//!
//! 1. pull the configured tag (`[self_update] image`) and take the digest Podman resolved;
//! 2. verify the cosign signature of that digest against the pinned public key (`cosign.pub`,
//!    embedded; `[self_update] public_key_file` overrides it);
//! 3. compare the image's OCI label `io.weglarka.state-schema` with the state's recorded schema
//!    (`docs/decisions/0023`) and refuse a downgrade across a schema bump;
//! 4. render the service definition with `repo@sha256:<digest>` and install it (`Platform`);
//! 5. record the digest as `pending` **before** restarting, then `systemctl --user restart`.
//!
//! The daemon confirms the switch on its next start (`crate::start`): it compares `pending` with the
//! digest of its own container and records `current`/`previous` — the rollback target. If it does not
//! run the pinned digest, `doctor` and a `SelfUpdatePending` event say so instead of silently
//! pretending the update happened. Automatic fallback is #100; until then `--rollback` is the lever.
//!
//! The whole procedure is a function over three traits (`PodmanClient`, `Registry`, `Platform`), so
//! the tests drive it end to end without Podman, a registry or systemd.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use futures_util::StreamExt;
use weglarka_core::app::Digest;
use weglarka_core::config::SelfUpdateConfig;
use weglarka_core::events::{Event, EventSink};
use weglarka_core::platform::Platform;
use weglarka_core::podman::{PodmanClient, PodmanError, PullEvent};
use weglarka_core::self_update::{
    self as state, Confirmation, Decision, SelfUpdateState, SelfUpdateStateError, secs,
};
use weglarka_core::state as state_files;
use weglarka_registry::{
    DEFAULT_PUBLIC_KEY_PEM, ImageRef, KeyError, PublicKey, Registry, RegistryError, Signature,
    verify,
};

use crate::platform::SELF_UPDATE_TIMER;
use crate::service::{SERVICE_NAME, host_socket, service_spec};
use crate::settings::Settings;

/// OCI label through which the image declares the state schema it writes (`docs/decisions/0023`).
pub const SCHEMA_LABEL: &str = "io.weglarka.state-schema";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("[self_update] {0}")]
    Config(String),
    #[error(transparent)]
    State(#[from] SelfUpdateStateError),
    /// The state files cannot be read (e.g. written by a newer daemon): the switcher must not
    /// replace the image while it cannot tell what the state needs (`docs/decisions/0023`).
    #[error(transparent)]
    Store(#[from] state_files::StateError),
    #[error(transparent)]
    Podman(#[from] PodmanError),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Platform(#[from] weglarka_core::platform::PlatformError),
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{0}")]
    Message(String),
}

/// What the operator asked for on the command line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Report only: pull, verify and check the schema, but never write the unit or restart.
    pub check: bool,
    /// Ignore the configured interval and the "this digest already failed" shortcut.
    pub force: bool,
    /// Pin the recorded previous digest instead of looking for a new image.
    pub rollback: bool,
}

/// Outcome of a run; the caller logs it and maps it to an exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// No `[self_update]` section, or `enabled = false`.
    Disabled,
    /// The interval since the last check has not passed yet.
    NotDue,
    /// The pulled digest is already the running or the pending one.
    UpToDate { digest: Digest },
    /// `--check`: a new, verified digest is available (nothing was changed).
    Available { from: Option<Digest>, to: Digest },
    /// The new digest is pinned in the service definition and the service was restarted.
    Applied { from: Option<Digest>, to: Digest },
    /// `--rollback`: the previous digest is pinned and the service was restarted.
    RolledBack { from: Option<Digest>, to: Digest },
    /// Nothing was changed; the reason is in the state file and in the log.
    Refused { reason: String },
}

impl Report {
    /// `false` for the outcomes that need the operator's attention (the timer then shows a failed
    /// unit in `systemctl --user list-timers`, which is the point of running it there).
    pub fn is_success(&self) -> bool {
        !matches!(self, Self::Refused { .. })
    }
}

/// Runs one check/switch. `now` is injected so the tests are deterministic.
pub async fn run<P, R, Pl>(
    podman: &P,
    registry: &R,
    platform: &Pl,
    settings: &Settings,
    options: Options,
    now: SystemTime,
) -> Result<Report, Error>
where
    P: PodmanClient,
    R: Registry,
    Pl: Platform,
{
    let Some(config) = settings.host.self_update.as_ref() else {
        return Ok(Report::Disabled);
    };
    if !config.enabled {
        return Ok(Report::Disabled);
    }
    config.validate().map_err(Error::Config)?;

    let state_dir = settings.paths.state_dir.clone();
    let mut st = state::load(&state_dir)?;
    let interval = Duration::from_secs(config.interval_secs);
    // `--check` and `--force` are explicitly the operator asking now.
    let explicit = options.check || options.force;
    if !options.rollback && !explicit && !st.is_due(interval, now) {
        return Ok(Report::NotDue);
    }

    let image = ImageRef::parse(&config.image).map_err(|e| Error::Config(e.to_string()))?;
    if options.rollback {
        return rollback(
            podman, platform, settings, &image, &state_dir, &mut st, options, now,
        )
        .await;
    }

    // 1. Pull the tag and take the digest Podman resolved — the same digest that gets pinned.
    let digest = pull_digest(podman, &config.image).await?;
    // Labels of the pulled image: the schema it writes and the state's own version.
    let image_schema = pulled_schema(podman, &config.image).await;
    let state_schema = state_schema(settings)?;

    // `--force` is the documented override for the schema gate (a deliberate downgrade); it never
    // overrides the signature check.
    let decision = state::decide(&st, &digest, image_schema, Some(state_schema));
    let (from, to) = match decision {
        Decision::UpToDate => {
            st.record_check(now);
            state::save(&state_dir, &st)?;
            return Ok(Report::UpToDate { digest });
        }
        Decision::Refused(reason) if !options.force => {
            st.record_error(&reason, Some(digest), now);
            state::save(&state_dir, &st)?;
            return Ok(Report::Refused { reason });
        }
        Decision::Refused(reason) => {
            tracing::warn!(%reason, "overriding the state-schema gate (--force)");
            (st.current.clone(), digest)
        }
        Decision::Update { from, to } => (from, to),
    };
    if !options.force
        && st.failed_for(&to)
        && let Some(error) = &st.error
    {
        // The registry and the signature check already failed for this digest; wait for the
        // tag to move instead of hitting the registry every wake-up.
        let reason = error.message.clone();
        st.record_check(now);
        state::save(&state_dir, &st)?;
        return Ok(Report::Refused { reason });
    }
    // 2. The signature, before anything is written.
    if let Err(reason) = check_signature(registry, config, &image, &to).await {
        st.record_error(&reason, Some(to), now);
        state::save(&state_dir, &st)?;
        return Ok(Report::Refused { reason });
    }
    if options.check {
        st.clear_error();
        st.record_check(now);
        state::save(&state_dir, &st)?;
        return Ok(Report::Available { from, to });
    }
    // 3. Pin the verified digest and restart. `pending` is written first: if the restart
    //    kills the service, the next start still knows what it should be running.
    apply(platform, settings, &image, &to, &state_dir, &mut st, now).await?;
    Ok(Report::Applied { from, to })
}

/// Pins `to` in the service definition and restarts the service, recording `pending` first.
async fn apply<Pl: Platform>(
    platform: &Pl,
    settings: &Settings,
    image: &ImageRef,
    to: &Digest,
    state_dir: &Path,
    st: &mut SelfUpdateState,
    now: SystemTime,
) -> Result<(), Error> {
    let socket = host_socket(settings, platform).await?;
    let spec = service_spec(settings, socket, pinned(image, to));
    platform.install_service(&spec).await?;
    st.pending = Some(to.clone());
    st.pending_at = Some(secs(now));
    st.clear_error();
    st.record_check(now);
    state::save(state_dir, st)?;
    platform.restart_service(SERVICE_NAME).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn rollback<P, Pl>(
    podman: &P,
    platform: &Pl,
    settings: &Settings,
    image: &ImageRef,
    state_dir: &Path,
    st: &mut SelfUpdateState,
    options: Options,
    now: SystemTime,
) -> Result<Report, Error>
where
    P: PodmanClient,
    Pl: Platform,
{
    let Some(previous) = st.previous.clone() else {
        return Ok(Report::Refused {
            reason: format!(
                "no previous image recorded in {} — nothing to roll back to (docs/install.md 6k)",
                state::path(state_dir).display()
            ),
        });
    };
    // The previous image is (normally) still in the local store: it is what the retention keeps.
    // Rolling back to an image that is missing would pin a reference the service cannot start.
    let previous_ref = pinned(image, &previous);
    let info = match podman.image_inspect(&previous_ref).await {
        Ok(info) => info,
        Err(PodmanError::NotFound(_)) => {
            return Ok(Report::Refused {
                reason: format!(
                    "the previous image {previous_ref} is not in the local store any more; \
                     pull it or install it with `weglarka-daemon platform install --image {previous_ref}`"
                ),
            });
        }
        Err(e) => return Err(Error::Podman(e)),
    };
    // The schema gate only applies when the label is readable: an image that predates the label
    // counts as schema 0, and a downgrade across a bump would lose fields (`docs/decisions/0023`).
    let state_schema = state_schema(settings)?;
    if let Some(image_schema) = schema_label(&info.labels)
        && image_schema < state_schema
        && !options.force
    {
        let reason = format!(
            "the previous image writes state schema {image_schema}, the state is at {state_schema}: \
             rolling back across a schema bump would lose fields (restore a state backup, or pass \
             --force if you know that image reads it)"
        );
        st.record_error(&reason, Some(previous), now);
        state::save(state_dir, st)?;
        return Ok(Report::Refused { reason });
    }
    let from = st.current.clone();
    if options.check {
        return Ok(Report::Available { from, to: previous });
    }
    apply(platform, settings, image, &previous, state_dir, st, now).await?;
    Ok(Report::RolledBack { from, to: previous })
}

/// The state schema the files are at: `schema_version` in `state.toml` (a file without the marker is
/// the implicit v1). A state this binary cannot read (written by a newer daemon) is an error — the
/// switcher must not replace the image while it cannot tell what that state needs.
fn state_schema(settings: &Settings) -> Result<u32, Error> {
    let state = state_files::load_state(&settings.paths.state.state)?;
    Ok(state.schema_version.unwrap_or(state_files::SCHEMA_VERSION))
}

/// `repo@sha256:…` — the service definition says exactly what runs, so a moving tag cannot change it.
fn pinned(image: &ImageRef, digest: &Digest) -> String {
    format!("{}@{}", image.repository_reference(), digest.as_str())
}

/// Pulls `reference` and returns the digest Podman resolved for it.
async fn pull_digest(podman: &impl PodmanClient, reference: &str) -> Result<Digest, Error> {
    let mut stream = std::pin::pin!(podman.image_pull(reference));
    let mut digest = None;
    while let Some(event) = stream.next().await {
        match event? {
            PullEvent::Progress { .. } => {}
            PullEvent::Complete { digest: d, .. } => digest = d,
        }
    }
    digest.ok_or_else(|| {
        Error::Message(format!(
            "podman reported no digest for {reference}: a reference without a digest cannot be pinned"
        ))
    })
}

async fn pulled_schema(podman: &impl PodmanClient, reference: &str) -> Option<u32> {
    match podman.image_inspect(reference).await {
        Ok(info) => schema_label(&info.labels),
        Err(e) => {
            // Not fatal: a missing label counts as schema 0, and the switcher refuses only when the
            // state is ahead of the image.
            tracing::warn!(error = %e, reference, "cannot read the image labels");
            None
        }
    }
}

fn schema_label(labels: &std::collections::BTreeMap<String, String>) -> Option<u32> {
    labels.get(SCHEMA_LABEL)?.trim().parse().ok()
}

/// Loads the pinned key: the override file when configured, otherwise the embedded `cosign.pub`.
fn public_key(config: &SelfUpdateConfig) -> Result<PublicKey, Error> {
    match &config.public_key_file {
        None => Ok(PublicKey::from_pem(DEFAULT_PUBLIC_KEY_PEM)?),
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
                path: path.clone(),
                source,
            })?;
            Ok(PublicKey::from_pem(&text)?)
        }
    }
}

/// Fetches the signatures stored next to the image and accepts the first one that verifies.
async fn check_signature(
    registry: &impl Registry,
    config: &SelfUpdateConfig,
    image: &ImageRef,
    digest: &Digest,
) -> Result<(), String> {
    let key = match public_key(config) {
        Ok(key) => key,
        Err(e) => return Err(format!("cannot load the pinned public key: {e}")),
    };
    let signatures: Vec<Signature> = registry
        .cosign_signatures(image, digest)
        .await
        .map_err(|e| format!("cannot fetch the cosign signature: {e}"))?;
    if signatures.is_empty() {
        return Err(format!(
            "no key-based cosign signature for {digest}: is the image signed with `cosign sign --key`?"
        ));
    }
    let mut last = None;
    for signature in &signatures {
        match verify(signature, &key, image, digest) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e.to_string()),
        }
    }
    Err(format!(
        "cosign signature verification failed: {}",
        last.unwrap_or_else(|| "no usable signature".to_owned())
    ))
}

/// The user units of the timer, rendered for this binary and configuration.
pub fn units(settings: &Settings) -> Result<Vec<weglarka_core::platform::UnitFile>, Error> {
    let binary = std::env::current_exe().map_err(|source| Error::Read {
        path: PathBuf::from("current executable"),
        source,
    })?;
    Ok(crate::platform::render_self_update_units(
        &binary,
        &settings.config_path,
    )?)
}

/// Confirms at startup which image this daemon really runs and resolves a switch requested by the
/// host-side switcher: `pending` == running updates `current`/`previous` (the rollback target), a
/// mismatch is reported instead of pretending the update happened.
///
/// Runs inside the container, so the daemon is identified by its container name (`weglarka`): the
/// `scratch` image has no other handle on itself. On a host run (or in tests) there is no such
/// container; the function then returns `None` and confirms nothing.
pub async fn confirm_startup<P: PodmanClient>(
    podman: &P,
    state_dir: &Path,
    events: &dyn EventSink,
) -> Option<Confirmation> {
    let running = match own_digest(podman).await {
        Some(digest) => digest,
        None => {
            tracing::debug!(
                container = SERVICE_NAME,
                "cannot determine the running image; skipping the self-update confirmation"
            );
            return None;
        }
    };
    let mut st = match state::load(state_dir) {
        Ok(st) => st,
        Err(e) => {
            tracing::warn!(error = %e, "cannot read the self-update state");
            return None;
        }
    };
    let confirmation = st.confirm(&running);
    match &confirmation {
        Confirmation::Updated { from, to } | Confirmation::Adopted { from, to } => {
            tracing::info!(
                %to,
                from = ?from.as_ref().map(Digest::as_str),
                "self-update confirmed: running the requested image"
            );
            events.emit(Event::SelfUpdated {
                from: from.clone(),
                to: to.clone(),
            });
        }
        Confirmation::Pending { expected, actual } => {
            tracing::warn!(
                %expected,
                %actual,
                "a self-update was requested but the container runs a different image \
                 (`weglarka-daemon self-update --rollback` returns to the previous one)"
            );
            events.emit(Event::SelfUpdatePending {
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
        Confirmation::Unchanged => {}
    }
    if !matches!(confirmation, Confirmation::Unchanged)
        && let Err(e) = state::save(state_dir, &st)
    {
        tracing::warn!(error = %e, "cannot save the self-update state");
    }
    Some(confirmation)
}

/// The digest of the image this daemon's container runs (`container_inspect` → `image_inspect`).
async fn own_digest(podman: &impl PodmanClient) -> Option<Digest> {
    let container = podman.container_inspect(SERVICE_NAME).await.ok()?;
    let image = podman.image_inspect(&container.image_id).await.ok()?;
    image.digest.or_else(|| {
        image
            .repo_digests
            .iter()
            .filter_map(|name| name.split_once('@'))
            .filter_map(|(_, digest)| Digest::new(digest).ok())
            .next()
    })
}

/// The timer unit name — re-exported so `platform install/remove/status` do not import two modules.
pub const TIMER: &str = SELF_UPDATE_TIMER;

/// A human-readable one-liner of a report (the `self-update` command prints it).
impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => {
                f.write_str("self-update is not configured ([self_update] absent or disabled)")
            }
            Self::NotDue => f.write_str("not due yet ([self_update] interval_secs not elapsed)"),
            Self::UpToDate { digest } => write!(f, "up to date ({digest})"),
            Self::Available { to, .. } => write!(f, "verified and available: {to}"),
            Self::Applied { from, to } => match from {
                Some(from) => write!(f, "updated {from} → {to}"),
                None => write!(f, "updated to {to}"),
            },
            Self::RolledBack { from, to } => match from {
                Some(from) => write!(f, "rolled back {from} → {to}"),
                None => write!(f, "rolled back to {to}"),
            },
            Self::Refused { reason } => write!(f, "refused: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use weglarka_core::config::{HostConfig, PlatformKind};
    use weglarka_core::platform::{PlatformError, ServiceStatus, UnitFile};
    use weglarka_core::testing::FakePodman;
    use weglarka_registry::ImageRef;
    use weglarka_registry::testing::{FakeRegistry, TestSigner};

    use super::*;
    use crate::service::SERVICE_NAME;

    const IMAGE: &str = "ghcr.io/jpalczewski/weglarka:latest";
    const SCHEMA_ONE: &str = "io.weglarka.state-schema";

    /// Records what the switcher asked the service manager to do.
    #[derive(Default)]
    struct FakePlatform {
        installed: Mutex<Vec<String>>,
        restarts: Mutex<u32>,
    }

    impl FakePlatform {
        fn installed_images(&self) -> Vec<String> {
            self.installed.lock().unwrap().clone()
        }
        fn restarts(&self) -> u32 {
            *self.restarts.lock().unwrap()
        }
    }

    impl Platform for FakePlatform {
        fn kind(&self) -> PlatformKind {
            PlatformKind::Systemd
        }
        async fn runtime_socket(&self, _: &str) -> Result<PathBuf, PlatformError> {
            Ok(PathBuf::from("/run/user/1001/podman/podman.sock"))
        }
        async fn install_service(
            &self,
            spec: &weglarka_core::platform::ServiceSpec,
        ) -> Result<(), PlatformError> {
            self.installed.lock().unwrap().push(spec.image.clone());
            Ok(())
        }
        async fn remove_service(&self, _: &str) -> Result<(), PlatformError> {
            Ok(())
        }
        async fn service_status(&self, _: &str) -> Result<ServiceStatus, PlatformError> {
            Ok(ServiceStatus::Active)
        }
        async fn install_user_units(&self, _: &[UnitFile]) -> Result<(), PlatformError> {
            Ok(())
        }
        async fn remove_user_units(&self, _: &[&str]) -> Result<(), PlatformError> {
            Ok(())
        }
        async fn restart_service(&self, _: &str) -> Result<(), PlatformError> {
            *self.restarts.lock().unwrap() += 1;
            Ok(())
        }
        async fn set_timer(&self, _: &str, _: bool) -> Result<(), PlatformError> {
            Ok(())
        }
    }

    struct Ctx {
        _dir: tempfile::TempDir,
        settings: Settings,
        podman: FakePodman,
        signer: TestSigner,
        registry: FakeRegistry,
        platform: FakePlatform,
        now: SystemTime,
    }

    impl Ctx {
        fn new(self_update: bool) -> Self {
            let dir = tempfile::Builder::new()
                .prefix("wg")
                .tempdir_in("/tmp")
                .unwrap();
            let root = dir.path().to_owned();
            let signer = TestSigner::generate().unwrap();
            std::fs::write(root.join("cosign.pub"), signer.public_key_pem()).unwrap();
            let section = if self_update {
                format!(
                    "[self_update]\nimage = \"{IMAGE}\"\ninterval_secs = 300\n\
                     public_key_file = \"{pubkey}\"\n",
                    pubkey = root.join("cosign.pub").display()
                )
            } else {
                String::new()
            };
            let host = HostConfig::from_toml_str(&format!(
                r#"
[ingress]
mode = "behind"
bind = "127.0.0.1:18082"
traefik_dynamic_file = "{root}/traefik.yml"

[admin]
socket = "{root}/run/admin.sock"

[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.eu"

[state]
dir = "{root}/state"
{section}
"#,
                root = root.display()
            ))
            .unwrap();
            std::fs::write(root.join("traefik.yml"), "").unwrap();
            let settings = Settings::from_host(host, root.join("weglarka.toml"));
            std::fs::create_dir_all(&settings.paths.state_dir).unwrap();
            Self {
                _dir: dir,
                settings,
                podman: FakePodman::new(),
                signer,
                registry: FakeRegistry::new(),
                platform: FakePlatform::default(),
                now: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000),
            }
        }

        fn image(&self) -> ImageRef {
            ImageRef::parse(IMAGE).unwrap()
        }

        fn state(&self) -> SelfUpdateState {
            state::load(&self.settings.paths.state_dir).unwrap()
        }

        fn save_state(&self, state: &SelfUpdateState) {
            state::save(&self.settings.paths.state_dir, state).unwrap();
        }

        fn pulled_digest(&self, digest: &Digest) {
            self.podman.set_pull_digest(IMAGE, digest.clone());
        }

        fn signed(&self, digest: &Digest) {
            let signature = self.signer.sign_for(&self.image(), digest).unwrap();
            self.registry.push_signature(signature);
        }

        async fn pull_image(&self, digest: &Digest) {
            self.pulled_digest(digest);
            let mut stream = std::pin::pin!(self.podman.image_pull(IMAGE));
            while let Some(event) = stream.next().await {
                event.unwrap();
            }
        }

        async fn run(&self, options: Options) -> Report {
            run(
                &self.podman,
                &self.registry,
                &self.platform,
                &self.settings,
                options,
                self.now,
            )
            .await
            .unwrap()
        }
    }

    fn digest_of(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    #[tokio::test]
    async fn without_the_section_nothing_happens() {
        let ctx = Ctx::new(false);
        assert_eq!(ctx.run(Options::default()).await, Report::Disabled);
        assert!(ctx.podman.calls().is_empty(), "nothing is pulled");
        assert!(ctx.registry.calls().is_empty());
    }

    #[tokio::test]
    async fn the_interval_is_respected_unless_forced() {
        let ctx = Ctx::new(true);
        ctx.save_state(&SelfUpdateState {
            checked_at: Some(state::secs(ctx.now) - 10),
            ..SelfUpdateState::default()
        });
        assert_eq!(ctx.run(Options::default()).await, Report::NotDue);
        assert!(ctx.podman.calls().is_empty());

        // `--force` (or `--check`) is the operator asking now and bypasses the interval.
        let pulled = digest_of('a');
        ctx.pulled_digest(&pulled);
        ctx.signed(&pulled);
        assert!(matches!(
            ctx.run(Options {
                force: true,
                ..Options::default()
            })
            .await,
            Report::Applied { .. }
        ));
    }

    #[tokio::test]
    async fn a_verified_image_is_pinned_and_the_service_restarted() {
        let ctx = Ctx::new(true);
        let digest = digest_of('a');
        ctx.pulled_digest(&digest);
        ctx.signed(&digest);

        let report = ctx.run(Options::default()).await;
        assert_eq!(
            report,
            Report::Applied {
                from: None,
                to: digest.clone()
            }
        );
        assert_eq!(
            ctx.platform.installed_images(),
            vec![format!("ghcr.io/jpalczewski/weglarka@{}", digest.as_str())],
            "the service definition pins the digest, not the tag"
        );
        assert_eq!(ctx.platform.restarts(), 1);
        let state = ctx.state();
        assert_eq!(state.pending, Some(digest), "recorded before the restart");
        assert_eq!(state.pending_at, Some(state::secs(ctx.now)));
        assert_eq!(state.checked_at, Some(state::secs(ctx.now)));
        assert!(state.error.is_none());
    }

    #[tokio::test]
    async fn an_unsigned_image_is_refused_and_nothing_is_touched() {
        let ctx = Ctx::new(true);
        let digest = digest_of('a');
        ctx.pulled_digest(&digest);

        let report = ctx.run(Options::default()).await;
        match &report {
            Report::Refused { reason } => {
                assert!(reason.contains("no key-based cosign signature"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(ctx.platform.installed_images().is_empty());
        assert_eq!(ctx.platform.restarts(), 0);
        let state = ctx.state();
        assert!(state.pending.is_none());
        assert_eq!(
            state.error.as_ref().and_then(|e| e.digest.clone()),
            Some(digest)
        );
        assert!(!report.is_success());
    }

    #[tokio::test]
    async fn a_signature_for_another_digest_is_refused() {
        let ctx = Ctx::new(true);
        let digest = digest_of('a');
        ctx.pulled_digest(&digest);
        // A perfectly valid signature — of a different image.
        ctx.signed(&digest_of('b'));

        match ctx.run(Options::default()).await {
            Report::Refused { reason } => {
                assert!(reason.contains("verification failed"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(ctx.platform.installed_images().is_empty());
    }

    #[tokio::test]
    async fn a_digest_that_already_failed_is_not_retried_until_it_moves() {
        let ctx = Ctx::new(true);
        let pulled = digest_of('a');
        ctx.pulled_digest(&pulled);
        assert!(matches!(
            ctx.run(Options::default()).await,
            Report::Refused { .. }
        ));
        assert_eq!(ctx.registry.calls().len(), 1);

        // Same digest, a later run that bypasses the interval: the registry is not asked again.
        assert!(matches!(
            ctx.run(Options {
                check: true,
                ..Options::default()
            })
            .await,
            Report::Refused { .. }
        ));
        assert_eq!(
            ctx.registry.calls().len(),
            1,
            "no second registry round-trip"
        );

        // `--force` retries it.
        ctx.signed(&pulled);
        assert!(matches!(
            ctx.run(Options {
                force: true,
                ..Options::default()
            })
            .await,
            Report::Applied { .. }
        ));
        assert_eq!(ctx.registry.calls().len(), 2);
    }

    #[tokio::test]
    async fn an_image_below_the_state_schema_is_refused_unless_forced() {
        let ctx = Ctx::new(true);
        let pulled = digest_of('a');
        ctx.pull_image(&pulled).await;
        // The image declares a schema older than the state's (schema 0 is not a real release; the
        // comparator must refuse anything below the state, and `--force` is the documented override).
        ctx.podman.set_pull_labels(IMAGE, &[(SCHEMA_ONE, "0")]);
        ctx.signed(&pulled);

        match ctx.run(Options::default()).await {
            Report::Refused { reason } => {
                assert!(reason.contains("schema 0"), "{reason}");
                assert!(reason.contains("schema 1"), "{reason}");
                assert!(reason.contains("--force"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(ctx.platform.installed_images().is_empty());

        assert!(matches!(
            ctx.run(Options {
                force: true,
                ..Options::default()
            })
            .await,
            Report::Applied { .. }
        ));
        assert_eq!(ctx.platform.restarts(), 1);
    }

    #[tokio::test]
    async fn check_reports_without_touching_the_service() {
        let ctx = Ctx::new(true);
        let digest = digest_of('a');
        ctx.pulled_digest(&digest);
        ctx.signed(&digest);

        assert_eq!(
            ctx.run(Options {
                check: true,
                ..Options::default()
            })
            .await,
            Report::Available {
                from: None,
                to: digest.clone()
            }
        );
        assert!(ctx.platform.installed_images().is_empty());
        assert_eq!(ctx.platform.restarts(), 0);
        assert!(ctx.state().pending.is_none());
        assert_eq!(ctx.state().checked_at, Some(state::secs(ctx.now)));
    }

    #[tokio::test]
    async fn rollback_pins_the_recorded_previous_digest() {
        let ctx = Ctx::new(true);
        let old = digest_of('a');
        let new = digest_of('b');
        // Both images are in the local store: the retention keeps the current and the previous one.
        ctx.pull_image(&old).await;
        ctx.pull_image(&new).await;
        ctx.save_state(&SelfUpdateState {
            current: Some(new.clone()),
            previous: Some(old.clone()),
            checked_at: Some(state::secs(ctx.now)),
            ..SelfUpdateState::default()
        });

        assert_eq!(
            ctx.run(Options {
                rollback: true,
                ..Options::default()
            })
            .await,
            Report::RolledBack {
                from: Some(new.clone()),
                to: old.clone()
            }
        );
        assert_eq!(
            ctx.platform.installed_images(),
            vec![format!("ghcr.io/jpalczewski/weglarka@{}", old.as_str())]
        );
        assert_eq!(ctx.platform.restarts(), 1);
        assert!(ctx.registry.calls().is_empty(), "no registry round-trip");
    }

    #[tokio::test]
    async fn rollback_without_a_previous_image_explains_itself() {
        let ctx = Ctx::new(true);
        match ctx
            .run(Options {
                rollback: true,
                ..Options::default()
            })
            .await
        {
            Report::Refused { reason } => {
                assert!(reason.contains("no previous image"), "{reason}");
                assert!(reason.contains("docs/install.md"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(ctx.platform.restarts(), 0);
    }

    #[tokio::test]
    async fn a_state_from_a_newer_daemon_stops_the_switcher() {
        let ctx = Ctx::new(true);
        // A state.toml written by a newer daemon: this binary must not act on it (ADR 0023).
        std::fs::write(&ctx.settings.paths.state.state, "schema_version = 99\n").unwrap();
        let err = run(
            &ctx.podman,
            &ctx.registry,
            &ctx.platform,
            &ctx.settings,
            Options::default(),
            ctx.now,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("99"), "{err}");
        assert_eq!(ctx.platform.restarts(), 0);
    }

    #[tokio::test]
    async fn an_already_running_digest_is_up_to_date() {
        let ctx = Ctx::new(true);
        let digest = digest_of('a');
        ctx.pulled_digest(&digest);
        ctx.save_state(&SelfUpdateState {
            current: Some(digest.clone()),
            ..SelfUpdateState::default()
        });

        assert_eq!(
            ctx.run(Options::default()).await,
            Report::UpToDate {
                digest: digest.clone()
            }
        );
        assert!(ctx.registry.calls().is_empty());
        assert_eq!(ctx.platform.restarts(), 0);
    }

    #[tokio::test]
    async fn startup_confirmation_tracks_current_and_previous() {
        use weglarka_core::events::VecSink;

        let ctx = Ctx::new(true);
        let running = digest_of('a');
        ctx.pull_image(&running).await;
        ctx.podman
            .add_foreign_container(crate::service::SERVICE_NAME, IMAGE);
        ctx.save_state(&SelfUpdateState {
            current: Some(digest_of('b')),
            pending: Some(running.clone()),
            pending_at: Some(1),
            ..SelfUpdateState::default()
        });

        let sink = VecSink::default();
        let confirmation = confirm_startup(&ctx.podman, &ctx.settings.paths.state_dir, &sink).await;
        assert_eq!(
            confirmation,
            Some(Confirmation::Updated {
                from: Some(digest_of('b')),
                to: running.clone()
            })
        );
        let state = ctx.state();
        assert_eq!(state.current, Some(running));
        assert_eq!(state.previous, Some(digest_of('b')));
        assert!(state.pending.is_none());
        assert_eq!(sink.events().len(), 1, "one SelfUpdated event");
    }

    #[test]
    fn options_are_off_by_default() {
        let options = Options::default();
        assert!(!options.check && !options.force && !options.rollback);
    }

    #[test]
    fn service_name_is_the_container_name_used_by_the_confirmation() {
        assert_eq!(SERVICE_NAME, "weglarka");
    }
}
