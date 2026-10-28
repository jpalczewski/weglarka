//! The generated config pipeline (#212): render → write → validate → swap → apply, for a consumer
//! app that reads files Węglarka renders (the identity provider's access rules and OIDC clients).
//!
//! Layout, per consumer: `<state dir>/generated/<consumer>/v-<fingerprint12>/…` plus a relative
//! symlink `current` to the live version. The parent directory is what the consumer mounts
//! read-only, so a new version is visible inside its mount the moment it is written — validation
//! needs no extra mount — and the swap is one `rename` over `current`.
//!
//! Everything runs under **one** acquisition of the engine lock and calls only `*_locked`
//! operations ([`EngineGuard`] makes that a compile-time fact): the lock is not re-entrant.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use weglarka_model::app::{AppSpec, AppsFile, InstanceName};
use weglarka_model::events::Event;
use weglarka_model::generated::{
    CURRENT_LINK, ConfigGenerator, Fingerprint, GeneratedFile, RenderInput, VERSION_PREFIX,
};
use weglarka_model::generated_state::{self, GeneratedState, GeneratorRecord, LastResult, tail};
use weglarka_model::labels;
use weglarka_model::podman::{ContainerState, PodmanClient, PodmanError};
use weglarka_model::secret_ops::Pbkdf2Digest;
use weglarka_model::state;

use crate::reconcile::{EngineError, EngineGuard, Reconciler};
use crate::run::{RunOptions, RunOutcome};

/// Where the consumer sees the parent of its versions (`<state dir>/generated/<consumer>`).
pub const MOUNT_TARGET: &str = "/weglarka/generated";
/// The validator is a config parse, not a job: anything longer is a hang.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(60);
/// The part of the validator output that goes into the event, hence to external notification
/// channels. The full tail stays in the 0600 state file and `doctor`.
const EVENT_OUTPUT_LIMIT: usize = 1024;
/// How much validator output is captured before masking and cutting it to [`OUTPUT_LIMIT`]. It is
/// far above any secret's length. The leftover of a value the window did cut sits in the first bytes
/// of the buffer; [`trim_edge`] drops them before masking.
const CAPTURE_LIMIT: usize = 64 * 1024;
/// Bytes dropped at the start of a capture window that cut the output, so that the leftover of a
/// secret the cut went through is gone. Well above any secret.
const SCRUB_MARGIN: usize = 4 * 1024;
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;

/// Credential digests (#213) for the apps in `AppsFile`; the pipeline never sees a secret value.
pub type DigestProvider = dyn Fn(&AppsFile) -> BTreeMap<InstanceName, Pbkdf2Digest> + Send + Sync;

/// The generators the engine knows, and where their credential digests come from. Used by the
/// bootstrap, which has to render from inside a deploy.
pub struct GeneratedWiring {
    pub generators: Vec<Arc<dyn ConfigGenerator>>,
    pub digests: Arc<DigestProvider>,
}

/// What one pass of [`Reconciler::apply_generated`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneratedOutcome {
    /// The render equals the version already applied.
    Unchanged,
    /// This exact render failed before (invalid, rolled back or not applicable) and is not repeated
    /// until it changes or the pass is forced.
    Skipped { last: LastResult },
    Applied {
        fingerprint: Fingerprint,
        /// The validator ran and passed (`false` for a consumer with no deployed digest or no validator).
        validated: bool,
        /// The consumer was running and was told to reload; `false` = it picks the files up on start.
        reloaded: bool,
    },
    /// The validator rejected the render; the live version is unchanged.
    Invalid { output: String },
    /// The consumer failed its health gate; the previous version is live again.
    RolledBack {
        fingerprint: Fingerprint,
        reason: String,
    },
}

impl<P: PodmanClient> Reconciler<P> {
    /// Renders `generator` and, when the output changed, puts it live in the consumer. `digests`
    /// yields the credential digests (#213) the render may use; it runs **under the engine lock**,
    /// so minting a missing credential cannot race another writer of the secret store. `force`
    /// retries a render that failed before.
    pub async fn apply_generated(
        self: &Arc<Self>,
        generator: &dyn ConfigGenerator,
        digests: &DigestProvider,
        force: bool,
    ) -> Result<GeneratedOutcome, EngineError> {
        let guard = self.acquire().await;
        self.apply_generated_locked(&guard, generator, digests, force)
            .await
    }

    pub(crate) async fn apply_generated_locked(
        self: &Arc<Self>,
        guard: &EngineGuard<'_>,
        generator: &dyn ConfigGenerator,
        digests: &DigestProvider,
        force: bool,
    ) -> Result<GeneratedOutcome, EngineError> {
        let id = generator.id();
        let consumer = generator.consumer().clone();
        let fail = |message: String| EngineError::Generated {
            consumer: consumer.clone(),
            message,
        };
        let apps = state::load_apps(&self.paths.apps)?;
        let spec = apps
            .apps
            .get(&consumer)
            .cloned()
            .ok_or_else(|| EngineError::UnknownInstance(consumer.clone()))?;

        // 1. Render. Equal to what is applied (and live) = nothing to do.
        let digests = digests(&apps);
        let files = generator.render(&RenderInput {
            apps: &apps,
            digests: &digests,
        })?;
        let fp = Fingerprint::of(id, &files)?;
        let want = fp.version_dir();
        let root = self.generated_dir(&consumer);
        let mut gstate = GeneratedState::load(&self.generated_state_path());
        let record = gstate.get(id).cloned().unwrap_or_default();
        let live = current_target(&root);

        if record.applied_fingerprint().as_ref() == Some(&fp) && live.as_deref() == Some(&want) {
            return Ok(GeneratedOutcome::Unchanged);
        }
        if !force
            && record.attempted.as_deref() == Some(fp.as_str())
            && matches!(
                record.last_result,
                LastResult::Invalid | LastResult::RolledBack | LastResult::Failed
            )
        {
            return Ok(GeneratedOutcome::Skipped {
                last: record.last_result,
            });
        }

        // `current` already points at this render but nothing recorded it as applied: the daemon
        // died between the swap and the apply. Skip straight to applying.
        let recovering = live.as_deref() == Some(&want);
        let previous = if recovering {
            record
                .applied_fingerprint()
                .map(|f| f.version_dir())
                .filter(|d| root.join(d).is_dir())
        } else {
            live.clone()
        };
        let mut validated = false;

        if !recovering {
            // 2. Write the version.
            write_version(&root, &want, &files)
                .map_err(|e| fail(format!("cannot write {}: {e}", root.join(&want).display())))?;

            // 3. Validate.
            match self
                .validate_generated(guard, generator, &spec, &consumer, &want)
                .await?
            {
                Some(Err(output)) => {
                    // Already masked and edge-trimmed by `validate_generated`: the validator ran with
                    // the consumer's secrets bound, so a value it echoes must not reach the state
                    // file, the log or a notification channel.
                    let output = tail(&output).to_owned();
                    self.record_generated(&mut gstate, id, |r| {
                        r.attempted = Some(fp.to_string());
                        r.last_result = LastResult::Invalid;
                        r.last_error = Some(output.clone());
                    });
                    self.events.emit(Event::GeneratedConfigInvalid {
                        id: id.to_owned(),
                        consumer: consumer.clone(),
                        output: tail_bytes(&output, EVENT_OUTPUT_LIMIT).to_owned(),
                    });
                    retain_versions(&root, &[live.as_deref(), Some(&want)]);
                    return Ok(GeneratedOutcome::Invalid { output });
                }
                Some(Ok(())) => validated = true,
                None => {}
            }

            // 4. Swap: one atomic rename.
            swap_current(&root, &want)
                .map_err(|e| fail(format!("cannot switch {CURRENT_LINK}: {e}")))?;
        }

        // 5. Apply.
        let (reloaded, health) = self.apply_to_consumer(guard, &consumer, &spec).await?;
        match health {
            Ok(()) => {
                self.record_generated(&mut gstate, id, |r| {
                    r.applied = Some(fp.to_string());
                    r.attempted = Some(fp.to_string());
                    r.validated = validated;
                    r.last_result = LastResult::Applied;
                    r.last_error = None;
                });
                self.events.emit(Event::GeneratedConfigApplied {
                    id: id.to_owned(),
                    consumer: consumer.clone(),
                    fingerprint: fp.to_string(),
                    validated,
                });
                retain_versions(&root, &[Some(&want), previous.as_deref()]);
                Ok(GeneratedOutcome::Applied {
                    fingerprint: fp,
                    validated,
                    reloaded,
                })
            }
            // 6. The consumer is unhealthy on the new version: one attempt to go back, no loop.
            Err(reason) => {
                let Some(prev) = previous else {
                    self.record_generated(&mut gstate, id, |r| {
                        r.attempted = Some(fp.to_string());
                        r.last_result = LastResult::Failed;
                        r.last_error = Some(tail(&reason).to_owned());
                    });
                    return Err(fail(format!(
                        "the consumer is unhealthy on {want} and there is no previous version: {reason}"
                    )));
                };
                swap_current(&root, &prev)
                    .map_err(|e| fail(format!("cannot switch {CURRENT_LINK} back: {e}")))?;
                let mut note = reason.clone();
                match self.apply_to_consumer(guard, &consumer, &spec).await {
                    Ok((_, Ok(()))) => {}
                    Ok((_, Err(e))) | Err(EngineError::Generated { message: e, .. }) => {
                        note = format!("{note}; still unhealthy after going back: {e}");
                    }
                    Err(e) => note = format!("{note}; cannot reload after going back: {e}"),
                }
                self.record_generated(&mut gstate, id, |r| {
                    r.attempted = Some(fp.to_string());
                    r.last_result = LastResult::RolledBack;
                    r.last_error = Some(tail(&note).to_owned());
                });
                self.events.emit(Event::GeneratedConfigRolledBack {
                    id: id.to_owned(),
                    consumer: consumer.clone(),
                });
                retain_versions(&root, &[Some(&prev), Some(&want)]);
                Ok(GeneratedOutcome::RolledBack {
                    fingerprint: fp,
                    reason,
                })
            }
        }
    }

    /// Runs the generator's validator in a one-off container of the consumer, against the new
    /// version. `None` = nothing to validate with: no validator, or the consumer was never deployed
    /// (no pinned digest to run). `Some(Err(output))` = the validator rejected the render.
    async fn validate_generated(
        self: &Arc<Self>,
        guard: &EngineGuard<'_>,
        generator: &dyn ConfigGenerator,
        spec: &AppSpec,
        consumer: &InstanceName,
        version: &str,
    ) -> Result<Option<Result<(), String>>, EngineError> {
        let dir = format!("{MOUNT_TARGET}/{version}");
        let Some(argv) = generator.validate_argv(spec, &dir) else {
            return Ok(None);
        };
        let Some((program, args)) = argv.split_first() else {
            return Ok(None);
        };
        let deployed = state::load_state(&self.paths.state)?
            .apps
            .get(consumer)
            .is_some_and(|s| s.current.is_some());
        if !deployed {
            return Ok(None);
        }
        let options = RunOptions {
            command: args.to_vec(),
            entrypoint: Some(vec![program.clone()]),
            timeout: Some(VALIDATE_TIMEOUT),
            ..Default::default()
        };
        let pending = self.prepare_run_locked(guard, consumer, &options).await?;
        let (tx, mut rx) = mpsc::channel::<weglarka_model::podman::LogChunk>(64);
        let collect = async {
            // Only the end of the output is kept: that is where a validator names what is wrong.
            let mut buf: Vec<u8> = Vec::new();
            let mut window_cut = false;
            while let Some(chunk) = rx.recv().await {
                buf.extend_from_slice(&chunk.data);
                if buf.len() > CAPTURE_LIMIT {
                    buf.drain(..buf.len() - CAPTURE_LIMIT);
                    window_cut = true;
                }
            }
            (String::from_utf8_lossy(&buf).into_owned(), window_cut)
        };
        let (outcome, (output, window_cut)) = tokio::join!(pending.drive(tx), collect);
        // Mask the whole capture, then drop the start the capture window may have cut through. The
        // order matters: dropping first would leave a new, arbitrary start that can split a secret
        // just as well, and a cut after masking cannot expose one.
        let masked = self.scrub_secrets(consumer, spec, &output);
        let output = trim_edge(&masked, window_cut);
        Ok(Some(match outcome? {
            RunOutcome::Exited(0) => Ok(()),
            RunOutcome::Exited(code) => Err(format!("validator exited with code {code}\n{output}")),
            RunOutcome::TimedOut => Err(format!(
                "validator did not finish within {}s\n{output}",
                VALIDATE_TIMEOUT.as_secs()
            )),
            RunOutcome::Cancelled => Err(format!("validator was cancelled\n{output}")),
        }))
    }

    /// Masks the values of the consumer's bound secrets (4+ bytes, so a one-character value does not
    /// shred the text) in `output`, longest first so a secret that contains another is not left half
    /// visible; a value is also masked without its trailing whitespace. Runs on the captured output
    /// *before* it is cut to the reported tail. A secret that cannot be read masks nothing, and
    /// encodings of a value (JSON escapes, URL encoding) are not recognised.
    fn scrub_secrets(&self, consumer: &InstanceName, spec: &AppSpec, output: &str) -> String {
        let mut values = std::collections::BTreeSet::new();
        for binding in &spec.secrets {
            let name = weglarka_model::secret_store::scoped_name(consumer, &binding.secret);
            if let Ok(Some(value)) = self.secrets.get(&name)
                && let Ok(plain) = std::str::from_utf8(value.expose())
            {
                for candidate in [plain, plain.trim_end()] {
                    if candidate.len() >= 4 {
                        values.insert(candidate.to_owned());
                    }
                }
            }
        }
        let mut values: Vec<String> = values.into_iter().collect();
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        values
            .iter()
            .fold(output.to_owned(), |text, v| text.replace(v.as_str(), "***"))
    }

    /// A running consumer reloads (a signal or a restart, per its spec) and must pass the health
    /// gate; a stopped or never-deployed one counts as applied — the files are live and its next
    /// start reads them. Returns whether it reloaded, and the gate's verdict.
    async fn apply_to_consumer(
        &self,
        guard: &EngineGuard<'_>,
        consumer: &InstanceName,
        spec: &AppSpec,
    ) -> Result<(bool, Result<(), String>), EngineError> {
        let name = labels::container_name(consumer);
        match self.podman.container_inspect(&name).await {
            Ok(info) if info.state == ContainerState::Running => {}
            Ok(_) | Err(PodmanError::NotFound(_)) => return Ok((false, Ok(()))),
            Err(e) => return Err(e.into()),
        }
        self.reload_locked(guard, consumer).await?;
        Ok((true, self.health_gate(&name, spec).await))
    }

    /// Bootstrap: the files exist before the consumer's **first** start (the identity provider
    /// refuses to start without its access rules). Renders, writes and swaps only when `current` does
    /// not exist yet; validation is impossible without a deployed digest, so the version is recorded
    /// as unvalidated — the consumer's own start is the validation, and a bad render shows up as a
    /// failed deploy with the provider's logs. Called under the engine lock from the launch paths.
    pub(crate) async fn bootstrap_generated(
        &self,
        instance: &InstanceName,
    ) -> Result<(), EngineError> {
        let Some(wiring) = &self.generated else {
            return Ok(());
        };
        for generator in wiring
            .generators
            .iter()
            .filter(|g| g.consumer() == instance)
        {
            let root = self.generated_dir(instance);
            if current_target(&root).is_some() {
                continue;
            }
            let id = generator.id();
            let apps = state::load_apps(&self.paths.apps)?;
            let digests = (wiring.digests)(&apps);
            let files = generator.render(&RenderInput {
                apps: &apps,
                digests: &digests,
            })?;
            let fp = Fingerprint::of(id, &files)?;
            let fail = |message: String| EngineError::Generated {
                consumer: instance.clone(),
                message,
            };
            write_version(&root, &fp.version_dir(), &files).map_err(|e| fail(e.to_string()))?;
            swap_current(&root, &fp.version_dir()).map_err(|e| fail(e.to_string()))?;
            let mut gstate = GeneratedState::load(&self.generated_state_path());
            self.record_generated(&mut gstate, id, |r| {
                r.applied = Some(fp.to_string());
                r.attempted = Some(fp.to_string());
                r.validated = false;
                r.last_result = LastResult::Applied;
                r.last_error = None;
            });
            self.events.emit(Event::GeneratedConfigApplied {
                id: id.to_owned(),
                consumer: instance.clone(),
                fingerprint: fp.to_string(),
                validated: false,
            });
        }
        Ok(())
    }

    /// Whether a registered generator renders files for `instance`.
    pub(crate) fn is_generated_consumer(&self, instance: &InstanceName) -> bool {
        self.generated
            .as_ref()
            .is_some_and(|w| w.generators.iter().any(|g| g.consumer() == instance))
    }

    /// The read-only bind of a consumer's generated directory at [`MOUNT_TARGET`] (none for any
    /// other app). The directory is created so the bind source exists before the first render; the
    /// canonical path is what mounts, like every host-side mount (ADR 0028). Its parent — not a
    /// single version — is mounted, so a new version and the `current` swap are visible live.
    pub(crate) fn generated_mounts(
        &self,
        instance: &InstanceName,
    ) -> Result<Vec<crate::config_mounts::Resolved>, EngineError> {
        if !self.is_generated_consumer(instance) {
            return Ok(vec![]);
        }
        let dir = self.generated_dir(instance);
        let fail = |e: io::Error| EngineError::Generated {
            consumer: instance.clone(),
            message: format!("cannot prepare {}: {e}", dir.display()),
        };
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&dir)
            .map_err(fail)?;
        Ok(vec![crate::config_mounts::Resolved {
            source: fs::canonicalize(&dir).map_err(fail)?,
            target: MOUNT_TARGET.to_owned(),
        }])
    }

    /// The version directory `current` points at for `consumer` (`v-<fingerprint12>`), for `doctor`.
    pub fn generated_live_version(&self, consumer: &InstanceName) -> Option<String> {
        current_target(&self.generated_dir(consumer))
    }

    /// `<state dir>/generated/<consumer>`.
    pub fn generated_dir(&self, consumer: &InstanceName) -> PathBuf {
        self.state_dir()
            .join("generated")
            .join(consumer.to_string())
    }

    fn generated_state_path(&self) -> PathBuf {
        self.state_dir().join(generated_state::FILE_NAME)
    }

    fn state_dir(&self) -> &Path {
        self.paths.state.parent().unwrap_or_else(|| Path::new("."))
    }

    /// Updates one generator's record and persists it. A failed write only warns: the bookkeeping
    /// must not undo a version that is already live (a restart re-applies from `current`).
    fn record_generated(
        &self,
        gstate: &mut GeneratedState,
        id: &str,
        update: impl FnOnce(&mut GeneratorRecord),
    ) {
        update(gstate.entry(id));
        if let Err(e) = gstate.save(&self.generated_state_path()) {
            tracing::warn!(generator = id, error = %e, "cannot persist the generated-config state");
        }
    }
}

/// Drops the first `SCRUB_MARGIN` bytes of already **masked** output when the capture window cut it:
/// the start may be the tail of a secret that masking could not recognise. Masking only shrinks the
/// text and leaves nothing to expose, so this is safe however much it shrank (possibly to nothing).
fn trim_edge(output: &str, window_cut: bool) -> &str {
    if !window_cut {
        return output;
    }
    let mut start = SCRUB_MARGIN.min(output.len());
    while !output.is_char_boundary(start) {
        start += 1;
    }
    &output[start..]
}

/// The last `limit` bytes of `text`, cut on a character boundary.
fn tail_bytes(text: &str, limit: usize) -> &str {
    let mut start = text.len().saturating_sub(limit);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

/// The directory name `current` points at, if the link exists.
pub(crate) fn current_target(root: &Path) -> Option<String> {
    fs::read_link(root.join(CURRENT_LINK))
        .ok()
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Writes `files` as `root/version/`, reusing a directory that already holds exactly this content.
/// Built in `<version>.tmp` and renamed into place, so a crash never leaves a half-written version
/// under its final name.
pub(crate) fn write_version(root: &Path, version: &str, files: &[GeneratedFile]) -> io::Result<()> {
    let target = root.join(version);
    if target.is_dir() && same_content(&target, files) {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(root)?;
    let tmp = root.join(format!("{version}.tmp"));
    remove_dir_if_exists(&tmp)?;
    remove_dir_if_exists(&target)?;
    fs::DirBuilder::new().mode(DIR_MODE).create(&tmp)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(DIR_MODE))?;
    for file in files {
        weglarka_model::fsutil::write_atomic(
            &tmp.join(file.name().as_str()),
            file.bytes(),
            FILE_MODE,
        )?;
    }
    fs::rename(&tmp, &target)
}

fn same_content(dir: &Path, files: &[GeneratedFile]) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.count() == files.len()
        && files
            .iter()
            .all(|f| fs::read(dir.join(f.name().as_str())).is_ok_and(|b| b == f.bytes()))
}

fn remove_dir_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Points `current` at `version` with one `rename` of a fresh relative symlink over it.
pub(crate) fn swap_current(root: &Path, version: &str) -> io::Result<()> {
    let tmp = root.join(format!("{CURRENT_LINK}.tmp"));
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    symlink(version, &tmp)?;
    fs::rename(&tmp, root.join(CURRENT_LINK))
}

/// Removes every version directory (and leftover `.tmp`) not named in `keep`. Best effort.
fn retain_versions(root: &Path, keep: &[Option<&str>]) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let stale_version =
            name.starts_with(VERSION_PREFIX) && !keep.iter().flatten().any(|k| *k == name);
        if (stale_version || name.ends_with(".tmp"))
            && let Err(e) = fs::remove_dir_all(entry.path())
        {
            tracing::debug!(path = %entry.path().display(), error = %e, "cannot remove an old generated version");
        }
    }
}
