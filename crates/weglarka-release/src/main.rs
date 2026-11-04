//! `weglarka-release` — the publisher-side sibling of the runtime verifier.
//!
//! Contract: [`docs/contracts/platform-update-v1`](../../docs/contracts/platform-update-v1/README.md)
//! and ADR 0067. The publisher and the runtime verifier are one implementation: both use
//! [`weglarka_model::release_set`] and the registry client from `weglarka-registry`, never an ad-hoc
//! JSON pipeline.
//!
//! Subcommands:
//!
//! - `assemble` builds the descriptor and its OCI manifest offline (fixtures, local inspection).
//! - `publish` allocates the per-channel sequence, pushes the immutable set tag under a legacy
//!   cosign signature, verifies the published bytes with the runtime verifier, and then moves the
//!   channel pointer forward.
//! - `verify` re-runs the runtime verifier against a published channel, set tag or digest.
//! - `reconcile` moves a channel pointer to the highest complete set above it (the
//!   post-promotion check for a superseded, queued run).

mod assemble;
mod publish;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use weglarka_model::release_set::{Channel, Compatibility, DescriptorContext, StrictDigest};
use weglarka_registry::{DEFAULT_PUBLIC_KEY_PEM, HttpRegistry, PublicKey, SigningKey};

use crate::assemble::{ReleaseSpec, ReuseComponent, component, crate_version, host_file};

#[derive(Debug, Parser)]
#[command(
    name = "weglarka-release",
    about = "Assemble, publish and verify signed Węglarka release sets (v1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Assemble and validate the descriptor and OCI manifest offline.
    Assemble(AssembleArgs),
    /// Allocate a sequence and push the immutable set (the workflow signs it with cosign next).
    Publish(PublishArgs),
    /// Verify an immutable set and move the channel pointer to it.
    Promote(PromoteArgs),
    /// Verify a published release set with the runtime verifier.
    ///
    /// Exit codes: 0 verified; 3 the channel tag itself (`main`/`stable`) does not exist, i.e. the
    /// channel has never been released; 1 any other failure (including other "not found"
    /// answers such as a missing blob or signature); 2 usage error.
    Verify(VerifyArgs),
    /// Move the channel pointer to the highest complete set above it.
    Reconcile(ReconcileArgs),
}

#[derive(Debug, clap::Args)]
struct DescriptorArgs {
    /// Channel to publish; `stable` and `main` never substitute for each other.
    #[arg(long, value_parser = parse_channel)]
    channel: Channel,
    /// Full 40-character lower-case source commit ID.
    #[arg(long)]
    revision: String,
    /// Daemon image repository (tag-free); omitted only with `--reuse-daemon`.
    #[arg(long)]
    daemon_repository: Option<String>,
    /// Daemon image manifest digest; omitted only with `--reuse-daemon`.
    #[arg(long)]
    daemon_digest: Option<String>,
    /// Panel image repository (tag-free); omitted only with `--reuse-panel`.
    #[arg(long)]
    panel_repository: Option<String>,
    /// Panel image manifest digest; omitted only with `--reuse-panel`.
    #[arg(long)]
    panel_digest: Option<String>,
    /// Directory of the daemon crate; its `[package] version` is the daemon component version.
    #[arg(long, default_value = assemble::DAEMON_CRATE)]
    daemon_crate: PathBuf,
    /// Directory of the panel crate; its `[package] version` is the panel component version.
    #[arg(long, default_value = assemble::PANEL_CRATE)]
    panel_crate: PathBuf,
    /// Directory of the CLI crate; its `[package] version` is the host CLI file version.
    #[arg(long, default_value = assemble::CLI_CRATE)]
    cli_crate: PathBuf,
    /// Directory holding the musl `weglarka-daemon` and `weglarka` binaries that the daemon image
    /// contains (the same artifact the image was built from).
    #[arg(long, default_value = "bin")]
    host_bin_dir: PathBuf,
    /// State schema the target daemon can read (repeatable); omitted only with `--reuse-daemon`.
    #[arg(long = "state-read")]
    state_read: Option<Vec<u32>>,
    /// State schema the target daemon writes; omitted only with `--reuse-daemon`.
    #[arg(long)]
    state_write: Option<u32>,
    /// Panel digest tested against this daemon (repeatable). The selected panel must be present.
    #[arg(long = "panel-tested")]
    panel_tested: Vec<String>,
    /// Reuse the daemon image, host-file records and state schemas from the current channel
    /// pointer (panel-only release: the daemon artifact is unchanged and must not be relabeled).
    #[arg(
        long,
        conflicts_with_all = ["daemon_repository", "daemon_digest", "state_read", "state_write"]
    )]
    reuse_daemon: bool,
    /// Reuse the panel image (its digest and version) from the current channel pointer (CLI-only
    /// release: the panel artifact is unchanged).
    #[arg(long, conflicts_with_all = ["panel_repository", "panel_digest"])]
    reuse_panel: bool,
}

/// The parts of a spec that are always known from the command line. A partial release (panel-only
/// or CLI-only) has one component unset; it is completed from the current pointer before anything
/// is serialized.
struct PartialSpec {
    channel: Channel,
    revision: String,
    daemon: Option<weglarka_model::release_set::Component>,
    panel: Option<weglarka_model::release_set::Component>,
    host_files: Vec<weglarka_model::release_set::HostFile>,
    state_read: Option<Vec<u32>>,
    state_write: Option<u32>,
    panel_tested: Vec<StrictDigest>,
}

impl PartialSpec {
    /// Completes a partial release from `previous` and validates the compatibility list against
    /// the selected panel. Every component this release does not build is copied by
    /// [`ReleaseSpec::reuse`]; this function never invents a component identity.
    fn complete(
        self,
        previous: Option<&weglarka_model::release_set::Descriptor>,
    ) -> Result<ReleaseSpec> {
        let reused = |what: &str| {
            previous.with_context(|| {
                format!("no {what} component was given and there is no existing pointer to reuse")
            })
        };
        if self.daemon.is_some() && (self.state_read.is_none() || self.state_write.is_none()) {
            bail!("--state-read and --state-write are required unless --reuse-daemon is set");
        }
        // A reused component only needs a value of the right shape here; `reuse` below replaces it
        // with the previous record, so the copy lives in one place.
        let mut spec = ReleaseSpec {
            channel: self.channel,
            revision: self.revision,
            daemon: match &self.daemon {
                Some(daemon) => daemon.clone(),
                None => reused("daemon")?.daemon.clone(),
            },
            panel: match &self.panel {
                Some(panel) => panel.clone(),
                None => reused("panel")?.panel.clone(),
            },
            host_files: self.host_files,
            compatibility: Compatibility {
                host_protocol: 1,
                state_read: self.state_read.unwrap_or_default(),
                state_write: self.state_write.unwrap_or_default(),
                panel_digests: Vec::new(),
            },
        };
        if self.daemon.is_none() {
            spec.reuse(ReuseComponent::Daemon, reused("daemon")?);
        }
        if self.panel.is_none() {
            spec.reuse(ReuseComponent::Panel, reused("panel")?);
        }
        spec.compatibility = assemble::compatibility(
            spec.compatibility.state_read,
            spec.compatibility.state_write,
            self.panel_tested,
            &spec.panel.digest,
        )?;
        Ok(spec)
    }
}

impl DescriptorArgs {
    fn spec(&self) -> Result<PartialSpec> {
        let daemon_version = crate_version(&self.daemon_crate)?;
        let panel_version = crate_version(&self.panel_crate)?;
        let cli_version = crate_version(&self.cli_crate)?;
        let daemon = match (&self.daemon_repository, &self.daemon_digest) {
            (Some(repository), Some(digest)) => {
                Some(component(repository, digest, &daemon_version)?)
            }
            (None, None) if self.reuse_daemon => None,
            _ => bail!(
                "--daemon-repository and --daemon-digest are required unless --reuse-daemon is set"
            ),
        };
        let panel = match (&self.panel_repository, &self.panel_digest) {
            (Some(repository), Some(digest)) => {
                Some(component(repository, digest, &panel_version)?)
            }
            (None, None) if self.reuse_panel => None,
            _ => bail!(
                "--panel-repository and --panel-digest are required unless --reuse-panel is set"
            ),
        };
        let host_files = if self.reuse_daemon {
            Vec::new()
        } else {
            vec![
                host_file(
                    "weglarka-daemon",
                    &self.host_bin_dir.join("weglarka-daemon"),
                    &daemon_version,
                )?,
                host_file(
                    "weglarka",
                    &self.host_bin_dir.join("weglarka"),
                    &cli_version,
                )?,
            ]
        };
        let panel_tested = self
            .panel_tested
            .iter()
            .map(|value| strict_digest(value, "tested panel digest"))
            .collect::<Result<Vec<_>>>()?;
        Ok(PartialSpec {
            channel: self.channel,
            revision: self.revision.clone(),
            daemon,
            panel,
            host_files,
            state_read: self.state_read.clone(),
            state_write: self.state_write,
            panel_tested,
        })
    }
}

#[derive(Debug, clap::Args)]
struct AssembleArgs {
    #[command(flatten)]
    descriptor: DescriptorArgs,
    /// Where to write the descriptor layer JSON.
    #[arg(long)]
    output: PathBuf,
    /// Where to write the OCI manifest JSON (optional).
    #[arg(long)]
    manifest_output: Option<PathBuf>,
    /// Sequence to assemble; publishing allocates it instead.
    #[arg(long)]
    sequence: u64,
}

#[derive(Debug, clap::Args)]
struct PublishArgs {
    #[command(flatten)]
    descriptor: DescriptorArgs,
    /// Release-set repository (`host/owner/name`).
    #[arg(long, default_value = assemble::RELEASE_REPOSITORY)]
    release_repository: String,
    /// Unencrypted PKCS#8 PEM of the P-256 release key. Omit in CI: `cosign sign` attaches the
    /// signature with the existing static key and `promote` then verifies it before the pointer
    /// moves.
    #[arg(long)]
    signing_key: Option<PathBuf>,
    /// Pinned public key to compare the signing key against (defaults to the embedded `cosign.pub`).
    #[arg(long)]
    public_key: Option<PathBuf>,
    #[command(flatten)]
    auth: RegistryAuth,
    /// Pin the sequence instead of allocating it; it must still be free and at least the next one.
    #[arg(long)]
    sequence: Option<u64>,
    /// Daemon image digest the compatibility job tested. Publishing fails before anything is pushed
    /// when the release set would carry another daemon (including a reused one).
    #[arg(long, value_name = "DIGEST")]
    expect_daemon_digest: Option<String>,
    /// Report the written set as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct PromoteArgs {
    /// Channel whose pointer should move.
    #[arg(long, value_parser = parse_channel)]
    channel: Channel,
    /// Immutable set tag (`set-<channel>-<sequence>`).
    #[arg(long)]
    tag: String,
    /// Release-set repository (`host/owner/name`).
    #[arg(long, default_value = assemble::RELEASE_REPOSITORY)]
    release_repository: String,
    /// Pinned public key PEM; defaults to the embedded `cosign.pub`.
    #[arg(long)]
    public_key: Option<PathBuf>,
    #[command(flatten)]
    auth: RegistryAuth,
    /// Report the promotion as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// Tag or digest of the release-set manifest (`stable`, `set-stable-3`, `sha256:…`).
    #[arg(default_value = "")]
    reference: String,
    /// Channel to bind the descriptor to; defaults to the reference when that is a channel tag.
    #[arg(long, value_parser = parse_channel)]
    channel: Option<Channel>,
    /// Release-set repository (`host/owner/name`).
    #[arg(long, default_value = assemble::RELEASE_REPOSITORY)]
    release_repository: String,
    /// Pinned public key PEM; defaults to the embedded `cosign.pub`.
    #[arg(long)]
    public_key: Option<PathBuf>,
    #[command(flatten)]
    auth: RegistryAuth,
    /// Print a machine-readable summary (used by the workflow for ancestry and reuse decisions).
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
struct ReconcileArgs {
    /// Channel whose pointer should catch up.
    #[arg(long, value_parser = parse_channel)]
    channel: Channel,
    /// Release-set repository (`host/owner/name`).
    #[arg(long, default_value = assemble::RELEASE_REPOSITORY)]
    release_repository: String,
    /// Pinned public key PEM; defaults to the embedded `cosign.pub`.
    #[arg(long)]
    public_key: Option<PathBuf>,
    #[command(flatten)]
    auth: RegistryAuth,
}

fn parse_channel(value: &str) -> Result<Channel, String> {
    Channel::parse(value)
        .ok_or_else(|| format!("unknown channel {value:?}; expected stable or main"))
}

fn strict_digest(value: &str, what: &str) -> Result<StrictDigest> {
    StrictDigest::new(value).map_err(|error| anyhow::anyhow!("invalid {what}: {error}"))
}

fn repository(value: &str) -> Result<weglarka_model::release_set::Repository> {
    weglarka_model::release_set::Repository::new(value)
        .map_err(|error| anyhow::anyhow!("invalid release repository: {error}"))
}

fn public_key(path: Option<&PathBuf>) -> Result<PublicKey> {
    match path {
        None => Ok(PublicKey::from_pem(DEFAULT_PUBLIC_KEY_PEM)?),
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            Ok(PublicKey::from_pem(&text)?)
        }
    }
}

fn signing_key(path: &PathBuf) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the signing key {}", path.display()))?;
    Ok(SigningKey::from_pem(&text)?)
}

/// Registry credentials shared by every subcommand. Publishing needs a token; verifying works
/// anonymously for a public package, but CI passes the workflow token so the first push and the
/// verification of a still-private package both work.
#[derive(Debug, clap::Args)]
struct RegistryAuth {
    /// Registry user for the token endpoint (GHCR: the workflow actor).
    #[arg(long)]
    registry_user: Option<String>,
    /// Environment variable holding the registry token.
    #[arg(long, default_value = "GITHUB_TOKEN")]
    registry_token_env: String,
}

impl RegistryAuth {
    fn client(&self) -> Result<HttpRegistry> {
        let token = std::env::var(&self.registry_token_env).ok();
        match (self.registry_user.as_deref(), token.as_deref()) {
            (Some(user), Some(token)) if !token.is_empty() => {
                Ok(HttpRegistry::with_basic_credentials(user, token)?)
            }
            (Some(_), _) => bail!(
                "--registry-user is set but {} is empty; the registry needs a token",
                self.registry_token_env
            ),
            (None, _) => Ok(HttpRegistry::new()?),
        }
    }
}

/// Exit code of every failure that has no dedicated code.
const EXIT_FAILURE: u8 = 1;
/// `verify` found no manifest under the channel tag itself: the channel has never been released.
/// The release workflow switches on this to allow a first release. Usage errors exit 2 (clap).
const EXIT_CHANNEL_TAG_MISSING: u8 = 3;

fn main() -> ExitCode {
    match try_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            ExitCode::from(exit_code(&error))
        }
    }
}

/// Maps a failure to the process exit code: [`EXIT_CHANNEL_TAG_MISSING`] only for a missing
/// channel tag, [`EXIT_FAILURE`] for everything else (auth, network, a missing blob or signature).
fn exit_code(error: &anyhow::Error) -> u8 {
    if error.downcast_ref::<publish::ChannelTagMissing>().is_some() {
        EXIT_CHANNEL_TAG_MISSING
    } else {
        EXIT_FAILURE
    }
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();
    // The registry client is async; the binary is otherwise synchronous and one-shot.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Assemble(args) => assemble_command(args),
        Command::Publish(args) => publish_command(args).await,
        Command::Promote(args) => promote_command(args).await,
        Command::Verify(args) => verify_command(args).await,
        Command::Reconcile(args) => reconcile_command(args).await,
    }
}

fn assemble_command(args: AssembleArgs) -> Result<()> {
    if args.descriptor.reuse_daemon || args.descriptor.reuse_panel {
        bail!("--reuse-daemon and --reuse-panel need a published pointer; use `publish`");
    }
    if args.descriptor.state_read.is_none() || args.descriptor.state_write.is_none() {
        bail!("assemble needs --state-read and --state-write");
    }
    let spec = args.descriptor.spec()?.complete(None)?;
    let layer = spec.descriptor_bytes(args.sequence)?;
    let (_, manifest) = assemble::manifest_for(&layer)?;
    std::fs::write(&args.output, &layer)
        .with_context(|| format!("cannot write {}", args.output.display()))?;
    if let Some(path) = &args.manifest_output {
        std::fs::write(path, &manifest)
            .with_context(|| format!("cannot write {}", path.display()))?;
    }
    println!(
        "descriptor: channel={} sequence={} layer={} bytes={}",
        spec.channel,
        args.sequence,
        assemble::sha256(&layer),
        layer.len()
    );
    println!(
        "manifest: digest={} tag={}",
        assemble::sha256(&manifest),
        assemble::set_tag(spec.channel, args.sequence)
    );
    Ok(())
}

async fn publish_command(args: PublishArgs) -> Result<()> {
    let repository = repository(&args.release_repository)?;
    let expected_daemon = args
        .expect_daemon_digest
        .as_deref()
        .map(|value| strict_digest(value, "expected daemon digest"))
        .transpose()?;
    let pinned = public_key(args.public_key.as_ref())?;
    let registry = args.auth.client()?;
    let partial = args.descriptor.spec()?;
    let previous = if args.descriptor.reuse_daemon || args.descriptor.reuse_panel {
        Some(
            publish::read_pointer(&registry, &repository, args.descriptor.channel, &pinned)
                .await?
                .with_context(|| {
                    format!(
                        "reusing a component needs an existing {} pointer",
                        args.descriptor.channel
                    )
                })?
                .descriptor,
        )
    } else {
        None
    };
    let spec = partial.complete(previous.as_ref())?;
    let outcome = publish::publish(
        &registry,
        &repository,
        &spec,
        args.sequence,
        expected_daemon.as_ref(),
    )
    .await?;
    let mut promoted = None;
    if let Some(path) = &args.signing_key {
        let key = signing_key(path)?;
        if key.public_key() != &pinned {
            bail!("the signing key does not match the pinned public key");
        }
        publish::sign(&registry, &repository, &outcome.release_set_digest, &key).await?;
        promoted = Some(
            publish::promote(
                &registry,
                &repository,
                args.descriptor.channel,
                &outcome.tag,
                &pinned,
            )
            .await?,
        );
    }
    if args.json {
        let mut value = serde_json::json!({
            "sequence": outcome.sequence,
            "release_set_digest": outcome.release_set_digest.as_str(),
            "tag": outcome.tag,
        });
        if let Some(promoted) = &promoted {
            value["pointer_moved"] = json!(promoted.pointer_moved);
            value["superseded_by"] = json!(promoted.superseded_by);
            value["revision"] = json!(promoted.revision);
        }
        println!("{value}");
    } else {
        println!(
            "published {} as {}",
            outcome.tag, outcome.release_set_digest
        );
        match &promoted {
            Some(promoted) if promoted.pointer_moved => {
                println!("channel pointer moved to {}", promoted.sequence)
            }
            Some(promoted) => println!(
                "channel pointer left in place (a newer set at sequence {} exists)",
                promoted.superseded_by.unwrap_or(promoted.sequence)
            ),
            None => println!(
                "sign {}@{} with the release key, then run `promote --tag {}`",
                args.release_repository, outcome.release_set_digest, outcome.tag
            ),
        }
    }
    Ok(())
}

async fn promote_command(args: PromoteArgs) -> Result<()> {
    let repository = repository(&args.release_repository)?;
    let pinned = public_key(args.public_key.as_ref())?;
    let registry = args.auth.client()?;
    let outcome =
        publish::promote(&registry, &repository, args.channel, &args.tag, &pinned).await?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "sequence": outcome.sequence,
                "release_set_digest": outcome.release_set_digest.as_str(),
                "revision": outcome.revision,
                "pointer_moved": outcome.pointer_moved,
                "superseded_by": outcome.superseded_by,
            })
        );
    } else if outcome.pointer_moved {
        println!(
            "promoted {} sequence {} ({})",
            args.channel, outcome.sequence, outcome.release_set_digest
        );
    } else {
        println!(
            "{} is already at sequence {}; nothing to move",
            args.channel,
            outcome.superseded_by.unwrap_or(outcome.sequence)
        );
    }
    Ok(())
}

async fn verify_command(args: VerifyArgs) -> Result<()> {
    let repository = repository(&args.release_repository)?;
    let key = public_key(args.public_key.as_ref())?;
    let reference = if args.reference.is_empty() {
        match args.channel {
            Some(channel) => channel.as_str().to_owned(),
            None => bail!("pass a reference (stable, main, set-<channel>-<n>) or --channel"),
        }
    } else {
        args.reference.clone()
    };
    let channel = args
        .channel
        .or_else(|| Channel::parse(&reference))
        .or_else(|| {
            // `set-<channel>-<n>` binds the channel too.
            [Channel::Stable, Channel::Main]
                .into_iter()
                .find(|channel| assemble::parse_set_tag(*channel, &reference).is_some())
        });
    let registry = args.auth.client()?;
    let set = publish::verify_reference(
        &registry,
        &repository,
        &reference,
        DescriptorContext { channel },
        &key,
    )
    .await?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "channel": set.descriptor.channel.as_str(),
                "sequence": set.descriptor.sequence,
                "release_set_digest": set.manifest_digest.as_str(),
                "layer_digest": set.layer_digest.as_str(),
                "revision": set.descriptor.revision,
                "daemon": set.descriptor.daemon,
                "panel": set.descriptor.panel,
                "host_files": set.descriptor.host_tools.files,
                "compatibility": set.descriptor.compatibility,
            })
        );
    } else {
        println!(
            "verified {} sequence {} ({} bytes), release set {}",
            set.descriptor.channel,
            set.descriptor.sequence,
            set.manifest_bytes.len(),
            set.manifest_digest
        );
        println!(
            "daemon {} {} {} / panel {} {} {}",
            set.descriptor.daemon.repository,
            set.descriptor.daemon.version,
            set.descriptor.daemon.digest,
            set.descriptor.panel.repository,
            set.descriptor.panel.version,
            set.descriptor.panel.digest
        );
    }
    Ok(())
}

async fn reconcile_command(args: ReconcileArgs) -> Result<()> {
    let repository = repository(&args.release_repository)?;
    let key = public_key(args.public_key.as_ref())?;
    let registry = args.auth.client()?;
    let outcome = publish::reconcile(&registry, &repository, args.channel, &key).await?;
    match outcome.moved_to {
        Some(sequence) => println!("reconciled {} to sequence {sequence}", args.channel),
        None => println!("{} is already at the highest complete set", args.channel),
    }
    for tag in outcome.skipped {
        eprintln!("skipped unsigned orphan {tag}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_model::release_set::parse_descriptor;

    #[test]
    fn channels_are_the_two_contract_channels() {
        assert_eq!(parse_channel("stable").unwrap(), Channel::Stable);
        assert_eq!(parse_channel("main").unwrap(), Channel::Main);
        assert!(parse_channel("edge").is_err());
    }

    #[test]
    fn only_a_missing_channel_tag_has_a_dedicated_exit_code() {
        use weglarka_model::release_set::Repository;
        use weglarka_registry::RegistryError;

        let status = |status| RegistryError::Status {
            status,
            what: "manifest",
        };
        let missing = anyhow::Error::new(publish::ChannelTagMissing {
            channel: Channel::Stable,
            repository: Repository::new("ghcr.io/example/releases").unwrap(),
            source: status(404),
        })
        .context("cannot resolve ghcr.io/example/releases:stable");
        assert_eq!(exit_code(&missing), EXIT_CHANNEL_TAG_MISSING);
        assert_eq!(EXIT_CHANNEL_TAG_MISSING, 3);

        // Other 404s (a blob, a signature, a set tag), auth and network failures stay generic.
        for error in [
            anyhow::Error::new(status(404)).context("cannot fetch the descriptor blob"),
            anyhow::Error::new(status(401))
                .context("cannot resolve ghcr.io/example/releases:stable"),
            anyhow::Error::new(status(403)),
            anyhow::Error::new(RegistryError::Http(weglarka_registry::HttpError::Request {
                what: "manifest",
                detail: "connection refused".to_owned(),
            })),
            anyhow::anyhow!("the published set does not verify"),
        ] {
            assert_eq!(exit_code(&error), EXIT_FAILURE, "{error:#}");
        }
    }

    #[test]
    fn fixture_descriptor_parses_through_the_shared_parser() {
        let bytes = include_bytes!(
            "../../../docs/contracts/platform-update-v1/fixtures/release-valid.json"
        );
        parse_descriptor(
            bytes,
            &DescriptorContext {
                channel: Some(Channel::Stable),
            },
        )
        .unwrap();
    }

    const DAEMON_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW_DAEMON_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const PANEL_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEW_PANEL_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    /// The fixture release set: daemon 0.9.0, panel 0.3.1, state schema 17.
    fn previous() -> weglarka_model::release_set::Descriptor {
        parse_descriptor(
            include_bytes!(
                "../../../docs/contracts/platform-update-v1/fixtures/release-valid.json"
            ),
            &DescriptorContext {
                channel: Some(Channel::Stable),
            },
        )
        .unwrap()
    }

    fn partial(
        daemon: Option<(&str, &str)>,
        panel: Option<(&str, &str)>,
        state: Option<(Vec<u32>, u32)>,
        panel_tested: &[&str],
    ) -> PartialSpec {
        let record = |(digest, version): (&str, &str)| {
            component("ghcr.io/example/weglarka-component", digest, version).unwrap()
        };
        PartialSpec {
            channel: Channel::Stable,
            revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            daemon: daemon.map(record),
            panel: panel.map(record),
            host_files: Vec::new(),
            state_read: state.as_ref().map(|(read, _)| read.clone()),
            state_write: state.map(|(_, write)| write),
            panel_tested: panel_tested
                .iter()
                .map(|digest| strict_digest(digest, "tested panel digest").unwrap())
                .collect(),
        }
    }

    #[test]
    fn a_panel_only_set_after_a_schema_bump_keeps_the_previous_state_versions() {
        let previous = previous();
        // The flags describe the current schema (18); the reused daemon was built for 17.
        let spec = partial(
            None,
            Some((NEW_PANEL_DIGEST, "0.4.0")),
            Some((vec![18], 18)),
            &[NEW_PANEL_DIGEST],
        )
        .complete(Some(&previous))
        .unwrap();
        assert_eq!(spec.compatibility.state_read, vec![17]);
        assert_eq!(spec.compatibility.state_write, 17);
        assert_eq!(spec.daemon, previous.daemon);
        assert_eq!(spec.host_files, previous.host_tools.files);
        assert_eq!(spec.panel.version, "0.4.0");
    }

    #[test]
    fn a_cli_only_set_after_a_panel_version_bump_keeps_the_panel_digest_and_version() {
        let previous = previous();
        // The current panel crate says 0.4.0, but the reused digest is the 0.3.1 build.
        let spec = partial(
            Some((NEW_DAEMON_DIGEST, "0.10.0")),
            None,
            Some((vec![17], 17)),
            &[PANEL_DIGEST],
        )
        .complete(Some(&previous))
        .unwrap();
        assert_eq!(spec.panel, previous.panel);
        assert_eq!(spec.panel.version, "0.3.1");
        assert_eq!(spec.daemon.digest.to_string(), NEW_DAEMON_DIGEST);
    }

    #[test]
    fn reusing_both_components_copies_both_records() {
        let previous = previous();
        let spec = partial(None, None, None, &[PANEL_DIGEST])
            .complete(Some(&previous))
            .unwrap();
        assert_eq!(spec.daemon, previous.daemon);
        assert_eq!(spec.panel, previous.panel);
        assert_eq!(
            spec.compatibility.state_read,
            previous.compatibility.state_read
        );
        assert_eq!(
            spec.compatibility.state_write,
            previous.compatibility.state_write
        );
    }

    #[test]
    fn a_reused_panel_must_still_be_in_the_tested_list() {
        let error = partial(
            Some((NEW_DAEMON_DIGEST, "0.10.0")),
            None,
            Some((vec![17], 17)),
            &[NEW_PANEL_DIGEST],
        )
        .complete(Some(&previous()))
        .expect_err("the reused panel is not tested")
        .to_string();
        assert!(
            error.contains("not in the tested list"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn reuse_needs_a_previous_pointer() {
        assert!(
            partial(
                None,
                Some((NEW_PANEL_DIGEST, "0.4.0")),
                None,
                &[NEW_PANEL_DIGEST]
            )
            .complete(None)
            .is_err()
        );
        assert!(
            partial(
                Some((NEW_DAEMON_DIGEST, "0.10.0")),
                None,
                Some((vec![17], 17)),
                &[PANEL_DIGEST]
            )
            .complete(None)
            .is_err()
        );
    }

    #[test]
    fn an_explicit_daemon_needs_its_state_flags() {
        let error = partial(
            Some((NEW_DAEMON_DIGEST, "0.10.0")),
            Some((NEW_PANEL_DIGEST, "0.4.0")),
            None,
            &[NEW_PANEL_DIGEST],
        )
        .complete(None)
        .expect_err("state flags are required")
        .to_string();
        assert!(error.contains("--state-read"), "unexpected: {error}");
    }

    fn parse(extra: &[&str]) -> Result<Cli, clap::Error> {
        let mut argv = vec![
            "weglarka-release",
            "assemble",
            "--channel",
            "stable",
            "--revision",
            "0123456789abcdef0123456789abcdef01234567",
            "--output",
            "descriptor.json",
            "--sequence",
            "1",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv)
    }

    #[test]
    fn reuse_flags_conflict_with_the_explicit_component_flags() {
        let daemon = format!("--daemon-digest={DAEMON_DIGEST}");
        let panel = format!("--panel-digest={PANEL_DIGEST}");
        for conflict in [
            ["--reuse-daemon", "--daemon-repository=ghcr.io/example/d"].as_slice(),
            ["--reuse-daemon", daemon.as_str()].as_slice(),
            ["--reuse-daemon", "--state-read=17"].as_slice(),
            ["--reuse-daemon", "--state-write=17"].as_slice(),
            ["--reuse-panel", "--panel-repository=ghcr.io/example/p"].as_slice(),
            ["--reuse-panel", panel.as_str()].as_slice(),
        ] {
            let error = parse(conflict).expect_err("the flags must conflict");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{conflict:?}"
            );
        }
        parse(&["--reuse-daemon", "--reuse-panel"]).unwrap();
    }
}
