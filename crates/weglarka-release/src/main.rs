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

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use weglarka_model::release_set::{Channel, DescriptorContext, StrictDigest};
use weglarka_registry::{DEFAULT_PUBLIC_KEY_PEM, HttpRegistry, PublicKey, SigningKey};

use crate::assemble::{ReleaseSpec, component, crate_version, host_file};

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
    /// Panel image repository (tag-free).
    #[arg(long)]
    panel_repository: String,
    /// Panel image manifest digest.
    #[arg(long)]
    panel_digest: String,
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
    /// State schema the target daemon can read (repeatable).
    #[arg(long = "state-read")]
    state_read: Vec<u32>,
    /// State schema the target daemon writes.
    #[arg(long)]
    state_write: u32,
    /// Panel digest tested against this daemon (repeatable). The selected panel must be present.
    #[arg(long = "panel-tested")]
    panel_tested: Vec<String>,
    /// Reuse the daemon image and host-file records from the current channel pointer
    /// (panel-only release: the daemon artifact is unchanged and must not be relabeled).
    #[arg(long)]
    reuse_daemon: bool,
}

/// The parts of a spec that are always known from the command line. A panel-only release has no
/// daemon input; it is completed from the current pointer before anything is serialized.
struct PartialSpec {
    channel: Channel,
    revision: String,
    daemon: Option<weglarka_model::release_set::Component>,
    panel: weglarka_model::release_set::Component,
    host_files: Vec<weglarka_model::release_set::HostFile>,
    compatibility: weglarka_model::release_set::Compatibility,
}

impl PartialSpec {
    /// Fills the daemon and host-tool records from `previous` when they were not passed (or keeps
    /// the explicit ones). Never invents a daemon identity.
    fn complete(
        self,
        previous: Option<&weglarka_model::release_set::Descriptor>,
    ) -> Result<ReleaseSpec> {
        match self.daemon {
            Some(daemon) => Ok(ReleaseSpec {
                channel: self.channel,
                revision: self.revision,
                daemon,
                panel: self.panel,
                host_files: self.host_files,
                compatibility: self.compatibility,
            }),
            None => {
                let previous = previous.context(
                    "no daemon component was given and there is no existing pointer to reuse",
                )?;
                let mut spec = ReleaseSpec {
                    channel: self.channel,
                    revision: self.revision,
                    daemon: previous.daemon.clone(),
                    panel: self.panel,
                    host_files: Vec::new(),
                    compatibility: self.compatibility,
                };
                spec.reuse_daemon(previous);
                Ok(spec)
            }
        }
    }
}

impl DescriptorArgs {
    fn spec(&self) -> Result<PartialSpec> {
        let daemon_version = crate_version(&self.daemon_crate)?;
        let panel_version = crate_version(&self.panel_crate)?;
        let cli_version = crate_version(&self.cli_crate)?;
        let panel_digest = strict_digest(&self.panel_digest, "panel digest")?;
        let panel = component(&self.panel_repository, &self.panel_digest, &panel_version)?;
        let tested = self
            .panel_tested
            .iter()
            .map(|value| strict_digest(value, "tested panel digest"))
            .collect::<Result<Vec<_>>>()?;
        let compatibility = assemble::compatibility(
            self.state_read.clone(),
            self.state_write,
            tested,
            &panel_digest,
        )?;
        let daemon = match (&self.daemon_repository, &self.daemon_digest) {
            (Some(repository), Some(digest)) => {
                Some(component(repository, digest, &daemon_version)?)
            }
            (None, None) if self.reuse_daemon => None,
            _ => bail!(
                "--daemon-repository and --daemon-digest are required unless --reuse-daemon is set"
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
        Ok(PartialSpec {
            channel: self.channel,
            revision: self.revision.clone(),
            daemon,
            panel,
            host_files,
            compatibility,
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

fn main() -> Result<()> {
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
    if args.descriptor.reuse_daemon {
        bail!("--reuse-daemon needs a published pointer; use `publish`");
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
    let pinned = public_key(args.public_key.as_ref())?;
    let registry = args.auth.client()?;
    let partial = args.descriptor.spec()?;
    let previous = if args.descriptor.reuse_daemon {
        Some(
            publish::read_pointer(&registry, &repository, args.descriptor.channel, &pinned)
                .await?
                .with_context(|| {
                    format!(
                        "--reuse-daemon needs an existing {} pointer to copy the daemon from",
                        args.descriptor.channel
                    )
                })?
                .descriptor,
        )
    } else {
        None
    };
    let spec = partial.complete(previous.as_ref())?;
    let outcome = publish::publish(&registry, &repository, &spec, args.sequence).await?;
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
}
