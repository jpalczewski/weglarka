//! `weglarka-release` — the publisher-side sibling of the runtime verifier.
//!
//! Contract: [`docs/contracts/platform-update-v1`](../../docs/contracts/platform-update-v1/README.md)
//! and ADR 0067. The publisher and the runtime verifier are one implementation: both use
//! [`weglarka_model::release_set`] and the registry client from `weglarka-registry`, never an ad-hoc
//! JSON pipeline.
//!
//! This binary is a **skeleton** from brief 0. `assemble` and `verify` parse their arguments and fail
//! with an explicit "not implemented" error; signed publication, sequence allocation, OCI manifest
//! construction and signature verification are brief B's work.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use weglarka_model::release_set::Channel;

#[derive(Debug, Parser)]
#[command(
    name = "weglarka-release",
    about = "Assemble and verify signed Węglarka release sets (v1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Assemble and sign a release set for one channel.
    Assemble(AssembleArgs),
    /// Verify a published release set, its descriptor and its signature.
    Verify(VerifyArgs),
}

#[derive(Debug, clap::Args)]
struct AssembleArgs {
    /// Channel to publish; `stable` and `main` never substitute for each other.
    #[arg(long, value_parser = parse_channel)]
    channel: Channel,
    /// Full 40-character lower-case source commit ID.
    #[arg(long)]
    revision: String,
    /// Where to write the assembled descriptor.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, clap::Args)]
struct VerifyArgs {
    /// Tag or digest reference of the release-set manifest.
    reference: String,
}

fn parse_channel(value: &str) -> Result<Channel, String> {
    Channel::parse(value)
        .ok_or_else(|| format!("unknown channel {value:?}; expected stable or main"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Assemble(args) => bail!(
            "assemble is not implemented yet (channel {}, revision {}, output {}); \
             signed publication and sequence allocation land in brief B",
            args.channel,
            args.revision,
            args.output.display()
        ),
        Command::Verify(args) => bail!(
            "verify is not implemented yet (reference {}); registry transport and signature \
             verification land in brief B",
            args.reference
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_model::release_set::{DescriptorContext, parse_descriptor};

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
