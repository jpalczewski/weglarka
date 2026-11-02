//! Runs every published contract case through the real parser.
//!
//! The fixture digests are synthetic, not downloadable artifacts: `valid_blobs` only proves that the
//! manifest references the exact fixture bytes by size and SHA-256. This is a wire-contract test,
//! not a cryptographic or registry test.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use weglarka_model::release_set::{
    Channel, DescriptorContext, Rejection, parse_descriptor, parse_manifest,
};

#[derive(Debug, Deserialize)]
struct Case {
    file: String,
    result: String,
    #[serde(default)]
    context: Option<CaseContext>,
    #[serde(default)]
    layer_file: Option<String>,
    #[serde(default)]
    config_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CaseContext {
    channel: Option<String>,
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/contracts/platform-update-v1/fixtures")
}

fn read(name: &str) -> Vec<u8> {
    let path = fixtures().join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn context(case: &Case) -> DescriptorContext {
    let channel = case
        .context
        .as_ref()
        .and_then(|context| context.channel.as_deref())
        .map(|name| Channel::parse(name).unwrap_or_else(|| panic!("unknown channel {name:?}")));
    DescriptorContext { channel }
}

#[test]
fn every_contract_fixture_case_matches_the_parser() {
    let path = fixtures().join("cases.json");
    let cases: Vec<Case> = serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
    )
    .expect("cases.json is valid");
    assert_eq!(cases.len(), 21, "the published case count changed");

    for case in &cases {
        let bytes = read(&case.file);
        match case.result.as_str() {
            "valid_descriptor" => {
                let descriptor = parse_descriptor(&bytes, &context(case)).unwrap_or_else(|error| {
                    panic!("{}: expected valid_descriptor, got {error}", case.file)
                });
                let serialized = serde_json::to_vec(&descriptor).expect("serializes");
                assert_eq!(
                    parse_descriptor(&serialized, &context(case)).expect("round trip parses"),
                    descriptor,
                    "{}: descriptor round trip",
                    case.file
                );
            }
            "valid_envelope" => {
                parse_manifest(&bytes).unwrap_or_else(|error| {
                    panic!("{}: expected valid_envelope, got {error}", case.file)
                });
            }
            "valid_blobs" => {
                let manifest = parse_manifest(&bytes).unwrap_or_else(|error| {
                    panic!("{}: expected valid_blobs, got {error}", case.file)
                });
                let layer = read(
                    case.layer_file
                        .as_deref()
                        .expect("valid_blobs names its layer file"),
                );
                let config = read(
                    case.config_file
                        .as_deref()
                        .expect("valid_blobs names its config file"),
                );
                manifest
                    .verify_blobs(&layer, &config)
                    .unwrap_or_else(|error| {
                        panic!(
                            "{}: referenced fixture bytes do not match: {error}",
                            case.file
                        )
                    });
            }
            expected => {
                let rejection = if case.file.starts_with("release-") {
                    parse_descriptor(&bytes, &context(case))
                        .err()
                        .map(|error| error.rejection)
                } else {
                    let parsed = parse_manifest(&bytes);
                    match parsed {
                        Err(error) => Some(error.rejection),
                        Ok(manifest) if case.layer_file.is_some() || case.config_file.is_some() => {
                            let layer = read(
                                case.layer_file
                                    .as_deref()
                                    .expect("a size/digest case names its layer file"),
                            );
                            let config = read(
                                case.config_file
                                    .as_deref()
                                    .unwrap_or("oci-empty-config.json"),
                            );
                            manifest
                                .verify_blobs(&layer, &config)
                                .err()
                                .map(|error| error.rejection)
                        }
                        Ok(_) => None,
                    }
                };
                let rejection = rejection.unwrap_or_else(|| {
                    panic!(
                        "{}: expected {expected}, but the parser accepted it",
                        case.file
                    )
                });
                assert_eq!(
                    rejection.as_str(),
                    expected,
                    "{}: parser reported {rejection} instead of {expected}",
                    case.file
                );
                assert!(
                    Rejection::from_name(expected).is_some(),
                    "{}: {expected} is not in the contract vocabulary",
                    case.file
                );
            }
        }
    }
    eprintln!(
        "platform update contract fixtures: {} cases passed",
        cases.len()
    );
}
