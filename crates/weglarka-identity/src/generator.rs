//! The Authelia adapter of the config pipeline (#212): renders the two list sections Węglarka owns
//! and builds the argv that validates them together with the provider's own base config.

use std::collections::BTreeMap;

use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::generated::{
    ConfigGenerator, FileName, GeneratedFile, RenderError, RenderInput,
};
use weglarka_model::identity::{GENERATED_CONFIG, IngressAuth, config_sources};

use crate::{AppClient, ForwardApp, render_access_control, render_oidc_clients};

/// Program used for validation when the provider's `command` carries only flags (the image's
/// entrypoint is then the program, which a one-off container run cannot inherit).
const DEFAULT_PROGRAM: &str = "authelia";

/// Renders `oidc-clients.yml` and `access-control.yml` for the provider instance `consumer`.
pub struct AutheliaGenerator {
    consumer: InstanceName,
    issuer: String,
}

impl AutheliaGenerator {
    pub fn new(consumer: InstanceName, issuer: String) -> Self {
        Self { consumer, issuer }
    }
}

impl ConfigGenerator for AutheliaGenerator {
    fn id(&self) -> &'static str {
        "identity"
    }

    fn consumer(&self) -> &InstanceName {
        &self.consumer
    }

    fn render(&self, input: &RenderInput<'_>) -> Result<Vec<GeneratedFile>, RenderError> {
        let failed = |e: crate::RenderError| RenderError::Failed {
            id: "identity",
            reason: e.to_string(),
        };
        // Digests are looked up by instance; a public client has none.
        let digests: BTreeMap<&InstanceName, String> = input
            .digests
            .iter()
            .map(|(name, digest)| (name, digest.to_string()))
            .collect();
        let clients: Vec<AppClient<'_>> = input
            .apps
            .apps
            .iter()
            .filter_map(|(instance, spec)| {
                let oidc = spec.oidc.as_ref()?;
                Some(AppClient {
                    instance,
                    spec: oidc,
                    secret_digest: if oidc.public {
                        None
                    } else {
                        digests.get(instance).map(String::as_str)
                    },
                })
            })
            .collect();
        // Every forward app, started or not: a stopped app must not make the provider restart.
        let forward: Vec<ForwardApp<'_>> = input
            .apps
            .apps
            .iter()
            .filter(|(_, spec)| spec.ingress.auth == IngressAuth::Forward)
            .map(|(instance, spec)| ForwardApp {
                instance,
                domains: &spec.domains,
                paths: &spec.paths,
                policy: spec.ingress.auth_policy,
                groups: &spec.ingress.auth_groups,
            })
            .collect();
        let file = |name: &str, text: String| {
            let name = FileName::new(name).map_err(|e| RenderError::Failed {
                id: "identity",
                reason: e.to_string(),
            })?;
            Ok::<_, RenderError>(GeneratedFile::new(name, text.into_bytes()))
        };
        Ok(vec![
            file(
                "oidc-clients.yml",
                render_oidc_clients(&clients, &input.apps.oidc_clients).map_err(failed)?,
            )?,
            file(
                "access-control.yml",
                render_access_control(&self.issuer, &forward).map_err(failed)?,
            )?,
        ])
    }

    /// `<program> config validate` with every `--config` source of the provider's command except the
    /// generated one, then `--config=<dir>` last — the order the provider itself uses at runtime.
    fn validate_argv(&self, consumer: &AppSpec, dir: &str) -> Option<Vec<String>> {
        let command = &consumer.command;
        let program = command
            .first()
            .filter(|first| !first.starts_with('-'))
            .map_or(DEFAULT_PROGRAM, String::as_str);
        let mut argv = vec![program.to_owned(), "config".into(), "validate".into()];
        argv.extend(
            config_sources(command)
                .into_iter()
                .filter(|source| source != GENERATED_CONFIG)
                .map(|source| format!("--config={source}")),
        );
        argv.push(format!("--config={dir}"));
        Some(argv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_() -> AutheliaGenerator {
        AutheliaGenerator::new(
            InstanceName::new("authelia").unwrap(),
            "https://auth.example.com".into(),
        )
    }

    fn provider(command: &[&str]) -> AppSpec {
        let mut spec: AppSpec = toml::from_str("image = \"authelia/authelia:4.39\"").unwrap();
        spec.command = command.iter().map(|s| (*s).to_owned()).collect();
        spec
    }

    #[test]
    fn validation_keeps_the_base_configs_and_swaps_in_the_new_directory() {
        let spec = provider(&[
            "authelia",
            "--config=/config/configuration.yml",
            "--config=/weglarka/generated/current",
        ]);
        assert_eq!(
            gen_()
                .validate_argv(&spec, "/weglarka/generated/v-abc")
                .unwrap(),
            [
                "authelia",
                "config",
                "validate",
                "--config=/config/configuration.yml",
                "--config=/weglarka/generated/v-abc"
            ]
        );
    }

    #[test]
    fn a_flags_only_command_validates_with_the_default_program() {
        let spec = provider(&["-c", "/a,/weglarka/generated/current"]);
        let argv = gen_().validate_argv(&spec, "/d").unwrap();
        assert_eq!(argv[0], "authelia");
        assert_eq!(&argv[3..], ["--config=/a", "--config=/d"]);
    }
}
