//! `FakePodman` against the `PodmanClient` contract (moved from `weglarka-model`, which has no fake).

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use futures_util::StreamExt;
    use weglarka_model::app::Resources;
    use weglarka_model::podman::*;

    use crate::testing::FakePodman;

    fn spec(name: &str, image: &str) -> ContainerSpec {
        ContainerSpec {
            name: name.into(),
            image: image.into(),
            command: vec![],
            entrypoint: None,
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            network_aliases: Default::default(),
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::Always,
            userns_auto: true,
            mounts: vec![],
            volumes: vec![],
            resources: Resources::default(),
            healthcheck: None,
            id_mapping: None,
            keep_groups: false,
            security: Default::default(),
        }
    }

    #[test]
    fn registry_auth_failures_are_told_apart_from_missing_images() {
        let api = |status| PodmanError::Api {
            status,
            message: String::new(),
        };
        assert!(api(401).is_registry_auth_failure());
        assert!(api(403).is_registry_auth_failure());
        assert!(!api(500).is_registry_auth_failure());
        assert!(!PodmanError::NotFound("x".into()).is_registry_auth_failure());
        for m in [
            "unauthorized: authentication required",
            "requested access to the resource is denied",
        ] {
            assert!(
                PodmanError::Pull(m.into()).is_registry_auth_failure(),
                "{m}"
            );
        }
        assert!(!PodmanError::Pull("manifest unknown".into()).is_registry_auth_failure());
    }

    #[tokio::test]
    async fn pull_create_start_health() {
        let fake = FakePodman::new();
        let events: Vec<_> = fake.image_pull("ghcr.io/x/y:latest").collect().await;
        assert!(matches!(
            events.last(),
            Some(Ok(PullEvent::Complete {
                digest: Some(_),
                ..
            }))
        ));

        fake.container_create(&spec("app", "ghcr.io/x/y:latest"))
            .await
            .unwrap();
        fake.container_start("app").await.unwrap();
        fake.script_health("app", [HealthStatus::Starting, HealthStatus::Healthy]);
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Starting
        );
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Healthy
        );
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Healthy
        );
    }

    #[tokio::test]
    async fn pull_error_arrives_mid_stream_and_missing_image_is_not_found() {
        let fake = FakePodman::new();
        fake.fail_pull("ghcr.io/x/bad:latest", "manifest unknown");
        let events: Vec<_> = fake.image_pull("ghcr.io/x/bad:latest").collect().await;
        assert!(matches!(events[0], Ok(PullEvent::Progress { .. })));
        assert!(matches!(events[1], Err(PodmanError::Pull(_))));

        let err = fake
            .container_create(&spec("a", "ghcr.io/x/bad:latest"))
            .await
            .unwrap_err();
        assert!(matches!(err, PodmanError::NotFound(_)));
    }

    /// A registry port is not a tag: a pull of `localhost:5000/y` registers the image under the
    /// full repository, exactly as libpod names it (#76).
    #[tokio::test]
    async fn pull_registers_the_image_under_the_repository_with_the_registry_port() {
        let fake = FakePodman::new();
        let events: Vec<_> = fake.image_pull("localhost:5000/y").collect().await;
        let digest = match events.last() {
            Some(Ok(PullEvent::Complete {
                digest: Some(digest),
                ..
            })) => digest.clone(),
            other => panic!("pull did not complete: {other:?}"),
        };

        let pinned = format!("localhost:5000/y@{digest}");
        assert!(fake.image_inspect(&pinned).await.is_ok());
        let port_as_repo = format!("localhost@{digest}");
        assert!(matches!(
            fake.image_inspect(&port_as_repo).await,
            Err(PodmanError::NotFound(_))
        ));
    }
}
