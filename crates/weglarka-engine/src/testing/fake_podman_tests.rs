//! `FakePodman` against the `PodmanClient` contract (moved from `weglarka-model`, which has no fake).

#[cfg(test)]
mod tests {

    use futures_util::StreamExt;
    use weglarka_model::app::Resources;
    use weglarka_model::podman::*;

    use crate::testing::{DEAD_CONMON_MESSAGE, FakePodman, StopFailure};

    fn spec(name: &str, image: &str) -> ContainerSpec {
        ContainerSpec {
            restart: RestartPolicy::Always,
            userns_auto: true,
            resources: Resources::default(),
            ..ContainerSpec::new(name, image)
        }
    }

    /// The same suite runs against `LibpodClient` in `weglarka-podman/tests/contract.rs`.
    #[tokio::test]
    async fn fake_passes_the_podman_contract() {
        weglarka_model::podman_contract::run_reachable(&FakePodman::new()).await;
    }

    #[tokio::test]
    async fn unreachable_fake_is_an_error_not_absent() {
        let fake = FakePodman::new();
        fake.set_unreachable(true);
        weglarka_model::podman_contract::unreachable_is_an_error_not_absent(&fake).await;
        fake.set_unreachable(false);
        weglarka_model::podman_contract::run_reachable(&fake).await;
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

    /// The scripted stop failures of a container whose conmon died (issue #470): the call answers
    /// HTTP 500 and leaves the container `exited`, or a stop that failed with it still running.
    #[tokio::test]
    async fn a_dead_conmon_makes_stop_fail_and_leaves_the_container_exited() {
        let fake = FakePodman::new();
        let _: Vec<_> = fake.image_pull("ghcr.io/x/y:latest").collect().await;
        fake.container_create(&spec("app", "ghcr.io/x/y:latest"))
            .await
            .unwrap();
        fake.container_start("app").await.unwrap();

        fake.script_next_stop_failure(StopFailure::DeadConmon);
        let stopped = fake.container_stop("app", 10).await;
        assert!(
            matches!(
                &stopped,
                Err(PodmanError::Api {
                    status: 500,
                    message
                }) if message == DEAD_CONMON_MESSAGE
            ),
            "{stopped:?}"
        );
        let info = fake.container_inspect("app").await.unwrap();
        assert_eq!(
            (info.state, info.exit_code),
            (ContainerState::Exited, Some(-1))
        );

        fake.container_start("app").await.unwrap();
        fake.script_next_stop_failure(StopFailure::LeftRunning);
        assert!(fake.container_stop("app", 10).await.is_err());
        let info = fake.container_inspect("app").await.unwrap();
        assert_eq!(info.state, ContainerState::Running);

        // A stop of a missing container is `NotFound`, scripted failure or not.
        fake.script_next_stop_failure(StopFailure::DeadConmon);
        assert!(matches!(
            fake.container_stop("gone", 10).await,
            Err(PodmanError::NotFound(_))
        ));
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
