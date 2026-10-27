//! Crash-loop and unhealthy detection: the policy and the in-memory state machine.
//!
//! The reconcile pass calls [`Watcher::observe`] with the containers it has just fetched and emits the
//! returned events through the engine's sink. Nothing here does I/O, touches state files or takes the
//! engine lock: the decision is a function of the observations, the [`Policy`] and the clock. That is why
//! the watcher lives in the engine rather than in a second daemon task — `container_list` already inspects
//! every container (for health and exit code), so the counter costs no extra libpod call.
//!
//! Decisions and rejected alternatives: `docs/decisions/0022-crash-loop-detection.md`.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::time::Instant;

use weglarka_model::app::{AppsFile, InstanceName};
use weglarka_model::config::MonitorConfig;
use weglarka_model::events::Event;
use weglarka_model::labels;
use weglarka_model::podman::{ContainerInfo, HealthStatus};

/// When an observation becomes an event. `0` disables the respective detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// New restarts inside `crash_loop_window` that make it a crash loop.
    pub crash_loop_restarts: u32,
    /// The rolling window for the restart counter; also the quiet period that counts as recovery.
    pub crash_loop_window: Duration,
    /// Consecutive observations with a failing healthcheck before [`Event::Unhealthy`].
    pub unhealthy_observations: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            crash_loop_restarts: 3,
            crash_loop_window: Duration::from_secs(600),
            unhealthy_observations: 2,
        }
    }
}

impl Policy {
    /// From `[monitor]`. The window is clamped to at least one second: `crash_loop_window_secs = 0`
    /// would otherwise open a new window on every pass and never accumulate a restart streak.
    pub fn from_config(config: &MonitorConfig) -> Self {
        Self {
            crash_loop_restarts: config.crash_loop_restarts,
            crash_loop_window: Duration::from_secs(config.crash_loop_window_secs.max(1)),
            unhealthy_observations: config.unhealthy_observations,
        }
    }

    /// Every detector off — for engine tests that are not about monitoring.
    pub fn disabled() -> Self {
        Self {
            crash_loop_restarts: 0,
            crash_loop_window: Duration::from_secs(1),
            unhealthy_observations: 0,
        }
    }
}

/// What the watcher remembers about one instance between reconcile passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Instance {
    /// `weglarka.generation` of the container these counters belong to.
    generation: Option<String>,
    /// Restart count when the current window opened.
    window_baseline: u32,
    /// Restart count seen at the previous observation.
    restarts_seen: u32,
    window_start: Option<Instant>,
    /// When the container last gained a restart (the quiet period is measured from here).
    last_restart_at: Option<Instant>,
    crash_alerted: bool,
    unhealthy_streak: u32,
    health_alerted: bool,
}

/// Per-instance crash and health state, rebuilt from scratch after a daemon restart.
#[derive(Debug, Default)]
pub struct Watcher {
    instances: BTreeMap<InstanceName, Instance>,
}

impl Watcher {
    /// One observation. `containers` is the engine's container list, `apps` its desired state; `now` is a
    /// monotonic clock (virtual in the engine tests). Returns the events to emit, in a stable order.
    pub fn observe(
        &mut self,
        containers: &[ContainerInfo],
        apps: &AppsFile,
        policy: &Policy,
        now: Instant,
    ) -> Vec<Event> {
        // A removed app is forgotten: its containers are pruned by the same reconcile pass.
        self.instances
            .retain(|name, _| apps.apps.contains_key(name));

        let mut events = Vec::new();
        for name in apps.apps.keys() {
            let container_name = labels::container_name(name);
            let container = containers.iter().find(|c| {
                c.name == container_name
                    && c.labels
                        .get(labels::INSTANCE)
                        .is_some_and(|i| i == name.as_str())
            });
            match container {
                // No container: `start = false`, waiting for secrets, not deployed yet or being replaced.
                None => {
                    self.instances.remove(name);
                }
                Some(info) => {
                    let state = self.instances.entry(name.clone()).or_default();
                    events.extend(watch_instance(name, info, state, policy, now));
                }
            }
        }
        events
    }

    /// How many instances are tracked (tests and future doctor reporting).
    pub fn tracked(&self) -> usize {
        self.instances.len()
    }
}

/// `Unhealthy`/`CrashLooping` first, one `Recovered` last when any detector recovered in this observation.
fn watch_instance(
    name: &InstanceName,
    info: &ContainerInfo,
    state: &mut Instance,
    policy: &Policy,
    now: Instant,
) -> Vec<Event> {
    let generation = info.labels.get(labels::GENERATION).cloned();
    if state.generation != generation {
        // A new container (deploy, recreate, rollback) starts at `RestartCount = 0`: its counters and any
        // active alert belong to the previous container and are dropped. No `Recovered` — the deploy that
        // replaced it already reported itself.
        *state = Instance {
            generation,
            window_baseline: info.restarts,
            restarts_seen: info.restarts,
            window_start: Some(now),
            ..Instance::default()
        };
    }

    let mut events = Vec::new();
    let mut recovered = false;

    if policy.crash_loop_restarts > 0 {
        if info.restarts > state.restarts_seen {
            state.last_restart_at = Some(now);
        }
        state.restarts_seen = info.restarts;
        // Defensive: a counter that went backwards within one container is treated as a new baseline.
        if info.restarts < state.window_baseline {
            state.window_baseline = info.restarts;
        }
        let delta = info.restarts.saturating_sub(state.window_baseline);
        if delta >= policy.crash_loop_restarts && !state.crash_alerted {
            events.push(Event::CrashLooping {
                instance: name.clone(),
                restarts: delta,
            });
            state.crash_alerted = true;
        }
        let window = policy.crash_loop_window;
        let elapsed = state
            .window_start
            .is_none_or(|start| now.duration_since(start) >= window);
        if elapsed {
            let quiet = state
                .last_restart_at
                .is_none_or(|last| now.duration_since(last) >= window);
            if state.crash_alerted && quiet {
                recovered = true;
                state.crash_alerted = false;
            }
            state.window_baseline = info.restarts;
            state.window_start = Some(now);
        }
    }

    if policy.unhealthy_observations > 0 {
        match info.health {
            Some(HealthStatus::Unhealthy) => {
                state.unhealthy_streak = state.unhealthy_streak.saturating_add(1);
                if state.unhealthy_streak >= policy.unhealthy_observations && !state.health_alerted
                {
                    events.push(Event::Unhealthy {
                        instance: name.clone(),
                    });
                    state.health_alerted = true;
                }
            }
            Some(HealthStatus::Healthy) => {
                if state.health_alerted {
                    recovered = true;
                    state.health_alerted = false;
                }
                state.unhealthy_streak = 0;
            }
            // `starting` is a probe still in flight; `None` means the image has no healthcheck.
            Some(HealthStatus::Starting) | None => state.unhealthy_streak = 0,
        }
    }

    if recovered {
        events.push(Event::Recovered {
            instance: name.clone(),
        });
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const GENERATION: u64 = 3;

    fn name(value: &str) -> InstanceName {
        InstanceName::new(value).unwrap()
    }

    fn apps(instances: &[&str]) -> AppsFile {
        let mut toml = String::new();
        for instance in instances {
            toml.push_str(&format!("[apps.{instance}]\nimage = \"ghcr.io/x/y:1\"\n"));
        }
        toml::from_str(&toml).unwrap()
    }

    fn container(instance: &str, restarts: u32, health: Option<HealthStatus>) -> ContainerInfo {
        ContainerInfo {
            id: "c".into(),
            name: instance.into(),
            image: "ghcr.io/x/y:1".into(),
            image_id: "i".into(),
            labels: BTreeMap::from([
                (labels::INSTANCE.to_owned(), instance.to_owned()),
                (labels::GENERATION.to_owned(), GENERATION.to_string()),
            ]),
            state: weglarka_model::podman::ContainerState::Running,
            exit_code: None,
            health,
            restarts,
            networks: vec![],
            addresses: vec![],
            published_ports: vec![],
        }
    }

    fn policy() -> Policy {
        Policy {
            crash_loop_restarts: 3,
            crash_loop_window: Duration::from_secs(60),
            unhealthy_observations: 2,
        }
    }

    /// One observation of instance `a` at `second` seconds after `t0`.
    fn observe(
        watcher: &mut Watcher,
        t0: Instant,
        second: u64,
        restarts: u32,
        health: Option<HealthStatus>,
    ) -> Vec<Event> {
        watcher.observe(
            &[container("a", restarts, health)],
            &apps(&["a"]),
            &policy(),
            t0 + Duration::from_secs(second),
        )
    }

    #[test]
    fn the_first_observation_only_sets_the_baseline() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        assert!(observe(&mut watcher, t0, 0, 2, None).is_empty());
        // Two restarts before we started looking are not a loop.
        assert!(observe(&mut watcher, t0, 10, 2, None).is_empty());
    }

    #[test]
    fn a_restart_streak_alerts_once() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        assert!(observe(&mut watcher, t0, 0, 0, None).is_empty());
        assert!(observe(&mut watcher, t0, 10, 1, None).is_empty());
        assert!(observe(&mut watcher, t0, 20, 2, None).is_empty());
        assert_eq!(
            observe(&mut watcher, t0, 30, 3, None),
            vec![Event::CrashLooping {
                instance: name("a"),
                restarts: 3,
            }]
        );
        // The same loop is reported once, not on every pass.
        assert!(observe(&mut watcher, t0, 40, 3, None).is_empty());
        assert!(observe(&mut watcher, t0, 50, 4, None).is_empty());
    }

    #[test]
    fn a_quiet_window_recovers_once() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        observe(&mut watcher, t0, 0, 0, None);
        observe(&mut watcher, t0, 10, 3, None);
        // Still inside the window: no recovery yet.
        assert!(observe(&mut watcher, t0, 40, 3, None).is_empty());
        assert_eq!(
            observe(&mut watcher, t0, 70, 3, None),
            vec![Event::Recovered {
                instance: name("a"),
            }]
        );
        // ... and only once.
        assert!(observe(&mut watcher, t0, 140, 3, None).is_empty());
    }

    #[test]
    fn restarts_spread_over_windows_never_alert() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        observe(&mut watcher, t0, 0, 0, None);
        // One restart every 50 s with a 60 s window: the baseline moves before the third one arrives.
        for (second, restarts) in [(10, 1), (60, 2), (120, 3), (180, 4), (240, 5)] {
            assert!(observe(&mut watcher, t0, second, restarts, None).is_empty());
        }
    }

    #[test]
    fn a_recreated_container_starts_from_zero() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        observe(&mut watcher, t0, 0, 0, None);
        observe(&mut watcher, t0, 10, 3, None); // alert
        // A deploy/recreate: same instance name, new generation, the counter starts over.
        let mut reloaded = container("a", 0, None);
        reloaded
            .labels
            .insert(labels::GENERATION.into(), "4".into());
        let events = watcher.observe(
            &[reloaded],
            &apps(&["a"]),
            &policy(),
            t0 + Duration::from_secs(20),
        );
        assert!(events.is_empty(), "{events:?}");
        // And no recovery event for the old alert.
        assert!(observe(&mut watcher, t0, 200, 0, None).is_empty());
    }

    #[test]
    fn a_missing_container_or_app_is_forgotten() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        observe(&mut watcher, t0, 0, 0, None);
        assert_eq!(watcher.tracked(), 1);
        // Container gone (`start = false`, waiting for secrets, removed): nothing to watch.
        let events = watcher.observe(&[], &apps(&["a"]), &policy(), t0);
        assert!(events.is_empty());
        assert_eq!(watcher.tracked(), 0);
        // A container of an app that is not in `apps.toml` (about to be pruned) is ignored.
        observe(&mut watcher, t0, 1, 0, None);
        let events = watcher.observe(
            &[container("a", 5, Some(HealthStatus::Unhealthy))],
            &apps(&["other"]),
            &policy(),
            t0 + Duration::from_secs(2),
        );
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(watcher.tracked(), 0);
    }

    #[test]
    fn an_unhealthy_check_needs_two_observations_and_recovers_once() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        let unhealthy = Some(HealthStatus::Unhealthy);
        assert!(observe(&mut watcher, t0, 0, 0, unhealthy).is_empty());
        assert_eq!(
            observe(&mut watcher, t0, 10, 0, unhealthy),
            vec![Event::Unhealthy {
                instance: name("a"),
            }]
        );
        assert!(
            observe(&mut watcher, t0, 20, 0, unhealthy).is_empty(),
            "one alert"
        );
        assert_eq!(
            observe(&mut watcher, t0, 30, 0, Some(HealthStatus::Healthy)),
            vec![Event::Recovered {
                instance: name("a"),
            }]
        );
        assert!(observe(&mut watcher, t0, 40, 0, Some(HealthStatus::Healthy)).is_empty());
    }

    #[test]
    fn a_single_failed_probe_or_a_missing_healthcheck_is_quiet() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        assert!(observe(&mut watcher, t0, 0, 0, Some(HealthStatus::Unhealthy)).is_empty());
        // Back to healthy before the second observation: the streak is dropped.
        assert!(observe(&mut watcher, t0, 10, 0, Some(HealthStatus::Healthy)).is_empty());
        assert!(observe(&mut watcher, t0, 20, 0, Some(HealthStatus::Unhealthy)).is_empty());
        assert!(observe(&mut watcher, t0, 30, 0, None).is_empty());
        assert!(observe(&mut watcher, t0, 40, 0, Some(HealthStatus::Unhealthy)).is_empty());
    }

    #[test]
    fn recovery_is_emitted_once_when_both_detectors_recover() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        observe(&mut watcher, t0, 0, 0, Some(HealthStatus::Unhealthy));
        observe(&mut watcher, t0, 10, 3, Some(HealthStatus::Unhealthy));
        // Crash and health recover in the same observation: exactly one Recovered.
        let events = observe(&mut watcher, t0, 80, 3, Some(HealthStatus::Healthy));
        assert_eq!(
            events,
            vec![Event::Recovered {
                instance: name("a"),
            }]
        );
    }

    #[test]
    fn disabled_detectors_emit_nothing() {
        let t0 = Instant::now();
        let mut watcher = Watcher::default();
        let disabled = Policy::disabled();
        for second in [0, 10, 20, 30] {
            let events = watcher.observe(
                &[container("a", second as u32, Some(HealthStatus::Unhealthy))],
                &apps(&["a"]),
                &disabled,
                t0 + Duration::from_secs(second),
            );
            assert!(events.is_empty(), "{events:?}");
        }
    }

    #[test]
    fn the_config_window_is_clamped_to_one_second() {
        let policy = Policy::from_config(&MonitorConfig {
            crash_loop_restarts: 2,
            crash_loop_window_secs: 0,
            unhealthy_observations: 0,
        });
        assert_eq!(policy.crash_loop_window, Duration::from_secs(1));
        assert_eq!(policy.crash_loop_restarts, 2);
        assert_eq!(policy.unhealthy_observations, 0);
        assert_eq!(
            Policy::from_config(&MonitorConfig::default()),
            Policy::default()
        );
    }
}
