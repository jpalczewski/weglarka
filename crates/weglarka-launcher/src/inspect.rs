//! One `podman inspect --type container` for the launcher and the daemon's platform adapters.
//!
//! The launcher (`daemon-service`), the systemd adapter and the OpenRC adapter all observe the
//! daemon container the same way: one fixed format, one argv, one parser and one rule for what a
//! failure means. Everything here is pure; the callers run the command through their own runner.

/// Go template printing the fields the adapters need, `|`-separated, in [`InspectedContainer`]
/// order. The epoch label is empty when the container was not created by an activation.
pub const CONTAINER_FORMAT: &str = "{{.Id}}|{{.State.Running}}|{{.Image}}|{{.Config.Image}}|\
     {{index .Config.Labels \"io.weglarka.activation-epoch\"}}";

/// What `podman inspect` reports about the service container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedContainer {
    pub id: String,
    pub running: bool,
    /// Image ID the container was created from.
    pub image_id: String,
    /// Image reference from the container config (`repository@sha256:…` when pinned).
    pub config_image: String,
    /// Activation epoch label; `None` when absent or not a number.
    pub epoch: Option<u64>,
}

/// The argv (without the program) that inspects the named container.
pub fn container_args(name: &str) -> Vec<String> {
    vec![
        "inspect".to_owned(),
        "--type".to_owned(),
        "container".to_owned(),
        "--format".to_owned(),
        CONTAINER_FORMAT.to_owned(),
        name.to_owned(),
    ]
}

/// Parses the stdout of a successful [`container_args`] run. `None` means Podman printed no
/// container id.
pub fn parse_inspect(stdout: &str) -> Option<InspectedContainer> {
    let mut parts = stdout.split('|').map(str::trim);
    let id = parts.next().unwrap_or_default();
    if id.is_empty() {
        return None;
    }
    Some(InspectedContainer {
        id: id.to_owned(),
        running: parts.next().unwrap_or_default() == "true",
        image_id: parts.next().unwrap_or_default().to_owned(),
        config_image: parts.next().unwrap_or_default().to_owned(),
        epoch: parts.next().unwrap_or_default().parse().ok(),
    })
}

/// Whether a failed inspect means the container does not exist (as opposed to an unreachable
/// socket or any other Podman failure, which the caller must report).
pub fn is_absent(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such") || stderr.contains("not found")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(
        id: &str,
        running: bool,
        image: &str,
        config: &str,
        epoch: Option<u64>,
    ) -> InspectedContainer {
        InspectedContainer {
            id: id.into(),
            running,
            image_id: image.into(),
            config_image: config.into(),
            epoch,
        }
    }

    #[test]
    fn parse_inspect_reads_every_field() {
        let cases: &[(&str, Option<InspectedContainer>)] = &[
            (
                "abc|true|img|repo@sha256:aa|4",
                Some(container("abc", true, "img", "repo@sha256:aa", Some(4))),
            ),
            (
                " abc | false | img | repo:latest | 12 ",
                Some(container("abc", false, "img", "repo:latest", Some(12))),
            ),
            // The label is empty when the container was not created by an activation.
            (
                "abc|true|img|repo|",
                Some(container("abc", true, "img", "repo", None)),
            ),
            (
                "abc|true|img|repo|not-a-number",
                Some(container("abc", true, "img", "repo", None)),
            ),
            // Anything but a literal `true` is not running.
            (
                "abc|false|img|repo|1",
                Some(container("abc", false, "img", "repo", Some(1))),
            ),
            (
                "abc|maybe|img|repo|1",
                Some(container("abc", false, "img", "repo", Some(1))),
            ),
            // Short output keeps the fields that are present.
            ("abc", Some(container("abc", false, "", "", None))),
            ("abc|true", Some(container("abc", true, "", "", None))),
            // No id: Podman reported nothing.
            ("", None),
            ("  ", None),
            ("|true|img|repo|1", None),
        ];
        for (stdout, expected) in cases {
            assert_eq!(&parse_inspect(stdout), expected, "stdout {stdout:?}");
        }
    }

    #[test]
    fn the_argv_inspects_one_container_by_name() {
        let args = container_args("weglarka");
        assert_eq!(&args[..4], ["inspect", "--type", "container", "--format"]);
        assert_eq!(args[4], CONTAINER_FORMAT);
        assert_eq!(args[5], "weglarka");
        assert_eq!(args.len(), 6);
    }

    #[test]
    fn only_a_missing_container_is_absent() {
        let cases = [
            ("Error: no such container weglarka", true),
            (
                "Error: inspecting object: no such object: \"weglarka\"",
                true,
            ),
            ("Error: NO SUCH CONTAINER", true),
            ("Error: container weglarka not found", true),
            (
                "Cannot connect to Podman. Please verify your connection to the Linux system \
                 using `podman system connection list`",
                false,
            ),
            ("Error: permission denied", false),
            ("", false),
        ];
        for (stderr, absent) in cases {
            assert_eq!(is_absent(stderr), absent, "stderr {stderr:?}");
        }
    }
}
