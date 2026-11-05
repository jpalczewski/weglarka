//! On-disk layout of static-site releases (ADR 0049): `releases/<id>`, `releases/<id>.partial` and
//! the relative `current` symlink. Everything here is synchronous; callers run it under
//! `spawn_blocking`, like the extractor itself.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use weglarka_model::app::{AppSpec, Digest};

use super::extract::SiteError;

/// Files a release must contain before `current` may point at it (ADR 0049, ADR 0069).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseGate {
    /// Release-relative paths, e.g. `index.html` and `404.html`.
    required: Vec<String>,
}

impl ReleaseGate {
    /// `index.html` plus the site's configured `ingress.static.not_found_page` (if any). The
    /// configured page is a URL path (`/404.html`); the gate checks it relative to the release root.
    pub fn for_spec(spec: &AppSpec) -> Self {
        let mut required = vec!["index.html".to_owned()];
        if let Some(page) = spec
            .ingress
            .static_
            .as_ref()
            .and_then(|opts| opts.not_found_page.as_deref())
        {
            required.push(page.trim_start_matches('/').to_owned());
        }
        Self { required }
    }

    /// Fails with the operator-facing reason when a required file is missing. The messages stay
    /// byte-identical to the ones the release code emitted before the store existed.
    pub fn check(&self, release_dir: &Path) -> Result<(), ReleaseError> {
        for required in &self.required {
            if release_dir.join(required).is_file() {
                continue;
            }
            return Err(if required == "index.html" {
                ReleaseError::MissingIndex
            } else {
                ReleaseError::MissingFile {
                    page: format!("/{required}"),
                }
            });
        }
        Ok(())
    }
}

/// Why a release cannot be built or switched. Every variant's `Display` is the operator-facing text
/// recorded in `state.toml` (`FailedDeploy.reason`) and `Event::DeployFailed`.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    /// The image could not be exported from Podman (`image_save`, stream included).
    #[error("cannot export the image: {0}")]
    Export(String),
    /// The exported archive was rejected or could not be unpacked.
    #[error(transparent)]
    Extract(#[from] SiteError),
    /// The release has no `index.html` at its root.
    #[error("the site has no index.html at its root")]
    MissingIndex,
    /// The release lacks the `ingress.static.not_found_page` it names.
    #[error("the site has no {page} at its root (ingress.static.not_found_page)")]
    MissingFile { page: String },
    /// A filesystem operation failed; the path is part of the message.
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A blocking task panicked or was cancelled; `context` names the step.
    #[error("{context} failed: {source}")]
    Blocking {
        context: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
    /// `switch_to` refuses to point `current` at a release that is not complete.
    #[error("release {id} is incomplete; refusing to switch `current`")]
    Incomplete { id: String },
}

/// The release layout of one site (`<sites_root>/<site>`).
#[derive(Debug, Clone)]
pub struct SiteReleases {
    site_dir: PathBuf,
}

impl SiteReleases {
    pub fn new(site_dir: PathBuf) -> Self {
        Self { site_dir }
    }

    /// Directory every release lives in (`<site>/releases`).
    pub fn releases_dir(&self) -> PathBuf {
        self.site_dir.join("releases")
    }

    pub fn release_dir(&self, id: &str) -> PathBuf {
        self.releases_dir().join(id)
    }

    pub fn partial_dir(&self, id: &str) -> PathBuf {
        self.releases_dir().join(format!("{id}.partial"))
    }

    /// The id `current` points at (`releases/<id>`), if the link exists and has that shape.
    pub fn current_id(&self) -> Option<String> {
        let target = fs::read_link(self.site_dir.join("current")).ok()?;
        if target.parent()? != Path::new("releases") {
            return None;
        }
        target.file_name()?.to_str().map(str::to_owned)
    }

    /// `releases/<id>` exists and passes `gate`.
    pub fn is_complete(&self, id: &str, gate: &ReleaseGate) -> bool {
        let release = self.release_dir(id);
        release.is_dir() && gate.check(&release).is_ok()
    }

    /// `current` points at `id` and `is_complete`.
    pub fn serves(&self, id: &str, gate: &ReleaseGate) -> bool {
        self.current_id().as_deref() == Some(id) && self.is_complete(id, gate)
    }

    /// Moves `<id>.partial` into `releases/<id>` (keeping an existing complete one, as before) and
    /// calls [`Self::switch_to`].
    pub fn publish(&self, id: &str, gate: &ReleaseGate) -> Result<(), ReleaseError> {
        let (partial, release) = (self.partial_dir(id), self.release_dir(id));
        if self.is_complete(id, gate) {
            // Same digest deployed again: the content is identical, keep what is there.
            let _ = fs::remove_dir_all(&partial);
        } else {
            let _ = fs::remove_dir_all(&release);
            fs::rename(&partial, &release).map_err(|source| ReleaseError::Io {
                path: release.clone(),
                source,
            })?;
        }
        self.switch_to(id, gate)
    }

    /// Points `current` at an existing complete release with `symlink(current.tmp)` + `rename(2)`.
    /// Refuses (and changes nothing) when the release is not complete — `current` never dangles.
    pub fn switch_to(&self, id: &str, gate: &ReleaseGate) -> Result<(), ReleaseError> {
        if !self.is_complete(id, gate) {
            return Err(ReleaseError::Incomplete { id: id.to_owned() });
        }
        let tmp = self.site_dir.join("current.tmp");
        let _ = fs::remove_file(&tmp);
        std::os::unix::fs::symlink(Path::new("releases").join(id), &tmp).map_err(|source| {
            ReleaseError::Io {
                path: tmp.clone(),
                source,
            }
        })?;
        let current = self.site_dir.join("current");
        fs::rename(&tmp, &current).map_err(|source| ReleaseError::Io {
            path: current,
            source,
        })
    }

    /// Removes every entry of `releases/` not in `keep`, `.partial` leftovers included. Best effort.
    pub fn prune(&self, keep: &[String]) {
        let Ok(entries) = fs::read_dir(self.releases_dir()) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if keep.iter().any(|kept| kept == name) {
                continue;
            }
            let path = entry.path();
            let _ = if path.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
        }
    }
}

/// Directory name of a release: the leading hex of its digest.
pub fn release_id(digest: &Digest) -> String {
    digest
        .as_str()
        .trim_start_matches("sha256:")
        .chars()
        .take(20)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn store() -> (TempDir, SiteReleases) {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("blog");
        fs::create_dir_all(site.join("releases")).unwrap();
        (tmp, SiteReleases::new(site))
    }

    fn gate() -> ReleaseGate {
        ReleaseGate::for_spec(&toml::from_str("image = \"i\"").unwrap())
    }

    /// A release that is still waiting in `<id>.partial`.
    fn stage(releases: &SiteReleases, id: &str, body: &str) {
        let partial = releases.partial_dir(id);
        fs::create_dir_all(&partial).unwrap();
        fs::write(partial.join("index.html"), body).unwrap();
    }

    /// A release that is already in `releases/<id>` (e.g. a crash between rename and symlink).
    fn installed(releases: &SiteReleases, id: &str, body: &str) {
        let release = releases.release_dir(id);
        fs::create_dir_all(&release).unwrap();
        fs::write(release.join("index.html"), body).unwrap();
    }

    fn current(releases: &SiteReleases) -> Option<String> {
        releases.current_id()
    }

    #[test]
    fn publish_then_switch_between_two_releases() {
        let (_tmp, releases) = store();
        let gate = gate();
        stage(&releases, "a", "a");
        releases.publish("a", &gate).unwrap();
        assert_eq!(current(&releases).as_deref(), Some("a"));
        assert!(releases.serves("a", &gate));

        stage(&releases, "b", "b");
        releases.publish("b", &gate).unwrap();
        assert_eq!(current(&releases).as_deref(), Some("b"));
        assert!(releases.serves("b", &gate));
        assert!(!releases.serves("a", &gate));

        releases.switch_to("a", &gate).unwrap();
        assert_eq!(current(&releases).as_deref(), Some("a"));
        assert_eq!(
            fs::read_to_string(releases.site_dir.join("current/index.html")).unwrap(),
            "a"
        );
    }

    #[test]
    fn switching_to_an_incomplete_or_missing_release_keeps_current() {
        let (_tmp, releases) = store();
        let gate = gate();
        stage(&releases, "a", "a");
        releases.publish("a", &gate).unwrap();

        let err = releases.switch_to("missing", &gate).unwrap_err();
        assert!(matches!(err, ReleaseError::Incomplete { .. }), "{err}");
        assert_eq!(current(&releases).as_deref(), Some("a"));

        // A directory without the required file is not a release either.
        fs::create_dir_all(releases.release_dir("b")).unwrap();
        let err = releases.switch_to("b", &gate).unwrap_err();
        assert!(matches!(err, ReleaseError::Incomplete { .. }), "{err}");
        assert_eq!(current(&releases).as_deref(), Some("a"));
        assert!(releases.serves("a", &gate));
    }

    #[test]
    fn a_leftover_partial_leaves_the_old_release_served_and_the_next_publish_works() {
        let (_tmp, releases) = store();
        let gate = gate();
        stage(&releases, "a", "a");
        releases.publish("a", &gate).unwrap();

        // A deploy of `b` extracted its release but crashed before the switch.
        stage(&releases, "b", "b");
        assert!(releases.serves("a", &gate));
        assert!(!releases.serves("b", &gate));

        releases.publish("b", &gate).unwrap();
        assert!(releases.serves("b", &gate));
        assert!(!releases.partial_dir("b").exists());
    }

    #[test]
    fn a_crash_between_rename_and_symlink_is_completed_by_the_fast_path() {
        let (_tmp, releases) = store();
        let gate = gate();
        stage(&releases, "a", "a");
        releases.publish("a", &gate).unwrap();

        // The new release was renamed into place, the process died before `current` moved.
        installed(&releases, "b", "b");
        assert!(releases.serves("a", &gate));
        assert!(!releases.serves("b", &gate));
        assert!(releases.is_complete("b", &gate));

        // The next deploy of `b` takes the fast path and only switches.
        releases.switch_to("b", &gate).unwrap();
        assert!(releases.serves("b", &gate));
    }

    #[test]
    fn a_stale_current_tmp_is_replaced() {
        let (_tmp, releases) = store();
        let gate = gate();
        stage(&releases, "a", "a");
        releases.publish("a", &gate).unwrap();
        fs::write(releases.site_dir.join("current.tmp"), "stale").unwrap();

        stage(&releases, "b", "b");
        releases.publish("b", &gate).unwrap();
        assert_eq!(current(&releases).as_deref(), Some("b"));
        assert!(!releases.site_dir.join("current.tmp").exists());
    }

    #[test]
    fn prune_keeps_exactly_keep_and_removes_partial_directories() {
        let (_tmp, releases) = store();
        let gate = gate();
        for id in ["a", "b", "c"] {
            installed(&releases, id, id);
        }
        fs::create_dir_all(releases.partial_dir("d")).unwrap();

        releases.prune(&["a".to_owned(), "b".to_owned()]);
        let mut left: Vec<String> = fs::read_dir(releases.releases_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["a", "b"]);
        assert!(releases.is_complete("a", &gate));
    }

    #[test]
    fn release_gate_requires_index_and_the_configured_not_found_page() {
        let plain: AppSpec = toml::from_str("image = \"i\"").unwrap();
        let gate = ReleaseGate::for_spec(&plain);
        assert_eq!(gate.required, ["index.html"]);

        let with_page: AppSpec =
            toml::from_str("image = \"i\"\n[ingress.static]\nnot_found_page = \"/404.html\"\n")
                .unwrap();
        let page_gate = ReleaseGate::for_spec(&with_page);
        assert_eq!(page_gate.required, ["index.html", "404.html"]);

        let (_tmp, releases) = store();
        installed(&releases, "a", "a");
        gate.check(&releases.release_dir("a")).unwrap();
        let err = page_gate.check(&releases.release_dir("a")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "the site has no /404.html at its root (ingress.static.not_found_page)"
        );

        fs::create_dir_all(releases.release_dir("b")).unwrap();
        let err = gate.check(&releases.release_dir("b")).unwrap_err();
        assert_eq!(err.to_string(), "the site has no index.html at its root");
    }
}
