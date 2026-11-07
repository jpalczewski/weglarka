//! Line diff of two texts: the shared core of `weglarka update --dry-run` (an app spec rendered as
//! TOML) and `weglarka-daemon platform install --check` (a unit file against the installed one).

/// Line diff of `old` against `new`: `- ` marks a line only in `old`, `+ ` a line only in `new`.
/// Unchanged lines are omitted, so an empty string means the texts are equal line by line.
///
/// The comparison is line-wise, never byte-wise: a missing or extra trailing newline is not a
/// change (issue #610 — an editor and `platform install` must not disagree about a unit file).
#[must_use]
pub fn line_diff(old: &str, new: &str) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    // Longest common subsequence; both inputs are a few dozen lines.
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, String::new());
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            (i, j) = (i + 1, j + 1);
        } else if i < a.len() && (j == b.len() || lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push_str(&format!("- {}\n", a[i]));
            i += 1;
        } else {
            out.push_str(&format!("+ {}\n", b[j]));
            j += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_text_is_an_empty_diff() {
        assert_eq!(line_diff("", ""), "");
        assert_eq!(line_diff("a\nb\n", "a\nb\n"), "");
        // Line-wise: the trailing newline is not a change.
        assert_eq!(line_diff("a\nb", "a\nb\n"), "");
    }

    #[test]
    fn added_line_is_plus() {
        assert_eq!(line_diff("a\n", "a\nb\n"), "+ b\n");
    }

    #[test]
    fn removed_line_is_minus() {
        assert_eq!(line_diff("a\nb\n", "a\n"), "- b\n");
    }

    #[test]
    fn changed_line_shows_both_sides() {
        assert_eq!(line_diff("a\nb\nc\n", "a\nB\nc\n"), "- b\n+ B\n");
    }

    #[test]
    fn unchanged_lines_are_omitted() {
        let diff = line_diff("one\ntwo\nthree\nfour\n", "one\ntwo\nTHREE\nfour\n");
        assert_eq!(diff, "- three\n+ THREE\n");
    }
}
