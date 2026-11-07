//! The credential format of HTTP basic auth (issue #169, `docs/decisions/0081-http-basic-auth.md`):
//! `user:password` lines of a named secret, and the nginx `map` lines the daemon renders from them.
//!
//! The daemon parses the secret before it writes the map file, so a malformed secret never reaches
//! `nginx -t`. The rules of the format are the ADR's: printable ASCII only in the password, one
//! distinct user per line, at most [`MAX_USERS`] lines. A value that does not parse is an error that
//! names the **line number** and nothing else — a password must never end up in a log line, an error
//! message or a snapshot. For the same reason [`Credentials`] has a hand-written `Debug` that prints
//! the user names only.
//!
//! A value without a single credential (only empty lines) is an error too, so the daemon treats it
//! like a missing secret: the instance answers 503 and `doctor` reports it, instead of a map that
//! silently refuses everyone with 401 (ADR 0081, "missing, empty or invalid").

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Longest accepted user name.
pub const MAX_USER_LEN: usize = 64;
/// Shortest and longest accepted password, in bytes.
pub const MIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 128;
/// Most credentials one secret may declare.
pub const MAX_USERS: usize = 32;

/// Why a secret does not describe a usable set of credentials. Every variant names the 1-based line
/// number and never the line's content, which holds the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BasicAuthError {
    #[error("line {line}: not valid UTF-8")]
    NotUtf8 { line: usize },
    #[error("line {line}: expected `user:password`")]
    MissingSeparator { line: usize },
    #[error("line {line}: the user must be 1-64 characters of [A-Za-z0-9._-]")]
    InvalidUser { line: usize },
    #[error(
        "line {line}: the password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} printable ASCII \
         characters (no spaces or control characters)"
    )]
    InvalidPassword { line: usize },
    #[error("line {line}: the user is declared twice")]
    DuplicateUser { line: usize },
    #[error("line {line}: at most {max} credentials are allowed")]
    TooManyUsers { line: usize, max: usize },
    #[error("the secret declares no credential")]
    Empty,
}

/// The credentials of one secret: user name → password, sorted by user name, so the rendered map file
/// is deterministic. The fields stay private: a password is only ever exposed through
/// [`Credentials::nginx_map_lines`].
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    users: BTreeMap<String, String>,
}

impl Credentials {
    /// The user names, sorted. Never a password.
    pub fn users(&self) -> impl Iterator<Item = &str> {
        self.users.keys().map(String::as_str)
    }

    /// Number of credentials, i.e. of accepted users.
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Always false for a value returned by [`parse`], which refuses an empty secret.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// The `include`d `map` body, one line per user: `"~^Basic <base64(user:password)>$" 1;`. The base64
    /// is password-equivalent material, so this is rendered straight into the `0600` map file and
    /// never logged.
    ///
    /// The key is an anchored regex, not a plain string: nginx compares plain `map` keys **ignoring
    /// case**, which would accept the base64 of a different password whose letters differ only in
    /// case (and a `basic` scheme). A `~` key is case-sensitive. `+` is the only regex
    /// metacharacter of the standard base64 alphabet and becomes `[+]`; `/` and `=` match themselves.
    pub fn nginx_map_lines(&self) -> String {
        let mut out = String::new();
        for (user, password) in &self.users {
            let key = STANDARD
                .encode(format!("{user}:{password}"))
                .replace('+', "[+]");
            out.push_str(&format!("\"~^Basic {key}$\" 1;\n"));
        }
        out
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Users only: this type is `Debug`ged in traces and tests, and the values are passwords.
        f.debug_struct("Credentials")
            .field("users", &self.users.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn valid_user(user: &str) -> bool {
    (1..=MAX_USER_LEN).contains(&user.len())
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Printable ASCII of [`MIN_PASSWORD_LEN`]..=[`MAX_PASSWORD_LEN`] bytes. The alphabet excludes the
/// space and the control characters, so nothing in the line needs escaping in `nginx.conf` and a
/// value pasted with a newline is not silently truncated.
fn valid_password(password: &str) -> bool {
    (MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&password.len())
        && password.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Parses one secret value: `user:password` lines, `\n`-terminated except for the last one, empty
/// lines ignored, at least one credential. A password may contain `:`; the split is at the first one.
pub fn parse(value: &[u8]) -> Result<Credentials, BasicAuthError> {
    let text = std::str::from_utf8(value).map_err(|e| BasicAuthError::NotUtf8 {
        line: line_of(value, e.valid_up_to()),
    })?;
    let mut users: BTreeMap<String, String> = BTreeMap::new();
    // `split` yields one empty tail for a trailing newline: exactly the ignored empty line.
    for (index, content) in text.split('\n').enumerate() {
        let line = index + 1;
        if content.is_empty() {
            continue;
        }
        let Some((user, password)) = content.split_once(':') else {
            return Err(BasicAuthError::MissingSeparator { line });
        };
        if !valid_user(user) {
            return Err(BasicAuthError::InvalidUser { line });
        }
        if !valid_password(password) {
            return Err(BasicAuthError::InvalidPassword { line });
        }
        if users.contains_key(user) {
            return Err(BasicAuthError::DuplicateUser { line });
        }
        if users.len() == MAX_USERS {
            return Err(BasicAuthError::TooManyUsers {
                line,
                max: MAX_USERS,
            });
        }
        users.insert(user.to_owned(), password.to_owned());
    }
    if users.is_empty() {
        return Err(BasicAuthError::Empty);
    }
    Ok(Credentials { users })
}

/// The 1-based line number of the byte at `offset`.
fn line_of(value: &[u8], offset: usize) -> usize {
    value[..offset].iter().filter(|b| **b == b'\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deliberately fake credential of the tests, and the only value allowed to appear in a
    /// message or a fixture.
    const ALICE: &str = "alice:correct-horse-battery";

    fn ok(value: &str) -> Credentials {
        parse(value.as_bytes()).expect("valid credentials")
    }

    fn err(value: &str) -> BasicAuthError {
        parse(value.as_bytes()).expect_err("invalid credentials")
    }

    #[test]
    fn a_single_credential_parses() {
        let credentials = ok(&format!("{ALICE}\n"));
        assert_eq!(credentials.users().collect::<Vec<_>>(), ["alice"]);
        assert_eq!(credentials.len(), 1);
        assert!(!credentials.is_empty());
    }

    #[test]
    fn several_credentials_are_sorted_by_user() {
        let credentials = ok(&format!("zoe:abcdefghijkl\n{ALICE}\nbob:123456789012\n"));
        assert_eq!(
            credentials.users().collect::<Vec<_>>(),
            ["alice", "bob", "zoe"],
            "a `BTreeMap` keeps the map file deterministic"
        );
    }

    #[test]
    fn the_last_line_needs_no_trailing_newline() {
        assert_eq!(ok(ALICE), ok(&format!("{ALICE}\n")));
    }

    #[test]
    fn a_secret_without_credentials_is_an_error() {
        // Treated like a missing secret (503 + doctor), never an empty map that 401s everyone.
        for empty in ["", "\n", "\n\n\n"] {
            assert_eq!(err(empty), BasicAuthError::Empty, "{empty:?}");
        }
    }

    #[test]
    fn empty_lines_are_ignored() {
        let spaced = format!("\n{ALICE}\n\nbob:123456789012\n\n");
        assert_eq!(ok(&spaced).len(), 2);
    }

    #[test]
    fn a_duplicate_user_is_rejected() {
        assert_eq!(
            err(&format!("{ALICE}\nalice:another-password\n")),
            BasicAuthError::DuplicateUser { line: 2 }
        );
    }

    #[test]
    fn user_names_follow_the_secret_name_alphabet() {
        for bad in [
            "al ice:abcdefghijkl",
            "ał:abcdefghijkl",
            "a@b:abcdefghijkl",
            "a/b:abcdefghijkl",
            "user\x07:abcdefghijkl",
        ] {
            assert_eq!(
                err(&format!("{bad}\n")),
                BasicAuthError::InvalidUser { line: 1 },
                "{bad:?}"
            );
        }
        // An empty user is an invalid user, not a missing separator.
        assert_eq!(
            err(":abcdefghijkl"),
            BasicAuthError::InvalidUser { line: 1 }
        );
        let long_user = format!("{}:abcdefghijkl", "u".repeat(MAX_USER_LEN + 1));
        assert_eq!(err(&long_user), BasicAuthError::InvalidUser { line: 1 });
        ok(&format!("{}:abcdefghijkl", "u".repeat(MAX_USER_LEN)));
        // The split is at the first colon, so a password may contain one.
        ok("alice:with:colons:1");
    }

    #[test]
    fn passwords_are_printable_ascii_of_a_bounded_length() {
        let with_password = |password: &str| format!("alice:{password}\n");
        for bad in [
            "p".repeat(MIN_PASSWORD_LEN - 1),
            "p".repeat(MAX_PASSWORD_LEN + 1),
            // A space, a tab, a stray `\r` (a value pasted with a newline, never silently
            // truncated), DEL and a non-ASCII character.
            format!("{} ", "p".repeat(MIN_PASSWORD_LEN)),
            format!("{}\t", "p".repeat(MIN_PASSWORD_LEN)),
            format!("{}\r", "p".repeat(MIN_PASSWORD_LEN)),
            format!("{}\x7f", "p".repeat(MIN_PASSWORD_LEN)),
            format!("{}ł", "p".repeat(MIN_PASSWORD_LEN)),
        ] {
            assert_eq!(
                err(&with_password(&bad)),
                BasicAuthError::InvalidPassword { line: 1 },
                "{bad:?}"
            );
        }
        ok(&with_password(&"p".repeat(MIN_PASSWORD_LEN)));
        ok(&with_password(&"p".repeat(MAX_PASSWORD_LEN)));
        // Every printable ASCII character is allowed.
        let printable: String = (0x21..=0x7e).map(|b| char::from(b as u8)).collect();
        assert_eq!(ok(&with_password(&printable)).len(), 1);
    }

    #[test]
    fn a_line_without_a_colon_is_an_error() {
        assert_eq!(err("alice\n"), BasicAuthError::MissingSeparator { line: 1 });
        assert_eq!(
            err(&format!("{ALICE}\n\n \n")),
            BasicAuthError::MissingSeparator { line: 3 }
        );
    }

    #[test]
    fn at_most_thirty_two_users() {
        let user = |i: usize| format!("u{i}:abcdefghijkl\n");
        let many: String = (0..MAX_USERS).map(user).collect();
        assert_eq!(ok(&many).len(), MAX_USERS);
        let mut too_many = many.clone();
        too_many.push_str(&user(MAX_USERS));
        assert_eq!(
            err(&too_many),
            BasicAuthError::TooManyUsers {
                line: MAX_USERS + 1,
                max: MAX_USERS,
            }
        );
    }

    #[test]
    fn an_invalid_utf8_value_names_its_line() {
        let mut value = format!("{ALICE}\n").into_bytes();
        value.push(0xff);
        assert_eq!(
            parse(&value).unwrap_err(),
            BasicAuthError::NotUtf8 { line: 2 }
        );
    }

    #[test]
    fn errors_never_carry_the_line_content() {
        for message in [
            err("alice-correct-horse-battery").to_string(),
            err("alice:short").to_string(),
            err(&format!("{ALICE}\n{ALICE}\n")).to_string(),
            err(&format!("al ice:{ALICE}")).to_string(),
        ] {
            assert!(!message.contains("correct-horse-battery"), "{message}");
            assert!(message.starts_with("line "), "{message}");
        }
    }

    #[test]
    fn the_map_lines_encode_user_and_password() {
        let credentials = ok(&format!("{ALICE}\nbob:123456789012\n"));
        let expected = format!(
            "\"~^Basic {}$\" 1;\n\"~^Basic {}$\" 1;\n",
            STANDARD.encode(ALICE),
            STANDARD.encode("bob:123456789012"),
        );
        assert_eq!(credentials.nginx_map_lines(), expected);
    }

    #[test]
    fn a_plus_in_the_base64_is_escaped_for_the_regex_key() {
        // `alice:p+ss/w=rd-1234>?` encodes to base64 with a `+`, the one regex metacharacter of
        // the alphabet; nginx was checked to accept exactly this line and reject a case-flipped key.
        let credentials = ok("alice:p+ss/w=rd-1234>?");
        assert_eq!(
            credentials.nginx_map_lines(),
            "\"~^Basic YWxpY2U6cCtzcy93PXJkLTEyMzQ[+]Pw==$\" 1;\n"
        );
    }

    #[test]
    fn debug_names_the_users_only() {
        let credentials = ok(&format!("{ALICE}\nbob:123456789012\n"));
        let debug = format!("{credentials:?}");
        assert!(debug.contains("alice") && debug.contains("bob"), "{debug}");
        assert!(!debug.contains("correct-horse-battery"), "{debug}");
        assert!(!debug.contains("123456789012"), "{debug}");
    }
}
