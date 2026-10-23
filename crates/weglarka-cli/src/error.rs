//! CLI errors and their mapping to stable exit codes.
//!
//! The code table is part of the interface for agents — changes are additive only.

use serde::Serialize;
use weglarka_api::ErrorCode;

/// Process exit codes (`weglarka --help` contains the same table).
pub mod exit {
    pub const OK: i32 = 0;
    // 1 and 2 are reserved for `doctor` (`DoctorReport::exit_code`: warn / fail).
    pub const NOT_FOUND: i32 = 3;
    pub const CONFLICT: i32 = 4;
    pub const INVALID_REQUEST: i32 = 5;
    /// `deploy`: the new version failed the health gate, rolled back to the previous one.
    pub const ROLLED_BACK: i32 = 6;
    /// Invalid invocation, or input rejected locally.
    pub const USAGE: i32 = 64;
    /// No connection to the daemon (socket missing / no permission / daemon not running).
    pub const UNREACHABLE: i32 = 69;
    /// Internal error: I/O, protocol, daemon error (5xx).
    pub const INTERNAL: i32 = 70;
    /// Missing or invalid `weglarka.toml`.
    pub const CONFIG: i32 = 78;

    pub const TABLE: &str = "\
Kody wyjścia:
   0  sukces
   1  doctor: najgorszy wynik = warn
   2  doctor: najgorszy wynik = fail
   3  nie znaleziono (apka)
   4  już istnieje / konflikt
   5  demon odrzucił żądanie (invalid_request)
   6  deploy: wycofano do poprzedniej wersji (rolled_back)
  64  błędne wywołanie lub dane wejściowe
  69  demon nieosiągalny (socket admin API)
  70  błąd wewnętrzny (I/O, protokół, błąd demona)
  78  brak lub błędny weglarka.toml";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Usage,
    NotFound,
    Conflict,
    InvalidRequest,
    Unreachable,
    Internal,
    Config,
}

impl Kind {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Usage => exit::USAGE,
            Self::NotFound => exit::NOT_FOUND,
            Self::Conflict => exit::CONFLICT,
            Self::InvalidRequest => exit::INVALID_REQUEST,
            Self::Unreachable => exit::UNREACHABLE,
            Self::Internal => exit::INTERNAL,
            Self::Config => exit::CONFIG,
        }
    }

    /// Stable identifier in `--json` (`error.code`).
    pub fn code(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::InvalidRequest => "invalid_request",
            Self::Unreachable => "daemon_unreachable",
            Self::Internal => "internal",
            Self::Config => "config",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CliError {
    pub kind: Kind,
    pub message: String,
    pub hint: Option<String>,
}

impl CliError {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Kind::Usage, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Kind::Internal, message)
    }

    pub fn exit_code(&self) -> i32 {
        self.kind.exit_code()
    }

    /// Daemon response error (`ApiError`) with a code-dependent hint.
    pub fn from_api(code: ErrorCode, message: String) -> Self {
        let (kind, hint) = match code {
            ErrorCode::NotFound => (Kind::NotFound, Some("sprawdź nazwy: `weglarka apps list`")),
            ErrorCode::AlreadyExists => (
                Kind::Conflict,
                Some(
                    "instancja już istnieje: `weglarka apps show <nazwa>`, usuń ją przez `apps remove`",
                ),
            ),
            ErrorCode::Conflict => (
                Kind::Conflict,
                Some("operacja koliduje z trwającą inną — spróbuj ponownie za chwilę"),
            ),
            ErrorCode::InvalidRequest => (Kind::InvalidRequest, None),
            ErrorCode::Internal => (
                Kind::Internal,
                Some("szczegóły w logach demona (`journalctl --user -u weglarka`)"),
            ),
        };
        let mut err = Self::new(kind, message);
        err.hint = hint.map(str::to_owned);
        err
    }
}

/// Shape of the error in `--json` (`{"error": {...}}`).
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope<'a> {
    pub error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody<'a> {
    pub code: &'a str,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'a str>,
    pub exit_code: i32,
}

impl CliError {
    pub fn envelope(&self) -> ErrorEnvelope<'_> {
        ErrorEnvelope {
            error: ErrorBody {
                code: self.kind.code(),
                message: &self.message,
                hint: self.hint.as_deref(),
                exit_code: self.exit_code(),
            },
        }
    }
}
