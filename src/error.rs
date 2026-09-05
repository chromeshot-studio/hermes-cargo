//! Error types.
//!
//! Security failures get their own hard-typed enum so they can never be
//! confused with (or silently downgraded to) an ordinary I/O or network error.
//! Everything that reaches the top level is rendered by `main.rs`; a
//! [`SecurityError`] always aborts the operation and is never retried.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    // ---- cryptography -----------------------------------------------------
    #[error("signature algorithm '{0}' is not supported (expected ed25519)")]
    UnsupportedAlgorithm(String),
    #[error("public key is malformed: {0}")]
    MalformedPublicKey(String),
    #[error("signature is malformed: {0}")]
    MalformedSignature(String),
    #[error("SIGNATURE VERIFICATION FAILED - the manifest was not signed by the studio key pinned in the .origin file")]
    BadSignature,
    #[error("checksum mismatch: manifest promised sha256:{expected}, download hashed to sha256:{actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("manifest is for origin '{found}' but was fetched for '{expected}'")]
    OriginMismatch { expected: String, found: String },
    #[error("manifest expired at {expires_at} (now {now}); refusing a possibly replayed manifest")]
    ManifestExpired { expires_at: i64, now: i64 },
    #[error("manifest is dated {issued_at}, which is too far in the future (now {now})")]
    ManifestFromFuture { issued_at: i64, now: i64 },
    #[error("rollback refused: installed version {installed} is newer than offered version {offered}")]
    RollbackRefused { installed: String, offered: String },
    #[error("the pinned public key for '{id}' changed; refusing to overwrite the trusted key without --force")]
    KeyPinViolation { id: String },

    // ---- transport --------------------------------------------------------
    #[error("insecure URL '{0}': HERMES requires https (set HERMES_ALLOW_INSECURE_HTTP=1 for local testing only)")]
    InsecureUrl(String),
    #[error("response exceeded the {limit} byte cap for {what}")]
    ResponseTooLarge { what: &'static str, limit: u64 },

    // ---- archive / path sandbox ------------------------------------------
    #[error("path traversal blocked: archive entry '{entry}' resolves outside the destination ({reason})")]
    PathTraversal { entry: String, reason: String },
    #[error("unsafe path '{path}': {reason}")]
    UnsafePath { path: String, reason: String },
    #[error("archive entry '{0}' is a symlink or special file; HERMES only extracts regular files and directories")]
    UnsafeEntryKind(String),
    #[error("archive entry '{0}' appears twice; refusing to let a later entry overwrite an earlier one")]
    DuplicateEntry(String),
    #[error("archive exceeds its limits: {0}")]
    ArchiveLimit(String),

    // ---- foiled plan / consent -------------------------------------------
    #[error("step '{step}' touches '{path}', which is outside the folder scope declared by the .foiled plan")]
    UndeclaredScope { step: String, path: String },
    #[error("declared scope '{path}' escapes the install root")]
    ScopeEscape { path: PathBuf },
    #[error("the user did not grant access; update aborted")]
    ConsentDenied,
    #[error("refusing to prompt for folder access on a non-interactive terminal (deny by default)")]
    ConsentUnavailable,

    // ---- auth -------------------------------------------------------------
    #[error("the auth callback carried the wrong state parameter; possible CSRF, token discarded")]
    StateMismatch,
    #[error("the studio returned a malformed token: {0}")]
    MalformedToken(String),
}

/// Any security error is fatal. Helper so call sites read as an abort.
pub type SecResult<T> = std::result::Result<T, SecurityError>;
