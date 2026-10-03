//! A single secret read from standard input (SHA-247).
//!
//! `rotate plan --stdin` takes one leaked value without a report file. The
//! input is read into zeroized memory, one trailing newline is dropped, and
//! an AWS access key pair is recognised by shape: a key id (`AKIA` or `ASIA`
//! plus 16 uppercase letters or digits) followed by `:` or a newline, then
//! the secret half. Nothing read here is ever printed.

use std::io::{self, Read, Write};

use crate::finding::{Finding, SourceLocation, ACCESS_KEY_ID};
use crate::provider::Credential;
use crate::secret::{SecretPair, SecretValue};

/// Detector name and source file of a finding read from stdin.
pub const STDIN: &str = "stdin";

/// Shown on stderr before reading when stdin is a terminal.
pub const TTY_HINT: &str = "Reading the secret from stdin: paste it, then press Ctrl-D.";

/// Length of an AWS access key id.
const AWS_KEY_ID_LEN: usize = 20;

/// Why stdin did not yield a secret. Never includes what was read.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// Reading failed.
    #[error("could not read stdin: {0}")]
    Read(#[from] io::Error),
    /// Nothing but whitespace was read.
    #[error("no secret on stdin")]
    Empty,
}

/// Writes [`TTY_HINT`] to `out` when stdin is a terminal, so an operator who
/// typed `rotate plan --stdin` knows rotate is waiting for input.
pub fn stdin_hint(is_terminal: bool, out: &mut impl Write) -> io::Result<()> {
    if is_terminal {
        writeln!(out, "{TTY_HINT}")?;
    }
    Ok(())
}

/// Reads one secret from `reader` and returns it as a finding with detector
/// and source `stdin`.
pub fn read_secret(reader: impl Read) -> Result<Finding, InputError> {
    let all = SecretValue::from_reader(reader)?;
    let (raw, key_id) = all
        .expose_secret(|bytes| {
            let value = trim_one_newline(bytes);
            if value.iter().all(u8::is_ascii_whitespace) {
                return None;
            }
            Some(match split_aws_pair(value) {
                Some((key_id, secret)) => (SecretValue::from(secret), Some(key_id)),
                None => (SecretValue::from(value), None),
            })
        })
        .ok_or(InputError::Empty)?;

    let finding = Finding::new(raw, STDIN, SourceLocation::file(STDIN));
    Ok(match key_id {
        Some(key_id) => finding.with_extra(ACCESS_KEY_ID, key_id),
        None => finding,
    })
}

/// Longest replacement accepted from a file, a variable or the terminal, in
/// bytes. Under the 4096 bytes reserved for a read, so a read never
/// reallocates and leaves a copy behind.
pub const REPLACEMENT_MAX: usize = 4000;

/// Why a supplied replacement (SHA-257) was refused. Never includes the
/// value, the variable name or the path: a secret pasted in the wrong place
/// must not be echoed back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplacementInputError {
    /// `--replacement-from-env` names a variable that is not set.
    #[error("the --replacement-from-env variable is not set; nothing was changed")]
    EnvUnset,
    /// `--replacement-file` could not be opened or read.
    #[error("could not read the --replacement-file file ({0}); nothing was changed")]
    Read(io::ErrorKind),
    /// `--replacement-file` lets group or other users in.
    #[error(
        "the --replacement-file file has permissions {mode:04o}, but it must be readable by its owner only; run `chmod 600` on it and check who could have read it; nothing was changed"
    )]
    WideMode {
        /// The permission bits.
        mode: u32,
    },
    /// `--replacement-file` is a directory, device or similar.
    #[error("the --replacement-file path is not a regular file; nothing was changed")]
    NotRegular,
    /// Nothing but whitespace.
    #[error("the replacement is empty")]
    Empty,
    /// Longer than [`REPLACEMENT_MAX`].
    #[error("the replacement is longer than {REPLACEMENT_MAX} bytes")]
    TooLong,
    /// The leaked credential is a key pair and the paste was not
    /// `KEY_ID:SECRET`.
    #[error("the replacement must be a key pair written as KEY_ID:SECRET")]
    NotAPair,
}

/// Drops one trailing newline and refuses a blank or oversized value. The
/// result is a new secret only when something was trimmed.
pub fn normalize_replacement(value: SecretValue) -> Result<SecretValue, ReplacementInputError> {
    if value.len() > REPLACEMENT_MAX {
        return Err(ReplacementInputError::TooLong);
    }
    let trimmed = value.expose_secret(|bytes| {
        let line = trim_one_newline(bytes);
        if line.iter().all(u8::is_ascii_whitespace) {
            Err(ReplacementInputError::Empty)
        } else if line.len() == bytes.len() {
            Ok(None)
        } else {
            Ok(Some(SecretValue::from(line)))
        }
    })?;
    Ok(trimmed.unwrap_or(value))
}

/// Reads the replacement from the environment variable `name`
/// (`--replacement-from-env`). The bytes move into a [`SecretValue`]
/// without a copy; the process environment keeps its own.
#[cfg(unix)]
pub fn replacement_from_env(name: &std::ffi::OsStr) -> Result<SecretValue, ReplacementInputError> {
    use std::os::unix::ffi::OsStringExt;

    let value = std::env::var_os(name).ok_or(ReplacementInputError::EnvUnset)?;
    normalize_replacement(SecretValue::new(value.into_vec()))
}

/// Reads the replacement from `path` (`--replacement-file`), once. The
/// opened file must be a regular file with no group or other permission
/// bits (0600 or 0400); the check uses the open descriptor, so the file
/// cannot be swapped between the check and the read.
#[cfg(unix)]
pub fn replacement_from_file(path: &std::path::Path) -> Result<SecretValue, ReplacementInputError> {
    use std::os::unix::fs::PermissionsExt;

    let file = std::fs::File::open(path).map_err(|e| ReplacementInputError::Read(e.kind()))?;
    let meta = file
        .metadata()
        .map_err(|e| ReplacementInputError::Read(e.kind()))?;
    if !meta.is_file() {
        return Err(ReplacementInputError::NotRegular);
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(ReplacementInputError::WideMode { mode });
    }
    let limit = u64::try_from(REPLACEMENT_MAX + 1).unwrap_or(u64::MAX);
    let value = SecretValue::from_reader(file.take(limit))
        .map_err(|e| ReplacementInputError::Read(e.kind()))?;
    normalize_replacement(value)
}

/// Shapes a pasted value like the leaked credential: a token stays a token;
/// for a key pair the paste is `KEY_ID:SECRET`, split at the first `:`.
pub fn replacement_credential(
    value: SecretValue,
    like: &Credential,
) -> Result<Credential, ReplacementInputError> {
    match like {
        Credential::Token(_) => Ok(Credential::Token(value)),
        Credential::KeyPair(_) => value.expose_secret(|bytes| {
            let colon = bytes
                .iter()
                .position(|b| *b == b':')
                .ok_or(ReplacementInputError::NotAPair)?;
            let (key_id, secret) = (&bytes[..colon], &bytes[colon + 1..]);
            if key_id.is_empty() || secret.is_empty() || !key_id.iter().all(u8::is_ascii_graphic) {
                return Err(ReplacementInputError::NotAPair);
            }
            let key_id = std::str::from_utf8(key_id)
                .map_err(|_| ReplacementInputError::NotAPair)?
                .to_owned();
            Ok(Credential::KeyPair(SecretPair::new(
                key_id,
                SecretValue::from(secret),
            )))
        }),
    }
}

/// Drops one trailing `\n` or `\r\n`, as `echo` and a pasted line add one.
fn trim_one_newline(bytes: &[u8]) -> &[u8] {
    match bytes.strip_suffix(b"\n") {
        Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
        None => bytes,
    }
}

/// Splits `<key id>:<secret>`, `<key id>\n<secret>` or `<key id>\r\n<secret>`.
/// The key id is not secret and is returned as a plain string.
fn split_aws_pair(bytes: &[u8]) -> Option<(String, &[u8])> {
    let key_id = bytes.get(..AWS_KEY_ID_LEN)?;
    if !is_aws_key_id(key_id) {
        return None;
    }
    let rest = &bytes[AWS_KEY_ID_LEN..];
    let secret = rest
        .strip_prefix(b":")
        .or_else(|| rest.strip_prefix(b"\r\n"))
        .or_else(|| rest.strip_prefix(b"\n"))?;
    if secret.is_empty() {
        return None;
    }
    let key_id = std::str::from_utf8(key_id).ok()?.to_owned();
    Some((key_id, secret))
}

fn is_aws_key_id(bytes: &[u8]) -> bool {
    (bytes.starts_with(b"AKIA") || bytes.starts_with(b"ASIA"))
        && bytes[4..]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn read(input: &str) -> Finding {
        read_secret(input.as_bytes()).unwrap()
    }

    #[test]
    fn token_becomes_stdin_finding() {
        let finding = read("mock_abc\n");
        assert_eq!(finding.detector, STDIN);
        assert_eq!(finding.source, SourceLocation::file(STDIN));
        assert_eq!(finding.raw, SecretValue::from("mock_abc"));
        assert!(finding.extra.is_empty());
    }

    #[test]
    fn trims_exactly_one_newline() {
        assert_eq!(read("abc").raw, SecretValue::from("abc"));
        assert_eq!(read("abc\r\n").raw, SecretValue::from("abc"));
        assert_eq!(read("abc\n\n").raw, SecretValue::from("abc\n"));
        assert_eq!(read("abc\r").raw, SecretValue::from("abc\r"));
        assert_eq!(read(" abc \n").raw, SecretValue::from(" abc "));
    }

    #[test]
    fn empty_input_is_rejected() {
        for input in ["", "\n", "\r\n", "  \n"] {
            let err = read_secret(input.as_bytes()).unwrap_err();
            assert!(matches!(err, InputError::Empty), "{input:?}");
            assert_eq!(err.to_string(), "no secret on stdin");
        }
    }

    // T4 (AC4)
    #[test]
    fn aws_pair_colon_and_two_line_forms() {
        for input in [
            format!("{KEY_ID}:{SECRET}\n"),
            format!("{KEY_ID}\n{SECRET}\n"),
            format!("{KEY_ID}\r\n{SECRET}\r\n"),
        ] {
            let finding = read(&input);
            assert_eq!(
                finding.extra.get(ACCESS_KEY_ID).map(String::as_str),
                Some(KEY_ID),
                "{input:?}"
            );
            assert_eq!(
                finding.fingerprint(),
                SecretValue::from(SECRET).fingerprint()
            );
            assert_eq!(finding.credential().key_id(), Some(KEY_ID));
        }
        // A temporary-credential (ASIA) key id, derived at runtime from AWS's
        // documented example. Written out as a literal it matches GitHub
        // secret scanning's AWS pattern and raises a false alert.
        let session_id = KEY_ID.replacen("AKIA", "ASIA", 1);
        let session = read(&format!("{session_id}:{SECRET}"));
        assert_eq!(
            session.extra.get(ACCESS_KEY_ID).map(String::as_str),
            Some(session_id.as_str())
        );
    }

    #[test]
    fn non_aws_colon_is_not_split() {
        for input in [
            "user:pass",
            "AKIAiosfodnn7example:secret",
            "AKIAIOSFODNN7EXAMPL:secret",
            "AKIAIOSFODNN7EXAMPLE:",
            "AKIAIOSFODNN7EXAMPLE",
        ] {
            let finding = read(input);
            assert!(finding.extra.is_empty(), "{input:?}");
            assert_eq!(finding.raw, SecretValue::from(input));
        }
    }

    // T5 (AC5)
    #[test]
    fn tty_hint_written_only_for_terminal() {
        let mut out = Vec::new();
        stdin_hint(true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Ctrl-D"), "{text}");

        let mut out = Vec::new();
        stdin_hint(false, &mut out).unwrap();
        assert!(out.is_empty());
    }

    // SHA-257 T5 (AC5)
    #[test]
    fn replacement_file_rules() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pasted-replacement-file");
        let value = "npm_input_unit_file_value";
        std::fs::write(&path, format!("{value}\n")).unwrap();
        for (mode, ok) in [(0o600, true), (0o400, true), (0o644, false), (0o640, false)] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            match replacement_from_file(&path) {
                Ok(secret) => {
                    assert!(ok, "{mode:o} accepted");
                    assert_eq!(secret, SecretValue::from(value));
                }
                Err(err) => {
                    assert!(!ok, "{mode:o} refused: {err}");
                    assert_eq!(err, ReplacementInputError::WideMode { mode });
                    let text = err.to_string();
                    assert!(text.contains("chmod 600"), "{text}");
                    assert!(!text.contains("pasted-replacement-file"), "{text}");
                }
            }
        }
        assert_eq!(
            replacement_from_file(dir.path()).unwrap_err(),
            ReplacementInputError::NotRegular
        );
        let missing = replacement_from_file(&dir.path().join("missing")).unwrap_err();
        assert_eq!(
            missing,
            ReplacementInputError::Read(io::ErrorKind::NotFound)
        );
        assert!(!missing.to_string().contains("missing"));

        std::fs::write(&path, "x".repeat(REPLACEMENT_MAX + 1)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            replacement_from_file(&path).unwrap_err(),
            ReplacementInputError::TooLong
        );
    }

    // SHA-257 T4 (AC4)
    #[test]
    fn replacement_env_rules() {
        let name = std::ffi::OsStr::new("ROTATE_INPUT_UNIT_REPLACEMENT");
        assert_eq!(
            replacement_from_env(name).unwrap_err(),
            ReplacementInputError::EnvUnset
        );
        std::env::set_var(name, "npm_input_unit_env_value\n");
        assert_eq!(
            replacement_from_env(name).unwrap(),
            SecretValue::from("npm_input_unit_env_value")
        );
        std::env::set_var(name, " \n");
        assert_eq!(
            replacement_from_env(name).unwrap_err(),
            ReplacementInputError::Empty
        );
        std::env::remove_var(name);
        assert!(!ReplacementInputError::EnvUnset
            .to_string()
            .contains("ROTATE_INPUT_UNIT"));
    }

    #[test]
    fn replacement_takes_the_leaked_credentials_shape() {
        let token = Credential::Token(SecretValue::from("old-token-value"));
        let pasted = replacement_credential(SecretValue::from("new-token-value"), &token).unwrap();
        assert_eq!(
            pasted,
            Credential::Token(SecretValue::from("new-token-value"))
        );

        let pair = Credential::KeyPair(SecretPair::new("OLDKEYID", SecretValue::from("old")));
        let pasted =
            replacement_credential(SecretValue::from("NEWKEYID:new-secret:part"), &pair).unwrap();
        assert_eq!(pasted.key_id(), Some("NEWKEYID"));
        assert_eq!(pasted.secret(), &SecretValue::from("new-secret:part"));
        for bad in ["no-colon", ":secret", "KEY:", "KEY ID:secret"] {
            assert_eq!(
                replacement_credential(SecretValue::from(bad), &pair).unwrap_err(),
                ReplacementInputError::NotAPair,
                "{bad}"
            );
        }
    }

    #[test]
    fn debug_never_shows_value() {
        let finding = read(&format!("{KEY_ID}:{SECRET}"));
        let rendered = format!("{finding:?}");
        assert!(!rendered.contains(SECRET));
        assert!(rendered.contains(KEY_ID));
    }
}
