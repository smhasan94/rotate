//! A single secret read from standard input (SHA-247).
//!
//! `rotate plan --stdin` takes one leaked value without a report file. The
//! input is read into zeroized memory, one trailing newline is dropped, and
//! an AWS access key pair is recognised by shape: a key id (`AKIA` or `ASIA`
//! plus 16 uppercase letters or digits) followed by `:` or a newline, then
//! the secret half. Nothing read here is ever printed.

use std::io::{self, Read, Write};

use crate::finding::{Finding, SourceLocation, ACCESS_KEY_ID};
use crate::secret::SecretValue;

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
        let session = read(&format!("ASIAIOSFODNN7EXAMPLE:{SECRET}"));
        assert_eq!(
            session.extra.get(ACCESS_KEY_ID).map(String::as_str),
            Some("ASIAIOSFODNN7EXAMPLE")
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

    #[test]
    fn debug_never_shows_value() {
        let finding = read(&format!("{KEY_ID}:{SECRET}"));
        let rendered = format!("{finding:?}");
        assert!(!rendered.contains(SECRET));
        assert!(rendered.contains(KEY_ID));
    }
}
