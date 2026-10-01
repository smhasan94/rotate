//! Provider token patterns (SHA-218).
//!
//! These catch secrets that were never registered: a token in an HTTP
//! response body, in an SDK error, or one whose `SecretValue` has already
//! been dropped. AWS key ids are not secret and are kept.

use std::borrow::Cow;
use std::sync::OnceLock;

use regex::{Captures, Regex};
use zeroize::Zeroizing;

/// GitHub, npm and OpenAI tokens, one named group per provider.
fn tokens() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?-u:\b)(?:",
            r"(?P<github>gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})",
            r"|(?P<npm>npm_[A-Za-z0-9]{36,255})",
            r"|(?P<openai>sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,255})",
            r")",
        ))
        .expect("token pattern compiles")
    })
}

/// What makes a following 40-character run an AWS secret access key: a key
/// id (long-term `AKIA` or temporary `ASIA`) or a secret-key keyword.
fn aws_context() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            // `(?i-u:...)`: ASCII case folding. Unicode case folding needs
            // regex's `unicode-case` feature, which the release build does
            // not enable; `cargo test` does through dev-dependencies, so only
            // `ci/smoke.sh` would notice its absence.
            r"(?-u:\b)(?:AKIA|ASIA)[0-9A-Z]{16}(?-u:\b)|(?i-u:secret_?access_?key|aws_?secret)",
        )
        .expect("aws context pattern compiles")
    })
}

const AWS_SECRET_LEN: usize = 40;

/// Replaces provider-shaped tokens with `[REDACTED <provider>]`.
pub(crate) fn redact(text: &str) -> Cow<'_, str> {
    let tokens_done = tokens().replace_all(text, |caps: &Captures<'_>| {
        if caps.name("github").is_some() {
            "[REDACTED github]".to_owned()
        } else if caps.name("npm").is_some() {
            "[REDACTED npm]".to_owned()
        } else {
            let token = &caps[0];
            // `sk-` is common in prose ("task-", "disk-" are excluded by the
            // word boundary, but "sk-learn-..." is not). Real keys always
            // carry a digit.
            if token.bytes().any(|b| b.is_ascii_digit()) {
                "[REDACTED openai]".to_owned()
            } else {
                token.to_owned()
            }
        }
    });
    match tokens_done {
        Cow::Borrowed(t) => redact_aws(t),
        Cow::Owned(s) => {
            let s = Zeroizing::new(s);
            Cow::Owned(redact_aws(&s).into_owned())
        }
    }
}

fn is_secret_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'/' || b == b'+'
}

/// Replaces 40-character `[A-Za-z0-9/+]` runs that follow an AWS key id or
/// keyword in the same text. Runs that are all hex digits (git SHAs) and
/// runs followed by `=` (base64 of something else) are kept.
fn redact_aws(text: &str) -> Cow<'_, str> {
    let Some(context) = aws_context().find(text) else {
        return Cow::Borrowed(text);
    };
    let bytes = text.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = context.end();
    while i < bytes.len() {
        if !is_secret_key_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_secret_key_byte(bytes[i]) {
            i += 1;
        }
        let run = &bytes[start..i];
        let padded = bytes.get(i) == Some(&b'=');
        let all_hex = run.iter().all(u8::is_ascii_hexdigit);
        if run.len() == AWS_SECRET_LEN && !padded && !all_hex {
            let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
            // `start` and `i` sit on ASCII bytes, so both are char boundaries.
            buf.push_str(&text[copied..start]);
            buf.push_str("[REDACTED aws]");
            copied = i;
        }
    }
    match out {
        None => Cow::Borrowed(text),
        Some(mut buf) => {
            buf.push_str(&text[copied..]);
            Cow::Owned(buf)
        }
    }
}
