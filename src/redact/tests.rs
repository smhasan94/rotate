//! Tests for SHA-218. Provider-shaped samples are built at runtime so no
//! token-shaped literal sits in the source for secret scanners to flag.

use std::borrow::Cow;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

use super::*;
use crate::secret::SecretValue;

/// In-memory sink for the layer under test.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `f` with the redacting subscriber installed and returns its output.
fn captured(f: impl FnOnce()) -> String {
    let sink = Sink::default();
    let subscriber = subscriber(LevelFilter::TRACE, sink.clone());
    tracing::subscriber::with_default(subscriber, f);
    sink.contents()
}

/// A key-id shape built at runtime. Not AWS's documented example id, which
/// other tests in this process register as a `SecretValue`.
fn aws_key_id() -> String {
    format!("AKIA{}", "REDACTTESTKEYID7")
}

/// A 40-character secret-key shape, unique per `tag`. Other tests in this
/// process may register AWS's documented example key, and a registered value
/// is (correctly) replaced by its fingerprint rather than `[REDACTED aws]`.
fn aws_secret_key(tag: &str) -> String {
    let mut key = format!("wJalrXUtnFEMI/{tag}/");
    key.push_str(&"bPxRfiCYEXAMPLEKEY".repeat(3));
    key.truncate(40);
    key
}

/// One sample per provider pattern and the marker it must become.
/// Unique per `tag` for the same reason as [`aws_secret_key`].
fn provider_samples(tag: &str) -> Vec<(String, &'static str)> {
    let mut alnum36 = format!(
        "{tag}{}",
        ["abcdefghijklmnopqrstuvwxyz", "0123456789"].concat()
    );
    alnum36.truncate(36);
    let mut samples: Vec<(String, &'static str)> = ["ghp", "gho", "ghu", "ghs", "ghr"]
        .iter()
        .map(|p| (format!("{p}_{alnum36}"), "[REDACTED github]"))
        .collect();
    samples.push((
        format!(
            "github_pat_{}_{tag}{}",
            "11ABCDEFG0123456789abc",
            "Zx9".repeat(20)
        ),
        "[REDACTED github]",
    ));
    samples.push((format!("npm_{tag}{}", "a1B2".repeat(9)), "[REDACTED npm]"));
    samples.push((
        format!("sk-{tag}{}", "a1B2".repeat(12)),
        "[REDACTED openai]",
    ));
    samples.push((
        format!("sk-proj-{tag}{}", "x9Y8_-".repeat(10)),
        "[REDACTED openai]",
    ));
    samples
}

// T1 (AC1)
#[test]
fn registered_value_in_message_is_redacted() {
    let secret = SecretValue::from("s3cr3t-value-xyz");
    let out = captured(|| tracing::info!("token is s3cr3t-value-xyz"));
    assert!(!out.contains("s3cr3t-value-xyz"), "value leaked: {out}");
    assert!(
        out.contains(&format!("token is [REDACTED {}]", secret.fingerprint())),
        "no marker in {out}"
    );
}

// T2 (AC2)
#[test]
fn provider_token_in_field_is_redacted() {
    for (token, marker) in provider_samples("T2") {
        let body = format!("{{\"error\":\"bad credential {token} supplied\"}}");
        let out = captured(|| tracing::warn!(body = %body, "provider said no"));
        assert!(!out.contains(&token), "token leaked for {marker}");
        assert!(out.contains(marker), "no {marker} in {out}");
    }

    let (id, key) = (aws_key_id(), aws_secret_key("T2"));
    let body = format!("aws_access_key_id={id} aws_secret_access_key={key}");
    let out = captured(|| tracing::warn!(body = %body, "aws"));
    assert!(!out.contains(&key), "aws secret key leaked");
    assert!(out.contains("[REDACTED aws]"), "no aws marker in {out}");
    assert!(out.contains(&id), "key id must be kept: {out}");
}

// T3 (AC3)
#[test]
fn url_and_base64_forms_are_redacted() {
    let raw = "s3cr3t/value+xyz=?&";
    let secret = SecretValue::from(raw);
    let marker = format!("[REDACTED {}]", secret.fingerprint());
    let encoded = [
        urlencoding::encode(raw).into_owned(),
        base64::engine::general_purpose::STANDARD.encode(raw),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw),
        base64::engine::general_purpose::URL_SAFE.encode(raw),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
    ];
    assert_ne!(encoded[0], raw, "test value must change when URL-encoded");
    for form in encoded {
        let out = captured(|| tracing::info!("sent Authorization: Basic {form}"));
        assert!(!out.contains(&form), "encoded form leaked: {out}");
        assert!(out.contains(&marker), "no marker for {form}: {out}");
    }
}

// T4 (AC4)
#[test]
fn clean_message_is_unchanged() {
    assert!(matches!(redact("rotation started"), Cow::Borrowed(_)));
    let out = captured(|| tracing::info!("rotation started"));
    let line = out.trim_end();
    assert!(line.ends_with(" rotation started"), "changed: {line}");
    assert!(!line.contains("REDACTED"));
}

// T5 (AC5)
#[test]
fn dropped_value_still_caught_by_pattern() {
    let (token, marker) = provider_samples("T5").remove(0);
    let plain = "dropped-plain-value-5150";
    let provider_secret = SecretValue::from(token.as_str());
    let plain_secret = SecretValue::from(plain);
    let copy = plain_secret.clone();
    assert!(redact(&token).starts_with("[REDACTED sha256:"));
    drop(provider_secret);
    drop(plain_secret);
    drop(copy);

    let out = captured(|| tracing::info!("late echo {token} and {plain}"));
    assert!(!out.contains(&token));
    assert!(out.contains(marker), "no {marker} in {out}");
    // No longer registered, and not provider-shaped: left as is.
    assert!(
        out.contains(plain),
        "dropped plain value still redacted: {out}"
    );
}

// T6 (AC6)
#[test]
fn ten_thousand_lines_under_one_second() {
    let secrets: Vec<SecretValue> = (0..50)
        .map(|i| SecretValue::from(format!("perf-secret-{i:03}-{}", "q7".repeat(10))))
        .collect();
    let github = provider_samples("T6").remove(0).0;
    let lines: Vec<String> = (0..10_000)
        .map(|i| {
            let mut line = match i % 20 {
                0 => format!(
                    "event {i} put secret perf-secret-{:03}-{}",
                    i % 50,
                    "q7".repeat(10)
                ),
                1 => format!("event {i} response body {github}"),
                _ => format!("event {i} consumer=github-actions repo=acme/api status=ok"),
            };
            while line.len() < 200 {
                line.push_str(" lorem ipsum");
            }
            line.truncate(200);
            line
        })
        .collect();

    let start = Instant::now();
    let mut redacted = 0;
    for line in &lines {
        if let Cow::Owned(_) = redact(line) {
            redacted += 1;
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(redacted, 1_000, "every secret line must be redacted");
    assert!(
        elapsed < Duration::from_secs(1),
        "redaction took {elapsed:?} for 10,000 lines"
    );
    drop(secrets);
}

// T5 (AC5): many threads registering, cloning, dropping and redacting at
// once must neither panic nor deadlock.
#[test]
fn concurrent_register_drop_redact() {
    let handles: Vec<_> = (0..8)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..200 {
                    let value = format!("concurrent-value-{t}-{i}-padding");
                    let secret = SecretValue::from(value.as_str());
                    let copy = secret.clone();
                    let out = redact(&format!("x {value} y")).into_owned();
                    assert!(!out.contains(&value));
                    drop(secret);
                    drop(copy);
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("no panic in registry");
    }
}

#[test]
fn longest_match_wins() {
    let short = SecretValue::from("overlap-value-1234");
    let long = SecretValue::from("overlap-value-1234-longer");
    let out = redact("got overlap-value-1234-longer!").into_owned();
    assert_eq!(out, format!("got [REDACTED {}]!", long.fingerprint()));
    drop(short);
}

#[test]
fn debug_escaped_form_is_redacted() {
    let raw = "quote\"and\\backslash-value";
    let _secret = SecretValue::from(raw);
    let escaped = format!("{raw:?}");
    let out = captured(|| tracing::info!(body = raw, "debug field"));
    assert!(!out.contains(raw));
    assert!(
        !out.contains(&escaped[1..escaped.len() - 1]),
        "escaped form leaked: {out}"
    );
    assert!(out.contains("[REDACTED sha256:"));
}

#[test]
fn git_sha_after_key_id_is_kept() {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let text = format!("key {} rotated in commit {sha}", aws_key_id());
    assert_eq!(redact(&text), text);
}

#[test]
fn aws_secret_without_context_is_kept() {
    let text = format!("opaque {}", aws_secret_key("nocontext"));
    assert_eq!(redact(&text), text);
    let keyword = format!("SecretAccessKey: {}", aws_secret_key("keyword"));
    assert_eq!(redact(&keyword), "SecretAccessKey: [REDACTED aws]");
}

#[test]
fn sk_inside_word_is_kept() {
    for text in [
        "task-abcdefghijklmnopqrstuvwxyz123",
        "sk-learn-preprocessing-pipeline-step",
    ] {
        assert_eq!(redact(text), text);
    }
}

#[test]
fn split_writes_are_redacted_together() {
    let _secret = SecretValue::from("split-write-secret-value");
    let sink = Sink::default();
    {
        let mut writer = RedactingWriter::new(sink.clone());
        writer.write_all(b"before split-write-").unwrap();
        writer.write_all(b"secret-value after\n").unwrap();
        writer.flush().unwrap();
        assert!(
            sink.contents().is_empty(),
            "flush must not write half an event"
        );
    }
    let out = sink.contents();
    assert!(!out.contains("split-write-secret-value"));
    assert!(out.starts_with("before [REDACTED sha256:"));
    assert!(out.ends_with("] after\n"));
}

#[test]
fn level_for_maps_verbosity() {
    assert_eq!(level_for(0), LevelFilter::WARN);
    assert_eq!(level_for(1), LevelFilter::INFO);
    assert_eq!(level_for(2), LevelFilter::DEBUG);
    assert_eq!(level_for(3), LevelFilter::TRACE);
    assert_eq!(level_for(u8::MAX), LevelFilter::TRACE);
}

#[test]
fn level_filter_drops_quieter_events() {
    let sink = Sink::default();
    let subscriber = subscriber(level_for(0), sink.clone());
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("hidden at default verbosity");
        tracing::warn!("shown at default verbosity");
    });
    let out = sink.contents();
    assert!(!out.contains("hidden"));
    assert!(out.contains("shown"));
}
