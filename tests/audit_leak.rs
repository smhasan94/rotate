//! SHA-219 T7: a secret value in an error never reaches the audit log or
//! any output the log produces.
//!
//! Stdout and stderr are exercised through `Display` and `Debug` into a
//! string, the same path `println!` and `eprintln!` use. Tracing output is
//! captured with `common::LogCapture` at TRACE level.

#![cfg(unix)]

mod common;

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;

use rotate::audit::{read_all, AuditEvent, AuditLog, AuditStep, Outcome};
use rotate::secret::SecretValue;

/// Fake, and shaped like no real provider's token.
const CANARY: &str = "rotate-audit-canary-5c2a-not-a-real-token";
const REPLACEMENT: &str = "rotate-audit-canary-replacement-e07d";

#[test]
fn secret_value_never_reaches_audit_log_or_output() {
    let dirs = common::TestDirs::new();
    let path = dirs.rotate_dir.join("audit.jsonl");
    let old = SecretValue::from(CANARY);
    let new = SecretValue::from(REPLACEMENT);

    let capture = common::LogCapture::default();
    let mut console = String::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut log = AuditLog::open_as(&path, "tester@host").unwrap();
        let event = AuditEvent::new(
            "rot-0001",
            "aws",
            old.fingerprint(),
            AuditStep::Verify,
            Outcome::Failed,
        )
        .with_replacement(new.fingerprint())
        .with_consumer("org/repo:AWS_SECRET_ACCESS_KEY")
        .with_error(&format!("boom {CANARY} then {REPLACEMENT}"));
        write!(console, "{event:?} {event:#?}").unwrap();
        let written = log.append(event).unwrap();
        write!(console, "{written:?} {written:#?} {log:?}").unwrap();
        if let Some(error) = &written.error {
            write!(console, "{error}").unwrap();
        }

        for entry in read_all(&path).unwrap() {
            let entry = entry.unwrap();
            write!(console, "{entry:?}").unwrap();
        }

        // An error path: a wide mode on a second file.
        let wide = dirs.rotate_dir.join("wide.jsonl");
        std::fs::write(&wide, b"").unwrap();
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = AuditLog::open_as(&wide, "tester@host").unwrap_err();
        write!(console, "{err} {err:?}").unwrap();
    });

    let file = std::fs::read_to_string(&path).unwrap();
    let logs = capture.contents();
    for (label, text) in [
        ("audit log", &file),
        ("stdout/stderr", &console),
        ("tracing", &logs),
    ] {
        for value in [CANARY, REPLACEMENT] {
            assert!(!text.contains(value), "{label}: secret value leaked");
        }
    }
    assert!(file.contains("[REDACTED"));
    assert!(file.contains(old.fingerprint().as_str()));
    assert!(file.contains(new.fingerprint().as_str()));
    assert!(logs.contains(old.fingerprint().as_str()), "{logs}");
}
