//! SHA-218 T7: with the subscriber `main` installs, no secret value reaches
//! the process's real stdout or stderr.
//!
//! The test re-runs this test binary as a child that installs
//! `rotate::redact::subscriber` on the real stderr, as `main` does, and logs
//! the T1 and T2 messages. The parent captures both streams of the child.
//! Token-shaped values are built at runtime so no literal in this file looks
//! like a credential to a secret scanner.

#![allow(clippy::disallowed_macros)]

use std::process::Command;

use rotate::redact::{level_for, subscriber};
use rotate::secret::SecretValue;

const CHILD_ENV: &str = "ROTATE_REDACT_LEAK_CHILD";

fn canary() -> String {
    ["rotate-canary-", "7f3e9b21-", "do-not-log"].concat()
}

fn provider_tokens() -> Vec<(String, &'static str)> {
    let body = ["T7leakcheck", "abcdefghijklmnopqrstuvwxy0"].concat();
    vec![
        (format!("ghp_{}", &body[..36]), "[REDACTED github]"),
        (
            format!(
                "github_pat_{}_{}",
                "11T7LEAK0123456789abcd",
                "Qw3".repeat(20)
            ),
            "[REDACTED github]",
        ),
        (format!("npm_{}", &body[..36]), "[REDACTED npm]"),
        (
            format!("sk-proj-{}", "T7x9Y8_-".repeat(8)),
            "[REDACTED openai]",
        ),
        (
            format!(
                "aws_access_key_id=AKIA{} aws_secret_access_key={}",
                "T7LEAKCHECKKEY01",
                ["wJalrXUtnFEMI/T7leak/", "bPxRfiCYEXAMPLEKEY0"].concat()
            ),
            "[REDACTED aws]",
        ),
    ]
}

/// The child half. Does nothing unless started by the parent below.
#[test]
fn child_logs_canaries() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    tracing::subscriber::set_global_default(subscriber(level_for(3), std::io::stderr))
        .expect("first subscriber in the child");
    let _secret = SecretValue::from(canary());
    // T1: a registered value in the message.
    tracing::info!("token is {}", canary());
    // T2: provider tokens in a field, never registered.
    for (token, _) in provider_tokens() {
        tracing::warn!(body = %format!("upstream said: {token}"), "provider error");
    }
    println!("child finished");
}

// T7 (AC1, AC2)
#[test]
fn child_stdout_and_stderr_hold_no_canary() {
    let exe = std::env::current_exe().expect("test binary path");
    let output = Command::new(exe)
        .args([
            "--exact",
            "child_logs_canaries",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("run child");
    assert!(output.status.success(), "child failed: {:?}", output.status);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("child finished"), "child did not run");

    let fingerprint = SecretValue::from(canary()).fingerprint();
    assert!(
        stderr.contains(&format!("token is [REDACTED {fingerprint}]")),
        "no registry marker on stderr"
    );
    let aws_secret = ["wJalrXUtnFEMI/T7leak/", "bPxRfiCYEXAMPLEKEY0"].concat();
    for (stream, text) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(!text.contains(&canary()), "canary on {stream}");
        assert!(!text.contains(&aws_secret), "aws secret key on {stream}");
        for (token, _) in provider_tokens() {
            if !token.starts_with("aws_") {
                assert!(!text.contains(&token), "provider token on {stream}");
            }
        }
    }
    for (_, marker) in provider_tokens() {
        assert!(stderr.contains(marker), "no {marker} on stderr");
    }
}
