//! SHA-247: input selection through the CLI. A secret on stdin or a report
//! path reaches `plan`; nothing read is ever echoed.
//!
//! T3 needs the mock providers registered by the `test-providers` feature;
//! CI runs `cargo test --all-features`.

use assert_cmd::Command;
use predicates::prelude::*;
use rotate::secret::SecretValue;

const GITLEAKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gitleaks.json");

fn rotate_in(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("rotate").expect("rotate binary builds");
    cmd.current_dir(dir).env_remove("ROTATE_CONFIG");
    cmd
}

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

// T1 (AC1)
#[test]
fn stdin_secret_reaches_plan() {
    let dir = tempfile::tempdir().unwrap();
    rotate_in(dir.path())
        .args(["plan", "--stdin"])
        .write_stdin("mock_abc\n")
        .assert()
        .success()
        .stdout(predicate::str::contains(fp("mock_abc")))
        .stdout(predicate::str::contains("stdin"))
        .stdout(predicate::str::contains(fp("mock_abc\n")).not());
}

// T2 (AC2)
#[test]
fn empty_stdin_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    for input in ["", "\n"] {
        rotate_in(dir.path())
            .args(["plan", "--stdin"])
            .write_stdin(input)
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("no secret on stdin"));
    }
}

// T3 (AC3)
#[cfg(feature = "test-providers")]
#[test]
fn unknown_provider_lists_known() {
    let dir = tempfile::tempdir().unwrap();
    let assert = rotate_in(dir.path())
        .args(["plan", "--stdin", "--provider", "nope"])
        .write_stdin("mock_abc\n")
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    for name in ["aws", "github", "npm", "openai"] {
        assert!(stderr.contains(name), "{name} missing from: {stderr}");
    }
    // The typed name is not echoed: a pasted secret could land there.
    assert!(!stderr.contains("nope"), "{stderr}");

    // A known name skips identification: the secret is checked as aws.
    rotate_in(dir.path())
        .args(["plan", "--stdin", "--provider", "aws"])
        .write_stdin("mock_abc\n")
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(format!(r"(?m)^aws\s+{}\s+valid", fp("mock_abc"))).unwrap(),
        );
}

// T6 (AC1, AC4)
#[test]
fn stdin_secret_never_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let token = "mock_canary-stdin-71d3-token";
    let secret = "canarySecretHalf/8c2e+EXAMPLEKEYxyz0";
    let pair = format!("AKIAIOSFODNN7EXAMPLE:{secret}\n");
    for (input, value) in [(format!("{token}\n"), token), (pair, secret)] {
        let output = rotate_in(dir.path())
            .args(["plan", "--stdin"])
            .write_stdin(input)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stdout.contains(&fp(value)), "fingerprint missing");
        for (label, text) in [("stdout", &stdout), ("stderr", &stderr)] {
            assert!(!text.contains(value), "{label}: value leaked");
        }
    }
}

#[test]
fn report_path_reaches_plan() {
    let dir = tempfile::tempdir().unwrap();
    let assert = rotate_in(dir.path())
        .args(["plan", GITLEAKS])
        .assert()
        .success()
        .stdout(predicate::str::contains(fp(
            "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001",
        )))
        .stdout(predicate::str::contains(fp("AKIAIOSFODNN7EXAMPLE")))
        .stdout(predicate::str::contains(fp(
            "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake0002",
        )));
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(!stdout.contains("ghp_FAKE"), "value leaked");
}

#[test]
fn format_mismatch_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    rotate_in(dir.path())
        .args(["plan", GITLEAKS, "--format", "trufflehog"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "--format trufflehog was given but the report looks like gitleaks",
        ));
}

#[test]
fn missing_report_exits_2_without_echoing_path() {
    let dir = tempfile::tempdir().unwrap();
    let pasted = "ghp_canaryPastedAsPath0000000000000000";
    rotate_in(dir.path())
        .args(["plan", pasted])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("could not read the report file"))
        .stderr(predicate::str::contains("--stdin"))
        .stderr(predicate::str::contains(pasted).not());
}

#[test]
fn input_flag_conflicts_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        vec!["plan", GITLEAKS, "--stdin"],
        vec!["plan", "--provider", "aws"],
    ] {
        rotate_in(dir.path()).args(&args).assert().code(2);
    }
}
