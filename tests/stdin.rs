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
            predicate::str::is_match(format!(
                r"(?m)^Rotation rot-[0-9a-f]{{8}}  aws  {}$",
                fp("mock_abc")
            ))
            .unwrap(),
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

// ---------------------------------------------------------------------------
// SHA-337: GitHub secret-scanning alerts, and any report, on stdin
// ---------------------------------------------------------------------------

const ALERTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/github_alerts.json"
);
const TRUFFLEHOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/trufflehog.ndjson"
);
const ALERT_URL: &str = "https://github.com/acme/api/security/secret-scanning";
const COMMIT: &str = "9f2c1e4b7a3d5f6e8c0b1a2d3e4f5a6b7c8d9e0f";

/// Every value in the alert fixture, and the base64 one as it is written.
const ALERT_VALUES: [&str; 8] = [
    "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001",
    "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake0002",
    "sk-proj-FAKEfakeFAKEfakeFAKEfakeFAKEfake0003",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake0004",
    "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0006",
    "Z2hwX0ZBS0VmYWtlRkFLRWZha2VGQUtFZmFrZUZBS0VmYWtlMDAwNg==",
    "FAKE-ssh-private-key-body-not-a-key-0009",
];

/// `rotate` in `dir` with a scenario whose call log is `dir/calls.jsonl`.
#[cfg(feature = "test-providers")]
fn rotate_logged(dir: &std::path::Path) -> Command {
    let scenario = serde_json::json!({ "call_log": dir.join("calls.jsonl") });
    std::fs::write(dir.join("scenario.json"), scenario.to_string()).unwrap();
    let mut cmd = rotate_in(dir);
    cmd.env("ROTATE_TEST_SCENARIO", dir.join("scenario.json"));
    cmd
}

#[cfg(feature = "test-providers")]
fn mutating_calls(dir: &std::path::Path) -> Vec<serde_json::Value> {
    let log = std::fs::read_to_string(dir.join("calls.jsonl")).expect("call log written");
    let calls: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!calls.is_empty(), "no call logged");
    calls
        .into_iter()
        .filter(|c| c["mutating"] == true)
        .collect()
}

#[cfg(feature = "test-providers")]
fn assert_no_alert_value(output: &std::process::Output) {
    for (label, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        for value in ALERT_VALUES {
            assert!(!text.contains(value), "{label}: an alert value leaked");
        }
    }
}

// SHA-337 T2 (AC1): the alert fixture on stdin and as a report file. Each
// secret-bearing alert of a supported type is one rotation whose source is
// the alert URL with line and commit, and the call log has no mutating call.
#[cfg(feature = "test-providers")]
#[test]
fn sha337_t2_github_alerts_plan_with_mocks() {
    let input = std::fs::read(ALERTS).unwrap();
    let source = |n: u32, line: u32| format!("{ALERT_URL}/{n}:{line}@{COMMIT}");
    let expected = [
        ("github", ALERT_VALUES[0], source(1, 12)),
        ("npm", ALERT_VALUES[1], source(2, 1)),
        ("openai", ALERT_VALUES[2], source(3, 4)),
        ("aws", ALERT_VALUES[3], source(4, 3)),
        ("github", ALERT_VALUES[5], source(8, 7)),
    ];
    let runs: [(&[&str], Option<&[u8]>); 2] = [
        (
            &["--json", "plan", "--stdin", "--format", "github-alert"],
            Some(&input),
        ),
        (
            &["--json", "plan", ALERTS, "--format", "github-alert"],
            None,
        ),
    ];
    for (args, stdin) in runs {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = rotate_logged(dir.path());
        cmd.args(args);
        if let Some(stdin) = stdin {
            cmd.write_stdin(stdin);
        }
        let output = cmd.output().unwrap();
        assert_no_alert_value(&output);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let rotations: Vec<(String, String, Vec<String>)> = plan["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["provider"].as_str().unwrap().to_owned(),
                    r["fingerprint"].as_str().unwrap().to_owned(),
                    serde_json::from_value(r["sources"].clone()).unwrap(),
                )
            })
            .collect();
        let want: Vec<(String, String, Vec<String>)> = expected
            .iter()
            .map(|(p, v, s)| ((*p).to_owned(), fp(v), vec![s.clone()]))
            .collect();
        assert_eq!(rotations, want, "{args:?}");

        // The unpaired key id and the unsupported type are skipped rows.
        let skipped: Vec<(String, String)> = plan["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["reason"].as_str().unwrap().to_owned(),
                    s["sources"][0].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let other_commit = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
        assert_eq!(
            skipped,
            vec![
                (
                    "not rotatable".to_owned(),
                    format!("{ALERT_URL}/6:2@{other_commit}")
                ),
                ("unsupported".to_owned(), source(10, 1)),
            ]
        );
        let stderr = String::from_utf8(output.stderr.clone()).unwrap();
        assert!(stderr.contains("alert #7 is resolved"), "{stderr}");
        assert!(
            stderr.contains("alert #9 has no `secret` field"),
            "{stderr}"
        );

        let mutating = mutating_calls(dir.path());
        assert!(mutating.is_empty(), "mutating calls: {mutating:?}");
    }
}

// SHA-337 T2 (AC5): `--stdin --format trufflehog` parses the report on
// stdin, as the file would be.
#[test]
fn sha337_t2_trufflehog_report_on_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let report = std::fs::read(TRUFFLEHOG).unwrap();
    let output = rotate_in(dir.path())
        .args(["plan", "--stdin", "--format", "trufflehog"])
        .write_stdin(report.clone())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    for value in [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001",
        "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake0002",
    ] {
        assert!(stdout.contains(&fp(value)), "fingerprint missing");
        assert!(!stdout.contains(value), "value leaked");
    }
    assert!(
        stdout.contains(&format!("deploy/aws.env:3@{COMMIT}")),
        "{stdout}"
    );
    // Read as a report, not as one secret.
    let whole = String::from_utf8(report).unwrap();
    assert!(
        !stdout.contains(&fp(whole.trim_end())),
        "read as one secret"
    );
}

// SHA-337 T2 (AC5): `--provider` with `--stdin --format` exits 2 without
// echoing the typed name, and `--format` needs an input.
#[test]
fn sha337_t2_provider_with_format_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let pasted = "ghp_canaryPastedAsProvider00000000000000";
    for format in ["github-alert", "trufflehog", "gitleaks"] {
        rotate_in(dir.path())
            .args(["plan", "--stdin", "--provider", pasted, "--format", format])
            .write_stdin("[]")
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("--format"))
            .stderr(predicate::str::contains(pasted).not());
    }
    rotate_in(dir.path())
        .args(["plan", "--format", "github-alert"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty());
}

// SHA-337 (AC4): a malformed alert document on stdin is refused by line and
// column, with no body text, even at trace level.
#[test]
fn sha337_malformed_alert_document_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let canary = "ghp_canaryMalformedAlertBody000000000000";
    let input = format!("[\n  {{\"number\": 3, \"secret_type\": \"x\", \"secret\": \"{canary}\"\n");
    rotate_in(dir.path())
        .args(["-vvv", "plan", "--stdin", "--format", "github-alert"])
        .env("RUST_LOG", "trace")
        .write_stdin(input)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "github-alert report is not valid JSON at line 3, column",
        ))
        .stderr(predicate::str::contains("canary").not());
}
