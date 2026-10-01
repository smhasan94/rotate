//! SHA-248 CLI half: `rotate plan` prints the assessment table or JSON and
//! exits 0, including when rows are unsupported, and never prints a value.
//!
//! The mock providers come from the `test-providers` feature (CI runs
//! `--all-features`); without it every row is unsupported, which these tests
//! also accept where noted.

use assert_cmd::Command;
use predicates::prelude::*;
use rotate::secret::SecretValue;

const TRUFFLEHOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/trufflehog.ndjson"
);
const GITLEAKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gitleaks.json");

fn rotate_in(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("rotate").expect("rotate binary builds");
    cmd.current_dir(dir).env_remove("ROTATE_CONFIG");
    cmd
}

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

// T2 (AC2)
#[test]
fn unsupported_row_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    rotate_in(dir.path())
        .args(["plan", "--stdin"])
        .write_stdin("zzz_matches_no_provider\n")
        .assert()
        .code(0)
        .stdout(
            predicate::str::is_match(format!(
                r"(?m)^-\s+{}\s+unsupported",
                fp("zzz_matches_no_provider")
            ))
            .unwrap(),
        );
}

#[cfg(feature = "test-providers")]
#[test]
fn report_rows_show_status_per_secret() {
    let dir = tempfile::tempdir().unwrap();
    let assert = rotate_in(dir.path())
        .args(["plan", GITLEAKS])
        .assert()
        .code(0);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let github = fp("ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001");
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("github") && l.contains(&github) && l.contains("valid")),
        "{stdout}"
    );
    // The gitleaks AWS finding is only a key id: not rotatable, reason in
    // the notes.
    assert!(stdout.contains("not rotatable"), "{stdout}");
    assert!(stdout.contains("Notes:"), "{stdout}");
}

#[test]
fn json_output_is_an_array_with_stable_fields() {
    let dir = tempfile::tempdir().unwrap();
    let output = rotate_in(dir.path())
        .args(["--json", "plan", TRUFFLEHOG])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let rows: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rows = rows.as_array().expect("a JSON array");
    assert_eq!(rows.len(), 3);
    for row in rows {
        for key in [
            "provider",
            "fingerprint",
            "status",
            "reason",
            "detectors",
            "sources",
            "scope",
            "scope_error",
        ] {
            assert!(row.get(key).is_some(), "{key} missing in {row}");
        }
    }
}

#[test]
fn concurrency_flag_is_validated() {
    let dir = tempfile::tempdir().unwrap();
    rotate_in(dir.path())
        .args(["plan", GITLEAKS, "--concurrency", "2"])
        .assert()
        .code(0);
    rotate_in(dir.path())
        .args(["plan", GITLEAKS, "--concurrency", "0"])
        .assert()
        .code(2);
}

// T8 (AC1 to AC7), CLI half: no value in stdout or stderr, table or JSON.
#[test]
fn plan_output_never_contains_a_value() {
    let dir = tempfile::tempdir().unwrap();
    let canary = "ghp_canaryAssessCli0000000000000000000";
    let fixture_values = [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001",
        "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake0002",
    ];
    let runs: Vec<(Vec<&str>, Option<String>)> = vec![
        (vec!["plan", "--stdin"], Some(format!("{canary}\n"))),
        (
            vec!["--json", "plan", "--stdin"],
            Some(format!("{canary}\n")),
        ),
        (vec!["plan", TRUFFLEHOG], None),
        (vec!["--json", "plan", TRUFFLEHOG], None),
        (vec!["plan", GITLEAKS], None),
    ];
    for (args, stdin) in runs {
        let mut cmd = rotate_in(dir.path());
        cmd.args(&args);
        if let Some(input) = stdin {
            cmd.write_stdin(input);
        }
        let output = cmd.output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            assert!(!text.contains(canary), "{args:?}: canary leaked");
            for (index, value) in fixture_values.iter().enumerate() {
                assert!(
                    !text.contains(value),
                    "{args:?}: fixture value {index} leaked"
                );
            }
        }
    }
}
