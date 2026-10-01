//! SHA-246 CLI half: what the binary prints on stdout and stderr, from
//! console writes, errors, panics, JSON and clap errors, never holds a
//! secret value.
//!
//! T2, T3, T5 and T6 drive the hidden `__test-console` subcommand, which
//! exists only with the `test-commands` feature (CI runs `--all-features`).
//! It reads the canary from stdin as a `SecretValue`, so the value is
//! registered exactly as real input is. Canaries are unique per test and
//! token-shaped ones are built at runtime so no literal in this file looks
//! like a credential to a secret scanner.

use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

fn rotate_in(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("rotate").expect("rotate binary builds");
    cmd.current_dir(dir)
        .env_remove("ROTATE_CONFIG")
        .env_remove("ROTATE_AUDIT_LOG")
        .env_remove("ROTATE_STATE_FILE")
        .env_remove("ROTATE_OVERLAP")
        .env_remove("RUST_BACKTRACE");
    cmd
}

/// A token-shaped value the redactor's GitHub pattern catches without it
/// ever being registered (nothing is registered at parse time).
fn github_shaped() -> String {
    ["gh", "p_", "consoleT7canary", "0123456789abcdefghijk"].concat()
}

/// Plan JSON is one document and holds no value, with or without the mock
/// providers.
#[test]
fn plan_json_holds_no_value() {
    let dir = tempfile::tempdir().unwrap();
    let canary = ["console-plan-json-", "6a2f91c0"].concat();
    let output = rotate_in(dir.path())
        .args(["--json", "plan", "--stdin"])
        .write_stdin(canary.clone())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let _: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON document");
    assert!(!stdout.contains(&canary));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&canary));
}

// T7 (AC2): clap errors that would echo a typed value do not.
#[test]
fn clap_value_errors_not_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let canary = github_shaped();
    for args in [
        vec!["--overlap", canary.as_str()],
        vec!["plan", "--concurrency", canary.as_str()],
        vec!["plan", "report.json", "--format", canary.as_str()],
        vec!["plan", "--stdin", "--provider", "aws", canary.as_str()],
        vec![canary.as_str()],
    ] {
        rotate_in(dir.path())
            .args(&args)
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(canary.as_str()).not())
            .stderr(predicate::str::contains("consoleT7canary").not())
            .stderr(predicate::str::contains("--stdin"))
            .stderr(predicate::str::contains("Usage"));
    }
    rotate_in(dir.path())
        .args(["--overlap", "soon"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid value for '--overlap"));
}

// T7 (AC2): a token pasted after --config is not repeated.
#[test]
fn config_path_not_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let canary = github_shaped();
    rotate_in(dir.path())
        .args(["--config", canary.as_str(), "status"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("could not read the config file"))
        .stderr(predicate::str::contains("consoleT7canary").not());
}

/// Release builds never contain the hidden subcommand.
#[cfg(not(feature = "test-commands"))]
#[test]
fn test_command_absent_without_feature() {
    let dir = tempfile::tempdir().unwrap();
    rotate_in(dir.path())
        .args(["__test-console", "out"])
        .write_stdin("console-absent-canary")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unrecognized argument"));
}

#[cfg(feature = "test-commands")]
mod hidden {
    use super::*;
    use rotate::secret::SecretValue;

    struct Run {
        code: Option<i32>,
        stdout: String,
        stderr: String,
        marker: String,
    }

    /// Runs `__test-console <mode>` with `canary` on stdin, logging at
    /// trace level, with the audit log and state file in `dir`.
    fn run(dir: &Path, mode: &str, canary: &str) -> Run {
        let output = rotate_in(dir)
            .args(["-vvv", "--json", "--audit-log"])
            .arg(dir.join("audit.jsonl"))
            .arg("--state-file")
            .arg(dir.join("state.json"))
            .args(["__test-console", mode])
            .write_stdin(canary.to_owned())
            .output()
            .unwrap();
        Run {
            code: output.status.code(),
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
            marker: format!("[REDACTED {}]", SecretValue::from(canary).fingerprint()),
        }
    }

    // T1 through the binary (AC1)
    #[test]
    fn out_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let canary = ["console-cli-out-", "d41e8a07"].concat();
        let run = run(dir.path(), "out", &canary);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(run.stdout, format!("value: {}\n", run.marker));
        assert!(!run.stderr.contains(&canary));
    }

    // T2 (AC2)
    #[test]
    fn error_display_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let canary = ["console-cli-error-", "52c0b7e9"].concat();
        let run = run(dir.path(), "error", &canary);
        assert_eq!(run.code, Some(1));
        assert!(run.stdout.is_empty());
        assert!(
            run.stderr
                .contains(&format!("error: provider rejected {}\n", run.marker)),
            "{}",
            run.stderr
        );
        assert!(!run.stderr.contains(&canary));
    }

    // T3 (AC3)
    #[test]
    fn panic_is_redacted_and_exits_101() {
        let dir = tempfile::tempdir().unwrap();
        let canary = ["console-cli-panic-", "8e3fa61d"].concat();
        let run = run(dir.path(), "panic", &canary);
        assert_eq!(run.code, Some(101));
        assert!(
            run.stderr.contains("thread 'main' panicked at src/main.rs:"),
            "{}",
            run.stderr
        );
        assert!(
            run.stderr
                .contains(&format!("test-console panic with {}\n", run.marker)),
            "{}",
            run.stderr
        );
        assert!(!run.stderr.contains(&canary));
        assert!(!run.stdout.contains(&canary));
    }

    fn strings<'a>(value: &'a serde_json::Value, out: &mut Vec<&'a str>) {
        match value {
            serde_json::Value::String(s) => out.push(s),
            serde_json::Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
            serde_json::Value::Object(map) => map.values().for_each(|v| strings(v, out)),
            _ => {}
        }
    }

    // T5 (AC5)
    #[test]
    fn json_output_is_one_redacted_document() {
        let dir = tempfile::tempdir().unwrap();
        let canary = ["console-cli-json-", "\\back\"quote-0f9c"].concat();
        let run = run(dir.path(), "json", &canary);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        let doc: serde_json::Value = serde_json::from_str(&run.stdout).expect("one JSON document");
        let mut all = Vec::new();
        strings(&doc, &mut all);
        assert!(all.iter().all(|s| !s.contains(&canary)), "{all:?}");
        let with_marker = all.iter().filter(|s| s.contains(&run.marker)).count();
        assert_eq!(with_marker, 3, "{all:?}");
        assert!(!run.stdout.contains("console-cli-json-"));
    }

    // T6 (AC1, AC2, AC3)
    #[test]
    fn canary_absent_everywhere() {
        for mode in ["out", "error", "panic", "json"] {
            let dir = tempfile::tempdir().unwrap();
            let canary = format!("console-cli-t6-{mode}-{}", "3b7d0e55");
            let run = run(dir.path(), mode, &canary);
            assert!(!run.stdout.contains(&canary), "{mode}: stdout");
            assert!(!run.stderr.contains(&canary), "{mode}: stderr");
            // The tracing event is on stderr, redacted.
            assert!(
                run.stderr
                    .contains(&format!("test-console saw {}", run.marker)),
                "{mode}: {}",
                run.stderr
            );
            for entry in walk(dir.path()) {
                let bytes = std::fs::read(&entry).unwrap();
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(&canary),
                    "{mode}: canary in {}",
                    entry.display()
                );
            }
        }
    }

    fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files.extend(walk(&path));
            } else {
                files.push(path);
            }
        }
        files
    }
}
