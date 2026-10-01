//! Integration tests for the CLI surface (SHA-194 T2 to T6).

use assert_cmd::Command;
use predicates::prelude::*;

fn rotate() -> Command {
    Command::cargo_bin("rotate").expect("rotate binary builds")
}

fn assert_stub(name: &str) {
    rotate()
        .arg(name)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(format!(
            "rotate {name}: not implemented"
        )));
}

/// `plan`, `apply` and `rollback` need input before reaching their stub.
fn assert_needs_input(args: &[&str]) {
    rotate()
        .args(args)
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "no input: pass a report path or --stdin",
        ));
}

/// T2 covers AC2.
#[test]
fn version_prints_crate_version() {
    rotate()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^rotate \d+\.\d+\.\d+\n$").unwrap());
}

/// T3 covers AC3.
#[test]
fn no_args_runs_plan() {
    assert_needs_input(&[]);
}

/// T4 covers AC4.
#[test]
fn apply_without_input_exits_2() {
    assert_needs_input(&["apply"]);
}

/// T4 covers AC4.
#[test]
fn rollback_without_input_exits_2() {
    assert_needs_input(&["rollback"]);
}

/// T4 covers AC4.
#[test]
fn status_stub_exits_2() {
    assert_stub("status");
}

/// T5 covers AC5.
#[test]
fn unknown_subcommand_exits_2() {
    rotate()
        .arg("bogus")
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Usage"));
}

/// T5 covers AC5: a token typed where a subcommand or flag goes is never
/// echoed, so a pasted secret cannot reach stderr.
#[test]
fn unknown_arg_is_not_echoed() {
    let canary = "AKIAIOSFODNN7EXAMPLE_canary_9f3c";
    for args in [vec![canary], vec!["plan", canary], vec!["--nope", canary]] {
        rotate()
            .args(&args)
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(canary).not())
            .stderr(predicate::str::contains("--stdin"))
            .stderr(predicate::str::contains("Usage"));
    }
}

/// T6 covers AC6.
#[test]
fn help_exits_0() {
    rotate()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
    rotate()
        .args(["plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}

/// Extra: global flags before the subcommand do not swallow it.
#[test]
fn global_flags_accepted_before_subcommand() {
    assert_needs_input(&["--json", "-v", "plan"]);
}

/// Extra: clap's own errors for missing values still exit 2.
#[test]
fn missing_flag_value_exits_2() {
    rotate()
        .arg("--config")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--config"));
}
