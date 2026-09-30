//! Integration tests for the CLI surface (SHA-194 T2 to T6).

use assert_cmd::Command;
use predicates::prelude::*;

fn rotate() -> Command {
    Command::cargo_bin("rotate").expect("rotate binary builds")
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
fn no_args_runs_plan_stub() {
    rotate()
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("rotate plan: not implemented"));
}

/// T4 covers AC4.
#[test]
fn subcommand_stubs_exit_2() {
    for name in ["apply", "rollback", "status"] {
        rotate()
            .arg(name)
            .assert()
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(format!(
                "rotate {name}: not implemented"
            )));
    }
}

/// T5 covers AC5.
#[test]
fn unknown_subcommand_exits_2() {
    rotate()
        .arg("bogus")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage"));
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
    rotate()
        .args(["--json", "-v", "plan"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("rotate plan: not implemented"));
}
