//! SHA-214 T3 (CLI half): a bad rotate.yaml stops every command with exit 2
//! and a message naming the field and the line.

use assert_cmd::Command;
use predicates::prelude::*;

fn rotate_in(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("rotate").expect("rotate binary builds");
    cmd.current_dir(dir)
        .env_remove("ROTATE_CONFIG")
        .env_remove("ROTATE_AUDIT_LOG")
        .env_remove("ROTATE_STATE_FILE")
        .env_remove("ROTATE_OVERLAP");
    cmd
}

#[test]
fn invalid_config_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rotate.yaml"), "overlap_window: soon\n").unwrap();

    for subcommand in ["plan", "apply", "rollback", "status"] {
        rotate_in(dir.path())
            .arg(subcommand)
            .assert()
            .code(2)
            .stderr(predicate::str::contains(
                "rotate.yaml: overlap_window at line 1",
            ))
            .stderr(predicate::str::contains("invalid duration \"soon\""))
            .stderr(predicate::str::contains("not implemented").not());
    }
}

#[test]
fn unknown_key_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("rotate.yaml"),
        "overlap_window: 0s\nunknown_key: 1\n",
    )
    .unwrap();
    rotate_in(dir.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown_key at line 2"));
}

#[test]
fn bad_overlap_env_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    rotate_in(dir.path())
        .env("ROTATE_OVERLAP", "later")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("ROTATE_OVERLAP: invalid duration"));
}

#[test]
fn valid_config_reaches_the_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("rotate.yaml"), "overlap_window: 30m\n").unwrap();
    // The subcommand itself is still a stub (SHA-250); reaching it proves the
    // config loaded.
    rotate_in(dir.path())
        .arg("plan")
        .assert()
        .stderr(predicate::str::contains("rotate plan: not implemented"));
}
