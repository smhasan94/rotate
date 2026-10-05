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
    std::fs::write(
        dir.path().join("rotate.yaml"),
        "overlap_window: 30m\nstate_file: elsewhere/state.json\n",
    )
    .unwrap();
    // `status` needs no input. It reports the state file the config names,
    // which proves the config loaded: an empty one is "no rotations", and
    // one with a wide mode is refused by that path.
    rotate_in(dir.path())
        .arg("status")
        .assert()
        .code(0)
        .stdout("no rotations\n");
    std::fs::create_dir(dir.path().join("elsewhere")).unwrap();
    std::fs::write(
        dir.path().join("elsewhere/state.json"),
        r#"{"version": 1, "rotations": []}"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join("elsewhere/state.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    rotate_in(dir.path())
        .arg("status")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("elsewhere/state.json"));
}

// SHA-287 T1 (AC1, AC4): plain http to a non-loopback host stops every
// command with exit 2, naming the field and the rule, before any state
// file or provider is touched.
#[test]
fn sha287_t1_http_endpoint_exits_2_before_anything() {
    for (field, yaml) in [
        (
            "providers.aws.endpoint_url",
            "providers:\n  aws:\n    endpoint_url: http://api.example.com\n",
        ),
        (
            "providers.github.api_url",
            "providers:\n  github:\n    api_url: http://api.example.com\n",
        ),
        (
            "providers.npm.registry",
            "providers:\n  npm:\n    registry: http://api.example.com\n",
        ),
        (
            "providers.openai.api_url",
            "providers:\n  openai:\n    api_url: http://api.example.com\n",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rotate.yaml"), yaml).unwrap();
        for subcommand in ["plan", "apply", "rollback", "status"] {
            rotate_in(dir.path())
                .arg(subcommand)
                .assert()
                .code(2)
                .stderr(predicate::str::contains(format!(
                    "rotate.yaml: {field} at line"
                )))
                .stderr(predicate::str::contains("only https:// is accepted"));
        }
        assert!(
            !dir.path().join(".rotate").exists(),
            "{field}: a state directory was created"
        );
    }
}
