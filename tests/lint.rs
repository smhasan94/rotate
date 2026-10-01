//! SHA-246 T4 (AC4): the repository's `clippy.toml` makes clippy reject
//! `println!` outside a module that opts out.
//!
//! Runs `cargo clippy` on the fixture crate `tests/fixtures/clippy_lint`
//! with `CLIPPY_CONF_DIR` pointing at this repository, in a fresh target
//! dir. When clippy is not installed the test skips with a note, unless
//! `ROTATE_REQUIRE_CLIPPY` is set (CI's test job sets it), where a missing
//! clippy is a failure.

#![allow(clippy::disallowed_macros)]

use std::path::Path;
use std::process::Command;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn clippy_installed() -> bool {
    Command::new("cargo")
        .args(["clippy", "--version"])
        .output()
        .is_ok_and(|o| o.status.success())
}

// T4 (AC4)
#[test]
fn println_outside_console_fails_clippy() {
    if !clippy_installed() {
        assert!(
            std::env::var_os("ROTATE_REQUIRE_CLIPPY").is_none(),
            "ROTATE_REQUIRE_CLIPPY is set but cargo clippy is not installed"
        );
        eprintln!("skipped: cargo clippy is not installed");
        return;
    }
    let fixture = Path::new(ROOT).join("tests/fixtures/clippy_lint");
    let target = tempfile::tempdir().unwrap();
    let output = Command::new("cargo")
        .args(["clippy", "--quiet", "--offline", "--manifest-path"])
        .arg(fixture.join("Cargo.toml"))
        .args(["--", "-D", "clippy::disallowed_macros"])
        .env("CLIPPY_CONF_DIR", ROOT)
        .env("CARGO_TARGET_DIR", target.path())
        .env_remove("RUSTFLAGS")
        .output()
        .expect("run cargo clippy");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "clippy passed:\n{stderr}");
    assert!(
        stderr.contains("use of a disallowed macro `std::println`"),
        "{stderr}"
    );
    assert!(stderr.contains("src/lib.rs"), "{stderr}");
    assert!(!stderr.contains("src/console.rs"), "{stderr}");
}
