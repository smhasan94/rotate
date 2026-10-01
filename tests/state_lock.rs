//! SHA-220 T4: a second process cannot open the state store for writing
//! while another holds the lock, and finds out within a second.
//!
//! The lock holder is a real child process: this test binary re-run with
//! `ROTATE_TEST_HOLD_LOCK` set, so that only `child_holds_lock` does
//! anything. The child opens the store, creates `<state>.ready`, and holds
//! the lock until `<state>.release` appears or it is killed.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use rotate::state::{lock_path, StateError, StateStore};

const HOLD_ENV: &str = "ROTATE_TEST_HOLD_LOCK";

fn marker(state: &Path, suffix: &str) -> PathBuf {
    let mut name = state.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn wait_for(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Runs only as the child; a no-op in a normal test run.
#[test]
fn child_holds_lock() {
    let Ok(state) = std::env::var(HOLD_ENV) else {
        return;
    };
    let state = PathBuf::from(state);
    let _store = StateStore::open(&state).expect("child opens the store");
    std::fs::write(marker(&state, ".ready"), b"").unwrap();
    wait_for(&marker(&state, ".release"), Duration::from_secs(30));
}

fn spawn_holder(state: &Path) -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["child_holds_lock", "--exact", "--test-threads=1"])
        .env(HOLD_ENV, state)
        .spawn()
        .expect("spawn lock holder");
    if !wait_for(&marker(state, ".ready"), Duration::from_secs(10)) {
        let _ = child.kill();
        panic!("child never took the lock");
    }
    child
}

#[test]
fn second_process_fails_fast_naming_lock() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join(".rotate/state.json");
    let mut child = spawn_holder(&state);

    let started = Instant::now();
    let result = StateStore::open(&state);
    let elapsed = started.elapsed();

    let err = result.expect_err("the lock is held by the child");
    assert!(elapsed < Duration::from_secs(1), "took {elapsed:?}");
    assert!(matches!(err, StateError::Locked { .. }), "{err}");
    let lock = lock_path(&state);
    assert!(
        err.to_string().contains(&lock.display().to_string()),
        "message must name the lock file: {err}"
    );
    assert!(err.is_usage(), "a held lock maps to exit 2");

    std::fs::write(marker(&state, ".release"), b"").unwrap();
    assert!(child.wait().unwrap().success());
    StateStore::open(&state).expect("lock is free once the child exits");
}

#[test]
fn lock_released_when_holder_dies() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let mut child = spawn_holder(&state);
    assert!(StateStore::open(&state).is_err());

    child.kill().unwrap();
    child.wait().unwrap();
    StateStore::open(&state).expect("the kernel drops the lock of a killed process");
}
