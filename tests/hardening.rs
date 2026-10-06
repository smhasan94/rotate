//! SHA-204: core dumps are off for a running rotate, and a refused `mlock`
//! costs one warning and nothing else.
//!
//! T1 reads `/proc` and runs on Linux only. T2 needs the `test-commands`
//! hook, T4 the `test-providers` mock that identifies `mock_` secrets; CI
//! runs `cargo test --all-features` on Linux and macOS.

#![cfg(unix)]

// T1 (AC1, AC3)
#[cfg(target_os = "linux")]
#[test]
fn running_rotate_has_core_limit_zero_and_is_not_dumpable() {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    // `plan --stdin` blocks reading stdin until it is closed, so the
    // process is alive, past `main`'s first line, while /proc is read.
    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("rotate"))
        .args(["plan", "--stdin"])
        .current_dir(dir.path())
        .env_remove("ROTATE_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let proc_dir = Path::new("/proc").join(child.id().to_string());

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut core_line = String::new();
    while Instant::now() < deadline {
        let limits = std::fs::read_to_string(proc_dir.join("limits")).unwrap_or_default();
        core_line = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap_or_default()
            .to_owned();
        if core_line.split_whitespace().skip(4).take(2).eq(["0", "0"]) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Not dumpable: the kernel hands /proc/<pid> to root. Only observable
    // when this test is not root itself.
    let owner = std::fs::metadata(proc_dir.join("status")).map(|m| m.uid());
    let euid = rustix::process::geteuid().as_raw();

    drop(child.stdin.take());
    let _ = child.kill();
    let _ = child.wait();

    let fields: Vec<&str> = core_line.split_whitespace().collect();
    assert_eq!(
        fields.get(4..6),
        Some(&["0", "0"][..]),
        "soft and hard core limits are not 0: {core_line:?}"
    );
    if euid != 0 {
        assert_eq!(owner.unwrap(), 0, "rotate is still dumpable");
    }
}

// T2 (AC1, AC3)
#[cfg(feature = "test-commands")]
#[test]
fn hardening_report_shows_core_limit_zero() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("hardening.txt");
    let status = std::process::Command::new(assert_cmd::cargo::cargo_bin("rotate"))
        .arg("--version")
        .env("ROTATE_TEST_HARDENING_REPORT", &report)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let text = std::fs::read_to_string(&report).expect("rotate wrote no hardening report");
    assert!(text.contains("core_soft=0 core_hard=0"), "{text}");
    #[cfg(target_os = "linux")]
    assert!(text.contains("dumpable=0"), "{text}");
}

// T4 (AC2): a real refusal. `ulimit -l 0` makes every `mlock` fail for an
// unprivileged process on Linux (EPERM) and macOS (EAGAIN). Root has
// CAP_IPC_LOCK and ignores the limit, so the test cannot run there.
#[cfg(feature = "test-providers")]
#[test]
fn refused_mlock_warns_once_and_plan_still_works() {
    use assert_cmd::Command;
    use rotate::secret::SecretValue;

    if rustix::process::geteuid().is_root() {
        return;
    }
    let canary = "mock_sha204canaryvalue0001";
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new("/bin/sh")
        .args(["-c", "ulimit -l 0 && exec \"$0\" plan --stdin"])
        .arg(assert_cmd::cargo::cargo_bin("rotate"))
        .current_dir(dir.path())
        .env_remove("ROTATE_CONFIG")
        .write_stdin(format!("{canary}\n"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr: {stderr}");
    let fingerprint = SecretValue::from(canary).fingerprint().to_string();
    assert!(stdout.contains(&fingerprint), "stdout: {stdout}");
    assert_eq!(
        stderr
            .matches("could not lock secret values in memory")
            .count(),
        1,
        "stderr: {stderr}"
    );
    assert!(stderr.contains("ulimit -l"), "stderr: {stderr}");
    assert!(!stdout.contains(canary) && !stderr.contains(canary));
}
