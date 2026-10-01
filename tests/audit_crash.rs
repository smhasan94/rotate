//! SHA-219 T5 and T6, which need a separate process.
//!
//! The child is this test binary re-run with `ROTATE_TEST_AUDIT_CHILD` set
//! to `<mode>:<path>`, so that only `audit_child` does anything.
//! - `append100`: appends 100 entries, pausing between them, until killed.
//! - `once`: appends one entry with the actor resolved from the environment.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rotate::audit::{read_all, AuditEvent, AuditLog, AuditStep, Outcome};
use rotate::secret::Fingerprint;

const CHILD_ENV: &str = "ROTATE_TEST_AUDIT_CHILD";

fn event(i: usize) -> AuditEvent {
    AuditEvent::new(
        format!("rot-{i:04}"),
        "aws",
        Fingerprint::of(format!("old-{i}").as_bytes()),
        AuditStep::Update,
        Outcome::Ok,
    )
    .with_replacement(Fingerprint::of(format!("new-{i}").as_bytes()))
    .with_consumer(format!("org/repo:SECRET_{i}"))
}

/// Runs only as the child; a no-op in a normal test run.
#[test]
fn audit_child() {
    let Ok(spec) = std::env::var(CHILD_ENV) else {
        return;
    };
    let (mode, path) = spec.split_once(':').expect("mode:path");
    let path = PathBuf::from(path);
    let mut log = AuditLog::open(&path).expect("child opens the log");
    match mode {
        "append100" => {
            for i in 0..100 {
                log.append(event(i)).unwrap();
                thread::sleep(Duration::from_millis(3));
            }
        }
        "once" => {
            log.append(event(0)).unwrap();
        }
        other => panic!("unknown child mode {other}"),
    }
}

fn child(mode: &str, path: &Path) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["audit_child", "--exact", "--test-threads=1"])
        .env(CHILD_ENV, format!("{mode}:{}", path.display()))
        .stdout(Stdio::null());
    cmd
}

fn line_count(path: &Path) -> usize {
    std::fs::read(path)
        .map(|b| b.iter().filter(|&&c| c == b'\n').count())
        .unwrap_or(0)
}

#[test]
fn killed_writer_leaves_only_complete_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".rotate/audit.jsonl");
    // A varying kill point between 1 and 99 lines, without a rand crate.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as usize;
    let target = 1 + nanos % 99;

    let mut writer = child("append100", &path).spawn().expect("spawn writer");
    let deadline = Instant::now() + Duration::from_secs(30);
    while line_count(&path) < target && Instant::now() < deadline {
        thread::sleep(Duration::from_micros(200));
    }
    writer.kill().expect("SIGKILL the writer");
    writer.wait().unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines.len() >= target && lines.len() < 100,
        "killed after {} lines, target {target}",
        lines.len()
    );
    assert!(text.ends_with('\n'), "last line is complete");
    for (n, line) in lines.iter().enumerate() {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("line {} does not parse: {:?}", n + 1, e.classify()));
    }
    let entries: Vec<_> = read_all(&path).unwrap().collect();
    assert_eq!(entries.len(), lines.len());
    for (i, entry) in entries.into_iter().enumerate() {
        let entry = entry.expect("every line is a valid entry");
        assert_eq!(entry.rotation_id, format!("rot-{i:04}"));
    }
}

#[test]
fn rotate_actor_env_sets_actor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let status = child("once", &path)
        .env("ROTATE_ACTOR", "ci-bot")
        .status()
        .expect("run child");
    assert!(status.success());
    let entries: Vec<_> = read_all(&path).unwrap().map(Result::unwrap).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].actor, "ci-bot");
}

#[test]
fn actor_defaults_to_user_at_host() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let status = child("once", &path)
        .env_remove("ROTATE_ACTOR")
        .env("USER", "audit-tester")
        .status()
        .expect("run child");
    assert!(status.success());
    let entries: Vec<_> = read_all(&path).unwrap().map(Result::unwrap).collect();
    let actor = &entries[0].actor;
    let (user, host) = actor.split_once('@').expect("user@host");
    assert_eq!(user, "audit-tester");
    assert!(!host.is_empty() && !host.contains('\n'), "{actor}");
}
