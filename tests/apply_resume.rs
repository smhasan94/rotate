//! SHA-258: resume, idempotency and the overlap window, end to end against
//! the `test-providers` mocks.
//!
//! Every run is a new process, as a real re-run would be: what one run
//! leaves in `.rotate/state.json` is all the next one knows. Some tests
//! seed the state file directly to stand for a process killed mid-run. The
//! scenario's `clock_offset_secs` moves the clock apply uses for the
//! overlap window (the injectable clock). The binary exports the call log
//! (target, method, reference) by fingerprint only. T8 needs one process,
//! so it drives the executor through the library API. Test values are
//! fake, unique per test, and shaped so no secret scanner matches them.

#![cfg(all(unix, feature = "test-providers"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use rotate::secret::SecretValue;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// What the npm mock mints for the first replacement in a process.
const REPLACEMENT: &str = "npm_npm-replacement-1";
/// The ref the npm mock gives that replacement.
const REPLACEMENT_REF: &str = "npm-ref-1";
const GHA: &str = "gha:org/repo:NPM_TOKEN";
const SM: &str = "sm:prod/npm-publish";

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

struct Run {
    dir: tempfile::TempDir,
    value: String,
    scenario: Value,
}

impl Run {
    /// One npm secret held by two consumers; confirmation must come from
    /// `--confirm`.
    fn new(value: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut run = Self {
            dir,
            value: value.to_owned(),
            scenario: Value::Null,
        };
        run.scenario = json!({
            "consumers": [
                { "name": "github-actions", "matches": [
                    { "fingerprint": fp(value), "ref": GHA, "method": "by_name" } ] },
                { "name": "aws-secrets-manager", "matches": [
                    { "fingerprint": fp(value), "ref": SM } ] }
            ],
            "call_log": run.file("calls.jsonl"),
            "prompt": "panic",
        });
        run.write();
        run
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    fn write(&self) {
        std::fs::write(self.file("scenario.json"), self.scenario.to_string()).unwrap();
    }

    fn set(&mut self, edit: impl FnOnce(&mut Value)) {
        edit(&mut self.scenario);
        self.write();
    }

    /// Moves the clock apply uses by `secs` from now.
    fn clock(&mut self, secs: i64) {
        self.set(|s| s["clock_offset_secs"] = json!(secs));
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::cargo_bin("rotate")
            .unwrap()
            .current_dir(self.path())
            .env_remove("ROTATE_CONFIG")
            .env_remove("ROTATE_STATE_FILE")
            .env_remove("ROTATE_AUDIT_LOG")
            .env_remove("ROTATE_OVERLAP")
            .env("ROTATE_ACTOR", "ci@runner")
            .env("ROTATE_TEST_SCENARIO", self.file("scenario.json"))
            .args(args)
            .write_stdin(format!("{}\n", self.value))
            .output()
            .unwrap()
    }

    fn planned_id(&self) -> String {
        let output = self.run(&["--json", "plan", "--stdin"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        plan["rotations"][0]["rotation_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `apply --stdin --confirm <id>` plus `extra`.
    fn apply(&self, id: &str, extra: &[&str]) -> Output {
        let mut args = vec!["apply", "--stdin", "--confirm", id];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn call_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// Every call as `target.method`.
    fn calls(&self) -> Vec<String> {
        self.call_lines().iter().map(name).collect()
    }

    /// The state-changing calls as `target.method`.
    fn mutating(&self) -> Vec<String> {
        self.call_lines()
            .iter()
            .filter(|c| c["mutating"] == true)
            .map(name)
            .collect()
    }

    fn rotation(&self, id: &str) -> Value {
        let state: Value = serde_json::from_str(&self.read(".rotate/state.json")).unwrap();
        state["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rotation_id"] == id)
            .unwrap_or_else(|| panic!("no rotation {id} in {state}"))
            .clone()
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file(".rotate/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.file(name)).unwrap_or_default()
    }

    /// Writes `rotations` as the state file, private as rotate requires.
    fn seed(&self, rotations: Value) {
        let dir = self.file(".rotate");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            json!({ "version": 1, "rotations": rotations }).to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn name(c: &Value) -> String {
    format!(
        "{}.{}",
        c["target"].as_str().unwrap(),
        c["method"].as_str().unwrap()
    )
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn updated(consumer: &str, consumer_ref: &str) -> Value {
    json!({ "consumer": consumer, "consumer_ref": consumer_ref,
            "status": "updated", "holds": "secret" })
}

/// A seeded rotation record of the npm secret `value` at `step`, with a
/// replacement the mock minted in an earlier process.
fn record(id: &str, value: &str, step: &str, consumers: Value) -> Value {
    json!({
        "rotation_id": id,
        "provider": "npm",
        "fingerprint": fp(value),
        "replacement_fingerprint": fp(REPLACEMENT),
        "replacement_ref": REPLACEMENT_REF,
        "step": step,
        "consumers": consumers,
        "revoke_not_before": null,
        "started_at": "2026-10-01T00:00:00Z",
        "updated_at": "2026-10-01T00:00:00Z",
        "force": false,
    })
}

fn not_before(rotation: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(rotation["revoke_not_before"].as_str().unwrap(), &Rfc3339).unwrap()
}

/// Plans, then applies with a 10 minute window: exits 3, pending.
fn pending(run: &Run) -> (String, Output) {
    let id = run.planned_id();
    let output = run.apply(&id, &["--overlap", "10m"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    (id, output)
}

// T1 (AC1)
#[test]
fn overlap_records_pending_revoke_and_says_when() {
    let run = Run::new("npm_resume_t1_value");
    let before = OffsetDateTime::now_utc();
    let (id, output) = pending(&run);

    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "pending_revoke");
    let at = not_before(&rotation);
    assert!(at >= before + time::Duration::minutes(10), "{at}");
    assert!(at <= OffsetDateTime::now_utc() + time::Duration::minutes(10));
    assert!(!run.calls().iter().any(|c| c.ends_with(".revoke")));
    let out = stdout(&output);
    let when = at.format(&Rfc3339).unwrap();
    assert!(
        out.contains(&format!("revoke pending until {when}")),
        "{out}"
    );
    assert!(out.contains("re-run rotate apply after that time"), "{out}");
    let last = run.audit().pop().unwrap();
    assert_eq!(last["step"], "revoke");
    assert_eq!(last["outcome"], "skipped");
}

// T2 (AC2)
#[test]
fn rerun_after_window_revokes_once() {
    let mut run = Run::new("npm_resume_t2_value");
    let (id, _) = pending(&run);
    let entries = run.audit().len();

    run.clock(11 * 60);
    let output = run.apply(&id, &["--overlap", "10m"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(run.mutating(), ["npm.revoke"]);
    let calls = run.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.ends_with(".create_replacement") || c.ends_with(".update")),
        "{calls:?}"
    );
    assert_eq!(run.rotation(&id)["step"], "revoked");
    assert!(stdout(&output).contains("Apply: 1 revoked"));

    let rerun: Vec<(String, String)> = run.audit()[entries..]
        .iter()
        .map(|e| {
            (
                e["step"].as_str().unwrap().to_owned(),
                e["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let pairs: Vec<(&str, &str)> = rerun
        .iter()
        .map(|(s, o)| (s.as_str(), o.as_str()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("plan", "ok"),
            ("create", "skipped"),
            ("update", "skipped"),
            ("update", "skipped"),
            ("verify", "skipped"),
            ("revoke", "ok"),
        ]
    );
}

// T3 (AC3)
#[test]
fn rerun_before_window_makes_no_mutation() {
    let mut run = Run::new("npm_resume_t3_value");
    let (id, _) = pending(&run);
    let at = run.rotation(&id)["revoke_not_before"].clone();

    run.clock(60);
    let output = run.apply(&id, &["--overlap", "10m"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(run.mutating().is_empty(), "{:?}", run.mutating());
    let out = stdout(&output);
    assert!(out.contains("(in 8m"), "{out}");
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "pending_revoke");
    assert_eq!(rotation["revoke_not_before"], at, "the time must not move");

    // A different --overlap does not move a recorded pending revoke.
    run.clock(0);
    let output = run.apply(&id, &["--overlap", "0s"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(run.mutating().is_empty());
}

// T4 (AC4)
#[test]
fn wait_blocks_then_revokes() {
    let run = Run::new("npm_resume_t4_value");
    let id = run.planned_id();
    let started = Instant::now();
    let output = run.apply(&id, &["--wait", "--overlap", "2s"]);
    let elapsed = started.elapsed();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
    assert!(
        stderr(&output).contains("waiting until"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        run.mutating(),
        [
            "npm.create_replacement",
            "github-actions.update",
            "aws-secrets-manager.update",
            "npm.revoke",
        ]
    );
    assert_eq!(run.rotation(&id)["step"], "revoked");
}

// T5 (AC5)
#[test]
fn consumers_updated_resumes_at_verify() {
    let value = "npm_resume_t5_value";
    let run = Run::new(value);
    run.seed(json!([record(
        "rot-t5000000",
        value,
        "consumers_updated",
        json!([
            updated("github-actions", GHA),
            updated("aws-secrets-manager", SM)
        ]),
    )]));
    let output = run.apply("rot-t5000000", &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let calls = run.calls();
    let steps: Vec<&String> = calls
        .iter()
        .filter(|c| !c.ends_with(".check_valid") && !c.ends_with(".describe_scope"))
        .filter(|c| !c.ends_with(".identify") && !c.ends_with(".find"))
        .collect();
    assert_eq!(steps, ["npm.verify_replacement", "npm.revoke"], "{calls:?}");
    assert_eq!(run.rotation("rot-t5000000")["step"], "revoked");
}

// AC5: a replacement that no longer verifies stops before revoke.
#[test]
fn failed_reverify_never_revokes() {
    let value = "npm_resume_t5_fail_value";
    let mut run = Run::new(value);
    run.set(|s| {
        s["providers"] = json!({ "npm": { "fail": { "verify_replacement": "key is inactive" } } })
    });
    run.seed(json!([record(
        "rot-t5f00000",
        value,
        "consumers_updated",
        json!([
            updated("github-actions", GHA),
            updated("aws-secrets-manager", SM)
        ]),
    )]));
    let output = run.apply("rot-t5f00000", &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(run.mutating().is_empty(), "{:?}", run.mutating());
    let rotation = run.rotation("rot-t5f00000");
    assert_eq!(rotation["step"], "failed");
    assert_eq!(rotation["failed_step"], "verify");
}

// T6 (AC6)
#[test]
fn created_after_exit_needs_rollback() {
    let value = "npm_resume_t6_value";
    let run = Run::new(value);
    run.seed(json!([record("rot-t6000000", value, "created", json!([]))]));
    let output = run.apply("rot-t6000000", &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(run.mutating().is_empty(), "{:?}", run.mutating());
    assert!(!run.calls().iter().any(|c| c.ends_with(".update")));
    let rotation = run.rotation("rot-t6000000");
    assert_eq!(rotation["step"], "needs_rollback");
    assert_eq!(rotation["consumers"], json!([]));
    let out = stdout(&output);
    assert!(out.contains("needs rollback"), "{out}");
    assert!(
        out.contains("the replacement value from the earlier run is gone"),
        "{out}"
    );
    assert!(
        out.contains("run rotate rollback with the same input"),
        "{out}"
    );
    let last = run.audit().pop().unwrap();
    assert_eq!(last["outcome"], "failed");

    // Apply leaves it alone from then on; rollback finishes it.
    let output = run.apply("rot-t6000000", &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(run.mutating().is_empty());
    assert!(stderr(&output).contains("run rotate rollback"));
    let output = run.run(&["rollback", "--stdin", "--confirm", "rot-t6000000"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(run.mutating(), ["npm.revoke_replacement"]);
    assert_eq!(run.rotation("rot-t6000000")["step"], "rolled_back");
}

// T7 (AC7)
#[test]
fn revoked_is_already_rotated_for_plan_and_apply() {
    let run = Run::new("npm_resume_t7_value");
    let id = run.planned_id();
    let output = run.apply(&id, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let revoked_at = run.rotation(&id)["updated_at"].as_str().unwrap().to_owned();

    let output = run.run(&["plan", "--stdin"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains(&format!("rotation {id} already rotated on {revoked_at}")),
        "{out}"
    );
    assert!(out.contains("0 to rotate, 1 skipped"), "{out}");
    assert!(run.calls().is_empty(), "{:?}", run.calls());

    let output = run.run(&["--json", "plan", "--stdin"]);
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["rotations"], json!([]));
    assert_eq!(plan["skipped"][0]["reason"], "already rotated");
    assert!(run.calls().is_empty(), "{:?}", run.calls());

    let entries = run.audit().len();
    let output = run.apply(&id, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains("already rotated"));
    assert!(stderr(&output).contains("Nothing to apply."));
    assert!(run.calls().is_empty(), "{:?}", run.calls());
    assert_eq!(run.audit().len(), entries);
    let state: Value = serde_json::from_str(&run.read(".rotate/state.json")).unwrap();
    assert_eq!(state["rotations"].as_array().unwrap().len(), 1);
}

// T8 (AC8): one process, one executor. The replacement minted by the first
// run is still in memory, so the second run updates only the consumer that
// failed, then verifies and revokes.
#[tokio::test]
async fn held_replacement_updates_only_the_failed_consumer() {
    use std::sync::Arc;

    use rotate::apply::{Executor, RunResult};
    use rotate::assess::{assess, AssessOptions};
    use rotate::audit::AuditLog;
    use rotate::calls::CallLog;
    use rotate::config::ConsumersConfig;
    use rotate::consumer::mock::MockConsumer;
    use rotate::consumer::{ConsumerError, ConsumerMatch, ConsumerRegistry};
    use rotate::finding::{Finding, SourceLocation};
    use rotate::provider::mock::MockProvider;
    use rotate::provider::ProviderRegistry;
    use rotate::state::{ConsumerStatus, StateStore, Step};

    let value = "npm_resume_t8_value";
    let dir = tempfile::tempdir().unwrap();
    let log = CallLog::new();
    let mut providers = ProviderRegistry::new();
    let provider = Arc::new(
        MockProvider::new("npm")
            .identify_prefix("npm_")
            .log(log.clone()),
    );
    providers.register(provider.clone());
    let a = Arc::new(
        MockConsumer::new("github-actions")
            .matching(
                SecretValue::from(value).fingerprint(),
                ConsumerMatch::by_name(GHA),
            )
            .log(log.clone()),
    );
    let b = Arc::new(
        MockConsumer::new("aws-secrets-manager")
            .matching(
                SecretValue::from(value).fingerprint(),
                ConsumerMatch::by_value(SM),
            )
            .log(log.clone()),
    );
    b.fail_next("update", ConsumerError::Transient("503 unavailable".into()));
    let mut consumers = ConsumerRegistry::new();
    consumers.register(a.clone());
    consumers.register(b.clone());

    let mut store = StateStore::open(dir.path().join("state.json")).unwrap();
    let mut audit = AuditLog::open_as(dir.path().join("audit.jsonl"), "tester@host").unwrap();
    let finding = Finding::new(SecretValue::from(value), "Mock", SourceLocation::file("a"));
    let assessed = assess(vec![finding], &providers, &AssessOptions::default()).await;
    let mut plan = rotate::plan::build(
        assessed,
        &providers,
        &consumers,
        "0s".parse().unwrap(),
        &ConsumersConfig::default(),
    )
    .await;
    rotate::plan::assign_ids(&mut plan, &mut store).unwrap();
    let rotation = &plan.rotations[0];

    let mut executor = Executor::new(&providers, &consumers, &mut store, &mut audit);
    let first = executor.run(rotation).await;
    assert!(
        matches!(first.result, RunResult::Failed { .. }),
        "{first:?}"
    );
    log.clear();

    let second = executor.run(rotation).await;
    assert_eq!(second.result, RunResult::Revoked, "{second:?}");
    let updates: Vec<_> = log
        .calls()
        .into_iter()
        .filter(|c| c.method == "update")
        .collect();
    assert_eq!(updates.len(), 1, "{updates:?}");
    assert_eq!(updates[0].target, "aws-secrets-manager");
    assert_eq!(updates[0].reference.as_deref(), Some(SM));
    assert!(log.calls().iter().all(|c| c.method != "create_replacement"));
    assert_eq!(
        log.mutating()
            .iter()
            .map(|c| c.method.as_str())
            .collect::<Vec<_>>(),
        ["update", "revoke"]
    );
    drop(executor);

    let new = second.replacement_fingerprint.clone().unwrap();
    assert_eq!(a.current(GHA), Some(new.clone()));
    assert_eq!(b.current(SM), Some(new));
    let stored = store.get(&rotation.rotation_id).unwrap();
    assert_eq!(stored.step, Step::Revoked);
    assert!(stored
        .consumers
        .iter()
        .all(|c| c.status == ConsumerStatus::Updated));
    assert_eq!(stored.consumers.len(), 2);
}

// FR22: three runs of the same command make each state-changing call once
// in total, and the last run makes no call at all.
#[test]
fn rerun_is_idempotent() {
    let mut run = Run::new("npm_resume_idem_value");
    let (id, _) = pending(&run);
    let mut mutating = run.mutating();
    run.clock(11 * 60);
    let output = run.apply(&id, &["--overlap", "10m"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    mutating.extend(run.mutating());
    let output = run.apply(&id, &["--overlap", "10m"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(run.calls().is_empty(), "{:?}", run.calls());
    assert_eq!(
        mutating,
        [
            "npm.create_replacement",
            "github-actions.update",
            "aws-secrets-manager.update",
            "npm.revoke",
        ]
    );
}

// Resume never acts on a rotation being rolled back: revoking now would
// revoke the old secret the rollback put back.
#[test]
fn resume_skips_a_rotation_being_rolled_back() {
    let value = "npm_resume_rollingback_value";
    let run = Run::new(value);
    let mut pending = record(
        "rot-rb000000",
        value,
        "pending_revoke",
        json!([{ "consumer": "github-actions", "consumer_ref": GHA,
                 "status": "restored", "holds": "secret" },
               updated("aws-secrets-manager", SM)]),
    );
    pending["revoke_not_before"] = json!("2026-10-01T00:10:00Z");
    pending["rollback"] = json!({ "restore_done": true, "revoke_done": false });
    let mut revoked = record(
        "rot-rb000001",
        value,
        "revoked",
        json!([updated("github-actions", GHA)]),
    );
    revoked["rollback"] = json!({ "restore_done": true, "revoke_done": false });
    for (id, rotation) in [("rot-rb000000", pending), ("rot-rb000001", revoked)] {
        run.seed(json!([rotation]));
        let output = run.apply(id, &["--wait"]);
        let err = stderr(&output);
        assert!(
            err.contains("a rollback of it is in progress"),
            "{id}: {err}"
        );
        assert!(run.mutating().is_empty(), "{id}: {:?}", run.mutating());
        assert_eq!(output.status.code(), Some(2), "{id}: {err}");
        let state: Value = serde_json::from_str(&run.read(".rotate/state.json")).unwrap();
        assert_eq!(state["rotations"].as_array().unwrap().len(), 1, "{id}");
    }
}

// T9 (AC1, AC2, AC5): T1, T2 and T5 with canary values at -vvv. Neither the
// old value nor the replacement reaches stdout, stderr (with tracing), the
// audit log, the state file or the call log.
#[test]
fn resume_never_leaks() {
    let old = "npm_resume_t9_canary";
    let mut run = Run::new(old);
    let id = run.planned_id();
    let first = run.apply(&id, &["-vvv", "--overlap", "10m"]);
    assert_eq!(first.status.code(), Some(3), "{}", stderr(&first));
    let first_calls = run.read("calls.jsonl");
    run.clock(11 * 60);
    let second = run.apply(&id, &["-vvv", "--overlap", "10m"]);
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    let second_calls = run.read("calls.jsonl");

    let resumed_old = "npm_resume_t9_seeded_canary";
    let mut seeded = Run::new(resumed_old);
    seeded.set(|s| s["clock_offset_secs"] = json!(0));
    seeded.seed(json!([record(
        "rot-t9000000",
        resumed_old,
        "consumers_updated",
        json!([
            updated("github-actions", GHA),
            updated("aws-secrets-manager", SM)
        ]),
    )]));
    let third = seeded.apply("rot-t9000000", &["-vvv"]);
    assert_eq!(third.status.code(), Some(0), "{}", stderr(&third));

    let captures = [
        ("T1 stdout", stdout(&first)),
        ("T1 stderr and tracing", stderr(&first)),
        ("T1 call log", first_calls),
        ("T2 stdout", stdout(&second)),
        ("T2 stderr and tracing", stderr(&second)),
        ("T2 call log", second_calls),
        ("T1/T2 audit log", run.read(".rotate/audit.jsonl")),
        ("T1/T2 state file", run.read(".rotate/state.json")),
        ("T5 stdout", stdout(&third)),
        ("T5 stderr and tracing", stderr(&third)),
        ("T5 call log", seeded.read("calls.jsonl")),
        ("T5 audit log", seeded.read(".rotate/audit.jsonl")),
        ("T5 state file", seeded.read(".rotate/state.json")),
    ];
    assert!(
        captures[4].1.contains("audit entry appended"),
        "tracing not captured"
    );
    assert!(captures[6].1.contains("skipped"), "resume not audited");
    for (name, text) in &captures {
        for value in [old, resumed_old, REPLACEMENT] {
            assert!(!text.contains(value), "{value} in {name}");
        }
    }
}
