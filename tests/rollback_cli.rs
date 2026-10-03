//! SHA-259: `rotate rollback` end to end against the `test-providers`
//! mocks.
//!
//! Most tests seed the state with a real `rotate apply` in one process,
//! then run `rotate rollback` in a second process whose scenario says the
//! consumers now hold the replacement. T7 and the in-progress test write
//! the state file directly. The binary exports the shared call log (with
//! the reference each call targeted) and what every mock consumer holds,
//! both by fingerprint only. Test values are fake, unique per test, and
//! shaped so no secret scanner matches them.

#![cfg(all(unix, feature = "test-providers"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use rotate::secret::SecretValue;
use serde_json::{json, Value};

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
    /// One secret held by two consumers: GitHub Actions (by name) and
    /// Secrets Manager (by value), both holding `held`.
    fn new(value: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut run = Self {
            dir,
            value: value.to_owned(),
            scenario: Value::Null,
        };
        run.consumers_hold(value, value);
        run
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    /// Resets the scenario: the Actions secret holds `gha`, the Secrets
    /// Manager entry `sm`. Confirmation must come from `--confirm`.
    fn consumers_hold(&mut self, gha: &str, sm: &str) {
        self.scenario = json!({
            "consumers": [
                { "name": "github-actions", "matches": [
                    { "fingerprint": fp(gha), "ref": GHA, "method": "by_name" } ] },
                { "name": "aws-secrets-manager", "matches": [
                    { "fingerprint": fp(sm), "ref": SM } ] }
            ],
            "call_log": self.file("calls.jsonl"),
            "consumer_state": self.file("held.json"),
            "prompt": "panic",
        });
        self.write();
    }

    fn write(&self) {
        std::fs::write(self.file("scenario.json"), self.scenario.to_string()).unwrap();
    }

    fn set(&mut self, edit: impl FnOnce(&mut Value)) {
        edit(&mut self.scenario);
        self.write();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("rotate").unwrap();
        cmd.current_dir(self.path())
            .env_remove("ROTATE_CONFIG")
            .env_remove("ROTATE_STATE_FILE")
            .env_remove("ROTATE_AUDIT_LOG")
            .env_remove("ROTATE_OVERLAP")
            .env("ROTATE_ACTOR", "ci@runner")
            .env("ROTATE_TEST_SCENARIO", self.file("scenario.json"))
            .args(args);
        cmd
    }

    fn run_with(&self, stdin: &str, args: &[&str]) -> Output {
        self.command(args)
            .write_stdin(format!("{stdin}\n"))
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(&self.value, args)
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

    /// Plans and applies with `--confirm`, expecting `code`; returns the id.
    fn apply(&self, code: i32) -> String {
        let id = self.planned_id();
        let output = self.run(&["apply", "--stdin", "--confirm", &id]);
        assert_eq!(output.status.code(), Some(code), "{}", stderr(&output));
        id
    }

    fn rollback(&self, extra: &[&str]) -> Output {
        let mut args = vec!["rollback", "--stdin"];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    /// Every call as `target.method(reference)`.
    fn calls(&self) -> Vec<String> {
        self.call_lines(false)
    }

    /// The mutating calls as `target.method(reference)`.
    fn mutations(&self) -> Vec<String> {
        self.call_lines(true)
    }

    fn call_lines(&self, mutating_only: bool) -> Vec<String> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|c| !mutating_only || c["mutating"] == true)
            .map(|c| {
                format!(
                    "{}.{}({})",
                    c["target"].as_str().unwrap(),
                    c["method"].as_str().unwrap(),
                    c["reference"].as_str().unwrap_or_default()
                )
            })
            .collect()
    }

    fn rotation(&self, id: &str) -> Value {
        let state: Value = serde_json::from_str(&self.read(".rotate/state.json")).unwrap();
        state["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rotation_id"] == id)
            .unwrap()
            .clone()
    }

    fn rollback_audit(&self) -> Vec<Value> {
        self.read(".rotate/audit.jsonl")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|e| e["step"] == "rollback")
            .collect()
    }

    fn held(&self) -> Value {
        serde_json::from_str(&self.read("held.json")).unwrap()
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.file(name)).unwrap()
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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A seeded rotation record of the npm secret `value`.
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

/// A completed apply, then a scenario where both consumers hold the
/// replacement, as they would in the real services.
fn applied(value: &str) -> (Run, String) {
    let mut run = Run::new(value);
    let id = run.apply(0);
    assert_eq!(run.rotation(&id)["step"], "revoked");
    run.consumers_hold(REPLACEMENT, REPLACEMENT);
    (run, id)
}

// T1 (AC1)
#[test]
fn rollback_after_apply_restores_in_order() {
    let (run, id) = applied("npm_rollback_t1_value");
    let restore_ref = run.rotation(&id)["restore_ref"]
        .as_str()
        .expect("apply records the restore handle")
        .to_owned();

    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        run.mutations(),
        [
            format!("npm.restore({restore_ref})"),
            format!("github-actions.restore({GHA})"),
            format!("aws-secrets-manager.restore({SM})"),
            format!("npm.revoke_replacement({REPLACEMENT_REF})"),
        ]
    );
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "rolled_back");
    assert_eq!(
        rotation["rollback"],
        json!({"restore_done": true, "revoke_done": true})
    );
    assert!(rotation["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["status"] == "restored"));

    let audit = run.rollback_audit();
    let actions: Vec<&str> = audit
        .iter()
        .map(|e| e["action"].as_str().unwrap_or("-"))
        .collect();
    assert_eq!(
        actions,
        [
            "restore_old",
            "restore_consumer",
            "restore_consumer",
            "revoke_replacement",
            "-"
        ]
    );
    assert!(audit
        .iter()
        .all(|e| e["outcome"] == "ok" && e["actor"] == "ci@runner"));
    let out = stdout(&output);
    assert!(
        out.starts_with("Rollback plan: 1 rotation to roll back. Nothing has been changed yet."),
        "{out}"
    );
    assert!(
        out.contains(&format!("reactivate with restore {restore_ref}")),
        "{out}"
    );
    assert!(out.contains("Rollback: 1 rolled back, 0 failed."), "{out}");
}

// T2 (AC2)
#[test]
fn rollback_puts_the_leaked_value_back() {
    let value = "npm_rollback_t2_value";
    let (run, id) = applied(value);
    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let held = run.held();
    assert_eq!(held["github-actions"][GHA], fp(value).as_str());
    assert_eq!(held["aws-secrets-manager"][SM], fp(value).as_str());
}

// T3 (AC3)
#[test]
fn restore_unsupported_still_restores_consumers() {
    let value = "npm_rollback_t3_value";
    let (mut run, id) = applied(value);
    run.set(|s| s["providers"] = json!({ "npm": { "restore": "unsupported" } }));
    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let mutations = run.mutations();
    assert_eq!(mutations.len(), 4, "{mutations:?}");
    assert!(mutations[0].starts_with("npm.restore("));
    assert_eq!(mutations[1], format!("github-actions.restore({GHA})"));
    assert_eq!(mutations[2], format!("aws-secrets-manager.restore({SM})"));
    assert_eq!(
        mutations[3],
        format!("npm.revoke_replacement({REPLACEMENT_REF})")
    );
    assert_eq!(run.held()["github-actions"][GHA], fp(value).as_str());
    let err = stderr(&output);
    assert!(
        err.contains(&format!(
            "warning: {id}: the old secret was not reactivated"
        )),
        "{err}"
    );
    assert!(err.contains("it stays revoked"), "{err}");
    assert!(stdout(&output).contains("warning: the old secret was not reactivated"));
    assert_eq!(run.rotation(&id)["step"], "rolled_back");
    assert_eq!(run.rollback_audit()[0]["outcome"], "skipped");
}

// T4 (AC4)
#[test]
fn unrelated_report_exits_2_without_calls() {
    let (run, id) = applied("npm_rollback_t4_value");
    let other = "npm_rollback_t4_unrelated";
    let output = run.run_with(other, &["rollback", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(
        err.contains(&format!("no rotation found for fingerprint {}", fp(other))),
        "{err}"
    );
    assert!(run.calls().is_empty(), "{:?}", run.calls());
    assert_eq!(run.rotation(&id)["step"], "revoked");
    assert!(run.rollback_audit().is_empty());

    // A report file works the same way.
    let report = run.file("other.jsonl");
    std::fs::write(
        &report,
        json!({"DetectorName": "NpmToken", "Raw": other, "SourceMetadata": {}}).to_string(),
    )
    .unwrap();
    let output = run.run(&["rollback", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("no rotation found for fingerprint"));
    assert!(run.calls().is_empty(), "{:?}", run.calls());
}

// T5 (AC5)
#[test]
fn wrong_confirmation_makes_no_mutation() {
    let (mut run, id) = applied("npm_rollback_t5_value");
    run.set(|s| s["prompt"] = json!({ "answers": ["rot-wrong"] }));
    let output = run.rollback(&[]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(
        err.contains(&format!("Type the rotation id {id} to continue")),
        "{err}"
    );
    assert!(err.contains("confirmation did not match"), "{err}");
    assert!(run.mutations().is_empty(), "{:?}", run.mutations());
    assert_eq!(run.rotation(&id)["step"], "revoked");
    assert!(run.rollback_audit().is_empty());

    // The right answer goes ahead.
    run.set(|s| s["prompt"] = json!({ "answers": [id.clone()] }));
    let output = run.rollback(&[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(run.rotation(&id)["step"], "rolled_back");
}

// T6 (AC6)
#[test]
fn partial_failure_restores_only_updated() {
    let value = "npm_rollback_t6_value";
    let mut run = Run::new(value);
    run.set(|s| s["consumers"][1]["fail"] = json!({ "update": "403 denied" }));
    let id = run.apply(1);
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "failed");
    assert_eq!(rotation["failed_step"], "update");
    assert_eq!(rotation["consumers"][0]["status"], "updated");
    assert_eq!(rotation["consumers"][1]["status"], "failed");

    // A holds the replacement; B still holds the old value.
    run.consumers_hold(REPLACEMENT, value);
    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        run.mutations(),
        [
            format!("github-actions.restore({GHA})"),
            format!("npm.revoke_replacement({REPLACEMENT_REF})"),
        ]
    );
    assert!(stdout(&output).contains(&format!("left as is    {SM} (update failed)")));
    assert!(stdout(&output).contains("never revoked; nothing to reactivate"));
    let held = run.held();
    assert_eq!(held["github-actions"][GHA], fp(value).as_str());
    assert_eq!(held["aws-secrets-manager"][SM], fp(value).as_str());
    assert_eq!(run.rotation(&id)["consumers"][1]["status"], "failed");
}

// T7 (AC7)
#[test]
fn created_only_revokes_replacement() {
    let value = "npm_rollback_t7_value";
    let run = Run::new(value);
    run.seed(json!([record(
        "rot-t7created",
        value,
        "created",
        json!([])
    )]));
    let output = run.rollback(&["--confirm", "rot-t7created"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        run.mutations(),
        [format!("npm.revoke_replacement({REPLACEMENT_REF})")]
    );
    let out = stdout(&output);
    assert!(out.contains("consumers     nothing to roll back"), "{out}");
    let held = run.held();
    assert_eq!(held["github-actions"][GHA], fp(value).as_str());
    assert_eq!(held["aws-secrets-manager"][SM], fp(value).as_str());
    assert_eq!(run.rotation("rot-t7created")["step"], "rolled_back");
}

// T8 (AC1, AC2): canary old and new values through apply and rollback,
// including rollback errors that echo the old value; neither reaches
// stdout, stderr (with tracing at -vvv), the audit log, the state file,
// the call log or the consumer state.
#[test]
fn rollback_never_leaks() {
    for (n, manual) in [false, true].into_iter().enumerate() {
        let old = format!("npm_rollback_t8_{n}_canary");
        let new = format!("npm_rollback_t8_{n}_new_canary");
        let mut run = Run::new(&old);
        if manual {
            run.set(|s| s["providers"] = json!({ "npm": { "mode": "manual" } }));
        }
        let id = run.planned_id();
        let applied = run
            .command(&[
                "-vvv",
                "apply",
                "--stdin",
                "--confirm",
                &id,
                "--replacement-from-env",
                "ROTATE_T8_NEW",
            ])
            .env("ROTATE_T8_NEW", &new)
            .write_stdin(format!("{old}\n"))
            .output()
            .unwrap();
        assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
        let replacement = if manual {
            new.clone()
        } else {
            REPLACEMENT.to_owned()
        };

        run.consumers_hold(&replacement, &replacement);
        if manual {
            run.set(|s| s["providers"] = json!({ "npm": { "mode": "manual" } }));
        }
        let echo = format!("upstream echoed {old}");
        run.set(|s| s["consumers"][1]["fail"] = json!({ "restore": echo }));
        let failed = run.rollback(&["-vvv", "--confirm", &id]);
        assert_eq!(failed.status.code(), Some(1), "{}", stderr(&failed));
        assert!(!run
            .mutations()
            .iter()
            .any(|c| c.contains("revoke_replacement")));
        run.set(|s| s["consumers"][1]["fail"] = json!({}));
        let done = run.rollback(&["-vvv", "--confirm", &id]);
        assert_eq!(done.status.code(), Some(0), "{}", stderr(&done));
        if manual {
            assert!(stderr(&done).contains("revoke the pasted replacement by hand"));
        }

        let captures = [
            ("apply stdout", stdout(&applied)),
            ("apply stderr", stderr(&applied)),
            ("failed rollback stdout", stdout(&failed)),
            ("failed rollback stderr and tracing", stderr(&failed)),
            ("rollback stdout", stdout(&done)),
            ("rollback stderr and tracing", stderr(&done)),
            ("audit log", run.read(".rotate/audit.jsonl")),
            ("state file", run.read(".rotate/state.json")),
            ("call log", run.read("calls.jsonl")),
            ("consumer state", run.read("held.json")),
        ];
        assert!(
            captures[3].1.contains("audit entry appended"),
            "tracing not captured"
        );
        assert!(
            captures[6].1.contains("upstream echoed"),
            "rollback error not recorded"
        );
        for (name, text) in &captures {
            assert!(!text.contains(&old), "manual={manual}: old value in {name}");
            assert!(
                !text.contains(&replacement),
                "manual={manual}: new value in {name}"
            );
        }
        assert_eq!(run.rotation(&id)["step"], "rolled_back");
    }
}

// Re-running a finished rollback makes no call.
#[test]
fn second_rollback_is_a_no_op() {
    let (run, id) = applied("npm_rollback_again_value");
    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let entries = run.rollback_audit().len();

    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains(&format!("{id}: already rolled back; nothing to do")));
    assert!(stderr(&output).contains("Nothing to roll back."));
    assert!(run.calls().is_empty(), "{:?}", run.calls());
    assert_eq!(run.rollback_audit().len(), entries);
}

// A failed consumer restore stops before the replacement is revoked; the
// re-run continues without repeating what succeeded.
#[test]
fn failed_consumer_restore_stops_and_rerun_continues() {
    let value = "npm_rollback_rerun_value";
    let (mut run, id) = applied(value);
    run.set(|s| s["consumers"][1]["fail"] = json!({ "restore": "503 unavailable" }));
    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let mutations = run.mutations();
    assert!(
        !mutations.iter().any(|c| c.contains("revoke_replacement")),
        "{mutations:?}"
    );
    let out = stdout(&output);
    assert!(out.contains("restoring a consumer failed"), "{out}");
    assert!(out.contains("re-run rotate rollback to continue"), "{out}");
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "revoked");
    assert_eq!(rotation["consumers"][0]["status"], "restored");
    assert_eq!(rotation["consumers"][1]["status"], "updated");

    // B still holds the replacement in the real service; A holds the old value.
    run.consumers_hold(value, REPLACEMENT);
    let output = run.rollback(&["--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        run.mutations(),
        [
            format!("aws-secrets-manager.restore({SM})"),
            format!("npm.revoke_replacement({REPLACEMENT_REF})"),
        ]
    );
    assert!(stdout(&output).contains("continuing an earlier rollback"));
    assert_eq!(run.rotation(&id)["step"], "rolled_back");
}

// Apply leaves a rotation alone while its rollback is unfinished: going on
// would revoke the old secret the rollback put back.
#[test]
fn apply_skips_a_rotation_being_rolled_back() {
    let value = "npm_rollback_inprogress_value";
    let run = Run::new(value);
    let mut rotation = record(
        "rot-rollingback",
        value,
        "verified",
        json!([{ "consumer": "github-actions", "consumer_ref": GHA,
                 "status": "restored", "holds": "secret" }]),
    );
    rotation["rollback"] = json!({ "restore_done": true, "revoke_done": false });
    run.seed(json!([rotation]));
    let output = run.run(&["apply", "--stdin", "--confirm", "rot-rollingback"]);
    let err = stderr(&output);
    assert!(err.contains("a rollback of it is in progress"), "{err}");
    assert!(run.mutations().is_empty(), "{:?}", run.mutations());
    assert_ne!(output.status.code(), Some(0));
}

// --rotation narrows the match; an id that does not match is AC4's error.
#[test]
fn rotation_flag_narrows_the_match() {
    let value = "npm_rollback_flag_value";
    let run = Run::new(value);
    run.seed(json!([
        record("rot-flaga", value, "created", json!([])),
        record("rot-flagb", value, "created", json!([])),
    ]));
    let output = run.rollback(&["--rotation", "rot-flagb", "--confirm", "rot-flagb"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(run.rotation("rot-flagb")["step"], "rolled_back");
    assert_eq!(run.rotation("rot-flaga")["step"], "created");

    let output = run.rollback(&["--rotation", "rot-missing"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("no rotation found for fingerprint"));
    assert!(run.calls().is_empty());
}
