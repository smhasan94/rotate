//! SHA-254: `rotate apply` end to end against the `test-providers` mocks.
//!
//! Each test reads one secret with `--stdin`, gets its rotation id from
//! `plan --json`, then runs `apply` with a scenario that scripts the
//! confirmation prompt (`ROTATE_TEST_SCENARIO`). The binary exports the
//! shared call log and what every mock consumer holds, both by fingerprint
//! only. Test values are fake and shaped so no secret scanner matches them.

#![cfg(all(unix, feature = "test-providers"))]

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use rotate::secret::SecretValue;
use serde_json::{json, Value};

/// What the npm mock mints for the first replacement in a process.
const REPLACEMENT: &str = "npm_npm-replacement-1";

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

struct Run {
    dir: tempfile::TempDir,
    value: String,
}

impl Run {
    /// A temp dir for one secret, with the default two-consumer scenario.
    fn new(value: &str) -> Self {
        let run = Self {
            dir: tempfile::tempdir().unwrap(),
            value: value.to_owned(),
        };
        run.scenario(json!({}));
        run
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    /// Two consumers holding the secret, plus whatever `extra` sets.
    fn scenario(&self, extra: Value) {
        let mut scenario = json!({
            "consumers": [
                { "name": "github-actions", "matches": [
                    { "fingerprint": fp(&self.value), "ref": "gha:org/repo:NPM_TOKEN", "method": "by_name" } ] },
                { "name": "aws-secrets-manager", "matches": [
                    { "fingerprint": fp(&self.value), "ref": "sm:prod/npm-publish" } ] }
            ],
            "call_log": self.file("calls.jsonl"),
            "consumer_state": self.file("held.json"),
        });
        for (key, value) in extra.as_object().unwrap() {
            scenario[key] = value.clone();
        }
        std::fs::write(
            self.file("scenario.json"),
            serde_json::to_string(&scenario).unwrap(),
        )
        .unwrap();
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

    /// The rotation id `plan` assigns; the state file keeps it for apply.
    fn planned_id(&self) -> String {
        let output = self.run(&["--json", "plan", "--stdin"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        plan["rotations"][0]["rotation_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `target.method` of every call, in order.
    fn calls(&self) -> Vec<String> {
        self.call_lines()
            .iter()
            .map(|c| {
                format!(
                    "{}.{}",
                    c["target"].as_str().unwrap(),
                    c["method"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn call_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn mutating(&self) -> Vec<String> {
        self.call_lines()
            .iter()
            .filter(|c| c["mutating"] == true)
            .map(|c| {
                format!(
                    "{}.{}",
                    c["target"].as_str().unwrap(),
                    c["method"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn state(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.file(".rotate/state.json")).unwrap())
            .unwrap()
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file(".rotate/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Runs a confirmed apply to completion and returns the run and its id.
fn completed(value: &str) -> (Run, String, Output) {
    let run = Run::new(value);
    let id = run.planned_id();
    run.scenario(json!({ "prompt": { "answers": [id] } }));
    let output = run.run(&["apply", "--stdin"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    (run, id, output)
}

// T1 (AC1)
#[test]
fn typed_mismatch_exits_2_without_mutations() {
    let run = Run::new("npm_applycli_t1_value");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": { "answers": ["no"] } }));
    let output = run.run(&["apply", "--stdin"]);
    assert_eq!(output.status.code(), Some(2));
    let err = stderr(&output);
    assert!(
        err.contains(&format!("Type the rotation id {id} to continue:")),
        "{err}"
    );
    assert!(err.contains("confirmation did not match"), "{err}");
    assert!(run.mutating().is_empty(), "{:?}", run.mutating());
    assert!(run.audit().is_empty());
}

// T2 (AC2)
#[test]
fn typed_id_runs_steps_in_order() {
    let (run, _, output) = completed("npm_applycli_t2_value");
    let steps: Vec<String> = run
        .calls()
        .into_iter()
        .filter(|c| {
            ["create_replacement", "update", "verify", "revoke"]
                .iter()
                .any(|m| c.ends_with(&format!(".{m}")))
        })
        .collect();
    assert_eq!(
        steps,
        [
            "npm.create_replacement",
            "github-actions.update",
            "aws-secrets-manager.update",
            "npm.verify",
            "npm.revoke",
        ]
    );
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("Apply: 1 revoked"), "{out}");
}

// Revoke is the last mutating call and nothing mutates before create.
#[test]
fn revoke_is_last_mutating_call() {
    let (run, _, _) = completed("npm_applycli_last_value");
    let mutating = run.mutating();
    assert_eq!(
        mutating.first().map(String::as_str),
        Some("npm.create_replacement")
    );
    assert_eq!(mutating.last().map(String::as_str), Some("npm.revoke"));
    assert_eq!(
        mutating.iter().filter(|c| c.ends_with(".revoke")).count(),
        1
    );
}

// T3 (AC3)
#[test]
fn confirm_flag_skips_prompt() {
    let run = Run::new("npm_applycli_t3_value");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": "panic" }));
    let output = run.run(&["apply", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!stderr(&output).contains("Type the rotation id"));
    assert!(run.calls().contains(&"npm.revoke".to_owned()));
}

#[test]
fn no_terminal_without_confirm_exits_2() {
    let run = Run::new("npm_applycli_notty_value");
    run.scenario(json!({ "prompt": "no_tty" }));
    let output = run.run(&["apply", "--stdin"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("pass --confirm <rotation-id>"));
    assert!(run.mutating().is_empty());
}

// T4 (AC4)
#[test]
fn wrong_confirm_id_exits_2_without_mutations() {
    let run = Run::new("npm_applycli_t4_value");
    run.planned_id();
    run.scenario(json!({ "prompt": "panic" }));
    let output = run.run(&["apply", "--stdin", "--confirm", "rot-00000000"]);
    assert_eq!(output.status.code(), Some(2));
    let err = stderr(&output);
    assert!(err.contains("not a rotation in this plan"), "{err}");
    assert!(!err.contains("rot-00000000"), "typed id echoed: {err}");
    assert!(run.mutating().is_empty(), "{:?}", run.mutating());
}

// T5 (AC5)
#[test]
fn audit_has_every_step_with_fingerprints() {
    let value = "npm_applycli_t5_value";
    let (run, id, _) = completed(value);
    let audit = run.audit();
    let steps: Vec<&str> = audit.iter().map(|e| e["step"].as_str().unwrap()).collect();
    assert_eq!(
        steps,
        ["plan", "create", "update", "update", "verify", "revoke"]
    );
    for entry in &audit {
        assert_eq!(entry["outcome"], "ok", "{entry}");
        assert_eq!(entry["rotation_id"], id.as_str());
        assert_eq!(entry["provider"], "npm");
        assert_eq!(entry["fingerprint"], fp(value).as_str());
        assert_eq!(entry["actor"], "ci@runner");
        let replacement = &entry["replacement_fingerprint"];
        if entry["step"] == "plan" {
            assert!(replacement.is_null());
        } else {
            assert_eq!(replacement, fp(REPLACEMENT).as_str(), "{entry}");
        }
    }
    assert_eq!(audit[2]["consumer"], "gha:org/repo:NPM_TOKEN");
    assert_eq!(audit[3]["consumer"], "sm:prod/npm-publish");
}

// T6 (AC6)
#[test]
fn state_ends_revoked_with_consumers_updated() {
    let (run, id, _) = completed("npm_applycli_t6_value");
    let state = run.state();
    let rotation = state["rotations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["rotation_id"] == id.as_str())
        .unwrap();
    assert_eq!(rotation["step"], "revoked");
    assert_eq!(rotation["replacement_ref"], "npm-ref-1");
    assert_eq!(
        rotation["replacement_fingerprint"],
        fp(REPLACEMENT).as_str()
    );
    let consumers = rotation["consumers"].as_array().unwrap();
    assert_eq!(consumers.len(), 2);
    assert!(consumers.iter().all(|c| c["status"] == "updated"));
}

// T7 (AC7)
#[test]
fn consumer_holds_replacement_fingerprint() {
    let (run, _, _) = completed("npm_applycli_t7_value");
    let held: Value =
        serde_json::from_str(&std::fs::read_to_string(run.file("held.json")).unwrap()).unwrap();
    assert_eq!(
        held["github-actions"]["gha:org/repo:NPM_TOKEN"],
        fp(REPLACEMENT).as_str()
    );
    assert_eq!(
        held["aws-secrets-manager"]["sm:prod/npm-publish"],
        fp(REPLACEMENT).as_str()
    );
}

// T8 (AC2, AC5, AC6)
#[test]
fn apply_never_leaks_old_or_new_value() {
    let canary = "npm_applycli_t8_canary_value";
    let run = Run::new(canary);
    let id = run.planned_id();
    run.scenario(json!({ "prompt": { "answers": [id] } }));
    let output = run.run(&["-vvv", "apply", "--stdin"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let files = [
        (
            "stdout",
            String::from_utf8_lossy(&output.stdout).into_owned(),
        ),
        ("stderr and tracing", stderr(&output)),
        (
            "audit log",
            std::fs::read_to_string(run.file(".rotate/audit.jsonl")).unwrap(),
        ),
        (
            "state file",
            std::fs::read_to_string(run.file(".rotate/state.json")).unwrap(),
        ),
        (
            "call log",
            std::fs::read_to_string(run.file("calls.jsonl")).unwrap(),
        ),
        (
            "consumer state",
            std::fs::read_to_string(run.file("held.json")).unwrap(),
        ),
    ];
    assert!(
        files[1].1.contains("audit entry appended"),
        "tracing not captured"
    );
    for (name, text) in &files {
        assert!(!text.is_empty(), "{name} is empty");
        assert!(!text.contains(canary), "old value in {name}");
        assert!(!text.contains(REPLACEMENT), "new value in {name}");
    }
}

// Revoke is skipped on any earlier failure (CLAUDE.md safety rule).
#[test]
fn injected_failure_never_revokes() {
    for (n, (kind, method)) in [
        ("provider", "create_replacement"),
        ("consumer", "update"),
        ("provider", "verify"),
    ]
    .into_iter()
    .enumerate()
    {
        let run = Run::new(&format!("npm_applycli_fail_{n}_value"));
        let id = run.planned_id();
        let mut extra = json!({ "prompt": "panic" });
        if kind == "provider" {
            extra["providers"] = json!({ "npm": { "fail": { method: "403 denied" } } });
            run.scenario(extra);
        } else {
            run.scenario(extra);
            let mut scenario: Value =
                serde_json::from_str(&std::fs::read_to_string(run.file("scenario.json")).unwrap())
                    .unwrap();
            scenario["consumers"][1]["fail"] = json!({ method: "403 denied" });
            std::fs::write(run.file("scenario.json"), scenario.to_string()).unwrap();
        }
        let output = run.run(&["apply", "--stdin", "--confirm", &id]);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{method}: {}",
            stderr(&output)
        );
        assert!(
            !run.calls().iter().any(|c| c.ends_with(".revoke")),
            "{method}: revoke called: {:?}",
            run.calls()
        );
        let out = String::from_utf8_lossy(&output.stdout);
        assert!(out.contains("stopped before revoke"), "{method}: {out}");
        assert_eq!(run.state()["rotations"][0]["step"], "failed", "{method}");
        let audit = run.audit();
        let last = audit.last().unwrap();
        assert_eq!(last["outcome"], "failed", "{method}");
        assert!(last["error"].as_str().unwrap().contains("403 denied"));
    }
}

#[test]
fn not_updatable_consumer_holds_before_revoke() {
    let run = Run::new("npm_applycli_hold_value");
    let mut scenario: Value =
        serde_json::from_str(&std::fs::read_to_string(run.file("scenario.json")).unwrap()).unwrap();
    scenario["consumers"][0]["matches"][0]["not_updatable"] = json!("org secret needs admin");
    scenario["prompt"] = json!("panic");
    std::fs::write(run.file("scenario.json"), scenario.to_string()).unwrap();
    let id = run.planned_id();
    let output = run.run(&["apply", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!run.calls().iter().any(|c| c.ends_with(".revoke")));
    assert_eq!(run.state()["rotations"][0]["step"], "verified");
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        out.contains("1 consumer not updated; revoke skipped"),
        "{out}"
    );
}

// Manual mode runs (SHA-257; tests/apply_manual.rs). Without a terminal
// or a supplied value it stops at create having changed nothing.
#[test]
fn manual_mode_without_input_changes_nothing() {
    let run = Run::new("npm_applycli_manual_value");
    let id = run.planned_id();
    run.scenario(json!({ "providers": { "npm": { "mode": "manual" } }, "prompt": "no_tty" }));
    let output = run.run(&["apply", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("failed at create"));
    assert!(run.mutating().is_empty());
}

#[test]
fn overlap_records_pending_revoke_exit_3() {
    let run = Run::new("npm_applycli_overlap_value");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": "panic" }));
    let output = run.run(&["apply", "--stdin", "--overlap", "10m", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(!run.calls().iter().any(|c| c.ends_with(".revoke")));
    let state = run.state();
    assert_eq!(state["rotations"][0]["step"], "pending_revoke");
    assert!(state["rotations"][0]["revoke_not_before"].is_string());
    assert!(String::from_utf8_lossy(&output.stdout).contains("revoke pending until"));
}

#[test]
fn apply_json_is_refused() {
    let run = Run::new("npm_applycli_json_value");
    let output = run.run(&["--json", "apply", "--stdin"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(run.calls().is_empty());
}
