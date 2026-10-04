//! SHA-289: the "revoke by hand" outcome, end to end against the
//! `test-providers` mocks.
//!
//! A provider that cannot revoke the old secret leaves the rotation at
//! `revoke_manual` with its instructions and exit 4, instead of `failed`.
//! A later apply confirms the operator deleted it with a read-only check
//! and records `revoked`. Every run is a new process; the scenario file
//! drives the mocks, and the binary exports the call log by fingerprint
//! only. Test values are fake, unique per test, and shaped so no secret
//! scanner matches them.

#![cfg(all(unix, feature = "test-providers"))]

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use rotate::secret::SecretValue;
use serde_json::{json, Value};

/// The OpenAI provider's revoke row without an Admin API key.
const NEEDS_ADMIN: &str = rotate::provider::openai::REVOKE_NEEDS_ADMIN;
const GHA: &str = "gha:org/repo:NPM_TOKEN";
const SM: &str = "sm:prod/npm-publish";
/// What the npm mock mints for the first replacement in a process.
const REPLACEMENT: &str = "npm_npm-replacement-1";

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

struct Run {
    dir: tempfile::TempDir,
    value: String,
    scenario: Value,
}

impl Run {
    /// One npm secret held by two consumers, whose provider cannot revoke
    /// it: `manual_revoke` returns [`NEEDS_ADMIN`].
    fn new(value: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut run = Self {
            dir,
            value: value.to_owned(),
            scenario: Value::Null,
        };
        run.scenario = json!({
            "providers": { "npm": { "manual_revoke": NEEDS_ADMIN } },
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

    fn run(&self, args: &[&str]) -> Output {
        Command::cargo_bin("rotate")
            .unwrap()
            .current_dir(self.path())
            .env_remove("ROTATE_CONFIG")
            .env_remove("ROTATE_STATE_FILE")
            .env_remove("ROTATE_AUDIT_LOG")
            .env_remove("ROTATE_OVERLAP")
            .env("ROTATE_ACTOR", "ci@runner")
            .arg("-vvv")
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

    fn apply(&self, id: &str) -> Output {
        self.run(&["apply", "--stdin", "--confirm", id, "--overlap", "0s"])
    }

    /// The calls of the last run: each process writes its own log.
    fn call_lines(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn calls(&self) -> Vec<String> {
        self.call_lines().iter().map(name).collect()
    }

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
        self.read(".rotate/audit.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.file(name)).unwrap_or_default()
    }

    /// T11: neither the leaked value nor the replacement is in `outputs`,
    /// the state file or the audit log.
    fn assert_no_values(&self, outputs: &[&Output]) {
        let state = self.read(".rotate/state.json");
        let audit = self.read(".rotate/audit.jsonl");
        assert!(!state.is_empty() && !audit.is_empty());
        for value in [self.value.as_str(), REPLACEMENT] {
            for output in outputs {
                assert!(!stdout(output).contains(value), "a value in stdout");
                assert!(!stderr(output).contains(value), "a value in stderr");
            }
            assert!(!state.contains(value), "a value in the state file");
            assert!(!audit.contains(value), "a value in the audit log");
        }
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

/// Plans and applies: the rotation ends at `revoke_manual` with exit 4.
fn by_hand(run: &Run) -> (String, Output) {
    let id = run.planned_id();
    let output = run.apply(&id);
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    (id, output)
}

// T1 (AC1), T3 (AC3), T11 (AC1)
#[test]
fn manual_revoke_stops_at_revoke_manual_with_exit_4() {
    let run = Run::new("npm_manual_t1_value");
    let (id, output) = by_hand(&run);

    assert_eq!(
        run.mutating(),
        [
            "npm.create_replacement",
            "github-actions.update",
            "aws-secrets-manager.update"
        ]
    );
    assert!(!run.calls().iter().any(|c| c == "npm.revoke"));
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "revoke_manual");
    assert_eq!(rotation["revoke_instructions"], NEEDS_ADMIN);
    assert!(rotation.get("failed_step").is_none(), "{rotation}");

    let last = run.audit().pop().unwrap();
    assert_eq!(last["step"], "revoke");
    assert_eq!(last["outcome"], "skipped");
    assert_eq!(last["error"], NEEDS_ADMIN);

    let out = stdout(&output);
    assert!(out.contains("1 revoke by hand"), "{out}");
    assert!(
        out.contains(&format!(
            "{id}: revoke by hand: without an Admin API key rotate cannot delete OpenAI keys; delete it at https://platform.openai.com/api-keys; the replacement is live and verified"
        )),
        "{out}"
    );
    run.assert_no_values(&[&output]);
}

// The provider refusing revoke as unsupported is a revoke by hand too.
#[test]
fn unsupported_revoke_is_revoke_manual() {
    let mut run = Run::new("npm_manual_unsupported_value");
    let text = "the API does not accept this token; delete it at https://example.test/tokens";
    run.set(|s| s["providers"]["npm"] = json!({ "unsupported": { "revoke": text } }));
    let (id, _) = by_hand(&run);
    assert!(run.calls().iter().any(|c| c == "npm.revoke"));
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "revoke_manual");
    assert_eq!(rotation["revoke_instructions"], text);
}

// T7 (AC7): any other revoke error is still a failure at revoke.
#[test]
fn permanent_revoke_error_still_fails() {
    let mut run = Run::new("npm_manual_permanent_value");
    run.set(|s| s["providers"]["npm"] = json!({ "fail": { "revoke": "denied" } }));
    let id = run.planned_id();
    let output = run.apply(&id);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "failed");
    assert_eq!(rotation["failed_step"], "revoke");
}

// T5 (AC5), T11 (AC5): the operator deleted the old secret; the plan's
// read-only check sees it invalid, and apply records it revoked with no
// further call.
#[test]
fn rerun_after_delete_by_hand_records_revoked() {
    let mut run = Run::new("npm_manual_t5_value");
    let (id, first) = by_hand(&run);
    let entries = run.audit().len();

    run.set(|s| s["providers"]["npm"]["validity"] = json!("invalid"));
    let plan = run.run(&["--json", "plan", "--stdin"]);
    assert_eq!(plan.status.code(), Some(0), "{}", stderr(&plan));
    let planned: Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(planned["skipped"][0]["reason"], "revoked by hand");
    assert_eq!(
        run.rotation(&id)["step"],
        "revoke_manual",
        "plan changed it"
    );

    let output = run.run(&["apply", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(run.mutating().is_empty(), "{:?}", run.mutating());
    assert!(run.calls().contains(&"npm.check_valid".to_owned()));
    assert!(
        run.calls()
            .iter()
            .all(|c| !c.ends_with(".verify") && !c.ends_with(".revoke")),
        "{:?}",
        run.calls()
    );
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "revoked");
    assert!(rotation.get("revoke_instructions").is_none(), "{rotation}");
    let new: Vec<Value> = run.audit()[entries..].to_vec();
    assert_eq!(new.len(), 1, "{new:?}");
    assert_eq!(new[0]["step"], "revoke");
    assert_eq!(new[0]["outcome"], "ok");
    assert_eq!(new[0]["error"], "revoked by hand, confirmed by check_valid");
    assert!(
        stdout(&output).contains("Apply: 1 revoked"),
        "{}",
        stdout(&output)
    );

    // Finished: a third run skips it as already rotated.
    let again = run.run(&["apply", "--stdin", "--all"]);
    assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
    run.assert_no_values(&[&first, &plan, &output, &again]);
}

// T6 (AC6): still valid; only the read-only check, exit 4 again.
#[test]
fn rerun_while_still_valid_stays_revoke_manual() {
    let run = Run::new("npm_manual_t6_value");
    let (id, _) = by_hand(&run);
    let entries = run.audit().len();

    let output = run.apply(&id);
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    let rerun: Vec<String> = run.calls();
    assert!(
        rerun.iter().all(|c| c.ends_with(".identify")
            || c.ends_with(".check_valid")
            || c.ends_with(".describe_scope")
            || c.ends_with(".find")),
        "{rerun:?}"
    );
    // The plan's check, then the executor's.
    assert_eq!(
        rerun.iter().filter(|c| *c == "npm.check_valid").count(),
        2,
        "{rerun:?}"
    );
    assert_eq!(run.rotation(&id)["step"], "revoke_manual");
    let last = run.audit().pop().unwrap();
    assert_eq!(last["step"], "revoke");
    assert_eq!(last["outcome"], "skipped");
    assert!(run.audit().len() > entries);
    assert!(stdout(&output).contains(&format!("{id}: revoke by hand: ")));
}

// T10 (AC10): status lists it as pending with the instructions; rollback
// treats the old secret as never revoked.
#[test]
fn status_and_rollback_of_a_revoke_manual_rotation() {
    let run = Run::new("npm_manual_t10_value");
    let (id, _) = by_hand(&run);

    let status = run.run(&["--json", "status"]);
    assert_eq!(status.status.code(), Some(3), "{}", stderr(&status));
    let rows: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(rows[0]["rotation_id"], id.as_str());
    assert_eq!(rows[0]["step"], "revoke_manual");
    assert_eq!(rows[0]["pending"], true);
    let hint = rows[0]["hint"].as_str().unwrap();
    assert!(
        hint.contains("delete it at https://platform.openai.com/api-keys"),
        "{hint}"
    );
    let table = stdout(&run.run(&["status"]));
    assert!(table.contains("revoke_manual"), "{table}");

    let output = run.run(&["rollback", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let rerun: Vec<String> = run.calls();
    assert!(!rerun.iter().any(|c| c == "npm.restore"), "{rerun:?}");
    assert!(
        rerun.iter().any(|c| c == "npm.revoke_replacement"),
        "{rerun:?}"
    );
    let out = stdout(&output);
    assert!(out.contains("never revoked"), "{out}");
    assert_eq!(run.rotation(&id)["step"], "rolled_back");
}
