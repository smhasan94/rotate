//! SHA-256: apply safety rules end to end against the `test-providers`
//! mocks. Any failure stops before revoke; a consumer that was not updated
//! blocks the revoke unless `--force`; `--force` is recorded and never
//! bypasses a failed create or verify.
//!
//! Every test asserts from the exported call log that no `revoke` follows a
//! failed step. Test values are fake, unique per test, and shaped so no
//! secret scanner matches them.

#![cfg(all(unix, feature = "test-providers"))]

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use rotate::secret::SecretValue;
use serde_json::{json, Value};

/// What the npm mock mints for the first replacement in a process.
const REPLACEMENT: &str = "npm_npm-replacement-1";
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
    /// Secrets Manager (by value).
    fn new(value: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let scenario = json!({
            "consumers": [
                { "name": "github-actions", "matches": [
                    { "fingerprint": fp(value), "ref": GHA, "method": "by_name" } ] },
                { "name": "aws-secrets-manager", "matches": [
                    { "fingerprint": fp(value), "ref": SM } ] }
            ],
            "call_log": dir.path().join("calls.jsonl"),
            "consumer_state": dir.path().join("held.json"),
            "prompt": "panic",
        });
        let run = Self {
            dir,
            value: value.to_owned(),
            scenario,
        };
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

    /// Edits the scenario in place.
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

    fn run(&self, args: &[&str]) -> Output {
        self.command(args)
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

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let c: Value = serde_json::from_str(line).unwrap();
                format!(
                    "{}.{}",
                    c["target"].as_str().unwrap(),
                    c["method"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn called(&self, method: &str) -> bool {
        self.calls()
            .iter()
            .any(|c| c.ends_with(&format!(".{method}")))
    }

    fn rotation(&self, id: &str) -> Value {
        let state: Value = serde_json::from_str(
            &std::fs::read_to_string(self.file(".rotate/state.json")).unwrap(),
        )
        .unwrap();
        state["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rotation_id"] == id)
            .unwrap()
            .clone()
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file(".rotate/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn held(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.file("held.json")).unwrap()).unwrap()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn fail_consumer(run: &mut Run, index: usize, method: &str, error: &str) {
    run.set(|s| s["consumers"][index]["fail"] = json!({ method: error }));
}

fn fail_provider(run: &mut Run, method: &str, error: &str) {
    run.set(|s| s["providers"] = json!({ "npm": { "fail": { method: error } } }));
}

fn not_updatable(run: &mut Run) {
    run.set(|s| s["consumers"][0]["matches"][0]["not_updatable"] = json!("org secret needs admin"));
}

// T1 (AC1)
#[test]
fn update_failure_stops_before_revoke() {
    let mut run = Run::new("npm_safety_t1_value");
    let id = run.planned_id();
    fail_consumer(&mut run, 1, "update", "403 denied");
    let output = run.apply(&id, &[]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(!run.called("revoke"), "{:?}", run.calls());
    assert!(!run.called("verify"), "{:?}", run.calls());

    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "failed");
    assert_eq!(rotation["failed_step"], "update");
    assert_eq!(rotation["force"], false);

    let audit = run.audit();
    let last = audit.last().unwrap();
    assert_eq!(last["step"], "update");
    assert_eq!(last["outcome"], "failed");
    assert_eq!(last["consumer"], SM);

    let out = stdout(&output);
    assert!(
        out.contains(&format!(
            "{id}: update failed: {SM}: 403 denied; stopped before revoke; old secret still valid; \
             consumers: {GHA} updated, {SM} failed"
        )),
        "{out}"
    );
    // The old secret is still valid, and Secrets Manager still holds it.
    assert_eq!(
        run.held()["aws-secrets-manager"][SM],
        fp(&run.value).as_str()
    );
}

// T2 (AC2)
#[test]
fn verify_failure_never_revokes_even_with_force() {
    for (n, force) in [(0, false), (1, true)] {
        let mut run = Run::new(&format!("npm_safety_t2_{n}_value"));
        not_updatable(&mut run);
        let id = run.planned_id();
        fail_provider(&mut run, "verify", "verify rejected");
        let extra: &[&str] = if force { &["--force"] } else { &[] };
        let output = run.apply(&id, extra);
        assert_eq!(output.status.code(), Some(1), "force={force}");
        assert!(run.called("verify"));
        assert!(!run.called("revoke"), "force={force}: {:?}", run.calls());
        let rotation = run.rotation(&id);
        assert_eq!(rotation["failed_step"], "verify");
        assert_eq!(rotation["force"], false, "force={force}");
        assert!(run.audit().iter().all(|e| e["step"] != "force"));
        assert!(stdout(&output).contains("verify failed: "));
    }
}

// T3 (AC3)
#[test]
fn not_updatable_holds_and_mentions_force() {
    let mut run = Run::new("npm_safety_t3_value");
    not_updatable(&mut run);
    let id = run.planned_id();
    let output = run.apply(&id, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!run.called("revoke"));
    assert_eq!(run.rotation(&id)["step"], "verified");
    let out = stdout(&output);
    assert!(
        out.contains(&format!(
            "1 consumer not updated ({GHA}); re-run with --force to revoke anyway"
        )),
        "{out}"
    );
    assert!(out.contains("held before revoke"));
}

// T4 (AC4)
#[test]
fn force_revokes_and_records_force() {
    let mut run = Run::new("npm_safety_t4_value");
    not_updatable(&mut run);
    let id = run.planned_id();
    let output = run.apply(&id, &["--force"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(run.calls().last().map(String::as_str), Some("npm.revoke"));
    let rotation = run.rotation(&id);
    assert_eq!(rotation["force"], true);
    assert_eq!(rotation["step"], "revoked");
    let audit = run.audit();
    let force: Vec<&Value> = audit.iter().filter(|e| e["step"] == "force").collect();
    assert_eq!(force.len(), 1, "{audit:?}");
    assert_eq!(force[0]["consumer"], GHA);
    assert_eq!(force[0]["actor"], "ci@runner");
    assert_eq!(force[0]["outcome"], "ok");
    let force_at = audit.iter().position(|e| e["step"] == "force").unwrap();
    assert_eq!(audit.last().unwrap()["step"], "revoke");
    assert!(force_at < audit.len() - 1);
    let out = stdout(&output);
    assert!(out.contains("revoked (forced)"), "{out}");
    assert!(out.contains(&format!("--force used; not updated: {GHA}")));
}

// T3 then T4 (AC3, AC4): the message's advice works.
#[test]
fn held_rotation_finishes_with_force_on_rerun() {
    let mut run = Run::new("npm_safety_rerun_value");
    not_updatable(&mut run);
    let id = run.planned_id();
    assert_eq!(run.apply(&id, &[]).status.code(), Some(1));
    assert_eq!(run.rotation(&id)["step"], "verified");

    let output = run.apply(&id, &["--force"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    // The second process only revokes: nothing is created or updated again.
    let mutating: Vec<String> = run
        .calls()
        .into_iter()
        .filter(|c| {
            ["create_replacement", "update", "verify", "revoke"]
                .iter()
                .any(|m| c.ends_with(&format!(".{m}")))
        })
        .collect();
    assert_eq!(mutating, ["npm.revoke"]);
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "revoked");
    assert_eq!(rotation["force"], true);
}

// T5 (AC5)
#[test]
fn second_rotation_completes_after_first_fails() {
    let first = "npm_safety_t5_first_value";
    let second = "npm_safety_t5_second_value";
    let mut run = Run::new(first);
    run.set(|s| {
        s["consumers"] = json!([
            { "name": "github-actions", "matches": [
                { "fingerprint": fp(first), "ref": GHA, "method": "by_name" } ],
              "fail": { "update": "403 denied" } },
            { "name": "aws-secrets-manager", "matches": [
                { "fingerprint": fp(second), "ref": SM } ] }
        ]);
    });
    let findings: Vec<Value> = [first, second]
        .iter()
        .enumerate()
        .map(|(i, value)| {
            json!({
                "RuleID": "npm-access-token", "Description": "fixture",
                "StartLine": i + 1, "EndLine": i + 1, "StartColumn": 1, "EndColumn": 10,
                "Match": value, "Secret": value, "File": format!("ci/npmrc{i}"),
                "SymlinkFile": "", "Commit": "", "Entropy": 4.0, "Author": "",
                "Email": "", "Date": "", "Message": "", "Tags": [],
                "Fingerprint": format!("ci/npmrc{i}:npm-access-token:{}", i + 1),
            })
        })
        .collect();
    let report = run.file("report.json");
    std::fs::write(&report, serde_json::to_string(&findings).unwrap()).unwrap();
    let report = report.to_str().unwrap();

    let output = run.command(&["--json", "plan", report]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    let id_of = |value: &str| {
        plan["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["fingerprint"] == fp(value).as_str())
            .unwrap()["rotation_id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (id1, id2) = (id_of(first), id_of(second));

    let output = run
        .command(&["apply", report, "--confirm", &id1, "--confirm", &id2])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(run.rotation(&id1)["step"], "failed");
    assert_eq!(run.rotation(&id1)["failed_step"], "update");
    assert_eq!(run.rotation(&id2)["step"], "revoked");
    // Exactly one revoke, and it is for the second secret.
    let log = std::fs::read_to_string(run.file("calls.jsonl")).unwrap();
    let revokes: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|c| c["method"] == "revoke")
        .collect();
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0]["fingerprint"], fp(second).as_str());
    assert!(stdout(&output).contains("Apply: 1 revoked, 0 pending revoke, 0 held, 1 failed"));
}

// T6 (AC6)
#[test]
fn revoke_failure_says_replacement_is_live() {
    let mut run = Run::new("npm_safety_t6_value");
    let id = run.planned_id();
    fail_provider(&mut run, "revoke", "500 upstream");
    let output = run.apply(&id, &[]);
    assert_eq!(output.status.code(), Some(1));
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "failed");
    assert_eq!(rotation["failed_step"], "revoke");
    let out = stdout(&output);
    assert!(
        out.contains("the replacement is live and the old secret may still be valid"),
        "{out}"
    );
    assert!(!out.contains("stopped before revoke"));
    assert_eq!(run.audit().last().unwrap()["step"], "revoke");
    assert_eq!(run.audit().last().unwrap()["outcome"], "failed");
}

// T7 (AC7)
#[test]
fn create_failure_updates_nothing() {
    let mut run = Run::new("npm_safety_t7_value");
    let id = run.planned_id();
    fail_provider(&mut run, "create_replacement", "quota exceeded");
    let output = run.apply(&id, &["--force"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!run.called("update"), "{:?}", run.calls());
    assert!(!run.called("revoke"));
    let held = run.held();
    assert_eq!(held["github-actions"][GHA], fp(&run.value).as_str());
    assert_eq!(held["aws-secrets-manager"][SM], fp(&run.value).as_str());
    assert_eq!(run.rotation(&id)["failed_step"], "create");
    assert!(stdout(&output).contains(&format!("consumers: {GHA} unchanged, {SM} unchanged")));
}

// T8 (AC1, AC2, AC6): injected errors echo the old and new values; neither
// reaches stdout, stderr (with tracing at -vvv), the audit log or the state.
#[test]
fn failures_never_leak_values() {
    for (n, case) in ["update", "verify", "verify_force", "revoke"]
        .into_iter()
        .enumerate()
    {
        let canary = format!("npm_safety_t8_{n}_canary");
        let mut run = Run::new(&canary);
        let id = run.planned_id();
        // The replacement is dropped after verify, so the revoke error only
        // echoes the old value.
        let echo = if case == "revoke" {
            format!("upstream echoed {canary}")
        } else {
            format!("upstream echoed {canary} and {REPLACEMENT}")
        };
        match case {
            "update" => fail_consumer(&mut run, 0, "update", &echo),
            "verify" | "verify_force" => {
                not_updatable(&mut run);
                fail_provider(&mut run, "verify", &echo);
            }
            _ => fail_provider(&mut run, "revoke", &echo),
        }
        let mut args = vec!["-vvv", "apply", "--stdin", "--confirm", &id];
        if case == "verify_force" {
            args.push("--force");
        }
        let output = run.run(&args);
        assert_eq!(output.status.code(), Some(1), "{case}");
        if case != "revoke" {
            assert!(!run.called("revoke"), "{case}");
        }
        let captures = [
            ("stdout", stdout(&output)),
            ("stderr and tracing", stderr(&output)),
            (
                "audit log",
                std::fs::read_to_string(run.file(".rotate/audit.jsonl")).unwrap(),
            ),
            (
                "state file",
                std::fs::read_to_string(run.file(".rotate/state.json")).unwrap(),
            ),
        ];
        assert!(
            captures[1].1.contains("audit entry appended"),
            "{case}: tracing not captured"
        );
        assert!(
            captures[2].1.contains("upstream echoed"),
            "{case}: error not recorded"
        );
        for (name, text) in &captures {
            assert!(!text.contains(&canary), "{case}: old value in {name}");
            assert!(!text.contains(REPLACEMENT), "{case}: new value in {name}");
        }
    }
}

// Apply's plan header says what will happen; plan keeps the dry-run header.
#[test]
fn apply_header_is_not_dry_run() {
    let run = Run::new("npm_safety_header_value");
    let plan = run.run(&["plan", "--stdin"]);
    assert!(stdout(&plan).contains("Dry run: nothing was changed."));
    let id = run.planned_id();
    let output = run.apply(&id, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.starts_with("Plan to apply: 1 to rotate, 0 skipped. Nothing has been changed yet."),
        "{out}"
    );
    assert!(!out.contains("Dry run"), "{out}");
}
