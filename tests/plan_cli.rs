//! SHA-250: `rotate plan` end to end against the `test-providers` mocks.
//!
//! Each test writes a scenario (`ROTATE_TEST_SCENARIO`) choosing mock
//! validity, replacement mode and consumer matches, and reads back the call
//! log the binary exports, which holds fingerprints only. Test values are
//! fake and shaped so no secret scanner matches them.

#![cfg(all(unix, feature = "test-providers"))]

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use rotate::secret::SecretValue;
use serde_json::{json, Value};

const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/plan-schema.json");
const REFUSE: &str = "apply will refuse to revoke without --force";

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

/// A temp dir holding a gitleaks report, a scenario and the call log.
struct Run {
    dir: tempfile::TempDir,
}

impl Run {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn calls_path(&self) -> PathBuf {
        self.path().join("calls.jsonl")
    }

    /// Writes a gitleaks report with one finding per value, and returns its
    /// path. `npm_` values get the `npm-access-token` rule, others
    /// `generic-api-key`, which names no provider.
    fn report(&self, values: &[&str]) -> PathBuf {
        let findings: Vec<Value> = values
            .iter()
            .enumerate()
            .map(|(i, value)| {
                let rule = if value.starts_with("npm_") {
                    "npm-access-token"
                } else {
                    "generic-api-key"
                };
                json!({
                    "RuleID": rule,
                    "Description": "fixture",
                    "StartLine": i + 1,
                    "EndLine": i + 1,
                    "StartColumn": 1,
                    "EndColumn": 10,
                    "Match": value,
                    "Secret": value,
                    "File": format!("ci/npmrc{i}"),
                    "SymlinkFile": "",
                    "Commit": "",
                    "Entropy": 4.0,
                    "Author": "",
                    "Email": "",
                    "Date": "",
                    "Message": "",
                    "Tags": [],
                    "Fingerprint": format!("ci/npmrc{i}:{rule}:{}", i + 1),
                })
            })
            .collect();
        let path = self.path().join("report.json");
        std::fs::write(&path, serde_json::to_string(&findings).unwrap()).unwrap();
        path
    }

    /// Writes the scenario with the call log path filled in.
    fn scenario(&self, mut scenario: Value) {
        scenario["call_log"] = json!(self.calls_path());
        std::fs::write(
            self.path().join("scenario.json"),
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
            .env("ROTATE_TEST_SCENARIO", self.path().join("scenario.json"))
            .args(args)
            .output()
            .unwrap()
    }

    fn calls(&self) -> Vec<Value> {
        std::fs::read_to_string(self.calls_path())
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn state(&self) -> String {
        std::fs::read_to_string(self.path().join(".rotate/state.json")).unwrap_or_default()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn two_matches(value: &str) -> Value {
    json!({
        "consumers": [
            { "name": "github-actions", "matches": [
                { "fingerprint": fp(value), "ref": "gha:org/repo:NPM_TOKEN", "method": "by_name" } ] },
            { "name": "aws-secrets-manager", "matches": [
                { "fingerprint": fp(value), "ref": "sm:prod/npm-publish", "method": "by_value" } ] }
        ]
    })
}

// T1 (AC1)
#[test]
fn plan_lists_replacement_consumers_revoke_and_overlap() {
    let value = "npm_plancli_t1_value";
    let run = Run::new();
    let report = run.report(&[value]);
    run.scenario(two_matches(value));
    let output = run.run(&["--overlap", "2h", "plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let out = stdout(&output);
    assert!(out.contains(&format!("npm  {}", fp(value))), "{out}");
    assert!(
        out.contains("replacement:  create a new npm credential for npm-user"),
        "{out}"
    );
    assert!(out.contains("gha:org/repo:NPM_TOKEN  by name"), "{out}");
    assert!(out.contains("sm:prod/npm-publish"), "{out}");
    assert!(
        out.contains("revoke:       delete the access token"),
        "{out}"
    );
    assert!(out.contains("overlap:      2h"), "{out}");
    assert!(!out.contains("blockers:"), "{out}");
}

// T2 (AC2)
#[test]
fn plan_makes_no_mutating_calls() {
    let value = "npm_plancli_t2_value";
    let run = Run::new();
    let report = run.report(&[value]);
    run.scenario(two_matches(value));
    let output = run.run(&["plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));

    let calls = run.calls();
    let methods: Vec<(&str, &str)> = calls
        .iter()
        .map(|c| (c["target"].as_str().unwrap(), c["method"].as_str().unwrap()))
        .collect();
    assert!(methods.contains(&("npm", "check_valid")), "{methods:?}");
    assert!(methods.contains(&("github-actions", "find")), "{methods:?}");
    assert!(
        methods.contains(&("aws-secrets-manager", "find")),
        "{methods:?}"
    );
    let mutating: Vec<_> = calls.iter().filter(|c| c["mutating"] == true).collect();
    assert!(mutating.is_empty(), "mutating calls: {mutating:?}");
    for (_, method) in methods {
        assert!(
            ["identify", "check_valid", "describe_scope", "find"].contains(&method),
            "{method}"
        );
    }
}

// T3 (AC3)
#[test]
fn not_updatable_consumer_is_a_blocker_exit_0() {
    let value = "npm_plancli_t3_value";
    let run = Run::new();
    let report = run.report(&[value]);
    run.scenario(json!({
        "consumers": [ { "name": "github-actions", "matches": [
            { "fingerprint": fp(value), "ref": "gha:org:NPM_TOKEN", "method": "by_name",
              "not_updatable": "org secret needs admin" } ] } ]
    }));
    let output = run.run(&["plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let out = stdout(&output);
    assert!(
        out.contains("cannot update: org secret needs admin"),
        "{out}"
    );
    assert!(out.contains("blockers:"), "{out}");
    assert!(
        out.contains(&format!("1 consumer cannot be updated; {REFUSE}")),
        "{out}"
    );
}

#[test]
fn consumer_lookup_error_is_a_blocker() {
    let value = "npm_plancli_lookup_value";
    let run = Run::new();
    let report = run.report(&[value]);
    run.scenario(json!({
        "consumers": [ { "name": "aws-secrets-manager", "fail_find": "403 denied" } ]
    }));
    let output = run.run(&["plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let out = stdout(&output);
    assert!(out.contains("lookup failed: 403 denied"), "{out}");
    assert!(
        out.contains(&format!(
            "consumer aws-secrets-manager could not be searched; {REFUSE}"
        )),
        "{out}"
    );
}

// T4 (AC4)
#[test]
fn invalid_secret_is_skipped_without_lookup() {
    let value = "npm_plancli_t4_value";
    let run = Run::new();
    let report = run.report(&[value]);
    let mut scenario = two_matches(value);
    scenario["providers"] = json!({ "npm": { "validity": "invalid" } });
    run.scenario(scenario);
    let output = run.run(&["plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let out = stdout(&output);
    assert!(out.contains("Plan: 0 to rotate, 1 skipped."), "{out}");
    assert!(out.contains("Skipped:"), "{out}");
    let row = out
        .lines()
        .find(|l| l.contains(&fp(value)))
        .expect("skipped row");
    assert!(row.starts_with("npm") && row.contains("invalid"), "{row}");

    let calls = run.calls();
    assert!(calls.iter().any(|c| c["method"] == "check_valid"));
    let finds: Vec<_> = calls
        .iter()
        .filter(|c| c["method"] == "find" && c["fingerprint"] == fp(value).as_str())
        .collect();
    assert!(finds.is_empty(), "{finds:?}");
    assert!(run.state().is_empty() || !run.state().contains(&fp(value)));
}

fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|v| strings(v, out)),
        Value::Object(map) => map.iter().for_each(|(k, v)| {
            out.push(k.clone());
            strings(v, out);
        }),
        _ => {}
    }
}

// T5 (AC5)
#[test]
fn json_validates_against_schema_and_has_no_value() {
    let value = "npm_plancli_t5_canary";
    let other = "zzz_plancli_t5_unsupported";
    let run = Run::new();
    let report = run.report(&[value, other]);
    let mut scenario = two_matches(value);
    scenario["consumers"][0]["matches"][0]["not_updatable"] = json!("needs admin");
    run.scenario(scenario);
    let output = run.run(&["--json", "plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));

    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(SCHEMA).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&plan)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(plan["rotations"].as_array().unwrap().len(), 1);
    assert_eq!(plan["skipped"].as_array().unwrap().len(), 1);
    assert_eq!(plan["rotations"][0]["consumers"][0]["updatable"], false);

    let mut all = Vec::new();
    strings(&plan, &mut all);
    for s in all {
        assert!(!s.contains(value), "canary in a JSON string");
        assert!(!s.contains(other), "unsupported value in a JSON string");
    }
}

fn rotation_ids(output: &Output) -> Vec<String> {
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    plan["rotations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rotation_id"].as_str().unwrap().to_owned())
        .collect()
}

// T6 (AC6)
#[test]
fn rotation_ids_stable_across_runs() {
    let values = ["npm_plancli_t6_first", "npm_plancli_t6_second"];
    let run = Run::new();
    let report = run.report(&values);
    run.scenario(json!({}));
    let first = run.run(&["--json", "plan", report.to_str().unwrap()]);
    let second = run.run(&["--json", "plan", report.to_str().unwrap()]);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    let ids = rotation_ids(&first);
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    assert_eq!(rotation_ids(&second), ids);
    let state = run.state();
    for id in &ids {
        assert!(state.contains(id.as_str()), "{id} not in the state file");
    }
    assert!(state.contains("\"planned\""));
}

// T7 (AC7)
#[test]
fn manual_mode_replacement_wording() {
    let value = "npm_plancli_t7_value";
    let run = Run::new();
    let report = run.report(&[value]);
    run.scenario(json!({ "providers": { "npm": { "mode": "manual" } } }));
    let output = run.run(&["plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    let out = stdout(&output);
    assert!(
        out.contains("replacement:  manual: you will be asked to paste the new secret"),
        "{out}"
    );
    let json = run.run(&["--json", "plan", report.to_str().unwrap()]);
    let plan: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(plan["rotations"][0]["replacement"]["mode"], "manual");
}

// T8 (AC1, AC5)
#[test]
fn plan_never_leaks_canary() {
    let canary = "npm_plancli_t8_canary_value";
    let run = Run::new();
    let report = run.report(&[canary]);
    let mut scenario = two_matches(canary);
    scenario["consumers"][1]["matches"][0]["not_updatable"] = json!("needs KMS grant");
    run.scenario(scenario);
    let report = report.to_str().unwrap();
    for args in [
        vec!["-vvv", "plan", report],
        vec!["-vvv", "--json", "plan", report],
    ] {
        let output = run.run(&args);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        for (name, stream) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            let text = String::from_utf8_lossy(stream);
            assert!(!text.contains(canary), "{args:?}: canary in {name}");
        }
    }
    let state = run.state();
    assert!(!state.is_empty());
    assert!(!state.contains(canary), "canary in the state file");
    let calls = std::fs::read_to_string(run.calls_path()).unwrap();
    assert!(!calls.contains(canary), "canary in the call log");
    // `plan` writes no audit records; if the file exists it holds no value.
    let audit = std::fs::read_to_string(run.path().join(".rotate/audit.jsonl")).unwrap_or_default();
    assert!(!audit.contains(canary), "canary in the audit log");
}

#[test]
fn locked_state_file_exits_2_before_any_call() {
    let value = "npm_plancli_lock_value";
    let run = Run::new();
    let report = run.report(&[value]);
    run.scenario(json!({}));
    let lock =
        rotate::fsutil::LockFile::try_acquire(&run.path().join(".rotate/state.json.lock")).unwrap();
    let output = run.run(&["plan", report.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("another rotate process"), "{err}");
    assert!(run.calls().is_empty(), "{:?}", run.calls());
    drop(lock);
    assert_eq!(
        run.run(&["plan", report.to_str().unwrap()]).status.code(),
        Some(0)
    );
}
