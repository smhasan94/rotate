//! SHA-263: `rotate status`, end to end against seeded state and audit
//! files.
//!
//! Every test seeds `.rotate/state.json` (and, for T3, `.rotate/audit.jsonl`)
//! directly, as an earlier apply would have left them, then runs the binary.
//! The scenario's `clock_offset_secs` moves the clock status uses (the
//! injectable clock). Status must read only: T6 proves it makes no call on
//! the shared mock call log and no HTTP request with the real plugins, and
//! T7 that a provider-shaped token in the audit log never reaches any
//! output. Test values are fake and built at run time so no secret scanner
//! matches this file.

#![cfg(all(unix, feature = "test-providers"))]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use rotate::secret::SecretValue;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/status-schema.json");
const GHA: &str = "gha:org/repo:NPM_TOKEN";
const SM: &str = "sm:prod/npm-publish";

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

/// A GitHub-shaped token the redactor's provider patterns catch, assembled
/// at run time.
fn canary() -> String {
    ["gh", "p_", &"Q7canary".repeat(5)].concat()
}

fn at(offset: Duration) -> String {
    (OffsetDateTime::now_utc() + offset)
        .format(&Rfc3339)
        .unwrap()
}

struct Run {
    dir: tempfile::TempDir,
    scenario: Value,
}

impl Run {
    /// Mock providers and two mock consumers registered, sharing one call
    /// log, and a prompt that fails the test if anything asks.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut run = Self {
            dir,
            scenario: Value::Null,
        };
        run.scenario = json!({
            "providers": { "npm": {}, "aws": {}, "github": {}, "openai": {} },
            "consumers": [
                { "name": "github-actions", "matches": [
                    { "fingerprint": fp("npm_status-old"), "ref": GHA, "method": "by_name" } ] },
                { "name": "aws-secrets-manager", "matches": [
                    { "fingerprint": fp("npm_status-old"), "ref": SM } ] }
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

    /// Moves the clock status uses by `secs` from now.
    fn clock(&mut self, secs: i64) {
        self.scenario["clock_offset_secs"] = json!(secs);
        self.write();
    }

    fn run(&self, args: &[&str]) -> Output {
        assert_cmd::Command::cargo_bin("rotate")
            .unwrap()
            .current_dir(self.path())
            .env_remove("ROTATE_CONFIG")
            .env_remove("ROTATE_STATE_FILE")
            .env_remove("ROTATE_AUDIT_LOG")
            .env_remove("ROTATE_OVERLAP")
            .env("ROTATE_ACTOR", "ci@runner")
            .env("ROTATE_TEST_SCENARIO", self.file("scenario.json"))
            .args(args)
            .output()
            .unwrap()
    }

    /// Every call the mocks recorded in the last run.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .expect("the binary writes the call log on exit")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn private_dir(&self) -> PathBuf {
        let dir = self.file(".rotate");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn write_private(&self, name: &str, text: &str) {
        let path = self.private_dir().join(name);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn seed(&self, rotations: Value) {
        self.write_private(
            "state.json",
            &json!({ "version": 1, "rotations": rotations }).to_string(),
        );
    }

    fn seed_audit(&self, entries: &[Value]) {
        let text: String = entries.iter().map(|e| format!("{e}\n")).collect();
        self.write_private("audit.jsonl", &text);
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.file(name)).unwrap_or_default()
    }
}

/// A rotation record as apply writes it.
fn rotation(id: &str, value: &str, step: &str) -> Value {
    json!({
        "rotation_id": id,
        "provider": "npm",
        "fingerprint": fp(value),
        "replacement_fingerprint": fp(&format!("{value}-new")),
        "replacement_ref": "npm-ref-1",
        "step": step,
        "consumers": [
            { "consumer": "github-actions", "consumer_ref": GHA, "status": "updated", "holds": "secret" },
            { "consumer": "aws-secrets-manager", "consumer_ref": SM, "status": "updated", "holds": "secret" }
        ],
        "revoke_not_before": null,
        "started_at": at(Duration::minutes(-20)),
        "updated_at": at(Duration::minutes(-3)),
        "force": false
    })
}

fn audit_entry(id: &str, value: &str, step: &str, outcome: &str, error: Option<&str>) -> Value {
    let mut entry = json!({
        "version": 1,
        "ts": at(Duration::minutes(-3)),
        "actor": "ci@runner",
        "rotation_id": id,
        "provider": "npm",
        "fingerprint": fp(value),
        "step": step,
        "outcome": outcome,
    });
    if let Some(error) = error {
        entry["error"] = json!(error);
    }
    entry
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn shown(output: &Output) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout(output),
        stderr(output)
    )
}

fn row<'a>(table: &'a str, id: &str) -> &'a str {
    table
        .lines()
        .find(|l| l.starts_with(id))
        .unwrap_or_else(|| panic!("no row for {id}:\n{table}"))
}

// T1 (AC1): `revoke_not_before` an hour ahead of the real clock, and the
// injected clock 55 minutes ahead: five minutes left.
#[test]
fn t1_pending_revoke_shows_remaining_time_and_exits_3() {
    let mut run = Run::new();
    let mut pending = rotation("rot-00000001", "npm_status-old", "pending_revoke");
    pending["revoke_not_before"] = json!(at(Duration::hours(1)));
    run.seed(json!([pending]));
    run.clock(55 * 60);

    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
    let table = stdout(&output);
    assert!(table.starts_with("ROTATION"), "{table}");
    let line = row(&table, "rot-00000001");
    assert!(line.contains("pending_revoke"), "{line}");
    assert!(line.contains("npm"), "{line}");
    assert!(line.contains(&fp("npm_status-old")), "{line}");
    assert!(line.contains("2/2"), "{line}");
    assert!(
        line.contains("(in 4m 5") || line.contains("(in 5m 0s)"),
        "about five minutes left: {line}"
    );
    assert!(line.contains("re-run `rotate apply` after "), "{line}");
    assert!(line.contains(" UTC to revoke the old secret"), "{line}");
    assert!(run.calls().is_empty(), "{:?}", run.calls());
}

// T2 (AC2)
#[test]
fn t2_revoked_only_hidden_without_all_and_exits_0() {
    let run = Run::new();
    run.seed(json!([
        rotation("rot-0000000a", "npm_status-a", "revoked"),
        rotation("rot-0000000b", "npm_status-b", "revoked"),
    ]));

    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let text = stdout(&output);
    assert!(!text.contains("rot-0000000a"), "{text}");
    assert!(!text.contains("rot-0000000b"), "{text}");
    assert!(
        text.contains("no rotations in progress (2 finished; use --all to show them)"),
        "{text}"
    );
    assert!(run.calls().is_empty());

    let output = run.run(&["status", "--all"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    for id in ["rot-0000000a", "rot-0000000b"] {
        let line = row(&table, id);
        assert!(line.contains("revoked"), "{line}");
        assert!(line.contains("done"), "{line}");
    }
    assert!(run.calls().is_empty());

    let output = run.run(&["--json", "status"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );
}

/// A failed rotation whose last audit entry carries the canary in its
/// error, plus an earlier entry with an error that must not be shown.
fn failed_with_canary(run: &Run) {
    let mut failed = rotation("rot-0000000f", "npm_status-f", "failed");
    failed["failed_step"] = json!("update");
    failed["consumers"][1]["status"] = json!("failed");
    run.seed(json!([failed]));
    run.seed_audit(&[
        audit_entry(
            "rot-0000000f",
            "npm_status-f",
            "check",
            "failed",
            Some("older error"),
        ),
        audit_entry("rot-0000000f", "npm_status-f", "create", "ok", None),
        audit_entry(
            "rot-0000000f",
            "npm_status-f",
            "update",
            "failed",
            Some(&format!(
                "PutSecretValue denied: upstream echoed {}",
                canary()
            )),
        ),
    ]);
}

// T3 (AC3)
#[test]
fn t3_failed_shows_redacted_audit_error_and_exits_3() {
    let run = Run::new();
    failed_with_canary(&run);

    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
    let table = stdout(&output);
    let line = row(&table, "rot-0000000f");
    assert!(line.contains("failed"), "{line}");
    assert!(line.contains("1/2"), "{line}");
    assert!(
        line.contains(&format!("consumer {SM} failed: see the audit log")),
        "{line}"
    );
    let detail = table
        .lines()
        .find(|l| l.trim_start().starts_with("last error (update, "))
        .unwrap_or_else(|| panic!("no error line:\n{table}"));
    assert!(
        detail.contains("PutSecretValue denied: upstream echoed [REDACTED github]"),
        "{detail}"
    );
    assert!(!table.contains("older error"), "{table}");
    assert!(!table.contains(&canary()), "{table}");
    assert!(run.calls().is_empty());
}

// T4 (AC4)
#[test]
fn t4_no_state_file_prints_no_rotations() {
    let run = Run::new();
    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(stdout(&output), "no rotations\n");
    assert!(!run.file(".rotate").exists(), "status created files");

    let output = run.run(&["status", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );

    run.seed(json!([]));
    let output = run.run(&["status", "--all"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(stdout(&output), "no rotations\n");
    assert!(run.calls().is_empty());
}

// T5 (AC5): every row of the table is an object with the same fields, and
// the document matches docs/status-schema.json.
#[test]
fn t5_json_rows_match_schema_and_table() {
    let mut run = Run::new();
    let mut pending = rotation("rot-00000001", "npm_status-p", "pending_revoke");
    pending["revoke_not_before"] = json!(at(Duration::hours(1)));
    let mut failed = rotation("rot-00000002", "npm_status-f", "failed");
    failed["failed_step"] = json!("verify");
    let planned = rotation("rot-00000003", "npm_status-n", "planned");
    let done = rotation("rot-00000004", "npm_status-d", "revoked");
    run.seed(json!([pending, failed, planned, done]));
    run.seed_audit(&[audit_entry(
        "rot-00000002",
        "npm_status-f",
        "verify",
        "failed",
        Some("verify said no"),
    )]);
    run.clock(55 * 60);

    let output = run.run(&["status", "--json"]);
    assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
    let rows: Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(SCHEMA).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let errors: Vec<String> = validator
        .iter_errors(&rows)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:?}");

    let rows = rows.as_array().unwrap();
    let ids: Vec<&str> = rows
        .iter()
        .map(|r| r["rotation_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["rot-00000001", "rot-00000002", "rot-00000003"]);

    let pending = &rows[0];
    assert_eq!(pending["provider"], "npm");
    assert_eq!(pending["fingerprint"], fp("npm_status-p"));
    assert_eq!(pending["step"], "pending_revoke");
    assert_eq!(pending["rollback_in_progress"], false);
    assert_eq!(pending["consumers_updated"], 2);
    assert_eq!(pending["consumers_total"], 2);
    assert_eq!(pending["pending"], true);
    let left = pending["revoke_remaining_seconds"].as_i64().unwrap();
    assert!((290..=300).contains(&left), "{left}");
    assert!(pending["revoke_not_before"].is_string());
    let ago = pending["updated_seconds_ago"].as_i64().unwrap();
    assert!(ago >= 3 * 60, "{ago}");
    assert!(pending["error"].is_null());

    let failed = &rows[1];
    assert_eq!(failed["failed_step"], "verify");
    assert_eq!(failed["error"]["step"], "verify");
    assert_eq!(failed["error"]["text"], "verify said no");
    assert!(failed["revoke_remaining_seconds"].is_null());

    let planned = &rows[2];
    assert_eq!(planned["pending"], false);
    assert_eq!(
        planned["hint"],
        "not started: run `rotate apply` to start it"
    );

    // The table shows the same rows with the same hints.
    let output = run.run(&["status"]);
    let table = stdout(&output);
    for r in rows {
        let line = row(&table, r["rotation_id"].as_str().unwrap());
        assert!(line.contains(r["hint"].as_str().unwrap()), "{line}");
        assert!(line.contains(r["step"].as_str().unwrap()), "{line}");
    }
    assert!(run.calls().is_empty());
}

/// One rotation per step for every provider, so a status that reached for
/// a plugin anywhere would have a reason to.
fn every_step(run: &Run) {
    let mut rotations = Vec::new();
    let steps = [
        "planned",
        "created",
        "consumers_updated",
        "verified",
        "pending_revoke",
        "failed",
        "needs_rollback",
        "revoked",
        "rolled_back",
    ];
    for (p, provider) in ["aws", "github", "npm", "openai"].iter().enumerate() {
        for (s, step) in steps.iter().enumerate() {
            let mut r = rotation(
                &format!("rot-{p:04}{s:04}"),
                &format!("{provider}_status-{s}"),
                step,
            );
            r["provider"] = json!(provider);
            if *step == "pending_revoke" {
                r["revoke_not_before"] = json!(at(Duration::minutes(5)));
            }
            if *step == "revoked" {
                r["rollback"] = json!({ "restore_done": true, "revoke_done": false });
            }
            rotations.push(r);
        }
    }
    run.seed(Value::Array(rotations));
}

// T6 (AC6): mocks registered for every provider and two consumers; the
// shared call log is empty after every run.
#[test]
fn t6_status_makes_no_call() {
    let run = Run::new();
    for args in [&["status"][..], &["status", "--all"], &["--json", "status"]] {
        let output = run.run(args);
        assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
        assert!(run.calls().is_empty(), "{args:?}: {:?}", run.calls());
    }
    every_step(&run);
    failed_with_canary(&run);
    every_step(&run);
    for args in [
        &["status"][..],
        &["status", "--all"],
        &["--json", "status", "--all"],
        &["-vvv", "status"],
    ] {
        let output = run.run(args);
        assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
        assert!(run.calls().is_empty(), "{args:?}: {:?}", run.calls());
    }
}

// T6 (AC6): the real plugins, every one pointed at a recording server
// through rotate.yaml, see no request.
#[tokio::test(flavor = "multi_thread")]
async fn t6_status_makes_no_http_request() {
    let rec = common::CallRecorder::start().await;
    let run = Run::new();
    let uri = rec.uri();
    std::fs::write(
        run.file("rotate.yaml"),
        format!(
            "consumers:\n  github_actions:\n    targets: [org/repo]\n  aws_secrets_manager:\n    secrets: [prod/app]\n\
             providers:\n  aws:\n    region: us-east-1\n    endpoint_url: {uri}\n  github:\n    api_url: {uri}\n\
             \x20 npm:\n    registry: {uri}\n  openai:\n    api_url: {uri}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        run.file("scenario.json"),
        json!({ "real_plugins": true, "prompt": "panic" }).to_string(),
    )
    .unwrap();
    every_step(&run);
    for args in [&["status"][..], &["-vvv", "--json", "status", "--all"]] {
        let output = assert_cmd::Command::cargo_bin("rotate")
            .unwrap()
            .current_dir(run.path())
            .env_clear()
            .env("HOME", run.path())
            .env("ROTATE_TEST_SCENARIO", run.file("scenario.json"))
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
    }
    let calls = rec.calls().await;
    assert!(calls.is_empty(), "{calls:?}");
}

// T7 (AC3): the canary from T3's audit entry is absent from stdout and
// stderr at -vvv, in table and JSON form, and status left the state file
// and the audit log byte for byte as they were.
#[test]
fn t7_no_secret_in_any_output() {
    let run = Run::new();
    failed_with_canary(&run);
    let state = run.read(".rotate/state.json");
    let audit = run.read(".rotate/audit.jsonl");
    assert!(String::from_utf8_lossy(&audit).contains(&canary()));

    for args in [
        &["-vvv", "status"][..],
        &["-vvv", "status", "--all"],
        &["-vvv", "--json", "status"],
    ] {
        let output = assert_cmd::Command::cargo_bin("rotate")
            .unwrap()
            .current_dir(run.path())
            .env("ROTATE_TEST_SCENARIO", run.file("scenario.json"))
            .env("RUST_LOG", "trace")
            .env_remove("ROTATE_STATE_FILE")
            .env_remove("ROTATE_AUDIT_LOG")
            .env_remove("ROTATE_CONFIG")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
        let all = format!("{}{}", stdout(&output), stderr(&output));
        assert!(!all.contains(&canary()), "{args:?}: {all}");
        assert!(!all.contains("Q7canary"), "{args:?}: {all}");
        assert!(all.contains("[REDACTED github]"), "{args:?}: {all}");
    }
    assert_eq!(run.read(".rotate/state.json"), state);
    assert_eq!(run.read(".rotate/audit.jsonl"), audit);
    assert!(run.calls().is_empty());
    let leftovers: Vec<String> = std::fs::read_dir(run.file(".rotate"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let mut leftovers = leftovers;
    leftovers.sort();
    assert_eq!(
        leftovers,
        ["audit.jsonl", "state.json"],
        "status wrote a file"
    );
}

#[test]
fn rollback_in_progress_of_revoked_is_listed_and_pending() {
    let run = Run::new();
    let mut r = rotation("rot-000000rb", "npm_status-rb", "revoked");
    r["rollback"] = json!({ "restore_done": true, "revoke_done": false });
    r["consumers"][0]["status"] = json!("restored");
    run.seed(json!([r]));
    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
    let table = stdout(&output);
    let line = row(&table, "rot-000000rb");
    assert!(line.contains("rolling_back (revoked)"), "{line}");
    assert!(
        line.contains(
            "rollback in progress: re-run `rotate rollback` with the same input to finish it"
        ),
        "{line}"
    );
}

#[test]
fn needs_rollback_and_planned_hints() {
    let run = Run::new();
    let mut nr = rotation("rot-00000001", "npm_status-nr", "needs_rollback");
    nr["failed_step"] = json!("update");
    run.seed(json!([
        nr,
        rotation("rot-00000002", "npm_status-pl", "planned")
    ]));
    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
    let table = stdout(&output);
    assert!(row(&table, "rot-00000001")
        .contains("run `rotate rollback` with the same input, then `rotate apply` again"));
    assert!(row(&table, "rot-00000002").contains("not started"));

    // Only planned: listed, but nothing is pending.
    run.seed(json!([rotation(
        "rot-00000002",
        "npm_status-pl",
        "planned"
    )]));
    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
}

#[test]
fn wide_audit_log_is_a_warning() {
    let run = Run::new();
    failed_with_canary(&run);
    let path = run.file(".rotate/audit.jsonl");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(3), "{}", shown(&output));
    assert!(row(&stdout(&output), "rot-0000000f").contains("failed"));
    assert!(!stdout(&output).contains("last error"));
    let err = stderr(&output);
    assert!(
        err.contains("warning: audit log errors are not shown:"),
        "{err}"
    );
    assert!(err.contains("chmod 600"), "{err}");
}

#[test]
fn wide_state_file_exits_2() {
    let run = Run::new();
    run.seed(json!([rotation("rot-00000001", "npm_status-w", "failed")]));
    let path = run.file(".rotate/state.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = run.run(&["status"]);
    assert_eq!(output.status.code(), Some(2), "{}", shown(&output));
    assert!(stderr(&output).contains("error: "), "{}", shown(&output));
    assert!(stdout(&output).is_empty());
}
