//! SHA-264: an AWS key rotated end to end through the `rotate` binary.
//!
//! The real AWS provider and the real Secrets Manager consumer run against
//! one wiremock server playing STS, IAM and Secrets Manager. Behind every
//! route is [`AwsModel`], an in-memory account whose answers change as calls
//! happen: `CreateAccessKey` adds a key that STS then accepts,
//! `UpdateAccessKey` flips a key's status, `PutSecretValue` adds a secret
//! version. `rotate.yaml` points `providers.aws.endpoint_url` at the server.
//!
//! In a `test-providers` build (CI tests with `--all-features`) the scenario
//! sets `real_plugins`, so the binary registers the real plugins exactly as
//! a release build does; without the feature it registers them anyway.
//! Each child process gets a cleared environment holding fake operator
//! credentials only, so nothing can reach real AWS or a local profile.
//!
//! Every command runs at `-vvv` with `RUST_LOG=trace`, and every run is
//! checked for both secret access keys (T8): stdout, stderr, the audit log,
//! the state file, and every request the server recorded except the
//! `PutSecretValue` bodies, which must carry a pair. Key ids and secrets are
//! built at runtime so no literal here matches a secret-scanning pattern.
//!
//! The model and runner live in `tests/e2e/mod.rs`, shared with the MVP
//! acceptance test (SHA-267).

mod common;
mod e2e;

use serde_json::{json, Value};

use e2e::*;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// T1 (AC1)
#[tokio::test(flavor = "multi_thread")]
async fn t1_plan_lists_user_entry_and_deactivate_without_mutations() {
    let e2e = E2e::start().await;
    let before = e2e.model.snapshot();

    let output = e2e.run(&["plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    assert!(table.contains("Dry run: nothing was changed."), "{table}");
    assert!(table.contains("1 to rotate, 0 skipped"), "{table}");
    assert!(table.contains(&user_arn()), "{table}");
    assert!(table.contains(&fp(&e2e.leaked.secret)), "{table}");
    let row = table
        .lines()
        .find(|l| l.contains(PAIR_REF))
        .unwrap_or_else(|| panic!("no Secrets Manager row: {table}"));
    assert!(row.contains("aws-secrets-manager"), "{row}");
    assert!(row.contains("by value"), "{row}");
    assert!(row.contains("update"), "{row}");
    assert!(
        table.contains("deactivate the access key (not deleted; rollback can reactivate it)"),
        "{table}"
    );

    let output = e2e.run(&["--json", "plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rotation = &plan["rotations"][0];
    assert_eq!(rotation["provider"], "aws");
    assert_eq!(rotation["validity"], "valid");
    assert_eq!(rotation["scope"]["identity"], user_arn());
    let lines: Vec<&str> = rotation["scope"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(lines.contains(&"user: deploy-bot"), "{lines:?}");
    assert!(lines.contains(&"access keys: 1 of 2 used"), "{lines:?}");
    assert_eq!(rotation["replacement"]["mode"], "automatic");
    assert_eq!(
        rotation["consumers"],
        json!([{
            "consumer": "aws-secrets-manager",
            "consumer_ref": PAIR_REF,
            "match_method": "by_value",
            "holds": "key_pair",
            "updatable": true,
            "reason": null,
        }])
    );
    assert!(rotation["revoke_action"]
        .as_str()
        .unwrap()
        .starts_with("deactivate the access key"));
    assert_eq!(rotation["blockers"], json!([]));

    // Zero mutating requests, and the model is exactly as it started.
    e2e.rec.assert_no_mutations().await;
    assert_eq!(e2e.model.snapshot(), before);
    for op in MUTATING {
        assert_eq!(e2e.model.count(op), 0, "{op}");
    }
    // The leaked key signed exactly one call per plan: GetCallerIdentity.
    assert_eq!(
        e2e.non_operator_calls().await,
        ["leaked: GetCallerIdentity", "leaked: GetCallerIdentity"]
    );
    assert!(e2e.assert_requests_clean().await.is_empty());
}

// T2 (AC2)
#[tokio::test(flavor = "multi_thread")]
async fn t2_apply_rotates_key_and_secret() {
    let e2e = E2e::start().await;
    let (_, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert!(stdout(&output).contains("1 revoked"), "{}", shown(&output));

    assert_eq!(
        e2e.model.key_ids(),
        [e2e.leaked.id.clone(), e2e.new_id.clone()]
    );
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Active"));
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Inactive"));
    e2e.assert_secret_holds(&e2e.new_id, &e2e.new_secret);
    assert_eq!(e2e.model.versions(), 2);
    assert_eq!(e2e.model.count("CreateAccessKey"), 1);
    assert_eq!(e2e.model.count("PutSecretValue"), 1);
    // Create, write the secret, then revoke last.
    let mutations: Vec<String> = e2e
        .model
        .ops()
        .into_iter()
        .filter(|op| MUTATING.contains(&op.as_str()))
        .collect();
    assert_eq!(
        mutations,
        ["CreateAccessKey", "PutSecretValue", "UpdateAccessKey"]
    );
    // The leaked key only ever proved itself; the new one only verified.
    let signed = e2e.non_operator_calls().await;
    assert!(
        signed
            .iter()
            .all(|c| c == "leaked: GetCallerIdentity" || c == "new: GetCallerIdentity"),
        "{signed:?}"
    );
    assert!(signed.contains(&"new: GetCallerIdentity".to_owned()));
    assert_eq!(e2e.assert_requests_clean().await, ["new"]);
}

// T3 (AC3)
#[tokio::test(flavor = "multi_thread")]
async fn t3_audit_has_every_step_with_both_fingerprints() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let leaked = fp(&e2e.leaked.secret);
    let new = fp(&e2e.new_secret);
    let audit = e2e.audit();
    let steps: Vec<&str> = audit.iter().map(|e| e["step"].as_str().unwrap()).collect();
    assert_eq!(
        steps,
        ["plan", "create", "update", "verify", "revoke"],
        "{audit:?}"
    );
    for entry in &audit {
        assert_eq!(entry["outcome"], "ok", "{entry}");
        assert_eq!(entry["rotation_id"], id.as_str(), "{entry}");
        assert_eq!(entry["provider"], "aws", "{entry}");
        assert_eq!(entry["fingerprint"], leaked.as_str(), "{entry}");
        assert_eq!(entry["actor"], "e2e@runner", "{entry}");
        if entry["step"] != "plan" {
            assert_eq!(entry["replacement_fingerprint"], new.as_str(), "{entry}");
        }
    }
    let update = audit.iter().find(|e| e["step"] == "update").unwrap();
    assert_eq!(update["consumer"], PAIR_REF, "{update}");
    e2e.assert_requests_clean().await;
}

// T4 (AC4): the record `rotate status` reads.
#[tokio::test(flavor = "multi_thread")]
async fn t4_state_records_revoked() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let rotation = e2e.rotation(&id);
    assert_eq!(rotation["step"], "revoked", "{rotation}");
    assert_eq!(rotation["provider"], "aws");
    assert_eq!(rotation["fingerprint"], fp(&e2e.leaked.secret).as_str());
    assert_eq!(
        rotation["replacement_fingerprint"],
        fp(&e2e.new_secret).as_str()
    );
    assert_eq!(rotation["replacement_ref"], e2e.new_id.as_str());
    assert!(rotation["revoke_not_before"].is_null(), "{rotation}");
    let consumers = rotation["consumers"].as_array().unwrap();
    assert_eq!(consumers.len(), 1, "{rotation}");
    assert_eq!(consumers[0]["consumer_ref"], PAIR_REF);
    assert_eq!(consumers[0]["status"], "updated");
}

// T4 (AC4): the command itself. `rotate status` is a stub until SHA-263.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs `rotate status` (SHA-263)"]
async fn t4_status_all_shows_revoked() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let calls = e2e.rec.calls().await.len();

    let output = e2e.run(&["status", "--all"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    let row = table
        .lines()
        .find(|l| l.contains(&id))
        .unwrap_or_else(|| panic!("no row for {id}: {table}"));
    assert!(row.contains("revoked"), "{row}");
    assert_eq!(e2e.rec.calls().await.len(), calls, "status made a call");
}

// T5 (AC5)
#[tokio::test(flavor = "multi_thread")]
async fn t5_rollback_restores_old_key_and_secret() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let output = e2e.run(&["rollback", "report.ndjson", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Inactive"));
    e2e.assert_secret_holds(&e2e.leaked.id, &e2e.leaked.secret);
    assert_eq!(e2e.model.versions(), 3);
    // Nothing was deleted and no second replacement was minted.
    assert_eq!(e2e.model.key_ids().len(), 2);
    assert_eq!(e2e.model.count("CreateAccessKey"), 1);

    assert_eq!(e2e.rotation(&id)["step"], "rolled_back");
    let rollback: Vec<Value> = e2e
        .audit()
        .into_iter()
        .filter(|e| e["step"] == "rollback")
        .collect();
    let actions: Vec<&str> = rollback
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    for action in ["restore_old", "restore_consumer", "revoke_replacement"] {
        assert!(actions.contains(&action), "{actions:?}");
    }
    assert!(
        rollback.iter().all(|e| e["outcome"] == "ok"),
        "{rollback:?}"
    );
    // Apply wrote the new pair, rollback the old one; nothing else carried
    // a secret.
    assert_eq!(e2e.assert_requests_clean().await, ["new", "leaked"]);
}

// T6 (AC6)
#[tokio::test(flavor = "multi_thread")]
async fn t6_two_keys_refused_before_create() {
    let e2e = E2e::start().await;
    let other = Key {
        id: key_id("E2EOTHR"),
        secret: secret("e2eOthr1"),
        status: "Active",
    };
    e2e.model.state().keys.push(other.clone());
    let before = e2e.model.snapshot();

    let (_, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(1), "{}", shown(&output));
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        text.contains("already has 2 access keys"),
        "{}",
        shown(&output)
    );
    assert!(text.contains(&other.id), "{}", shown(&output));

    assert_eq!(e2e.model.count("CreateAccessKey"), 0);
    assert_eq!(e2e.model.count("PutSecretValue"), 0);
    assert_eq!(e2e.model.count("UpdateAccessKey"), 0);
    assert_eq!(e2e.model.snapshot(), before);
    e2e.rec.assert_no_mutations().await;
    e2e.assert_secret_holds(&e2e.leaked.id, &e2e.leaked.secret);
    assert!(e2e.assert_requests_clean().await.is_empty());
}

// T7 (AC7)
#[tokio::test(flavor = "multi_thread")]
async fn t7_put_denied_stops_before_revoke() {
    let e2e = E2e::start().await;
    e2e.model.state().deny_put = true;

    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(1), "{}", shown(&output));
    let summary = stdout(&output);
    assert!(
        summary.contains("stopped before revoke; old secret still valid"),
        "{}",
        shown(&output)
    );

    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));
    assert_eq!(e2e.model.count("PutSecretValue"), 1);
    assert_eq!(
        e2e.model.count("UpdateAccessKey"),
        0,
        "revoke must not be attempted"
    );
    e2e.assert_secret_holds(&e2e.leaked.id, &e2e.leaked.secret);
    assert_eq!(e2e.model.versions(), 1);
    assert_eq!(e2e.rotation(&id)["step"], "failed");
    let audit = e2e.audit();
    assert!(audit.iter().all(|e| e["step"] != "revoke"), "{audit:?}");
    assert!(audit
        .iter()
        .any(|e| e["step"] == "update" && e["outcome"] == "failed"));
    // The denied write carried the new pair; nothing else carried a secret.
    assert_eq!(e2e.assert_requests_clean().await, ["new"]);
}

// T8 (AC2, AC5)
#[tokio::test(flavor = "multi_thread")]
async fn t8_no_secret_in_any_output() {
    let e2e = E2e::start().await;
    // `run` checks stdout, stderr (at -vvv, RUST_LOG=trace), the audit log
    // and the state file of every command.
    let output = e2e.run(&["plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    // The trace output really is at trace level, SDK events included, so
    // the absence checks above mean something.
    let err = stderr(&output);
    assert!(err.contains("TRACE"), "stderr is not at trace level");
    assert!(err.contains("aws_smithy"), "no SDK events in the trace");
    let output = e2e.run(&["rollback", "report.ndjson", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let output = e2e.run(&["--json", "plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(e2e.assert_requests_clean().await, ["new", "leaked"]);

    // The files exist and name both secrets by fingerprint only.
    for name in [".rotate/audit.jsonl", ".rotate/state.json"] {
        let text = std::fs::read_to_string(e2e.file(name)).unwrap();
        assert!(text.contains(&fp(&e2e.leaked.secret)), "{name}");
        assert!(text.contains(&fp(&e2e.new_secret)), "{name}");
    }
}
