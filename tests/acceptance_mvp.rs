//! SHA-267: the MVP acceptance test.
//!
//! The brief's "Success for MVP", as a test: given a TruffleHog report with a
//! leaked AWS key referenced by one GitHub Actions secret and one Secrets
//! Manager entry, `rotate plan` shows the full plan with no changes made, and
//! `rotate apply` rotates it end to end: old key revoked, both consumers
//! updated, complete audit log, and the secret value appearing nowhere in
//! output or logs.
//!
//! The `rotate` binary runs with the real AWS provider, the real Secrets
//! Manager consumer and the real GitHub Actions consumer against one
//! wiremock server (`tests/e2e/mod.rs`): an AWS model (STS, IAM, Secrets
//! Manager entry `prod/app`) and a GitHub model (the Actions secrets of
//! `acme/api`, which hold the leaked pair under the convention names
//! `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`). The GitHub model owns a
//! sealed-box key pair, so the test opens every `PUT` body with the private
//! key and checks what was written.
//!
//! Every command runs at `-vvv` with `RUST_LOG=trace` in a cleared
//! environment, and every run is checked for the leaked and the new secret
//! access key and the GitHub token in stdout, stderr, the audit log and the
//! state file.

mod common;
mod e2e;

use std::collections::BTreeSet;

use serde_json::Value;

use e2e::*;

fn gh_ref(name: &str) -> String {
    format!("github-actions:{REPO}:{name}")
}

/// The three consumer matches: the Secrets Manager entry by value, and the
/// two Actions secrets by name.
fn consumer_refs() -> BTreeSet<String> {
    [
        PAIR_REF.to_owned(),
        gh_ref(GH_KEY_ID_NAME),
        gh_ref(GH_SECRET_NAME),
    ]
    .into_iter()
    .collect()
}

/// State-changing requests to either model, in the order the server saw
/// them: the AWS action, or `PUT <secret name>` for GitHub.
async fn mutations(e2e: &E2e) -> Vec<String> {
    let requests = e2e.rec.server().received_requests().await.unwrap();
    let mut seen = Vec::new();
    for req in &requests {
        if is_github(req) {
            if req.method.as_str() != "GET" {
                let name = req.url.path().rsplit('/').next().unwrap_or("");
                seen.push(format!("{} {name}", req.method));
            }
            continue;
        }
        let op = sm_target(req)
            .map(str::to_owned)
            .unwrap_or_else(|| fields(&req.body).get("Action").cloned().unwrap_or_default());
        if MUTATING.contains(&op.as_str()) {
            seen.push(op);
        }
    }
    seen
}

/// Every Actions `PUT` the server recorded, opened with the repository's
/// private key, as `(secret name, plaintext)`.
async fn opened_puts(e2e: &E2e) -> Vec<(String, String)> {
    let requests = e2e.rec.server().received_requests().await.unwrap();
    requests
        .iter()
        .filter(|req| is_github(req) && req.method.as_str() == "PUT")
        .map(|req| {
            let name = req.url.path().rsplit('/').next().unwrap().to_owned();
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            assert_eq!(body["key_id"], GH_KEY_ID, "PUT {name}");
            let plain = e2e
                .gh()
                .open(body["encrypted_value"].as_str().unwrap())
                .unwrap_or_else(|| panic!("PUT {name} is not sealed for the repository key"));
            (name, plain)
        })
        .collect()
}

/// `acme/api` holds `(id, secret)` under the convention names and its
/// unrelated secret is untouched.
fn assert_actions_hold(e2e: &E2e, id: &str, secret: &str) {
    let gh = e2e.gh();
    assert_eq!(gh.value(GH_KEY_ID_NAME), id);
    assert!(
        gh.value(GH_SECRET_NAME) == secret,
        "{GH_SECRET_NAME} does not hold the expected secret"
    );
    assert_eq!(gh.value(GH_UNRELATED), "https://hooks.example.invalid/x");
}

fn apply_args(id: &str) -> [&str; 6] {
    ["apply", "report.ndjson", "--confirm", id, "--overlap", "0s"]
}

/// Plans, then applies with `--confirm` and no overlap window.
fn apply(e2e: &E2e) -> (String, std::process::Output) {
    let id = e2e.rotation_id();
    let output = e2e.run(&apply_args(&id));
    (id, output)
}

// T1 (AC1)
#[tokio::test(flavor = "multi_thread")]
async fn t1_plan_shows_full_plan_and_changes_nothing() {
    let e2e = E2e::start_with_github().await;
    let aws_before = e2e.model.snapshot();
    let gh_before = e2e.gh().state().values.clone();

    let output = e2e.run(&["plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    assert!(table.contains("Dry run: nothing was changed."), "{table}");
    assert!(table.contains("1 to rotate, 0 skipped"), "{table}");
    assert!(table.contains(&user_arn()), "{table}");
    assert!(table.contains(&fp(&e2e.leaked.secret)), "{table}");
    let row = |consumer_ref: &str| {
        table
            .lines()
            .find(|l| l.contains(consumer_ref) && !l.contains(&format!("{consumer_ref}_")))
            .unwrap_or_else(|| panic!("no row for {consumer_ref}: {table}"))
            .to_owned()
    };
    let sm = row(PAIR_REF);
    assert!(sm.contains("aws-secrets-manager"), "{sm}");
    assert!(sm.contains("by value"), "{sm}");
    assert!(sm.contains("update"), "{sm}");
    for name in [GH_KEY_ID_NAME, GH_SECRET_NAME] {
        let gh = row(&gh_ref(name));
        assert!(gh.contains("github-actions"), "{gh}");
        assert!(gh.contains("by name"), "{gh}");
        assert!(gh.contains("update"), "{gh}");
    }
    assert!(!table.contains(GH_UNRELATED), "{table}");
    assert!(
        table.contains("deactivate the access key (not deleted; rollback can reactivate it)"),
        "{table}"
    );

    let output = e2e.run(&["--json", "plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["rotations"].as_array().unwrap().len(), 1, "{plan}");
    let rotation = &plan["rotations"][0];
    assert_eq!(rotation["provider"], "aws");
    assert_eq!(rotation["validity"], "valid");
    assert_eq!(rotation["scope"]["identity"], user_arn());
    assert!(
        rotation["scope"]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "user: deploy-bot"),
        "{rotation}"
    );
    assert_eq!(rotation["replacement"]["mode"], "automatic");
    let consumers = rotation["consumers"].as_array().unwrap();
    assert_eq!(consumers.len(), 3, "{rotation}");
    let refs: BTreeSet<String> = consumers
        .iter()
        .map(|c| c["consumer_ref"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(refs, consumer_refs());
    for c in consumers {
        assert_eq!(c["updatable"], true, "{c}");
        let expected = match c["consumer_ref"].as_str().unwrap() {
            r if r == PAIR_REF => ("aws-secrets-manager", "by_value", "key_pair"),
            r if r == gh_ref(GH_KEY_ID_NAME) => ("github-actions", "by_name", "key_id"),
            _ => ("github-actions", "by_name", "secret"),
        };
        assert_eq!(
            (
                c["consumer"].as_str().unwrap(),
                c["match_method"].as_str().unwrap(),
                c["holds"].as_str().unwrap(),
            ),
            expected,
            "{c}"
        );
    }
    assert!(rotation["revoke_action"]
        .as_str()
        .unwrap()
        .starts_with("deactivate the access key"));
    assert_eq!(rotation["blockers"], serde_json::json!([]));

    // The Actions consumer really looked, and only read.
    let gh_ops = e2e.gh().state().ops.clone();
    assert!(gh_ops.iter().all(|op| op.starts_with("GET ")), "{gh_ops:?}");
    assert!(
        gh_ops.contains(&format!("GET {REPO_SECRETS}")),
        "{gh_ops:?}"
    );
    // Zero mutating requests reached either model, and both are unchanged.
    e2e.rec.assert_no_mutations().await;
    assert!(mutations(&e2e).await.is_empty());
    assert_eq!(e2e.model.snapshot(), aws_before);
    assert_eq!(e2e.gh().state().values, gh_before);
    assert!(e2e.gh().puts().is_empty());
    assert!(e2e.assert_requests_clean().await.is_empty());
}

// T2 (AC2)
#[tokio::test(flavor = "multi_thread")]
async fn t2_apply_rotates_key_and_both_consumers() {
    let e2e = E2e::start_with_github().await;
    let (_, output) = apply(&e2e);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert!(stdout(&output).contains("1 revoked"), "{}", shown(&output));

    // AWS: a new active key, the old one inactive (not deleted).
    assert_eq!(
        e2e.model.key_ids(),
        [e2e.leaked.id.clone(), e2e.new_id.clone()]
    );
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Active"));
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Inactive"));
    // Secrets Manager holds the new pair.
    e2e.assert_secret_holds(&e2e.new_id, &e2e.new_secret);
    assert_eq!(e2e.model.versions(), 2);
    // The two Actions PUT bodies, opened with the repository's private key,
    // hold the new key id and the new secret.
    let opened = opened_puts(&e2e).await;
    assert_eq!(opened.len(), 2, "{:?}", e2e.gh().put_names());
    assert_eq!(opened[0].0, GH_KEY_ID_NAME);
    assert_eq!(opened[0].1, e2e.new_id);
    assert_eq!(opened[1].0, GH_SECRET_NAME);
    assert!(
        opened[1].1 == e2e.new_secret,
        "secret PUT holds another value"
    );
    assert_actions_hold(&e2e, &e2e.new_id, &e2e.new_secret);

    // Create first, then every consumer write, revoke last.
    let seen = mutations(&e2e).await;
    assert_eq!(seen.len(), 5, "{seen:?}");
    assert_eq!(seen[0], "CreateAccessKey", "{seen:?}");
    assert_eq!(seen[4], "UpdateAccessKey", "{seen:?}");
    let writes: BTreeSet<&str> = seen[1..4].iter().map(String::as_str).collect();
    assert_eq!(
        writes,
        BTreeSet::from([
            "PutSecretValue",
            "PUT AWS_ACCESS_KEY_ID",
            "PUT AWS_SECRET_ACCESS_KEY"
        ]),
        "{seen:?}"
    );
    // The leaked key only proved itself; the new one only verified.
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
async fn t3_audit_is_complete() {
    let e2e = E2e::start_with_github().await;
    let (id, output) = apply(&e2e);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let leaked = fp(&e2e.leaked.secret);
    let new = fp(&e2e.new_secret);
    let audit = e2e.audit();
    let steps: Vec<&str> = audit.iter().map(|e| e["step"].as_str().unwrap()).collect();
    assert_eq!(
        steps,
        ["plan", "create", "update", "update", "update", "verify", "revoke"],
        "{audit:?}"
    );
    for entry in &audit {
        assert_eq!(entry["outcome"], "ok", "{entry}");
        assert_eq!(entry["rotation_id"], id.as_str(), "{entry}");
        assert_eq!(entry["provider"], "aws", "{entry}");
        assert_eq!(entry["fingerprint"], leaked.as_str(), "{entry}");
        assert_eq!(entry["actor"], "e2e@runner", "{entry}");
        assert!(entry["ts"].is_string(), "{entry}");
        if entry["step"] != "plan" {
            assert_eq!(entry["replacement_fingerprint"], new.as_str(), "{entry}");
        }
    }
    // One update per consumer match, covering both consumers.
    let updated: BTreeSet<String> = audit
        .iter()
        .filter(|e| e["step"] == "update")
        .map(|e| e["consumer"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(updated, consumer_refs());
    e2e.assert_requests_clean().await;
}

// T4 (AC4): the record `rotate status` reads.
#[tokio::test(flavor = "multi_thread")]
async fn t4_state_records_revoked() {
    let e2e = E2e::start_with_github().await;
    let (id, output) = apply(&e2e);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let rotation = e2e.rotation(&id);
    assert_eq!(rotation["step"], "revoked", "{rotation}");
    assert_eq!(rotation["provider"], "aws");
    assert_eq!(rotation["fingerprint"], fp(&e2e.leaked.secret).as_str());
    assert_eq!(
        rotation["replacement_fingerprint"],
        fp(&e2e.new_secret).as_str()
    );
    assert!(rotation["revoke_not_before"].is_null(), "{rotation}");
    let consumers = rotation["consumers"].as_array().unwrap();
    let refs: BTreeSet<String> = consumers
        .iter()
        .map(|c| c["consumer_ref"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(refs, consumer_refs(), "{rotation}");
    assert!(
        consumers.iter().all(|c| c["status"] == "updated"),
        "{rotation}"
    );
}

// T4 (AC4): the command itself.
#[tokio::test(flavor = "multi_thread")]
async fn t4_status_all_shows_revoked() {
    let e2e = E2e::start_with_github().await;
    let (id, output) = apply(&e2e);
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
    assert!(row.contains("3/3"), "{row}");
    assert_eq!(e2e.rec.calls().await.len(), calls, "status made a call");
}

// T5 (AC5)
#[tokio::test(flavor = "multi_thread")]
async fn t5_no_secret_anywhere() {
    let e2e = E2e::start_with_github().await;
    // `run` checks stdout, stderr (-vvv, RUST_LOG=trace), the audit log and
    // the state file of every command for the leaked and the new secret
    // access key and the GitHub token.
    let output = e2e.run(&["plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let (_, output) = apply(&e2e);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    // The trace really is at trace level, SDK and HTTP client events
    // included, so the absence checks mean something.
    let err = stderr(&output);
    assert!(err.contains("TRACE"), "stderr is not at trace level");
    assert!(err.contains("aws_smithy"), "no SDK events in the trace");
    assert!(
        err.contains("hyper_util"),
        "no HTTP client events in the trace"
    );
    // Afterwards the report's key is already rotated: nothing to do.
    let output = e2e.run(&["--json", "plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert!(
        stdout(&output).contains("already rotated"),
        "{}",
        shown(&output)
    );

    // Requests: no secret in any header or body except the one
    // PutSecretValue, which holds the new pair; Actions PUTs are sealed.
    assert_eq!(e2e.assert_requests_clean().await, ["new"]);
    // The token was used, and only in the authorization header.
    let requests = e2e.rec.server().received_requests().await.unwrap();
    let bearer = format!("Bearer {}", e2e.github_token);
    assert!(requests.iter().filter(|r| is_github(r)).all(|r| r
        .headers
        .get("authorization")
        .unwrap()
        == bearer.as_str()));

    // The files exist and name both secrets by fingerprint only.
    for name in [".rotate/audit.jsonl", ".rotate/state.json"] {
        let text = std::fs::read_to_string(e2e.file(name)).unwrap();
        assert!(text.contains(&fp(&e2e.leaked.secret)), "{name}");
        assert!(text.contains(&fp(&e2e.new_secret)), "{name}");
    }
}

// T6 (AC6)
#[tokio::test(flavor = "multi_thread")]
async fn t6_actions_put_denied_then_recovered() {
    let e2e = E2e::start_with_github().await;

    // 1. GitHub answers 403 on PUT: apply stops before revoke.
    e2e.gh().state().deny_put = true;
    let (id, output) = apply(&e2e);
    assert_eq!(output.status.code(), Some(1), "{}", shown(&output));
    assert!(
        stdout(&output).contains("stopped before revoke; old secret still valid"),
        "{}",
        shown(&output)
    );
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));
    assert_eq!(e2e.model.count("UpdateAccessKey"), 0, "revoke attempted");
    assert!(e2e.gh().puts().is_empty());
    assert_actions_hold(&e2e, &e2e.leaked.id, &e2e.leaked.secret);
    assert_eq!(e2e.rotation(&id)["step"], "failed");
    let audit = e2e.audit();
    assert!(audit.iter().all(|e| e["step"] != "revoke"), "{audit:?}");
    assert!(audit.iter().any(|e| e["step"] == "update"
        && e["outcome"] == "failed"
        && e["consumer"]
            .as_str()
            .unwrap_or("")
            .starts_with("github-actions:")));

    // 2. The model is fixed. The replacement's secret existed only in the
    // first process, so a re-run cannot write the Actions secret: it marks
    // the rotation needs_rollback without any state-changing call.
    e2e.gh().state().deny_put = false;
    let before = mutations(&e2e).await;
    let output = e2e.run(&apply_args(&id));
    assert_eq!(output.status.code(), Some(1), "{}", shown(&output));
    assert!(
        stdout(&output).contains("rotate rollback"),
        "{}",
        shown(&output)
    );
    assert_eq!(e2e.rotation(&id)["step"], "needs_rollback");
    assert_eq!(mutations(&e2e).await, before, "the re-run changed state");
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));

    // 3. Rollback restores the consumers and deactivates the replacement.
    let output = e2e.run(&["rollback", "report.ndjson", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(e2e.rotation(&id)["step"], "rolled_back");
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Inactive"));
    e2e.assert_secret_holds(&e2e.leaked.id, &e2e.leaked.secret);
    assert_actions_hold(&e2e, &e2e.leaked.id, &e2e.leaked.secret);

    // 4. The inactive replacement still counts toward IAM's two-key limit
    // and rotate never deletes a key, so the operator deletes it (here, in
    // the model). Plan and apply again: a fresh replacement, one PUT per
    // Actions secret, then the old key is revoked.
    e2e.model.state().keys.retain(|k| k.id != e2e.new_id);
    e2e.next_replacement();
    let puts_before = e2e.gh().puts().len();
    let (second, output) = apply(&e2e);
    assert_ne!(second, id, "a rolled-back rotation is not reused");
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Inactive"));
    assert_eq!(e2e.model.status(&e2e.second_id), Some("Active"));
    e2e.assert_secret_holds(&e2e.second_id, &e2e.second_secret);
    let puts = e2e.gh().puts();
    let names: Vec<&str> = puts[puts_before..]
        .iter()
        .map(|(n, _)| n.as_str())
        .collect();
    assert_eq!(names, [GH_KEY_ID_NAME, GH_SECRET_NAME]);
    assert_actions_hold(&e2e, &e2e.second_id, &e2e.second_secret);
    assert_eq!(e2e.rotation(&second)["step"], "revoked");
    let seen = mutations(&e2e).await;
    assert_eq!(seen.last().map(String::as_str), Some("UpdateAccessKey"));
    assert_eq!(e2e.assert_requests_clean().await.last(), Some(&"second"));
}
