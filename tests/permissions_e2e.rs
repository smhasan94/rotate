//! SHA-270: `rotate plan --check-permissions` and the documented IAM policy,
//! end to end against the wiremock models of `tests/e2e/mod.rs`.
//!
//! The AWS model enforces a policy when one is set: any operator call
//! outside it is denied, and `SimulatePrincipalPolicy` answers from it. The
//! GitHub model can deny the Actions public-key read and send classic
//! `x-oauth-scopes`.

mod common;
mod e2e;

use std::collections::BTreeSet;

use serde_json::Value;

use rotate::consumer::github_actions::LACKS_SECRETS_WRITE;
use rotate::provider::aws;

use e2e::*;

const DOC: &str = include_str!("../docs/permissions.md");

/// The actions of the minimal IAM policy in `docs/permissions.md`.
fn documented_policy() -> BTreeSet<String> {
    let start = DOC.find("### Minimal IAM policy").unwrap();
    let rest = &DOC[start..];
    let open = rest.find("```json\n").unwrap() + "```json\n".len();
    let close = rest[open..].find("```").unwrap();
    let policy: Value = serde_json::from_str(&rest[open..open + close]).unwrap();
    let mut actions = BTreeSet::new();
    for statement in policy["Statement"].as_array().unwrap() {
        match &statement["Action"] {
            Value::String(a) => {
                actions.insert(a.clone());
            }
            Value::Array(list) => {
                actions.extend(list.iter().map(|a| a.as_str().unwrap().to_owned()));
            }
            other => panic!("unexpected Action {other}"),
        }
    }
    actions
}

/// Every call signed with the operator's AWS credentials, as the IAM
/// action it needs (`iam:CreateAccessKey`, `secretsmanager:PutSecretValue`).
async fn operator_actions(e2e: &E2e) -> BTreeSet<String> {
    let requests = e2e.rec.server().received_requests().await.unwrap();
    requests
        .iter()
        .filter(|req| !is_github(req) && signer(req).as_deref() == Some(&e2e.operator_id))
        .map(|req| match sm_target(req) {
            Some(op) => format!("secretsmanager:{op}"),
            None => {
                let action = fields(&req.body).get("Action").cloned().unwrap_or_default();
                let service = if action == "GetCallerIdentity" {
                    "sts"
                } else {
                    "iam"
                };
                format!("{service}:{action}")
            }
        })
        .collect()
}

fn plan_json(e2e: &E2e, extra: &[&str]) -> Value {
    let mut args = vec!["--json", "plan", "report.ndjson"];
    args.extend_from_slice(extra);
    let output = e2e.run(&args);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn actions_consumers(plan: &Value) -> Vec<Value> {
    plan["rotations"][0]["consumers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["consumer"] == "github-actions")
        .cloned()
        .collect()
}

// AC1: the documented policy, enforced by the model, is enough for the MVP
// acceptance sequence (plan with the probe, apply, rollback), every
// operator call is in it, and it holds no iam:DeleteAccessKey.
#[tokio::test(flavor = "multi_thread")]
async fn ac1_documented_policy_covers_plan_apply_rollback() {
    let policy = documented_policy();
    assert!(!policy.contains("iam:DeleteAccessKey"));
    let e2e = E2e::start_with_github().await;
    e2e.model.state().policy = Some(policy.clone());

    let output = e2e.run(&["plan", "report.ndjson", "--check-permissions"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    assert!(!table.contains("operator lacks"), "{table}");
    assert!(!table.contains("blockers:"), "{table}");
    // The entry is named by name in rotate.yaml, so it is not simulated.
    assert!(
        stderr(&output).contains("aws-secrets-manager prod/app: named by name"),
        "{}",
        shown(&output)
    );
    let simulations = e2e.model.state().simulations.clone();
    assert_eq!(simulations.len(), 1, "{simulations:?}");
    let (principal, actions, resources) = &simulations[0];
    assert_eq!(principal, &operator_arn());
    assert_eq!(actions, aws::REQUIRED_ACTIONS);
    assert_eq!(resources, &[user_arn()]);
    e2e.rec.assert_no_mutations().await;

    let id = e2e.rotation_id();
    let output = e2e.run(&[
        "apply",
        "report.ndjson",
        "--confirm",
        &id,
        "--overlap",
        "0s",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Inactive"));
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Active"));

    let output = e2e.run(&["rollback", "report.ndjson", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Inactive"));

    let used = operator_actions(&e2e).await;
    let outside: Vec<&String> = used.difference(&policy).collect();
    assert!(outside.is_empty(), "calls outside the policy: {outside:?}");
    for needed in [
        "iam:GetAccessKeyLastUsed",
        "iam:GetUser",
        "iam:ListAccessKeys",
        "iam:CreateAccessKey",
        "iam:UpdateAccessKey",
        "iam:SimulatePrincipalPolicy",
        "sts:GetCallerIdentity",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
    ] {
        assert!(
            used.contains(needed),
            "{needed} was not exercised: {used:?}"
        );
    }
    assert!(!used.contains("iam:DeleteAccessKey"));
    e2e.assert_requests_clean().await;
}

// AC1: an action missing from the operator's policy is a blocker, and the
// probe changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn ac1_missing_action_is_a_blocker() {
    let e2e = E2e::start_with_github().await;
    let mut policy = documented_policy();
    policy.remove("iam:CreateAccessKey");
    e2e.model.state().policy = Some(policy);

    let output = e2e.run(&["plan", "report.ndjson", "--check-permissions"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let expected = format!(
        "operator lacks iam:CreateAccessKey on {} (IAM policy simulation)",
        user_arn()
    );
    assert!(stdout(&output).contains(&expected), "{}", shown(&output));

    let plan = plan_json(&e2e, &["--check-permissions"]);
    let blockers = plan["rotations"][0]["blockers"].as_array().unwrap();
    assert_eq!(blockers, &[Value::String(expected)], "{plan}");
    // Without the flag there is no probe and no permission blocker.
    let calls = e2e.model.state().simulations.len();
    let plan = plan_json(&e2e, &[]);
    assert_eq!(plan["rotations"][0]["blockers"], serde_json::json!([]));
    assert_eq!(e2e.model.state().simulations.len(), calls);
    e2e.rec.assert_no_mutations().await;
}

// A simulation the operator may not run is a warning, never a blocker.
#[tokio::test(flavor = "multi_thread")]
async fn simulation_denied_is_a_warning() {
    let e2e = E2e::start_with_github().await;
    let output = e2e.run(&["plan", "report.ndjson", "--check-permissions"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert!(
        stderr(&output)
            .contains("warning: AWS permissions not checked: iam:SimulatePrincipalPolicy"),
        "{}",
        shown(&output)
    );
    assert!(!stdout(&output).contains("blockers:"), "{}", shown(&output));
    e2e.rec.assert_no_mutations().await;
}

// T2 (AC2): the public-key read is refused, so both Actions matches are
// not updatable with the reason, and no mutating call is made.
#[tokio::test(flavor = "multi_thread")]
async fn t2_token_without_secrets_write_is_not_updatable() {
    let e2e = E2e::start_with_github().await;
    e2e.gh().state().deny_public_key = true;

    // Without the flag: no probe, both matches updatable.
    let plan = plan_json(&e2e, &[]);
    assert!(actions_consumers(&plan)
        .iter()
        .all(|c| c["updatable"] == true));
    let probe = format!("GET {REPO_SECRETS}/public-key");
    assert!(!e2e.gh().state().ops.contains(&probe));

    let output = e2e.run(&["plan", "report.ndjson", "--check-permissions"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    for name in [GH_KEY_ID_NAME, GH_SECRET_NAME] {
        let row = table
            .lines()
            .find(|l| l.contains(&format!("github-actions:{REPO}:{name}")))
            .unwrap_or_else(|| panic!("no row for {name}: {table}"));
        assert!(
            row.contains(&format!("cannot update: {LACKS_SECRETS_WRITE}")),
            "{row}"
        );
    }
    assert!(
        table
            .contains("2 consumers cannot be updated; apply will refuse to revoke without --force"),
        "{table}"
    );
    // The Secrets Manager match is untouched.
    assert!(
        table
            .lines()
            .any(|l| l.contains(PAIR_REF) && l.trim_end().ends_with("update")),
        "{table}"
    );

    let plan = plan_json(&e2e, &["--check-permissions"]);
    let consumers = actions_consumers(&plan);
    assert_eq!(consumers.len(), 2, "{plan}");
    for c in &consumers {
        assert_eq!(c["updatable"], false, "{c}");
        assert_eq!(c["reason"], LACKS_SECRETS_WRITE, "{c}");
    }
    // One probe per target per run, and only reads.
    let ops = e2e.gh().state().ops.clone();
    assert_eq!(ops.iter().filter(|o| **o == probe).count(), 2, "{ops:?}");
    assert!(ops.iter().all(|o| o.starts_with("GET ")), "{ops:?}");
    e2e.rec.assert_no_mutations().await;
    assert!(e2e.gh().puts().is_empty());
}

// T2 (AC2): a classic token is judged by its scopes.
#[tokio::test(flavor = "multi_thread")]
async fn t2_classic_token_scopes() {
    let e2e = E2e::start_with_github().await;
    e2e.gh().state().scopes = Some("workflow, read:org".into());
    let plan = plan_json(&e2e, &["--check-permissions"]);
    for c in actions_consumers(&plan) {
        assert_eq!(c["reason"], LACKS_SECRETS_WRITE, "{c}");
    }

    e2e.gh().state().scopes = Some("repo, workflow".into());
    let output = e2e.run(&["--json", "plan", "report.ndjson", "--check-permissions"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    for c in actions_consumers(&plan) {
        assert_eq!(c["updatable"], true, "{c}");
    }
    // A classic token with the scope needs no fine-grained warning.
    assert!(
        !stderr(&output).contains("fine-grained"),
        "{}",
        shown(&output)
    );
    e2e.rec.assert_no_mutations().await;
}

// T4 (AC2): T2 with a canary operator token in GITHUB_TOKEN. `E2e::run`
// fails on the token in stdout, stderr (at -vvv with RUST_LOG=trace), the
// audit log or the state file; this checks it was really used and
// repeats the checks explicitly.
#[tokio::test(flavor = "multi_thread")]
async fn t4_canary_token_never_leaks() {
    let e2e = E2e::start_with_github().await;
    *e2e.token_var.lock().unwrap() = "GITHUB_TOKEN";
    e2e.gh().state().deny_public_key = true;

    let output = e2e.run(&["plan", "report.ndjson", "--check-permissions"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert!(
        stdout(&output).contains(LACKS_SECRETS_WRITE),
        "{}",
        shown(&output)
    );
    let err = stderr(&output);
    assert!(err.contains("TRACE"), "stderr is not at trace level");
    for (place, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert!(
            !String::from_utf8_lossy(bytes).contains(&e2e.github_token),
            "{place} contains the GitHub token"
        );
    }
    for name in [".rotate/audit.jsonl", ".rotate/state.json"] {
        if let Ok(text) = std::fs::read_to_string(e2e.file(name)) {
            assert!(!text.contains(&e2e.github_token), "{name} contains it");
        }
    }
    // The token from GITHUB_TOKEN signed the probe, in its header only.
    let requests = e2e.rec.server().received_requests().await.unwrap();
    let bearer = format!("Bearer {}", e2e.github_token);
    let probes: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().ends_with("/public-key"))
        .collect();
    assert_eq!(probes.len(), 1);
    assert_eq!(
        probes[0].headers.get("authorization").unwrap(),
        bearer.as_str()
    );
    e2e.assert_requests_clean().await;
    e2e.rec.assert_no_mutations().await;
}
