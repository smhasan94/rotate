//! GitHub token provider (SHA-260) against a wiremock GitHub API.
//!
//! Every GitHub read is a GET; the one state-changing call is `POST
//! /credentials/revoke`, so the recorder's default (POST is mutating) is
//! exactly right. Tokens are built at runtime with unique tags so no
//! literal matches a secret scanner and every test can search for its own
//! values.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

use rotate::apply::{self, Executor, ReplacementSource, RunResult, ScriptedPrompt, Terminal};
use rotate::assess::{self, AssessOptions};
use rotate::audit::{AuditLog, AuditStep, Outcome as AuditOutcome};
use rotate::config::ConsumersConfig;
use rotate::conformance::{provider_suite, MutationProbe, Outcome, ProviderFixture};
use rotate::consumer::mock::MockConsumer;
use rotate::consumer::Holds;
use rotate::consumer::{ConsumerMatch, ConsumerRegistry};
use rotate::finding::{Finding, SourceLocation};
use rotate::plan;
use rotate::provider::github::{
    GithubProvider, FINE_GRAINED_NOTE, INSTALLATION_UNSUPPORTED, REVOKE_BATCH,
};
use rotate::provider::mock::MockProvider;
use rotate::provider::{
    Credential, Identity, Provider, ProviderError, ProviderRegistry, ReplacementMode,
    RestoreOutcome, Revoked, Validity,
};
use rotate::secret::SecretValue;
use rotate::state::{ConsumerState, ConsumerStatus, StateStore, Step};

use common::CallRecorder;

/// A token of `prefix` (split so no literal matches a scanner) carrying
/// `tag`, padded to a realistic length.
fn token(prefix: [&str; 2], tag: &str) -> String {
    let body_len = if prefix.concat() == "github_pat_" {
        82
    } else {
        36
    };
    let pad = "Zx9".repeat(body_len);
    format!("{}{tag}{}", prefix.concat(), &pad[..body_len - tag.len()])
}

fn classic(tag: &str) -> String {
    token(["gh", "p_"], tag)
}

fn fine_grained(tag: &str) -> String {
    token(["github", "_pat_"], tag)
}

fn cred(value: &str) -> Credential {
    Credential::Token(SecretValue::from(value))
}

fn provider(rec: &CallRecorder) -> GithubProvider {
    GithubProvider::new(&rec.uri())
}

fn bearer(value: &str) -> String {
    format!("Bearer {value}")
}

/// `GET /user` signed with `value` answers `login`, with `x-oauth-scopes`
/// when given.
async fn mount_user(rec: &CallRecorder, value: &str, login: &str, scopes: Option<&str>) {
    let mut response =
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "login": login, "id": 1 }));
    if let Some(scopes) = scopes {
        response = response.insert_header("x-oauth-scopes", scopes);
    }
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", bearer(value).as_str()))
        .respond_with(response)
        .with_priority(2)
        .mount(rec.server())
        .await;
}

async fn mount_orgs(rec: &CallRecorder, value: &str, orgs: &[&str]) {
    let body: Vec<serde_json::Value> = orgs
        .iter()
        .map(|o| serde_json::json!({ "login": o }))
        .collect();
    Mock::given(method("GET"))
        .and(path("/user/orgs"))
        .and(header("authorization", bearer(value).as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// `GET /user` signed with `value` answers 401 Bad credentials.
async fn mount_bad_credentials(rec: &CallRecorder, value: &str) {
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", bearer(value).as_str()))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "message": "Bad credentials" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
}

async fn mount_revoke(rec: &CallRecorder, status: u16) {
    Mock::given(method("POST"))
        .and(path("/credentials/revoke"))
        .respond_with(ResponseTemplate::new(status).set_body_json(serde_json::json!({})))
        .with_priority(3)
        .mount(rec.server())
        .await;
}

/// Every `POST /credentials/revoke` received, as parsed JSON plus whether
/// it carried an `Authorization` header.
async fn revokes(rec: &CallRecorder) -> Vec<(serde_json::Value, bool)> {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == "/credentials/revoke")
        .map(|r| {
            (
                serde_json::from_slice(&r.body).expect("revoke body is JSON"),
                r.headers.contains_key("authorization"),
            )
        })
        .collect()
}

fn fast_opts() -> AssessOptions {
    AssessOptions {
        concurrency: 2,
        attempts: 2,
        base_delay: Duration::from_millis(1),
        force_provider: None,
    }
}

fn registry(p: GithubProvider) -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(p));
    registry
}

fn finding(value: &str) -> Finding {
    Finding::new(
        SecretValue::from(value),
        "Github",
        SourceLocation::file(".github/workflows/ci.yml"),
    )
}

// T2 (AC2)
#[tokio::test]
async fn check_valid_and_scope_classic() {
    let rec = CallRecorder::start().await;
    let leaked = classic("t2Valid");
    mount_user(&rec, &leaked, "octocat", Some("repo, workflow")).await;
    mount_orgs(&rec, &leaked, &["acme", "octo-org"]).await;
    let p = provider(&rec);

    assert_eq!(
        p.check_valid(&cred(&leaked)).await.unwrap(),
        Validity::Valid
    );
    let scope = p.describe_scope(&cred(&leaked)).await.unwrap();
    assert_eq!(scope.identity, Identity("octocat".into()));
    assert_eq!(
        scope.lines,
        [
            "login: octocat",
            "type: classic",
            "scopes: repo, workflow",
            "orgs: acme, octo-org",
        ]
    );
    rec.assert_no_mutations().await;
}

#[tokio::test]
async fn scope_reports_expiry_and_unreadable_orgs() {
    let rec = CallRecorder::start().await;
    let leaked = classic("expires");
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "login": "octocat" }))
                .insert_header("x-oauth-scopes", "")
                .insert_header(
                    "github-authentication-token-expiration",
                    "2026-12-01 00:00:00 UTC",
                ),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/user/orgs"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(serde_json::json!({ "message": "Resource not accessible" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let scope = provider(&rec).describe_scope(&cred(&leaked)).await.unwrap();
    assert!(scope.lines.contains(&"scopes: none".to_owned()));
    assert!(scope
        .lines
        .contains(&"expires: 2026-12-01 00:00:00 UTC".to_owned()));
    assert!(
        scope
            .lines
            .iter()
            .any(|l| l.starts_with("orgs: not readable") && l.contains("403")),
        "{:?}",
        scope.lines
    );
}

// T3 (AC3)
#[tokio::test]
async fn check_valid_401_is_invalid() {
    let rec = CallRecorder::start().await;
    let leaked = classic("t3Revkd");
    mount_bad_credentials(&rec, &leaked).await;
    assert_eq!(
        provider(&rec).check_valid(&cred(&leaked)).await.unwrap(),
        Validity::Invalid
    );
    rec.assert_no_mutations().await;
}

#[tokio::test]
async fn check_valid_other_status_is_unknown_and_5xx_retryable() {
    let rec = CallRecorder::start().await;
    let forbidden = classic("t3Forbd");
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", bearer(&forbidden).as_str()))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(serde_json::json!({ "message": "SSO" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let busy = classic("t3Busy0");
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", bearer(&busy).as_str()))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(2)
        .mount(rec.server())
        .await;
    let limited = classic("t3Limit");
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", bearer(&limited).as_str()))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
        .with_priority(2)
        .mount(rec.server())
        .await;
    let p = provider(&rec);
    match p.check_valid(&cred(&forbidden)).await.unwrap() {
        Validity::Unknown { reason } => {
            assert!(
                reason.contains("GET /user") && reason.contains("403"),
                "{reason}"
            )
        }
        other => panic!("expected unknown, got {other:?}"),
    }
    assert!(p
        .check_valid(&cred(&busy))
        .await
        .unwrap_err()
        .is_retryable());
    assert_eq!(
        p.check_valid(&cred(&limited)).await.unwrap_err(),
        ProviderError::RateLimited {
            retry_after: Some(Duration::from_secs(7))
        }
    );
}

// T4 (AC4)
#[tokio::test]
async fn describe_scope_fine_grained() {
    let rec = CallRecorder::start().await;
    let leaked = fine_grained("t4Fine");
    mount_user(&rec, &leaked, "octocat", None).await;
    mount_orgs(&rec, &leaked, &[]).await;
    let scope = provider(&rec).describe_scope(&cred(&leaked)).await.unwrap();
    assert!(scope.lines.contains(&"type: fine-grained".to_owned()));
    assert!(scope.lines.contains(&FINE_GRAINED_NOTE.to_owned()));
    assert!(!scope.lines.iter().any(|l| l.starts_with("scopes:")));
}

#[tokio::test]
async fn installation_token_checked_but_never_revoked() {
    let rec = CallRecorder::start().await;
    let leaked = token(["gh", "s_"], "instal");
    Mock::given(method("GET"))
        .and(path("/installation/repositories"))
        .and(header("authorization", bearer(&leaked).as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "total_count": 3, "repositories": [] })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let p = provider(&rec);
    assert_eq!(
        p.check_valid(&cred(&leaked)).await.unwrap(),
        Validity::Valid
    );
    let scope = p.describe_scope(&cred(&leaked)).await.unwrap();
    assert!(scope.lines.contains(&"repositories: 3".to_owned()));
    assert!(scope.lines.iter().any(|l| l.starts_with("warning: ")));
    assert!(p
        .manual_instructions(&scope)
        .starts_with("unsupported: regenerate via the app"));
    assert!(matches!(
        p.revoke(&cred(&leaked)).await,
        Err(ProviderError::Unsupported(_))
    ));
    rec.assert_no_mutations().await;
}

// T5 (AC5)
#[tokio::test]
async fn revoke_posts_token_without_authorization() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked = classic("t5Revok");
    let revoked = provider(&rec).revoke(&cred(&leaked)).await.unwrap();
    assert_eq!(revoked.restore_ref, None);

    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1);
    let (body, authorized) = &sent[0];
    assert_eq!(body, &serde_json::json!({ "credentials": [leaked] }));
    assert!(
        !authorized,
        "the revocation API must be called without auth"
    );
    let calls = rec.calls().await;
    assert_eq!(calls.len(), 1, "revoke makes exactly one call: {calls:?}");
}

#[tokio::test]
async fn revoke_many_batches_by_a_thousand() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let values: Vec<SecretValue> = (0..REVOKE_BATCH + 1)
        .map(|i| SecretValue::from(classic(&format!("b{i:05}"))))
        .collect();
    let refs: Vec<&SecretValue> = values.iter().collect();
    provider(&rec).revoke_many(&refs).await.unwrap();
    let sent = revokes(&rec).await;
    let sizes: Vec<usize> = sent
        .iter()
        .map(|(body, _)| body["credentials"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [REVOKE_BATCH, 1]);
}

// T6 (AC6)
#[tokio::test]
async fn revoke_twice_already_revoked_is_ok() {
    let rec = CallRecorder::start().await;
    Mock::given(method("POST"))
        .and(path("/credentials/revoke"))
        .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({})))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(rec.server())
        .await;
    Mock::given(method("POST"))
        .and(path("/credentials/revoke"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(serde_json::json!({ "message": "Credential already revoked" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let p = provider(&rec);
    let leaked = cred(&classic("t6Twice"));
    p.revoke(&leaked).await.unwrap();
    p.revoke(&leaked).await.unwrap();
    assert_eq!(revokes(&rec).await.len(), 2);
}

#[tokio::test]
async fn revoke_repeat_202_ok_and_other_422_fails() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let p = provider(&rec);
    let leaked = cred(&classic("t6Again"));
    p.revoke(&leaked).await.unwrap();
    p.revoke(&leaked).await.unwrap();

    let rec = CallRecorder::start().await;
    Mock::given(method("POST"))
        .and(path("/credentials/revoke"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_json(serde_json::json!({ "message": "Validation Failed" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let err = provider(&rec).revoke(&leaked).await.unwrap_err();
    assert_eq!(
        err,
        ProviderError::Permanent(
            "POST /credentials/revoke: GitHub returned 422: Validation Failed".into()
        )
    );
}

#[tokio::test]
async fn revoke_rate_limited_is_retryable() {
    let rec = CallRecorder::start().await;
    Mock::given(method("POST"))
        .and(path("/credentials/revoke"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-remaining", "0")
                .set_body_json(serde_json::json!({ "message": "API rate limit exceeded" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let err = provider(&rec)
        .revoke(&cred(&classic("t6Limit")))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::RateLimited { .. }), "{err:?}");
}

// T7 (AC7)
#[tokio::test]
async fn verify_other_login_names_both() {
    let rec = CallRecorder::start().await;
    let replacement = classic("t7NewTk");
    mount_user(&rec, &replacement, "mallory", Some("repo")).await;
    let p = provider(&rec);
    let err = p
        .verify(&cred(&replacement), &Identity("octocat".into()))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("mallory"), "{text}");
    assert!(text.contains("octocat"), "{text}");
    // Logins compare case-insensitively.
    p.verify(&cred(&replacement), &Identity("Mallory".into()))
        .await
        .unwrap();
    rec.assert_no_mutations().await;
}

#[tokio::test]
async fn verify_rejected_replacement_fails() {
    let rec = CallRecorder::start().await;
    let replacement = classic("t7Reject");
    mount_bad_credentials(&rec, &replacement).await;
    let err = provider(&rec)
        .verify(&cred(&replacement), &Identity("octocat".into()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");
}

// T8 (AC8)
#[tokio::test]
async fn restore_unsupported_without_calls() {
    let rec = CallRecorder::start().await;
    let p = provider(&rec);
    assert_eq!(
        p.restore("anything").await.unwrap(),
        RestoreOutcome::Unsupported
    );
    assert_eq!(p.replacement_mode(), ReplacementMode::Manual);
    assert!(matches!(
        p.create_replacement(&cred(&classic("t8Creat"))).await,
        Err(ProviderError::Unsupported(_))
    ));
    assert!(
        rec.calls().await.is_empty(),
        "restore and create made calls"
    );
}

/// Writes what the executor prints, for assertions.
#[derive(Default)]
struct Term {
    out: String,
    err: String,
}

impl Terminal for Term {
    fn stdout(&mut self, text: &str) {
        self.out.push_str(text);
    }

    fn stderr(&mut self, text: &str) {
        self.err.push_str(text);
    }
}

/// One leaked token, one consumer holding it, planned with ids assigned.
struct Pipeline {
    dir: tempfile::TempDir,
    providers: ProviderRegistry,
    consumers: ConsumerRegistry,
    gha: Arc<MockConsumer>,
    store: StateStore,
    audit: AuditLog,
    plan: plan::Plan,
}

async fn pipeline(rec: &CallRecorder, leaked: &str) -> Pipeline {
    let dir = tempfile::tempdir().unwrap();
    let providers = registry(provider(rec));
    let gha = Arc::new(MockConsumer::new("github-actions").matching(
        SecretValue::from(leaked).fingerprint(),
        ConsumerMatch::by_value("gha:acme/app:GH_TOKEN"),
    ));
    let mut consumers = ConsumerRegistry::new();
    consumers.register(gha.clone());
    let assessed = assess::assess(vec![finding(leaked)], &providers, &fast_opts()).await;
    let mut built = plan::build(
        assessed,
        &providers,
        &consumers,
        "0s".parse().unwrap(),
        &ConsumersConfig::default(),
    )
    .await;
    let mut store = StateStore::open(dir.path().join("state.json")).unwrap();
    plan::assign_ids(&mut built, &mut store).unwrap();
    let audit = AuditLog::open_as(dir.path().join("audit.jsonl"), "tester@host").unwrap();
    assert_eq!(built.rotations.len(), 1, "{}", plan::render_table(&built));
    Pipeline {
        dir,
        providers,
        consumers,
        gha,
        store,
        audit,
        plan: built,
    }
}

// The plan is a dry run: assess, build and render make no state-changing
// call to GitHub (NFR3).
#[tokio::test]
async fn plan_makes_no_state_changing_calls() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked = classic("planDry");
    mount_user(&rec, &leaked, "octocat", Some("repo, workflow")).await;
    mount_orgs(&rec, &leaked, &["acme"]).await;
    let p = pipeline(&rec, &leaked).await;
    let table = plan::render_table(&p.plan);
    let json = plan::render_json(&p.plan);
    assert!(table.contains("octocat"), "{table}");
    assert!(table.contains("revoke the token"), "{table}");
    assert!(json.contains("\"mode\": \"manual\"") || json.contains("\"mode\":\"manual\""));
    let calls = rec.calls().await;
    assert!(
        calls.iter().any(|c| c.path == "/user"),
        "plan checked validity: {calls:?}"
    );
    rec.assert_no_mutations().await;
    assert!(revokes(&rec).await.is_empty());
}

// T7 (AC7) through the executor: a replacement owned by someone else is
// rejected at create, nothing is updated and nothing is revoked.
#[tokio::test]
async fn executor_wrong_login_never_revokes() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked = classic("exLeakd");
    let replacement = classic("exOther");
    mount_user(&rec, &leaked, "octocat", Some("repo")).await;
    mount_orgs(&rec, &leaked, &[]).await;
    mount_user(&rec, &replacement, "mallory", Some("repo")).await;
    let mut p = pipeline(&rec, &leaked).await;
    let mut term = Term::default();

    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .with_manual(
            ReplacementSource::Supplied(Some(SecretValue::from(replacement.as_str()))),
            &mut term,
        )
        .run(&p.plan.rotations[0])
        .await;
    match &outcome.result {
        RunResult::Failed { error, .. } => {
            assert!(error.to_string().contains("mallory"), "{error}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
    assert!(revokes(&rec).await.is_empty(), "revoke was called");
    assert_eq!(
        p.gha.current("gha:acme/app:GH_TOKEN"),
        Some(SecretValue::from(leaked.as_str()).fingerprint()),
        "the consumer still holds the old token"
    );
}

/// A TRACE-level capture installed as this binary's global subscriber
/// (see the AWS provider tests for why it is global).
fn trace_capture() -> common::LogCapture {
    static CAPTURE: std::sync::OnceLock<common::LogCapture> = std::sync::OnceLock::new();
    CAPTURE
        .get_or_init(|| {
            let capture = common::LogCapture::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(capture.clone())
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other global subscriber in this test binary");
            capture
        })
        .clone()
}

// T10 (AC2, AC5): a full plan and apply. The leaked and the new token
// appear in no table, JSON, summary, terminal text, log, audit entry or
// state file. On the wire the leaked token is only in the revoke body and
// in the Authorization header of the read-only checks; the new token only
// in the Authorization header of `GET /user`.
#[tokio::test]
async fn token_never_in_output_logs_audit_or_state() {
    let capture = trace_capture();
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked = classic("t10Leak");
    let replacement = classic("t10NewT");
    mount_user(&rec, &leaked, "octocat", Some("repo, workflow")).await;
    mount_orgs(&rec, &leaked, &["acme"]).await;
    mount_user(&rec, &replacement, "octocat", Some("repo, workflow")).await;

    let mut p = pipeline(&rec, &leaked).await;
    let table = plan::render_table(&p.plan);
    let plan_json = plan::render_json(&p.plan);
    let mut term = Term::default();
    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .with_manual(
            ReplacementSource::Supplied(Some(SecretValue::from(replacement.as_str()))),
            &mut term,
        )
        .run(&p.plan.rotations[0])
        .await;
    assert!(
        matches!(outcome.result, RunResult::Revoked),
        "{:?}",
        outcome.result
    );
    assert_eq!(
        p.gha.current("gha:acme/app:GH_TOKEN"),
        Some(SecretValue::from(replacement.as_str()).fingerprint())
    );
    assert!(
        term.out.contains("with these scopes: repo, workflow"),
        "{}",
        term.out
    );
    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, serde_json::json!({ "credentials": [leaked] }));
    assert!(!sent[0].1);

    let summary = apply::render_summary(std::slice::from_ref(&outcome));
    let audit = std::fs::read_to_string(p.dir.path().join("audit.jsonl")).unwrap();
    let state = std::fs::read_to_string(p.dir.path().join("state.json")).unwrap();
    assert!(audit.contains(
        &SecretValue::from(replacement.as_str())
            .fingerprint()
            .to_string()
    ));
    let logs = capture.contents();
    assert!(!logs.is_empty(), "the TRACE capture saw nothing");
    for value in [&leaked, &replacement] {
        for (label, text) in [
            ("plan table", &table),
            ("plan json", &plan_json),
            ("summary", &summary),
            ("stdout", &term.out),
            ("stderr", &term.err),
            ("audit log", &audit),
            ("state file", &state),
            ("logs", &logs),
            ("outcome", &format!("{outcome:?}")),
        ] {
            assert!(!text.contains(value.as_str()), "token in {label}");
        }
    }

    for req in rec.server().received_requests().await.unwrap() {
        let target = format!("{} {}", req.method, req.url.path());
        let body = String::from_utf8_lossy(&req.body);
        let auth = req
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_owned())
            .unwrap_or_default();
        for (name, value) in &req.headers {
            if name.as_str() != "authorization" {
                let value = value.to_str().unwrap_or("");
                assert!(!value.contains(&leaked) && !value.contains(&replacement));
            }
        }
        if body.contains(&leaked) {
            assert_eq!(target, "POST /credentials/revoke", "leaked token in a body");
        }
        assert!(!body.contains(&replacement), "new token in {target} body");
        if auth.contains(&leaked) {
            assert!(
                target == "GET /user" || target == "GET /user/orgs",
                "leaked token signed {target}"
            );
        }
        if auth.contains(&replacement) {
            assert_eq!(target, "GET /user", "new token signed {target}");
        }
    }
}

/// `GET /installation/repositories` signed with `value` answers 3 repos.
async fn mount_installation(rec: &CallRecorder, value: &str) {
    Mock::given(method("GET"))
        .and(path("/installation/repositories"))
        .and(header("authorization", bearer(value).as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "total_count": 3, "repositories": [] })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
}

// SHA-289 T9 (AC9): plan shows the manual revoke row and blocker for an
// installation token, with zero state-changing calls.
#[tokio::test]
async fn installation_token_plan_shows_manual_revoke() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked = token(["gh", "s_"], "t9Inst");
    mount_installation(&rec, &leaked).await;
    let p = pipeline(&rec, &leaked).await;
    let rotation = &p.plan.rotations[0];
    assert_eq!(rotation.revoke_action, INSTALLATION_UNSUPPORTED);
    assert!(
        rotation
            .blockers
            .contains(&plan::MANUAL_REVOKE_BLOCKER.to_owned()),
        "{:?}",
        rotation.blockers
    );
    let table = plan::render_table(&p.plan);
    assert!(table.contains(plan::MANUAL_REVOKE_BLOCKER), "{table}");
    let json = plan::render_json(&p.plan);
    assert!(json.contains("regenerate via the app"), "{json}");
    assert!(!table.contains(&leaked) && !json.contains(&leaked));
    rec.assert_no_mutations().await;
    assert!(revokes(&rec).await.is_empty());
}

// SHA-289 T2 (AC2), T11 (AC2): apply reaching revoke for an installation
// token (state seeded at verified: no replacement for one can be verified)
// records revoke_manual with the provider's text and never posts to
// /credentials/revoke. The token is in no output, log, audit entry or
// state file.
#[tokio::test]
async fn installation_token_apply_stops_at_revoke_manual() {
    let capture = trace_capture();
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked = token(["gh", "s_"], "t2Inst");
    mount_installation(&rec, &leaked).await;
    let mut p = pipeline(&rec, &leaked).await;
    let id = p.plan.rotations[0].rotation_id.clone();
    let mut record = p.store.get(&id).unwrap().clone();
    record.step = Step::Verified;
    record.replacement_ref = Some(apply::MANUAL_REF.into());
    record.replacement_fingerprint = Some(SecretValue::from("replacement-t2").fingerprint());
    record.consumers = vec![ConsumerState {
        consumer: "github-actions".into(),
        consumer_ref: "gha:acme/app:GH_TOKEN".into(),
        status: ConsumerStatus::Updated,
        holds: Some(Holds::Secret),
    }];
    p.store.upsert(record).unwrap();
    let mut term = Term::default();

    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .with_manual(ReplacementSource::Supplied(None), &mut term)
        .run(&p.plan.rotations[0])
        .await;
    match &outcome.result {
        RunResult::RevokeManual { instructions } => {
            assert_eq!(instructions.as_str(), INSTALLATION_UNSUPPORTED);
        }
        other => panic!("expected revoke by hand, got {other:?}"),
    }
    assert_eq!(
        apply::run_status(std::slice::from_ref(&outcome)),
        apply::RunStatus::RevokeManual
    );
    let stored = p.store.get(&id).unwrap();
    assert_eq!(stored.step, Step::RevokeManual);
    assert_eq!(
        stored.revoke_instructions.as_deref(),
        Some(INSTALLATION_UNSUPPORTED)
    );
    assert!(revokes(&rec).await.is_empty(), "revoke was posted");
    rec.assert_no_mutations().await;

    let summary = apply::render_summary(std::slice::from_ref(&outcome));
    assert!(
        summary.contains(&format!("{id}: revoke by hand: regenerate via the app.")),
        "{summary}"
    );
    let audit = std::fs::read_to_string(p.dir.path().join("audit.jsonl")).unwrap();
    let state = std::fs::read_to_string(p.dir.path().join("state.json")).unwrap();
    assert!(state.contains("revoke_manual"), "{state}");
    let logs = capture.contents();
    for (label, text) in [
        ("summary", &summary),
        ("stdout", &term.out),
        ("stderr", &term.err),
        ("audit log", &audit),
        ("state file", &state),
        ("logs", &logs),
        ("outcome", &format!("{outcome:?}")),
    ] {
        assert!(!text.contains(leaked.as_str()), "token in {label}");
    }
}

// ---------------------------------------------------------------------------
// SHA-286: every GitHub token of a run revoked in one request per 1000.
// ---------------------------------------------------------------------------

/// Several leaked values planned in one registry: the GitHub provider plus
/// `extra`, one `github-actions` consumer holding every value (ref
/// `gha:acme/app<i>:GH_TOKEN`), overlap `0s`, ids assigned.
async fn pipeline_many(
    rec: &CallRecorder,
    leaked: &[&str],
    extra: Vec<Arc<dyn Provider>>,
) -> Pipeline {
    let dir = tempfile::tempdir().unwrap();
    let mut providers = registry(provider(rec));
    for p in extra {
        providers.register(p);
    }
    let mut gha = MockConsumer::new("github-actions");
    for (i, value) in leaked.iter().enumerate() {
        gha = gha.matching(
            SecretValue::from(*value).fingerprint(),
            ConsumerMatch::by_value(format!("gha:acme/app{i}:GH_TOKEN")),
        );
    }
    let gha = Arc::new(gha);
    let mut consumers = ConsumerRegistry::new();
    consumers.register(gha.clone());
    // A detector hint names a provider, so a value for `extra` gets none.
    let findings = leaked
        .iter()
        .map(|v| match v.starts_with("mock_") {
            true => Finding::new(SecretValue::from(*v), "Mock", SourceLocation::file("a.env")),
            false => finding(v),
        })
        .collect();
    let assessed = assess::assess(findings, &providers, &fast_opts()).await;
    let mut built = plan::build(
        assessed,
        &providers,
        &consumers,
        "0s".parse().unwrap(),
        &ConsumersConfig::default(),
    )
    .await;
    let mut store = StateStore::open(dir.path().join("state.json")).unwrap();
    plan::assign_ids(&mut built, &mut store).unwrap();
    let audit = AuditLog::open_as(dir.path().join("audit.jsonl"), "tester@host").unwrap();
    assert_eq!(
        built.rotations.len(),
        leaked.len(),
        "{}",
        plan::render_table(&built)
    );
    Pipeline {
        dir,
        providers,
        consumers,
        gha,
        store,
        audit,
        plan: built,
    }
}

impl Pipeline {
    /// The planned rotation of `value`, by fingerprint.
    fn rotation(&self, value: &str) -> &plan::PlannedRotation {
        let fp = SecretValue::from(value).fingerprint();
        self.plan
            .rotations
            .iter()
            .find(|r| r.fingerprint == fp)
            .expect("planned")
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap()
    }

    fn state_text(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("state.json")).unwrap()
    }

    fn audit_entries(&self) -> Vec<rotate::audit::AuditEntry> {
        rotate::audit::read_all(&self.dir.path().join("audit.jsonl"))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
}

/// The planned rotations of `values` in `plan`, in that order.
fn pick<'p>(plan: &'p plan::Plan, values: &[&str]) -> Vec<&'p plan::PlannedRotation> {
    values
        .iter()
        .map(|v| {
            let fp = SecretValue::from(*v).fingerprint();
            plan.rotations
                .iter()
                .find(|r| r.fingerprint == fp)
                .expect("planned")
        })
        .collect()
}

/// Moves `value`'s record to `verified` with a pasted replacement and its
/// one consumer updated, as an earlier run would have left it.
fn seed_verified(p: &mut Pipeline, value: &str) -> String {
    let rotation = p.rotation(value).clone();
    let mut record = p.store.get(&rotation.rotation_id).unwrap().clone();
    record.step = Step::Verified;
    record.replacement_ref = Some(apply::MANUAL_REF.into());
    record.replacement_fingerprint =
        Some(SecretValue::from(format!("{value}-replacement")).fingerprint());
    record.consumers = rotation
        .consumers
        .iter()
        .map(|c| ConsumerState {
            consumer: c.consumer.into(),
            consumer_ref: c.found.consumer_ref.clone(),
            status: ConsumerStatus::Updated,
            holds: Some(Holds::Secret),
        })
        .collect();
    p.store.upsert(record).unwrap();
    rotation.rotation_id
}

/// Mounts `GET /user` and `GET /user/orgs` for every leaked GitHub token.
async fn mount_leaked(rec: &CallRecorder, leaked: &[String]) {
    for value in leaked {
        mount_user(rec, value, "octocat", Some("repo")).await;
        mount_orgs(rec, value, &["acme"]).await;
    }
}

/// `POST /credentials/revoke` answers 429 with `retry-after: 1800`.
async fn mount_revoke_limited(rec: &CallRecorder) {
    Mock::given(method("POST"))
        .and(path("/credentials/revoke"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "1800")
                .set_body_json(serde_json::json!({ "message": "rate limited" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// The fixed clock of the rate-limit runs.
fn fixed_clock() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

/// What a batch run left behind, for the assertions and the T10 sweep.
struct BatchRun {
    p: Pipeline,
    term: Term,
    outcomes: Vec<apply::Outcome>,
    leaked: Vec<String>,
    replacements: Vec<String>,
    aws: MockProvider,
}

/// T1's run: five classic tokens and one mock AWS key, five pasted
/// replacements, one apply.
async fn t1_run(rec: &CallRecorder) -> BatchRun {
    mount_revoke(rec, 202).await;
    let leaked: Vec<String> = (0..5).map(|i| classic(&format!("t1Lk{i}"))).collect();
    let replacements: Vec<String> = (0..5).map(|i| classic(&format!("t1Nw{i}"))).collect();
    mount_leaked(rec, &leaked).await;
    for value in &replacements {
        mount_user(rec, value, "octocat", Some("repo")).await;
    }
    let aws_value = "mock_aws_sha286_t1_key";
    let log = rotate::calls::CallLog::new();
    let aws = MockProvider::new("aws")
        .identify_prefix("mock_aws_")
        .log(log.clone());
    let aws_shared = Arc::new(
        MockProvider::new("aws")
            .identify_prefix("mock_aws_")
            .log(log),
    );
    let mut values: Vec<&str> = leaked.iter().map(String::as_str).collect();
    values.push(aws_value);
    let mut p = pipeline_many(rec, &values, vec![aws_shared]).await;
    let mut term = Term::default();
    let answers: Vec<String> = replacements.clone();
    let outcomes = {
        let requested = pick(&p.plan, &values);
        Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_manual(
                ReplacementSource::Prompt(Box::new(ScriptedPrompt::new(answers))),
                &mut term,
            )
            .run_all(&requested)
            .await
    };
    BatchRun {
        p,
        term,
        outcomes,
        leaked,
        replacements,
        aws,
    }
}

/// T4's run: three seeded rotations, every revoke request rate-limited.
async fn t4_run(rec: &CallRecorder) -> BatchRun {
    mount_revoke_limited(rec).await;
    let leaked: Vec<String> = (0..3).map(|i| classic(&format!("t4Lk{i}"))).collect();
    mount_leaked(rec, &leaked).await;
    let values: Vec<&str> = leaked.iter().map(String::as_str).collect();
    let mut p = pipeline_many(rec, &values, Vec::new()).await;
    for value in &values {
        seed_verified(&mut p, value);
    }
    let mut term = Term::default();
    let outcomes = {
        let requested = pick(&p.plan, &values);
        Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_clock(fixed_clock)
            .with_manual(ReplacementSource::Supplied(None), &mut term)
            .run_all(&requested)
            .await
    };
    BatchRun {
        p,
        term,
        outcomes,
        leaked,
        replacements: Vec::new(),
        aws: MockProvider::new("aws"),
    }
}

// SHA-286 T1 (AC1): five GitHub rotations and one AWS rotation in one
// apply: one unauthenticated POST with exactly the five leaked tokens, one
// revoke call for the AWS key, six revoked outcomes in input order.
#[tokio::test]
async fn sha286_t1_five_github_and_one_aws_revoke_in_one_post() {
    let rec = CallRecorder::start().await;
    let run = t1_run(&rec).await;
    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1, "one request: {sent:?}");
    let (body, authorized) = &sent[0];
    assert_eq!(body, &serde_json::json!({ "credentials": run.leaked }));
    assert!(
        !authorized,
        "the revocation API must be called without auth"
    );

    let aws_rotation = run.p.rotation("mock_aws_sha286_t1_key");
    let aws_revokes: Vec<_> = run
        .aws
        .call_log()
        .calls()
        .into_iter()
        .filter(|c| c.method == "revoke")
        .collect();
    assert_eq!(aws_revokes.len(), 1, "{aws_revokes:?}");
    assert_eq!(
        aws_revokes[0].fingerprint.as_ref(),
        Some(&aws_rotation.fingerprint)
    );

    assert_eq!(run.outcomes.len(), 6);
    let mut values: Vec<&str> = run.leaked.iter().map(String::as_str).collect();
    values.push("mock_aws_sha286_t1_key");
    for (outcome, value) in run.outcomes.iter().zip(&values) {
        assert_eq!(
            outcome.fingerprint,
            SecretValue::from(*value).fingerprint(),
            "input order"
        );
        assert_eq!(outcome.result, RunResult::Revoked, "{value}");
    }
    assert_eq!(apply::run_status(&run.outcomes), apply::RunStatus::Done);
    assert!(
        run.term
            .err
            .contains("revoking 5 github tokens in one request"),
        "{}",
        run.term.err
    );
    for (i, value) in run.replacements.iter().enumerate() {
        assert_eq!(
            run.p.gha.current(&format!("gha:acme/app{i}:GH_TOKEN")),
            Some(SecretValue::from(value.as_str()).fingerprint())
        );
    }
}

// SHA-286 T2 (AC2): 1001 tokens go in two requests, 1000 then 1.
#[tokio::test]
async fn sha286_t2_revoke_batch_chunks_1001_tokens() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let creds: Vec<Credential> = (0..REVOKE_BATCH + 1)
        .map(|i| cred(&classic(&format!("c{i:05}"))))
        .collect();
    let refs: Vec<&Credential> = creds.iter().collect();
    let results = provider(&rec).revoke_batch(&refs).await;
    let sizes: Vec<usize> = revokes(&rec)
        .await
        .iter()
        .map(|(body, _)| body["credentials"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes, [REVOKE_BATCH, 1]);
    assert_eq!(results.len(), REVOKE_BATCH + 1);
    assert!(results
        .iter()
        .all(|r| r == &Ok(Revoked { restore_ref: None })));
}

// SHA-286 T3 (AC3): a batch still writes one revoke entry and one record
// per rotation, and no token reaches the audit log or the state file.
#[tokio::test]
async fn sha286_t3_batch_writes_one_revoke_entry_and_record_each() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked: Vec<String> = (0..3).map(|i| classic(&format!("t3Lk{i}"))).collect();
    mount_leaked(&rec, &leaked).await;
    let values: Vec<&str> = leaked.iter().map(String::as_str).collect();
    let mut p = pipeline_many(&rec, &values, Vec::new()).await;
    let ids: Vec<String> = values.iter().map(|v| seed_verified(&mut p, v)).collect();
    let mut term = Term::default();
    let outcomes = {
        let requested = pick(&p.plan, &values);
        Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_manual(ReplacementSource::Supplied(None), &mut term)
            .run_all(&requested)
            .await
    };
    assert!(outcomes.iter().all(|o| o.result == RunResult::Revoked));
    assert_eq!(revokes(&rec).await.len(), 1);

    let revoke_entries: Vec<_> = p
        .audit_entries()
        .into_iter()
        .filter(|e| e.step == AuditStep::Revoke)
        .collect();
    assert_eq!(revoke_entries.len(), 3, "{revoke_entries:?}");
    assert!(revoke_entries.iter().all(|e| e.outcome == AuditOutcome::Ok));
    let mut logged: Vec<(String, String)> = revoke_entries
        .iter()
        .map(|e| (e.rotation_id.clone(), e.fingerprint.to_string()))
        .collect();
    let mut planned: Vec<(String, String)> = values
        .iter()
        .map(|v| {
            let r = p.rotation(v);
            (r.rotation_id.clone(), r.fingerprint.to_string())
        })
        .collect();
    logged.sort();
    planned.sort();
    assert_eq!(logged, planned);
    for id in &ids {
        assert_eq!(p.store.get(id).unwrap().step, Step::Revoked);
    }
    let (audit, state) = (p.audit_text(), p.state_text());
    for value in &leaked {
        assert!(!audit.contains(value.as_str()), "token in the audit log");
        assert!(!state.contains(value.as_str()), "token in the state file");
    }
}

// SHA-286 T4 (AC4), provider level: a rate-limited request stops the batch;
// the later chunk is never sent and gets the same error.
#[tokio::test]
async fn sha286_t4_rate_limited_chunk_stops_the_batch() {
    let rec = CallRecorder::start().await;
    mount_revoke_limited(&rec).await;
    let creds: Vec<Credential> = (0..REVOKE_BATCH + 1)
        .map(|i| cred(&classic(&format!("r{i:05}"))))
        .collect();
    let refs: Vec<&Credential> = creds.iter().collect();
    let results = provider(&rec).revoke_batch(&refs).await;
    assert_eq!(revokes(&rec).await.len(), 1, "the second chunk was sent");
    assert_eq!(results.len(), REVOKE_BATCH + 1);
    let limited = Err(ProviderError::RateLimited {
        retry_after: Some(Duration::from_secs(1800)),
    });
    assert!(results.iter().all(|r| r == &limited));
}

// SHA-286 T4 (AC4), through the executor: every rotation of the batch
// fails at revoke with the time to re-run, nothing is retried, exit 1.
#[tokio::test]
async fn sha286_t4_rate_limited_revoke_fails_every_rotation() {
    let rec = CallRecorder::start().await;
    let run = t4_run(&rec).await;
    assert_eq!(revokes(&rec).await.len(), 1, "nothing is retried");
    let at = (fixed_clock() + time::Duration::minutes(30))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    for outcome in &run.outcomes {
        match &outcome.result {
            RunResult::Failed {
                step: AuditStep::Revoke,
                error,
            } => {
                assert!(
                    error.as_str().contains("re-run rotate apply after"),
                    "{error}"
                );
                assert!(error.as_str().contains(&at), "{error}");
                assert!(error.as_str().contains("(in 30m 0s)"), "{error}");
            }
            other => panic!("expected a failed revoke, got {other:?}"),
        }
        let stored = run.p.store.get(&outcome.rotation_id).unwrap();
        assert_eq!(stored.step, Step::Failed);
        assert_eq!(stored.failed_step, Some(AuditStep::Revoke));
    }
    assert_eq!(apply::run_status(&run.outcomes), apply::RunStatus::Failed);
    let summary = apply::render_summary(&run.outcomes);
    assert!(summary.contains(&at), "{summary}");
    assert!(summary.contains("3 failed"), "{summary}");
}

// SHA-286 T5 (AC5): only rotations that passed their gate enter the batch;
// pending, held and failed ones are left out.
#[tokio::test]
async fn sha286_t5_only_gate_passed_rotations_enter_the_batch() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked: Vec<String> = ["t5Pend", "t5Held", "t5Fail", "t5Redy"]
        .iter()
        .map(|t| classic(t))
        .collect();
    mount_leaked(&rec, &leaked).await;
    let failing = classic("t5FailN");
    let ready = classic("t5RedyN");
    // Answers the paste check only; verify then gets the catch-all empty
    // 200, which does not decode.
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("authorization", bearer(&failing).as_str()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "login": "octocat", "id": 1 })),
        )
        .up_to_n_times(1)
        .with_priority(2)
        .mount(rec.server())
        .await;
    mount_user(&rec, &ready, "octocat", Some("repo")).await;
    let values: Vec<&str> = leaked.iter().map(String::as_str).collect();
    let mut p = pipeline_many(&rec, &values, Vec::new()).await;

    let pending = seed_verified(&mut p, values[0]);
    let mut record = p.store.get(&pending).unwrap().clone();
    record.step = Step::PendingRevoke;
    record.revoke_not_before = Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1));
    p.store.upsert(record).unwrap();
    // A not-updatable consumer leaves the record verified with that
    // consumer skipped, so the gate holds the revoke.
    let held = seed_verified(&mut p, values[1]);
    let mut record = p.store.get(&held).unwrap().clone();
    record.consumers[0].status = ConsumerStatus::Skipped;
    p.store.upsert(record).unwrap();

    let mut term = Term::default();
    let outcomes = {
        let requested = pick(&p.plan, &values);
        Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_manual(
                ReplacementSource::Prompt(Box::new(ScriptedPrompt::new([
                    failing.clone(),
                    ready.clone(),
                ]))),
                &mut term,
            )
            .run_all(&requested)
            .await
    };
    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, serde_json::json!({ "credentials": [values[3]] }));
    assert!(
        matches!(outcomes[0].result, RunResult::PendingRevoke { .. }),
        "{:?}",
        outcomes[0].result
    );
    assert!(
        matches!(outcomes[1].result, RunResult::Held { .. }),
        "{:?}",
        outcomes[1].result
    );
    assert!(
        matches!(
            outcomes[2].result,
            RunResult::Failed {
                step: AuditStep::Verify,
                ..
            }
        ),
        "{:?}",
        outcomes[2].result
    );
    assert_eq!(outcomes[3].result, RunResult::Revoked);
}

// SHA-286 T6 (AC6), provider level: an installation token is refused in
// place and left out of the request.
#[tokio::test]
async fn sha286_t6_revoke_batch_leaves_out_installation_tokens() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let values = [
        token(["gh", "s_"], "t6Inst"),
        classic("t6Clas1"),
        classic("t6Clas2"),
    ];
    let creds: Vec<Credential> = values.iter().map(|v| cred(v)).collect();
    let refs: Vec<&Credential> = creds.iter().collect();
    let results = provider(&rec).revoke_batch(&refs).await;
    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].0,
        serde_json::json!({ "credentials": [values[1], values[2]] })
    );
    let refused = results[0].as_ref().unwrap_err();
    assert_eq!(
        refused.base(),
        &ProviderError::Unsupported(INSTALLATION_UNSUPPORTED.into())
    );
    assert_eq!(refused.guidance(), Some(INSTALLATION_UNSUPPORTED));
    assert!(results[1].is_ok() && results[2].is_ok());
}

/// One installation token, whose scope does not name its type, plus the
/// classic tokens `others`, all verified and run through the executor
/// with GitHub answering every revoke with 202.
async fn installation_batch(
    tag: &str,
    others: &[String],
) -> (CallRecorder, Term, Vec<rotate::apply::Outcome>) {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let installation = token(["gh", "s_"], &format!("{tag}InEx"));
    mount_installation(&rec, &installation).await;
    mount_leaked(&rec, others).await;
    let mut values = vec![installation.as_str()];
    values.extend(others.iter().map(String::as_str));
    let mut p = pipeline_many(&rec, &values, Vec::new()).await;
    for value in &values {
        seed_verified(&mut p, value);
    }
    let fp = SecretValue::from(installation.as_str()).fingerprint();
    for rotation in &mut p.plan.rotations {
        if rotation.fingerprint == fp {
            if let Some(scope) = rotation.scope.as_mut() {
                scope.lines.retain(|l| !l.starts_with("type: "));
            }
        }
    }
    assert_eq!(
        p.providers
            .get("github")
            .unwrap()
            .manual_revoke(p.rotation(&installation).scope.as_ref()),
        None
    );
    let mut term = Term::default();
    let outcomes = {
        let requested = pick(&p.plan, &values);
        Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_manual(ReplacementSource::Supplied(None), &mut term)
            .run_all(&requested)
            .await
    };
    match &outcomes[0].result {
        RunResult::RevokeManual { instructions } => {
            assert!(
                instructions.as_str().contains(INSTALLATION_UNSUPPORTED),
                "{instructions}"
            );
        }
        other => panic!("expected a revoke by hand, got {other:?}"),
    }
    (rec, term, outcomes)
}

// SHA-286 T6 (AC6), through the executor: an installation token whose
// scope does not name its type reaches the batch, is refused there and
// ends as a revoke by hand; the others are revoked in one request.
// SHA-330 T1 (AC1): the notice counts the two tokens the request carries.
#[tokio::test]
async fn sha286_t6_installation_token_in_a_batch_is_by_hand() {
    let others = [classic("t6ExCl1"), classic("t6ExCl2")];
    let (rec, term, outcomes) = installation_batch("t6", &others).await;
    assert_eq!(outcomes[1].result, RunResult::Revoked);
    assert_eq!(outcomes[2].result, RunResult::Revoked);
    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].0,
        serde_json::json!({ "credentials": [others[0], others[1]] })
    );
    assert!(
        term.err.contains("revoking 2 github tokens in one request"),
        "{}",
        term.err
    );
    assert!(!term.err.contains("revoking 3"), "{}", term.err);
}

// SHA-330 T2 (AC2): with the installation token left out, one token goes
// in the request, so there is no "in one request" notice.
#[tokio::test]
async fn sha330_t2_one_batchable_token_has_no_batch_notice() {
    let others = [classic("t2ExCl1")];
    let (rec, term, outcomes) = installation_batch("t2", &others).await;
    assert_eq!(outcomes[1].result, RunResult::Revoked);
    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, serde_json::json!({ "credentials": [others[0]] }));
    assert!(!term.err.contains("in one request"), "{}", term.err);
}

/// Answers `POST /credentials/revoke` with 202 after noting what the audit
/// log held at that moment: whether every forced rotation has a `force`
/// entry, and whether any `revoke` entry is `ok` yet.
struct AuditAtRevoke {
    audit: std::path::PathBuf,
    forced: Vec<String>,
    seen: Arc<Mutex<Option<(bool, bool)>>>,
}

impl Respond for AuditAtRevoke {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let entries: Vec<rotate::audit::AuditEntry> = rotate::audit::read_all(&self.audit)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let forced = self.forced.iter().all(|id| {
            entries
                .iter()
                .any(|e| &e.rotation_id == id && e.step == AuditStep::Force)
        });
        let revoked = entries
            .iter()
            .any(|e| e.step == AuditStep::Revoke && e.outcome == AuditOutcome::Ok);
        *self.seen.lock().unwrap() = Some((forced, revoked));
        ResponseTemplate::new(202).set_body_json(serde_json::json!({}))
    }
}

// SHA-286 T7 (AC7): every `force` entry of a batch is on record before the
// request is sent.
#[tokio::test]
async fn sha286_t7_force_is_recorded_before_the_batch_request() {
    let rec = CallRecorder::start().await;
    let leaked: Vec<String> = (0..2).map(|i| classic(&format!("t7Lk{i}"))).collect();
    mount_leaked(&rec, &leaked).await;
    let values: Vec<&str> = leaked.iter().map(String::as_str).collect();
    let mut p = pipeline_many(&rec, &values, Vec::new()).await;
    let mut ids = Vec::new();
    for value in &values {
        let id = seed_verified(&mut p, value);
        let mut record = p.store.get(&id).unwrap().clone();
        record.consumers[0].status = ConsumerStatus::Skipped;
        p.store.upsert(record).unwrap();
        ids.push(id);
    }
    let seen = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .and(path("/credentials/revoke"))
        .respond_with(AuditAtRevoke {
            audit: p.dir.path().join("audit.jsonl"),
            forced: ids.clone(),
            seen: seen.clone(),
        })
        .with_priority(2)
        .mount(rec.server())
        .await;
    let mut term = Term::default();
    let outcomes = {
        let requested = pick(&p.plan, &values);
        Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_force(true)
            .with_manual(ReplacementSource::Supplied(None), &mut term)
            .run_all(&requested)
            .await
    };
    assert!(outcomes.iter().all(|o| o.result == RunResult::Revoked));
    assert_eq!(revokes(&rec).await.len(), 1);
    assert_eq!(*seen.lock().unwrap(), Some((true, false)));
    for id in &ids {
        assert!(p.store.get(id).unwrap().force);
    }
    let steps: Vec<AuditStep> = p
        .audit_entries()
        .into_iter()
        .map(|e| e.step)
        .filter(|s| matches!(s, AuditStep::Force | AuditStep::Revoke))
        .collect();
    assert_eq!(
        steps,
        [
            AuditStep::Force,
            AuditStep::Force,
            AuditStep::Revoke,
            AuditStep::Revoke
        ]
    );
}

// SHA-286 T8 (AC8): with --wait, the GitHub group waits once, for the
// latest window, then sends one request.
#[tokio::test]
async fn sha286_t8_wait_sends_one_batch_after_the_latest_window() {
    let rec = CallRecorder::start().await;
    mount_revoke(&rec, 202).await;
    let leaked: Vec<String> = (0..2).map(|i| classic(&format!("t8Lk{i}"))).collect();
    mount_leaked(&rec, &leaked).await;
    let values: Vec<&str> = leaked.iter().map(String::as_str).collect();
    let mut p = pipeline_many(&rec, &values, Vec::new()).await;
    let started = std::time::Instant::now();
    let now = time::OffsetDateTime::now_utc();
    let mut ids = Vec::new();
    for (i, value) in values.iter().enumerate() {
        let id = seed_verified(&mut p, value);
        let mut record = p.store.get(&id).unwrap().clone();
        record.step = Step::PendingRevoke;
        record.revoke_not_before = Some(now + time::Duration::seconds(i as i64 + 1));
        p.store.upsert(record).unwrap();
        ids.push(id);
    }
    let mut term = Term::default();
    let outcomes = {
        let requested = pick(&p.plan, &values);
        Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_wait(true)
            .with_manual(ReplacementSource::Supplied(None), &mut term)
            .run_all(&requested)
            .await
    };
    assert!(started.elapsed() >= Duration::from_secs(2));
    let sent = revokes(&rec).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, serde_json::json!({ "credentials": values }));
    assert!(outcomes.iter().all(|o| o.result == RunResult::Revoked));
    for id in &ids {
        assert_eq!(p.store.get(id).unwrap().step, Step::Revoked);
    }
    assert_eq!(term.err.matches("waiting until").count(), 1, "{}", term.err);
    let notice = term
        .err
        .lines()
        .find(|l| l.contains("waiting until"))
        .unwrap();
    assert!(
        ids.iter().all(|id| notice.contains(id.as_str())),
        "{notice}"
    );
    assert!(
        term.err.contains("revoking 2 github tokens in one request"),
        "{}",
        term.err
    );
}

/// Every place a batch run could have written `value`, by label.
fn places(run: &BatchRun, logs: &str) -> Vec<(&'static str, String)> {
    vec![
        ("summary", apply::render_summary(&run.outcomes)),
        ("stdout", run.term.out.clone()),
        ("stderr", run.term.err.clone()),
        ("audit log", run.p.audit_text()),
        ("state file", run.p.state_text()),
        ("logs", logs.to_owned()),
        ("outcomes", format!("{:?}", run.outcomes)),
    ]
}

/// On the wire, a leaked token is only in the revoke body and in the
/// `Authorization` of the read-only checks; a replacement only in the
/// `Authorization` of `GET /user`.
async fn assert_wire_clean(rec: &CallRecorder, leaked: &[String], replacements: &[String]) {
    for req in rec.server().received_requests().await.unwrap() {
        let target = format!("{} {}", req.method, req.url.path());
        let body = String::from_utf8_lossy(&req.body);
        let auth = req
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_owned())
            .unwrap_or_default();
        for (name, value) in &req.headers {
            if name.as_str() != "authorization" {
                let value = value.to_str().unwrap_or("");
                for secret in leaked.iter().chain(replacements) {
                    assert!(!value.contains(secret.as_str()), "token in header {name}");
                }
            }
        }
        for value in leaked {
            if body.contains(value.as_str()) {
                assert_eq!(target, "POST /credentials/revoke", "leaked token in a body");
            }
            if auth.contains(value.as_str()) {
                assert!(
                    target == "GET /user" || target == "GET /user/orgs",
                    "leaked token signed {target}"
                );
            }
        }
        for value in replacements {
            assert!(!body.contains(value.as_str()), "new token in {target} body");
            if auth.contains(value.as_str()) {
                assert_eq!(target, "GET /user", "new token signed {target}");
            }
        }
    }
}

// SHA-286 T10 (AC1, AC4): the T1 and T4 runs under a TRACE capture. No
// leaked or replacement token appears in the summary, the terminal, the
// audit log, the state file, the logs or the outcomes' Debug output, and
// on the wire each appears only where it must.
#[tokio::test]
async fn sha286_t10_batch_revoke_never_leaks() {
    let capture = trace_capture();
    let rec = CallRecorder::start().await;
    let t1 = t1_run(&rec).await;
    assert!(t1.outcomes.iter().all(|o| o.result == RunResult::Revoked));
    let rec4 = CallRecorder::start().await;
    let t4 = t4_run(&rec4).await;
    assert!(t4
        .outcomes
        .iter()
        .all(|o| matches!(o.result, RunResult::Failed { .. })));
    let logs = capture.contents();
    assert!(!logs.is_empty(), "the TRACE capture saw nothing");

    let aws_value = "mock_aws_sha286_t1_key".to_owned();
    for (run, extra) in [(&t1, Some(&aws_value)), (&t4, None)] {
        let places = places(run, &logs);
        for value in run.leaked.iter().chain(&run.replacements).chain(extra) {
            for (label, text) in &places {
                assert!(!text.contains(value.as_str()), "token in {label}");
            }
        }
    }
    assert_wire_clean(&rec, &t1.leaked, &t1.replacements).await;
    assert_wire_clean(&rec4, &t4.leaked, &[]).await;
}

/// Labels the recorder's state-changing calls by method and path.
struct RecorderProbe(CallRecorder);

#[async_trait]
impl MutationProbe for RecorderProbe {
    async fn mutations(&self) -> Vec<String> {
        self.0
            .calls()
            .await
            .iter()
            .filter(|c| c.mutating)
            .map(|c| format!("{} {}", c.method, c.path))
            .collect()
    }
}

// T11 (AC1 to AC8): the shared provider suite in manual mode.
#[tokio::test]
async fn conformance_manual_mode() {
    let report = provider_suite(|| async {
        let rec = CallRecorder::start().await;
        let live = classic("t11Live");
        let unknown = classic("t11Unkn");
        mount_user(&rec, &live, "dave", Some("repo")).await;
        mount_orgs(&rec, &live, &["acme"]).await;
        mount_bad_credentials(&rec, &unknown).await;
        mount_revoke(&rec, 202).await;
        ProviderFixture {
            provider: Arc::new(provider(&rec)),
            live: cred(&live),
            identity: Identity("dave".into()),
            unknown: cred(&unknown),
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await;
    assert_eq!(report.plugin, "github");
    report.assert_ok();
    assert!(matches!(
        report.outcome("replacement_differs"),
        Some(Outcome::Skipped(_))
    ));
    for name in [
        "identify_rejects_foreign",
        "check_valid_unknown_invalid",
        "read_only_check_valid",
        "read_only_describe_scope",
        "read_only_verify",
        "verify_wrong_identity_fails",
        "idempotent_revoke",
        "restore_outcome",
        "errors_redacted",
    ] {
        assert_eq!(
            report.outcome(name),
            Some(&Outcome::Passed),
            "{name}: {report}"
        );
    }
}

// Live, read-only: a real token from the environment is valid and its
// scope names a login.
#[tokio::test]
#[ignore]
async fn live_github_check_valid_and_scope() {
    common::live_guard!();
    let Some(value) = common::live_env("ROTATE_LIVE_GITHUB_TOKEN") else {
        return;
    };
    let p = GithubProvider::new("https://api.github.com");
    let credential = cred(&value);
    assert_eq!(p.check_valid(&credential).await.unwrap(), Validity::Valid);
    let scope = p.describe_scope(&credential).await.unwrap();
    assert!(!scope.identity.0.is_empty());
    p.verify(&credential, &scope.identity).await.unwrap();
}

// Live, destructive: revokes a throwaway token through the credential
// revocation API, twice, and expects it to stop working. Use a token made
// for this test only.
#[tokio::test]
#[ignore]
async fn live_github_revoke() {
    common::live_guard!();
    let Some(value) = common::live_env("ROTATE_LIVE_GITHUB_REVOKE_TOKEN") else {
        return;
    };
    let p = GithubProvider::new("https://api.github.com");
    let credential = cred(&value);
    p.revoke(&credential).await.unwrap();
    p.revoke(&credential).await.unwrap();
    // Revocation is processed asynchronously.
    for _ in 0..30 {
        if p.check_valid(&credential).await.unwrap() == Validity::Invalid {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("the token still works a minute after revoke");
}
