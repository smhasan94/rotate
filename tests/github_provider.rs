//! GitHub token provider (SHA-260) against a wiremock GitHub API.
//!
//! Every GitHub read is a GET; the one state-changing call is `POST
//! /credentials/revoke`, so the recorder's default (POST is mutating) is
//! exactly right. Tokens are built at runtime with unique tags so no
//! literal matches a secret scanner and every test can search for its own
//! values.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

use rotate::apply::{self, Executor, ReplacementSource, RunResult, Terminal};
use rotate::assess::{self, AssessOptions};
use rotate::audit::AuditLog;
use rotate::config::ConsumersConfig;
use rotate::conformance::{provider_suite, MutationProbe, Outcome, ProviderFixture};
use rotate::consumer::mock::MockConsumer;
use rotate::consumer::{ConsumerMatch, ConsumerRegistry};
use rotate::finding::{Finding, SourceLocation};
use rotate::plan;
use rotate::provider::github::{GithubProvider, FINE_GRAINED_NOTE, REVOKE_BATCH};
use rotate::provider::{
    Credential, Identity, Provider, ProviderError, ProviderRegistry, ReplacementMode,
    RestoreOutcome, Validity,
};
use rotate::secret::SecretValue;
use rotate::state::StateStore;

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

fn live_env(name: &str) -> Option<String> {
    let value = common::require_env(name);
    if value.is_none() {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "skipped: {name} not set");
    }
    value
}

// Live, read-only: a real token from the environment is valid and its
// scope names a login.
#[tokio::test]
#[ignore]
async fn live_github_check_valid_and_scope() {
    common::live_guard!();
    let Some(value) = live_env("ROTATE_LIVE_GITHUB_TOKEN") else {
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
    let Some(value) = live_env("ROTATE_LIVE_GITHUB_REVOKE_TOKEN") else {
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
