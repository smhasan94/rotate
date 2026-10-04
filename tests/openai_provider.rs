//! OpenAI API key provider (SHA-262) against a wiremock OpenAI API.
//!
//! Every read is a GET; the state-changing calls are the service-account
//! POST and the DELETEs, so the recorder's default classification is
//! exactly right. Keys are built at runtime with unique tags so no literal
//! matches a secret scanner and every test can search for its own values.

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
use rotate::plan::{self, MANUAL_REVOKE_BLOCKER};
use rotate::provider::openai::{
    AdminKey, OpenAiProvider, GUIDE_ADMIN_IS_LEAKED, GUIDE_NEEDS_ADMIN, KEYS_PAGE,
    PERMISSIONS_NOTE, REVOKE_NEEDS_ADMIN, REVOKE_UNDELETABLE, SCOPE_WIDENING_NOTE,
    UNDELETABLE_WARNING,
};
use rotate::provider::{
    Credential, Identity, Provider, ProviderError, ProviderRegistry, ReplacementMode,
    RestoreOutcome, Validity,
};
use rotate::secret::SecretValue;
use rotate::state::StateStore;

use common::CallRecorder;

const PROJ: [&str; 2] = ["sk-", "proj-"];
const SVC: [&str; 2] = ["sk-", "svcacct-"];
const ADMIN: [&str; 2] = ["sk-", "admin-"];

/// A key of `prefix` (split so no literal matches a scanner) starting with
/// `tag` (at least six characters, unique per key), 100 body characters.
fn key(prefix: [&str; 2], tag: &str) -> String {
    assert!(tag.len() >= 6 && tag.bytes().all(|b| b.is_ascii_alphanumeric()));
    let pad = "Qz7".repeat(40);
    format!("{}{tag}{}", prefix.concat(), &pad[..100 - tag.len()])
}

/// OpenAI's redacted form: the prefix and the first six body characters,
/// `...`, the last four.
fn redacted(value: &str) -> String {
    let body_start = value.rfind('-').map(|i| i + 1).unwrap_or(3);
    format!(
        "{}...{}",
        &value[..body_start + 6],
        &value[value.len() - 4..]
    )
}

fn cred(value: &str) -> Credential {
    Credential::Token(SecretValue::from(value))
}

fn bearer(value: &str) -> String {
    format!("Bearer {value}")
}

fn admin_key() -> String {
    key(ADMIN, "admin0")
}

/// An admin key and the opt-in to a broader replacement (SHA-291).
fn automatic(rec: &CallRecorder, admin: &str) -> OpenAiProvider {
    admin_only(rec, admin).with_allow_broader_replacement(true)
}

/// An admin key without the opt-in: manual replacement (SHA-291).
fn admin_only(rec: &CallRecorder, admin: &str) -> OpenAiProvider {
    OpenAiProvider::new(&rec.uri(), AdminKey::Value(SecretValue::from(admin)))
        .with_verify_delay(Duration::ZERO)
}

fn manual(rec: &CallRecorder) -> OpenAiProvider {
    OpenAiProvider::new(&rec.uri(), AdminKey::None).with_verify_delay(Duration::ZERO)
}

/// `GET /v1/models` signed with `value` answers `status`, with
/// `openai-organization` when given.
async fn mount_models(rec: &CallRecorder, value: &str, status: u16, org: Option<&str>) {
    let mut response = ResponseTemplate::new(status);
    response = match status {
        200 => response.set_body_json(serde_json::json!({ "object": "list", "data": [] })),
        401 => response.set_body_json(serde_json::json!({
            "error": {
                // OpenAI echoes part of the key; rotate must never copy it.
                "message": format!("Incorrect API key provided: {}.", redacted(value)),
                "type": "invalid_request_error",
                "code": "invalid_api_key"
            }
        })),
        _ => response,
    };
    if let Some(org) = org {
        response = response.insert_header("openai-organization", org);
    }
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", bearer(value).as_str()))
        .respond_with(response)
        .with_priority(2)
        .mount(rec.server())
        .await;
}

async fn mount_projects(rec: &CallRecorder, admin: &str, projects: &[(&str, &str)]) {
    let data: Vec<serde_json::Value> = projects
        .iter()
        .map(|(id, name)| {
            serde_json::json!({
                "object": "organization.project", "id": id, "name": name,
                "created_at": 1_700_000_000, "status": "active"
            })
        })
        .collect();
    Mock::given(method("GET"))
        .and(path("/v1/organization/projects"))
        .and(header("authorization", bearer(admin).as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "list", "data": data, "has_more": false
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// A user-owned key listing entry.
fn user_key(id: &str, name: &str, value: &str) -> serde_json::Value {
    serde_json::json!({
        "object": "organization.project.api_key",
        "id": id, "name": name, "redacted_value": redacted(value),
        "created_at": 1_700_000_000, "last_used_at": 1_750_000_000,
        "owner": {
            "type": "user",
            "user": { "id": "user_1", "name": "Ada", "email": "ada@example.com", "role": "owner" }
        }
    })
}

/// A service-account-owned key listing entry.
fn account_key(id: &str, account: &str, value: &str) -> serde_json::Value {
    serde_json::json!({
        "object": "organization.project.api_key",
        "id": id, "name": "Secret Key", "redacted_value": redacted(value),
        "created_at": 1_700_000_000, "last_used_at": null,
        "owner": {
            "type": "service_account",
            "service_account": { "id": account, "name": "ci-bot", "role": "member" }
        }
    })
}

async fn mount_keys(rec: &CallRecorder, admin: &str, project: &str, keys: Vec<serde_json::Value>) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/organization/projects/{project}/api_keys"
        )))
        .and(header("authorization", bearer(admin).as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "list", "data": keys, "has_more": false
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
}

async fn mount_create(rec: &CallRecorder, project: &str, account: &str, new_value: &str) {
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/organization/projects/{project}/service_accounts"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "object": "organization.project.service_account",
            "id": account, "name": "rotate", "role": "member", "created_at": 1_760_000_000,
            "api_key": {
                "object": "organization.project.service_account.api_key",
                "value": new_value, "name": "Secret Key", "created_at": 1_760_000_000,
                "id": "key_new"
            }
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// `DELETE path` answers `first` once, then 404.
async fn mount_delete(rec: &CallRecorder, at: &str, first: u16) {
    Mock::given(method("DELETE"))
        .and(path(at))
        .respond_with(
            ResponseTemplate::new(first).set_body_json(serde_json::json!({
                "id": "x", "deleted": true
            })),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(rec.server())
        .await;
    Mock::given(method("DELETE"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": { "message": "not found", "type": "invalid_request_error", "code": null }
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// Every request as `METHOD path`, with the bearer it carried.
async fn requests(rec: &CallRecorder) -> Vec<(String, String)> {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| {
            let auth = r
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            (format!("{} {}", r.method, r.url.path()), auth)
        })
        .collect()
}

/// A standard organization: project A with an unrelated key, project B
/// with the leaked user key and one more. Optional `extra` keys go in B.
async fn mount_org(rec: &CallRecorder, admin: &str, leaked: &str, extra: Vec<serde_json::Value>) {
    mount_projects(rec, admin, &[("proj_a", "Website"), ("proj_b", "Backend")]).await;
    mount_keys(
        rec,
        admin,
        "proj_a",
        vec![user_key("key_other", "other", &key(PROJ, "other0"))],
    )
    .await;
    let mut keys = vec![
        user_key("key_unrel", "unrelated", &key(PROJ, "unrel0")),
        user_key("key_leak", "backend prod", leaked),
    ];
    keys.extend(extra);
    mount_keys(rec, admin, "proj_b", keys).await;
}

fn fast_opts() -> AssessOptions {
    AssessOptions {
        concurrency: 2,
        attempts: 2,
        base_delay: Duration::from_millis(1),
        force_provider: None,
    }
}

fn finding(value: &str) -> Finding {
    Finding::new(
        SecretValue::from(value),
        "OpenAI",
        SourceLocation::file("backend/.env"),
    )
}

// T2 (AC2)
#[tokio::test]
async fn check_valid_maps_status() {
    let rec = CallRecorder::start().await;
    let ok = key(PROJ, "t2ok00");
    let revoked = key(PROJ, "t2gone");
    let limited = key(PROJ, "t2rate");
    let restricted = key(PROJ, "t2rstr");
    let forbidden = key(PROJ, "t2forb");
    let busy = key(PROJ, "t2busy");
    mount_models(&rec, &ok, 200, None).await;
    mount_models(&rec, &revoked, 401, None).await;
    mount_models(&rec, &limited, 429, None).await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", bearer(&restricted).as_str()))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "message": "You have insufficient permissions for this operation. Missing scopes: api.model.read.", "type": "invalid_request_error" }
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
    mount_models(&rec, &forbidden, 403, None).await;
    mount_models(&rec, &busy, 503, None).await;
    let p = manual(&rec);

    assert_eq!(p.check_valid(&cred(&ok)).await.unwrap(), Validity::Valid);
    assert_eq!(
        p.check_valid(&cred(&revoked)).await.unwrap(),
        Validity::Invalid
    );
    assert_eq!(
        p.check_valid(&cred(&limited)).await.unwrap(),
        Validity::Valid
    );
    assert_eq!(
        p.check_valid(&cred(&restricted)).await.unwrap(),
        Validity::Valid,
        "a restricted key without the models scope is still live"
    );
    match p.check_valid(&cred(&forbidden)).await.unwrap() {
        Validity::Unknown { reason } => assert!(reason.contains("403"), "{reason}"),
        other => panic!("expected unknown, got {other:?}"),
    }
    assert!(p
        .check_valid(&cred(&busy))
        .await
        .unwrap_err()
        .is_retryable());
    rec.assert_no_mutations().await;
}

// T3 (AC3)
#[tokio::test]
async fn describe_scope_matches_redacted_value() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "t3leak");
    mount_org(&rec, &admin, &leaked, vec![]).await;
    let scope = automatic(&rec, &admin)
        .describe_scope(&cred(&leaked))
        .await
        .unwrap();
    assert_eq!(scope.identity, Identity("proj_b".into()));
    assert_eq!(
        scope.lines,
        [
            "project: Backend (proj_b)",
            "key: backend prod (key_leak)",
            "owner: user Ada <ada@example.com>",
            "created: 2023-11-14T22:13:20Z",
            "last used: 2025-06-15T15:06:40Z",
            PERMISSIONS_NOTE,
        ]
    );
    rec.assert_no_mutations().await;
    for (target, auth) in requests(&rec).await {
        assert_eq!(
            auth,
            bearer(&admin),
            "{target} not signed with the admin key"
        );
    }
}

#[tokio::test]
async fn ambiguous_or_missing_match_is_an_error() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "t3twin");
    // The same redacted value in two projects.
    mount_projects(&rec, &admin, &[("proj_a", "A"), ("proj_b", "B")]).await;
    mount_keys(&rec, &admin, "proj_a", vec![user_key("k1", "one", &leaked)]).await;
    mount_keys(&rec, &admin, "proj_b", vec![user_key("k2", "two", &leaked)]).await;
    let p = automatic(&rec, &admin);
    let err = p.describe_scope(&cred(&leaked)).await.unwrap_err();
    assert!(err.to_string().contains("2 keys"), "{err}");

    let missing = key(PROJ, "t3miss");
    let err = p.describe_scope(&cred(&missing)).await.unwrap_err();
    assert!(err.to_string().contains("no project"), "{err}");
    rec.assert_no_mutations().await;
}

// T4 (AC4), wiremock half: without an admin key the scope comes from the
// leaked key's own read-only call.
#[tokio::test]
async fn manual_scope_reads_org_header() {
    let rec = CallRecorder::start().await;
    let leaked = key(PROJ, "t4manu");
    mount_models(&rec, &leaked, 200, Some("org-acme")).await;
    let p = manual(&rec);
    assert_eq!(p.replacement_mode(), ReplacementMode::Manual);
    let scope = p.describe_scope(&cred(&leaked)).await.unwrap();
    assert_eq!(scope.identity, Identity("org-acme".into()));
    assert_eq!(scope.lines[0], "scope unavailable: set OPENAI_ADMIN_KEY");
    assert!(p
        .manual_instructions(&scope)
        .contains("platform.openai.com/api-keys"));
    assert_eq!(p.manual_revoke(Some(&scope)), Some(REVOKE_NEEDS_ADMIN));
    assert_eq!(
        p.revoke(&cred(&leaked)).await.unwrap_err(),
        // SHA-298 T5.
        ProviderError::Unsupported(REVOKE_NEEDS_ADMIN.into()).with_guidance(GUIDE_NEEDS_ADMIN)
    );
    // A pasted key from another organization fails verify.
    let other = key(PROJ, "t4othr");
    mount_models(&rec, &other, 200, Some("org-evil")).await;
    let err = p.verify(&cred(&other), &scope.identity).await.unwrap_err();
    assert!(err.to_string().contains("org-evil"), "{err}");
    rec.assert_no_mutations().await;
}

// T5 (AC5)
#[tokio::test]
async fn create_replacement_posts_service_account() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "t5leak");
    let fresh = key(SVC, "t5new0");
    mount_org(&rec, &admin, &leaked, vec![]).await;
    mount_create(&rec, "proj_b", "svc_acct_new", &fresh).await;
    let replacement = automatic(&rec, &admin)
        .create_replacement(&cred(&leaked))
        .await
        .unwrap();
    assert_ne!(
        replacement.credential.fingerprint(),
        cred(&leaked).fingerprint()
    );
    assert_eq!(
        replacement.credential.fingerprint(),
        cred(&fresh).fingerprint()
    );
    assert_eq!(
        replacement.replacement_ref,
        "openai:proj_b:svc_acct_new:key_new"
    );

    let calls = rec.calls().await;
    let posts: Vec<_> = calls.iter().filter(|c| c.mutating).collect();
    assert_eq!(posts.len(), 1, "{calls:?}");
    assert_eq!(posts[0].method, "POST");
    assert_eq!(
        posts[0].path,
        "/v1/organization/projects/proj_b/service_accounts"
    );
    let body: serde_json::Value = serde_json::from_slice(posts[0].body()).unwrap();
    let hex = cred(&leaked)
        .fingerprint()
        .as_str()
        .trim_start_matches("sha256:")
        .to_owned();
    assert_eq!(body, serde_json::json!({ "name": format!("rotate-{hex}") }));
    let posted = requests(&rec).await;
    assert!(posted
        .iter()
        .any(|(t, a)| t.starts_with("POST ") && *a == bearer(&admin)));
}

// T6 (AC6)
#[tokio::test]
async fn revoke_deletes_user_key_with_admin_bearer() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "t6leak");
    mount_org(&rec, &admin, &leaked, vec![]).await;
    let at = "/v1/organization/projects/proj_b/api_keys/key_leak";
    mount_delete(&rec, at, 200).await;
    let p = automatic(&rec, &admin);
    assert_eq!(p.revoke(&cred(&leaked)).await.unwrap().restore_ref, None);
    // The second DELETE answers 404: already revoked is Ok.
    p.revoke(&cred(&leaked)).await.unwrap();

    let deletes: Vec<(String, String)> = requests(&rec)
        .await
        .into_iter()
        .filter(|(t, _)| t.starts_with("DELETE "))
        .collect();
    assert_eq!(deletes.len(), 2);
    for (target, auth) in &deletes {
        assert_eq!(target, &format!("DELETE {at}"));
        assert_eq!(auth, &bearer(&admin));
    }
}

#[tokio::test]
async fn revoke_of_unlisted_dead_key_is_ok() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let gone = key(PROJ, "t6gone");
    mount_org(&rec, &admin, &key(PROJ, "t6else"), vec![]).await;
    mount_models(&rec, &gone, 401, None).await;
    automatic(&rec, &admin).revoke(&cred(&gone)).await.unwrap();
    rec.assert_no_mutations().await;
    // Unlisted but still live is an error, not a silent success.
    let live = key(PROJ, "t6live");
    mount_models(&rec, &live, 200, None).await;
    let err = automatic(&rec, &admin)
        .revoke(&cred(&live))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no project"), "{err}");
    rec.assert_no_mutations().await;
}

#[tokio::test]
async fn sole_service_account_key_revoke_deletes_the_account() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(SVC, "t6svc0");
    mount_org(
        &rec,
        &admin,
        &key(PROJ, "t6user"),
        vec![account_key("key_svc", "svc_acct_ci", &leaked)],
    )
    .await;
    let at = "/v1/organization/projects/proj_b/service_accounts/svc_acct_ci";
    mount_delete(&rec, at, 200).await;
    let p = automatic(&rec, &admin);
    let scope = p.describe_scope(&cred(&leaked)).await.unwrap();
    assert!(scope
        .lines
        .contains(&"owner: service account ci-bot (svc_acct_ci)".to_owned()));
    assert_eq!(p.manual_revoke(Some(&scope)), None);
    p.revoke(&cred(&leaked)).await.unwrap();
    let mutations: Vec<String> = rec
        .calls()
        .await
        .iter()
        .filter(|c| c.mutating)
        .map(|c| format!("{} {}", c.method, c.path))
        .collect();
    assert_eq!(mutations, [format!("DELETE {at}")]);
}

#[tokio::test]
async fn revoke_replacement_deletes_service_account() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let at = "/v1/organization/projects/proj_b/service_accounts/svc_acct_new";
    mount_delete(&rec, at, 200).await;
    let p = automatic(&rec, &admin);
    p.revoke_replacement("openai:proj_b:svc_acct_new:key_new")
        .await
        .unwrap();
    p.revoke_replacement("openai:proj_b:svc_acct_new:key_new")
        .await
        .unwrap();
    let deletes = requests(&rec).await;
    assert_eq!(deletes.len(), 2);
    assert!(deletes
        .iter()
        .all(|(t, a)| *t == format!("DELETE {at}") && *a == bearer(&admin)));
    assert!(matches!(
        p.revoke_replacement("manual").await,
        Err(ProviderError::Permanent(_))
    ));
    assert_eq!(rec.calls().await.len(), 2);
}

// T8 (AC8), through wiremock: no call.
#[tokio::test]
async fn restore_unsupported_without_calls() {
    let rec = CallRecorder::start().await;
    assert_eq!(
        automatic(&rec, &admin_key())
            .restore("anything")
            .await
            .unwrap(),
        RestoreOutcome::Unsupported
    );
    assert!(rec.calls().await.is_empty());
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

/// One leaked key, one consumer holding it, planned with ids assigned.
struct Pipeline {
    dir: tempfile::TempDir,
    providers: ProviderRegistry,
    consumers: ConsumerRegistry,
    gha: Arc<MockConsumer>,
    store: StateStore,
    audit: AuditLog,
    plan: plan::Plan,
}

async fn pipeline(p: OpenAiProvider, leaked: &str) -> Pipeline {
    pipeline_with(p, leaked, "0s").await
}

/// [`pipeline`] with an overlap window.
async fn pipeline_with(p: OpenAiProvider, leaked: &str, overlap: &str) -> Pipeline {
    let dir = tempfile::tempdir().unwrap();
    let mut providers = ProviderRegistry::new();
    providers.register(Arc::new(p));
    let gha = Arc::new(MockConsumer::new("github-actions").matching(
        SecretValue::from(leaked).fingerprint(),
        ConsumerMatch::by_value("gha:acme/app:OPENAI_API_KEY"),
    ));
    let mut consumers = ConsumerRegistry::new();
    consumers.register(gha.clone());
    let assessed = assess::assess(vec![finding(leaked)], &providers, &fast_opts()).await;
    let mut built = plan::build(
        assessed,
        &providers,
        &consumers,
        overlap.parse().unwrap(),
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
// call to OpenAI (NFR3), with or without an admin key.
#[tokio::test]
async fn plan_makes_no_state_changing_calls() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "plandr");
    mount_models(&rec, &leaked, 200, Some("org-acme")).await;
    mount_org(&rec, &admin, &leaked, vec![]).await;
    mount_create(&rec, "proj_b", "svc_acct_new", &key(SVC, "plannw")).await;
    mount_delete(
        &rec,
        "/v1/organization/projects/proj_b/api_keys/key_leak",
        200,
    )
    .await;

    let p = pipeline(automatic(&rec, &admin), &leaked).await;
    let table = plan::render_table(&p.plan);
    let json = plan::render_json(&p.plan);
    assert!(table.contains("proj_b"), "{table}");
    assert!(
        table.contains("delete the API key (OpenAI Admin API)"),
        "{table}"
    );
    assert!(json.contains("\"mode\": \"automatic\""), "{json}");
    let calls = rec.calls().await;
    assert!(
        calls.iter().any(|c| c.path == "/v1/models"),
        "plan checked validity: {calls:?}"
    );
    rec.assert_no_mutations().await;

    let p = pipeline(manual(&rec), &leaked).await;
    let table = plan::render_table(&p.plan);
    assert!(table.contains(REVOKE_NEEDS_ADMIN), "{table}");
    assert!(table.contains(MANUAL_REVOKE_BLOCKER), "{table}");
    assert!(
        table.contains("scope unavailable: set OPENAI_ADMIN_KEY") || table.contains("org-acme")
    );
    rec.assert_no_mutations().await;
}

// T7 (AC7): a service-account key whose account holds other keys cannot be
// deleted through the Admin API. The plan's revoke row says to delete it at
// the dashboard, and apply rotates the consumer but makes no DELETE.
#[tokio::test]
async fn undeletable_key_plan_row_and_no_delete_after_apply() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(SVC, "t7leak");
    let fresh = key(SVC, "t7new0");
    mount_models(&rec, &leaked, 200, None).await;
    mount_models(&rec, &fresh, 200, None).await;
    mount_org(
        &rec,
        &admin,
        &key(PROJ, "t7user"),
        vec![
            account_key("key_svc", "svc_acct_ci", &leaked),
            account_key("key_svc2", "svc_acct_ci", &key(SVC, "t7sib0")),
            account_key("key_new", "svc_acct_new", &fresh),
        ],
    )
    .await;
    mount_create(&rec, "proj_b", "svc_acct_new", &fresh).await;

    let mut p = pipeline(automatic(&rec, &admin), &leaked).await;
    let rotation = &p.plan.rotations[0];
    assert_eq!(rotation.revoke_action, REVOKE_UNDELETABLE);
    assert!(rotation
        .blockers
        .contains(&MANUAL_REVOKE_BLOCKER.to_owned()));
    let table = plan::render_table(&p.plan);
    assert!(table.contains("platform.openai.com/api-keys"), "{table}");
    assert!(
        table.contains(&UNDELETABLE_WARNING["warning: ".len()..]),
        "{table}"
    );
    let json = plan::render_json(&p.plan);
    assert!(json.contains(REVOKE_UNDELETABLE), "{json}");

    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .run(&p.plan.rotations[0])
        .await;
    // SHA-289: a revoke rotate cannot do ends at revoke_manual, not failed.
    match &outcome.result {
        RunResult::RevokeManual { instructions } => {
            assert_eq!(instructions.as_str(), REVOKE_UNDELETABLE);
        }
        other => panic!("expected a revoke by hand, got {other:?}"),
    }
    assert_eq!(
        p.store
            .get(&p.plan.rotations[0].rotation_id)
            .unwrap()
            .revoke_instructions
            .as_deref(),
        Some(REVOKE_UNDELETABLE)
    );
    assert_eq!(
        p.gha.current("gha:acme/app:OPENAI_API_KEY"),
        Some(SecretValue::from(fresh.as_str()).fingerprint()),
        "the consumer holds the replacement"
    );
    let calls = rec.calls().await;
    assert!(
        !calls.iter().any(|c| c.method == "DELETE"),
        "apply attempted a DELETE: {calls:?}"
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

// T9 (AC2, AC5, AC6): plan and a full automatic apply. The leaked, the new
// and the admin key appear in no table, JSON, summary, terminal text, log,
// audit entry, state file or outcome. On the wire the leaked and the new
// key sign only `GET /v1/models` and the admin key only Admin API calls;
// no request body or URL holds any of them.
#[tokio::test]
async fn keys_never_in_output_logs_audit_or_state() {
    let capture = trace_capture();
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "t9leak");
    let fresh = key(SVC, "t9new0");
    mount_models(&rec, &leaked, 200, None).await;
    mount_models(&rec, &fresh, 200, None).await;
    mount_org(
        &rec,
        &admin,
        &leaked,
        vec![account_key("key_new", "svc_acct_new", &fresh)],
    )
    .await;
    mount_create(&rec, "proj_b", "svc_acct_new", &fresh).await;
    mount_delete(
        &rec,
        "/v1/organization/projects/proj_b/api_keys/key_leak",
        200,
    )
    .await;

    let mut p = pipeline(automatic(&rec, &admin), &leaked).await;
    let table = plan::render_table(&p.plan);
    let plan_json = plan::render_json(&p.plan);
    let mut term = Term::default();
    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .with_manual(ReplacementSource::Supplied(None), &mut term)
        .run(&p.plan.rotations[0])
        .await;
    assert!(
        matches!(outcome.result, RunResult::Revoked),
        "{:?}",
        outcome.result
    );
    assert_eq!(
        p.gha.current("gha:acme/app:OPENAI_API_KEY"),
        Some(SecretValue::from(fresh.as_str()).fingerprint())
    );

    let summary = apply::render_summary(std::slice::from_ref(&outcome));
    let audit = std::fs::read_to_string(p.dir.path().join("audit.jsonl")).unwrap();
    let state = std::fs::read_to_string(p.dir.path().join("state.json")).unwrap();
    assert!(audit.contains(&SecretValue::from(fresh.as_str()).fingerprint().to_string()));
    assert!(
        state.contains("openai:proj_b:svc_acct_new:key_new"),
        "{state}"
    );
    let logs = capture.contents();
    assert!(!logs.is_empty(), "the TRACE capture saw nothing");
    for (who, value) in [("leaked", &leaked), ("new", &fresh), ("admin", &admin)] {
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
            assert!(!text.contains(value.as_str()), "{who} key in {label}");
            // Not even OpenAI's redacted form of it.
            assert!(
                !text.contains(&redacted(value)),
                "{who} redacted key in {label}"
            );
        }
    }

    for req in rec.server().received_requests().await.unwrap() {
        let target = format!("{} {}", req.method, req.url.path());
        let body = String::from_utf8_lossy(&req.body);
        let url = req.url.to_string();
        let auth = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        for value in [&leaked, &fresh, &admin] {
            assert!(!body.contains(value.as_str()), "a key in the {target} body");
            assert!(!url.contains(value.as_str()), "a key in the {target} URL");
            for (name, header) in &req.headers {
                if name.as_str() != "authorization" {
                    assert!(!header.to_str().unwrap_or("").contains(value.as_str()));
                }
            }
        }
        if auth == bearer(&leaked) || auth == bearer(&fresh) {
            assert_eq!(target, "GET /v1/models", "a rotated key signed {target}");
        } else {
            assert_eq!(auth, bearer(&admin), "{target} signed with an unknown key");
            assert!(
                req.url.path().starts_with("/v1/organization/"),
                "the admin key signed {target}"
            );
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

const ALWAYS: [&str; 7] = [
    "identify_rejects_foreign",
    "check_valid_unknown_invalid",
    "read_only_check_valid",
    "read_only_describe_scope",
    "read_only_verify",
    "verify_wrong_identity_fails",
    "errors_redacted",
];

// T10 (AC1 to AC8): the shared provider suite with an admin key.
#[tokio::test]
async fn conformance_automatic_mode() {
    let report = provider_suite(|| async {
        let rec = CallRecorder::start().await;
        let admin = admin_key();
        let live = key(PROJ, "t10liv");
        let unknown = key(PROJ, "t10unk");
        let fresh = key(SVC, "t10new");
        mount_models(&rec, &live, 200, None).await;
        mount_models(&rec, &unknown, 401, None).await;
        mount_models(&rec, &fresh, 200, None).await;
        mount_projects(&rec, &admin, &[("proj_c", "Conformance")]).await;
        mount_keys(
            &rec,
            &admin,
            "proj_c",
            vec![
                user_key("key_live", "live", &live),
                account_key("key_new", "svc_acct_new", &fresh),
            ],
        )
        .await;
        mount_create(&rec, "proj_c", "svc_acct_new", &fresh).await;
        mount_delete(
            &rec,
            "/v1/organization/projects/proj_c/api_keys/key_live",
            200,
        )
        .await;
        ProviderFixture {
            provider: Arc::new(automatic(&rec, &admin)),
            live: cred(&live),
            identity: Identity("proj_c".into()),
            unknown: cred(&unknown),
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await;
    assert_eq!(report.plugin, "openai");
    report.assert_ok();
    for name in ALWAYS.iter().chain(&[
        "replacement_differs",
        "idempotent_revoke",
        "restore_outcome",
    ]) {
        assert_eq!(
            report.outcome(name),
            Some(&Outcome::Passed),
            "{name}: {report}"
        );
    }
}

// T10 (AC1 to AC8): the shared provider suite without an admin key.
#[tokio::test]
async fn conformance_manual_mode() {
    let report = provider_suite(|| async {
        let rec = CallRecorder::start().await;
        let live = key(PROJ, "t10mlv");
        let unknown = key(PROJ, "t10muk");
        mount_models(&rec, &live, 200, Some("org-conf")).await;
        mount_models(&rec, &unknown, 401, None).await;
        ProviderFixture {
            provider: Arc::new(manual(&rec)),
            live: cred(&live),
            identity: Identity("org-conf".into()),
            unknown: cred(&unknown),
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await;
    assert_eq!(report.plugin, "openai");
    report.assert_ok();
    for name in ALWAYS {
        assert_eq!(
            report.outcome(name),
            Some(&Outcome::Passed),
            "{name}: {report}"
        );
    }
    for name in [
        "replacement_differs",
        "idempotent_revoke",
        "restore_outcome",
    ] {
        assert!(
            matches!(report.outcome(name), Some(Outcome::Skipped(_))),
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

// Live, read-only: a real key from the environment is valid; with an admin
// key its scope names a project.
#[tokio::test]
#[ignore]
async fn live_openai_check_valid_and_scope() {
    common::live_guard!();
    let Some(value) = live_env("ROTATE_LIVE_OPENAI_KEY") else {
        return;
    };
    let admin = match common::require_env("OPENAI_ADMIN_KEY") {
        Some(admin) => AdminKey::Value(SecretValue::from(admin)),
        None => AdminKey::None,
    };
    let p = OpenAiProvider::new("https://api.openai.com", admin);
    let credential = cred(&value);
    assert_eq!(p.check_valid(&credential).await.unwrap(), Validity::Valid);
    let scope = p.describe_scope(&credential).await.unwrap();
    assert!(!scope.identity.0.is_empty());
    p.verify(&credential, &scope.identity).await.unwrap();
}

// Live, state-changing: with an admin key, creates a service account in the
// key's project, verifies its key, then deletes the service account with
// `revoke_replacement`. The key under test is never revoked.
#[tokio::test]
#[ignore]
async fn live_openai_replacement_cycle() {
    common::live_guard!();
    let (Some(value), Some(admin)) = (
        live_env("ROTATE_LIVE_OPENAI_KEY"),
        live_env("OPENAI_ADMIN_KEY"),
    ) else {
        return;
    };
    let p = OpenAiProvider::new(
        "https://api.openai.com",
        AdminKey::Value(SecretValue::from(admin)),
    );
    let credential = cred(&value);
    let scope = p.describe_scope(&credential).await.unwrap();
    let replacement = p.create_replacement(&credential).await.unwrap();
    let verified = p.verify(&replacement.credential, &scope.identity).await;
    p.revoke_replacement(&replacement.replacement_ref)
        .await
        .unwrap();
    verified.unwrap();
}

// SHA-291: an admin key no longer means an automatic, broader replacement.

/// The audit log's `create` entries.
fn create_entries(dir: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["step"] == "create")
        .collect()
}

/// No text holds any of `values`, nor OpenAI's redacted form of them.
fn assert_absent(values: &[(&str, &str)], texts: &[(&str, &str)]) {
    for (who, value) in values {
        for (label, text) in texts {
            assert!(!text.contains(value), "{who} key in {label}");
            assert!(
                !text.contains(&redacted(value)),
                "{who} redacted key in {label}"
            );
        }
    }
}

// SHA-291 T1 (AC1): admin key, no opt-in. The replacement row says the
// replacement would get all permissions, the mode is manual, there is no
// blocker for it, and the plan makes no service-accounts POST.
#[tokio::test]
async fn sha291_t1_no_opt_in_plans_manual_without_post() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "w1leak");
    mount_models(&rec, &leaked, 200, None).await;
    mount_org(&rec, &admin, &leaked, vec![]).await;
    mount_create(&rec, "proj_b", "svc_acct_new", &key(SVC, "w1new0")).await;

    let p = pipeline(admin_only(&rec, &admin), &leaked).await;
    let rotation = &p.plan.rotations[0];
    assert_eq!(rotation.replacement_mode, ReplacementMode::Manual);
    assert_eq!(rotation.scope_widening, Some(SCOPE_WIDENING_NOTE));
    assert_eq!(rotation.widens_scope(), None);
    assert!(rotation.blockers.is_empty(), "{:?}", rotation.blockers);
    let table = plan::render_table(&p.plan);
    let row = table
        .lines()
        .find(|l| l.trim_start().starts_with("replacement:"))
        .unwrap();
    assert!(row.contains("manual: you will be asked to paste"), "{row}");
    assert!(row.contains("all permissions"), "{row}");
    assert!(row.contains("--allow-broader-replacement"), "{row}");
    assert!(!table.contains("scope widening:"), "{table}");
    let json: serde_json::Value = serde_json::from_str(&plan::render_json(&p.plan)).unwrap();
    let replacement = &json["rotations"][0]["replacement"];
    assert_eq!(replacement["mode"], "manual");
    assert!(replacement["action"]
        .as_str()
        .unwrap()
        .contains("all permissions"));
    assert!(replacement["scope_widening"].is_null());

    let calls = rec.calls().await;
    assert!(
        !calls
            .iter()
            .any(|c| c.method == "POST" && c.path.ends_with("/service_accounts")),
        "{calls:?}"
    );
    rec.assert_no_mutations().await;
}

// SHA-291 T2 (AC2), library half: with the opt-in the mode is automatic,
// the note is shown on its own line and in JSON, and nothing blocks.
#[tokio::test]
async fn sha291_t2_opt_in_plans_automatic_with_note() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "w2leak");
    mount_models(&rec, &leaked, 200, None).await;
    mount_org(&rec, &admin, &leaked, vec![]).await;

    let p = pipeline(automatic(&rec, &admin), &leaked).await;
    let rotation = &p.plan.rotations[0];
    assert_eq!(rotation.replacement_mode, ReplacementMode::Automatic);
    assert_eq!(rotation.widens_scope(), Some(SCOPE_WIDENING_NOTE));
    assert!(rotation.blockers.is_empty(), "{:?}", rotation.blockers);
    let table = plan::render_table(&p.plan);
    assert!(
        table.contains(&format!("  scope widening: {SCOPE_WIDENING_NOTE}\n")),
        "{table}"
    );
    assert!(table.contains("create a new openai credential for proj_b"));
    assert!(!table.contains("blockers:"), "{table}");
    let json: serde_json::Value = serde_json::from_str(&plan::render_json(&p.plan)).unwrap();
    assert_eq!(json["rotations"][0]["replacement"]["mode"], "automatic");
    assert_eq!(
        json["rotations"][0]["replacement"]["scope_widening"],
        SCOPE_WIDENING_NOTE
    );
    assert_eq!(json["rotations"][0]["blockers"], serde_json::json!([]));
    rec.assert_no_mutations().await;
}

// SHA-291 T3 (AC3): apply with the opt-in creates the service account as
// before, and the create audit entry records `scope_widened: true`.
#[tokio::test]
async fn sha291_t3_opt_in_apply_posts_and_audits_scope_widened() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "w3leak");
    let fresh = key(SVC, "w3new0");
    mount_models(&rec, &leaked, 200, None).await;
    mount_models(&rec, &fresh, 200, None).await;
    mount_org(
        &rec,
        &admin,
        &leaked,
        vec![account_key("key_new", "svc_acct_new", &fresh)],
    )
    .await;
    mount_create(&rec, "proj_b", "svc_acct_new", &fresh).await;
    mount_delete(
        &rec,
        "/v1/organization/projects/proj_b/api_keys/key_leak",
        200,
    )
    .await;

    let mut p = pipeline(automatic(&rec, &admin), &leaked).await;
    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .run(&p.plan.rotations[0])
        .await;
    assert!(
        matches!(outcome.result, RunResult::Revoked),
        "{:?}",
        outcome.result
    );
    let calls = rec.calls().await;
    let posts: Vec<_> = calls.iter().filter(|c| c.method == "POST").collect();
    assert_eq!(posts.len(), 1, "{calls:?}");
    assert_eq!(
        posts[0].path,
        "/v1/organization/projects/proj_b/service_accounts"
    );
    let creates = create_entries(p.dir.path());
    assert_eq!(creates.len(), 1, "{creates:?}");
    assert_eq!(creates[0]["outcome"], "ok");
    assert_eq!(creates[0]["replacement_mode"], "automatic");
    assert_eq!(creates[0]["scope_widened"], true);
}

/// T4's setup: admin key, no opt-in, and a restricted key `fresh` the
/// operator made in the same project.
async fn manual_with_admin(rec: &CallRecorder, admin: &str, leaked: &str, fresh: &str) {
    mount_models(rec, leaked, 200, None).await;
    mount_models(rec, fresh, 200, None).await;
    mount_org(
        rec,
        admin,
        leaked,
        vec![user_key("key_fresh", "backend prod restricted", fresh)],
    )
    .await;
    mount_create(rec, "proj_b", "svc_acct_new", &key(SVC, "w4svc0")).await;
    mount_delete(
        rec,
        "/v1/organization/projects/proj_b/api_keys/key_leak",
        200,
    )
    .await;
}

// SHA-291 T4 (AC4): without the opt-in, apply prints instructions naming
// the project, the leaked key's name and the keys page where restricted
// keys are made, takes the pasted key, verifies it is in the same project,
// and never creates a service account.
#[tokio::test]
async fn sha291_t4_manual_instructions_name_project_key_and_page() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "w4leak");
    let fresh = key(PROJ, "w4new0");
    manual_with_admin(&rec, &admin, &leaked, &fresh).await;

    let mut p = pipeline(admin_only(&rec, &admin), &leaked).await;
    let mut term = Term::default();
    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .with_manual(
            ReplacementSource::Supplied(Some(SecretValue::from(fresh.as_str()))),
            &mut term,
        )
        .run(&p.plan.rotations[0])
        .await;
    assert!(
        matches!(outcome.result, RunResult::Revoked),
        "{:?}",
        outcome.result
    );
    for needle in [
        "Backend (proj_b)",
        "backend prod (key_leak)",
        KEYS_PAGE,
        "Restricted",
        "same permissions",
        "--allow-broader-replacement",
    ] {
        assert!(term.out.contains(needle), "{needle} not in: {}", term.out);
    }
    let calls = rec.calls().await;
    assert!(!calls.iter().any(|c| c.method == "POST"), "{calls:?}");
    let creates = create_entries(p.dir.path());
    assert_eq!(creates[0]["replacement_mode"], "manual");
    assert!(creates[0].get("scope_widened").is_none(), "{creates:?}");
    assert_eq!(
        p.gha.current("gha:acme/app:OPENAI_API_KEY"),
        Some(SecretValue::from(fresh.as_str()).fingerprint())
    );
}

// SHA-291 T5 (AC5): the scope-widening note is in
// `replacement.scope_widening`, which `docs/plan-schema.json` documents,
// and the document validates against the schema.
#[tokio::test]
async fn sha291_t5_scope_widening_field_is_in_the_schema() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "w5leak");
    mount_models(&rec, &leaked, 200, None).await;
    mount_org(&rec, &admin, &leaked, vec![]).await;
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../docs/plan-schema.json")).unwrap();
    let field =
        &schema["$defs"]["rotation"]["properties"]["replacement"]["properties"]["scope_widening"];
    assert_eq!(field["type"], serde_json::json!(["string", "null"]));
    assert!(field["description"].as_str().unwrap().len() > 20);
    let validator = jsonschema::validator_for(&schema).unwrap();
    for provider in [automatic(&rec, &admin), admin_only(&rec, &admin)] {
        let p = pipeline(provider, &leaked).await;
        let json: serde_json::Value = serde_json::from_str(&plan::render_json(&p.plan)).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&json)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        let note = &json["rotations"][0]["replacement"]["scope_widening"];
        match p.plan.rotations[0].replacement_mode {
            ReplacementMode::Automatic => assert_eq!(note, SCOPE_WIDENING_NOTE),
            ReplacementMode::Manual => assert!(note.is_null()),
        }
    }
}

// SHA-291 T6 (AC1, AC3, AC4): the T1 plan, the T3 automatic apply and the
// T4 manual apply, with canary leaked, new, pasted and admin keys. None of
// them, nor OpenAI's redacted form, is in a table, JSON, terminal text,
// summary, outcome, TRACE log, audit log or state file.
#[tokio::test]
async fn sha291_t6_no_key_in_any_output() {
    let capture = trace_capture();
    let admin = admin_key();

    // T1 and T4: no opt-in.
    let rec = CallRecorder::start().await;
    let leaked = key(PROJ, "w6leak");
    let pasted = key(PROJ, "w6past");
    manual_with_admin(&rec, &admin, &leaked, &pasted).await;
    let mut manual_run = pipeline(admin_only(&rec, &admin), &leaked).await;
    let manual_table = plan::render_table(&manual_run.plan);
    let manual_json = plan::render_json(&manual_run.plan);
    let mut term = Term::default();
    let manual_outcome = Executor::new(
        &manual_run.providers,
        &manual_run.consumers,
        &mut manual_run.store,
        &mut manual_run.audit,
    )
    .with_manual(
        ReplacementSource::Supplied(Some(SecretValue::from(pasted.as_str()))),
        &mut term,
    )
    .run(&manual_run.plan.rotations[0])
    .await;
    assert!(matches!(manual_outcome.result, RunResult::Revoked));

    // T3: opt-in.
    let rec = CallRecorder::start().await;
    let leaked_auto = key(PROJ, "w6aleak");
    let fresh = key(SVC, "w6anew0");
    mount_models(&rec, &leaked_auto, 200, None).await;
    mount_models(&rec, &fresh, 200, None).await;
    mount_org(
        &rec,
        &admin,
        &leaked_auto,
        vec![account_key("key_new", "svc_acct_new", &fresh)],
    )
    .await;
    mount_create(&rec, "proj_b", "svc_acct_new", &fresh).await;
    mount_delete(
        &rec,
        "/v1/organization/projects/proj_b/api_keys/key_leak",
        200,
    )
    .await;
    let mut auto_run = pipeline(automatic(&rec, &admin), &leaked_auto).await;
    let auto_table = plan::render_table(&auto_run.plan);
    let auto_outcome = Executor::new(
        &auto_run.providers,
        &auto_run.consumers,
        &mut auto_run.store,
        &mut auto_run.audit,
    )
    .run(&auto_run.plan.rotations[0])
    .await;
    assert!(matches!(auto_outcome.result, RunResult::Revoked));

    let read = |run: &Pipeline, name: &str| {
        std::fs::read_to_string(run.dir.path().join(name)).unwrap_or_default()
    };
    let manual_audit = read(&manual_run, "audit.jsonl");
    let auto_audit = read(&auto_run, "audit.jsonl");
    assert!(!manual_audit.is_empty() && !auto_audit.is_empty());
    let summary = apply::render_summary(&[manual_outcome.clone(), auto_outcome.clone()]);
    let logs = capture.contents();
    assert!(!logs.is_empty(), "the TRACE capture saw nothing");
    let texts = [
        ("manual plan table", manual_table),
        ("manual plan json", manual_json),
        ("automatic plan table", auto_table),
        ("stdout", term.out.clone()),
        ("stderr", term.err.clone()),
        ("summary", summary),
        ("outcomes", format!("{manual_outcome:?}{auto_outcome:?}")),
        ("manual audit log", manual_audit),
        ("manual state file", read(&manual_run, "state.json")),
        ("automatic audit log", auto_audit),
        ("automatic state file", read(&auto_run, "state.json")),
        ("logs", logs),
    ];
    let texts: Vec<(&str, &str)> = texts.iter().map(|(l, t)| (*l, t.as_str())).collect();
    assert_absent(
        &[
            ("leaked", &leaked),
            ("pasted", &pasted),
            ("automatic leaked", &leaked_auto),
            ("new", &fresh),
            ("admin", &admin),
        ],
        &texts,
    );
}

/// Runs the binary with the real plugins against `rec` (SHA-264), the
/// admin key in the environment and `extra_yaml` added to the OpenAI
/// provider settings in `rotate.yaml`.
#[cfg(all(unix, feature = "test-providers"))]
fn run_binary(
    dir: &std::path::Path,
    rec: &CallRecorder,
    extra_yaml: &str,
    args: &[&str],
    secrets: (&str, &str),
) -> std::process::Output {
    const ADMIN_ENV: &str = "ROTATE_SHA291_OPENAI_ADMIN";
    let (admin, leaked) = secrets;
    std::fs::write(
        dir.join("rotate.yaml"),
        format!(
            "providers:\n  openai:\n    api_url: {}\n    admin_key_env: {ADMIN_ENV}\n{extra_yaml}",
            rec.uri()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("scenario.json"),
        serde_json::json!({ "real_plugins": true, "prompt": "panic" }).to_string(),
    )
    .unwrap();
    assert_cmd::Command::cargo_bin("rotate")
        .unwrap()
        .current_dir(dir)
        .env_clear()
        .env("HOME", dir)
        .env("ROTATE_TEST_SCENARIO", dir.join("scenario.json"))
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env(ADMIN_ENV, admin)
        .args(args)
        .write_stdin(format!("{leaked}\n"))
        .output()
        .unwrap()
}

// SHA-291 T1 and T2 (AC1, AC2) through the binary: no opt-in plans a
// manual replacement; the opt-in by rotate.yaml, then by the flag, plans an
// automatic one with the note and no blocker. No run makes a
// state-changing call, and neither key reaches stdout, stderr (at -vvv) or
// the state file.
#[cfg(all(unix, feature = "test-providers"))]
#[tokio::test(flavor = "multi_thread")]
async fn sha291_t2_opt_in_by_config_and_by_flag_through_the_binary() {
    let rec = CallRecorder::start().await;
    let admin = admin_key();
    let leaked = key(PROJ, "w2bin0");
    mount_models(&rec, &leaked, 200, None).await;
    mount_org(&rec, &admin, &leaked, vec![]).await;
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../docs/plan-schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    let cases: [(&str, &str, &[&str]); 3] = [
        ("no opt-in", "", &[]),
        ("config", "    allow_broader_replacement: true\n", &[]),
        ("flag", "", &["--allow-broader-replacement"]),
    ];
    for (case, yaml, flag) in cases {
        let dir = tempfile::tempdir().unwrap();
        let mut args = vec!["-vvv", "--json", "plan", "--stdin", "--provider", "openai"];
        args.extend_from_slice(flag);
        let output = run_binary(dir.path(), &rec, yaml, &args, (&admin, &leaked));
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert_eq!(output.status.code(), Some(0), "{case}: {stdout}{stderr}");
        let plan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&plan)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{case}: {errors:?}");
        let rotation = &plan["rotations"][0];
        assert_eq!(rotation["blockers"], serde_json::json!([]), "{case}");
        let replacement = &rotation["replacement"];
        if case == "no opt-in" {
            assert_eq!(replacement["mode"], "manual", "{case}");
            assert!(replacement["scope_widening"].is_null(), "{case}");
            assert!(replacement["action"]
                .as_str()
                .unwrap()
                .contains("all permissions"));
        } else {
            assert_eq!(replacement["mode"], "automatic", "{case}");
            assert_eq!(replacement["scope_widening"], SCOPE_WIDENING_NOTE, "{case}");
        }
        args.retain(|a| *a != "--json");
        let table = run_binary(dir.path(), &rec, yaml, &args, (&admin, &leaked));
        let table_out = String::from_utf8_lossy(&table.stdout).into_owned();
        let table_err = String::from_utf8_lossy(&table.stderr).into_owned();
        assert_eq!(table.status.code(), Some(0), "{case}: {table_err}");
        assert_eq!(
            table_out.contains("scope widening:"),
            case != "no opt-in",
            "{case}: {table_out}"
        );
        let state = std::fs::read_to_string(dir.path().join(".rotate/state.json")).unwrap();
        assert_absent(
            &[("leaked", &leaked), ("admin", &admin)],
            &[
                ("stdout", &stdout),
                ("stderr", &stderr),
                ("table stdout", &table_out),
                ("table stderr", &table_err),
                ("state file", &state),
            ],
        );
    }
    let calls = rec.calls().await;
    assert!(
        calls.iter().any(|c| c.path == "/v1/organization/projects"),
        "the plans listed projects: {calls:?}"
    );
    rec.assert_no_mutations().await;
}

fn two_hours_later() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::hours(2)
}

// SHA-298 T1 (AC1), T3 (AC3): a manual rotation planned and applied with
// an Admin API key reaches pending_revoke; a new executor (which never
// held the replacement) resumes it after the window with a different
// operator setup. Without an Admin API key it is a revoke by hand naming
// the key and the keys page; with the leaked key as the Admin API key it
// fails with the safe summary plus rotate's guidance. No value reaches the
// result, the audit log, the state file or the terminal, and nothing is
// deleted.
#[tokio::test]
async fn sha298_t1_resumed_revoke_keeps_admin_key_guidance() {
    for case in ["no admin key", "admin key is the leaked key"] {
        let rec = CallRecorder::start().await;
        let admin = admin_key();
        let leaked = key(PROJ, "g1leak");
        let fresh = key(PROJ, "g1new0");
        manual_with_admin(&rec, &admin, &leaked, &fresh).await;
        let mut p = pipeline_with(admin_only(&rec, &admin), &leaked, "1h").await;
        let mut term = Term::default();
        let first = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_manual(
                ReplacementSource::Supplied(Some(SecretValue::from(fresh.as_str()))),
                &mut term,
            )
            .run(&p.plan.rotations[0])
            .await;
        assert!(
            matches!(first.result, RunResult::PendingRevoke { .. }),
            "{case}: {:?}",
            first.result
        );

        let later = match case {
            "no admin key" => manual(&rec),
            _ => OpenAiProvider::new(
                &rec.uri(),
                AdminKey::Value(SecretValue::from(leaked.as_str())),
            )
            .with_verify_delay(Duration::ZERO),
        };
        let mut resumed = ProviderRegistry::new();
        resumed.register(Arc::new(later));
        let outcome = Executor::new(&resumed, &p.consumers, &mut p.store, &mut p.audit)
            .with_clock(two_hours_later)
            .run(&p.plan.rotations[0])
            .await;
        let stored = p.store.get(&outcome.rotation_id).unwrap().clone();
        let text = match (&outcome.result, case) {
            (RunResult::RevokeManual { instructions }, "no admin key") => {
                assert_eq!(
                    stored.revoke_instructions.as_deref(),
                    Some(instructions.as_str())
                );
                instructions.as_str().to_owned()
            }
            (RunResult::Failed { error, .. }, "admin key is the leaked key") => {
                let error = error.to_string();
                assert!(error.contains("provider message not kept"), "{error}");
                error
            }
            (other, _) => panic!("{case}: unexpected {other:?}"),
        };
        let guidance = match case {
            "no admin key" => REVOKE_NEEDS_ADMIN,
            _ => GUIDE_ADMIN_IS_LEAKED,
        };
        assert!(text.contains(guidance), "{case}: {text}");
        assert!(text.contains("Admin API key"), "{case}: {text}");
        let audit = std::fs::read_to_string(p.dir.path().join("audit.jsonl")).unwrap();
        let last: serde_json::Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(last["step"], "revoke", "{case}: {last}");
        assert!(
            audit.lines().last().unwrap().contains(guidance),
            "{case}: {last}"
        );
        let state = std::fs::read_to_string(p.dir.path().join("state.json")).unwrap();
        for value in [&leaked, &fresh, &admin] {
            for (place, text) in [
                ("result", format!("{:?}", outcome.result)),
                ("audit", audit.clone()),
                ("state", state.clone()),
                ("terminal", format!("{}{}", term.out, term.err)),
            ] {
                assert!(
                    !text.contains(value.as_str()),
                    "{case}: a value in the {place}"
                );
            }
        }
        let calls = rec.calls().await;
        assert!(
            !calls.iter().any(|c| c.method == "DELETE"),
            "{case}: {calls:?}"
        );
    }
}
