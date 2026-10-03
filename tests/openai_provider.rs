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
    AdminKey, OpenAiProvider, PERMISSIONS_NOTE, REVOKE_NEEDS_ADMIN, REVOKE_UNDELETABLE,
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

fn automatic(rec: &CallRecorder, admin: &str) -> OpenAiProvider {
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
        ProviderError::Unsupported(REVOKE_NEEDS_ADMIN.into())
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
    match &outcome.result {
        RunResult::Failed { step, error } => {
            assert_eq!(*step, rotate::audit::AuditStep::Revoke);
            assert!(
                error.to_string().contains("platform.openai.com/api-keys"),
                "{error}"
            );
        }
        other => panic!("expected the revoke step to stop, got {other:?}"),
    }
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
