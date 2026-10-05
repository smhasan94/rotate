//! npm token provider (SHA-261) against a wiremock npm registry.
//!
//! Every registry read is a GET; the one state-changing call is `DELETE
//! /-/npm/v1/tokens/token/{key}`, so the recorder's default (DELETE is
//! mutating) is exactly right. Tokens are built at runtime with unique tags
//! so no literal matches a secret scanner and every test can search for its
//! own values.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, ResponseTemplate};

use rotate::apply::{
    self, Executor, Prompt, PromptError, PromptOtp, ReplacementSource, RunResult, ScriptedPrompt,
    Terminal,
};
use rotate::assess::{self, AssessOptions};
use rotate::audit::AuditLog;
use rotate::config::ConsumersConfig;
use rotate::conformance::{provider_suite, MutationProbe, Outcome, ProviderFixture};
use rotate::consumer::mock::MockConsumer;
use rotate::consumer::{ConsumerMatch, ConsumerRegistry};
use rotate::finding::{Finding, SourceLocation};
use rotate::plan;
use rotate::provider::npm::{
    token_key, NpmProvider, GUIDE_NO_OPERATOR, GUIDE_OPERATOR_IS_LEAKED, GUIDE_OTHER_USER,
    GUIDE_OTP, GUIDE_OTP_REJECTED, GUIDE_SESSION_TOKEN, NOT_VISIBLE,
};
use rotate::provider::otp::{Chain, EnvOtp, OtpError, OtpSource};
use rotate::provider::{
    Credential, Identity, Provider, ProviderError, ProviderRegistry, ReplacementMode,
    RestoreOutcome, Validity,
};
use rotate::secret::SecretValue;
use rotate::state::StateStore;

use common::CallRecorder;

const LIST_PATH: &str = "/-/npm/v1/tokens";
const UUID: &str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

/// An npm token carrying `tag` (letters and digits only), padded to the
/// real length: `npm_` plus 36 alphanumerics.
fn npm_token(tag: &str) -> String {
    assert!(tag.chars().all(|c| c.is_ascii_alphanumeric()));
    let pad = "Zx9".repeat(36);
    format!("{}{tag}{}", ["np", "m_"].concat(), &pad[..36 - tag.len()])
}

/// npm's redacted form: the first 8 and last 4 characters.
fn redacted(value: &str) -> String {
    format!("{}...{}", &value[..8], &value[value.len() - 4..])
}

fn cred(value: &str) -> Credential {
    Credential::Token(SecretValue::from(value))
}

fn bearer(value: &str) -> String {
    format!("Bearer {value}")
}

fn provider(rec: &CallRecorder, operator: Option<&str>) -> NpmProvider {
    NpmProvider::new(&rec.uri()).with_operator_token(operator.map(SecretValue::from))
}

/// `GET /-/whoami` signed with `value` answers `username`.
async fn mount_whoami(rec: &CallRecorder, value: &str, username: &str) {
    Mock::given(method("GET"))
        .and(path("/-/whoami"))
        .and(header("authorization", bearer(value).as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "username": username })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// `GET /-/whoami` signed with `value` answers `status`.
async fn mount_whoami_status(rec: &CallRecorder, value: &str, status: u16) {
    Mock::given(method("GET"))
        .and(path("/-/whoami"))
        .and(header("authorization", bearer(value).as_str()))
        .respond_with(
            ResponseTemplate::new(status)
                .set_body_json(serde_json::json!({ "error": "Unauthorized" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// `GET /-/npm/v1/tokens` signed with `operator` answers `entries`.
async fn mount_list(rec: &CallRecorder, operator: &str, entries: serde_json::Value) {
    let total = entries.as_array().map_or(0, Vec::len);
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .and(header("authorization", bearer(operator).as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "objects": entries,
            "total": total,
            "urls": {}
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
}

async fn mount_delete(rec: &CallRecorder, status: u16) {
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/-/npm/v1/tokens/token/"))
        .respond_with(ResponseTemplate::new(status))
        .with_priority(3)
        .mount(rec.server())
        .await;
}

/// A current granular entry for `value`, matched by its redacted form.
fn granular_entry(value: &str) -> serde_json::Value {
    serde_json::json!({
        "key": UUID,
        "token": redacted(value),
        "name": "ci-publish",
        "readonly": false,
        "bypass_2fa": false,
        "cidr": ["10.0.0.0/8"],
        "permissions": [{ "name": "package", "action": "write" }],
        "scopes": [{ "type": "package", "name": "@acme/app" }],
        "created": "2026-09-01T00:00:00.000Z",
        "expiry": "2026-11-30T00:00:00.000Z",
        "revoked": null
    })
}

/// An unrelated entry.
fn other_entry() -> serde_json::Value {
    serde_json::json!({
        "key": "ffffffff-0000-1111-2222-333333333333",
        "token": "npm_Q0Q0...Q0Q0",
        "readonly": true,
        "created": "2026-01-01T00:00:00.000Z"
    })
}

/// Every DELETE received, as (path, authorization header).
async fn deletes(rec: &CallRecorder) -> Vec<(String, String)> {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .map(|r| {
            (
                r.url.path().to_owned(),
                r.headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap_or("").to_owned())
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// Every request target signed with `value`, as `METHOD path`.
async fn signed_with(rec: &CallRecorder, value: &str) -> Vec<String> {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            r.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == bearer(value))
        })
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

// T2 (AC2): Valid, the username from whoami, and the leaked token signed
// only the read-only whoami.
#[tokio::test]
async fn check_valid_whoami_alice() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("t2Valid");
    let operator = npm_token("t2Oper");
    mount_whoami(&rec, &leaked, "alice").await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    let p = provider(&rec, Some(&operator));

    assert_eq!(
        p.check_valid(&cred(&leaked)).await.unwrap(),
        Validity::Valid
    );
    let scope = p.describe_scope(&cred(&leaked)).await.unwrap();
    assert_eq!(scope.identity, Identity("alice".into()));
    assert_eq!(scope.lines[0], "user: alice");

    let by_leaked = signed_with(&rec, &leaked).await;
    assert_eq!(by_leaked, ["GET /-/whoami", "GET /-/whoami"]);
    assert_eq!(signed_with(&rec, &operator).await, ["GET /-/npm/v1/tokens"]);
    rec.assert_no_mutations().await;
}

// T3 (AC3)
#[tokio::test]
async fn check_valid_401_is_invalid() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("t3Revkd");
    mount_whoami_status(&rec, &leaked, 401).await;
    assert_eq!(
        provider(&rec, None)
            .check_valid(&cred(&leaked))
            .await
            .unwrap(),
        Validity::Invalid
    );
    rec.assert_no_mutations().await;
}

#[tokio::test]
async fn check_valid_other_status_is_unknown_and_5xx_retryable() {
    let rec = CallRecorder::start().await;
    let forbidden = npm_token("t3Forbd");
    mount_whoami_status(&rec, &forbidden, 403).await;
    let busy = npm_token("t3Busy");
    mount_whoami_status(&rec, &busy, 503).await;
    let limited = npm_token("t3Limit");
    Mock::given(method("GET"))
        .and(path("/-/whoami"))
        .and(header("authorization", bearer(&limited).as_str()))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
        .with_priority(2)
        .mount(rec.server())
        .await;
    let p = provider(&rec, None);
    match p.check_valid(&cred(&forbidden)).await.unwrap() {
        Validity::Unknown { reason } => assert!(
            reason.contains("GET /-/whoami") && reason.contains("403"),
            "{reason}"
        ),
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

// T4 (AC4): an entry whose key is the sha512 hex of the leaked token.
#[tokio::test]
async fn describe_scope_legacy_key_match() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("t4Key");
    let operator = npm_token("t4Oper");
    mount_whoami(&rec, &leaked, "alice").await;
    let entry = serde_json::json!({
        "key": token_key(leaked.as_bytes()),
        "token": &leaked[..6],
        "readonly": false,
        "automation": true,
        "cidr_whitelist": ["192.168.0.0/16", "10.1.0.0/16"],
        "created": "2024-05-01T00:00:00.000Z"
    });
    mount_list(&rec, &operator, serde_json::json!([other_entry(), entry])).await;
    let scope = provider(&rec, Some(&operator))
        .describe_scope(&cred(&leaked))
        .await
        .unwrap();
    assert_eq!(
        scope.lines,
        [
            "user: alice",
            "type: automation",
            "access: read-write",
            "automation: true",
            "cidr: 192.168.0.0/16, 10.1.0.0/16",
            "created: 2024-05-01T00:00:00.000Z",
        ]
    );
    rec.assert_no_mutations().await;
}

// T4 (AC4), current scheme: a UUID key and the redacted token.
#[tokio::test]
async fn describe_scope_granular_match() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("t4Gran");
    let operator = npm_token("t4Oper2");
    mount_whoami(&rec, &leaked, "alice").await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([other_entry(), granular_entry(&leaked)]),
    )
    .await;
    let p = provider(&rec, Some(&operator));
    let scope = p.describe_scope(&cred(&leaked)).await.unwrap();
    assert_eq!(
        scope.lines,
        [
            "user: alice",
            "type: granular",
            "name: ci-publish",
            "access: read-write",
            "bypass_2fa: false",
            "cidr: 10.0.0.0/8",
            "permissions: package:write",
            "scopes: package:@acme/app",
            "created: 2026-09-01T00:00:00.000Z",
            "expires: 2026-11-30T00:00:00.000Z",
        ]
    );
    let text = p.manual_instructions(&scope);
    assert!(text.contains("permissions package:write"), "{text}");
    assert!(text.contains("scopes package:@acme/app"), "{text}");
    for line in &scope.lines {
        assert!(!line.contains(&redacted(&leaked)), "{line}");
    }
}

#[tokio::test]
async fn token_list_follows_pages() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("pages");
    let operator = npm_token("pagesOp");
    mount_whoami(&rec, &leaked, "alice").await;
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .and(query_param("page", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "objects": [other_entry()],
            "total": 2,
            "urls": { "next": "/-/npm/v1/tokens?page=1&perPage=100" }
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "objects": [granular_entry(&leaked)],
            "total": 2,
            "urls": {}
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
    let scope = provider(&rec, Some(&operator))
        .describe_scope(&cred(&leaked))
        .await
        .unwrap();
    assert!(
        scope.lines.contains(&"type: granular".to_owned()),
        "{:?}",
        scope.lines
    );

    // A next link outside the registry is never followed.
    let rec = CallRecorder::start().await;
    mount_whoami(&rec, &leaked, "alice").await;
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "objects": [],
            "total": 5,
            "urls": { "next": "https://elsewhere.example/-/npm/v1/tokens?page=1" }
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
    let scope = provider(&rec, Some(&operator))
        .describe_scope(&cred(&leaked))
        .await
        .unwrap();
    assert!(
        scope.lines[1].starts_with(NOT_VISIBLE) && scope.lines[1].contains("outside"),
        "{:?}",
        scope.lines
    );
}

fn not_visible_line(lines: &[String]) -> &str {
    lines
        .iter()
        .find(|l| l.starts_with(NOT_VISIBLE))
        .unwrap_or_else(|| panic!("no {NOT_VISIBLE:?} line in {lines:?}"))
}

// T5 (AC5): no matching key; check_valid's result stands.
#[tokio::test]
async fn describe_scope_no_match_not_visible() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("t5None");
    let operator = npm_token("t5Oper");
    mount_whoami(&rec, &leaked, "alice").await;
    mount_list(&rec, &operator, serde_json::json!([])).await;
    let p = provider(&rec, Some(&operator));
    let scope = p.describe_scope(&cred(&leaked)).await.unwrap();
    assert_eq!(scope.identity, Identity("alice".into()));
    assert_eq!(scope.lines.len(), 2, "{:?}", scope.lines);
    assert!(not_visible_line(&scope.lines).contains("none of"));
    assert_eq!(
        p.check_valid(&cred(&leaked)).await.unwrap(),
        Validity::Valid
    );
    let text = p.manual_instructions(&scope);
    assert!(text.contains("could not read them"), "{text}");
    rec.assert_no_mutations().await;
}

// T5 (AC5): the list is unavailable for other reasons, and the scope
// still says why.
#[tokio::test]
async fn describe_scope_without_operator_list() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("t5NoOp");
    mount_whoami(&rec, &leaked, "alice").await;

    let scope = provider(&rec, None)
        .describe_scope(&cred(&leaked))
        .await
        .unwrap();
    assert!(not_visible_line(&scope.lines).contains("ROTATE_NPM_TOKEN"));

    let granular = npm_token("t5Gat");
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .and(header("authorization", bearer(&granular).as_str()))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "error": "session token required" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let scope = provider(&rec, Some(&granular))
        .describe_scope(&cred(&leaked))
        .await
        .unwrap();
    let line = not_visible_line(&scope.lines);
    assert!(
        line.contains("401") && line.contains("session token"),
        "{line}"
    );

    // The leaked token is never used as the operator token.
    let before = rec.calls().await.len();
    let scope = provider(&rec, Some(&leaked))
        .describe_scope(&cred(&leaked))
        .await
        .unwrap();
    assert!(not_visible_line(&scope.lines).contains("D3"));
    let after: Vec<String> = rec.calls().await[before..]
        .iter()
        .map(|c| c.path.clone())
        .collect();
    assert_eq!(after, ["/-/whoami"], "only whoami ran");
    rec.assert_no_mutations().await;
}

// T6 (AC6): DELETE to the derived key, signed with the operator token.
#[tokio::test]
async fn revoke_deletes_derived_key_with_operator_token() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let leaked = npm_token("t6Revok");
    let operator = npm_token("t6Oper");
    let key = token_key(leaked.as_bytes());
    mount_list(
        &rec,
        &operator,
        serde_json::json!([other_entry(), { "key": key, "token": &leaked[..6] }]),
    )
    .await;
    let revoked = provider(&rec, Some(&operator))
        .revoke(&cred(&leaked))
        .await
        .unwrap();
    assert_eq!(revoked.restore_ref, None);

    assert_eq!(
        deletes(&rec).await,
        [(format!("/-/npm/v1/tokens/token/{key}"), bearer(&operator))]
    );
    assert!(signed_with(&rec, &leaked).await.is_empty());
    let calls: Vec<String> = rec
        .calls()
        .await
        .iter()
        .map(|c| format!("{} {}", c.method, c.path))
        .collect();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0], "GET /-/npm/v1/tokens");
}

// T6 (AC6), current scheme: the listed UUID.
#[tokio::test]
async fn revoke_granular_deletes_listed_id() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let leaked = npm_token("t6Gran");
    let operator = npm_token("t6Oper2");
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    provider(&rec, Some(&operator))
        .revoke(&cred(&leaked))
        .await
        .unwrap();
    assert_eq!(
        deletes(&rec).await,
        [(format!("/-/npm/v1/tokens/token/{UUID}"), bearer(&operator))]
    );
}

// T7 (AC7)
#[tokio::test]
async fn revoke_404_is_ok() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 404).await;
    let leaked = npm_token("t7Gone");
    let operator = npm_token("t7Oper");
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    let p = provider(&rec, Some(&operator));
    p.revoke(&cred(&leaked)).await.unwrap();
    p.revoke(&cred(&leaked)).await.unwrap();
    assert_eq!(deletes(&rec).await.len(), 2);
}

#[tokio::test]
async fn revoke_already_revoked_or_gone_is_ok() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let operator = npm_token("t7Oper2");
    let marked = npm_token("t7Mark");
    let gone = npm_token("t7NoList");
    let mut entry = granular_entry(&marked);
    entry["revoked"] = serde_json::json!("2026-10-01T00:00:00.000Z");
    mount_list(&rec, &operator, serde_json::json!([entry])).await;
    mount_whoami_status(&rec, &gone, 401).await;
    let p = provider(&rec, Some(&operator));

    p.revoke(&cred(&marked)).await.unwrap();
    p.revoke(&cred(&gone)).await.unwrap();
    assert!(deletes(&rec).await.is_empty());
    assert_eq!(signed_with(&rec, &gone).await, ["GET /-/whoami"]);
}

#[tokio::test]
async fn revoke_not_visible_names_the_user() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let leaked = npm_token("t7Other");
    let operator = npm_token("t7Oper3");
    mount_list(&rec, &operator, serde_json::json!([other_entry()])).await;
    mount_whoami(&rec, &leaked, "bob").await;
    let err = NpmProvider::new(&rec.uri())
        .with_operator_token(Some(SecretValue::from(operator.as_str())))
        .revoke(&cred(&leaked))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.starts_with(NOT_VISIBLE), "{text}");
    assert!(text.contains("bob"), "{text}");
    assert_eq!(err.guidance(), Some(GUIDE_OTHER_USER));
    assert!(deletes(&rec).await.is_empty());
}

#[tokio::test]
async fn revoke_otp_and_bypass_refusals_fail_clearly() {
    let leaked = npm_token("otpLeak");
    let operator = npm_token("otpOper");

    let rec = CallRecorder::start().await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/-/npm/v1/tokens/token/"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", "OTP")
                .set_body_json(serde_json::json!({ "error": "otp required" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let err = provider(&rec, Some(&operator))
        .revoke(&cred(&leaked))
        .await
        .unwrap_err();
    assert!(matches!(err.base(), ProviderError::Permanent(_)), "{err:?}");
    assert!(err.to_string().contains("one-time password"), "{err}");
    // SHA-298 T5.
    assert_eq!(err.guidance(), Some(GUIDE_OTP));

    let rec = CallRecorder::start().await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/-/npm/v1/tokens/token/"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": "Granular access tokens that bypass two-factor authentication may not \
                      perform this action."
        })))
        .with_priority(2)
        .mount(rec.server())
        .await;
    let err = provider(&rec, Some(&operator))
        .revoke(&cred(&leaked))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bypasses 2FA"), "{err}");
    assert_eq!(err.guidance(), Some(GUIDE_SESSION_TOKEN));
}

// Decision D3: the leaked token never deletes itself.
#[tokio::test]
async fn revoke_refuses_leaked_operator_token() {
    let rec = CallRecorder::start().await;
    let leaked = npm_token("selfRev");
    let err = provider(&rec, Some(&leaked))
        .revoke(&cred(&leaked))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("D3"), "{err}");
    assert_eq!(err.guidance(), Some(GUIDE_OPERATOR_IS_LEAKED));
    assert!(rec.calls().await.is_empty(), "revoke made a call");
}

#[tokio::test]
async fn revoke_replacement_by_id_only() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let operator = npm_token("rrOper");
    let p = provider(&rec, Some(&operator));
    p.revoke_replacement(UUID).await.unwrap();
    assert_eq!(
        deletes(&rec).await,
        [(format!("/-/npm/v1/tokens/token/{UUID}"), bearer(&operator))]
    );
    for reference in ["manual", &npm_token("rrValue")] {
        assert!(matches!(
            p.revoke_replacement(reference).await,
            Err(ProviderError::Unsupported(_))
        ));
    }
    assert_eq!(deletes(&rec).await.len(), 1);
}

// T8 (AC8)
#[tokio::test]
async fn verify_other_username_names_both() {
    let rec = CallRecorder::start().await;
    let replacement = npm_token("t8NewTk");
    mount_whoami(&rec, &replacement, "mallory").await;
    let p = provider(&rec, None);
    let err = p
        .verify(&cred(&replacement), &Identity("alice".into()))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("mallory"), "{text}");
    assert!(text.contains("alice"), "{text}");
    p.verify(&cred(&replacement), &Identity("Mallory".into()))
        .await
        .unwrap();

    let rejected = npm_token("t8Reject");
    mount_whoami_status(&rec, &rejected, 401).await;
    let err = p
        .verify(&cred(&rejected), &Identity("alice".into()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");
    rec.assert_no_mutations().await;
}

// T9 (AC9), against the server: no call at all.
#[tokio::test]
async fn restore_unsupported_without_calls() {
    let rec = CallRecorder::start().await;
    let p = provider(&rec, Some(&npm_token("t9Oper")));
    assert_eq!(
        p.restore("anything").await.unwrap(),
        RestoreOutcome::Unsupported
    );
    assert_eq!(p.replacement_mode(), ReplacementMode::Manual);
    assert!(matches!(
        p.create_replacement(&cred(&npm_token("t9Creat"))).await,
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

fn fast_opts() -> AssessOptions {
    AssessOptions {
        concurrency: 2,
        attempts: 2,
        base_delay: Duration::from_millis(1),
        force_provider: None,
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

async fn pipeline(rec: &CallRecorder, leaked: &str, operator: &str) -> Pipeline {
    pipeline_with(rec, leaked, operator, "0s").await
}

/// [`pipeline`] with an overlap window.
async fn pipeline_with(
    rec: &CallRecorder,
    leaked: &str,
    operator: &str,
    overlap: &str,
) -> Pipeline {
    pipeline_of(provider(rec, Some(operator)), leaked, overlap).await
}

/// [`pipeline`] around a given provider.
async fn pipeline_of(npm: NpmProvider, leaked: &str, overlap: &str) -> Pipeline {
    let dir = tempfile::tempdir().unwrap();
    let mut providers = ProviderRegistry::new();
    providers.register(Arc::new(npm));
    let gha = Arc::new(MockConsumer::new("github-actions").matching(
        SecretValue::from(leaked).fingerprint(),
        ConsumerMatch::by_value("gha:acme/app:NPM_TOKEN"),
    ));
    let mut consumers = ConsumerRegistry::new();
    consumers.register(gha.clone());
    let finding = Finding::new(
        SecretValue::from(leaked),
        "NpmToken",
        SourceLocation::file(".npmrc"),
    );
    let assessed = assess::assess(vec![finding], &providers, &fast_opts()).await;
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
// call to npm (NFR3).
#[tokio::test]
async fn plan_makes_no_state_changing_calls() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let leaked = npm_token("planDry");
    let operator = npm_token("planOp");
    mount_whoami(&rec, &leaked, "alice").await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    let p = pipeline(&rec, &leaked, &operator).await;
    let table = plan::render_table(&p.plan);
    let json = plan::render_json(&p.plan);
    assert!(table.contains("alice"), "{table}");
    assert!(table.contains("delete the access token"), "{table}");
    assert!(json.contains("\"mode\": \"manual\"") || json.contains("\"mode\":\"manual\""));
    let calls = rec.calls().await;
    assert!(
        calls.iter().any(|c| c.path == "/-/whoami"),
        "plan checked validity: {calls:?}"
    );
    rec.assert_no_mutations().await;
    assert!(deletes(&rec).await.is_empty());
}

// AC8 through the executor: a replacement owned by someone else is
// rejected, nothing is updated and nothing is deleted.
#[tokio::test]
async fn executor_wrong_user_never_revokes() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let leaked = npm_token("exLeakd");
    let operator = npm_token("exOper");
    let replacement = npm_token("exOther");
    mount_whoami(&rec, &leaked, "alice").await;
    mount_whoami(&rec, &replacement, "mallory").await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    let mut p = pipeline(&rec, &leaked, &operator).await;
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
    assert!(deletes(&rec).await.is_empty(), "revoke was called");
    assert_eq!(
        p.gha.current("gha:acme/app:NPM_TOKEN"),
        Some(SecretValue::from(leaked.as_str()).fingerprint()),
        "the consumer still holds the old token"
    );
}

fn two_hours_later() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::hours(2)
}

// SHA-298 T2 (AC2), T3 (AC3): a revoke resumed by a new executor (which
// never held the replacement) after the overlap window, with no operator
// token set. The failure keeps the safe summary of npm's error plus
// rotate's own guidance; no value reaches the result, the audit log or the
// state file, and nothing is deleted.
#[tokio::test]
async fn sha298_t2_resumed_revoke_without_operator_keeps_guidance() {
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let leaked = npm_token("g2Leakd");
    let operator = npm_token("g2Oper");
    let replacement = npm_token("g2Repl");
    mount_whoami(&rec, &leaked, "alice").await;
    mount_whoami(&rec, &replacement, "alice").await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;
    let mut p = pipeline_with(&rec, &leaked, &operator, "1h").await;
    let mut term = Term::default();
    let first = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .with_manual(
            ReplacementSource::Supplied(Some(SecretValue::from(replacement.as_str()))),
            &mut term,
        )
        .run(&p.plan.rotations[0])
        .await;
    assert!(
        matches!(first.result, RunResult::PendingRevoke { .. }),
        "{:?}",
        first.result
    );

    // The later run: a new process, so a new registry, with no operator.
    let mut resumed = ProviderRegistry::new();
    resumed.register(Arc::new(provider(&rec, None)));
    let outcome = Executor::new(&resumed, &p.consumers, &mut p.store, &mut p.audit)
        .with_clock(two_hours_later)
        .run(&p.plan.rotations[0])
        .await;
    let error = match &outcome.result {
        RunResult::Failed { error, .. } => error.to_string(),
        other => panic!("expected a failed revoke, got {other:?}"),
    };
    for needle in [
        "npm revoke failed",
        "provider message not kept",
        GUIDE_NO_OPERATOR,
    ] {
        assert!(error.contains(needle), "{needle} not in: {error}");
    }
    let audit = std::fs::read_to_string(p.dir.path().join("audit.jsonl")).unwrap();
    let last: serde_json::Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(last["step"], "revoke", "{last}");
    assert!(
        last["error"].as_str().unwrap().contains(GUIDE_NO_OPERATOR),
        "{last}"
    );
    let state = std::fs::read_to_string(p.dir.path().join("state.json")).unwrap();
    for value in [&leaked, &replacement, &operator] {
        for (place, text) in [
            ("result", format!("{:?}", outcome.result)),
            ("audit", audit.clone()),
            ("state", state.clone()),
            ("terminal", format!("{}{}", term.out, term.err)),
        ] {
            assert!(!text.contains(value.as_str()), "a value in the {place}");
        }
    }
    assert!(deletes(&rec).await.is_empty(), "revoke deleted a token");
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

// T10 (AC2, AC6): a full plan and apply. The leaked, operator and new
// tokens appear in no table, JSON, summary, terminal text, log, audit entry
// or state file. On the wire no token is ever in a URL or a body; the
// leaked token signs only `GET /-/whoami`, the operator token only the list
// and the DELETE, the new token only `GET /-/whoami`.
#[tokio::test]
async fn tokens_never_in_output_logs_audit_or_state() {
    let capture = trace_capture();
    let rec = CallRecorder::start().await;
    mount_delete(&rec, 204).await;
    let leaked = npm_token("t10Leak");
    let operator = npm_token("t10Oper");
    let replacement = npm_token("t10NewT");
    mount_whoami(&rec, &leaked, "alice").await;
    mount_whoami(&rec, &replacement, "alice").await;
    mount_list(
        &rec,
        &operator,
        serde_json::json!([granular_entry(&leaked)]),
    )
    .await;

    let mut p = pipeline(&rec, &leaked, &operator).await;
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
        p.gha.current("gha:acme/app:NPM_TOKEN"),
        Some(SecretValue::from(replacement.as_str()).fingerprint())
    );
    assert!(
        term.out.contains("granular access token for alice")
            && term.out.contains("permissions package:write"),
        "{}",
        term.out
    );
    assert_eq!(
        deletes(&rec).await,
        [(format!("/-/npm/v1/tokens/token/{UUID}"), bearer(&operator))]
    );

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
    for value in [&leaked, &operator, &replacement] {
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
        let url = req.url.as_str().to_owned();
        let body = String::from_utf8_lossy(&req.body);
        let auth = req
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("").to_owned())
            .unwrap_or_default();
        for value in [&leaked, &operator, &replacement] {
            assert!(
                !url.contains(value.as_str()),
                "a token in the URL of {target}"
            );
            assert!(
                !body.contains(value.as_str()),
                "a token in the body of {target}"
            );
            for (name, header) in &req.headers {
                if name.as_str() != "authorization" {
                    assert!(!header.to_str().unwrap_or("").contains(value.as_str()));
                }
            }
        }
        if auth.contains(&leaked) {
            assert_eq!(target, "GET /-/whoami", "leaked token signed {target}");
        }
        if auth.contains(&replacement) {
            assert_eq!(target, "GET /-/whoami", "new token signed {target}");
        }
        if auth.contains(&operator) {
            assert!(
                target == "GET /-/npm/v1/tokens"
                    || target.starts_with("DELETE /-/npm/v1/tokens/token/"),
                "operator token signed {target}"
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

// T11 (AC1 to AC9): the shared provider suite in manual mode.
#[tokio::test]
async fn conformance_manual_mode() {
    let report = provider_suite(|| async {
        let rec = CallRecorder::start().await;
        let live = npm_token("t11Live");
        let unknown = npm_token("t11Unkn");
        let operator = npm_token("t11Oper");
        mount_whoami(&rec, &live, "dave").await;
        mount_whoami_status(&rec, &unknown, 401).await;
        mount_list(&rec, &operator, serde_json::json!([granular_entry(&live)])).await;
        mount_delete(&rec, 204).await;
        ProviderFixture {
            provider: Arc::new(provider(&rec, Some(&operator))),
            live: cred(&live),
            identity: Identity("dave".into()),
            unknown: cred(&unknown),
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await;
    assert_eq!(report.plugin, "npm");
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
// scope names a user. With `ROTATE_NPM_TOKEN` set to a session token of
// the same account, the scope also shows the token's settings.
#[tokio::test]
#[ignore]
async fn live_npm_check_valid_and_scope() {
    common::live_guard!();
    let Some(value) = common::live_env("ROTATE_LIVE_NPM_TOKEN") else {
        return;
    };
    let p = NpmProvider::new("https://registry.npmjs.org");
    let credential = cred(&value);
    assert_eq!(p.check_valid(&credential).await.unwrap(), Validity::Valid);
    let scope = p.describe_scope(&credential).await.unwrap();
    assert!(!scope.identity.0.is_empty());
    p.verify(&credential, &scope.identity).await.unwrap();
}

// Live, destructive: deletes a throwaway token, twice, and expects it to
// stop working. `ROTATE_LIVE_NPM_REVOKE_TOKEN` is a token made for this
// test only; `ROTATE_NPM_TOKEN` is an `npm login` session token of the same
// account, on an account whose 2FA does not ask for a one-time password to
// delete tokens.
#[tokio::test]
#[ignore]
async fn live_npm_revoke() {
    common::live_guard!();
    let Some(value) = common::live_env("ROTATE_LIVE_NPM_REVOKE_TOKEN") else {
        return;
    };
    if common::live_env("ROTATE_NPM_TOKEN").is_none() {
        return;
    }
    let p = NpmProvider::new("https://registry.npmjs.org");
    let credential = cred(&value);
    p.revoke(&credential).await.unwrap();
    p.revoke(&credential).await.unwrap();
    for _ in 0..30 {
        if p.check_valid(&credential).await.unwrap() == Validity::Invalid {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("the token still works a minute after revoke");
}

// ---------------------------------------------------------------------------
// SHA-288: one-time password on token delete
// ---------------------------------------------------------------------------

/// A source that always returns `code`, counting the calls and keeping the
/// questions.
#[derive(Default)]
struct FixedOtp {
    code: String,
    asked: std::sync::Mutex<Vec<String>>,
}

impl FixedOtp {
    fn new(code: &str) -> Arc<Self> {
        Arc::new(Self {
            code: code.to_owned(),
            asked: std::sync::Mutex::default(),
        })
    }

    fn questions(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

#[async_trait]
impl OtpSource for FixedOtp {
    async fn one_time_password(&self, question: &str) -> Result<SecretValue, OtpError> {
        self.asked.lock().unwrap().push(question.to_owned());
        Ok(SecretValue::from(self.code.as_str()))
    }
}

/// A source that must never be asked.
struct PanicOtp;

#[async_trait]
impl OtpSource for PanicOtp {
    async fn one_time_password(&self, _: &str) -> Result<SecretValue, OtpError> {
        panic!("the one-time password source was asked without a challenge");
    }
}

/// A terminal that keeps what is written to it.
#[derive(Clone, Default)]
struct SharedTerm(Arc<std::sync::Mutex<String>>);

impl Terminal for SharedTerm {
    fn stdout(&mut self, text: &str) {
        self.0.lock().unwrap().push_str(text);
    }

    fn stderr(&mut self, text: &str) {
        self.0.lock().unwrap().push_str(text);
    }
}

/// A DELETE without `npm-otp` gets npm's OTP challenge; one carrying
/// `npm-otp: <code>` (when `code` is given) is accepted with 204.
async fn mount_otp_delete(rec: &CallRecorder, code: Option<&str>) {
    if let Some(code) = code {
        Mock::given(method("DELETE"))
            .and(path_regex(r"^/-/npm/v1/tokens/token/"))
            .and(header("npm-otp", code))
            .respond_with(ResponseTemplate::new(204))
            .with_priority(1)
            .mount(rec.server())
            .await;
    }
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/-/npm/v1/tokens/token/"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("www-authenticate", "OTP")
                .set_body_json(serde_json::json!({ "error": "otp required" })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
}

/// Every DELETE received, as (authorization, npm-otp) headers.
async fn delete_headers(rec: &CallRecorder) -> Vec<(String, Option<String>)> {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .map(|r| {
            let get = |name: &str| {
                r.headers
                    .get(name)
                    .map(|v| v.to_str().unwrap_or("").to_owned())
            };
            (get("authorization").unwrap_or_default(), get("npm-otp"))
        })
        .collect()
}

/// A provider for one leaked granular token listed by `operator`, with
/// `whoami` for the operator answering "alice".
async fn otp_setup(rec: &CallRecorder, tag: &str) -> (String, String) {
    let leaked = npm_token(&format!("{tag}Lk"));
    let operator = npm_token(&format!("{tag}Op"));
    mount_list(rec, &operator, serde_json::json!([granular_entry(&leaked)])).await;
    mount_whoami(rec, &operator, "alice").await;
    (leaked, operator)
}

// SHA-288 T1 (AC1): ROTATE_NPM_OTP answers the challenge; the retry
// carries `npm-otp` and the operator bearer.
#[tokio::test]
async fn sha288_t1_env_otp_retries_delete_with_npm_otp_header() {
    let rec = CallRecorder::start().await;
    let (leaked, operator) = otp_setup(&rec, "t1").await;
    mount_otp_delete(&rec, Some("123456")).await;
    let var = "ROTATE_TEST_NPM_OTP_T1";
    std::env::set_var(var, "123456");
    let p = provider(&rec, Some(&operator)).with_otp_source(Arc::new(EnvOtp::new(var)));
    p.revoke(&cred(&leaked)).await.unwrap();
    std::env::remove_var(var);
    assert_eq!(
        delete_headers(&rec).await,
        [
            (bearer(&operator), None),
            (bearer(&operator), Some("123456".to_owned())),
        ]
    );
}

// SHA-288 T2 (AC2): the hidden prompt is asked once, names the npm user,
// never shows the code, and the retry carries what was typed.
#[tokio::test]
async fn sha288_t2_prompted_otp_is_asked_once_and_never_shown() {
    let rec = CallRecorder::start().await;
    let (leaked, operator) = otp_setup(&rec, "t2").await;
    mount_otp_delete(&rec, Some("246813")).await;
    let term = SharedTerm::default();
    let prompt = ScriptedPrompt::new(["246813"]);
    let source = PromptOtp::new(Box::new(prompt), Box::new(term.clone()));
    let p = provider(&rec, Some(&operator)).with_otp_source(Arc::new(source));
    p.revoke(&cred(&leaked)).await.unwrap();
    let shown = term.0.lock().unwrap().clone();
    assert_eq!(shown.matches("One-time password").count(), 1, "{shown}");
    assert!(shown.contains("npm user alice"), "{shown}");
    assert!(shown.contains("(input is hidden)"), "{shown}");
    assert!(!shown.contains("246813"), "{shown}");
    assert_eq!(
        delete_headers(&rec).await[1],
        (bearer(&operator), Some("246813".to_owned()))
    );
}

// SHA-288 T3 (AC3): no source: one DELETE, no lookup of the user, and the
// error names the one-time password and the tokens page.
#[tokio::test]
async fn sha288_t3_no_otp_source_sends_one_delete() {
    let rec = CallRecorder::start().await;
    let (leaked, operator) = otp_setup(&rec, "t3").await;
    mount_otp_delete(&rec, None).await;
    let err = provider(&rec, Some(&operator))
        .revoke(&cred(&leaked))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("one-time password"), "{text}");
    assert!(text.contains("none was available"), "{text}");
    assert!(
        text.contains("https://www.npmjs.com/settings/<username>/tokens")
            || text.contains("token settings"),
        "{text}"
    );
    assert_eq!(err.guidance(), Some(GUIDE_OTP));
    assert_eq!(delete_headers(&rec).await.len(), 1);
    assert!(
        !signed_with(&rec, &operator)
            .await
            .contains(&"GET /-/whoami".to_owned()),
        "the user was looked up without a source"
    );
}

// SHA-288 T4 (AC4): the retry is challenged too (or answered with a plain
// 401): no third DELETE, and the error says the code was rejected.
#[tokio::test]
async fn sha288_t4_second_challenge_is_rejected_without_third_delete() {
    for plain_401 in [false, true] {
        let rec = CallRecorder::start().await;
        let (leaked, operator) = otp_setup(&rec, "t4").await;
        if plain_401 {
            Mock::given(method("DELETE"))
                .and(path_regex(r"^/-/npm/v1/tokens/token/"))
                .and(header("npm-otp", "135791"))
                .respond_with(
                    ResponseTemplate::new(401)
                        .set_body_json(serde_json::json!({ "error": "Unauthorized" })),
                )
                .with_priority(1)
                .mount(rec.server())
                .await;
        }
        mount_otp_delete(&rec, None).await;
        let source = FixedOtp::new("135791");
        let p = provider(&rec, Some(&operator)).with_otp_source(source.clone());
        let err = p.revoke(&cred(&leaked)).await.unwrap_err();
        let text = err.to_string();
        assert!(text.contains("rejected the one-time password"), "{text}");
        assert!(!text.contains("135791"), "{text}");
        assert_eq!(err.guidance(), Some(GUIDE_OTP_REJECTED));
        assert_eq!(
            delete_headers(&rec).await.len(),
            2,
            "plain 401: {plain_401}"
        );
        assert_eq!(source.questions().len(), 1);
    }
}

// SHA-288 T5 (AC5): no challenge, no question and no user lookup.
#[tokio::test]
async fn sha288_t5_no_challenge_never_asks() {
    let rec = CallRecorder::start().await;
    let (leaked, operator) = otp_setup(&rec, "t5").await;
    mount_delete(&rec, 204).await;
    let p = provider(&rec, Some(&operator)).with_otp_source(Arc::new(PanicOtp));
    p.revoke(&cred(&leaked)).await.unwrap();
    assert_eq!(delete_headers(&rec).await, [(bearer(&operator), None)]);
    assert!(!signed_with(&rec, &operator)
        .await
        .contains(&"GET /-/whoami".to_owned()));
}

// SHA-288 T6 (AC6): rollback's revoke_replacement retries with the code.
#[tokio::test]
async fn sha288_t6_revoke_replacement_retries_with_otp() {
    let rec = CallRecorder::start().await;
    let (_, operator) = otp_setup(&rec, "t6").await;
    mount_otp_delete(&rec, Some("975310")).await;
    let p = provider(&rec, Some(&operator)).with_otp_source(FixedOtp::new("975310"));
    p.revoke_replacement(UUID).await.unwrap();
    let paths: Vec<String> = deletes(&rec).await.into_iter().map(|(p, _)| p).collect();
    let path = format!("/-/npm/v1/tokens/token/{UUID}");
    assert_eq!(paths, [path.clone(), path]);
    assert_eq!(delete_headers(&rec).await[1].1.as_deref(), Some("975310"));
}

// SHA-288 T7 (AC7): the variable serves one DELETE; a second challenge in
// the same run, with no terminal, fails without reusing it.
#[tokio::test]
async fn sha288_t7_env_otp_is_single_use() {
    let rec = CallRecorder::start().await;
    let (leaked, operator) = otp_setup(&rec, "t7").await;
    mount_otp_delete(&rec, Some("112233")).await;
    let var = "ROTATE_TEST_NPM_OTP_T7";
    std::env::set_var(var, "112233");
    struct NoTerminal;
    impl Prompt for NoTerminal {
        fn read_line(&mut self) -> Result<String, PromptError> {
            Err(PromptError::NoTerminal)
        }
        fn read_secret(
            &mut self,
            _: &str,
            _: &mut dyn Terminal,
        ) -> Result<SecretValue, PromptError> {
            Err(PromptError::NoTerminalForSecret)
        }
    }
    let chain = Chain(vec![
        Arc::new(EnvOtp::new(var)),
        Arc::new(PromptOtp::new(
            Box::new(NoTerminal),
            Box::new(SharedTerm::default()),
        )),
    ]);
    let p = provider(&rec, Some(&operator)).with_otp_source(Arc::new(chain));
    p.revoke(&cred(&leaked)).await.unwrap();
    let err = p.revoke_replacement(UUID).await.unwrap_err();
    assert!(std::env::var(var).is_ok(), "the variable was cleared");
    std::env::remove_var(var);
    assert_eq!(err.guidance(), Some(GUIDE_OTP));
    let headers = delete_headers(&rec).await;
    assert_eq!(headers.len(), 3, "{headers:?}");
    assert_eq!(headers[1].1.as_deref(), Some("112233"));
    assert_eq!(headers[2].1, None);
}

// SHA-288 T8 (AC8), in-process half: a full apply where the delete is
// challenged, once with the variable and once with the prompt, and a
// seven-digit canary code below the redactor's minimum length. Neither the
// code nor any token reaches the terminal, the TRACE log, the audit log,
// the state file or the outcome.
#[tokio::test]
async fn sha288_t8_otp_never_in_output_logs_audit_or_state() {
    let capture = trace_capture();
    for via_prompt in [false, true] {
        let code = if via_prompt { "7351902" } else { "7351903" };
        let rec = CallRecorder::start().await;
        let leaked = npm_token(if via_prompt { "t8LkP" } else { "t8LkE" });
        let operator = npm_token(if via_prompt { "t8OpP" } else { "t8OpE" });
        let replacement = npm_token(if via_prompt { "t8NwP" } else { "t8NwE" });
        mount_whoami(&rec, &leaked, "alice").await;
        mount_whoami(&rec, &replacement, "alice").await;
        mount_whoami(&rec, &operator, "alice").await;
        mount_list(
            &rec,
            &operator,
            serde_json::json!([granular_entry(&leaked)]),
        )
        .await;
        mount_otp_delete(&rec, Some(code)).await;
        let var = format!("ROTATE_TEST_NPM_OTP_T8_{via_prompt}");
        let term_q = SharedTerm::default();
        let source: Arc<dyn OtpSource> = if via_prompt {
            Arc::new(PromptOtp::new(
                Box::new(ScriptedPrompt::new([code])),
                Box::new(term_q.clone()),
            ))
        } else {
            std::env::set_var(&var, code);
            Arc::new(EnvOtp::new(var.as_str()))
        };
        let npm = provider(&rec, Some(&operator)).with_otp_source(source);
        let mut p = pipeline_of(npm, &leaked, "0s").await;
        let mut term = Term::default();
        let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
            .with_manual(
                ReplacementSource::Supplied(Some(SecretValue::from(replacement.as_str()))),
                &mut term,
            )
            .run(&p.plan.rotations[0])
            .await;
        std::env::remove_var(&var);
        assert!(
            matches!(outcome.result, RunResult::Revoked),
            "{:?}",
            outcome.result
        );
        assert_eq!(delete_headers(&rec).await[1].1.as_deref(), Some(code));
        let audit = std::fs::read_to_string(p.dir.path().join("audit.jsonl")).unwrap();
        let state = std::fs::read_to_string(p.dir.path().join("state.json")).unwrap();
        let summary = apply::render_summary(std::slice::from_ref(&outcome));
        let logs = capture.contents();
        let question = term_q.0.lock().unwrap().clone();
        for value in [
            code,
            leaked.as_str(),
            operator.as_str(),
            replacement.as_str(),
        ] {
            for (label, text) in [
                ("stdout", &term.out),
                ("stderr", &term.err),
                ("question", &question),
                ("summary", &summary),
                ("audit log", &audit),
                ("state file", &state),
                ("logs", &logs),
                ("outcome", &format!("{outcome:?}")),
            ] {
                assert!(!text.contains(value), "a value in the {label}");
            }
        }
    }
}

// SHA-288 T9 (AC1, AC3): the provider conformance suite passes with an OTP
// source against a registry that challenges every DELETE without a code
// (the no-source half is `conformance_manual_mode`).
#[tokio::test]
async fn sha288_t9_conformance_with_otp_source() {
    let report = provider_suite(|| async {
        let rec = CallRecorder::start().await;
        let live = npm_token("t9Live");
        let unknown = npm_token("t9Unkn");
        let operator = npm_token("t9Oper");
        mount_whoami(&rec, &live, "dave").await;
        mount_whoami(&rec, &operator, "dave").await;
        mount_whoami_status(&rec, &unknown, 401).await;
        mount_list(&rec, &operator, serde_json::json!([granular_entry(&live)])).await;
        mount_otp_delete(&rec, Some("864200")).await;
        ProviderFixture {
            provider: Arc::new(
                provider(&rec, Some(&operator)).with_otp_source(FixedOtp::new("864200")),
            ),
            live: cred(&live),
            identity: Identity("dave".into()),
            unknown: cred(&unknown),
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await;
    report.assert_ok();
    for name in ["idempotent_revoke", "restore_outcome", "errors_redacted"] {
        assert_eq!(
            report.outcome(name),
            Some(&Outcome::Passed),
            "{name}: {report}"
        );
    }
}

#[test]
fn debug_hides_the_otp_source() {
    let p = NpmProvider::new("http://127.0.0.1:1").with_otp_source(FixedOtp::new("5550123"));
    let shown = format!("{p:?}");
    assert!(shown.contains("otp: \"[set]\""), "{shown}");
    assert!(!shown.contains("5550123"), "{shown}");
}
