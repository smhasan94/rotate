use std::sync::Arc;

use async_trait::async_trait;

use super::mock::{consumer_fixture, provider_fixture};
use super::*;
use crate::consumer::mock::MockConsumer;
use crate::finding::Finding;
use crate::provider::mock::MockProvider;
use crate::provider::{
    Confidence, Identity, Provider, ProviderError, Replacement, ReplacementMode, RestoreOutcome,
    Revoked, Scope, Validity,
};

const PROVIDER_CHECKS: [&str; 10] = [
    "identify_rejects_foreign",
    "check_valid_unknown_invalid",
    "read_only_check_valid",
    "read_only_describe_scope",
    "read_only_verify",
    "replacement_differs",
    "verify_wrong_identity_fails",
    "idempotent_revoke",
    "restore_outcome",
    "errors_redacted",
];

fn detail<'a>(report: &'a SuiteReport, name: &str) -> &'a str {
    match report.outcome(name) {
        Some(Outcome::Failed(detail)) => detail,
        other => panic!("{name} did not fail: {other:?}\n{report}"),
    }
}

/// Every value the mock fixtures and the suite use, as plain strings, so a
/// test can assert none of them reached the report.
fn values() -> Vec<String> {
    let fx = provider_fixture(MockProvider::new("mock"));
    let cx = consumer_fixture(MockConsumer::new("mock"));
    [&fx.live, &fx.unknown, &cx.old, &cx.new, &canary(&fx.live)]
        .iter()
        .map(|c| c.secret().expose_secret_str(str::to_owned).unwrap())
        .collect()
}

fn assert_clean(report: &SuiteReport) {
    let rendered = format!("{report}\n{report:?}");
    for value in values() {
        assert!(!rendered.contains(&value), "report leaks a value");
    }
}

// T1 (AC1)
#[tokio::test]
async fn provider_suite_passes_on_default_mock() {
    let report = provider_suite(|| async { provider_fixture(MockProvider::new("mock")) }).await;
    report.assert_ok();
    assert_eq!(report.plugin, "mock");
    assert_eq!(report.suite, "provider");
    let names: Vec<&str> = report.checks.iter().map(|c| c.name).collect();
    assert_eq!(names, PROVIDER_CHECKS);
    assert!(report.skipped().is_empty());
    assert_eq!(
        report.to_string(),
        "provider conformance for mock: 10 passed, 0 failed, 0 skipped"
    );
}

// T2 (AC2)
#[tokio::test]
async fn second_revoke_error_fails_idempotent_revoke() {
    let report = provider_suite(|| async {
        let mock = MockProvider::new("mock");
        mock.fail_after(
            "revoke",
            1,
            ProviderError::Permanent("404 not found".into()),
        );
        provider_fixture(mock)
    })
    .await;
    assert_eq!(report.failed(), ["idempotent_revoke"]);
    assert!(detail(&report, "idempotent_revoke").contains("second revoke"));
    assert!(report
        .to_string()
        .contains("FAILED idempotent_revoke: second revoke"));
    let panic = std::panic::catch_unwind(|| report.assert_ok()).unwrap_err();
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("idempotent_revoke"), "{message}");
}

// SHA-262: a provider that cannot revoke at all (OpenAI without an admin
// key) skips the revoke checks rather than failing them.
#[tokio::test]
async fn unsupported_revoke_skips_revoke_checks() {
    let report = provider_suite(|| async {
        let mock = MockProvider::new("mock");
        mock.fail_always(
            "revoke",
            ProviderError::Unsupported("needs an admin key".into()),
        );
        provider_fixture(mock)
    })
    .await;
    report.assert_ok();
    assert_eq!(report.skipped(), ["idempotent_revoke", "restore_outcome"]);
}

// T3 (AC3)
#[tokio::test]
async fn mutation_in_check_valid_fails_read_only_check_valid() {
    let report = provider_suite(|| async {
        provider_fixture(MockProvider::new("mock").mutates_in("check_valid"))
    })
    .await;
    assert_eq!(report.failed(), ["read_only_check_valid"]);
    assert_eq!(
        detail(&report, "read_only_check_valid"),
        "check_valid made state-changing calls: mock.revoke"
    );
}

// T4 (AC4)
#[tokio::test]
async fn consumer_suite_passes_on_default_mock() {
    let report = consumer_suite(|| async { consumer_fixture(MockConsumer::new("mock")) }).await;
    report.assert_ok();
    let names: Vec<&str> = report.checks.iter().map(|c| c.name).collect();
    assert_eq!(
        names,
        [
            "find_unknown_empty",
            "read_only_find",
            "update_then_find",
            "restore_reverses_update",
            "errors_redacted",
        ]
    );
    assert_eq!(report.suite, "consumer");
}

// T5 (AC5)
#[tokio::test]
async fn noop_restore_fails_restore_reverses_update() {
    let report =
        consumer_suite(|| async { consumer_fixture(MockConsumer::new("mock").restore_is_noop()) })
            .await;
    assert_eq!(report.failed(), ["restore_reverses_update"]);
    let detail = detail(&report, "restore_reverses_update");
    assert!(
        detail.contains("misses mock:conformance/by-value"),
        "{detail}"
    );
    assert!(
        detail.contains("still holds the new credential"),
        "{detail}"
    );
}

// T6 (AC6)
#[tokio::test]
async fn leaking_error_fails_errors_redacted() {
    let report = provider_suite(|| async {
        provider_fixture(MockProvider::new("mock").leak_secret_in_errors("check_valid"))
    })
    .await;
    assert!(report.failed().contains(&"errors_redacted"), "{report}");
    assert_eq!(
        detail(&report, "errors_redacted"),
        "error text from check_valid contains a secret value"
    );
    // The check that saw the error quotes it scrubbed.
    assert!(detail(&report, "check_valid_unknown_invalid").contains("[secret]"));
    assert_clean(&report);
}

// T6 (AC6)
#[tokio::test]
async fn leaking_consumer_error_fails_errors_redacted() {
    let report = consumer_suite(|| async {
        consumer_fixture(MockConsumer::new("mock").leak_secret_in_errors("update"))
    })
    .await;
    assert!(report.failed().contains(&"errors_redacted"), "{report}");
    assert_eq!(
        detail(&report, "errors_redacted"),
        "error text from update contains a secret value"
    );
    assert!(detail(&report, "update_then_find").contains("[secret]"));
    assert_clean(&report);
}

#[tokio::test]
async fn manual_mode_skips_replacement_differs() {
    let report = provider_suite(|| async {
        provider_fixture(MockProvider::new("mock").mode(ReplacementMode::Manual))
    })
    .await;
    report.assert_ok();
    assert_eq!(report.skipped(), ["replacement_differs"]);
    assert!(report.to_string().contains("9 passed, 0 failed, 1 skipped"));
}

#[tokio::test]
async fn identify_claiming_foreign_value_fails() {
    // An empty prefix claims every value, including the empty one.
    let report =
        provider_suite(|| async { provider_fixture(MockProvider::new("aws").identify_prefix("")) })
            .await;
    assert_eq!(report.failed(), ["identify_rejects_foreign"]);
    let detail = detail(&report, "identify_rejects_foreign");
    assert!(detail.contains("the empty value"), "{detail}");
    assert!(detail.contains("the github sample"), "{detail}");
    // A provider is not asked to reject its own format.
    assert!(!detail.contains("the aws sample"), "{detail}");
}

/// Delegates to a `MockProvider` but accepts any identity in `verify`.
struct IgnoresIdentity(MockProvider);

#[async_trait]
impl Provider for IgnoresIdentity {
    fn name(&self) -> &'static str {
        self.0.name()
    }
    fn replacement_mode(&self) -> ReplacementMode {
        self.0.replacement_mode()
    }
    fn identify(&self, finding: &Finding) -> Option<Confidence> {
        self.0.identify(finding)
    }
    async fn check_valid(&self, c: &Credential) -> Result<Validity, ProviderError> {
        self.0.check_valid(c).await
    }
    async fn describe_scope(&self, c: &Credential) -> Result<Scope, ProviderError> {
        self.0.describe_scope(c).await
    }
    async fn create_replacement(&self, c: &Credential) -> Result<Replacement, ProviderError> {
        self.0.create_replacement(c).await
    }
    async fn verify(&self, c: &Credential, _identity: &Identity) -> Result<(), ProviderError> {
        self.0.verify(c, &self.0.identity()).await
    }
    async fn revoke(&self, c: &Credential) -> Result<Revoked, ProviderError> {
        self.0.revoke(c).await
    }
    async fn restore(&self, r: &str) -> Result<RestoreOutcome, ProviderError> {
        self.0.restore(r).await
    }
}

#[tokio::test]
async fn verify_ignoring_identity_fails() {
    let report = provider_suite(|| async {
        let mut fx = provider_fixture(MockProvider::new("mock"));
        let mock = MockProvider::new("mock").revoked(fx.unknown.fingerprint());
        fx.probe = Box::new(mock.call_log());
        fx.provider = Arc::new(IgnoresIdentity(mock));
        fx
    })
    .await;
    assert_eq!(report.failed(), ["verify_wrong_identity_fails"]);
    assert_eq!(
        detail(&report, "verify_wrong_identity_fails"),
        "verify accepted a wrong identity"
    );
}

#[test]
fn canary_keeps_the_credential_shape() {
    use crate::secret::SecretPair;
    let pair = Credential::KeyPair(SecretPair::new("KEYID", SecretValue::from("x")));
    assert!(canary(&pair).key_id().is_some());
    let token = Credential::Token(SecretValue::from("x"));
    assert!(canary(&token).key_id().is_none());
}
