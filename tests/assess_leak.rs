//! SHA-248 T7 and T8: a detector hint beats the value pattern with a logged
//! warning, and no secret reaches the table, JSON, `Debug` or tracing.

mod common;

use std::sync::Arc;
use std::time::Duration;

use rotate::assess::{assess, render_json, render_table, AssessOptions, Disposition};
use rotate::calls::CallLog;
use rotate::finding::{Finding, SourceLocation, ACCESS_KEY_ID, IS_CANARY};
use rotate::provider::mock::MockProvider;
use rotate::provider::{Confidence, ProviderError, ProviderRegistry, Validity};
use rotate::secret::SecretValue;

fn opts() -> AssessOptions {
    AssessOptions {
        base_delay: Duration::from_millis(1),
        ..AssessOptions::default()
    }
}

fn finding(value: &str, detector: &str, file: &str) -> Finding {
    Finding::new(
        SecretValue::from(value),
        detector,
        SourceLocation::file(file),
    )
}

// T7 (AC7)
#[tokio::test]
async fn hint_beats_pattern_and_warns() {
    let capture = common::LogCapture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());

    let log = CallLog::new();
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(MockProvider::new("aws").log(log.clone())));
    registry.register(Arc::new(
        MockProvider::new("github")
            .identify_prefix("ghp_")
            .log(log.clone()),
    ));

    let assessed = assess(
        vec![finding("ghp_looks_like_github", "AWS", "a.env")],
        &registry,
        &opts(),
    )
    .await;

    assert_eq!(
        assessed[0].disposition,
        Disposition::Supported {
            provider: "aws",
            confidence: Confidence::High
        }
    );
    let logs = capture.contents();
    assert!(logs.contains("disagree"), "no warning logged: {logs}");
    assert!(
        logs.contains("hint=\"aws\"") || logs.contains("hint=aws"),
        "{logs}"
    );
    assert!(logs.contains("github"), "{logs}");
    assert!(
        !logs.contains("ghp_looks_like_github"),
        "value leaked into the warning"
    );
    log.assert_no_mutations();
}

// T8 (AC1 to AC7)
#[tokio::test]
async fn secret_never_reaches_output_or_logs() {
    let capture = common::LogCapture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());

    const VALID: &str = "valid_canary-1f3a-secret";
    const INVALID: &str = "invalid_canary-2b4c-secret";
    const FAILING: &str = "failing_canary-3c5d-secret";
    const UNSUPPORTED: &str = "zzz_canary-4d6e-secret";
    const CANARY_AWS: &str = "awscanary_canary-5e7f-secret";
    // Not AWS-shaped on purpose: only the gitleaks rule name matters here,
    // and an AKIA-shaped literal trips GitHub secret scanning.
    const KEY_ID_ONLY: &str = "keyid_canary-6f80-only";
    let secrets = [
        VALID,
        INVALID,
        FAILING,
        UNSUPPORTED,
        CANARY_AWS,
        KEY_ID_ONLY,
    ];

    let log = CallLog::new();
    let valid = Arc::new(
        MockProvider::new("valid")
            .identify_prefix("valid_")
            .log(log.clone()),
    );
    let invalid = Arc::new(
        MockProvider::new("invalid")
            .identify_prefix("invalid_")
            .validity(Validity::Invalid)
            .log(log.clone()),
    );
    let failing = Arc::new(
        MockProvider::new("failing")
            .identify_prefix("failing_")
            .log(log.clone()),
    );
    failing.fail_next(
        "check_valid",
        ProviderError::RateLimited { retry_after: None },
    );
    failing.fail_always(
        "check_valid",
        ProviderError::Transient("503 from provider".into()),
    );
    let aws = Arc::new(MockProvider::new("aws").log(log.clone()));
    let mut registry = ProviderRegistry::new();
    for mock in [valid, invalid, failing, aws] {
        registry.register(mock);
    }

    let findings = vec![
        finding(VALID, "Mock", "a.env"),
        finding(VALID, "Mock", "b.env"),
        finding(INVALID, "Mock", "c.env"),
        finding(FAILING, "Mock", "d.env"),
        finding(UNSUPPORTED, "Scanner", "e.env"),
        finding(CANARY_AWS, "AWS", "f.env")
            .with_extra(ACCESS_KEY_ID, "AKIAMOCKCANARY")
            .with_extra(IS_CANARY, "true"),
        finding(KEY_ID_ONLY, "aws-access-token", "g.env"),
    ];
    let assessed = assess(findings, &registry, &opts()).await;
    assert_eq!(assessed.len(), 6);

    let table = render_table(&assessed);
    let json = render_json(&assessed);
    tracing::info!(?assessed, %table, "assessed");
    let rendered = format!("{assessed:?} {assessed:#?} {registry:?} {:?}", log.calls());
    let logs = capture.contents();
    assert!(logs.contains("assessed"), "event not captured");

    for (label, text) in [
        ("table", &table),
        ("json", &json),
        ("debug", &rendered),
        ("tracing", &logs),
    ] {
        for (index, secret) in secrets.iter().enumerate() {
            assert!(!text.contains(secret), "{label}: secrets[{index}] leaked");
        }
        for item in &assessed {
            assert!(
                text.contains(item.fingerprint.as_str()),
                "{label}: fingerprint missing"
            );
        }
    }
    for status in [
        "valid",
        "invalid",
        "unknown: transient provider failure: 503 from provider",
        "unsupported",
        "not rotatable",
    ] {
        assert!(table.contains(status), "table is missing {status:?}");
    }
    log.assert_no_mutations();
}
