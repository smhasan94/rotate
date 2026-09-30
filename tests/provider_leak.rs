//! SHA-221 T7: a credential run through every provider method never reaches
//! the call log, any `Debug` output or tracing.

mod common;

use std::sync::Arc;

use rotate::calls::CallLog;
use rotate::finding::{Finding, SourceLocation, ACCESS_KEY_ID};
use rotate::provider::mock::MockProvider;
use rotate::provider::ProviderRegistry;
use rotate::secret::SecretValue;

const CANARY: &str = "mock_canary-7d1e-secret-value";

#[tokio::test]
async fn secret_never_reaches_recorder_or_logs() {
    let capture = common::LogCapture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());

    let finding = Finding::new(
        SecretValue::from(CANARY),
        "Mock",
        SourceLocation::file("config/.env"),
    )
    .with_extra(ACCESS_KEY_ID, "AKIAMOCKEXAMPLE");
    let credential = finding.credential();
    let fingerprint = credential.fingerprint();

    let log = CallLog::new();
    let mock = Arc::new(
        MockProvider::new("mock")
            .identify_prefix("mock_")
            .log(log.clone()),
    );
    let mut registry = ProviderRegistry::new();
    registry.register(mock.clone());

    let identified = registry.identify(&finding).unwrap().unwrap();
    let provider = identified.provider.clone();
    let validity = provider.check_valid(&credential).await.unwrap();
    let scope = provider.describe_scope(&credential).await.unwrap();
    let replacement = provider.create_replacement(&credential).await.unwrap();
    provider
        .verify(&replacement.credential, &scope.identity)
        .await
        .unwrap();
    let revoked = provider.revoke(&credential).await.unwrap();
    let outcome = provider
        .restore(revoked.restore_ref.as_deref().unwrap())
        .await
        .unwrap();
    let new_value = replacement
        .credential
        .secret()
        .expose_secret_str(|s| s.to_owned())
        .unwrap();

    tracing::info!(
        ?finding,
        ?credential,
        ?identified,
        ?validity,
        ?scope,
        ?replacement,
        ?revoked,
        ?outcome,
        ?registry,
        mock = ?mock,
        calls = ?log.calls(),
        log = ?log,
        "rotation exercised"
    );

    let rendered = format!(
        "{finding:?} {finding:#?} {credential:?} {identified:?} {validity:?} {scope:?} \
         {replacement:?} {replacement:#?} {revoked:?} {outcome:?} {registry:?} {mock:?} {log:?} {:?}",
        log.calls()
    );
    let logs = capture.contents();
    assert!(logs.contains("rotation exercised"), "event not captured");

    for (label, text) in [("debug output", &rendered), ("tracing", &logs)] {
        assert!(!text.contains(CANARY), "{label}: old value leaked");
        assert!(!text.contains(&new_value), "{label}: replacement leaked");
        assert!(
            text.contains(fingerprint.as_str()),
            "{label}: fingerprint missing"
        );
    }

    let calls = log.calls();
    assert_eq!(calls.len(), 7, "{calls:?}");
    assert_eq!(log.mutating().len(), 3);
    assert!(calls
        .iter()
        .filter(|c| c.method != "restore")
        .all(|c| c.fingerprint.is_some()));
}
