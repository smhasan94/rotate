//! SHA-222 T6: old and replacement credentials run through find, update and
//! restore never reach the call log, any `Debug` output or tracing.

mod common;

use rotate::calls::CallLog;
use rotate::consumer::mock::MockConsumer;
use rotate::consumer::{Consumer, ConsumerMatch, Holds, SecretRef};
use rotate::provider::Credential;
use rotate::secret::{SecretPair, SecretValue};

const OLD: &str = "mock_canary-old-4b1f-secret";
const NEW: &str = "mock_canary-new-9e2a-secret";

#[tokio::test]
async fn secret_never_reaches_recorder_or_logs() {
    let capture = common::LogCapture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());

    let old = Credential::KeyPair(SecretPair::new("AKIAMOCKOLD", SecretValue::from(OLD)));
    let new = Credential::KeyPair(SecretPair::new("AKIAMOCKNEW", SecretValue::from(NEW)));
    let log = CallLog::new();
    let mock = MockConsumer::new("mock")
        .log(log.clone())
        .matching(
            old.fingerprint(),
            ConsumerMatch::by_value("mock:prod/app").holding(Holds::KeyPair),
        )
        .matching(
            old.fingerprint(),
            ConsumerMatch::by_name("mock:repo:AWS_ACCESS_KEY_ID").holding(Holds::KeyId),
        )
        .matching(
            old.fingerprint(),
            ConsumerMatch::by_name("mock:org:AWS_SECRET_ACCESS_KEY")
                .not_updatable("org secret needs admin"),
        );

    let secret = SecretRef::new("mock", &old).with_names(["AWS_ACCESS_KEY_ID"]);
    let found = mock.find(&secret).await.unwrap();
    let mut receipts = Vec::new();
    let mut errors = Vec::new();
    for target in &found {
        match mock.update(target, &new).await {
            Ok(receipt) => receipts.push(receipt),
            Err(err) => errors.push(err),
        }
    }
    for target in found.iter().filter(|m| m.is_updatable()) {
        mock.restore(target, &old).await.unwrap();
    }
    assert_eq!(receipts.len(), 2);
    assert_eq!(errors.len(), 1);
    assert_eq!(mock.current("mock:prod/app"), Some(old.fingerprint()));

    tracing::info!(
        ?secret,
        ?found,
        ?receipts,
        ?errors,
        mock = ?mock,
        calls = ?log.calls(),
        "consumers exercised"
    );
    let error_text: Vec<String> = errors.iter().map(ToString::to_string).collect();
    let rendered =
        format!("{secret:?} {found:#?} {receipts:?} {errors:?} {error_text:?} {mock:?} {log:?}");
    let logs = capture.contents();
    assert!(logs.contains("consumers exercised"), "event not captured");

    for (label, text) in [("debug output", &rendered), ("tracing", &logs)] {
        assert!(!text.contains(OLD), "{label}: old value leaked");
        assert!(!text.contains(NEW), "{label}: replacement leaked");
        assert!(
            text.contains(old.fingerprint().as_str()),
            "{label}: old fingerprint missing"
        );
    }
    assert!(log
        .calls()
        .iter()
        .all(|c| c.fingerprint.is_some() && c.target == "mock"));
}
