//! SHA-249: the conformance suite is reachable from integration tests, the
//! way a real plugin's test under `tests/` calls it, and a leaking plugin's
//! report and tracing output never carry a value.

mod common;

use async_trait::async_trait;

use rotate::calls::CallLog;
use rotate::conformance::mock::{consumer_fixture, provider_fixture};
use rotate::conformance::{canary, consumer_suite, provider_suite, MutationProbe};
use rotate::consumer::mock::MockConsumer;
use rotate::provider::mock::MockProvider;

/// A probe implemented outside the crate, as a wiremock-backed plugin test
/// would implement it for its `CallRecorder`.
struct LocalProbe(CallLog);

#[async_trait]
impl MutationProbe for LocalProbe {
    async fn mutations(&self) -> Vec<String> {
        self.0.mutating().into_iter().map(|c| c.method).collect()
    }
}

#[tokio::test]
async fn suites_pass_from_outside_the_crate() {
    provider_suite(|| async {
        let mut fx = provider_fixture(MockProvider::new("mock"));
        let log = CallLog::new();
        let mock = MockProvider::new("mock")
            .revoked(fx.unknown.fingerprint())
            .log(log.clone());
        fx.provider = std::sync::Arc::new(mock);
        fx.probe = Box::new(LocalProbe(log));
        fx
    })
    .await
    .assert_ok();

    consumer_suite(|| async { consumer_fixture(MockConsumer::new("mock")) })
        .await
        .assert_ok();
}

// T6 (AC6), end to end through tracing.
#[tokio::test]
async fn leaking_plugin_report_and_logs_stay_clean() {
    let capture = common::LogCapture::default();
    let _guard = tracing::subscriber::set_default(capture.subscriber());

    let provider = provider_suite(|| async {
        provider_fixture(MockProvider::new("mock").leak_secret_in_errors("revoke"))
    })
    .await;
    let consumer = consumer_suite(|| async {
        consumer_fixture(MockConsumer::new("mock").leak_secret_in_errors("restore"))
    })
    .await;
    tracing::error!(%provider, ?consumer, "conformance reports");

    assert!(provider.failed().contains(&"errors_redacted"));
    assert!(consumer.failed().contains(&"errors_redacted"));

    let pfx = provider_fixture(MockProvider::new("mock"));
    let cfx = consumer_fixture(MockConsumer::new("mock"));
    let rendered = format!("{provider}\n{provider:?}\n{consumer}\n{consumer:?}");
    let logs = capture.contents();
    assert!(logs.contains("errors_redacted"));
    for credential in [
        &pfx.live,
        &pfx.unknown,
        &cfx.old,
        &cfx.new,
        &canary(&pfx.live),
    ] {
        let leaked = credential
            .secret()
            .expose_secret_str(|value| rendered.contains(value) || logs.contains(value))
            .unwrap();
        assert!(!leaked, "a value reached the report or the logs");
    }
}
