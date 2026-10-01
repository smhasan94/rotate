//! SHA-252 T9: values handled by the Secrets Manager consumer never reach
//! tracing output (SDK events at TRACE included) or `Debug` and `Display`
//! of matches, receipts and errors. Its own binary, so no other test's
//! subscriber changes which events are enabled.

mod common;
mod sm_fake;

use rotate::consumer::{Consumer, SecretRef};

use sm_fake::*;

// T9 (AC1, AC3, AC5)
#[tokio::test]
async fn values_never_reach_logs_or_debug() {
    const OLD: &str = "t9-canary-old-c0ffee-secret";
    const NEW: &str = "t9-canary-new-facade-secret";
    let capture = common::LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let old = pair("TESTKEYIDT9OLD", OLD);
    let new = pair("TESTKEYIDT9NEW", NEW);
    let fake = FakeSecretsManager::default();
    fake.put("prod/app", &pair_json("TESTKEYIDT9OLD", OLD))
        .put("prod/plain", OLD)
        .deny("prod/locked");
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/app", "prod/plain", "prod/locked"]));

    let secret = SecretRef::new("aws", &old);
    let found = sm.find(&secret).await.unwrap();
    assert_eq!(found.len(), 3);
    let mut receipts = Vec::new();
    let mut errors = Vec::new();
    for target in &found {
        match sm.update(target, &new).await {
            Ok(r) => receipts.push(r),
            Err(e) => errors.push(e),
        }
    }
    for target in found.iter().filter(|m| m.is_updatable()) {
        sm.restore(target, &old).await.unwrap();
    }
    assert_eq!(receipts.len(), 2);
    assert_eq!(errors.len(), 1);
    let error_text: Vec<String> = errors.iter().map(ToString::to_string).collect();
    tracing::info!(?found, ?receipts, ?errors, consumer = ?sm, "exercised");

    let rendered = format!("{secret:?} {found:#?} {receipts:?} {errors:?} {error_text:?} {sm:?}");
    let logs = capture.contents();
    assert!(logs.contains("exercised"));
    // The SDK's own TRACE events, including request signing, were captured.
    assert!(logs.contains("rpc.method=\"PutSecretValue\""));
    for (label, text) in [("debug output", &rendered), ("tracing", &logs)] {
        assert!(!text.contains(OLD), "{label}: old value leaked");
        assert!(!text.contains(NEW), "{label}: replacement leaked");
    }
}
