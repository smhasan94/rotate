//! Self-tests for the shared test harness (SHA-216 T1, T2, T5 and extras).

mod common;

use common::{assert_no_mutations_in, CallRecorder, TestDirs};

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// T1 covers AC1.
#[tokio::test]
async fn recorder_lists_get_and_post_with_flags() {
    let rec = CallRecorder::start().await;
    let c = client();
    c.get(format!("{}/read", rec.uri())).send().await.unwrap();
    c.post(format!("{}/write", rec.uri()))
        .body("x=1")
        .send()
        .await
        .unwrap();

    let calls = rec.calls().await;
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (calls[0].method.as_str(), calls[0].path.as_str()),
        ("GET", "/read")
    );
    assert!(!calls[0].mutating);
    assert_eq!(
        (calls[1].method.as_str(), calls[1].path.as_str()),
        ("POST", "/write")
    );
    assert!(calls[1].mutating);
    assert_eq!(calls[1].body(), b"x=1");
}

/// T2 covers AC2 (passing half).
#[tokio::test]
async fn recorder_get_only_passes() {
    let rec = CallRecorder::start().await;
    let c = client();
    for p in ["/a", "/b"] {
        c.get(format!("{}{p}", rec.uri())).send().await.unwrap();
    }
    rec.assert_no_mutations().await;
}

/// T2 covers AC2 (panicking half). The message must name the call and must
/// not contain the body.
#[tokio::test]
async fn recorder_post_panics_naming_call() {
    let rec = CallRecorder::start().await;
    let body = "secret-body-canary-7c2e";
    client()
        .post(format!("{}/revoke", rec.uri()))
        .body(body)
        .send()
        .await
        .unwrap();

    let calls = rec.calls().await;
    let result = std::panic::catch_unwind(|| assert_no_mutations_in(&calls));
    let payload = result.expect_err("a POST must fail the assertion");
    let msg = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("panic payload is a string");
    assert!(msg.contains("POST /revoke"), "message was: {msg}");
    assert!(!msg.contains(body), "panic message leaked the body");
}

/// T5 covers AC5.
#[tokio::test]
async fn recorder_read_only_predicate_overrides_method() {
    let mut rec = CallRecorder::start().await;
    rec.mark_read_only(|req| req.body.starts_with(b"Action=GetCallerIdentity"));
    let c = client();
    c.post(format!("{}/", rec.uri()))
        .body("Action=GetCallerIdentity&Version=2011-06-15")
        .send()
        .await
        .unwrap();
    c.post(format!("{}/", rec.uri()))
        .body("Action=CreateAccessKey&UserName=ci")
        .send()
        .await
        .unwrap();

    let calls = rec.calls().await;
    assert_eq!(calls.len(), 2);
    assert!(
        !calls[0].mutating,
        "read-only predicate should clear the flag"
    );
    assert!(calls[1].mutating, "non-matching POST stays mutating");
}

/// Extra: the temp working directory has `.rotate/` ready.
#[test]
fn test_dirs_creates_rotate_dir() {
    let dirs = TestDirs::new();
    assert!(dirs.rotate_dir.is_dir());
    assert_eq!(dirs.rotate_dir, dirs.path().join(".rotate"));
}

/// Extra: `Debug` on a recorded call never shows the body.
#[tokio::test]
async fn recorded_call_debug_hides_body() {
    let rec = CallRecorder::start().await;
    let body = "debug-body-canary-41aa";
    client()
        .put(format!("{}/item?x=1", rec.uri()))
        .body(body)
        .send()
        .await
        .unwrap();
    let calls = rec.calls().await;
    let dbg = format!("{:?}", calls[0]);
    assert!(dbg.contains("PUT"), "{dbg}");
    assert!(dbg.contains("body_len"), "{dbg}");
    assert!(!dbg.contains(body), "Debug leaked the body: {dbg}");
    assert_eq!(calls[0].query.as_deref(), Some("x=1"));
}
