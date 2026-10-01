//! SHA-252: the AWS Secrets Manager consumer against a wiremock server that
//! speaks the Secrets Manager JSON protocol and keeps secret versions.
//!
//! Every value here is fake. Key ids are not in the AWS key id format.

mod common;
mod sm_fake;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use wiremock::matchers::any;
use wiremock::Mock;

use rotate::config::{SecretsManagerConfig, TagFilter};
use rotate::conformance::{consumer_suite, ConsumerFixture, MutationProbe};
use rotate::consumer::aws_secrets_manager::SecretsManagerConsumer;
use rotate::consumer::{Consumer, ConsumerError, Holds, MatchMethod, SecretRef};

use sm_fake::*;

// T1 (AC1)
#[tokio::test]
async fn json_pair_matches_by_value_with_both_paths() {
    let old = pair("TESTKEYIDT1OLD", "t1-leaked-9d2e-secret");
    let fake = FakeSecretsManager::default();
    fake.put(
        "prod/app",
        &pair_json("TESTKEYIDT1OLD", "t1-leaked-9d2e-secret"),
    )
    .put(
        "prod/unrelated",
        &pair_json("TESTKEYIDOTHER", "t1-other-secret"),
    );
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/app", "prod/unrelated"]));

    let found = sm.find(&SecretRef::new("aws", &old)).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].consumer_ref, PAIR_REF);
    assert_eq!(found[0].match_method, MatchMethod::ByValue);
    assert_eq!(found[0].holds, Holds::KeyPair);
    assert!(found[0].is_updatable());
}

// T2 (AC2)
#[tokio::test]
async fn plain_string_matches_with_dollar_path() {
    let leaked = token("t2-plain-leaked-41aa");
    let fake = FakeSecretsManager::default();
    fake.put("prod/token", "t2-plain-leaked-41aa")
        .put("prod/other", "t2-not-it");
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/token", "prod/other"]));

    let found = sm.find(&SecretRef::new("npm", &leaked)).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].consumer_ref, "aws-secrets-manager:prod/token#$");
    assert_eq!(found[0].match_method, MatchMethod::ByValue);
    assert_eq!(found[0].holds, Holds::Secret);
}

// T3 (AC3)
#[tokio::test]
async fn update_replaces_both_fields_keeps_other_and_sends_token() {
    let old = pair("TESTKEYIDT3OLD", "t3-leaked-77c1-secret");
    let new = pair("TESTKEYIDT3NEW", "t3-replacement-0b5f-secret");
    let fake = FakeSecretsManager::default();
    fake.put(
        "prod/app",
        &pair_json("TESTKEYIDT3OLD", "t3-leaked-77c1-secret"),
    );
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/app"]));

    let found = sm.find(&SecretRef::new("aws", &old)).await.unwrap();
    let receipt = sm.update(&found[0], &new).await.unwrap();
    assert_eq!(receipt.consumer_ref, PAIR_REF);
    assert_eq!(receipt.version.as_deref(), Some("v2"));

    let puts = puts(&rec).await;
    assert_eq!(puts.len(), 1);
    assert_eq!(puts[0]["SecretId"], "prod/app");
    let written: Value = serde_json::from_str(puts[0]["SecretString"].as_str().unwrap()).unwrap();
    assert_eq!(
        written,
        json!({
            "AWS_ACCESS_KEY_ID": "TESTKEYIDT3NEW",
            "AWS_SECRET_ACCESS_KEY": "t3-replacement-0b5f-secret",
            "other": "x",
        })
    );
    let token = puts[0]["ClientRequestToken"].as_str().unwrap();
    assert!(token.starts_with("rotate-") && (32..=64).contains(&token.len()));
}

// T4 (AC4)
#[tokio::test]
async fn same_update_twice_sends_same_token() {
    let old = pair("TESTKEYIDT4OLD", "t4-leaked-5e5e-secret");
    let new = pair("TESTKEYIDT4NEW", "t4-replacement-1a2b-secret");
    let fake = FakeSecretsManager::default();
    fake.put(
        "prod/app",
        &pair_json("TESTKEYIDT4OLD", "t4-leaked-5e5e-secret"),
    );
    let rec = server(&fake).await;
    // The second update must see the same starting version, as a retry
    // after a lost response would: answer GetSecretValue with v1 always.
    Mock::given(wiremock::matchers::header(TARGET, GET))
        .respond_with(aws_json(
            200,
            json!({
                "Name": "prod/app",
                "VersionId": "v1",
                "SecretString": pair_json("TESTKEYIDT4OLD", "t4-leaked-5e5e-secret"),
            }),
        ))
        .with_priority(1)
        .mount(rec.server())
        .await;
    let sm = consumer(&rec, names(&["prod/app"]));

    let found = sm.find(&SecretRef::new("aws", &old)).await.unwrap();
    let first = sm.update(&found[0], &new).await.unwrap();
    let second = sm.update(&found[0], &new).await.unwrap();
    let puts = puts(&rec).await;
    assert_eq!(puts.len(), 2);
    assert_eq!(puts[0]["ClientRequestToken"], puts[1]["ClientRequestToken"]);
    assert_eq!(first.version, second.version, "AWS dedupes by token");
}

// T4 (AC4)
#[tokio::test]
async fn update_is_noop_when_value_already_new() {
    let old = pair("TESTKEYIDT4BOLD", "t4b-leaked-3c3c-secret");
    let new = pair("TESTKEYIDT4BNEW", "t4b-replacement-6d6d-secret");
    let fake = FakeSecretsManager::default();
    fake.put(
        "prod/app",
        &pair_json("TESTKEYIDT4BOLD", "t4b-leaked-3c3c-secret"),
    );
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/app"]));

    let found = sm.find(&SecretRef::new("aws", &old)).await.unwrap();
    let first = sm.update(&found[0], &new).await.unwrap();
    let second = sm.update(&found[0], &new).await.unwrap();
    assert_eq!(puts(&rec).await.len(), 1, "second update must not write");
    assert_eq!(first.version, second.version);
}

// T5 (AC5)
#[tokio::test]
async fn update_then_restore_writes_original_json() {
    let original = r#"{"AWS_ACCESS_KEY_ID":"TESTKEYIDT5OLD","n":{"deep":[1,2]},"AWS_SECRET_ACCESS_KEY":"t5-leaked-2f2f-secret","other":"x","port":5432}"#;
    let old = pair("TESTKEYIDT5OLD", "t5-leaked-2f2f-secret");
    let new = pair("TESTKEYIDT5NEW", "t5-replacement-8e8e-secret");
    let fake = FakeSecretsManager::default();
    fake.put("prod/app", original);
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/app"]));

    let found = sm.find(&SecretRef::new("aws", &old)).await.unwrap();
    sm.update(&found[0], &new).await.unwrap();
    sm.restore(&found[0], &old).await.unwrap();

    let puts = puts(&rec).await;
    assert_eq!(puts.len(), 2);
    let last = puts[1]["SecretString"].as_str().unwrap();
    assert_eq!(last, original, "same keys, same order, compact");
    assert_ne!(puts[0]["ClientRequestToken"], puts[1]["ClientRequestToken"]);
    assert_eq!(fake.current("prod/app").as_deref(), Some(original));
}

// T6 (AC6)
#[tokio::test]
async fn tag_filter_pages_through_three_list_calls() {
    let tagged = |i: usize, value: &str| {
        json!({
            "ARN": format!("arn:aws:secretsmanager:us-east-1:000000000000:secret:svc/{i}"),
            "Name": format!("svc/{i}"),
            "Tags": [{ "Key": "team", "Value": value }],
        })
    };
    let mut pages: Vec<Vec<Value>> = vec![
        (0..50).map(|i| tagged(i, "payments")).collect(),
        (50..100).map(|i| tagged(i, "payments")).collect(),
        (100..120).map(|i| tagged(i, "payments")).collect(),
    ];
    // AWS matches tag-key and tag-value on any tag; this one has the key
    // with another value and must be dropped locally.
    pages[2].push(tagged(999, "search"));
    let fake = FakeSecretsManager::default();
    fake.pages(pages).put("svc/7", "t6-leaked-4b4b");
    let rec = server(&fake).await;
    let config = SecretsManagerConfig {
        tag_filters: vec![TagFilter {
            key: "team".into(),
            values: vec!["payments".into()],
        }],
        ..SecretsManagerConfig::default()
    };
    let sm = consumer(&rec, config);

    let found = sm
        .find(&SecretRef::new("npm", &token("t6-leaked-4b4b")))
        .await
        .unwrap();
    assert_eq!(count(&rec, LIST).await, 3);
    assert_eq!(count(&rec, GET).await, 120);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].consumer_ref, "aws-secrets-manager:svc/7#$");

    let first: Value =
        serde_json::from_slice(&rec.server().received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(
        first["Filters"],
        json!([
            { "Key": "tag-key", "Values": ["team"] },
            { "Key": "tag-value", "Values": ["payments"] },
        ])
    );
}

// T7 (AC7)
#[tokio::test]
async fn access_denied_is_not_updatable_and_others_checked() {
    let leaked = token("t7-leaked-6a6a");
    let fake = FakeSecretsManager::default();
    fake.deny("prod/locked").put("prod/token", "t7-leaked-6a6a");
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/locked", "prod/missing", "prod/token"]));

    let found = sm.find(&SecretRef::new("npm", &leaked)).await.unwrap();
    assert_eq!(found.len(), 2);
    let locked = &found[0];
    assert_eq!(locked.consumer_ref, "aws-secrets-manager:prod/locked");
    assert_eq!(locked.match_method, MatchMethod::ByName);
    let reason = locked.updatable.as_ref().unwrap_err().to_string();
    assert!(reason.contains("AccessDeniedException"), "{reason}");
    assert!(reason.contains("not authorized"), "{reason}");
    assert_eq!(found[1].consumer_ref, "aws-secrets-manager:prod/token#$");
    assert!(found[1].is_updatable());

    let err = sm.update(locked, &token("t7-new-value")).await.unwrap_err();
    assert!(matches!(err, ConsumerError::NotUpdatable(_)));
    assert_eq!(puts(&rec).await.len(), 0);
}

// T7: throttling fails find so the plan shows a lookup error.
#[tokio::test]
async fn throttled_find_is_an_error() {
    let rec = common::CallRecorder::start().await;
    Mock::given(any())
        .respond_with(aws_error("ThrottlingException", "Rate exceeded"))
        .with_priority(1)
        .mount(rec.server())
        .await;
    let sm = consumer(&rec, names(&["prod/app"]));
    let err = sm
        .find(&SecretRef::new("npm", &token("t7b-value")))
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
}

// T8 (AC8)
#[tokio::test]
async fn find_makes_no_mutating_call() {
    let old = pair("TESTKEYIDT8OLD", "t8-leaked-1f1f-secret");
    let fake = FakeSecretsManager::default();
    fake.put(
        "prod/app",
        &pair_json("TESTKEYIDT8OLD", "t8-leaked-1f1f-secret"),
    )
    .deny("prod/locked")
    .pages(vec![vec![json!({
        "Name": "prod/app",
        "Tags": [{ "Key": "rotate", "Value": "yes" }],
    })]]);
    let rec = server(&fake).await;
    let config = SecretsManagerConfig {
        secrets: vec!["prod/locked".into()],
        tag_filters: vec![TagFilter {
            key: "rotate".into(),
            values: vec![],
        }],
        json_keys: None,
    };
    let sm = consumer(&rec, config);
    let found = sm.find(&SecretRef::new("aws", &old)).await.unwrap();
    assert_eq!(found.len(), 2);
    assert!(rec.calls().await.len() >= 3);
    rec.assert_no_mutations().await;
}

// T8 (AC8): no section in rotate.yaml means no call at all.
#[tokio::test]
async fn empty_config_makes_no_call() {
    let rec = common::CallRecorder::start().await;
    let sm = consumer(&rec, SecretsManagerConfig::default());
    let found = sm
        .find(&SecretRef::new("npm", &token("t8b-value")))
        .await
        .unwrap();
    assert!(found.is_empty());
    assert!(rec.calls().await.is_empty());

    // The production constructor loads nothing until a call needs it.
    let lazy = SecretsManagerConsumer::new(SecretsManagerConfig::default(), None);
    assert!(lazy
        .find(&SecretRef::new("npm", &token("t8b-value")))
        .await
        .unwrap()
        .is_empty());
    assert!(format!("{lazy:?}").contains("client_built: false"));
}

#[tokio::test]
async fn json_keys_restrict_comparison() {
    let leaked = token("t-keys-leaked-2c2c");
    let fake = FakeSecretsManager::default();
    fake.put(
        "prod/app",
        &json!({ "A": "t-keys-leaked-2c2c", "B": "t-keys-leaked-2c2c" }).to_string(),
    );
    let rec = server(&fake).await;
    let config = SecretsManagerConfig {
        json_keys: Some(vec!["B".into()]),
        ..names(&["prod/app"])
    };
    let sm = consumer(&rec, config);
    let found = sm.find(&SecretRef::new("npm", &leaked)).await.unwrap();
    assert_eq!(found[0].consumer_ref, "aws-secrets-manager:prod/app#$.B");
    sm.update(&found[0], &token("t-keys-new-3d3d"))
        .await
        .unwrap();
    let written: Value = serde_json::from_str(fake.current("prod/app").unwrap().as_str()).unwrap();
    assert_eq!(
        written,
        json!({ "A": "t-keys-leaked-2c2c", "B": "t-keys-new-3d3d" })
    );
}

#[tokio::test]
async fn token_cannot_replace_a_key_pair() {
    let old = pair("TESTKEYIDSHAPE", "t-shape-leaked-5f5f");
    let fake = FakeSecretsManager::default();
    fake.put(
        "prod/app",
        &pair_json("TESTKEYIDSHAPE", "t-shape-leaked-5f5f"),
    );
    let rec = server(&fake).await;
    let sm = consumer(&rec, names(&["prod/app"]));
    let found = sm.find(&SecretRef::new("aws", &old)).await.unwrap();
    let err = sm
        .update(&found[0], &token("t-shape-token-6a6a"))
        .await
        .unwrap_err();
    assert!(matches!(err, ConsumerError::Unsupported(_)));
    assert!(!err.to_string().contains("t-shape"));
    assert_eq!(puts(&rec).await.len(), 0);
}

/// Mutations seen by the fake, labelled by operation.
struct Probe(common::CallRecorder);

#[async_trait]
impl MutationProbe for Probe {
    async fn mutations(&self) -> Vec<String> {
        self.0
            .server()
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| target(r).to_owned())
            .filter(|t| !matches!(t.as_str(), GET | LIST))
            .collect()
    }
}

// T10 (AC1 to AC8)
#[tokio::test]
async fn conformance_suite_passes() {
    consumer_suite(|| async {
        let old = pair("TESTKEYIDCONFOLD", "t10-conformance-old-9a9a");
        let new = pair("TESTKEYIDCONFNEW", "t10-conformance-new-8b8b");
        let fake = FakeSecretsManager::default();
        fake.put(
            "prod/app",
            &pair_json("TESTKEYIDCONFOLD", "t10-conformance-old-9a9a"),
        )
        .put("prod/plain", "t10-conformance-old-9a9a")
        .put("prod/unrelated", "t10-unrelated-value");
        let rec = server(&fake).await;
        let sm = consumer(&rec, names(&["prod/app", "prod/plain", "prod/unrelated"]));
        ConsumerFixture {
            consumer: Arc::new(sm),
            secret: SecretRef::new("aws", &old),
            old,
            new,
            probe: Box::new(Probe(rec)),
        }
    })
    .await
    .assert_ok();
}

#[tokio::test]
#[ignore]
async fn live_secrets_manager_find_is_read_only() {
    common::live_guard!();
    let Some(id) = common::require_env("ROTATE_LIVE_SM_SECRET") else {
        return;
    };
    let sm = SecretsManagerConsumer::new(names(&[id.as_str()]), None);
    let found = sm
        .find(&SecretRef::new(
            "npm",
            &token("rotate-live-not-a-real-value"),
        ))
        .await
        .unwrap();
    assert!(found.iter().all(|m| m.match_method == MatchMethod::ByName));
}
