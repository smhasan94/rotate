//! GitHub Actions secrets consumer against wiremock (SHA-253).
//!
//! Test values are built at runtime and never match a GitHub or AWS
//! secret-scanning pattern.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Value};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

use common::{CallRecorder, LogCapture};
use rotate::config::{ActionsTarget, ConsumersConfig, ProviderName};
use rotate::conformance::{consumer_suite, ConsumerFixture, MutationProbe};
use rotate::consumer::github_actions::{GithubActionsConsumer, NOT_FOUND_REASON};
use rotate::consumer::{Consumer, ConsumerError, ConsumerMatch, Holds, MatchMethod, SecretRef};
use rotate::github::GithubClient;
use rotate::plan::consumer_names;
use rotate::provider::Credential;
use rotate::secret::{SecretPair, SecretValue};

const KEY_ID: &str = "kid-test-3141";

// ---- fixtures -------------------------------------------------------------

/// The test key pair GitHub would hold; the public half is served by the
/// mock `public-key` endpoints.
fn secret_key() -> crypto_box::SecretKey {
    crypto_box::SecretKey::from([7u8; 32])
}

fn public_key_b64() -> String {
    BASE64.encode(secret_key().public_key().as_bytes())
}

fn open_sealed(encrypted_b64: &str) -> Vec<u8> {
    let bytes = BASE64
        .decode(encrypted_b64)
        .expect("encrypted_value is base64");
    secret_key()
        .unseal(&bytes)
        .expect("sealed for the test key")
}

/// An operator token that matches no scanner pattern.
fn op_token(tag: &str) -> SecretValue {
    SecretValue::from(format!("op-token-{tag}-{}", "5d1e"))
}

/// A fake AWS-shaped pair: the key id is not an AKIA/ASIA literal.
fn aws_pair(tag: &str) -> Credential {
    let key_id = format!("TESTKEY{}", tag.to_uppercase());
    let secret = format!("aws-secret-{tag}-{}", "0b9f");
    Credential::KeyPair(SecretPair::new(key_id, SecretValue::from(secret)))
}

fn token(value: String) -> Credential {
    Credential::Token(SecretValue::from(value))
}

fn config(targets: &[&str]) -> ConsumersConfig {
    let mut config = ConsumersConfig::default();
    config.github_actions.targets = targets
        .iter()
        .map(|t| ActionsTarget::try_from((*t).to_owned()).unwrap())
        .collect();
    config
}

fn consumer(rec: &CallRecorder, config: &ConsumersConfig, tag: &str) -> GithubActionsConsumer {
    GithubActionsConsumer::new(GithubClient::new(&rec.uri(), Some(op_token(tag))), config)
}

/// What the planner asks for: D4 names plus `rotate.yaml` mappings.
fn secret_ref(provider: &str, credential: &Credential, config: &ConsumersConfig) -> SecretRef {
    SecretRef::new(provider, credential).with_names(consumer_names(provider, config).all().cloned())
}

async fn mount_get(rec: &CallRecorder, at: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

async fn mount_status(rec: &CallRecorder, verb: &str, at: &str, status: u16, body: Value) {
    Mock::given(method(verb))
        .and(path(at))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

async fn mount_list(rec: &CallRecorder, base: &str, names: &[&str]) {
    let secrets: Vec<Value> = names.iter().map(|n| json!({ "name": n })).collect();
    mount_get(
        rec,
        &format!("{base}/actions/secrets"),
        json!({ "total_count": secrets.len(), "secrets": secrets }),
    )
    .await;
}

async fn mount_public_key(rec: &CallRecorder, base: &str) {
    mount_get(
        rec,
        &format!("{base}/actions/secrets/public-key"),
        json!({ "key_id": KEY_ID, "key": public_key_b64() }),
    )
    .await;
}

/// PUT requests received, in order: (path, JSON body).
async fn puts(rec: &CallRecorder) -> Vec<(String, Value)> {
    rec.calls()
        .await
        .into_iter()
        .filter(|c| c.method == "PUT")
        .map(|c| {
            let body = serde_json::from_slice(c.body()).expect("PUT body is JSON");
            (c.path.clone(), body)
        })
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// True when `haystack` holds `value` raw or base64-encoded.
fn holds_value(haystack: &[u8], value: &SecretValue) -> bool {
    value
        .expose_secret(|v| contains(haystack, v) || contains(haystack, BASE64.encode(v).as_bytes()))
}

// ---- T1 to T8 -------------------------------------------------------------

/// T1 (AC1): the AWS convention names match by name, key id first.
#[tokio::test]
async fn find_matches_aws_convention_names_by_name() {
    let rec = CallRecorder::start().await;
    mount_list(
        &rec,
        "/repos/acme/api",
        &["AWS_SECRET_ACCESS_KEY", "UNRELATED", "AWS_ACCESS_KEY_ID"],
    )
    .await;
    let cfg = config(&["acme/api"]);
    let found = consumer(&rec, &cfg, "t1")
        .find(&secret_ref("aws", &aws_pair("t1"), &cfg))
        .await
        .unwrap();
    assert_eq!(
        found,
        [
            ConsumerMatch::by_name("github-actions:acme/api:AWS_ACCESS_KEY_ID")
                .holding(Holds::KeyId),
            ConsumerMatch::by_name("github-actions:acme/api:AWS_SECRET_ACCESS_KEY"),
        ]
    );
    assert!(found.iter().all(|m| m.match_method == MatchMethod::ByName));
    assert!(found.iter().all(ConsumerMatch::is_updatable));
}

/// T2 (AC2): a mapped name matches without any convention name present.
#[tokio::test]
async fn find_matches_mapped_name_without_defaults() {
    let rec = CallRecorder::start().await;
    mount_list(&rec, "/repos/acme/api", &["PROD_AWS_SECRET", "OTHER"]).await;
    let mut cfg = config(&["acme/api"]);
    cfg.github_actions
        .secret_names
        .insert(ProviderName::Aws, vec!["PROD_AWS_SECRET".into()]);
    let found = consumer(&rec, &cfg, "t2")
        .find(&secret_ref("aws", &aws_pair("t2"), &cfg))
        .await
        .unwrap();
    assert_eq!(
        found,
        [ConsumerMatch::by_name(
            "github-actions:acme/api:PROD_AWS_SECRET"
        )]
    );
}

/// T3 (AC3): the PUT carries a sealed value and key id, never plaintext.
#[tokio::test]
async fn update_puts_sealed_value_that_decrypts_to_replacement() {
    let rec = CallRecorder::start().await;
    mount_list(&rec, "/repos/acme/api", &["NPM_TOKEN"]).await;
    mount_public_key(&rec, "/repos/acme/api").await;
    let cfg = config(&["acme/api"]);
    let c = consumer(&rec, &cfg, "t3");
    let old = token(format!("npm-old-t3-{}", "a1"));
    let new = token(format!("npm-new-t3-{}", "b2"));
    let found = c.find(&secret_ref("npm", &old, &cfg)).await.unwrap();
    assert_eq!(found.len(), 1);

    let receipt = c.update(&found[0], &new).await.unwrap();
    assert_eq!(receipt.consumer_ref, "github-actions:acme/api:NPM_TOKEN");

    let puts = puts(&rec).await;
    assert_eq!(puts.len(), 1);
    let (put_path, body) = &puts[0];
    assert_eq!(put_path, "/repos/acme/api/actions/secrets/NPM_TOKEN");
    assert_eq!(body["key_id"], KEY_ID);
    let opened = open_sealed(body["encrypted_value"].as_str().unwrap());
    assert!(new.secret().expose_secret(|v| v == opened.as_slice()));
    let raw: Vec<_> = rec
        .calls()
        .await
        .into_iter()
        .filter(|c| c.mutating)
        .collect();
    assert!(!holds_value(raw[0].body(), new.secret()));

    // The operator token goes in the Authorization header as a bearer token.
    let requests = rec.server().received_requests().await.unwrap();
    let expected = op_token("t3")
        .expose_secret_str(|t| format!("Bearer {t}"))
        .unwrap();
    assert!(
        requests
            .iter()
            .all(|r| r.headers.get("authorization").map(|h| h.as_bytes())
                == Some(expected.as_bytes()))
    );
    assert!(requests
        .iter()
        .all(|r| r.headers.get("x-github-api-version").is_some()));
}

/// T4 (AC4): an org secret keeps `selected` visibility and its repos.
#[tokio::test]
async fn update_org_secret_preserves_selected_visibility() {
    let rec = CallRecorder::start().await;
    mount_list(&rec, "/orgs/acme", &["OPENAI_API_KEY"]).await;
    mount_public_key(&rec, "/orgs/acme").await;
    mount_get(
        &rec,
        "/orgs/acme/actions/secrets/OPENAI_API_KEY",
        json!({ "name": "OPENAI_API_KEY", "visibility": "selected" }),
    )
    .await;
    mount_get(
        &rec,
        "/orgs/acme/actions/secrets/OPENAI_API_KEY/repositories",
        json!({ "total_count": 2, "repositories": [ { "id": 101 }, { "id": 202 } ] }),
    )
    .await;
    let cfg = config(&["org:acme"]);
    let c = consumer(&rec, &cfg, "t4");
    let new = token(format!("openai-new-t4-{}", "c3"));
    let found = c.find(&secret_ref("openai", &new, &cfg)).await.unwrap();
    assert_eq!(
        found[0].consumer_ref,
        "github-actions:org:acme:OPENAI_API_KEY"
    );

    c.update(&found[0], &new).await.unwrap();
    let puts = puts(&rec).await;
    let (put_path, body) = &puts[0];
    assert_eq!(put_path, "/orgs/acme/actions/secrets/OPENAI_API_KEY");
    assert_eq!(body["visibility"], "selected");
    assert_eq!(body["selected_repository_ids"], json!([101, 202]));
    assert_eq!(body["key_id"], KEY_ID);
}

/// T4 companion: `all` and `private` keep their visibility and send no ids.
#[tokio::test]
async fn update_org_secret_keeps_private_visibility() {
    let rec = CallRecorder::start().await;
    mount_list(&rec, "/orgs/acme", &["NPM_TOKEN"]).await;
    mount_public_key(&rec, "/orgs/acme").await;
    mount_get(
        &rec,
        "/orgs/acme/actions/secrets/NPM_TOKEN",
        json!({ "name": "NPM_TOKEN", "visibility": "private" }),
    )
    .await;
    let cfg = config(&["org:acme"]);
    let c = consumer(&rec, &cfg, "t4b");
    let new = token(format!("npm-new-t4b-{}", "d4"));
    let found = c.find(&secret_ref("npm", &new, &cfg)).await.unwrap();
    c.update(&found[0], &new).await.unwrap();
    let body = &puts(&rec).await[0].1;
    assert_eq!(body["visibility"], "private");
    assert!(body.get("selected_repository_ids").is_none());
}

/// T5 (AC5): restore writes the old value back.
#[tokio::test]
async fn restore_puts_old_value() {
    let rec = CallRecorder::start().await;
    mount_list(&rec, "/repos/acme/api", &["GH_PAT"]).await;
    mount_public_key(&rec, "/repos/acme/api").await;
    let cfg = config(&["acme/api"]);
    let c = consumer(&rec, &cfg, "t5");
    let old = token(format!("gh-old-t5-{}", "e5"));
    let new = token(format!("gh-new-t5-{}", "f6"));
    let found = c.find(&secret_ref("github", &old, &cfg)).await.unwrap();
    c.update(&found[0], &new).await.unwrap();
    c.restore(&found[0], &old).await.unwrap();

    let puts = puts(&rec).await;
    assert_eq!(puts.len(), 2);
    let first = open_sealed(puts[0].1["encrypted_value"].as_str().unwrap());
    let last = open_sealed(puts[1].1["encrypted_value"].as_str().unwrap());
    assert!(new.secret().expose_secret(|v| v == first.as_slice()));
    assert!(old.secret().expose_secret(|v| v == last.as_slice()));
}

/// T6 (AC6): a 404 target is not updatable, a 403 org carries GitHub's
/// message, and the other targets are still searched.
#[tokio::test]
async fn find_lists_404_target_as_not_updatable_and_checks_others() {
    let rec = CallRecorder::start().await;
    mount_status(
        &rec,
        "GET",
        "/repos/acme/gone/actions/secrets",
        404,
        json!({ "message": "Not Found" }),
    )
    .await;
    mount_status(
        &rec,
        "GET",
        "/orgs/acme/actions/secrets",
        403,
        json!({ "message": "Must have admin rights to Repository." }),
    )
    .await;
    mount_list(&rec, "/repos/acme/api", &["NPM_TOKEN"]).await;
    let cfg = config(&["acme/gone", "org:acme", "acme/api"]);
    let found = consumer(&rec, &cfg, "t6")
        .find(&secret_ref("npm", &token(format!("npm-t6-{}", "g7")), &cfg))
        .await
        .unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(found[0].consumer_ref, "github-actions:acme/gone");
    assert_eq!(
        found[0].updatable.as_ref().unwrap_err().reason,
        NOT_FOUND_REASON
    );
    assert_eq!(found[1].consumer_ref, "github-actions:org:acme");
    assert_eq!(
        found[1].updatable.as_ref().unwrap_err().reason,
        "token lacks access: Must have admin rights to Repository."
    );
    assert_eq!(found[2].consumer_ref, "github-actions:acme/api:NPM_TOKEN");
    assert!(found[2].is_updatable());

    // update on the blocked match is refused without a call.
    let before = rec.calls().await.len();
    let err = consumer(&rec, &cfg, "t6")
        .update(&found[0], &token(format!("npm-t6n-{}", "h8")))
        .await
        .unwrap_err();
    assert!(matches!(err, ConsumerError::NotUpdatable(_)));
    assert_eq!(rec.calls().await.len(), before);
}

/// T7 (AC7): find makes no PUT, POST or DELETE.
#[tokio::test]
async fn find_makes_no_mutating_calls() {
    let rec = CallRecorder::start().await;
    mount_list(
        &rec,
        "/repos/acme/api",
        &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
    )
    .await;
    mount_list(&rec, "/orgs/acme", &["AWS_SECRET_ACCESS_KEY"]).await;
    let cfg = config(&["acme/api", "org:acme"]);
    let found = consumer(&rec, &cfg, "t7")
        .find(&secret_ref("aws", &aws_pair("t7"), &cfg))
        .await
        .unwrap();
    assert_eq!(found.len(), 3);
    assert!(!rec.calls().await.is_empty());
    rec.assert_no_mutations().await;
}

/// T7 companion: without targets the consumer makes no call at all, so
/// startup and `plan` stay offline.
#[tokio::test]
async fn no_targets_makes_no_calls() {
    let rec = CallRecorder::start().await;
    let cfg = config(&[]);
    let found = consumer(&rec, &cfg, "t7b")
        .find(&secret_ref("aws", &aws_pair("t7b"), &cfg))
        .await
        .unwrap();
    assert!(found.is_empty());
    assert!(rec.calls().await.is_empty());
}

/// T8 (AC8): an AWS pair updates the key id first, then the secret.
#[tokio::test]
async fn aws_pair_puts_key_id_then_secret() {
    let rec = CallRecorder::start().await;
    mount_list(
        &rec,
        "/repos/acme/api",
        &["AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID"],
    )
    .await;
    mount_public_key(&rec, "/repos/acme/api").await;
    let cfg = config(&["acme/api"]);
    let c = consumer(&rec, &cfg, "t8");
    let old = aws_pair("t8old");
    let new = aws_pair("t8new");
    let found = c.find(&secret_ref("aws", &old, &cfg)).await.unwrap();
    for m in &found {
        c.update(m, &new).await.unwrap();
    }
    let puts = puts(&rec).await;
    let paths: Vec<&str> = puts.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/repos/acme/api/actions/secrets/AWS_ACCESS_KEY_ID",
            "/repos/acme/api/actions/secrets/AWS_SECRET_ACCESS_KEY",
        ]
    );
    let id = open_sealed(puts[0].1["encrypted_value"].as_str().unwrap());
    assert_eq!(id, new.key_id().unwrap().as_bytes());
    let secret = open_sealed(puts[1].1["encrypted_value"].as_str().unwrap());
    assert!(new.secret().expose_secret(|v| v == secret.as_slice()));
}

// ---- T9: no value or token leaks ------------------------------------------

/// T9 (AC3, AC5): old and new values and the operator token never reach
/// tracing output (TRACE, including reqwest and hyper), error text, match
/// refs, reasons or request bodies, on success and on failure.
#[tokio::test]
async fn values_and_token_never_leak() {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let rec = CallRecorder::start().await;
    mount_list(
        &rec,
        "/repos/acme/api",
        &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
    )
    .await;
    mount_public_key(&rec, "/repos/acme/api").await;
    // A second repo whose writes fail, to exercise the error paths.
    mount_list(&rec, "/repos/acme/broken", &["AWS_SECRET_ACCESS_KEY"]).await;
    mount_public_key(&rec, "/repos/acme/broken").await;
    mount_status(
        &rec,
        "PUT",
        "/repos/acme/broken/actions/secrets/AWS_SECRET_ACCESS_KEY",
        422,
        json!({ "message": "Bad request" }),
    )
    .await;
    let cfg = config(&["acme/api", "acme/broken"]);
    let c = consumer(&rec, &cfg, "t9");
    let old = aws_pair("t9leakold");
    let new = aws_pair("t9leaknew");

    let mut text = String::new();
    let found = c.find(&secret_ref("aws", &old, &cfg)).await.unwrap();
    text.push_str(&format!("{found:?} {c:?}"));
    for m in &found {
        match c.update(m, &new).await {
            Ok(receipt) => text.push_str(&format!("{receipt:?}")),
            Err(e) => text.push_str(&format!("{e} {e:?}")),
        }
        if let Err(e) = c.restore(m, &old).await {
            text.push_str(&format!("{e} {e:?}"));
        }
    }
    assert!(
        text.contains("Bad request"),
        "the failing PUT was exercised"
    );
    // A network failure too: nothing listens on this port.
    let offline = GithubActionsConsumer::new(
        GithubClient::new("http://127.0.0.1:9", Some(op_token("t9"))),
        &cfg,
    );
    if let Err(e) = offline.update(&found[0], &new).await {
        text.push_str(&format!("{e} {e:?}"));
    }

    let logs = capture.contents();
    let bodies: Vec<u8> = rec
        .calls()
        .await
        .iter()
        .flat_map(|c| c.body().to_vec())
        .collect();
    let operator = op_token("t9");
    for (what, value) in [
        ("old secret", old.secret()),
        ("new secret", new.secret()),
        ("operator token", &operator),
    ] {
        assert!(
            !holds_value(logs.as_bytes(), value),
            "{what} in tracing output"
        );
        assert!(
            !holds_value(text.as_bytes(), value),
            "{what} in errors or refs"
        );
        assert!(!holds_value(&bodies, value), "{what} in a request body");
    }
}

// ---- client behaviour -----------------------------------------------------

#[tokio::test]
async fn rate_limit_maps_to_retry_after() {
    let rec = CallRecorder::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/actions/secrets"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("retry-after", "30")
                .set_body_json(json!({ "message": "API rate limit exceeded" })),
        )
        .with_priority(1)
        .mount(rec.server())
        .await;
    let cfg = config(&["acme/api"]);
    let err = consumer(&rec, &cfg, "rl")
        .find(&secret_ref("npm", &token(format!("npm-rl-{}", "i9")), &cfg))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        ConsumerError::RateLimited {
            retry_after: Some(Duration::from_secs(30))
        }
    );
}

#[tokio::test]
async fn server_error_is_transient() {
    let rec = CallRecorder::start().await;
    mount_status(
        &rec,
        "GET",
        "/repos/acme/api/actions/secrets",
        502,
        json!({ "message": "Server Error" }),
    )
    .await;
    let cfg = config(&["acme/api"]);
    let err = consumer(&rec, &cfg, "5xx")
        .find(&secret_ref(
            "npm",
            &token(format!("npm-5xx-{}", "j1")),
            &cfg,
        ))
        .await
        .unwrap_err();
    assert!(matches!(err, ConsumerError::Transient(_)), "{err}");
}

#[tokio::test]
async fn pagination_follows_link() {
    let rec = CallRecorder::start().await;
    let next = format!(
        "{}/repos/acme/api/actions/secrets?per_page=100&page=2",
        rec.uri()
    );
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/actions/secrets"))
        .and(query_param("page", "2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "total_count": 2, "secrets": [ { "name": "NPM_TOKEN" } ] })),
        )
        .with_priority(1)
        .mount(rec.server())
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/actions/secrets"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("link", format!("<{next}>; rel=\"next\"").as_str())
                .set_body_json(json!({ "total_count": 2, "secrets": [ { "name": "A" } ] })),
        )
        .with_priority(2)
        .mount(rec.server())
        .await;
    let cfg = config(&["acme/api"]);
    let found = consumer(&rec, &cfg, "pg")
        .find(&secret_ref("npm", &token(format!("npm-pg-{}", "k2")), &cfg))
        .await
        .unwrap();
    assert_eq!(found[0].consumer_ref, "github-actions:acme/api:NPM_TOKEN");
    let gets = rec.calls().await;
    assert_eq!(gets.len(), 2);
    assert!(gets[0].query.as_deref().unwrap().contains("per_page=100"));
}

#[tokio::test]
async fn next_link_to_other_host_is_refused() {
    let rec = CallRecorder::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api/actions/secrets"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "link",
                    "<https://elsewhere.invalid/steal?page=2>; rel=\"next\"",
                )
                .set_body_json(json!({ "total_count": 9, "secrets": [] })),
        )
        .with_priority(1)
        .mount(rec.server())
        .await;
    let cfg = config(&["acme/api"]);
    let err = consumer(&rec, &cfg, "host")
        .find(&secret_ref(
            "npm",
            &token(format!("npm-host-{}", "l3")),
            &cfg,
        ))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("outside the API base URL"),
        "{err}"
    );
    assert_eq!(rec.calls().await.len(), 1);
}

#[tokio::test]
async fn missing_token_fails_find_without_calls() {
    let rec = CallRecorder::start().await;
    let cfg = config(&["acme/api"]);
    let c = GithubActionsConsumer::new(GithubClient::new(&rec.uri(), None), &cfg);
    let err = c
        .find(&secret_ref("npm", &token(format!("npm-nt-{}", "m4")), &cfg))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ROTATE_GITHUB_TOKEN"));
    assert!(rec.calls().await.is_empty());
}

// ---- T10: conformance -----------------------------------------------------

struct RecorderProbe(CallRecorder);

#[async_trait]
impl MutationProbe for RecorderProbe {
    async fn mutations(&self) -> Vec<String> {
        self.0
            .calls()
            .await
            .into_iter()
            .filter(|c| c.mutating)
            .map(|c| format!("{} {}", c.method, c.path))
            .collect()
    }
}

/// T10 (AC1 to AC8): the shared consumer suite, by name, for an AWS pair
/// stored in one repo and one org.
#[tokio::test]
async fn conformance() {
    consumer_suite(|| async {
        let rec = CallRecorder::start().await;
        for base in ["/repos/acme/api", "/orgs/acme"] {
            mount_list(&rec, base, &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]).await;
            mount_public_key(&rec, base).await;
        }
        for name in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] {
            mount_get(
                &rec,
                &format!("/orgs/acme/actions/secrets/{name}"),
                json!({ "name": name, "visibility": "all" }),
            )
            .await;
        }
        let cfg = config(&["acme/api", "org:acme"]);
        let old = aws_pair("confold");
        let new = aws_pair("confnew");
        let secret = secret_ref("aws", &old, &cfg);
        ConsumerFixture {
            consumer: Arc::new(consumer(&rec, &cfg, "conf")),
            old,
            new,
            secret,
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await
    .assert_ok();
}

// ---- live -----------------------------------------------------------------

/// Read-only: lists the Actions secrets of `ROTATE_LIVE_GITHUB_REPO`
/// (`owner/repo`) with the operator token from the environment.
#[tokio::test]
#[ignore]
async fn live_github_actions_find() {
    common::live_guard!();
    let Some(repo) = common::require_env("ROTATE_LIVE_GITHUB_REPO") else {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "skipped: ROTATE_LIVE_GITHUB_REPO not set"
        );
        return;
    };
    let cfg = config(&[repo.as_str()]);
    let c = GithubActionsConsumer::from_config(&cfg, &Default::default());
    let probe = token(format!("live-probe-{}", "n5"));
    let found = c.find(&secret_ref("npm", &probe, &cfg)).await;
    assert!(found.is_ok(), "{}", found.unwrap_err());
}
