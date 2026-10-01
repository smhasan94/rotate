//! SHA-251: the AWS provider's read side against wiremock.
//!
//! Every test points STS and IAM at a `CallRecorder`. AWS query actions are
//! POSTs, so `Get*` and `List*` actions are marked read-only; anything else
//! counts as a mutation. Key ids and secrets are built at runtime so no
//! literal here matches a secret-scanning pattern.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use wiremock::matchers::body_string_contains;
use wiremock::{Match, Mock, Request, ResponseTemplate};

use rotate::assess::{self, AssessOptions, Disposition};
use rotate::config::{ConsumersConfig, Overlap};
use rotate::conformance::{provider_suite, MutationProbe, Outcome, ProviderFixture};
use rotate::consumer::ConsumerRegistry;
use rotate::finding::{Finding, SourceLocation, ACCESS_KEY_ID, IS_CANARY};
use rotate::plan;
use rotate::provider::aws::{AwsProvider, TEMPORARY_CREDENTIAL};
use rotate::provider::{Credential, Provider, ProviderRegistry, Validity};
use rotate::secret::{SecretPair, SecretValue};

use common::CallRecorder;

const ACCOUNT: &str = "000000000000";

/// A 20-char key id: `prefix` + 9 chars of the documentation example + a
/// 7-char tag. Built at runtime.
fn key_id(prefix: &str, tag: &str) -> String {
    assert_eq!(tag.len(), 7);
    let doc = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    format!("{prefix}{}{tag}", &doc[4..13])
}

/// A unique 40-char secret per test (the redaction registry is process
/// wide), built at runtime.
fn secret(tag: &str) -> SecretValue {
    assert_eq!(tag.len(), 8);
    SecretValue::from(["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", tag, "Q0"].concat())
}

fn plain(value: &SecretValue) -> String {
    value.expose_secret_str(str::to_owned).unwrap()
}

fn pair(id: &str, value: SecretValue) -> Credential {
    Credential::KeyPair(SecretPair::new(id, value))
}

fn user_arn(name: &str) -> String {
    format!("arn:aws:iam::{ACCOUNT}:user/{name}")
}

async fn recorder() -> CallRecorder {
    let mut rec = CallRecorder::start().await;
    rec.mark_read_only(|req| {
        let body = String::from_utf8_lossy(&req.body);
        body.contains("Action=Get") || body.contains("Action=List")
    });
    rec
}

fn provider(rec: &CallRecorder) -> AwsProvider {
    AwsProvider::new()
        .with_region("us-east-1")
        .with_endpoint_url(rec.uri())
}

/// Matches requests signed with `key_id` (SigV4 `Credential=<id>/...`).
struct SignedBy(String);

impl Match for SignedBy {
    fn matches(&self, req: &Request) -> bool {
        req.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains(&format!("Credential={}/", self.0)))
    }
}

fn xml(status: u16, body: String) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "text/xml")
        .set_body_string(body)
}

async fn mount_caller(rec: &CallRecorder, id: &str, arn: &str) {
    let body = format!(
        "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <GetCallerIdentityResult><Arn>{arn}</Arn><UserId>AIDAEXAMPLEUSERID</UserId>\
         <Account>{ACCOUNT}</Account></GetCallerIdentityResult>\
         <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>\
         </GetCallerIdentityResponse>"
    );
    Mock::given(body_string_contains("Action=GetCallerIdentity"))
        .and(SignedBy(id.to_owned()))
        .respond_with(xml(200, body))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

fn error_xml(code: &str) -> String {
    format!(
        "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <Error><Type>Sender</Type><Code>{code}</Code>\
         <Message>The security token included in the request is invalid.</Message></Error>\
         <RequestId>req-2</RequestId></ErrorResponse>"
    )
}

async fn mount_error(rec: &CallRecorder, action: &str, id: &str, code: &str) {
    Mock::given(body_string_contains(format!("Action={action}")))
        .and(SignedBy(id.to_owned()))
        .respond_with(xml(403, error_xml(code)))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

fn iam(action: &str, result: &str) -> String {
    format!(
        "<{action}Response xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">\
         <{action}Result>{result}</{action}Result>\
         <ResponseMetadata><RequestId>req-3</RequestId></ResponseMetadata></{action}Response>"
    )
}

async fn mount_iam(rec: &CallRecorder, user: &str) {
    let answers = [
        (
            "GetAccessKeyLastUsed",
            format!(
                "<UserName>{user}</UserName><AccessKeyLastUsed>\
                 <LastUsedDate>2026-09-01T10:00:00Z</LastUsedDate>\
                 <ServiceName>s3</ServiceName><Region>eu-west-1</Region></AccessKeyLastUsed>"
            ),
        ),
        (
            "ListAttachedUserPolicies",
            "<AttachedPolicies>\
             <member><PolicyName>ReadOnlyAccess</PolicyName>\
             <PolicyArn>arn:aws:iam::aws:policy/ReadOnlyAccess</PolicyArn></member>\
             <member><PolicyName>DeployBucketWrite</PolicyName>\
             <PolicyArn>arn:aws:iam::000000000000:policy/DeployBucketWrite</PolicyArn></member>\
             </AttachedPolicies><IsTruncated>false</IsTruncated>"
                .to_owned(),
        ),
        (
            "ListUserPolicies",
            "<PolicyNames><member>inline-ci</member></PolicyNames>\
             <IsTruncated>false</IsTruncated>"
                .to_owned(),
        ),
        (
            "ListGroupsForUser",
            "<Groups><member><Path>/</Path><GroupName>deployers</GroupName>\
             <GroupId>AGPAEXAMPLEGROUPID</GroupId>\
             <Arn>arn:aws:iam::000000000000:group/deployers</Arn>\
             <CreateDate>2020-01-01T00:00:00Z</CreateDate></member></Groups>\
             <IsTruncated>false</IsTruncated>"
                .to_owned(),
        ),
    ];
    for (action, result) in answers {
        Mock::given(body_string_contains(format!("Action={action}")))
            .respond_with(xml(200, iam(action, &result)))
            .with_priority(1)
            .mount(rec.server())
            .await;
    }
}

/// T7 (AC7): no recorded request asked for a mutating IAM or STS action.
async fn assert_no_mutating_actions(rec: &CallRecorder) {
    for call in rec.calls().await {
        let body = call.body_str();
        for verb in ["Create", "Update", "Delete", "Put"] {
            assert!(
                !body.contains(&format!("Action={verb}")),
                "mutating action {verb}* requested: {} {}",
                call.method,
                call.path
            );
        }
    }
    rec.assert_no_mutations().await;
}

fn finding(id: &str, value: SecretValue) -> Finding {
    Finding::new(value, "AWS", SourceLocation::file("deploy/aws.env")).with_extra(ACCESS_KEY_ID, id)
}

fn registry(p: AwsProvider) -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(p));
    registry
}

fn fast_opts() -> AssessOptions {
    AssessOptions {
        concurrency: 2,
        attempts: 3,
        base_delay: Duration::from_millis(1),
        force_provider: None,
    }
}

// T2 (AC2)
#[tokio::test]
async fn check_valid_valid_signed_with_leaked_key_id() {
    let rec = recorder().await;
    let id = key_id("AKIA", "T2VALID");
    let value = secret("t2valid0");
    mount_caller(&rec, &id, &user_arn("alice")).await;

    let got = provider(&rec)
        .check_valid(&pair(&id, value.clone()))
        .await
        .unwrap();
    assert_eq!(got, Validity::Valid);

    let requests = rec.server().received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let auth = requests[0]
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_owned();
    assert!(auth.starts_with("AWS4-HMAC-SHA256"), "not SigV4");
    assert!(
        auth.contains(&format!("Credential={id}/")),
        "key id missing"
    );
    assert!(!auth.contains(&plain(&value)), "secret in the header");
    assert_no_mutating_actions(&rec).await;
}

// T3 (AC3)
#[tokio::test]
async fn check_valid_invalid_client_token_id() {
    let rec = recorder().await;
    let p = provider(&rec);
    for (tag, code) in [
        ("T3INVAL", "InvalidClientTokenId"),
        ("T3SIGNA", "SignatureDoesNotMatch"),
    ] {
        let id = key_id("AKIA", tag);
        mount_error(&rec, "GetCallerIdentity", &id, code).await;
        let got = p.check_valid(&pair(&id, secret("t3invali"))).await.unwrap();
        assert_eq!(got, Validity::Invalid, "{code}");
    }
    assert_no_mutating_actions(&rec).await;
}

// T4 (AC4)
#[tokio::test]
async fn check_valid_503_three_attempts_unknown() {
    let rec = recorder().await;
    let id = key_id("AKIA", "T4UNAVL");
    Mock::given(body_string_contains("Action=GetCallerIdentity"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(1)
        .expect(3)
        .mount(rec.server())
        .await;

    let assessed = assess::assess(
        vec![finding(&id, secret("t4unavai"))],
        &registry(provider(&rec)),
        &fast_opts(),
    )
    .await;
    match &assessed[0].validity {
        Some(Validity::Unknown { reason }) => {
            assert!(reason.contains("503"), "{reason}");
            assert!(reason.contains("GetCallerIdentity"), "{reason}");
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
    rec.server().verify().await;
    assert_no_mutating_actions(&rec).await;
}

// T5 (AC5)
#[tokio::test]
async fn describe_scope_lists_user_account_last_used_policies() {
    let rec = recorder().await;
    let id = key_id("AKIA", "T5SCOPE");
    mount_caller(&rec, &id, &user_arn("alice")).await;
    mount_iam(&rec, "alice").await;

    let scope = provider(&rec)
        .describe_scope(&pair(&id, secret("t5scope0")))
        .await
        .unwrap();
    assert_eq!(scope.identity.0, user_arn("alice"));
    for want in [
        format!("account: {ACCOUNT}"),
        "user: alice".to_owned(),
        "last used: s3 in eu-west-1 at 2026-09-01T10:00:00Z".to_owned(),
        "attached policy: ReadOnlyAccess".to_owned(),
        "attached policy: DeployBucketWrite".to_owned(),
        "inline policy: inline-ci".to_owned(),
        "group: deployers".to_owned(),
    ] {
        assert!(scope.lines.contains(&want), "{want:?} missing: {scope:?}");
    }
    let actions: Vec<String> = rec
        .calls()
        .await
        .iter()
        .map(|c| c.body_str().split('&').next().unwrap_or("").to_owned())
        .collect();
    for action in [
        "GetCallerIdentity",
        "GetAccessKeyLastUsed",
        "ListAttachedUserPolicies",
        "ListUserPolicies",
        "ListGroupsForUser",
    ] {
        assert!(
            actions.contains(&format!("Action={action}")),
            "{action} not called: {actions:?}"
        );
    }
    assert_no_mutating_actions(&rec).await;
}

// T5 (AC5): a leaked key without IAM read rights still gets user and
// account, and each denied read becomes a line.
#[tokio::test]
async fn describe_scope_access_denied_is_a_line() {
    let rec = recorder().await;
    let id = key_id("AKIA", "T5DENYD");
    mount_caller(&rec, &id, &user_arn("ci/bob")).await;
    for action in [
        "GetAccessKeyLastUsed",
        "ListAttachedUserPolicies",
        "ListUserPolicies",
        "ListGroupsForUser",
    ] {
        mount_error(&rec, action, &id, "AccessDenied").await;
    }
    let scope = provider(&rec)
        .describe_scope(&pair(&id, secret("t5denied")))
        .await
        .unwrap();
    assert!(scope.lines.contains(&"user: bob".to_owned()), "{scope:?}");
    assert!(scope
        .lines
        .contains(&"attached policies: not visible to the leaked key (AccessDenied)".to_owned()));
    assert_eq!(
        scope
            .lines
            .iter()
            .filter(|l| l.contains("not visible"))
            .count(),
        4
    );
    assert_no_mutating_actions(&rec).await;
}

// T6 (AC6)
#[tokio::test]
async fn asia_key_is_temporary_unknown_without_calls() {
    let rec = recorder().await;
    let id = key_id("ASIA", "T6TEMPO");
    let providers = registry(provider(&rec));
    assert_eq!(
        providers
            .get("aws")
            .unwrap()
            .identify(&finding(&id, secret("t6tempor"))),
        Some(rotate::provider::Confidence::High)
    );
    let assessed = assess::assess(
        vec![finding(&id, secret("t6tempor"))],
        &providers,
        &fast_opts(),
    )
    .await;
    assert_eq!(
        assessed[0].validity,
        Some(Validity::Unknown {
            reason: TEMPORARY_CREDENTIAL.into()
        })
    );

    let built = plan::build(
        assessed,
        &providers,
        &ConsumerRegistry::new(),
        Overlap::default(),
        &ConsumersConfig::default(),
    )
    .await;
    assert!(built.rotations.is_empty(), "no replacement step");
    assert_eq!(built.skipped.len(), 1);
    assert_eq!(built.skipped[0].reason, "unknown");
    assert_eq!(
        built.skipped[0].detail.as_deref(),
        Some(TEMPORARY_CREDENTIAL)
    );
    let table = plan::render_table(&built);
    assert!(table.contains(TEMPORARY_CREDENTIAL), "{table}");
    assert!(!table.contains("replacement:"), "{table}");
    assert!(rec.calls().await.is_empty(), "an ASIA key reached AWS");
}

// Canary tokens alert whoever planted them on any API call: assessment
// stops them before the provider, so AWS never sees one.
#[tokio::test]
async fn canary_finding_never_reaches_aws() {
    let rec = recorder().await;
    let id = key_id("AKIA", "CANARY0");
    let canary = finding(&id, secret("canary00")).with_extra(IS_CANARY, "true");
    let assessed = assess::assess(vec![canary], &registry(provider(&rec)), &fast_opts()).await;
    assert!(matches!(
        assessed[0].disposition,
        Disposition::NotRotatable { .. }
    ));
    assert_eq!(assessed[0].validity, None);
    assert!(rec.calls().await.is_empty(), "a canary key reached AWS");
}

#[tokio::test]
async fn example_key_is_invalid_without_calls() {
    let rec = recorder().await;
    let doc = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    let assessed = assess::assess(
        vec![finding(&doc, secret("example0"))],
        &registry(provider(&rec)),
        &fast_opts(),
    )
    .await;
    assert_eq!(assessed[0].validity, Some(Validity::Invalid));
    assert!(rec.calls().await.is_empty());
}

#[tokio::test]
async fn token_credential_is_unsupported() {
    let rec = recorder().await;
    let err = provider(&rec)
        .check_valid(&Credential::Token(secret("tokenonl")))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("KEY_ID:SECRET"), "{err}");
    assert!(rec.calls().await.is_empty());
}

#[tokio::test]
async fn new_makes_no_calls() {
    let rec = recorder().await;
    let providers = registry(provider(&rec));
    let id = key_id("AKIA", "NOCALLS");
    assert!(providers
        .identify(&finding(&id, secret("nocalls0")))
        .unwrap()
        .is_some());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(rec.calls().await.is_empty());
}

/// A TRACE-level capture installed as this binary's global subscriber.
///
/// Global rather than scoped: with a scoped subscriber, tests running on
/// other threads leave the SDK's callsites cached as disabled and the
/// capture comes back empty. Every test here then logs into it, which is
/// fine: none of them may log a secret either.
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

// T8 (AC2, AC5)
#[tokio::test]
async fn secret_never_in_logs_output_or_requests() {
    let capture = trace_capture();

    let rec = recorder().await;
    let id = key_id("AKIA", "T8LEAKS");
    let value = secret("t8leakca");
    mount_caller(&rec, &id, &user_arn("carol")).await;
    mount_iam(&rec, "carol").await;
    let unknown_id = key_id("AKIA", "T8UNKNW");
    let unknown_value = secret("t8unknwn");
    mount_error(
        &rec,
        "GetCallerIdentity",
        &unknown_id,
        "InvalidClientTokenId",
    )
    .await;

    let assessed = assess::assess(
        vec![
            finding(&id, value.clone()),
            finding(&unknown_id, unknown_value.clone()),
        ],
        &registry(provider(&rec)),
        &fast_opts(),
    )
    .await;
    assert!(assessed
        .iter()
        .any(|a| a.validity == Some(Validity::Valid) && a.scope.is_some()));
    let table = assess::render_table(&assessed);
    let json = assess::render_json(&assessed);
    let debug = format!("{assessed:?}");
    let logs = capture.contents();
    assert!(
        logs.contains("GetCallerIdentity") || logs.contains("sts"),
        "TRACE capture saw no SDK events"
    );

    let requests = rec.server().received_requests().await.unwrap();
    assert!(!requests.is_empty());
    for v in [plain(&value), plain(&unknown_value)] {
        for (label, text) in [
            ("table", &table),
            ("json", &json),
            ("debug", &debug),
            ("logs", &logs),
        ] {
            assert!(!text.contains(&v), "secret in {label}");
        }
        for req in &requests {
            assert!(
                !String::from_utf8_lossy(&req.body).contains(&v),
                "secret in a request body"
            );
            for (name, header) in &req.headers {
                let header = header.to_str().unwrap_or("");
                assert!(!header.contains(&v), "secret in header {name}");
            }
        }
    }
    assert_no_mutating_actions(&rec).await;
}

/// Labels the recorder's state-changing calls by action, never by body.
struct RecorderProbe(CallRecorder);

#[async_trait]
impl MutationProbe for RecorderProbe {
    async fn mutations(&self) -> Vec<String> {
        self.0
            .calls()
            .await
            .iter()
            .filter(|c| c.mutating)
            .map(|c| {
                let action = c
                    .body_str()
                    .split('&')
                    .find_map(|p| p.strip_prefix("Action=").map(str::to_owned))
                    .unwrap_or_default();
                format!("{} {} {action}", c.method, c.path)
            })
            .collect()
    }
}

/// Checks that need the write side (SHA-255) and fail until then.
const WRITE_SIDE: &[&str] = &[
    "replacement_differs",
    "verify_wrong_identity_fails",
    "idempotent_revoke",
    "restore_outcome",
];

// T9 (AC1, AC3, AC7)
#[tokio::test]
async fn conformance_read_side() {
    let report = provider_suite(|| async {
        let rec = recorder().await;
        let live_id = key_id("AKIA", "T9LIVE0");
        let unknown_id = key_id("AKIA", "T9UNKNO");
        mount_caller(&rec, &live_id, &user_arn("dave")).await;
        mount_iam(&rec, "dave").await;
        mount_error(
            &rec,
            "GetCallerIdentity",
            &unknown_id,
            "InvalidClientTokenId",
        )
        .await;
        ProviderFixture {
            provider: Arc::new(provider(&rec)),
            live: pair(&live_id, secret("t9live00")),
            identity: rotate::provider::Identity(user_arn("dave")),
            unknown: pair(&unknown_id, secret("t9unknow")),
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await;
    assert_eq!(report.plugin, "aws");
    for check in &report.checks {
        if WRITE_SIDE.contains(&check.name) {
            continue;
        }
        assert_eq!(check.outcome, Outcome::Passed, "{}: {report}", check.name);
    }
    for name in [
        "identify_rejects_foreign",
        "check_valid_unknown_invalid",
        "read_only_check_valid",
        "read_only_describe_scope",
        "read_only_verify",
        "errors_redacted",
    ] {
        assert!(
            report.checks.iter().any(|c| c.name == name),
            "{name} did not run"
        );
    }
}

// Live: a real key pair from the environment. Read-only calls only.
#[tokio::test]
#[ignore]
async fn live_aws_check_valid_and_scope() {
    common::live_guard!();
    let (Some(id), Some(value)) = (
        common::require_env("ROTATE_LIVE_AWS_ACCESS_KEY_ID"),
        common::require_env("ROTATE_LIVE_AWS_SECRET_ACCESS_KEY"),
    ) else {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "skipped: ROTATE_LIVE_AWS_ACCESS_KEY_ID and ROTATE_LIVE_AWS_SECRET_ACCESS_KEY not set"
        );
        return;
    };
    let credential = pair(&id, SecretValue::from(value));
    let p = AwsProvider::new();
    assert_eq!(p.check_valid(&credential).await.unwrap(), Validity::Valid);
    let scope = p.describe_scope(&credential).await.unwrap();
    assert!(
        scope.identity.0.starts_with("arn:aws"),
        "{}",
        scope.identity
    );
}
