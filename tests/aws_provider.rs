//! The AWS provider against wiremock: SHA-251 read side, SHA-255 write side.
//!
//! Every test points STS and IAM at a `CallRecorder`. AWS query actions are
//! POSTs, so `Get*` and `List*` actions are marked read-only; anything else
//! counts as a mutation. Operator calls are signed by a separate operator
//! key id, so `SignedBy` shows which key signed what. Key ids and secrets
//! are built at runtime so no literal here matches a secret-scanning
//! pattern.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::{future, ProvideCredentials};
use aws_sdk_sts::config::Credentials;
use wiremock::matchers::body_string_contains;
use wiremock::{Match, Mock, Request, ResponseTemplate};

use rotate::apply::{self, Executor, RunResult};
use rotate::assess::{self, AssessOptions, Disposition};
use rotate::audit::AuditLog;
use rotate::config::{ConsumersConfig, Overlap};
use rotate::conformance::{provider_suite, MutationProbe, Outcome, ProviderFixture};
use rotate::consumer::mock::MockConsumer;
use rotate::consumer::{ConsumerMatch, ConsumerRegistry};
use rotate::finding::{Finding, SourceLocation, ACCESS_KEY_ID, IS_CANARY};
use rotate::plan;
use rotate::provider::aws::{AwsProvider, NO_OPERATOR_CREDENTIALS, TEMPORARY_CREDENTIAL};
use rotate::provider::{
    Credential, Identity, Provider, ProviderError, ProviderRegistry, RestoreOutcome, Validity,
};
use rotate::secret::{SecretPair, SecretValue};
use rotate::state::StateStore;

use common::CallRecorder;

const ACCOUNT: &str = "000000000000";

/// A 20-char key id: `prefix` + 9 chars of the documentation example + a
/// 7-char tag. Built at runtime.
fn key_id(prefix: &str, tag: &str) -> String {
    assert_eq!(tag.len(), 7);
    let doc = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    format!("{prefix}{}{tag}", &doc[4..13])
}

/// The operator's key id. Never a leaked key.
fn operator_id() -> String {
    key_id("AKIA", "OPERATR")
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

fn operator_credentials() -> Credentials {
    let value = ["operatorSecretFromTheChain", "0000000000000x"].concat();
    Credentials::new(operator_id(), value, None, None, "test-operator")
}

/// The provider under test: wiremock endpoint, operator credentials and a
/// fast verify loop (10 ms between attempts, 500 ms budget).
fn provider(rec: &CallRecorder) -> AwsProvider {
    AwsProvider::new()
        .with_region("us-east-1")
        .with_endpoint_url(rec.uri())
        .with_operator_credentials(operator_credentials())
        .with_verify_timing(Duration::from_millis(10), Duration::from_millis(500))
}

/// Matches requests signed with `key_id` (SigV4 `Credential=<id>/...`).
struct SignedBy(String);

impl Match for SignedBy {
    fn matches(&self, req: &Request) -> bool {
        signer(req).as_deref() == Some(self.0.as_str())
    }
}

/// The key id a request was signed with.
fn signer(req: &Request) -> Option<String> {
    let auth = req.headers.get("authorization")?.to_str().ok()?;
    let rest = auth.split("Credential=").nth(1)?;
    rest.split('/').next().map(str::to_owned)
}

fn operator() -> SignedBy {
    SignedBy(operator_id())
}

fn xml(status: u16, body: String) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "text/xml")
        .set_body_string(body)
}

async fn mount_caller(rec: &CallRecorder, id: &str, arn: &str) {
    Mock::given(body_string_contains("Action=GetCallerIdentity"))
        .and(SignedBy(id.to_owned()))
        .respond_with(xml(200, caller_xml(arn)))
        .with_priority(2)
        .mount(rec.server())
        .await;
}

fn caller_xml(arn: &str) -> String {
    format!(
        "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <GetCallerIdentityResult><Arn>{arn}</Arn><UserId>AIDAEXAMPLEUSERID</UserId>\
         <Account>{ACCOUNT}</Account></GetCallerIdentityResult>\
         <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>\
         </GetCallerIdentityResponse>"
    )
}

fn error_xml(code: &str) -> String {
    format!(
        "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <Error><Type>Sender</Type><Code>{code}</Code>\
         <Message>The security token included in the request is invalid.</Message></Error>\
         <RequestId>req-2</RequestId></ErrorResponse>"
    )
}

async fn mount_error(rec: &CallRecorder, action: &str, signed_by: &str, code: &str) {
    Mock::given(body_string_contains(format!("Action={action}&")))
        .and(SignedBy(signed_by.to_owned()))
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

const LAST_USED: &str = "2026-09-01T10:00:00Z";

/// Operator-signed answers for the owner and scope reads of `user`.
async fn mount_iam(rec: &CallRecorder, user: &str) {
    let answers = [
        (
            "GetAccessKeyLastUsed",
            format!(
                "<UserName>{user}</UserName><AccessKeyLastUsed>\
                 <LastUsedDate>{LAST_USED}</LastUsedDate>\
                 <ServiceName>s3</ServiceName><Region>eu-west-1</Region></AccessKeyLastUsed>"
            ),
        ),
        (
            "GetUser",
            format!(
                "<User><Path>/</Path><UserName>{user}</UserName>\
                 <UserId>AIDAEXAMPLEUSERID</UserId><Arn>{}</Arn>\
                 <CreateDate>2020-01-01T00:00:00Z</CreateDate></User>",
                user_arn(user)
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
        Mock::given(body_string_contains(format!("Action={action}&")))
            .and(operator())
            .respond_with(xml(200, iam(action, &result)))
            .with_priority(3)
            .mount(rec.server())
            .await;
    }
}

/// `ListAccessKeys` for `user` answers `keys` (id, status).
async fn mount_keys(rec: &CallRecorder, user: &str, keys: &[(&str, &str)]) {
    let members: String = keys
        .iter()
        .map(|(id, status)| {
            format!(
                "<member><UserName>{user}</UserName><AccessKeyId>{id}</AccessKeyId>\
                 <Status>{status}</Status><CreateDate>2020-01-01T00:00:00Z</CreateDate></member>"
            )
        })
        .collect();
    let result =
        format!("<AccessKeyMetadata>{members}</AccessKeyMetadata><IsTruncated>false</IsTruncated>");
    Mock::given(body_string_contains("Action=ListAccessKeys&"))
        .and(operator())
        .respond_with(xml(200, iam("ListAccessKeys", &result)))
        .with_priority(3)
        .mount(rec.server())
        .await;
}

/// `GetAccessKeyLastUsed` for `id` says it was never used.
async fn mount_never_used(rec: &CallRecorder, user: &str, id: &str) {
    let result = format!(
        "<UserName>{user}</UserName><AccessKeyLastUsed>\
         <ServiceName>N/A</ServiceName><Region>N/A</Region></AccessKeyLastUsed>"
    );
    Mock::given(body_string_contains("Action=GetAccessKeyLastUsed&"))
        .and(body_string_contains(format!("AccessKeyId={id}")))
        .and(operator())
        .respond_with(xml(200, iam("GetAccessKeyLastUsed", &result)))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

/// `CreateAccessKey` for `user` returns `new_id` and `new_secret`.
async fn mount_create(rec: &CallRecorder, user: &str, new_id: &str, new_secret: &SecretValue) {
    let result = format!(
        "<AccessKey><UserName>{user}</UserName><AccessKeyId>{new_id}</AccessKeyId>\
         <Status>Active</Status><SecretAccessKey>{}</SecretAccessKey>\
         <CreateDate>2026-10-01T00:00:00Z</CreateDate></AccessKey>",
        plain(new_secret)
    );
    Mock::given(body_string_contains("Action=CreateAccessKey&"))
        .and(operator())
        .respond_with(xml(200, iam("CreateAccessKey", &result)))
        .with_priority(3)
        .mount(rec.server())
        .await;
}

async fn mount_update(rec: &CallRecorder) {
    let body = "<UpdateAccessKeyResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">\
                <ResponseMetadata><RequestId>req-4</RequestId></ResponseMetadata>\
                </UpdateAccessKeyResponse>"
        .to_owned();
    Mock::given(body_string_contains("Action=UpdateAccessKey&"))
        .and(operator())
        .respond_with(xml(200, body))
        .with_priority(3)
        .mount(rec.server())
        .await;
}

/// Everything a full rotation of `leaked` (owned by `user`) needs, with the
/// replacement `new_id` answering STS as `new_arn`.
async fn mount_rotation(
    rec: &CallRecorder,
    user: &str,
    leaked: &str,
    new_id: &str,
    new_secret: &SecretValue,
    new_arn: &str,
) {
    mount_caller(rec, leaked, &user_arn(user)).await;
    mount_iam(rec, user).await;
    mount_keys(rec, user, &[(leaked, "Active")]).await;
    mount_create(rec, user, new_id, new_secret).await;
    mount_caller(rec, new_id, new_arn).await;
    mount_update(rec).await;
}

/// Decoded form fields of a recorded query-API body.
fn fields(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| {
            let decode = |s: &str| urlencoding::decode(s).map(|c| c.into_owned());
            (decode(k).unwrap_or_default(), decode(v).unwrap_or_default())
        })
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Recorded calls of one action, as decoded fields.
async fn calls_of(rec: &CallRecorder, action: &str) -> Vec<Vec<(String, String)>> {
    rec.calls()
        .await
        .iter()
        .map(|c| fields(&c.body_str()))
        .filter(|f| field(f, "Action") == Some(action))
        .collect()
}

/// `(AccessKeyId, Status)` of every `UpdateAccessKey`, in order.
async fn updates(rec: &CallRecorder) -> Vec<(String, String)> {
    calls_of(rec, "UpdateAccessKey")
        .await
        .iter()
        .map(|f| {
            (
                field(f, "AccessKeyId").unwrap_or_default().to_owned(),
                field(f, "Status").unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// T8 (AC8): no recorded request ever asked for a delete.
async fn assert_no_delete(rec: &CallRecorder) {
    for call in rec.calls().await {
        let body = call.body_str();
        assert!(
            !body.contains("Action=Delete"),
            "delete requested: {} {}",
            call.method,
            call.path
        );
    }
}

/// T7 (SHA-251 AC7): no recorded request asked for a mutating action.
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

/// Key ids that signed at least one request, with the actions they signed.
async fn signed_actions(rec: &CallRecorder, id: &str) -> Vec<String> {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| signer(r).as_deref() == Some(id))
        .map(|r| {
            field(&fields(&String::from_utf8_lossy(&r.body)), "Action")
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
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

// SHA-251 T2 (AC2)
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

// SHA-251 T3 (AC3)
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

// SHA-251 T4 (AC4)
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

// SHA-251 T5 (AC5), now read with the operator's credentials.
#[tokio::test]
async fn describe_scope_lists_user_account_last_used_policies() {
    let rec = recorder().await;
    let id = key_id("AKIA", "T5SCOPE");
    mount_iam(&rec, "alice").await;
    mount_keys(&rec, "alice", &[(&id, "Active")]).await;

    let scope = provider(&rec)
        .describe_scope(&pair(&id, secret("t5scope0")))
        .await
        .unwrap();
    assert_eq!(scope.identity.0, user_arn("alice"));
    for want in [
        format!("account: {ACCOUNT}"),
        "user: alice".to_owned(),
        format!("last used: s3 in eu-west-1 at {LAST_USED}"),
        "attached policy: ReadOnlyAccess".to_owned(),
        "attached policy: DeployBucketWrite".to_owned(),
        "inline policy: inline-ci".to_owned(),
        "group: deployers".to_owned(),
        "access keys: 1 of 2 used".to_owned(),
    ] {
        assert!(scope.lines.contains(&want), "{want:?} missing: {scope:?}");
    }
    assert!(!scope.lines.iter().any(|l| l.starts_with("warning: ")));
    let actions = signed_actions(&rec, &operator_id()).await;
    for action in [
        "GetAccessKeyLastUsed",
        "GetUser",
        "ListAttachedUserPolicies",
        "ListUserPolicies",
        "ListGroupsForUser",
        "ListAccessKeys",
    ] {
        assert!(
            actions.iter().any(|a| a == action),
            "{action} not called: {actions:?}"
        );
    }
    assert!(signed_actions(&rec, &id).await.is_empty());
    assert_no_mutating_actions(&rec).await;
}

// Decision 1: the leaked key signs only the validity check; the scope
// reads are signed by the operator.
#[tokio::test]
async fn check_valid_is_the_only_leaked_key_call() {
    let rec = recorder().await;
    let id = key_id("AKIA", "ONLYSTS");
    mount_caller(&rec, &id, &user_arn("ivy")).await;
    mount_iam(&rec, "ivy").await;
    mount_keys(&rec, "ivy", &[(&id, "Active")]).await;

    let assessed = assess::assess(
        vec![finding(&id, secret("onlysts0"))],
        &registry(provider(&rec)),
        &fast_opts(),
    )
    .await;
    assert_eq!(assessed[0].validity, Some(Validity::Valid));
    assert!(assessed[0].scope.is_some(), "{:?}", assessed[0].scope_error);
    assert_eq!(signed_actions(&rec, &id).await, ["GetCallerIdentity"]);
    assert!(!signed_actions(&rec, &operator_id()).await.is_empty());
    assert_no_mutating_actions(&rec).await;
}

/// A credentials chain that finds nothing.
#[derive(Debug)]
struct NoCredentials;

impl ProvideCredentials for NoCredentials {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::ready(Err(CredentialsError::not_loaded(
            "nothing in /home/someone/.aws/credentials",
        )))
    }
}

// Decision 1: without operator credentials, scope says why and validity
// still comes from the leaked key's single STS call.
#[tokio::test]
async fn describe_scope_without_operator_credentials_explains() {
    let rec = recorder().await;
    let id = key_id("AKIA", "NOOPERA");
    mount_caller(&rec, &id, &user_arn("jo")).await;
    let p = AwsProvider::new()
        .with_region("us-east-1")
        .with_endpoint_url(rec.uri())
        .with_operator_credentials(NoCredentials);

    let assessed = assess::assess(
        vec![finding(&id, secret("noopera0"))],
        &registry(p),
        &fast_opts(),
    )
    .await;
    assert_eq!(assessed[0].validity, Some(Validity::Valid));
    assert!(assessed[0].scope.is_none());
    let err = assessed[0].scope_error.as_deref().unwrap();
    assert_eq!(err, NO_OPERATOR_CREDENTIALS);
    assert!(!err.contains("/home/someone"), "chain error echoed: {err}");
    assert_eq!(signed_actions(&rec, &id).await, ["GetCallerIdentity"]);
    assert_eq!(rec.calls().await.len(), 1, "no IAM call without operator");
}

// SHA-251 T5 (AC5): each denied list read becomes a line.
#[tokio::test]
async fn describe_scope_access_denied_is_a_line() {
    let rec = recorder().await;
    let id = key_id("AKIA", "T5DENYD");
    mount_iam(&rec, "bob").await;
    for action in [
        "ListAttachedUserPolicies",
        "ListUserPolicies",
        "ListGroupsForUser",
        "ListAccessKeys",
    ] {
        mount_error(&rec, action, &operator_id(), "AccessDenied").await;
    }
    let scope = provider(&rec)
        .describe_scope(&pair(&id, secret("t5denied")))
        .await
        .unwrap();
    assert!(scope.lines.contains(&"user: bob".to_owned()), "{scope:?}");
    assert!(scope.lines.contains(
        &"attached policies: not visible to the operator credentials (AccessDenied)".to_owned()
    ));
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

// SHA-251 T6 (AC6)
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

// T1 (AC1, AC8)
#[tokio::test]
async fn create_replacement_one_key_creates_once() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T1LEAKD");
    let new_id = key_id("AKIA", "T1NEWKY");
    let leaked_value = secret("t1leaked");
    let new_value = secret("t1newsec");
    mount_iam(&rec, "erin").await;
    mount_keys(&rec, "erin", &[(&leaked, "Active")]).await;
    mount_create(&rec, "erin", &new_id, &new_value).await;

    let replacement = provider(&rec)
        .create_replacement(&pair(&leaked, leaked_value.clone()))
        .await
        .unwrap();
    assert_eq!(replacement.replacement_ref, new_id);
    assert_eq!(replacement.credential.key_id(), Some(new_id.as_str()));
    assert_ne!(
        replacement.credential.fingerprint(),
        leaked_value.fingerprint()
    );
    assert_eq!(
        replacement.credential.fingerprint(),
        new_value.fingerprint()
    );
    let creates = calls_of(&rec, "CreateAccessKey").await;
    assert_eq!(creates.len(), 1);
    assert_eq!(field(&creates[0], "UserName"), Some("erin"));
    assert_eq!(signed_actions(&rec, &leaked).await, Vec::<String>::new());
    assert_no_delete(&rec).await;
}

// T2 (AC2, AC8)
#[tokio::test]
async fn create_replacement_two_keys_refuses() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T2LEAKD");
    let other = key_id("AKIA", "T2OTHER");
    mount_iam(&rec, "finn").await;
    mount_never_used(&rec, "finn", &other).await;
    mount_keys(&rec, "finn", &[(&leaked, "Active"), (&other, "Inactive")]).await;
    mount_create(
        &rec,
        "finn",
        &key_id("AKIA", "T2NEVER"),
        &secret("t2never0"),
    )
    .await;

    let err = provider(&rec)
        .create_replacement(&pair(&leaked, secret("t2leaked")))
        .await
        .unwrap_err();
    assert!(matches!(err, ProviderError::Permanent(_)));
    let text = err.to_string();
    for want in [
        format!("{leaked} Active, last used s3 in eu-west-1 at {LAST_USED}"),
        format!("{other} Inactive, last used never"),
        "finn".to_owned(),
    ] {
        assert!(text.contains(&want), "{want:?} missing: {text}");
    }
    assert!(calls_of(&rec, "CreateAccessKey").await.is_empty());
    rec.assert_no_mutations().await;
    assert_no_delete(&rec).await;
}

// T2 (AC2): the plan shows the refusal before apply runs.
#[tokio::test]
async fn two_keys_warning_in_scope_and_plan_table() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T2PLANK");
    let other = key_id("AKIA", "T2PLAN2");
    mount_caller(&rec, &leaked, &user_arn("gwen")).await;
    mount_iam(&rec, "gwen").await;
    mount_keys(&rec, "gwen", &[(&leaked, "Active"), (&other, "Active")]).await;
    let providers = registry(provider(&rec));

    let assessed = assess::assess(
        vec![finding(&leaked, secret("t2planks"))],
        &providers,
        &fast_opts(),
    )
    .await;
    let scope = assessed[0].scope.clone().unwrap();
    assert!(scope.lines.contains(&"access keys: 2 of 2 used".to_owned()));
    let built = plan::build(
        assessed,
        &providers,
        &ConsumerRegistry::new(),
        Overlap::default(),
        &ConsumersConfig::default(),
    )
    .await;
    let table = plan::render_table(&built);
    let warning = table
        .lines()
        .find(|l| l.contains("warning:"))
        .unwrap_or_else(|| panic!("no warning line: {table}"));
    assert!(
        warning.contains(&leaked) && warning.contains(&other),
        "{warning}"
    );
    assert!(
        warning.contains("will not create a replacement"),
        "{warning}"
    );
    assert!(plan::render_json(&built).contains("warning: "));
    assert_no_mutating_actions(&rec).await;
}

// T3 (AC3)
#[tokio::test]
async fn verify_retries_until_new_key_propagates() {
    let rec = recorder().await;
    let new_id = key_id("AKIA", "T3NEWKY");
    Mock::given(body_string_contains("Action=GetCallerIdentity"))
        .and(SignedBy(new_id.clone()))
        .respond_with(xml(403, error_xml("InvalidClientTokenId")))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(rec.server())
        .await;
    mount_caller(&rec, &new_id, &user_arn("hank")).await;

    provider(&rec)
        .verify(
            &pair(&new_id, secret("t3newsec")),
            &Identity(user_arn("hank")),
        )
        .await
        .unwrap();
    assert_eq!(
        signed_actions(&rec, &new_id).await,
        ["GetCallerIdentity"; 3]
    );
    assert_no_mutating_actions(&rec).await;
}

// T3 (AC3): a key that never propagates fails after the budget.
#[tokio::test]
async fn verify_gives_up_after_the_budget() {
    let rec = recorder().await;
    let new_id = key_id("AKIA", "T3NEVER");
    mount_error(&rec, "GetCallerIdentity", &new_id, "InvalidClientTokenId").await;
    let p = provider(&rec).with_verify_timing(Duration::from_millis(10), Duration::from_millis(60));
    let err = p
        .verify(
            &pair(&new_id, secret("t3neverp")),
            &Identity(user_arn("hank")),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not accepted within"), "{err}");
    let attempts = signed_actions(&rec, &new_id).await.len();
    assert!((2..=7).contains(&attempts), "{attempts} attempts");
}

// T4 (AC4)
#[tokio::test]
async fn verify_wrong_arn_names_both() {
    let rec = recorder().await;
    let new_id = key_id("AKIA", "T4NEWKY");
    mount_caller(&rec, &new_id, &user_arn("mallory")).await;
    let err = provider(&rec)
        .verify(
            &pair(&new_id, secret("t4newsec")),
            &Identity(user_arn("iris")),
        )
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains(&user_arn("mallory")), "{text}");
    assert!(text.contains(&user_arn("iris")), "{text}");
    assert_eq!(signed_actions(&rec, &new_id).await.len(), 1, "no retry");
}

/// A plan for one leaked key with one consumer holding it, ids assigned.
struct Pipeline {
    dir: tempfile::TempDir,
    providers: ProviderRegistry,
    consumers: ConsumerRegistry,
    sm: Arc<MockConsumer>,
    store: StateStore,
    audit: AuditLog,
    plan: plan::Plan,
}

async fn pipeline(rec: &CallRecorder, leaked: &str, value: &SecretValue) -> Pipeline {
    let dir = tempfile::tempdir().unwrap();
    let providers = registry(provider(rec));
    let sm = Arc::new(
        MockConsumer::new("aws-secrets-manager")
            .matching(value.fingerprint(), ConsumerMatch::by_value("sm:prod/aws")),
    );
    let mut consumers = ConsumerRegistry::new();
    consumers.register(sm.clone());
    let assessed = assess::assess(
        vec![finding(leaked, value.clone())],
        &providers,
        &fast_opts(),
    )
    .await;
    let mut built = plan::build(
        assessed,
        &providers,
        &consumers,
        "0s".parse().unwrap(),
        &ConsumersConfig::default(),
    )
    .await;
    let mut store = StateStore::open(dir.path().join("state.json")).unwrap();
    plan::assign_ids(&mut built, &mut store).unwrap();
    let audit = AuditLog::open_as(dir.path().join("audit.jsonl"), "tester@host").unwrap();
    assert_eq!(built.rotations.len(), 1, "{}", plan::render_table(&built));
    Pipeline {
        dir,
        providers,
        consumers,
        sm,
        store,
        audit,
        plan: built,
    }
}

// T4 (AC4, AC8): through the executor, a wrong ARN stops before revoke.
#[tokio::test]
async fn executor_wrong_arn_never_revokes() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T4EXECK");
    let new_id = key_id("AKIA", "T4EXNEW");
    let value = secret("t4execlk");
    mount_rotation(
        &rec,
        "judy",
        &leaked,
        &new_id,
        &secret("t4exnews"),
        &user_arn("mallory"),
    )
    .await;
    let mut p = pipeline(&rec, &leaked, &value).await;

    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .run(&p.plan.rotations[0])
        .await;
    match &outcome.result {
        RunResult::Failed { step, error } => {
            assert_eq!(format!("{step:?}"), "Verify");
            assert!(error.to_string().contains(&user_arn("mallory")), "{error}");
        }
        other => panic!("expected a verify failure, got {other:?}"),
    }
    assert!(updates(&rec).await.is_empty(), "UpdateAccessKey was called");
    assert_eq!(calls_of(&rec, "CreateAccessKey").await.len(), 1);
    assert_no_delete(&rec).await;
}

// T5 (AC5, AC8)
#[tokio::test]
async fn revoke_deactivates_only_the_leaked_key() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T5LEAKD");
    let other = key_id("AKIA", "T5OTHER");
    mount_iam(&rec, "kim").await;
    mount_keys(&rec, "kim", &[(&leaked, "Active"), (&other, "Active")]).await;
    mount_update(&rec).await;

    let revoked = provider(&rec)
        .revoke(&pair(&leaked, secret("t5leaked")))
        .await
        .unwrap();
    assert_eq!(revoked.restore_ref.as_deref(), Some(leaked.as_str()));
    let calls = calls_of(&rec, "UpdateAccessKey").await;
    assert_eq!(calls.len(), 1);
    assert_eq!(field(&calls[0], "AccessKeyId"), Some(leaked.as_str()));
    assert_eq!(field(&calls[0], "Status"), Some("Inactive"));
    assert_eq!(field(&calls[0], "UserName"), Some("kim"));
    assert_eq!(signed_actions(&rec, &leaked).await, Vec::<String>::new());
    assert_no_delete(&rec).await;
}

// T6 (AC6, AC8)
#[tokio::test]
async fn revoke_already_inactive_is_ok() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T6LEAKD");
    mount_iam(&rec, "lee").await;
    mount_keys(&rec, "lee", &[(&leaked, "Inactive")]).await;
    mount_update(&rec).await;
    let p = provider(&rec);
    let credential = pair(&leaked, secret("t6leaked"));

    for _ in 0..2 {
        let revoked = p.revoke(&credential).await.unwrap();
        assert_eq!(revoked.restore_ref.as_deref(), Some(leaked.as_str()));
    }
    assert!(updates(&rec).await.is_empty());
    assert_no_delete(&rec).await;
}

// T6 (AC6): a key deleted elsewhere is revoked already; nothing to restore.
#[tokio::test]
async fn revoke_missing_key_is_ok_without_restore_ref() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T6GONE0");
    mount_iam(&rec, "lee").await;
    mount_keys(&rec, "lee", &[]).await;
    let revoked = provider(&rec)
        .revoke(&pair(&leaked, secret("t6gonek0")))
        .await
        .unwrap();
    assert_eq!(revoked.restore_ref, None);
    assert!(updates(&rec).await.is_empty());
    assert_no_delete(&rec).await;
}

// T7 (AC7, AC8)
#[tokio::test]
async fn restore_activates_old_then_deactivates_new() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T7LEAKD");
    let new_id = key_id("AKIA", "T7NEWKY");
    mount_rotation(
        &rec,
        "max",
        &leaked,
        &new_id,
        &secret("t7newsec"),
        &user_arn("max"),
    )
    .await;
    let p = provider(&rec);
    let credential = pair(&leaked, secret("t7leaked"));

    p.create_replacement(&credential).await.unwrap();
    let revoked = p.revoke(&credential).await.unwrap();
    let restore_ref = revoked.restore_ref.unwrap();
    assert_eq!(
        restore_ref,
        rotate::provider::aws::restore_ref(&leaked, &new_id)
    );

    assert_eq!(
        p.restore(&restore_ref).await.unwrap(),
        RestoreOutcome::Restored
    );
    assert_eq!(
        updates(&rec).await,
        [
            (leaked.clone(), "Inactive".to_owned()),
            (leaked.clone(), "Active".to_owned()),
            (new_id.clone(), "Inactive".to_owned()),
        ]
    );
    assert_no_delete(&rec).await;
}

// T7 (AC7): a bare old key id (revoke ran in another process) only
// reactivates the old key.
#[tokio::test]
async fn restore_bare_ref_reactivates_old_only() {
    let rec = recorder().await;
    let leaked = key_id("AKIA", "T7BAREK");
    mount_iam(&rec, "max").await;
    mount_update(&rec).await;
    assert_eq!(
        provider(&rec).restore(&leaked).await.unwrap(),
        RestoreOutcome::Restored
    );
    assert_eq!(updates(&rec).await, [(leaked, "Active".to_owned())]);
    assert_no_delete(&rec).await;
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

/// Panics when any request body or header holds one of `values`.
async fn assert_not_in_requests(rec: &CallRecorder, values: &[String]) {
    let requests = rec.server().received_requests().await.unwrap();
    assert!(!requests.is_empty());
    for v in values {
        for req in &requests {
            assert!(
                !String::from_utf8_lossy(&req.body).contains(v),
                "secret in a request body"
            );
            for (name, header) in &req.headers {
                let header = header.to_str().unwrap_or("");
                assert!(!header.contains(v), "secret in header {name}");
            }
        }
    }
}

// SHA-251 T8 (AC2, AC5)
#[tokio::test]
async fn secret_never_in_logs_output_or_requests() {
    let capture = trace_capture();

    let rec = recorder().await;
    let id = key_id("AKIA", "T8LEAKS");
    let value = secret("t8leakca");
    mount_caller(&rec, &id, &user_arn("carol")).await;
    mount_iam(&rec, "carol").await;
    mount_keys(&rec, "carol", &[(&id, "Active")]).await;
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
    let values = [plain(&value), plain(&unknown_value)];
    for v in &values {
        for (label, text) in [
            ("table", &table),
            ("json", &json),
            ("debug", &debug),
            ("logs", &logs),
        ] {
            assert!(!text.contains(v), "secret in {label}");
        }
    }
    assert_not_in_requests(&rec, &values).await;
    assert_no_mutating_actions(&rec).await;
}

// T9 (AC1, AC3): a full apply run, the leaked and the new secret access key
// appear in no output, log, audit entry, state file or request.
#[tokio::test]
async fn secret_values_never_in_output_logs_audit_or_state() {
    let capture = trace_capture();

    let rec = recorder().await;
    let leaked = key_id("AKIA", "T9LEAKD");
    let new_id = key_id("AKIA", "T9NEWKY");
    let leaked_value = secret("t9leakcn");
    let new_value = secret("t9newcan");
    mount_rotation(
        &rec,
        "nora",
        &leaked,
        &new_id,
        &new_value,
        &user_arn("nora"),
    )
    .await;
    // The new key needs two attempts before IAM has propagated it.
    Mock::given(body_string_contains("Action=GetCallerIdentity"))
        .and(SignedBy(new_id.clone()))
        .respond_with(xml(403, error_xml("InvalidClientTokenId")))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(rec.server())
        .await;
    let mut p = pipeline(&rec, &leaked, &leaked_value).await;
    let table = plan::render_table(&p.plan);
    let plan_json = plan::render_json(&p.plan);

    let outcome = Executor::new(&p.providers, &p.consumers, &mut p.store, &mut p.audit)
        .run(&p.plan.rotations[0])
        .await;
    assert!(
        matches!(outcome.result, RunResult::Revoked),
        "{:?}",
        outcome.result
    );
    assert_eq!(
        p.sm.current("sm:prod/aws"),
        Some(new_value.fingerprint()),
        "consumer holds the new key"
    );
    assert_eq!(
        updates(&rec).await,
        [(leaked.clone(), "Inactive".to_owned())]
    );
    let summary = apply::render_summary(std::slice::from_ref(&outcome));
    let audit = std::fs::read_to_string(p.dir.path().join("audit.jsonl")).unwrap();
    let state = std::fs::read_to_string(p.dir.path().join("state.json")).unwrap();
    assert!(audit.contains(&new_value.fingerprint().to_string()));
    assert!(state.contains(&new_id), "state records the replacement ref");
    let logs = capture.contents();
    assert!(logs.contains("CreateAccessKey"), "TRACE capture missed IAM");

    let values = [plain(&leaked_value), plain(&new_value)];
    for v in &values {
        for (label, text) in [
            ("plan table", &table),
            ("plan json", &plan_json),
            ("summary", &summary),
            ("audit log", &audit),
            ("state file", &state),
            ("logs", &logs),
            ("outcome", &format!("{outcome:?}")),
        ] {
            assert!(!text.contains(v.as_str()), "secret in {label}");
        }
    }
    assert_not_in_requests(&rec, &values).await;
    assert_no_delete(&rec).await;
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

// T10 (AC1 to AC8): the full provider suite, read and write side.
#[tokio::test]
async fn conformance_full() {
    let report = provider_suite(|| async {
        let rec = recorder().await;
        let live_id = key_id("AKIA", "T10LIVE");
        let new_id = key_id("AKIA", "T10NEWK");
        let unknown_id = key_id("AKIA", "T10UNKN");
        mount_rotation(
            &rec,
            "dave",
            &live_id,
            &new_id,
            &secret("t10newse"),
            &user_arn("dave"),
        )
        .await;
        mount_error(
            &rec,
            "GetCallerIdentity",
            &unknown_id,
            "InvalidClientTokenId",
        )
        .await;
        ProviderFixture {
            provider: Arc::new(provider(&rec)),
            live: pair(&live_id, secret("t10live0")),
            identity: Identity(user_arn("dave")),
            unknown: pair(&unknown_id, secret("t10unkno")),
            probe: Box::new(RecorderProbe(rec)),
        }
    })
    .await;
    assert_eq!(report.plugin, "aws");
    report.assert_ok();
    assert!(report.skipped().is_empty(), "{report}");
    for name in [
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
    ] {
        assert_eq!(
            report.outcome(name),
            Some(&Outcome::Passed),
            "{name}: {report}"
        );
    }
}

fn live_env(name: &str) -> Option<String> {
    let value = common::require_env(name);
    if value.is_none() {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "skipped: {name} not set");
    }
    value
}

// Live: a real key pair from the environment. Read-only calls; scope with
// the operator's default credential chain.
#[tokio::test]
#[ignore]
async fn live_aws_check_valid_and_scope() {
    common::live_guard!();
    let (Some(id), Some(value)) = (
        live_env("ROTATE_LIVE_AWS_ACCESS_KEY_ID"),
        live_env("ROTATE_LIVE_AWS_SECRET_ACCESS_KEY"),
    ) else {
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

// Live: rotates a throwaway key of a test user end to end with the
// operator's default chain, then restores it and deactivates the key it
// created. Needs a dedicated IAM user holding exactly one key.
#[tokio::test]
#[ignore]
async fn live_aws_rotate_round_trip() {
    common::live_guard!();
    let (Some(id), Some(value)) = (
        live_env("ROTATE_LIVE_AWS_ACCESS_KEY_ID"),
        live_env("ROTATE_LIVE_AWS_SECRET_ACCESS_KEY"),
    ) else {
        return;
    };
    let credential = pair(&id, SecretValue::from(value));
    let p = AwsProvider::new();
    let scope = p.describe_scope(&credential).await.unwrap();
    let replacement = p.create_replacement(&credential).await.unwrap();
    p.verify(&replacement.credential, &scope.identity)
        .await
        .unwrap();
    let revoked = p.revoke(&credential).await.unwrap();
    let restore_ref = revoked.restore_ref.unwrap();
    assert_eq!(
        p.restore(&restore_ref).await.unwrap(),
        RestoreOutcome::Restored
    );
    assert_eq!(p.check_valid(&credential).await.unwrap(), Validity::Valid);
}
