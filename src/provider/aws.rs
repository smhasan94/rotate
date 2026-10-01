//! AWS IAM access keys (SHA-251 read side; SHA-255 adds the write side).
//!
//! Read side: [`AwsProvider::check_valid`] and [`AwsProvider::describe_scope`]
//! sign with the leaked key pair itself. Both are read-only calls in which
//! the key answers questions about itself (`sts:GetCallerIdentity`, then the
//! IAM reads on its own user), so `rotate plan` needs no operator AWS setup
//! and never loads the default credential chain. See
//! `docs/plans/SHA-251.md` for why.
//!
//! Nothing happens at construction: the region is resolved and a client is
//! built on the first call that needs one, never at startup.
//!
//! Error text and scope lines are built by rotate from the operation name,
//! a sanitised error code and the HTTP status. The service's own message is
//! dropped, so an endpoint that echoes its input cannot put a value into
//! plan output.

use std::time::Duration;

use async_trait::async_trait;
use aws_config::environment::EnvironmentVariableRegionProvider;
use aws_config::meta::region::RegionProviderChain;
use aws_config::profile::ProfileFileRegionProvider;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_sts::config::http::HttpResponse;
use aws_sdk_sts::config::retry::RetryConfig;
use aws_sdk_sts::config::timeout::TimeoutConfig;
use aws_sdk_sts::config::Credentials;
use aws_sdk_sts::error::{ProvideErrorMetadata, SdkError};
use tokio::sync::OnceCell;

use super::{
    Confidence, Credential, Identity, Provider, ProviderError, Replacement, ReplacementMode,
    RestoreOutcome, Revoked, Scope, Validity,
};
use crate::finding::Finding;
use crate::secret::SecretPair;

/// Name used in plans, config and the audit log.
pub const NAME: &str = "aws";

/// `Unknown` reason for an `ASIA` key.
pub const TEMPORARY_CREDENTIAL: &str = "temporary credential: revoke by rotating the source";

/// Region used when neither config, environment nor profile names one. IAM
/// is global; the region only picks the STS endpoint.
const FALLBACK_REGION: &str = "us-east-1";

/// Detector names and gitleaks rule ids that name AWS.
const HINTS: &[&str] = &["AWS", "aws-access-token"];

/// STS and IAM error codes that mean the key itself is not accepted.
const INVALID_CODES: &[&str] = &["InvalidClientTokenId", "SignatureDoesNotMatch"];

/// Error codes AWS uses for throttling.
const THROTTLE_CODES: &[&str] = &[
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
];

/// Most pages read from one IAM list call.
const MAX_PAGES: usize = 20;

/// Credential source name the SDK shows in its own `Debug` output.
const CREDENTIAL_SOURCE: &str = "rotate-leaked-key";

/// The AWS IAM access key provider.
#[derive(Debug, Default)]
pub struct AwsProvider {
    region: Option<String>,
    endpoint_url: Option<String>,
    resolved_region: OnceCell<Region>,
}

impl AwsProvider {
    /// A provider that resolves its region on first use. Makes no call and
    /// reads nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses `region` (`providers.aws.region`) instead of the environment.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Sends STS and IAM calls to `url` instead of AWS. For tests against a
    /// local server.
    pub fn with_endpoint_url(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    async fn region(&self) -> Region {
        self.resolved_region
            .get_or_init(|| async {
                if let Some(region) = &self.region {
                    return Region::new(region.clone());
                }
                RegionProviderChain::first_try(EnvironmentVariableRegionProvider::new())
                    .or_else(ProfileFileRegionProvider::new())
                    .or_else(Region::from_static(FALLBACK_REGION))
                    .region()
                    .await
                    .unwrap_or_else(|| Region::from_static(FALLBACK_REGION))
            })
            .await
            .clone()
    }

    async fn sts(&self, pair: &SecretPair) -> Result<aws_sdk_sts::Client, ProviderError> {
        let mut config = aws_sdk_sts::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(self.region().await)
            .retry_config(RetryConfig::disabled())
            .timeout_config(timeouts())
            .credentials_provider(static_credentials(pair)?);
        if let Some(url) = &self.endpoint_url {
            config = config.endpoint_url(url.clone());
        }
        Ok(aws_sdk_sts::Client::from_conf(config.build()))
    }

    async fn iam(&self, pair: &SecretPair) -> Result<aws_sdk_iam::Client, ProviderError> {
        let mut config = aws_sdk_iam::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(self.region().await)
            .retry_config(aws_sdk_iam::config::retry::RetryConfig::disabled())
            .timeout_config(timeouts())
            .credentials_provider(static_credentials(pair)?);
        if let Some(url) = &self.endpoint_url {
            config = config.endpoint_url(url.clone());
        }
        Ok(aws_sdk_iam::Client::from_conf(config.build()))
    }

    /// `sts:GetCallerIdentity` signed with `pair`: the ARN and account.
    async fn caller(&self, pair: &SecretPair) -> Result<Caller, Failure> {
        let out = self
            .sts(pair)
            .await
            .map_err(Failure::Provider)?
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| classify("sts:GetCallerIdentity", &e))?;
        let arn = out.arn().map(clean).unwrap_or_default();
        if arn.is_empty() {
            return Err(Failure::Provider(ProviderError::Permanent(
                "sts:GetCallerIdentity returned no ARN".into(),
            )));
        }
        Ok(Caller {
            account: out.account().map(clean),
            arn,
        })
    }

    async fn user_lines(
        &self,
        pair: &SecretPair,
        user: &str,
        lines: &mut Vec<String>,
    ) -> Result<(), ProviderError> {
        let iam = self.iam(pair).await?;

        let last_used = iam
            .get_access_key_last_used()
            .access_key_id(pair.key_id.clone())
            .send()
            .await
            .map_err(|e| classify("iam:GetAccessKeyLastUsed", &e));
        match last_used {
            Ok(out) => lines.push(match out.access_key_last_used() {
                Some(used) if used.last_used_date().is_some() => {
                    let date = used
                        .last_used_date()
                        .and_then(|d| {
                            d.fmt(aws_sdk_iam::primitives::DateTimeFormat::DateTime)
                                .ok()
                        })
                        .unwrap_or_default();
                    format!(
                        "last used: {} in {} at {}",
                        clean(used.service_name()),
                        clean(used.region()),
                        date
                    )
                }
                _ => "last used: never".to_owned(),
            }),
            Err(f) => lines.push(f.into_line("last used")?),
        }

        let mut marker = None;
        for _ in 0..MAX_PAGES {
            let out = iam
                .list_attached_user_policies()
                .user_name(user)
                .set_marker(marker.take())
                .send()
                .await
                .map_err(|e| classify("iam:ListAttachedUserPolicies", &e));
            match out {
                Ok(out) => {
                    for policy in out.attached_policies() {
                        if let Some(name) = policy.policy_name() {
                            lines.push(format!("attached policy: {}", clean(name)));
                        }
                    }
                    marker = next_marker(out.is_truncated(), out.marker());
                }
                Err(f) => lines.push(f.into_line("attached policies")?),
            }
            if marker.is_none() {
                break;
            }
        }

        let mut marker = None;
        for _ in 0..MAX_PAGES {
            let out = iam
                .list_user_policies()
                .user_name(user)
                .set_marker(marker.take())
                .send()
                .await
                .map_err(|e| classify("iam:ListUserPolicies", &e));
            match out {
                Ok(out) => {
                    for name in out.policy_names() {
                        lines.push(format!("inline policy: {}", clean(name)));
                    }
                    marker = next_marker(out.is_truncated(), out.marker());
                }
                Err(f) => lines.push(f.into_line("inline policies")?),
            }
            if marker.is_none() {
                break;
            }
        }

        let mut marker = None;
        for _ in 0..MAX_PAGES {
            let out = iam
                .list_groups_for_user()
                .user_name(user)
                .set_marker(marker.take())
                .send()
                .await
                .map_err(|e| classify("iam:ListGroupsForUser", &e));
            match out {
                Ok(out) => {
                    for group in out.groups() {
                        lines.push(format!("group: {}", clean(group.group_name())));
                    }
                    marker = next_marker(out.is_truncated(), out.marker());
                }
                Err(f) => lines.push(f.into_line("groups")?),
            }
            if marker.is_none() {
                break;
            }
        }
        Ok(())
    }
}

/// What `GetCallerIdentity` told us.
struct Caller {
    arn: String,
    account: Option<String>,
}

/// A classified SDK failure.
enum Failure {
    /// The service rejected the key: `InvalidClientTokenId` or
    /// `SignatureDoesNotMatch`.
    InvalidKey,
    /// The key works but may not make this call.
    AccessDenied(String),
    /// Anything else.
    Provider(ProviderError),
}

impl Failure {
    fn into_error(self, op: &str) -> ProviderError {
        match self {
            Failure::InvalidKey => {
                ProviderError::Permanent(format!("{op}: the access key was not accepted"))
            }
            Failure::AccessDenied(code) => ProviderError::Permanent(format!("{op}: {code}")),
            Failure::Provider(e) => e,
        }
    }

    /// A scope line for a denied IAM read; other failures stay errors so
    /// assessment can retry or report them.
    fn into_line(self, what: &str) -> Result<String, ProviderError> {
        match self {
            Failure::AccessDenied(code) => {
                Ok(format!("{what}: not visible to the leaked key ({code})"))
            }
            other => Err(other.into_error(what)),
        }
    }
}

fn timeouts() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(30))
        .build()
}

/// The one place the secret leaves its `SecretValue`: the SDK copies it into
/// a `Zeroizing<String>`, redacts it in `Debug` and only derives the SigV4
/// signing key from it.
fn static_credentials(pair: &SecretPair) -> Result<Credentials, ProviderError> {
    pair.secret
        .expose_secret_str(|secret| {
            Credentials::new(pair.key_id.clone(), secret, None, None, CREDENTIAL_SOURCE)
        })
        .map_err(|_| {
            ProviderError::Permanent("the AWS secret access key is not valid UTF-8".into())
        })
}

fn classify<E: ProvideErrorMetadata>(op: &str, err: &SdkError<E, HttpResponse>) -> Failure {
    let status = err.raw_response().map(|r| r.status().as_u16());
    let code = err.code().map(clean_code);
    let at = match (&code, status) {
        (Some(code), Some(status)) => format!("{op}: {code} (HTTP {status})"),
        (Some(code), None) => format!("{op}: {code}"),
        (None, Some(status)) => format!("{op}: HTTP {status}"),
        (None, None) => op.to_owned(),
    };
    if let Some(code) = code.as_deref() {
        if INVALID_CODES.contains(&code) {
            return Failure::InvalidKey;
        }
        if THROTTLE_CODES.contains(&code) {
            return Failure::Provider(ProviderError::RateLimited { retry_after: None });
        }
        if code == "AccessDenied" || code == "AccessDeniedException" {
            return Failure::AccessDenied(code.to_owned());
        }
    }
    match err {
        SdkError::TimeoutError(_) => {
            Failure::Provider(ProviderError::Transient(format!("{op}: timed out")))
        }
        SdkError::DispatchFailure(f) if f.is_timeout() => {
            Failure::Provider(ProviderError::Transient(format!("{op}: timed out")))
        }
        SdkError::DispatchFailure(_) => Failure::Provider(ProviderError::Transient(format!(
            "{op}: could not reach the endpoint"
        ))),
        SdkError::ConstructionFailure(_) => Failure::Provider(ProviderError::Permanent(format!(
            "{op}: could not build the request"
        ))),
        _ => match status {
            Some(429) => Failure::Provider(ProviderError::RateLimited { retry_after: None }),
            Some(s) if s >= 500 => Failure::Provider(ProviderError::Transient(at)),
            _ => Failure::Provider(ProviderError::Permanent(at)),
        },
    }
}

fn next_marker(truncated: bool, marker: Option<&str>) -> Option<String> {
    marker.filter(|_| truncated).map(str::to_owned)
}

/// An error code reduced to `[A-Za-z0-9.]`, at most 64 chars.
fn clean_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .take(64)
        .collect()
}

/// Service-supplied text (ARNs, names) reduced to printable ASCII, at most
/// 256 chars.
fn clean(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(256)
        .collect()
}

/// `AKIA` or `ASIA` followed by 16 uppercase letters or digits.
fn is_key_id(id: &str) -> bool {
    id.len() == 20
        && (id.starts_with("AKIA") || id.starts_with("ASIA"))
        && id[4..]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// A temporary (STS) key id.
fn is_temporary(id: &str) -> bool {
    id.starts_with("ASIA")
}

/// An example key from the AWS documentation, such as the one ending in
/// `EXAMPLE`. Never valid, so never sent anywhere.
fn is_documentation_example(id: &str) -> bool {
    id.ends_with("EXAMPLE")
}

fn is_secret_shape(bytes: &[u8]) -> bool {
    bytes.len() == 40
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'/' || *b == b'+')
}

/// The key pair, or `Unsupported` for a bare token.
fn key_pair(credential: &Credential) -> Result<&SecretPair, ProviderError> {
    match credential {
        Credential::KeyPair(pair) => Ok(pair),
        Credential::Token(_) => Err(ProviderError::Unsupported(
            "an AWS secret access key needs its access key id; pass KEY_ID:SECRET on stdin \
             or use a TruffleHog report"
                .into(),
        )),
    }
}

/// The user name from an IAM user ARN (`arn:aws:iam::<acct>:user/<path>/<name>`).
fn user_name(arn: &str) -> Option<&str> {
    let resource = arn.splitn(6, ':').nth(5)?;
    let rest = resource.strip_prefix("user/")?;
    rest.rsplit('/').next().filter(|n| !n.is_empty())
}

fn write_side(method: &str) -> ProviderError {
    ProviderError::Unsupported(format!("aws {method} is not implemented yet (SHA-255)"))
}

#[async_trait]
impl Provider for AwsProvider {
    fn name(&self) -> &'static str {
        NAME
    }

    fn replacement_mode(&self) -> ReplacementMode {
        ReplacementMode::Automatic
    }

    fn identify(&self, finding: &Finding) -> Option<Confidence> {
        match finding.credential() {
            Credential::KeyPair(pair) => {
                if !is_key_id(&pair.key_id) || !pair.secret.expose_secret(is_secret_shape) {
                    return None;
                }
                let hinted = HINTS
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(&finding.detector));
                Some(if hinted {
                    Confidence::High
                } else {
                    Confidence::Medium
                })
            }
            Credential::Token(raw) => raw
                .expose_secret_str(is_key_id)
                .unwrap_or(false)
                .then_some(Confidence::Low),
        }
    }

    async fn check_valid(&self, credential: &Credential) -> Result<Validity, ProviderError> {
        let pair = key_pair(credential)?;
        if is_temporary(&pair.key_id) {
            return Ok(Validity::Unknown {
                reason: TEMPORARY_CREDENTIAL.into(),
            });
        }
        if is_documentation_example(&pair.key_id) {
            return Ok(Validity::Invalid);
        }
        match self.caller(pair).await {
            Ok(_) => Ok(Validity::Valid),
            Err(Failure::InvalidKey) => Ok(Validity::Invalid),
            Err(f) => Err(f.into_error("sts:GetCallerIdentity")),
        }
    }

    async fn describe_scope(&self, credential: &Credential) -> Result<Scope, ProviderError> {
        let pair = key_pair(credential)?;
        if is_temporary(&pair.key_id) {
            return Err(ProviderError::Unsupported(TEMPORARY_CREDENTIAL.into()));
        }
        let caller = self
            .caller(pair)
            .await
            .map_err(|f| f.into_error("sts:GetCallerIdentity"))?;
        let mut lines = Vec::new();
        if let Some(account) = &caller.account {
            lines.push(format!("account: {account}"));
        }
        match user_name(&caller.arn) {
            Some(user) => {
                lines.push(format!("user: {user}"));
                self.user_lines(pair, user, &mut lines).await?;
            }
            None if caller.arn.ends_with(":root") => lines.push("principal: root user".into()),
            None => lines.push("principal: not an IAM user".into()),
        }
        Ok(Scope {
            identity: Identity(caller.arn),
            lines,
        })
    }

    async fn create_replacement(
        &self,
        _credential: &Credential,
    ) -> Result<Replacement, ProviderError> {
        Err(write_side("create_replacement"))
    }

    async fn verify(
        &self,
        _credential: &Credential,
        _identity: &Identity,
    ) -> Result<(), ProviderError> {
        Err(write_side("verify"))
    }

    async fn revoke(&self, _credential: &Credential) -> Result<Revoked, ProviderError> {
        Err(write_side("revoke"))
    }

    async fn restore(&self, _restore_ref: &str) -> Result<RestoreOutcome, ProviderError> {
        Err(write_side("restore"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{SourceLocation, ACCESS_KEY_ID};
    use crate::secret::SecretValue;

    /// A key id built at runtime from the AWS documentation example, so no
    /// literal here matches a secret-scanning pattern.
    fn key_id(prefix: &str, tail: &str) -> String {
        let doc = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        format!("{prefix}{}{tail}", &doc[4..13])
    }

    fn secret() -> SecretValue {
        SecretValue::from(["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYunitT1KEY0"].concat())
    }

    fn pair_finding(id: &str, detector: &str) -> Finding {
        Finding::new(secret(), detector, SourceLocation::file("a.env"))
            .with_extra(ACCESS_KEY_ID, id)
    }

    // T1 (AC1)
    #[test]
    fn identify_aws_fixture_high_github_none() {
        let p = AwsProvider::new();
        let id = key_id("AKIA", "UNITKEY");
        assert_eq!(
            p.identify(&pair_finding(&id, "AWS")),
            Some(Confidence::High)
        );
        assert_eq!(
            p.identify(&pair_finding(&id, "aws-access-token")),
            Some(Confidence::High)
        );
        let github = Finding::new(
            SecretValue::from(format!("{}{}", ["gh", "p_"].concat(), "x".repeat(36))),
            "Github",
            SourceLocation::file("a.env"),
        );
        assert_eq!(p.identify(&github), None);
    }

    // T1 (AC1)
    #[test]
    fn identify_shapes() {
        let p = AwsProvider::new();
        let akia = key_id("AKIA", "UNITKEY");
        let asia = key_id("ASIA", "UNITKEY");
        assert_eq!(
            p.identify(&pair_finding(&akia, "stdin")),
            Some(Confidence::Medium)
        );
        assert_eq!(
            p.identify(&pair_finding(&asia, "AWS")),
            Some(Confidence::High)
        );
        // Wrong key id shape or wrong secret length.
        assert_eq!(p.identify(&pair_finding("AKIA123", "AWS")), None);
        let short = Finding::new(
            SecretValue::from("tooShort"),
            "AWS",
            SourceLocation::file("a.env"),
        )
        .with_extra(ACCESS_KEY_ID, akia.clone());
        assert_eq!(p.identify(&short), None);
        // A bare key id: low, check_valid then asks for the pair.
        let bare = Finding::new(
            SecretValue::from(akia.clone()),
            "stdin",
            SourceLocation::file("-"),
        );
        assert_eq!(p.identify(&bare), Some(Confidence::Low));
        let empty = Finding::new(SecretValue::from(""), "", SourceLocation::file("-"));
        assert_eq!(p.identify(&empty), None);
    }

    #[test]
    fn user_name_from_arn() {
        assert_eq!(
            user_name("arn:aws:iam::000000000000:user/alice"),
            Some("alice")
        );
        assert_eq!(
            user_name("arn:aws:iam::000000000000:user/ci/deploy/bot"),
            Some("bot")
        );
        assert_eq!(user_name("arn:aws:iam::000000000000:root"), None);
        assert_eq!(
            user_name("arn:aws:sts::000000000000:assumed-role/r/s"),
            None
        );
    }

    #[test]
    fn cleaning_limits_service_text() {
        assert_eq!(
            clean_code("Invalid<Client>TokenId\n"),
            "InvalidClientTokenId"
        );
        assert_eq!(clean_code(&"A".repeat(100)).len(), 64);
        assert_eq!(clean("s3\u{7}\n"), "s3");
    }

    #[tokio::test]
    async fn token_and_temporary_and_example_make_no_call() {
        // No endpoint: any network call would fail the assertions below.
        let p = AwsProvider::new().with_endpoint_url("http://127.0.0.1:9");
        let token = Credential::Token(secret());
        assert!(matches!(
            p.check_valid(&token).await,
            Err(ProviderError::Unsupported(_))
        ));
        let asia = Credential::KeyPair(SecretPair::new(key_id("ASIA", "UNITKEY"), secret()));
        assert_eq!(
            p.check_valid(&asia).await.unwrap(),
            Validity::Unknown {
                reason: TEMPORARY_CREDENTIAL.into()
            }
        );
        assert!(matches!(
            p.describe_scope(&asia).await,
            Err(ProviderError::Unsupported(_))
        ));
        let example = Credential::KeyPair(SecretPair::new(
            ["AKIA", "IOSFODNN7EXAMPLE"].concat(),
            secret(),
        ));
        assert_eq!(p.check_valid(&example).await.unwrap(), Validity::Invalid);
    }

    #[test]
    fn write_side_is_unsupported_until_sha_255() {
        let e = write_side("revoke");
        assert!(matches!(e, ProviderError::Unsupported(_)));
        assert!(e.to_string().contains("SHA-255"));
    }
}
