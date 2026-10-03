//! AWS IAM access keys (SHA-251 read side, SHA-255 write side).
//!
//! The leaked key signs exactly one call: the `sts:GetCallerIdentity` in
//! [`AwsProvider::check_valid`]. Everything else runs with the operator's
//! own AWS credentials (decision D3): [`AwsProvider::describe_scope`], the
//! key creation, deactivation and reactivation. The operator configuration
//! comes from `aws_config`'s default chain (environment, shared profile,
//! SSO, credential process) and is loaded once, on the first call that
//! needs it. [`AwsProvider::verify`] signs with the replacement key, which
//! rotate itself created.
//!
//! Nothing happens at construction: the region, the operator configuration
//! and every client are resolved on first use, never at startup.
//!
//! Revoke deactivates the key (`UpdateAccessKey Status=Inactive`) and never
//! deletes it, so [`AwsProvider::restore`] can reactivate it. IAM allows two
//! access keys per user; when both are in use rotate refuses to create a
//! replacement rather than delete anything on its own.
//!
//! Error text and scope lines are built by rotate from the operation name,
//! a sanitised error code, key ids, user names and ARNs. The service's own
//! message is dropped, so an endpoint that echoes its input cannot put a
//! value into plan output.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use aws_config::environment::EnvironmentVariableRegionProvider;
use aws_config::meta::region::RegionProviderChain;
use aws_config::profile::ProfileFileRegionProvider;
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_iam::types::StatusType;
use aws_sdk_sts::config::http::HttpResponse;
use aws_sdk_sts::config::retry::RetryConfig;
use aws_sdk_sts::config::timeout::TimeoutConfig;
use aws_sdk_sts::config::{Credentials, ProvideCredentials, SharedCredentialsProvider};
use aws_sdk_sts::error::{ProvideErrorMetadata, SdkError};
use tokio::sync::OnceCell;

use super::{
    Confidence, Credential, Identity, Provider, ProviderError, Replacement, ReplacementMode,
    RestoreOutcome, Revoked, Scope, Validity,
};
use crate::finding::Finding;
use crate::secret::{SecretPair, SecretValue};

/// Name used in plans, config and the audit log.
pub const NAME: &str = "aws";

/// `Unknown` reason for an `ASIA` key.
pub const TEMPORARY_CREDENTIAL: &str = "temporary credential: revoke by rotating the source";

/// Error when the operator's AWS credentials cannot be loaded.
pub const NO_OPERATOR_CREDENTIALS: &str =
    "no AWS operator credentials: rotate reads the key's owner and changes keys with your own \
     AWS credentials (environment, shared profile, SSO or credential process), never with the \
     leaked key; configure them and run again";

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

/// Access keys IAM allows per user.
const KEY_SLOTS: usize = 2;

/// Credential source name the SDK shows in its own `Debug` output.
const CREDENTIAL_SOURCE: &str = "rotate-key-under-rotation";

/// How long `verify` keeps trying a new key that IAM has not propagated yet.
const VERIFY_BUDGET: Duration = Duration::from_secs(15);

/// Pause between `verify` attempts.
const VERIFY_INTERVAL: Duration = Duration::from_secs(2);

/// Separates the old and the new key id in a `restore_ref`. Key ids are
/// uppercase letters and digits, so it cannot occur in one.
const REF_SEPARATOR: char = ':';

/// The AWS IAM access key provider.
#[derive(Debug)]
pub struct AwsProvider {
    region: Option<String>,
    endpoint_url: Option<String>,
    resolved_region: OnceCell<Region>,
    operator_credentials: Option<SharedCredentialsProvider>,
    operator: OnceCell<Result<SdkConfig, String>>,
    /// Old key id to the replacement this process created for it, so
    /// `revoke` can hand `restore` both ids.
    replacements: Mutex<HashMap<String, String>>,
    verify_interval: Duration,
    verify_budget: Duration,
}

impl Default for AwsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsProvider {
    /// A provider that resolves its region and operator credentials on
    /// first use. Makes no call and reads nothing.
    pub fn new() -> Self {
        Self {
            region: None,
            endpoint_url: None,
            resolved_region: OnceCell::new(),
            operator_credentials: None,
            operator: OnceCell::new(),
            replacements: Mutex::new(HashMap::new()),
            verify_interval: VERIFY_INTERVAL,
            verify_budget: VERIFY_BUDGET,
        }
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

    /// Uses `credentials` as the operator's credentials instead of the
    /// default chain. For tests and embedders; never the leaked key.
    pub fn with_operator_credentials(
        mut self,
        credentials: impl ProvideCredentials + 'static,
    ) -> Self {
        self.operator_credentials = Some(SharedCredentialsProvider::new(credentials));
        self
    }

    /// How often and for how long `verify` retries a replacement key that
    /// is not accepted yet. Defaults: every 2 s for up to 15 s.
    pub fn with_verify_timing(mut self, interval: Duration, budget: Duration) -> Self {
        self.verify_interval = interval;
        self.verify_budget = budget;
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

    /// STS signed with `pair`: the leaked key in `check_valid`, the
    /// replacement in `verify`.
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

    /// The operator's configuration, loaded on first use. SDK retries are
    /// off: a retried `CreateAccessKey` after a lost response could mint a
    /// second key.
    async fn load_operator(&self) -> Result<SdkConfig, String> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(self.region().await)
            .retry_config(RetryConfig::disabled())
            .timeout_config(timeouts());
        if let Some(url) = &self.endpoint_url {
            loader = loader.endpoint_url(url.clone());
        }
        if let Some(credentials) = &self.operator_credentials {
            loader = loader.credentials_provider(credentials.clone());
        }
        let config = loader.load().await;
        let Some(credentials) = config.credentials_provider() else {
            return Err(NO_OPERATOR_CREDENTIALS.to_owned());
        };
        // The chain's own error can name files and profiles; it is dropped.
        match credentials.provide_credentials().await {
            Ok(_) => Ok(config),
            Err(_) => Err(NO_OPERATOR_CREDENTIALS.to_owned()),
        }
    }

    /// IAM with the operator's credentials.
    async fn iam(&self) -> Result<aws_sdk_iam::Client, ProviderError> {
        match self.operator.get_or_init(|| self.load_operator()).await {
            Ok(config) => Ok(aws_sdk_iam::Client::new(config)),
            Err(message) => Err(ProviderError::Permanent(message.clone())),
        }
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
        Ok(Caller { arn })
    }

    /// The IAM user owning `key_id` and when the key was last used, read
    /// with the operator's credentials.
    async fn owner(&self, iam: &aws_sdk_iam::Client, key_id: &str) -> Result<Owner, ProviderError> {
        const OP: &str = "iam:GetAccessKeyLastUsed";
        let out = iam
            .get_access_key_last_used()
            .access_key_id(key_id)
            .send()
            .await
            .map_err(|e| classify(OP, &e).into_operator_error(OP))?;
        let user = out.user_name().map(clean).unwrap_or_default();
        if user.is_empty() {
            return Err(ProviderError::Unsupported(
                "the access key does not belong to an IAM user; rotate root user keys in the \
                 AWS console"
                    .into(),
            ));
        }
        Ok(Owner {
            user,
            last_used: last_used_text(out.access_key_last_used()),
        })
    }

    /// The user's access keys. With `last_used`, each key's last use too
    /// (an extra read per key, at most two).
    async fn key_slots(
        &self,
        iam: &aws_sdk_iam::Client,
        user: &str,
        last_used: bool,
    ) -> Result<Vec<Slot>, Failure> {
        let mut slots = Vec::new();
        let mut marker = None;
        for _ in 0..MAX_PAGES {
            let out = iam
                .list_access_keys()
                .user_name(user)
                .set_marker(marker.take())
                .send()
                .await
                .map_err(|e| classify("iam:ListAccessKeys", &e))?;
            for key in out.access_key_metadata() {
                let Some(id) = key.access_key_id().map(clean) else {
                    continue;
                };
                let status = key.status().map_or("unknown", StatusType::as_str);
                slots.push(Slot {
                    id,
                    status: clean(status),
                    last_used: String::new(),
                });
            }
            marker = next_marker(out.is_truncated(), out.marker());
            if marker.is_none() {
                break;
            }
        }
        if last_used {
            for slot in &mut slots {
                slot.last_used = match iam
                    .get_access_key_last_used()
                    .access_key_id(&slot.id)
                    .send()
                    .await
                {
                    Ok(out) => last_used_text(out.access_key_last_used()),
                    Err(_) => "unknown".to_owned(),
                };
            }
        }
        Ok(slots)
    }

    async fn policy_lines(
        &self,
        iam: &aws_sdk_iam::Client,
        user: &str,
        lines: &mut Vec<String>,
    ) -> Result<(), ProviderError> {
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

    async fn set_status(
        &self,
        iam: &aws_sdk_iam::Client,
        user: &str,
        key_id: &str,
        status: StatusType,
    ) -> Result<(), ProviderError> {
        const OP: &str = "iam:UpdateAccessKey";
        iam.update_access_key()
            .user_name(user)
            .access_key_id(key_id)
            .status(status)
            .send()
            .await
            .map(drop)
            .map_err(|e| classify(OP, &e).into_operator_error(OP))
    }

    /// `OLD:NEW` when this process created the replacement for `old`, else
    /// `OLD`.
    fn restore_ref_for(&self, old: &str) -> String {
        let replacements = self
            .replacements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match replacements.get(old) {
            Some(new) => restore_ref(old, new),
            None => old.to_owned(),
        }
    }
}

/// The `restore_ref` that makes [`AwsProvider::restore`] reactivate `old`
/// and then deactivate `new`. Rollback builds it from the state record's
/// `replacement_ref` when the revoke ran in another process.
pub fn restore_ref(old: &str, new: &str) -> String {
    format!("{old}{REF_SEPARATOR}{new}")
}

/// What `GetCallerIdentity` told us.
struct Caller {
    arn: String,
}

/// The owner of a key, from `GetAccessKeyLastUsed`.
struct Owner {
    user: String,
    last_used: String,
}

/// One of a user's access keys.
struct Slot {
    id: String,
    status: String,
    last_used: String,
}

/// The refusal when both key slots are taken: both ids, their status and
/// last use.
fn two_keys(user: &str, slots: &[Slot]) -> String {
    let keys: Vec<String> = slots
        .iter()
        .map(|s| format!("{} {}, last used {}", s.id, s.status, s.last_used))
        .collect();
    format!(
        "IAM user {user} already has {} access keys ({}); IAM allows {KEY_SLOTS}, so rotate \
         will not create a replacement. Delete the key that is not leaked, then run apply again",
        slots.len(),
        keys.join("; ")
    )
}

/// A classified SDK failure.
enum Failure {
    /// The service rejected the signing key: `InvalidClientTokenId` or
    /// `SignatureDoesNotMatch`.
    InvalidKey,
    /// The key works but may not make this call.
    AccessDenied(String),
    /// Anything else.
    Provider(ProviderError),
}

impl Failure {
    /// For a call signed with the key under test (leaked or replacement).
    fn into_error(self, op: &str) -> ProviderError {
        match self {
            Failure::InvalidKey => {
                ProviderError::Permanent(format!("{op}: the access key was not accepted"))
            }
            Failure::AccessDenied(code) => ProviderError::Permanent(format!("{op}: {code}")),
            Failure::Provider(e) => e,
        }
    }

    /// For a call signed with the operator's credentials.
    fn into_operator_error(self, op: &str) -> ProviderError {
        match self {
            Failure::InvalidKey => ProviderError::Permanent(format!(
                "{op}: the operator AWS credentials were not accepted"
            )),
            Failure::AccessDenied(code) => ProviderError::Permanent(format!(
                "{op}: {code}: the operator AWS credentials may not make this call"
            )),
            Failure::Provider(e) => e,
        }
    }

    /// A scope line for a denied IAM read; other failures stay errors so
    /// assessment can retry or report them.
    fn into_line(self, what: &str) -> Result<String, ProviderError> {
        match self {
            Failure::AccessDenied(code) => Ok(format!(
                "{what}: not visible to the operator credentials ({code})"
            )),
            other => Err(other.into_operator_error(what)),
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            Failure::InvalidKey => true,
            Failure::AccessDenied(_) => false,
            Failure::Provider(e) => e.is_retryable(),
        }
    }
}

fn timeouts() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(5))
        .operation_timeout(Duration::from_secs(30))
        .build()
}

/// The one place a secret leaves its `SecretValue`: the SDK copies it into
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

/// `<service> in <region> at <date>`, or `never`.
fn last_used_text(used: Option<&aws_sdk_iam::types::AccessKeyLastUsed>) -> String {
    match used {
        Some(used) if used.last_used_date().is_some() => {
            let date = used
                .last_used_date()
                .and_then(|d| {
                    d.fmt(aws_sdk_iam::primitives::DateTimeFormat::DateTime)
                        .ok()
                })
                .unwrap_or_default();
            format!(
                "{} in {} at {}",
                clean(used.service_name()),
                clean(used.region()),
                date
            )
        }
        _ => "never".to_owned(),
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

/// A long-term (`AKIA`) key pair, the only kind rotate rotates. Anything
/// else is `Unsupported` before any call.
fn long_term_pair(credential: &Credential) -> Result<&SecretPair, ProviderError> {
    let pair = key_pair(credential)?;
    if is_temporary(&pair.key_id) {
        return Err(ProviderError::Unsupported(TEMPORARY_CREDENTIAL.into()));
    }
    if !is_key_id(&pair.key_id) {
        return Err(ProviderError::Unsupported(
            "not an AWS access key id (AKIA followed by 16 letters or digits)".into(),
        ));
    }
    Ok(pair)
}

/// `OLD` or `OLD:NEW`, both long-term key ids.
fn parse_restore_ref(restore_ref: &str) -> Result<(&str, Option<&str>), ProviderError> {
    let (old, new) = match restore_ref.split_once(REF_SEPARATOR) {
        Some((old, new)) => (old, Some(new)),
        None => (restore_ref, None),
    };
    let ok = |id: &str| is_key_id(id) && !is_temporary(id);
    if ok(old) && new.is_none_or(ok) {
        Ok((old, new))
    } else {
        Err(ProviderError::Permanent(
            "not an AWS restore reference (OLD_KEY_ID or OLD_KEY_ID:NEW_KEY_ID)".into(),
        ))
    }
}

/// The account id from an ARN (`arn:aws:iam::<acct>:user/...`).
fn account(arn: &str) -> Option<&str> {
    arn.split(':').nth(4).filter(|a| !a.is_empty())
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

    /// The only call signed with the leaked key.
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

    /// Owner, policies, groups and key slots, read with the operator's
    /// credentials. Two keys in use adds a `warning: ` line: apply will
    /// refuse to create a replacement.
    async fn describe_scope(&self, credential: &Credential) -> Result<Scope, ProviderError> {
        let pair = long_term_pair(credential)?;
        let iam = self.iam().await?;
        let owner = self.owner(&iam, &pair.key_id).await?;

        const OP: &str = "iam:GetUser";
        let out = iam
            .get_user()
            .user_name(&owner.user)
            .send()
            .await
            .map_err(|e| classify(OP, &e).into_operator_error(OP))?;
        let arn = out.user().map(|u| clean(u.arn())).unwrap_or_default();
        if arn.is_empty() {
            return Err(ProviderError::Permanent(
                "iam:GetUser returned no ARN".into(),
            ));
        }

        let mut lines = Vec::new();
        if let Some(account) = account(&arn) {
            lines.push(format!("account: {account}"));
        }
        lines.push(format!("user: {}", owner.user));
        lines.push(format!("last used: {}", owner.last_used));
        self.policy_lines(&iam, &owner.user, &mut lines).await?;
        match self.key_slots(&iam, &owner.user, true).await {
            Ok(slots) => {
                lines.push(format!("access keys: {} of {KEY_SLOTS} used", slots.len()));
                if slots.len() >= KEY_SLOTS {
                    lines.push(format!("warning: {}", two_keys(&owner.user, &slots)));
                }
            }
            Err(f) => lines.push(f.into_line("access keys")?),
        }
        Ok(Scope {
            identity: Identity(arn),
            lines,
        })
    }

    /// `iam:CreateAccessKey` for the leaked key's user, after checking a
    /// slot is free.
    async fn create_replacement(
        &self,
        credential: &Credential,
    ) -> Result<Replacement, ProviderError> {
        let pair = long_term_pair(credential)?;
        let iam = self.iam().await?;
        let owner = self.owner(&iam, &pair.key_id).await?;
        let slots = self
            .key_slots(&iam, &owner.user, true)
            .await
            .map_err(|f| f.into_operator_error("iam:ListAccessKeys"))?;
        if slots.len() >= KEY_SLOTS {
            return Err(ProviderError::Permanent(two_keys(&owner.user, &slots)));
        }

        const OP: &str = "iam:CreateAccessKey";
        let out = iam
            .create_access_key()
            .user_name(&owner.user)
            .send()
            .await
            .map_err(|e| classify(OP, &e).into_operator_error(OP))?;
        let Some(key) = out.access_key else {
            return Err(ProviderError::Permanent(format!(
                "{OP} returned no key; check user {} for a new key",
                owner.user
            )));
        };
        let new_id = clean(&key.access_key_id);
        // Moved, not copied: the SDK's `String` becomes the zeroized buffer.
        let secret = SecretValue::from(key.secret_access_key);
        if !is_key_id(&new_id) || is_temporary(&new_id) || new_id == pair.key_id {
            return Err(ProviderError::Permanent(format!(
                "{OP} returned an unexpected key id; check user {} for a new key",
                owner.user
            )));
        }
        self.replacements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(pair.key_id.clone(), new_id.clone());
        Ok(Replacement {
            credential: Credential::KeyPair(SecretPair::new(new_id.clone(), secret)),
            replacement_ref: new_id,
        })
    }

    /// `sts:GetCallerIdentity` signed with the replacement; its ARN must be
    /// `identity`. A key IAM has not propagated yet is retried within the
    /// verify budget; a different ARN fails at once.
    async fn verify(
        &self,
        credential: &Credential,
        identity: &Identity,
    ) -> Result<(), ProviderError> {
        const OP: &str = "sts:GetCallerIdentity";
        let pair = long_term_pair(credential)?;
        let started = Instant::now();
        loop {
            let failure = match self.caller(pair).await {
                Ok(caller) if caller.arn == identity.0 => return Ok(()),
                Ok(caller) => {
                    return Err(ProviderError::Permanent(format!(
                    "the replacement key belongs to {} but the leaked key belongs to {identity}",
                    caller.arn
                )))
                }
                Err(f) => f,
            };
            let out_of_time = started.elapsed() + self.verify_interval > self.verify_budget;
            if !failure.is_retryable() || out_of_time {
                return Err(match failure {
                    Failure::InvalidKey => ProviderError::Permanent(format!(
                        "{OP}: the replacement key was not accepted within {} s",
                        self.verify_budget.as_secs()
                    )),
                    other => other.into_error(OP),
                });
            }
            tokio::time::sleep(self.verify_interval).await;
        }
    }

    /// `iam:UpdateAccessKey Status=Inactive` on the leaked key, never a
    /// delete. Already inactive or already gone is `Ok`.
    async fn revoke(&self, credential: &Credential) -> Result<Revoked, ProviderError> {
        let pair = long_term_pair(credential)?;
        let iam = self.iam().await?;
        let owner = self.owner(&iam, &pair.key_id).await?;
        let slots = self
            .key_slots(&iam, &owner.user, false)
            .await
            .map_err(|f| f.into_operator_error("iam:ListAccessKeys"))?;
        let Some(slot) = slots.iter().find(|s| s.id == pair.key_id) else {
            return Ok(Revoked { restore_ref: None });
        };
        if slot.status != StatusType::Inactive.as_str() {
            self.set_status(&iam, &owner.user, &pair.key_id, StatusType::Inactive)
                .await?;
        }
        Ok(Revoked {
            restore_ref: Some(self.restore_ref_for(&pair.key_id)),
        })
    }

    /// Reactivates the old key, then deactivates the replacement when the
    /// reference names one.
    async fn restore(&self, restore_ref: &str) -> Result<RestoreOutcome, ProviderError> {
        let (old, new) = parse_restore_ref(restore_ref)?;
        let iam = self.iam().await?;
        let owner = self.owner(&iam, old).await?;
        self.set_status(&iam, &owner.user, old, StatusType::Active)
            .await?;
        if let Some(new) = new {
            self.set_status(&iam, &owner.user, new, StatusType::Inactive)
                .await
                .map_err(|e| {
                    ProviderError::Permanent(format!(
                        "{old} is active again, but deactivating the replacement {new} failed: {e}"
                    ))
                })?;
        }
        Ok(RestoreOutcome::Restored)
    }

    /// Deactivates the replacement key by its id, the `replacement_ref`
    /// `create_replacement` returned (SHA-259). Deactivating an inactive
    /// key is not an error; nothing is deleted.
    async fn revoke_replacement(&self, replacement_ref: &str) -> Result<(), ProviderError> {
        if !is_key_id(replacement_ref) || is_temporary(replacement_ref) {
            return Err(ProviderError::Permanent(
                "not an AWS access key id; the replacement reference must be the new key's id"
                    .into(),
            ));
        }
        let iam = self.iam().await?;
        let owner = self.owner(&iam, replacement_ref).await?;
        self.set_status(&iam, &owner.user, replacement_ref, StatusType::Inactive)
            .await
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
    fn restore_ref_round_trips_and_rejects_junk() {
        let old = key_id("AKIA", "OLDKEY0");
        let new = key_id("AKIA", "NEWKEY0");
        assert_eq!(parse_restore_ref(&old).unwrap(), (old.as_str(), None));
        let both = restore_ref(&old, &new);
        assert_eq!(
            parse_restore_ref(&both).unwrap(),
            (old.as_str(), Some(new.as_str()))
        );
        for junk in [
            "".to_owned(),
            "AKIA123".to_owned(),
            format!("{old}:"),
            format!("{old}:{new}:{new}"),
            key_id("ASIA", "TEMPKEY"),
        ] {
            assert!(parse_restore_ref(&junk).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn two_keys_text_lists_both() {
        let slots = [
            Slot {
                id: key_id("AKIA", "SLOTONE"),
                status: "Active".into(),
                last_used: "s3 in eu-west-1 at 2026-09-01T10:00:00Z".into(),
            },
            Slot {
                id: key_id("AKIA", "SLOTTWO"),
                status: "Inactive".into(),
                last_used: "never".into(),
            },
        ];
        let text = two_keys("alice", &slots);
        for want in [
            &key_id("AKIA", "SLOTONE"),
            &key_id("AKIA", "SLOTTWO"),
            "Active",
            "Inactive",
            "2026-09-01T10:00:00Z",
            "never",
            "alice",
        ] {
            assert!(text.contains(want), "{want} missing: {text}");
        }
    }

    #[tokio::test]
    async fn write_side_refuses_temporary_and_malformed_without_calls() {
        let p = AwsProvider::new().with_endpoint_url("http://127.0.0.1:9");
        for id in [key_id("ASIA", "UNITKEY"), "CONFORMANCECANARYKEY".to_owned()] {
            let c = Credential::KeyPair(SecretPair::new(id, secret()));
            assert!(matches!(
                p.create_replacement(&c).await,
                Err(ProviderError::Unsupported(_))
            ));
            assert!(matches!(
                p.verify(&c, &Identity("arn".into())).await,
                Err(ProviderError::Unsupported(_))
            ));
            assert!(matches!(
                p.revoke(&c).await,
                Err(ProviderError::Unsupported(_))
            ));
        }
        assert!(matches!(
            p.restore("not-a-key").await,
            Err(ProviderError::Permanent(_))
        ));
    }

    #[test]
    fn account_from_arn() {
        assert_eq!(
            account("arn:aws:iam::000000000000:user/a"),
            Some("000000000000")
        );
        assert_eq!(account("junk"), None);
    }
}
