//! The provider plugin contract (FR7) and the registry that resolves a
//! finding to a provider (SHA-221).
//!
//! A provider knows one kind of credential: how to recognise it, check it,
//! describe what it reaches, mint a replacement, and revoke or restore it.
//! The methods listed in [`MUTATING`] change state on the real service;
//! everything else is read-only and safe for a dry run.

pub mod aws;
pub mod github;
pub mod mock;
pub mod openai;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::finding::Finding;
use crate::secret::{Fingerprint, SecretPair, SecretValue};

/// Trait method names that change state on the provider. The mock uses
/// this list to flag calls; the engine uses it to describe the plan.
pub const MUTATING: &[&str] = &[
    "create_replacement",
    "revoke",
    "restore",
    "revoke_replacement",
];

/// True when the named trait method changes state on the provider.
pub fn is_mutating(method: &str) -> bool {
    MUTATING.contains(&method)
}

/// The credential a provider operates on.
///
/// Most providers use a single token. AWS signs requests with an access key
/// id plus a secret access key, so it needs both halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// A single secret token.
    Token(SecretValue),
    /// An AWS-style key id plus secret.
    KeyPair(SecretPair),
}

impl Credential {
    /// The secret half.
    pub fn secret(&self) -> &SecretValue {
        match self {
            Credential::Token(secret) => secret,
            Credential::KeyPair(pair) => &pair.secret,
        }
    }

    /// The printable key id, for key pairs only.
    pub fn key_id(&self) -> Option<&str> {
        match self {
            Credential::Token(_) => None,
            Credential::KeyPair(pair) => Some(&pair.key_id),
        }
    }

    /// Fingerprint of the secret half (assumption A1).
    pub fn fingerprint(&self) -> Fingerprint {
        self.secret().fingerprint()
    }
}

/// How sure a provider is that a finding is one of its credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Shape is compatible but nothing specific matched.
    Low,
    /// The value matches the provider's format.
    Medium,
    /// The value matches and the detector hint agrees.
    High,
}

/// Result of a validity check (FR5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validity {
    /// The provider accepted the credential.
    Valid,
    /// The provider rejected it: revoked, expired or never real.
    Invalid,
    /// Could not tell, for example a network or permission error.
    Unknown {
        /// Why the check could not decide. Must not contain the value.
        reason: String,
    },
}

/// Who a credential belongs to, as the provider names it: an IAM user ARN,
/// a GitHub login, an npm user, an OpenAI project.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity(pub String);

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a credential can reach (FR6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The owning identity.
    pub identity: Identity,
    /// Free-form lines for the operator: attached policies, token scopes.
    pub lines: Vec<String>,
}

/// A freshly minted credential and the provider's handle on it.
///
/// No `Serialize`: it holds a secret. The audit log records
/// `replacement_ref` and the fingerprint only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The new credential.
    pub credential: Credential,
    /// Provider-side reference to the new credential, for example the new
    /// AWS access key id or a token id. Never the value.
    pub replacement_ref: String,
}

/// Outcome of a revoke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// Handle to pass to [`Provider::restore`] when the provider can undo
    /// the revoke (a deactivated AWS key id). `None` when it cannot.
    pub restore_ref: Option<String>,
}

/// Outcome of a restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The old credential works again.
    Restored,
    /// The provider cannot reactivate a revoked credential.
    Unsupported,
}

/// Whether the provider can mint a replacement itself or must ask the
/// operator for one (decision D1). Serialized in the audit log as
/// `automatic` or `manual`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplacementMode {
    /// `create_replacement` calls the provider API.
    Automatic,
    /// The operator supplies the new secret; `create_replacement` is never
    /// called.
    Manual,
}

/// Why a provider call failed. Messages must never contain a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// HTTP 429 or equivalent; retry after the hint if any.
    #[error("rate limited by the provider")]
    RateLimited {
        /// The provider's retry hint, when it gave one.
        retry_after: Option<Duration>,
    },
    /// Network failure or 5xx; a retry may succeed.
    #[error("transient provider failure: {0}")]
    Transient(String),
    /// Authentication, authorization or a 4xx that will not change.
    #[error("{0}")]
    Permanent(String),
    /// The provider cannot do this for this credential, for example a
    /// token where a key pair was required.
    #[error("unsupported by the provider: {0}")]
    Unsupported(String),
}

impl ProviderError {
    /// True for failures a retry with backoff may fix (SHA-248).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ProviderError::RateLimited { .. } | ProviderError::Transient(_)
        )
    }
}

/// One provider plugin. Implementations are `Send + Sync` so the registry
/// can share them across tasks.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Short stable name used in plans, config and the audit log, for
    /// example `aws`.
    fn name(&self) -> &'static str;

    /// Whether this provider can mint replacements.
    fn replacement_mode(&self) -> ReplacementMode;

    /// What the operator must create by hand in manual replacement mode
    /// (decision D1), shown before the hidden prompt. Providers in manual
    /// mode override it to name the page and the scopes to copy. Must not
    /// contain a value.
    fn manual_instructions(&self, scope: &Scope) -> String {
        format!(
            "Create a new {} credential for {} with the same access as the leaked one, then paste it at the prompt.",
            self.name(),
            scope.identity
        )
    }

    /// The revoke row the plan shows instead of the usual one when rotate
    /// cannot revoke this credential itself, for example an OpenAI key the
    /// Admin API cannot delete. Pure: no network. `None` (the default)
    /// means `revoke` does it. Must not contain a value.
    fn manual_revoke(&self, scope: Option<&Scope>) -> Option<&'static str> {
        let _ = scope;
        None
    }

    /// Whether the finding looks like one of this provider's credentials.
    /// Pure: no network.
    fn identify(&self, finding: &Finding) -> Option<Confidence>;

    /// Cheapest read-only call that tells whether the credential works.
    async fn check_valid(&self, credential: &Credential) -> Result<Validity, ProviderError>;

    /// Read-only description of the owner and reach of the credential.
    async fn describe_scope(&self, credential: &Credential) -> Result<Scope, ProviderError>;

    /// Mints a replacement for the credential. Mutating.
    async fn create_replacement(
        &self,
        credential: &Credential,
    ) -> Result<Replacement, ProviderError>;

    /// Read-only check that `credential` works and belongs to `identity`,
    /// used on the replacement before anything is revoked (assumption A5).
    async fn verify(
        &self,
        credential: &Credential,
        identity: &Identity,
    ) -> Result<(), ProviderError>;

    /// Revokes the credential. Mutating, and always the last step.
    async fn revoke(&self, credential: &Credential) -> Result<Revoked, ProviderError>;

    /// Reactivates a revoked credential by the handle `revoke` returned.
    /// Mutating. Returns `Unsupported` rather than an error when the
    /// provider cannot.
    async fn restore(&self, restore_ref: &str) -> Result<RestoreOutcome, ProviderError>;

    /// Revokes a replacement by the `replacement_ref` that
    /// `create_replacement` returned, for `rotate rollback` (SHA-259):
    /// rotate never stores the replacement's value, so [`revoke`](Self::revoke)
    /// cannot be used. Mutating. Revoking one that is already revoked is
    /// not an error. The default returns `Unsupported`; rollback then tells
    /// the operator to revoke the replacement by hand.
    async fn revoke_replacement(&self, replacement_ref: &str) -> Result<(), ProviderError> {
        let _ = replacement_ref;
        Err(ProviderError::Unsupported(format!(
            "{} cannot revoke a credential by its reference",
            self.name()
        )))
    }
}

/// A provider chosen for a finding.
#[derive(Clone)]
pub struct Identified {
    /// The winning provider.
    pub provider: Arc<dyn Provider>,
    /// Its confidence.
    pub confidence: Confidence,
}

impl fmt::Debug for Identified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identified")
            .field("provider", &self.provider.name())
            .field("confidence", &self.confidence)
            .finish()
    }
}

/// Two or more providers claimed a finding with the same top confidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ambiguous provider at confidence {confidence:?}: {}", names.join(", "))]
pub struct AmbiguousProvider {
    /// The tied confidence.
    pub confidence: Confidence,
    /// Names of the tied providers, in registration order.
    pub names: Vec<&'static str>,
}

/// The set of registered providers.
#[derive(Clone, Default)]
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn Provider>>,
}

impl ProviderRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a provider. Order matters only for the names listed in an
    /// [`AmbiguousProvider`] error.
    pub fn register(&mut self, provider: Arc<dyn Provider>) {
        self.providers.push(provider);
    }

    /// Looks a provider up by name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Provider>> {
        self.providers.iter().find(|p| p.name() == name)
    }

    /// Names of every registered provider, in registration order.
    pub fn names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Resolves a finding to the provider with the highest confidence.
    ///
    /// `Ok(None)` when no provider claims it. A tie at the top confidence is
    /// an error rather than a silent pick.
    pub fn identify(&self, finding: &Finding) -> Result<Option<Identified>, AmbiguousProvider> {
        let claims: Vec<(Confidence, &Arc<dyn Provider>)> = self
            .providers
            .iter()
            .filter_map(|p| p.identify(finding).map(|c| (c, p)))
            .collect();
        let Some(top) = claims.iter().map(|(c, _)| *c).max() else {
            return Ok(None);
        };
        let winners: Vec<&Arc<dyn Provider>> = claims
            .iter()
            .filter(|(c, _)| *c == top)
            .map(|(_, p)| *p)
            .collect();
        match winners.as_slice() {
            [single] => Ok(Some(Identified {
                provider: Arc::clone(single),
                confidence: top,
            })),
            _ => Err(AmbiguousProvider {
                confidence: top,
                names: winners.iter().map(|p| p.name()).collect(),
            }),
        }
    }
}

impl fmt::Debug for ProviderRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderRegistry")
            .field("providers", &self.names())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockProvider;
    use super::*;
    use crate::finding::SourceLocation;

    fn finding(value: &str) -> Finding {
        Finding::new(
            SecretValue::from(value),
            "Mock",
            SourceLocation::file("a.env"),
        )
    }

    // T1 (AC1)
    #[test]
    fn registry_identifies_by_prefix() {
        let mut registry = ProviderRegistry::new();
        registry.register(Arc::new(MockProvider::new("mock").identify_prefix("mock_")));

        let hit = registry.identify(&finding("mock_abc")).unwrap().unwrap();
        assert_eq!(hit.provider.name(), "mock");
        assert_eq!(hit.confidence, Confidence::High);
        assert_eq!(
            format!("{hit:?}"),
            "Identified { provider: \"mock\", confidence: High }"
        );

        assert!(registry.identify(&finding("other")).unwrap().is_none());
    }

    // T6 (AC6)
    #[test]
    fn higher_confidence_wins() {
        let mut registry = ProviderRegistry::new();
        registry.register(Arc::new(
            MockProvider::new("medium")
                .identify_prefix("mock_")
                .confidence(Confidence::Medium),
        ));
        registry.register(Arc::new(
            MockProvider::new("high")
                .identify_prefix("mock_")
                .confidence(Confidence::High),
        ));
        registry.register(Arc::new(
            MockProvider::new("silent").identify_prefix("zzz_"),
        ));

        let hit = registry.identify(&finding("mock_abc")).unwrap().unwrap();
        assert_eq!(hit.provider.name(), "high");
        assert_eq!(hit.confidence, Confidence::High);
    }

    // T6 (AC6)
    #[test]
    fn tie_is_ambiguous_naming_both() {
        let mut registry = ProviderRegistry::new();
        registry.register(Arc::new(
            MockProvider::new("first").identify_prefix("mock_"),
        ));
        registry.register(Arc::new(
            MockProvider::new("second").identify_prefix("mock_"),
        ));
        registry.register(Arc::new(
            MockProvider::new("lower")
                .identify_prefix("mock_")
                .confidence(Confidence::Low),
        ));

        let err = registry.identify(&finding("mock_abc")).unwrap_err();
        assert_eq!(err.confidence, Confidence::High);
        assert_eq!(err.names, vec!["first", "second"]);
        assert_eq!(
            err.to_string(),
            "ambiguous provider at confidence High: first, second"
        );
    }

    #[test]
    fn registry_get_and_names() {
        let mut registry = ProviderRegistry::new();
        assert!(registry.names().is_empty());
        registry.register(Arc::new(MockProvider::new("a")));
        registry.register(Arc::new(MockProvider::new("b")));
        assert_eq!(registry.names(), vec!["a", "b"]);
        assert_eq!(registry.get("b").unwrap().name(), "b");
        assert!(registry.get("c").is_none());
        assert_eq!(
            format!("{registry:?}"),
            "ProviderRegistry { providers: [\"a\", \"b\"] }"
        );
    }

    #[test]
    fn error_retryable_classification() {
        assert!(ProviderError::RateLimited { retry_after: None }.is_retryable());
        assert!(ProviderError::Transient("503".into()).is_retryable());
        assert!(!ProviderError::Permanent("403".into()).is_retryable());
        assert!(!ProviderError::Unsupported("token".into()).is_retryable());
        assert_eq!(
            ProviderError::Permanent("forbidden".into()).to_string(),
            "forbidden"
        );
    }

    #[test]
    fn mutating_list_matches_contract() {
        assert!(is_mutating("create_replacement"));
        assert!(is_mutating("revoke"));
        assert!(is_mutating("restore"));
        assert!(is_mutating("revoke_replacement"));
        for read_only in ["identify", "check_valid", "describe_scope", "verify"] {
            assert!(!is_mutating(read_only), "{read_only}");
        }
    }
}
