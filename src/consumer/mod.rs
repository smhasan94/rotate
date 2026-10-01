//! The consumer plugin contract (FR10 to FR12) and the registry the planner
//! asks for every place a secret is used (SHA-222).
//!
//! A consumer is somewhere a credential is stored for use: a GitHub Actions
//! secret, a Secrets Manager entry. `find` is read-only; the methods listed
//! in [`MUTATING`] write to the real service.

pub mod github_actions;
pub mod mock;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::provider::Credential;
use crate::secret::Fingerprint;

/// Trait method names that change state on the consumer.
pub const MUTATING: &[&str] = &["update", "restore"];

/// True when the named trait method changes state on the consumer.
pub fn is_mutating(method: &str) -> bool {
    MUTATING.contains(&method)
}

/// What consumers are asked to look for. Holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// Name of the provider that owns the credential, for example `aws`.
    pub provider: String,
    /// Fingerprint of the secret half.
    pub fingerprint: Fingerprint,
    /// The access key id for key pairs. Not secret.
    pub key_id: Option<String>,
    /// Names to match by when values cannot be read back (decision D4),
    /// built by the engine from the provider's convention and `rotate.yaml`.
    pub names: Vec<String>,
}

impl SecretRef {
    /// A reference to `credential` owned by `provider`, with no name hints.
    pub fn new(provider: impl Into<String>, credential: &Credential) -> Self {
        Self {
            provider: provider.into(),
            fingerprint: credential.fingerprint(),
            key_id: credential.key_id().map(str::to_owned),
            names: Vec::new(),
        }
    }

    /// Adds name-convention hints.
    pub fn with_names<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.names.extend(names.into_iter().map(Into::into));
        self
    }
}

/// How a consumer was matched (FR11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMethod {
    /// The stored value's fingerprint equals the secret's.
    ByValue,
    /// The stored value cannot be read back; matched by name only.
    ByName,
}

/// Which part of a credential a consumer stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holds {
    /// The secret half, or the whole token.
    Secret,
    /// The access key id of a key pair, for example `AWS_ACCESS_KEY_ID`.
    KeyId,
    /// Both halves of a key pair, for example a JSON Secrets Manager entry.
    KeyPair,
}

/// Why a matched consumer cannot be updated automatically (FR12). The
/// reason is shown in the plan verbatim and must never contain a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct NotUpdatable {
    /// Human-readable reason, for example `org secret needs admin`.
    pub reason: String,
}

/// One place a secret is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerMatch {
    /// Display reference, for example
    /// `github-actions:org/repo:AWS_SECRET_ACCESS_KEY`. Never a value.
    pub consumer_ref: String,
    /// How it was matched.
    pub match_method: MatchMethod,
    /// Which part of the credential it stores.
    pub holds: Holds,
    /// `Err` with the reason when it cannot be updated automatically.
    pub updatable: Result<(), NotUpdatable>,
}

impl ConsumerMatch {
    /// An updatable match found by value, holding the secret.
    pub fn by_value(consumer_ref: impl Into<String>) -> Self {
        Self {
            consumer_ref: consumer_ref.into(),
            match_method: MatchMethod::ByValue,
            holds: Holds::Secret,
            updatable: Ok(()),
        }
    }

    /// An updatable match found by name, holding the secret.
    pub fn by_name(consumer_ref: impl Into<String>) -> Self {
        Self {
            match_method: MatchMethod::ByName,
            ..Self::by_value(consumer_ref)
        }
    }

    /// Sets which part of the credential the consumer stores.
    pub fn holding(mut self, holds: Holds) -> Self {
        self.holds = holds;
        self
    }

    /// Marks the match as not updatable for `reason`.
    pub fn not_updatable(mut self, reason: impl Into<String>) -> Self {
        self.updatable = Err(NotUpdatable {
            reason: reason.into(),
        });
        self
    }

    /// True when the match can be updated automatically.
    pub fn is_updatable(&self) -> bool {
        self.updatable.is_ok()
    }

    /// Fingerprint of what this consumer stores once it holds `credential`:
    /// the key id for [`Holds::KeyId`], the secret half otherwise.
    pub fn value_fingerprint(&self, credential: &Credential) -> Result<Fingerprint, ConsumerError> {
        match (self.holds, credential.key_id()) {
            (Holds::Secret, _) => Ok(credential.fingerprint()),
            (Holds::KeyId, Some(key_id)) => Ok(Fingerprint::of(key_id.as_bytes())),
            (Holds::KeyPair, Some(_)) => Ok(credential.fingerprint()),
            (Holds::KeyId | Holds::KeyPair, None) => Err(ConsumerError::Unsupported(format!(
                "{} stores part of a key pair but the credential is a single token",
                self.consumer_ref
            ))),
        }
    }
}

/// Result of a successful update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReceipt {
    /// The consumer that was updated.
    pub consumer_ref: String,
    /// Version the consumer assigned to the new value, when it has one
    /// (a Secrets Manager version id).
    pub version: Option<String>,
}

/// Why a consumer call failed. Messages must never contain a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConsumerError {
    /// HTTP 429 or equivalent; retry after the hint if any.
    #[error("rate limited by the consumer")]
    RateLimited {
        /// The service's retry hint, when it gave one.
        retry_after: Option<Duration>,
    },
    /// Network failure or 5xx; a retry may succeed.
    #[error("transient consumer failure: {0}")]
    Transient(String),
    /// Authentication, authorization or a 4xx that will not change.
    #[error("{0}")]
    Permanent(String),
    /// The consumer cannot do this, for example a key id for a token.
    #[error("unsupported by the consumer: {0}")]
    Unsupported(String),
    /// `update` was called on a match that `find` marked not updatable.
    #[error("not updatable: {0}")]
    NotUpdatable(NotUpdatable),
}

impl ConsumerError {
    /// True for failures a retry with backoff may fix.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ConsumerError::RateLimited { .. } | ConsumerError::Transient(_)
        )
    }
}

/// One consumer plugin. Implementations are `Send + Sync` so the registry
/// can share them across tasks.
#[async_trait]
pub trait Consumer: Send + Sync {
    /// Short stable name used in plans, config and the audit log, for
    /// example `github-actions`.
    fn name(&self) -> &'static str;

    /// Every place this consumer stores the secret. Read-only.
    async fn find(&self, secret: &SecretRef) -> Result<Vec<ConsumerMatch>, ConsumerError>;

    /// Writes the part of `new` that `target` holds. Mutating. Must return
    /// [`ConsumerError::NotUpdatable`] for a match marked not updatable.
    async fn update(
        &self,
        target: &ConsumerMatch,
        new: &Credential,
    ) -> Result<UpdateReceipt, ConsumerError>;

    /// Writes the part of `old` that `target` holds back. Mutating.
    async fn restore(&self, target: &ConsumerMatch, old: &Credential) -> Result<(), ConsumerError>;
}

/// What one consumer returned from [`ConsumerRegistry::find_all`].
#[derive(Debug)]
pub struct ConsumerFindings {
    /// The consumer's name.
    pub consumer: &'static str,
    /// Its matches, or why it could not look.
    pub result: Result<Vec<ConsumerMatch>, ConsumerError>,
}

/// The set of registered consumers.
#[derive(Clone, Default)]
pub struct ConsumerRegistry {
    consumers: Vec<Arc<dyn Consumer>>,
}

impl ConsumerRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a consumer.
    pub fn register(&mut self, consumer: Arc<dyn Consumer>) {
        self.consumers.push(consumer);
    }

    /// Looks a consumer up by name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Consumer>> {
        self.consumers.iter().find(|c| c.name() == name)
    }

    /// Names of every registered consumer, in registration order.
    pub fn names(&self) -> Vec<&'static str> {
        self.consumers.iter().map(|c| c.name()).collect()
    }

    /// Every registered consumer, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Consumer>> {
        self.consumers.iter()
    }

    /// Asks every consumer for `secret` in registration order. One
    /// consumer's error is kept next to the others' results.
    pub async fn find_all(&self, secret: &SecretRef) -> Vec<ConsumerFindings> {
        let mut found = Vec::with_capacity(self.consumers.len());
        for consumer in &self.consumers {
            found.push(ConsumerFindings {
                consumer: consumer.name(),
                result: consumer.find(secret).await,
            });
        }
        found
    }
}

impl fmt::Debug for ConsumerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockConsumer;
    use super::*;
    use crate::secret::{SecretPair, SecretValue};

    fn token(value: &str) -> Credential {
        Credential::Token(SecretValue::from(value))
    }

    fn pair(key_id: &str, secret: &str) -> Credential {
        Credential::KeyPair(SecretPair::new(key_id, SecretValue::from(secret)))
    }

    #[test]
    fn mutating_list_matches_contract() {
        assert!(is_mutating("update"));
        assert!(is_mutating("restore"));
        assert!(!is_mutating("find"));
    }

    #[test]
    fn error_retryable_classification() {
        assert!(ConsumerError::RateLimited { retry_after: None }.is_retryable());
        assert!(ConsumerError::Transient("503".into()).is_retryable());
        assert!(!ConsumerError::Permanent("403".into()).is_retryable());
        assert!(!ConsumerError::Unsupported("x".into()).is_retryable());
        let blocked = ConsumerError::NotUpdatable(NotUpdatable {
            reason: "org secret needs admin".into(),
        });
        assert!(!blocked.is_retryable());
        assert_eq!(blocked.to_string(), "not updatable: org secret needs admin");
    }

    #[test]
    fn secret_ref_carries_key_id_and_names() {
        let cred = pair("AKIAMOCK", "mock_secret");
        let secret = SecretRef::new("aws", &cred).with_names(["AWS_ACCESS_KEY_ID"]);
        assert_eq!(secret.fingerprint, cred.fingerprint());
        assert_eq!(secret.key_id.as_deref(), Some("AKIAMOCK"));
        assert_eq!(secret.names, ["AWS_ACCESS_KEY_ID"]);
        assert!(!format!("{secret:?}").contains("mock_secret"));
    }

    #[test]
    fn value_fingerprint_follows_holds() {
        let cred = pair("AKIAMOCK", "mock_secret");
        let secret_fp = cred.fingerprint();
        let m = ConsumerMatch::by_name("gha:AWS_SECRET_ACCESS_KEY");
        assert_eq!(m.value_fingerprint(&cred).unwrap(), secret_fp);
        let m = m.holding(Holds::KeyId);
        assert_eq!(
            m.value_fingerprint(&cred).unwrap(),
            Fingerprint::of(b"AKIAMOCK")
        );
        let m = m.holding(Holds::KeyPair);
        assert_eq!(m.value_fingerprint(&cred).unwrap(), secret_fp);
    }

    #[test]
    fn key_id_match_rejects_token() {
        for holds in [Holds::KeyId, Holds::KeyPair] {
            let m = ConsumerMatch::by_name("gha:AWS_ACCESS_KEY_ID").holding(holds);
            let err = m.value_fingerprint(&token("mock_tok")).unwrap_err();
            assert!(matches!(err, ConsumerError::Unsupported(_)));
            assert!(!err.to_string().contains("mock_tok"));
        }
    }

    #[test]
    fn match_builders() {
        let m = ConsumerMatch::by_value("sm:prod/db").not_updatable("needs KMS grant");
        assert_eq!(m.match_method, MatchMethod::ByValue);
        assert_eq!(m.holds, Holds::Secret);
        assert!(!m.is_updatable());
        assert_eq!(m.updatable.unwrap_err().to_string(), "needs KMS grant");
        assert_eq!(
            ConsumerMatch::by_name("gha:X").match_method,
            MatchMethod::ByName
        );
    }

    #[tokio::test]
    async fn registry_find_all_keeps_errors_per_consumer() {
        let cred = token("mock_abc");
        let ok =
            MockConsumer::new("ok").matching(cred.fingerprint(), ConsumerMatch::by_value("ok:a"));
        let broken = MockConsumer::new("broken");
        broken.fail_always("find", ConsumerError::Permanent("403".into()));
        let mut registry = ConsumerRegistry::new();
        registry.register(Arc::new(broken));
        registry.register(Arc::new(ok));

        let found = registry.find_all(&SecretRef::new("mock", &cred)).await;
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].consumer, "broken");
        assert_eq!(found[0].result, Err(ConsumerError::Permanent("403".into())));
        assert_eq!(found[1].consumer, "ok");
        assert_eq!(found[1].result.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn registry_get_and_names() {
        let mut registry = ConsumerRegistry::new();
        registry.register(Arc::new(MockConsumer::new("github-actions")));
        registry.register(Arc::new(MockConsumer::new("secrets-manager")));
        assert_eq!(registry.names(), ["github-actions", "secrets-manager"]);
        assert_eq!(
            registry.get("secrets-manager").unwrap().name(),
            "secrets-manager"
        );
        assert!(registry.get("vault").is_none());
        assert_eq!(registry.iter().count(), 2);
        assert_eq!(
            format!("{registry:?}"),
            r#"["github-actions", "secrets-manager"]"#
        );
    }
}
