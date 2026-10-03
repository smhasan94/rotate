//! A provider test double that records every call (FR8).
//!
//! Configure responses with the builder methods, share a [`CallLog`] across
//! several mocks with [`MockProvider::log`], and inject failures per method
//! with [`fail_next`](MockProvider::fail_next) (a queue, consumed in order)
//! or [`fail_always`](MockProvider::fail_always). Every method records a
//! [`Call`] before doing anything else, so a failed call is still counted.
//!
//! The mock remembers which fingerprints it has revoked: `check_valid`
//! reports them `Invalid` until `restore` brings them back. `verify` accepts
//! only the identity in its [`Scope`]. The knobs
//! [`fail_after`](MockProvider::fail_after),
//! [`mutates_in`](MockProvider::mutates_in) and
//! [`leak_secret_in_errors`](MockProvider::leak_secret_in_errors) make it
//! misbehave on purpose so the conformance suite (SHA-249) can be tested.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use super::{
    is_mutating, Confidence, Credential, Identity, Provider, ProviderError, Replacement,
    ReplacementMode, RestoreOutcome, Revoked, Scope, Validity,
};
use crate::calls::{Call, CallLog};
use crate::finding::Finding;
use crate::secret::{Fingerprint, SecretPair, SecretValue};

/// Test double for [`Provider`].
pub struct MockProvider {
    name: &'static str,
    identify_prefix: Option<String>,
    confidence: Confidence,
    validity: Validity,
    scope: Scope,
    restore_outcome: RestoreOutcome,
    mode: ReplacementMode,
    log: CallLog,
    queued_failures: Mutex<HashMap<String, VecDeque<ProviderError>>>,
    standing_failures: Mutex<HashMap<String, ProviderError>>,
    replacements: AtomicU64,
    revoked: Mutex<HashSet<Fingerprint>>,
    owners: HashMap<Fingerprint, Identity>,
    restore_refs: Mutex<HashMap<String, Fingerprint>>,
    created: Mutex<HashMap<String, Fingerprint>>,
    late_failures: Mutex<HashMap<String, (usize, ProviderError)>>,
    call_counts: Mutex<HashMap<String, usize>>,
    mutates_in: HashSet<String>,
    leaks_in: HashSet<String>,
    latency: Option<Duration>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

/// Counts a read call as in flight until dropped.
struct InFlight<'a>(&'a AtomicUsize);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl MockProvider {
    /// A mock that identifies nothing, reports every credential valid,
    /// mints replacements automatically and supports restore.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            identify_prefix: None,
            confidence: Confidence::High,
            validity: Validity::Valid,
            scope: Scope {
                identity: Identity(format!("{name}-user")),
                lines: vec![format!("{name}: full access")],
            },
            restore_outcome: RestoreOutcome::Restored,
            mode: ReplacementMode::Automatic,
            log: CallLog::new(),
            queued_failures: Mutex::new(HashMap::new()),
            standing_failures: Mutex::new(HashMap::new()),
            replacements: AtomicU64::new(0),
            revoked: Mutex::new(HashSet::new()),
            owners: HashMap::new(),
            restore_refs: Mutex::new(HashMap::new()),
            created: Mutex::new(HashMap::new()),
            late_failures: Mutex::new(HashMap::new()),
            call_counts: Mutex::new(HashMap::new()),
            mutates_in: HashSet::new(),
            leaks_in: HashSet::new(),
            latency: None,
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        }
    }

    /// Identify findings whose raw value starts with `prefix`. Generated
    /// replacements start with the same prefix so the mock recognises them.
    pub fn identify_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.identify_prefix = Some(prefix.into());
        self
    }

    /// Confidence reported by `identify` on a match (default `High`).
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// What `check_valid` returns (default `Valid`).
    pub fn validity(mut self, validity: Validity) -> Self {
        self.validity = validity;
        self
    }

    /// What `describe_scope` returns.
    pub fn scope(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// What `restore` returns (default `Restored`).
    pub fn restore_outcome(mut self, outcome: RestoreOutcome) -> Self {
        self.restore_outcome = outcome;
        self
    }

    /// What `Provider::replacement_mode` returns (default `Automatic`).
    pub fn mode(mut self, mode: ReplacementMode) -> Self {
        self.mode = mode;
        self
    }

    /// Write calls to a log shared with other doubles.
    pub fn log(mut self, log: CallLog) -> Self {
        self.log = log;
        self
    }

    /// Treat `fingerprint` as already revoked: `check_valid` reports it
    /// `Invalid`. Use it for a credential the provider does not know.
    pub fn revoked(self, fingerprint: Fingerprint) -> Self {
        lock(&self.revoked).insert(fingerprint);
        self
    }

    /// The credential with `fingerprint` belongs to `owner`: `verify`
    /// rejects it for any other identity. Credentials not named here belong
    /// to the scope's identity. Use it for a pasted replacement from the
    /// wrong account (SHA-257).
    pub fn owner(mut self, fingerprint: Fingerprint, owner: Identity) -> Self {
        self.owners.insert(fingerprint, owner);
        self
    }

    /// Misbehave: every call to `method` also records a mutating `revoke`
    /// call, as a plugin that changes state inside a read would.
    pub fn mutates_in(mut self, method: &str) -> Self {
        self.mutates_in.insert(method.to_owned());
        self
    }

    /// Misbehave: every call to `method` fails with an error whose text
    /// contains the secret it was given.
    pub fn leak_secret_in_errors(mut self, method: &str) -> Self {
        self.leaks_in.insert(method.to_owned());
        self
    }

    /// The identity `describe_scope` reports and `verify` accepts.
    pub fn identity(&self) -> Identity {
        self.scope.identity.clone()
    }

    /// True when the mock currently treats `fingerprint` as revoked.
    pub fn is_revoked(&self, fingerprint: &Fingerprint) -> bool {
        lock(&self.revoked).contains(fingerprint)
    }

    /// Make `check_valid`, `describe_scope` and `verify` wait `latency`
    /// before returning, so tests can observe concurrency.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Highest number of read calls that were in flight at the same time.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    /// Marks a read call in flight for as long as the guard lives.
    fn begin(&self) -> InFlight<'_> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        InFlight(&self.in_flight)
    }

    /// Records a read call, waits out the configured latency, then returns
    /// the injected failure if any.
    async fn read_call(&self, method: &str, credential: &Credential) -> Result<(), ProviderError> {
        let _in_flight = self.begin();
        let result = self.enter_with(method, credential);
        if let Some(latency) = self.latency {
            tokio::time::sleep(latency).await;
        }
        result
    }

    /// The log this mock writes to.
    pub fn call_log(&self) -> CallLog {
        self.log.clone()
    }

    /// Queue an error for the next call to `method`. Several calls queue in
    /// order; each call consumes one.
    pub fn fail_next(&self, method: &str, error: ProviderError) {
        self.queued_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(method.to_owned())
            .or_default()
            .push_back(error);
    }

    /// Fail every call to `method` with `error` once the queue for it is
    /// empty.
    pub fn fail_always(&self, method: &str, error: ProviderError) {
        self.standing_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(method.to_owned(), error);
    }

    /// Let the first `ok_calls` calls to `method` through, then fail every
    /// later one with `error`. Queued and standing failures still apply.
    pub fn fail_after(&self, method: &str, ok_calls: usize, error: ProviderError) {
        lock(&self.late_failures).insert(method.to_owned(), (ok_calls, error));
    }

    /// Records the call, then returns the injected failure for `method` if
    /// there is one.
    fn enter(&self, method: &str, fingerprint: Option<Fingerprint>) -> Result<(), ProviderError> {
        self.enter_ref(method, fingerprint, None)
    }

    /// [`enter`](Self::enter) for a call that targets a reference.
    fn enter_ref(
        &self,
        method: &str,
        fingerprint: Option<Fingerprint>,
        reference: Option<&str>,
    ) -> Result<(), ProviderError> {
        self.log.record(Call {
            target: self.name.to_owned(),
            method: method.to_owned(),
            mutating: is_mutating(method),
            fingerprint: fingerprint.clone(),
            reference: reference.map(str::to_owned),
        });
        if self.mutates_in.contains(method) {
            self.log.record(Call {
                target: self.name.to_owned(),
                method: "revoke".to_owned(),
                mutating: true,
                fingerprint,
                reference: None,
            });
        }
        let count = {
            let mut counts = lock(&self.call_counts);
            let count = counts.entry(method.to_owned()).or_default();
            *count += 1;
            *count
        };
        if let Some((ok_calls, error)) = lock(&self.late_failures).get(method) {
            if count > *ok_calls {
                return Err(error.clone());
            }
        }
        let queued = self
            .queued_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(method)
            .and_then(VecDeque::pop_front);
        if let Some(error) = queued {
            return Err(error);
        }
        let standing = self
            .standing_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(method)
            .cloned();
        match standing {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Records the call for a method that takes a credential, then returns
    /// the injected failure, or the deliberate leak when configured.
    fn enter_with(&self, method: &str, credential: &Credential) -> Result<(), ProviderError> {
        self.enter(method, Some(credential.fingerprint()))?;
        if self.leaks_in.contains(method) {
            let text = credential
                .secret()
                .expose_secret(|bytes| String::from_utf8_lossy(bytes).into_owned());
            return Err(ProviderError::Permanent(format!(
                "rejected credential {text}"
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for MockProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockProvider")
            .field("name", &self.name)
            .field("calls", &self.log.len())
            .finish()
    }
}

#[async_trait]
impl Provider for MockProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn replacement_mode(&self) -> ReplacementMode {
        self.mode
    }

    fn identify(&self, finding: &Finding) -> Option<Confidence> {
        // Recording is best effort here: identify is infallible.
        let _ = self.enter("identify", Some(finding.fingerprint()));
        let prefix = self.identify_prefix.as_deref()?;
        finding
            .raw
            .expose_secret(|bytes| bytes.starts_with(prefix.as_bytes()))
            .then_some(self.confidence)
    }

    async fn check_valid(&self, credential: &Credential) -> Result<Validity, ProviderError> {
        self.read_call("check_valid", credential).await?;
        if self.is_revoked(&credential.fingerprint()) {
            return Ok(Validity::Invalid);
        }
        Ok(self.validity.clone())
    }

    async fn describe_scope(&self, credential: &Credential) -> Result<Scope, ProviderError> {
        self.read_call("describe_scope", credential).await?;
        Ok(self.scope.clone())
    }

    async fn create_replacement(
        &self,
        credential: &Credential,
    ) -> Result<Replacement, ProviderError> {
        self.enter_with("create_replacement", credential)?;
        let n = self.replacements.fetch_add(1, Ordering::SeqCst) + 1;
        let prefix = self.identify_prefix.as_deref().unwrap_or_default();
        let value = SecretValue::from(format!("{prefix}{}-replacement-{n}", self.name));
        let credential = match credential {
            Credential::Token(_) => Credential::Token(value),
            Credential::KeyPair(_) => Credential::KeyPair(SecretPair::new(
                format!("{}-key-{n}", self.name.to_uppercase()),
                value,
            )),
        };
        let replacement_ref = format!("{}-ref-{n}", self.name);
        lock(&self.created).insert(replacement_ref.clone(), credential.fingerprint());
        Ok(Replacement {
            credential,
            replacement_ref,
        })
    }

    async fn verify(
        &self,
        credential: &Credential,
        identity: &Identity,
    ) -> Result<(), ProviderError> {
        self.read_call("verify", credential).await?;
        let owner = self
            .owners
            .get(&credential.fingerprint())
            .unwrap_or(&self.scope.identity);
        if identity != owner {
            return Err(ProviderError::Permanent(format!(
                "credential belongs to {owner}, not {identity}"
            )));
        }
        Ok(())
    }

    async fn revoke(&self, credential: &Credential) -> Result<Revoked, ProviderError> {
        self.enter_with("revoke", credential)?;
        let restore_ref = match credential.key_id() {
            Some(key_id) => key_id.to_owned(),
            None => format!("{}-{}", self.name, credential.fingerprint()),
        };
        lock(&self.revoked).insert(credential.fingerprint());
        lock(&self.restore_refs).insert(restore_ref.clone(), credential.fingerprint());
        Ok(Revoked {
            restore_ref: Some(restore_ref),
        })
    }

    async fn restore(&self, restore_ref: &str) -> Result<RestoreOutcome, ProviderError> {
        self.enter_ref("restore", None, Some(restore_ref))?;
        if self.restore_outcome == RestoreOutcome::Restored {
            if let Some(fingerprint) = lock(&self.restore_refs).get(restore_ref) {
                lock(&self.revoked).remove(fingerprint);
            }
        }
        Ok(self.restore_outcome)
    }

    /// Revokes a replacement this mock minted, by its ref. A ref it did not
    /// mint (another process made it) is recorded and accepted.
    async fn revoke_replacement(&self, replacement_ref: &str) -> Result<(), ProviderError> {
        let fingerprint = lock(&self.created).get(replacement_ref).cloned();
        self.enter_ref(
            "revoke_replacement",
            fingerprint.clone(),
            Some(replacement_ref),
        )?;
        if let Some(fingerprint) = fingerprint {
            lock(&self.revoked).insert(fingerprint);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(value: &str) -> Credential {
        Credential::Token(SecretValue::from(value))
    }

    fn methods(log: &CallLog) -> Vec<(String, bool)> {
        log.calls()
            .into_iter()
            .map(|c| (c.method, c.mutating))
            .collect()
    }

    // T2 (AC2)
    #[tokio::test]
    async fn read_methods_are_recorded_non_mutating() {
        let mock = MockProvider::new("mock");
        let cred = token("mock_abc");
        let scope = mock.describe_scope(&cred).await.unwrap();
        assert_eq!(mock.check_valid(&cred).await.unwrap(), Validity::Valid);
        mock.verify(&cred, &scope.identity).await.unwrap();

        let log = mock.call_log();
        assert_eq!(
            methods(&log),
            vec![
                ("describe_scope".to_owned(), false),
                ("check_valid".to_owned(), false),
                ("verify".to_owned(), false),
            ]
        );
        assert!(log
            .calls()
            .iter()
            .all(|c| c.fingerprint == Some(cred.fingerprint())));
        log.assert_no_mutations();
    }

    // T3 (AC3)
    #[tokio::test]
    async fn write_methods_are_recorded_mutating() {
        let mock = MockProvider::new("mock").identify_prefix("mock_");
        let cred = token("mock_abc");
        let replacement = mock.create_replacement(&cred).await.unwrap();
        assert_ne!(replacement.credential, cred);
        assert!(replacement
            .credential
            .secret()
            .expose_secret(|b| b.starts_with(b"mock_")));
        assert_eq!(replacement.replacement_ref, "mock-ref-1");

        let revoked = mock.revoke(&cred).await.unwrap();
        let restore_ref = revoked.restore_ref.unwrap();
        assert!(restore_ref.contains(cred.fingerprint().as_str()));
        assert_eq!(
            mock.restore(&restore_ref).await.unwrap(),
            RestoreOutcome::Restored
        );

        assert_eq!(
            methods(&mock.call_log()),
            vec![
                ("create_replacement".to_owned(), true),
                ("revoke".to_owned(), true),
                ("restore".to_owned(), true),
            ]
        );
        assert_eq!(mock.call_log().mutating().len(), 3);
    }

    #[tokio::test]
    async fn key_pair_replacement_gets_new_key_id() {
        let mock = MockProvider::new("aws");
        let cred = Credential::KeyPair(SecretPair::new("AKIAOLD", SecretValue::from("old")));
        let first = mock.create_replacement(&cred).await.unwrap();
        let second = mock.create_replacement(&cred).await.unwrap();
        assert_eq!(first.credential.key_id(), Some("AWS-key-1"));
        assert_eq!(second.credential.key_id(), Some("AWS-key-2"));
        assert_ne!(
            first.credential.fingerprint(),
            second.credential.fingerprint()
        );

        let revoked = mock.revoke(&cred).await.unwrap();
        assert_eq!(revoked.restore_ref.as_deref(), Some("AKIAOLD"));
    }

    // T4 (AC4)
    #[tokio::test]
    async fn injected_failure_is_returned_and_recorded() {
        let mock = MockProvider::new("mock");
        let cred = token("mock_abc");
        mock.fail_next("revoke", ProviderError::Permanent("forbidden".into()));

        let err = mock.revoke(&cred).await.unwrap_err();
        assert_eq!(err, ProviderError::Permanent("forbidden".into()));
        assert_eq!(mock.call_log().len(), 1);
        assert_eq!(mock.call_log().calls()[0].method, "revoke");

        // The queue is consumed: the next call succeeds.
        mock.revoke(&cred).await.unwrap();
        assert_eq!(mock.call_log().len(), 2);
    }

    // T4 (AC4)
    #[tokio::test]
    async fn fail_always_repeats() {
        let mock = MockProvider::new("mock");
        let cred = token("mock_abc");
        mock.fail_always("check_valid", ProviderError::Transient("boom".into()));
        for _ in 0..3 {
            assert_eq!(
                mock.check_valid(&cred).await.unwrap_err(),
                ProviderError::Transient("boom".into())
            );
        }
        assert_eq!(mock.call_log().len(), 3);
        // Other methods are unaffected.
        mock.describe_scope(&cred).await.unwrap();
    }

    #[tokio::test]
    async fn scripted_failures_pop_in_order() {
        let mock = MockProvider::new("mock");
        let cred = token("mock_abc");
        mock.fail_next(
            "check_valid",
            ProviderError::RateLimited {
                retry_after: Some(std::time::Duration::from_millis(1)),
            },
        );
        mock.fail_next(
            "check_valid",
            ProviderError::RateLimited { retry_after: None },
        );

        assert!(matches!(
            mock.check_valid(&cred).await,
            Err(ProviderError::RateLimited {
                retry_after: Some(_)
            })
        ));
        assert!(matches!(
            mock.check_valid(&cred).await,
            Err(ProviderError::RateLimited { retry_after: None })
        ));
        assert_eq!(mock.check_valid(&cred).await.unwrap(), Validity::Valid);
        assert_eq!(mock.call_log().len(), 3);
    }

    // T5 (AC5)
    #[tokio::test]
    async fn restore_unsupported_is_ok() {
        let mock = MockProvider::new("github").restore_outcome(RestoreOutcome::Unsupported);
        assert_eq!(
            mock.restore("anything").await.unwrap(),
            RestoreOutcome::Unsupported
        );
        assert_eq!(mock.call_log().mutating().len(), 1);
    }

    #[tokio::test]
    async fn revoke_replacement_by_ref() {
        let mock = MockProvider::new("mock");
        let replacement = mock.create_replacement(&token("mock_old")).await.unwrap();
        mock.revoke_replacement(&replacement.replacement_ref)
            .await
            .unwrap();
        assert_eq!(
            mock.check_valid(&replacement.credential).await.unwrap(),
            Validity::Invalid
        );
        mock.revoke_replacement("elsewhere-ref").await.unwrap();
        let calls = mock.call_log().calls();
        let revokes: Vec<_> = calls
            .iter()
            .filter(|c| c.method == "revoke_replacement")
            .collect();
        assert_eq!(revokes.len(), 2);
        assert!(revokes.iter().all(|c| c.mutating));
        assert_eq!(
            revokes[0].reference.as_deref(),
            Some(replacement.replacement_ref.as_str())
        );
        assert_eq!(
            revokes[0].fingerprint,
            Some(replacement.credential.fingerprint())
        );
        assert_eq!(revokes[1].fingerprint, None);
    }

    #[tokio::test]
    async fn mock_revoked_set_and_identity() {
        let cred = token("mock_abc");
        let unknown = token("mock_unknown");
        let mock = MockProvider::new("mock").revoked(unknown.fingerprint());
        assert_eq!(mock.check_valid(&unknown).await.unwrap(), Validity::Invalid);
        assert_eq!(mock.check_valid(&cred).await.unwrap(), Validity::Valid);

        let revoked = mock.revoke(&cred).await.unwrap();
        assert_eq!(mock.check_valid(&cred).await.unwrap(), Validity::Invalid);
        mock.restore(revoked.restore_ref.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(mock.check_valid(&cred).await.unwrap(), Validity::Valid);

        mock.verify(&cred, &Identity("mock-user".into()))
            .await
            .unwrap();
        let err = mock
            .verify(&cred, &Identity("someone-else".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Permanent(_)));
    }

    #[tokio::test]
    async fn misbehaviour_knobs() {
        let cred = token("mock_knob_value");
        let mock = MockProvider::new("mock")
            .mutates_in("check_valid")
            .leak_secret_in_errors("describe_scope");
        mock.fail_after("revoke", 1, ProviderError::Permanent("gone".into()));

        mock.check_valid(&cred).await.unwrap();
        assert_eq!(mock.call_log().mutating().len(), 1);

        let err = mock.describe_scope(&cred).await.unwrap_err();
        assert!(err.to_string().contains("mock_knob_value"));

        mock.revoke(&cred).await.unwrap();
        assert_eq!(
            mock.revoke(&cred).await.unwrap_err(),
            ProviderError::Permanent("gone".into())
        );
    }

    #[tokio::test]
    async fn configured_responses_and_shared_log() {
        let shared = CallLog::new();
        let mock = MockProvider::new("npm")
            .validity(Validity::Unknown {
                reason: "timeout".into(),
            })
            .scope(Scope {
                identity: Identity("npm:alice".into()),
                lines: vec!["publish".into()],
            })
            .mode(ReplacementMode::Manual)
            .log(shared.clone());
        let cred = token("npm_x");

        assert_eq!(mock.replacement_mode(), ReplacementMode::Manual);
        assert_eq!(
            mock.check_valid(&cred).await.unwrap(),
            Validity::Unknown {
                reason: "timeout".into()
            }
        );
        let scope = mock.describe_scope(&cred).await.unwrap();
        assert_eq!(scope.identity.to_string(), "npm:alice");
        assert_eq!(shared.len(), 2);
        assert_eq!(shared.calls()[0].target, "npm");
        assert_eq!(
            format!("{mock:?}"),
            "MockProvider { name: \"npm\", calls: 2 }"
        );
    }
}
