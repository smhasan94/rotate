//! A consumer test double that records every call and remembers which value
//! each consumer currently holds, by fingerprint (SHA-222).
//!
//! Register matches with [`MockConsumer::matching`], share a [`CallLog`]
//! with other doubles through [`MockConsumer::log`], and inject failures per
//! method with [`fail_next`](MockConsumer::fail_next) (a queue) or
//! [`fail_always`](MockConsumer::fail_always), or per consumer with
//! [`fail_for`](MockConsumer::fail_for). Every method records a [`Call`]
//! before doing anything else, so a failed call is still counted.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;

use super::{is_mutating, Consumer, ConsumerError, ConsumerMatch, SecretRef, UpdateReceipt};
use crate::calls::{Call, CallLog};
use crate::provider::Credential;
use crate::secret::Fingerprint;

/// Test double for [`Consumer`].
pub struct MockConsumer {
    name: &'static str,
    matches: Vec<(Fingerprint, ConsumerMatch)>,
    current: Mutex<BTreeMap<String, Fingerprint>>,
    log: CallLog,
    queued_failures: Mutex<HashMap<String, VecDeque<ConsumerError>>>,
    standing_failures: Mutex<HashMap<String, ConsumerError>>,
    ref_failures: Mutex<HashMap<(String, String), ConsumerError>>,
    updates: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

impl MockConsumer {
    /// A mock with no matches.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            matches: Vec::new(),
            current: Mutex::new(BTreeMap::new()),
            log: CallLog::new(),
            queued_failures: Mutex::new(HashMap::new()),
            standing_failures: Mutex::new(HashMap::new()),
            ref_failures: Mutex::new(HashMap::new()),
            updates: AtomicU64::new(0),
        }
    }

    /// `find` returns `target` for a secret with `fingerprint`. The
    /// consumer starts out holding `fingerprint`. Repeatable; matches come
    /// back in the order they were added.
    pub fn matching(mut self, fingerprint: Fingerprint, target: ConsumerMatch) -> Self {
        lock(&self.current).insert(target.consumer_ref.clone(), fingerprint.clone());
        self.matches.push((fingerprint, target));
        self
    }

    /// Write calls to a log shared with other doubles.
    pub fn log(mut self, log: CallLog) -> Self {
        self.log = log;
        self
    }

    /// The log this mock writes to.
    pub fn call_log(&self) -> CallLog {
        self.log.clone()
    }

    /// Fingerprint of what `consumer_ref` holds now.
    pub fn current(&self, consumer_ref: &str) -> Option<Fingerprint> {
        lock(&self.current).get(consumer_ref).cloned()
    }

    /// Queue an error for the next call to `method`.
    pub fn fail_next(&self, method: &str, error: ConsumerError) {
        lock(&self.queued_failures)
            .entry(method.to_owned())
            .or_default()
            .push_back(error);
    }

    /// Fail every call to `method` once its queue is empty.
    pub fn fail_always(&self, method: &str, error: ConsumerError) {
        lock(&self.standing_failures).insert(method.to_owned(), error);
    }

    /// Fail every call to `method` that targets `consumer_ref`. Checked
    /// before the per-method failures.
    pub fn fail_for(&self, method: &str, consumer_ref: &str, error: ConsumerError) {
        lock(&self.ref_failures).insert((method.to_owned(), consumer_ref.to_owned()), error);
    }

    /// Records the call, then returns the injected failure if any.
    fn enter(
        &self,
        method: &str,
        fingerprint: Fingerprint,
        consumer_ref: Option<&str>,
    ) -> Result<(), ConsumerError> {
        self.log.record(Call {
            target: self.name.to_owned(),
            method: method.to_owned(),
            mutating: is_mutating(method),
            fingerprint: Some(fingerprint),
        });
        if let Some(consumer_ref) = consumer_ref {
            let key = (method.to_owned(), consumer_ref.to_owned());
            if let Some(error) = lock(&self.ref_failures).get(&key) {
                return Err(error.clone());
            }
        }
        if let Some(error) = lock(&self.queued_failures)
            .get_mut(method)
            .and_then(VecDeque::pop_front)
        {
            return Err(error);
        }
        match lock(&self.standing_failures).get(method) {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    /// Stores the part of `credential` that `target` holds.
    fn store(&self, target: &ConsumerMatch, credential: &Credential) -> Result<(), ConsumerError> {
        if let Err(blocked) = &target.updatable {
            return Err(ConsumerError::NotUpdatable(blocked.clone()));
        }
        let fingerprint = target.value_fingerprint(credential)?;
        lock(&self.current).insert(target.consumer_ref.clone(), fingerprint);
        Ok(())
    }
}

impl fmt::Debug for MockConsumer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockConsumer")
            .field("name", &self.name)
            .field("calls", &self.log.len())
            .field("current", &*lock(&self.current))
            .finish()
    }
}

#[async_trait]
impl Consumer for MockConsumer {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn find(&self, secret: &SecretRef) -> Result<Vec<ConsumerMatch>, ConsumerError> {
        self.enter("find", secret.fingerprint.clone(), None)?;
        Ok(self
            .matches
            .iter()
            .filter(|(fp, _)| *fp == secret.fingerprint)
            .map(|(_, target)| target.clone())
            .collect())
    }

    async fn update(
        &self,
        target: &ConsumerMatch,
        new: &Credential,
    ) -> Result<UpdateReceipt, ConsumerError> {
        self.enter("update", new.fingerprint(), Some(&target.consumer_ref))?;
        self.store(target, new)?;
        let n = self.updates.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(UpdateReceipt {
            consumer_ref: target.consumer_ref.clone(),
            version: Some(format!("{}-v{n}", self.name)),
        })
    }

    async fn restore(&self, target: &ConsumerMatch, old: &Credential) -> Result<(), ConsumerError> {
        self.enter("restore", old.fingerprint(), Some(&target.consumer_ref))?;
        self.store(target, old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumer::{Holds, NotUpdatable};
    use crate::provider::mock::MockProvider;
    use crate::provider::Provider;
    use crate::secret::{SecretPair, SecretValue};

    fn token(value: &str) -> Credential {
        Credential::Token(SecretValue::from(value))
    }

    fn methods(log: &CallLog) -> Vec<(String, bool)> {
        log.calls()
            .into_iter()
            .map(|c| (c.method, c.mutating))
            .collect()
    }

    fn two_matches(old: &Credential) -> MockConsumer {
        MockConsumer::new("mock")
            .matching(
                old.fingerprint(),
                ConsumerMatch::by_name("mock:repo-a:TOKEN"),
            )
            .matching(old.fingerprint(), ConsumerMatch::by_value("mock:prod/app"))
    }

    // T1 (AC1)
    #[tokio::test]
    async fn find_returns_both_matches_non_mutating() {
        let old = token("mock_old");
        let other = token("mock_other");
        let mock = two_matches(&old).matching(other.fingerprint(), ConsumerMatch::by_value("x"));

        let found = mock.find(&SecretRef::new("mock", &old)).await.unwrap();
        let refs: Vec<&str> = found.iter().map(|m| m.consumer_ref.as_str()).collect();
        assert_eq!(refs, ["mock:repo-a:TOKEN", "mock:prod/app"]);

        let calls = mock.call_log().calls();
        assert_eq!(methods(&mock.call_log()), [("find".to_owned(), false)]);
        assert_eq!(calls[0].fingerprint, Some(old.fingerprint()));
        mock.call_log().assert_no_mutations();
    }

    // T2 (AC2)
    #[tokio::test]
    async fn not_updatable_reason_round_trips() {
        let old = token("mock_old");
        let reason = "org secret needs admin";
        let mock = MockConsumer::new("mock").matching(
            old.fingerprint(),
            ConsumerMatch::by_name("mock:org:TOKEN").not_updatable(reason),
        );

        let found = mock.find(&SecretRef::new("mock", &old)).await.unwrap();
        assert_eq!(
            found[0].updatable,
            Err(NotUpdatable {
                reason: reason.into()
            })
        );
        assert_eq!(found[0].updatable.as_ref().unwrap_err().to_string(), reason);

        let err = mock
            .update(&found[0], &token("mock_new"))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            ConsumerError::NotUpdatable(NotUpdatable {
                reason: reason.into()
            })
        );
        assert_eq!(mock.current("mock:org:TOKEN"), Some(old.fingerprint()));
    }

    // T3 (AC3)
    #[tokio::test]
    async fn update_stores_replacement_fingerprint_mutating() {
        let old = token("mock_old");
        let new = token("mock_new");
        let mock = two_matches(&old);
        let found = mock.find(&SecretRef::new("mock", &old)).await.unwrap();

        let receipt = mock.update(&found[0], &new).await.unwrap();
        assert_eq!(receipt.consumer_ref, "mock:repo-a:TOKEN");
        assert_eq!(receipt.version.as_deref(), Some("mock-v1"));
        assert_eq!(mock.current("mock:repo-a:TOKEN"), Some(new.fingerprint()));
        assert_eq!(mock.current("mock:prod/app"), Some(old.fingerprint()));

        let last = mock.call_log().calls().pop().unwrap();
        assert_eq!(last.method, "update");
        assert!(last.mutating);
        assert_eq!(last.fingerprint, Some(new.fingerprint()));
    }

    // T4 (AC4)
    #[tokio::test]
    async fn restore_puts_old_fingerprint_back() {
        let old = token("mock_old");
        let mock = two_matches(&old);
        let found = mock.find(&SecretRef::new("mock", &old)).await.unwrap();

        mock.update(&found[1], &token("mock_new")).await.unwrap();
        mock.restore(&found[1], &old).await.unwrap();
        assert_eq!(mock.current("mock:prod/app"), Some(old.fingerprint()));
        assert_eq!(
            methods(&mock.call_log()),
            [
                ("find".to_owned(), false),
                ("update".to_owned(), true),
                ("restore".to_owned(), true)
            ]
        );
    }

    // T5 (AC5)
    #[tokio::test]
    async fn fail_for_second_match_only() {
        let old = token("mock_old");
        let new = token("mock_new");
        let mock = two_matches(&old);
        let found = mock.find(&SecretRef::new("mock", &old)).await.unwrap();
        mock.call_log().clear();
        let injected = ConsumerError::Permanent("403 forbidden".into());
        mock.fail_for("update", "mock:prod/app", injected.clone());

        assert!(mock.update(&found[0], &new).await.is_ok());
        assert_eq!(mock.update(&found[1], &new).await.unwrap_err(), injected);
        assert_eq!(mock.call_log().len(), 2);
        assert_eq!(mock.call_log().mutating().len(), 2);
        assert_eq!(mock.current("mock:repo-a:TOKEN"), Some(new.fingerprint()));
        assert_eq!(mock.current("mock:prod/app"), Some(old.fingerprint()));
    }

    #[tokio::test]
    async fn queued_then_standing_failures() {
        let old = token("mock_old");
        let mock = two_matches(&old);
        let secret = SecretRef::new("mock", &old);
        mock.fail_next("find", ConsumerError::RateLimited { retry_after: None });
        mock.fail_always("find", ConsumerError::Transient("503".into()));

        assert_eq!(
            mock.find(&secret).await.unwrap_err(),
            ConsumerError::RateLimited { retry_after: None }
        );
        for _ in 0..2 {
            assert_eq!(
                mock.find(&secret).await.unwrap_err(),
                ConsumerError::Transient("503".into())
            );
        }
        assert_eq!(mock.call_log().len(), 3);
    }

    #[tokio::test]
    async fn key_id_match_stores_key_id_fingerprint() {
        let old = Credential::KeyPair(SecretPair::new("AKIAOLD", SecretValue::from("mock_old")));
        let new = Credential::KeyPair(SecretPair::new("AKIANEW", SecretValue::from("mock_new")));
        let id_match = ConsumerMatch::by_name("gha:repo:AWS_ACCESS_KEY_ID").holding(Holds::KeyId);
        let mock = MockConsumer::new("gha").matching(old.fingerprint(), id_match.clone());

        mock.update(&id_match, &new).await.unwrap();
        assert_eq!(
            mock.current("gha:repo:AWS_ACCESS_KEY_ID"),
            Some(Fingerprint::of(b"AKIANEW"))
        );
        mock.restore(&id_match, &old).await.unwrap();
        assert_eq!(
            mock.current("gha:repo:AWS_ACCESS_KEY_ID"),
            Some(Fingerprint::of(b"AKIAOLD"))
        );

        let err = mock
            .update(&id_match, &token("mock_tok"))
            .await
            .unwrap_err();
        assert!(matches!(err, ConsumerError::Unsupported(_)));
    }

    #[tokio::test]
    async fn shared_log_with_mock_provider() {
        let log = CallLog::new();
        let old = token("mock_old");
        let provider = MockProvider::new("mock").log(log.clone());
        let consumer = two_matches(&old).log(log.clone());

        provider.check_valid(&old).await.unwrap();
        consumer.find(&SecretRef::new("mock", &old)).await.unwrap();
        log.assert_no_mutations();

        let found = consumer.find(&SecretRef::new("mock", &old)).await.unwrap();
        consumer
            .update(&found[0], &token("mock_new"))
            .await
            .unwrap();
        let targets: Vec<(String, String)> = log
            .mutating()
            .into_iter()
            .map(|c| (c.target, c.method))
            .collect();
        assert_eq!(targets, [("mock".to_owned(), "update".to_owned())]);
        assert_eq!(log.len(), 4);
    }

    #[test]
    fn debug_shows_fingerprints_only() {
        let old = token("mock_old_value");
        let mock = two_matches(&old);
        let rendered = format!("{mock:?}");
        assert!(rendered.contains(old.fingerprint().as_str()));
        assert!(!rendered.contains("mock_old_value"));
    }
}
