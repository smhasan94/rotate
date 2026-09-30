//! Shared recorder for calls made against provider and consumer test doubles
//! (SHA-221). Tests prove a dry run made no state-changing call by reading
//! the log and asserting nothing in it is flagged mutating.

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::secret::Fingerprint;

/// One recorded call. Holds a fingerprint, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Name of the provider or consumer that received the call.
    pub target: String,
    /// Method name, for example `check_valid` or `update`.
    pub method: String,
    /// True when the call would change state on a real service.
    pub mutating: bool,
    /// Fingerprint of the credential the call operated on, when any.
    pub fingerprint: Option<Fingerprint>,
}

/// Append-only log of [`Call`]s, cheaply cloneable and shared between the
/// doubles that write to it and the test that reads it.
#[derive(Clone, Default)]
pub struct CallLog(Arc<Mutex<Vec<Call>>>);

impl CallLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one call.
    pub fn record(&self, call: Call) {
        self.lock().push(call);
    }

    /// Snapshot of every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.lock().clone()
    }

    /// Number of calls so far.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// True when nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// The calls flagged as mutating.
    pub fn mutating(&self) -> Vec<Call> {
        self.lock().iter().filter(|c| c.mutating).cloned().collect()
    }

    /// Panics when any recorded call is mutating, naming each by target and
    /// method.
    pub fn assert_no_mutations(&self) {
        let mutating = self.mutating();
        assert!(
            mutating.is_empty(),
            "expected no state-changing calls, found {}: {}",
            mutating.len(),
            mutating
                .iter()
                .map(|c| format!("{}.{}", c.target, c.method))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// Forgets every call.
    pub fn clear(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Call>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for CallLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.lock().iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(method: &str, mutating: bool) -> Call {
        Call {
            target: "mock".into(),
            method: method.into(),
            mutating,
            fingerprint: None,
        }
    }

    #[test]
    fn call_log_is_shared_between_clones() {
        let log = CallLog::new();
        let writer = log.clone();
        writer.record(call("check_valid", false));
        assert_eq!(log.len(), 1);
        assert_eq!(log.calls()[0].method, "check_valid");
        log.clear();
        assert!(writer.is_empty());
    }

    #[test]
    fn call_log_assert_no_mutations_lists_calls() {
        let log = CallLog::new();
        log.record(call("check_valid", false));
        log.assert_no_mutations();

        log.record(call("revoke", true));
        let err = std::panic::catch_unwind(|| log.assert_no_mutations()).unwrap_err();
        let message = err.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(message.contains("mock.revoke"), "{message}");
        assert!(!message.contains("check_valid"));
        assert_eq!(log.mutating().len(), 1);
    }
}
