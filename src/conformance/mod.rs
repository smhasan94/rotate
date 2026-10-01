//! Shared conformance suite for provider and consumer plugins (SHA-249,
//! NFR15).
//!
//! Every real plugin runs [`provider_suite`] or [`consumer_suite`] from its
//! own integration test, wired to a wiremock server, so the contract in
//! [`crate::provider::Provider`] and [`crate::consumer::Consumer`] is
//! enforced in one place. The suite calls the factory once per check, so
//! each check gets a fresh plugin and a fresh test server and no check sees
//! state another one left behind (for example a revoked credential).
//!
//! The suite never panics on a plugin failure. It returns a [`SuiteReport`]
//! naming each check and its outcome; call [`SuiteReport::assert_ok`] to
//! turn it into a test failure. Report text never contains a secret value:
//! every error a plugin returns is searched for the values the suite knows
//! about (that is the `errors_redacted` check) and scrubbed before it goes
//! into a detail string.
//!
//! ```ignore
//! use rotate::conformance::{provider_suite, ProviderFixture};
//!
//! #[tokio::test]
//! async fn conformance() {
//!     provider_suite(|| async {
//!         let server = common::CallRecorder::start().await;
//!         // mount answers for `live` and `unknown` ...
//!         ProviderFixture {
//!             provider: Arc::new(MyProvider::new(server.uri())),
//!             live, identity, unknown,
//!             probe: Box::new(RecorderProbe(server)),
//!         }
//!     })
//!     .await
//!     .assert_ok();
//! }
//! ```

mod consumer;
pub mod mock;
mod provider;

use std::fmt;

use async_trait::async_trait;

use crate::calls::CallLog;
use crate::provider::Credential;
use crate::secret::{SecretPair, SecretValue};

pub use consumer::{consumer_suite, ConsumerFixture};
pub use provider::{provider_suite, ProviderFixture};

/// Reports the state-changing calls the plugin under test has made.
///
/// [`CallLog`] implements it for the mocks. A plugin test implements it for
/// its wiremock recorder by returning a label (method and path) for every
/// received request it classifies as mutating.
#[async_trait]
pub trait MutationProbe: Send + Sync {
    /// Labels of every state-changing call seen so far, in order. Labels
    /// must never contain a value.
    async fn mutations(&self) -> Vec<String>;
}

#[async_trait]
impl MutationProbe for CallLog {
    async fn mutations(&self) -> Vec<String> {
        self.mutating()
            .into_iter()
            .map(|c| format!("{}.{}", c.target, c.method))
            .collect()
    }
}

/// A credential of the same shape as `like` holding a value the suite made
/// up. The suite feeds it to every method and fails `errors_redacted` when
/// any error text echoes it.
pub fn canary(like: &Credential) -> Credential {
    let value = SecretValue::from("rotate-conformance-canary-5e0c1d");
    match like {
        Credential::Token(_) => Credential::Token(value),
        Credential::KeyPair(_) => {
            Credential::KeyPair(SecretPair::new("CONFORMANCECANARYKEY", value))
        }
    }
}

/// How one check ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The plugin met the contract.
    Passed,
    /// The plugin broke the contract; the detail says how. Never holds a
    /// value.
    Failed(String),
    /// The check does not apply to this plugin; the detail says why.
    Skipped(String),
}

/// One named check and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    /// Stable check name, for example `idempotent_revoke`.
    pub name: &'static str,
    /// How it ended.
    pub outcome: Outcome,
}

/// Every check the suite ran against one plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteReport {
    /// `provider` or `consumer`.
    pub suite: &'static str,
    /// The plugin's `name()`.
    pub plugin: &'static str,
    /// Checks in the order they ran.
    pub checks: Vec<CheckResult>,
}

impl SuiteReport {
    fn new(suite: &'static str) -> Self {
        Self {
            suite,
            plugin: "",
            checks: Vec::new(),
        }
    }

    fn push(&mut self, name: &'static str, outcome: Outcome) {
        self.checks.push(CheckResult { name, outcome });
    }

    /// True when no check failed.
    pub fn is_ok(&self) -> bool {
        self.failed().is_empty()
    }

    /// Names of the failed checks, in order.
    pub fn failed(&self) -> Vec<&'static str> {
        self.with(|o| matches!(o, Outcome::Failed(_)))
    }

    /// Names of the skipped checks, in order.
    pub fn skipped(&self) -> Vec<&'static str> {
        self.with(|o| matches!(o, Outcome::Skipped(_)))
    }

    /// The outcome of the named check, if it ran.
    pub fn outcome(&self, name: &str) -> Option<&Outcome> {
        self.checks
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.outcome)
    }

    /// Panics with the report when any check failed.
    pub fn assert_ok(&self) {
        assert!(self.is_ok(), "{self}");
    }

    fn with(&self, pred: impl Fn(&Outcome) -> bool) -> Vec<&'static str> {
        self.checks
            .iter()
            .filter(|c| pred(&c.outcome))
            .map(|c| c.name)
            .collect()
    }
}

impl fmt::Display for SuiteReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let failed = self.failed().len();
        let skipped = self.skipped().len();
        write!(
            f,
            "{} conformance for {}: {} passed, {failed} failed, {skipped} skipped",
            self.suite,
            self.plugin,
            self.checks.len() - failed - skipped,
        )?;
        for check in &self.checks {
            match &check.outcome {
                Outcome::Passed => {}
                Outcome::Failed(detail) => write!(f, "\n  FAILED {}: {detail}", check.name)?,
                Outcome::Skipped(why) => write!(f, "\n  skipped {}: {why}", check.name)?,
            }
        }
        Ok(())
    }
}

/// Every secret the suite has handled, and the methods whose errors echoed
/// one of them.
#[derive(Default)]
struct Recorder {
    secrets: Vec<SecretValue>,
    leaks: Vec<&'static str>,
}

impl Recorder {
    /// Remember a credential's secret so errors can be searched for it.
    fn know(&mut self, credential: &Credential) {
        let secret = credential.secret();
        if !secret.is_empty() && !self.secrets.contains(secret) {
            self.secrets.push(secret.clone());
        }
    }

    /// True when `text` contains any known secret.
    fn leaks(&self, text: &str) -> bool {
        self.secrets.iter().any(|s| {
            s.expose_secret(|bytes| text.as_bytes().windows(bytes.len()).any(|w| w == bytes))
        })
    }

    /// `text` with every known secret replaced.
    fn scrub(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for secret in &self.secrets {
            // Non-UTF-8 secrets cannot appear in a `str` anyway.
            let _ = secret.expose_secret_str(|s| {
                if out.contains(s) {
                    out = out.replace(s, "[secret]");
                }
            });
        }
        out
    }

    /// Note an error `method` returned and give back its scrubbed text.
    fn error<E: fmt::Display + fmt::Debug>(&mut self, method: &'static str, error: &E) -> String {
        let display = error.to_string();
        if (self.leaks(&display) || self.leaks(&format!("{error:?}")))
            && !self.leaks.contains(&method)
        {
            self.leaks.push(method);
        }
        self.scrub(&display)
    }

    /// The `errors_redacted` outcome.
    fn redaction_outcome(&self) -> Outcome {
        if self.leaks.is_empty() {
            Outcome::Passed
        } else {
            Outcome::Failed(format!(
                "error text from {} contains a secret value",
                self.leaks.join(", ")
            ))
        }
    }
}

/// `Passed` when there are no problems, else `Failed` listing them.
fn failed_if_any(problems: Vec<String>) -> Outcome {
    if problems.is_empty() {
        Outcome::Passed
    } else {
        Outcome::Failed(problems.join("; "))
    }
}

/// The calls a closure made that the probe classed as mutating.
async fn mutations_during<Fut: std::future::Future<Output = ()>>(
    probe: &dyn MutationProbe,
    call: Fut,
) -> Vec<String> {
    let before = probe.mutations().await.len();
    call.await;
    let after = probe.mutations().await;
    after.into_iter().skip(before).collect()
}

#[cfg(test)]
mod tests;
