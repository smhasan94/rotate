//! The provider and consumer registries the CLI runs with.
//!
//! Real consumers: GitHub Actions secrets (SHA-253). Real providers and the
//! Secrets Manager consumer follow (SHA-251, SHA-252, SHA-260 to SHA-262). The `test-providers` feature registers
//! `MockProvider`s under the four real names so integration tests can drive
//! the CLI end to end, and lets a test describe a scenario in a JSON file
//! named by `ROTATE_TEST_SCENARIO` (see [`scenario`]). Release builds never
//! enable it, and nothing in this file reads the variable without it.

use std::sync::Arc;

use rotate::config::{ConsumersConfig, GithubConfig};
use rotate::consumer::github_actions::GithubActionsConsumer;
use rotate::consumer::ConsumerRegistry;
use rotate::provider::ProviderRegistry;

/// Every provider this build knows.
pub fn registry() -> ProviderRegistry {
    #[allow(unused_mut)]
    let mut registry = ProviderRegistry::new();
    #[cfg(feature = "test-providers")]
    scenario::register_providers(&mut registry);
    registry
}

/// Every consumer this build knows, with default settings: no Actions
/// targets, so the GitHub Actions consumer makes no call. Callers with a
/// loaded config use [`consumers_with`].
pub fn consumers() -> ConsumerRegistry {
    consumers_with(&ConsumersConfig::default(), &GithubConfig::default())
}

/// Every consumer this build knows, configured from `rotate.yaml`.
/// Building the registry makes no network call.
pub fn consumers_with(config: &ConsumersConfig, github: &GithubConfig) -> ConsumerRegistry {
    let mut registry = ConsumerRegistry::new();
    registry.register(Arc::new(GithubActionsConsumer::from_config(config, github)));
    #[cfg(feature = "test-providers")]
    scenario::register_consumers(&mut registry);
    registry
}

/// Called once before exit. With `test-providers`, writes the shared call
/// log to the scenario's `call_log` path; otherwise does nothing.
pub fn finish() {
    #[cfg(feature = "test-providers")]
    scenario::write_call_log();
}

/// Test-only scenario: mock behaviour chosen by a JSON file.
///
/// ```json
/// {
///   "providers": { "npm": { "validity": "invalid", "mode": "manual" } },
///   "consumers": [
///     { "name": "github-actions",
///       "fail_find": "403 denied",
///       "matches": [ { "fingerprint": "sha256:...", "ref": "gha:org/repo:NPM_TOKEN",
///                      "method": "by_name", "holds": "secret",
///                      "not_updatable": "org secret needs admin" } ] }
///   ],
///   "call_log": "/tmp/calls.jsonl"
/// }
/// ```
///
/// Every mock shares one `CallLog`. [`write_call_log`] writes it as JSON
/// lines (`target`, `method`, `mutating`, `fingerprint`), so a CLI test can
/// prove a run made no state-changing call. The file holds fingerprints
/// only. A malformed scenario panics: it is a broken test, not user input.
#[cfg(feature = "test-providers")]
mod scenario {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    use serde::Deserialize;

    use rotate::calls::CallLog;
    use rotate::consumer::mock::MockConsumer;
    use rotate::consumer::{ConsumerError, ConsumerMatch, ConsumerRegistry, Holds};
    use rotate::provider::mock::MockProvider;
    use rotate::provider::{ProviderRegistry, ReplacementMode, Validity};
    use rotate::secret::Fingerprint;

    const ENV: &str = "ROTATE_TEST_SCENARIO";

    #[derive(Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Scenario {
        #[serde(default)]
        providers: BTreeMap<String, ProviderSetup>,
        #[serde(default)]
        consumers: Vec<ConsumerSetup>,
        call_log: Option<PathBuf>,
    }

    #[derive(Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProviderSetup {
        validity: Option<String>,
        mode: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConsumerSetup {
        name: String,
        #[serde(default)]
        matches: Vec<MatchSetup>,
        fail_find: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MatchSetup {
        fingerprint: Fingerprint,
        #[serde(rename = "ref")]
        consumer_ref: String,
        method: Option<String>,
        holds: Option<String>,
        not_updatable: Option<String>,
    }

    struct Loaded {
        scenario: Scenario,
        log: CallLog,
    }

    fn loaded() -> &'static Loaded {
        static LOADED: OnceLock<Loaded> = OnceLock::new();
        LOADED.get_or_init(|| {
            let scenario = match std::env::var_os(ENV) {
                Some(path) => {
                    let text = std::fs::read_to_string(&path)
                        .unwrap_or_else(|err| panic!("{ENV}: cannot read the scenario: {err}"));
                    serde_json::from_str(&text)
                        .unwrap_or_else(|err| panic!("{ENV}: invalid scenario: {err}"))
                }
                None => Scenario::default(),
            };
            Loaded {
                scenario,
                log: CallLog::new(),
            }
        })
    }

    pub fn register_providers(registry: &mut ProviderRegistry) {
        let loaded = loaded();
        for (name, prefix) in [
            ("aws", "mock_aws_"),
            ("github", "ghp_"),
            ("npm", "npm_"),
            ("openai", "sk-"),
        ] {
            let mut mock = MockProvider::new(name)
                .identify_prefix(prefix)
                .log(loaded.log.clone());
            if let Some(setup) = loaded.scenario.providers.get(name) {
                mock = match setup.validity.as_deref() {
                    None | Some("valid") => mock,
                    Some("invalid") => mock.validity(Validity::Invalid),
                    Some("unknown") => mock.validity(Validity::Unknown {
                        reason: "scenario: check failed".into(),
                    }),
                    Some(other) => panic!("{ENV}: unknown validity {other:?}"),
                };
                mock = match setup.mode.as_deref() {
                    None | Some("automatic") => mock,
                    Some("manual") => mock.mode(ReplacementMode::Manual),
                    Some(other) => panic!("{ENV}: unknown mode {other:?}"),
                };
            }
            registry.register(Arc::new(mock));
        }
        for name in loaded.scenario.providers.keys() {
            assert!(
                registry.get(name).is_some(),
                "{ENV}: unknown provider {name:?}"
            );
        }
    }

    pub fn register_consumers(registry: &mut ConsumerRegistry) {
        let loaded = loaded();
        for setup in &loaded.scenario.consumers {
            // Consumer names are `&'static str`; a test binary runs once.
            let name: &'static str = Box::leak(setup.name.clone().into_boxed_str());
            let mut mock = MockConsumer::new(name).log(loaded.log.clone());
            for m in &setup.matches {
                let mut found = match m.method.as_deref() {
                    None | Some("by_value") => ConsumerMatch::by_value(&m.consumer_ref),
                    Some("by_name") => ConsumerMatch::by_name(&m.consumer_ref),
                    Some(other) => panic!("{ENV}: unknown match method {other:?}"),
                };
                found = found.holding(match m.holds.as_deref() {
                    None | Some("secret") => Holds::Secret,
                    Some("key_id") => Holds::KeyId,
                    Some("key_pair") => Holds::KeyPair,
                    Some(other) => panic!("{ENV}: unknown holds {other:?}"),
                });
                if let Some(reason) = &m.not_updatable {
                    found = found.not_updatable(reason);
                }
                mock = mock.matching(m.fingerprint.clone(), found);
            }
            if let Some(error) = &setup.fail_find {
                mock.fail_always("find", ConsumerError::Permanent(error.clone()));
            }
            registry.register(Arc::new(mock));
        }
    }

    pub fn write_call_log() {
        let loaded = loaded();
        let Some(path) = &loaded.scenario.call_log else {
            return;
        };
        let mut text = String::new();
        for call in loaded.log.calls() {
            let line = serde_json::json!({
                "target": call.target,
                "method": call.method,
                "mutating": call.mutating,
                "fingerprint": call.fingerprint.map(String::from),
            });
            text.push_str(&line.to_string());
            text.push('\n');
        }
        std::fs::write(path, text)
            .unwrap_or_else(|err| panic!("{ENV}: cannot write the call log: {err}"));
    }
}
