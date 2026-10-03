//! The provider and consumer registries the CLI runs with.
//!
//! Real plugins register in builds without `test-providers`: the AWS
//! provider (SHA-251), the GitHub token provider (SHA-260), the npm token
//! provider (SHA-261), the OpenAI API key provider (SHA-262), the AWS Secrets
//! Manager consumer (SHA-252) and the GitHub Actions secrets consumer
//! (SHA-253).
//! Constructing one makes no call and loads no credentials; that happens on
//! first use. The `test-providers` feature instead registers
//! `MockProvider`s under the four real names so integration tests can drive
//! the CLI end to end, and lets a test describe a scenario in a JSON file
//! named by `ROTATE_TEST_SCENARIO` (see [`scenario`]). A scenario with
//! `"real_plugins": true` gets the real plugins instead, registered exactly
//! as a release build registers them, so end-to-end tests can drive them
//! against a local server (SHA-264). Release builds never enable the
//! feature, and nothing in this file reads the variable without it.

use rotate::apply::Prompt;
use rotate::config::{AwsConfig, ConsumersConfig, GithubConfig, ProvidersConfig};
use rotate::consumer::ConsumerRegistry;
use rotate::provider::ProviderRegistry;

/// Every provider this build knows, with default settings: enough to list
/// the provider names. Callers with a loaded config use [`registry_with`].
pub fn registry() -> ProviderRegistry {
    registry_with(&ProvidersConfig::default())
}

/// Every provider this build knows, configured from `rotate.yaml`
/// (`providers.aws.region`, `providers.github.api_url`,
/// `providers.npm.registry`). Building the
/// registry makes no network call and loads no credentials.
pub fn registry_with(config: &ProvidersConfig) -> ProviderRegistry {
    let mut registry = ProviderRegistry::new();
    #[cfg(feature = "test-providers")]
    if !scenario::real_plugins() {
        scenario::register_providers(&mut registry);
        return registry;
    }
    registry.register(std::sync::Arc::new(aws_provider(&config.aws)));
    registry.register(std::sync::Arc::new(github_provider(&config.github)));
    registry.register(std::sync::Arc::new(npm_provider(&config.npm)));
    registry.register(std::sync::Arc::new(openai_provider(&config.openai)));
    registry
}

/// The GitHub token provider (SHA-260) for the configured API URL.
fn github_provider(config: &GithubConfig) -> rotate::provider::github::GithubProvider {
    rotate::provider::github::GithubProvider::new(config.api_url.as_str())
}

/// The OpenAI API key provider (SHA-262) for the configured API URL, with
/// the Admin API key read from `providers.openai.admin_key_env` when a call
/// needs it.
fn openai_provider(
    config: &rotate::config::OpenAiConfig,
) -> rotate::provider::openai::OpenAiProvider {
    rotate::provider::openai::OpenAiProvider::new(
        config.api_url.as_str(),
        rotate::provider::openai::AdminKey::Env(config.admin_key_env.clone()),
    )
}

/// The npm token provider (SHA-261) for the configured registry. The
/// operator token is read from the environment on first use.
fn npm_provider(config: &rotate::config::NpmConfig) -> rotate::provider::npm::NpmProvider {
    rotate::provider::npm::NpmProvider::new(config.registry.as_str())
}

/// The AWS provider with the configured region and endpoint, if any.
fn aws_provider(config: &AwsConfig) -> rotate::provider::aws::AwsProvider {
    let mut provider = rotate::provider::aws::AwsProvider::new();
    if let Some(region) = &config.region {
        provider = provider.with_region(region.clone());
    }
    if let Some(url) = &config.endpoint_url {
        provider = provider.with_endpoint_url(url.as_str());
    }
    provider
}

/// The Secrets Manager consumer (SHA-252) with the configured region and
/// endpoint, if any.
fn secrets_manager(
    config: &ConsumersConfig,
    aws: &AwsConfig,
) -> rotate::consumer::aws_secrets_manager::SecretsManagerConsumer {
    let consumer = rotate::consumer::aws_secrets_manager::SecretsManagerConsumer::new(
        config.aws_secrets_manager.clone(),
        aws.region.clone(),
    );
    match &aws.endpoint_url {
        Some(url) => consumer.with_endpoint_url(url.as_str()),
        None => consumer,
    }
}

/// Every consumer this build knows, configured from `rotate.yaml`. With
/// empty consumer sections neither real consumer makes a call.
/// Building the registry makes no network call and loads no credentials.
///
/// As with providers, real consumers and the scenario's mocks never share a
/// registry: both use the real names, and the first registration of a name
/// would win.
pub fn consumers_with(
    config: &ConsumersConfig,
    github: &GithubConfig,
    aws: &AwsConfig,
) -> ConsumerRegistry {
    let mut registry = ConsumerRegistry::new();
    #[cfg(feature = "test-providers")]
    if !scenario::real_plugins() {
        scenario::register_consumers(&mut registry);
        return registry;
    }
    registry.register(std::sync::Arc::new(
        rotate::consumer::github_actions::GithubActionsConsumer::from_config(config, github),
    ));
    registry.register(std::sync::Arc::new(secrets_manager(config, aws)));
    registry
}

/// The confirmation prompt a test scenario scripts, if any. Without
/// `test-providers` always `None`: apply reads the terminal.
pub fn prompt() -> Option<Box<dyn Prompt>> {
    #[cfg(feature = "test-providers")]
    return scenario::prompt();
    #[cfg(not(feature = "test-providers"))]
    None
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
/// For apply (SHA-254): `providers.<name>.fail` and `consumers[].fail` map a
/// method name to an error text that every call to it returns; `prompt` is
/// `{"answers": ["rot-..."]}`, `"panic"` (fails the test if apply asks) or
/// `"no_tty"`; `consumer_state` is a path the binary writes on exit with
/// what every mock consumer holds, `{"<name>": {"<ref>": "sha256:..."}}`.
///
/// For manual mode (SHA-257): prompt answers are also the pasted secrets,
/// in order after any confirmation answers; `prompt` may instead be
/// `{"tty": "<device>"}` to read a pseudo-terminal with the real hidden
/// prompt; `providers.<name>.foreign` lists fingerprints that `verify`
/// reports as belonging to another identity.
///
/// For end-to-end tests of the real plugins (SHA-264): `real_plugins:
/// true` registers them instead of mocks; only `prompt` applies then.
///
/// For rollback (SHA-259): `providers.<name>.restore` is `"unsupported"` to
/// make `restore` return `Unsupported`; each call-log line also has
/// `reference`, the consumer ref, restore handle or replacement ref the
/// call targeted (null when none).
///
/// Every mock shares one `CallLog`. [`write_call_log`] writes it as JSON
/// lines (`target`, `method`, `mutating`, `fingerprint`), so a CLI test can
/// prove a run made no state-changing call. The file holds fingerprints
/// only. A malformed scenario panics: it is a broken test, not user input.
#[cfg(feature = "test-providers")]
mod scenario {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, OnceLock};

    use serde::Deserialize;

    use rotate::apply::{Prompt, PromptError, ScriptedPrompt, Terminal, TtyPrompt};
    use rotate::calls::CallLog;
    use rotate::consumer::mock::MockConsumer;
    use rotate::consumer::{ConsumerError, ConsumerMatch, ConsumerRegistry, Holds};
    use rotate::provider::mock::MockProvider;
    use rotate::provider::{
        Identity, ProviderError, ProviderRegistry, ReplacementMode, RestoreOutcome, Validity,
    };
    use rotate::secret::{Fingerprint, SecretValue};

    const ENV: &str = "ROTATE_TEST_SCENARIO";

    #[derive(Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Scenario {
        #[serde(default)]
        providers: BTreeMap<String, ProviderSetup>,
        #[serde(default)]
        consumers: Vec<ConsumerSetup>,
        call_log: Option<PathBuf>,
        consumer_state: Option<PathBuf>,
        prompt: Option<serde_json::Value>,
        /// Register the real plugins, as a release build does, instead of
        /// mocks (SHA-264). Only `prompt` applies then.
        #[serde(default)]
        real_plugins: bool,
    }

    #[derive(Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProviderSetup {
        validity: Option<String>,
        mode: Option<String>,
        #[serde(default)]
        fail: BTreeMap<String, String>,
        #[serde(default)]
        foreign: Vec<Fingerprint>,
        restore: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConsumerSetup {
        name: String,
        #[serde(default)]
        matches: Vec<MatchSetup>,
        fail_find: Option<String>,
        #[serde(default)]
        fail: BTreeMap<String, String>,
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
        consumers: Mutex<Vec<Arc<MockConsumer>>>,
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
                consumers: Mutex::new(Vec::new()),
            }
        })
    }

    /// True when the scenario asks for the real plugins (SHA-264).
    pub fn real_plugins() -> bool {
        loaded().scenario.real_plugins
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
                mock = match setup.restore.as_deref() {
                    None | Some("restored") => mock,
                    Some("unsupported") => mock.restore_outcome(RestoreOutcome::Unsupported),
                    Some(other) => panic!("{ENV}: unknown restore outcome {other:?}"),
                };
                for fingerprint in &setup.foreign {
                    mock = mock.owner(fingerprint.clone(), Identity("someone-else".into()));
                }
                for (method, error) in &setup.fail {
                    mock.fail_always(method, ProviderError::Permanent(error.clone()));
                }
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
            for (method, error) in &setup.fail {
                mock.fail_always(method, ConsumerError::Permanent(error.clone()));
            }
            let mock = Arc::new(mock);
            loaded
                .consumers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(Arc::clone(&mock));
            registry.register(mock);
        }
    }

    /// Fails the test if apply asks for confirmation.
    struct PanicPrompt;

    impl Prompt for PanicPrompt {
        fn read_line(&mut self) -> Result<String, PromptError> {
            panic!("{ENV}: the scenario says apply must not prompt");
        }

        fn read_secret(
            &mut self,
            _question: &str,
            _term: &mut dyn Terminal,
        ) -> Result<SecretValue, PromptError> {
            panic!("{ENV}: the scenario says apply must not prompt for a secret");
        }
    }

    /// Stands in for a process with no controlling terminal.
    struct NoTty;

    impl Prompt for NoTty {
        fn read_line(&mut self) -> Result<String, PromptError> {
            Err(PromptError::NoTerminal)
        }

        fn read_secret(
            &mut self,
            _question: &str,
            _term: &mut dyn Terminal,
        ) -> Result<SecretValue, PromptError> {
            Err(PromptError::NoTerminalForSecret)
        }
    }

    pub fn prompt() -> Option<Box<dyn Prompt>> {
        let setup = loaded().scenario.prompt.as_ref()?;
        Some(match setup {
            serde_json::Value::String(mode) if mode == "panic" => Box::new(PanicPrompt),
            serde_json::Value::String(mode) if mode == "no_tty" => Box::new(NoTty),
            serde_json::Value::Object(map) if map.contains_key("tty") => {
                let path = map
                    .get("tty")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_else(|| panic!("{ENV}: prompt \"tty\" needs a path"));
                Box::new(TtyPrompt::with_path(path))
            }
            serde_json::Value::Object(map) => {
                let answers: Vec<String> = map
                    .get("answers")
                    .and_then(serde_json::Value::as_array)
                    .unwrap_or_else(|| panic!("{ENV}: prompt needs \"answers\""))
                    .iter()
                    .map(|a| a.as_str().unwrap_or_default().to_owned())
                    .collect();
                Box::new(ScriptedPrompt::new(answers))
            }
            other => panic!("{ENV}: unknown prompt {other}"),
        })
    }

    pub fn write_call_log() {
        let loaded = loaded();
        if let Some(path) = &loaded.scenario.consumer_state {
            let mut held = serde_json::Map::new();
            let consumers = loaded.consumers.lock().unwrap_or_else(|p| p.into_inner());
            for (mock, setup) in consumers.iter().zip(&loaded.scenario.consumers) {
                let refs: serde_json::Map<String, serde_json::Value> = setup
                    .matches
                    .iter()
                    .filter_map(|m| {
                        mock.current(&m.consumer_ref)
                            .map(|fp| (m.consumer_ref.clone(), serde_json::json!(fp.to_string())))
                    })
                    .collect();
                held.insert(setup.name.clone(), serde_json::Value::Object(refs));
            }
            std::fs::write(path, serde_json::Value::Object(held).to_string())
                .unwrap_or_else(|err| panic!("{ENV}: cannot write the consumer state: {err}"));
        }
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
                "reference": call.reference,
            });
            text.push_str(&line.to_string());
            text.push('\n');
        }
        std::fs::write(path, text)
            .unwrap_or_else(|err| panic!("{ENV}: cannot write the call log: {err}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_region_comes_from_config() {
        let mut config = AwsConfig::default();
        let debug = format!("{:?}", aws_provider(&config));
        assert!(debug.contains("region: None"), "{debug}");
        config.region = Some("eu-west-1".into());
        let debug = format!("{:?}", aws_provider(&config));
        assert!(debug.contains("region: Some(\"eu-west-1\")"), "{debug}");
    }

    #[test]
    fn aws_endpoint_url_comes_from_config() {
        let mut aws = AwsConfig::default();
        let consumers = ConsumersConfig::default();
        assert!(format!("{:?}", aws_provider(&aws)).contains("endpoint_url: None"));
        assert!(format!("{:?}", secrets_manager(&consumers, &aws)).contains("endpoint_url: None"));
        aws = serde_norway::from_str("endpoint_url: http://127.0.0.1:4566\n").unwrap();
        let shown = "endpoint_url: Some(\"http://127.0.0.1:4566\")";
        let debug = format!("{:?}", aws_provider(&aws));
        assert!(debug.contains(shown), "{debug}");
        let debug = format!("{:?}", secrets_manager(&consumers, &aws));
        assert!(debug.contains(shown), "{debug}");
    }

    #[test]
    fn github_api_url_comes_from_config() {
        use rotate::provider::Provider as _;
        let mut config = GithubConfig::default();
        let provider = github_provider(&config);
        assert_eq!(provider.name(), "github");
        assert_eq!(provider.web_url(), "https://github.com");
        config = serde_norway::from_str("api_url: https://ghe.example.com/api/v3\n").unwrap();
        let debug = format!("{:?}", github_provider(&config));
        assert!(
            debug.contains("base: \"https://ghe.example.com/api/v3\""),
            "{debug}"
        );
    }

    #[test]
    fn registry_with_registers_github() {
        assert!(registry_with(&ProvidersConfig::default())
            .get("github")
            .is_some());
    }

    #[test]
    fn openai_settings_come_from_config() {
        use rotate::provider::Provider as _;
        let mut config = rotate::config::OpenAiConfig::default();
        let provider = openai_provider(&config);
        assert_eq!(provider.name(), "openai");
        assert_eq!(provider.base_url(), "https://api.openai.com");
        config = serde_norway::from_str(
            "api_url: https://openai.example.com/\nadmin_key_env: ROTATE_TEST_NO_SUCH_ADMIN_KEY\n",
        )
        .unwrap();
        let provider = openai_provider(&config);
        assert_eq!(provider.base_url(), "https://openai.example.com");
        let debug = format!("{provider:?}");
        assert!(debug.contains("ROTATE_TEST_NO_SUCH_ADMIN_KEY"), "{debug}");
        assert!(!provider.has_admin_key());
    }

    #[test]
    fn registry_with_registers_openai() {
        assert!(registry_with(&ProvidersConfig::default())
            .get("openai")
            .is_some());
    }

    #[test]
    fn npm_registry_comes_from_config() {
        use rotate::config::NpmConfig;
        use rotate::provider::Provider as _;
        let provider = npm_provider(&NpmConfig::default());
        assert_eq!(provider.name(), "npm");
        assert_eq!(provider.registry_url(), "https://registry.npmjs.org");
        assert_eq!(provider.web_url(), Some("https://www.npmjs.com"));
        let config: NpmConfig =
            serde_norway::from_str("registry: http://127.0.0.1:4873/\n").unwrap();
        let provider = npm_provider(&config);
        assert_eq!(provider.registry_url(), "http://127.0.0.1:4873");
        assert_eq!(provider.web_url(), None);
        // Building it read no operator token.
        assert!(format!("{provider:?}").contains("[not loaded]"));
    }

    #[test]
    fn registry_with_registers_npm() {
        assert!(registry_with(&ProvidersConfig::default())
            .get("npm")
            .is_some());
    }

    #[test]
    fn registry_with_registers_aws() {
        let mut config = ProvidersConfig::default();
        config.aws.region = Some("eu-west-1".into());
        assert!(registry_with(&config).get("aws").is_some());
        assert!(registry().get("aws").is_some());
    }
}
