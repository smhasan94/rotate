//! `rotate.yaml`: schema, validation and resolution (SHA-214).
//!
//! Every setting resolves as command-line flag, then environment variable,
//! then the config file, then the default. The file is optional: without
//! one, every default applies. Unknown keys and malformed values are errors
//! that name the field and the line.
//!
//! The file holds no secrets. Provider credentials stay in the environment;
//! `providers.openai.admin_key_env` names a variable, it never holds a key.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::Deserialize;

/// Config file used when neither `--config` nor `ROTATE_CONFIG` is given.
pub const DEFAULT_CONFIG: &str = "rotate.yaml";
/// Default audit log path (decision D5).
pub const DEFAULT_AUDIT_LOG: &str = ".rotate/audit.jsonl";
/// Default state file path (decision D5).
pub const DEFAULT_STATE_FILE: &str = ".rotate/state.json";

/// Environment variable naming the config file.
pub const ENV_CONFIG: &str = "ROTATE_CONFIG";
/// Environment variable overriding `audit_log`.
pub const ENV_AUDIT_LOG: &str = "ROTATE_AUDIT_LOG";
/// Environment variable overriding `state_file`.
pub const ENV_STATE_FILE: &str = "ROTATE_STATE_FILE";
/// Environment variable overriding `overlap_window`.
pub const ENV_OVERLAP: &str = "ROTATE_OVERLAP";

/// How long the old secret stays valid after consumers are updated, written
/// as one or more `<integer><unit>` groups with units `s`, `m`, `h`, `d`:
/// `0s`, `90m`, `1h30m`, `7d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Deserialize)]
#[serde(try_from = "String")]
pub struct Overlap(Duration);

impl Overlap {
    /// The window as a `Duration`.
    pub fn as_duration(self) -> Duration {
        self.0
    }
}

/// A duration string that is not `<integer><s|m|h|d>` groups.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid duration {input:?}: expected <number><s|m|h|d>, for example 30m or 1h30m")]
pub struct InvalidOverlap {
    input: String,
}

impl FromStr for Overlap {
    type Err = InvalidOverlap;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidOverlap {
            input: input.to_owned(),
        };
        let mut total: u64 = 0;
        let mut digits = String::new();
        let mut groups = 0;
        for c in input.trim().chars() {
            if c.is_ascii_digit() {
                digits.push(c);
                continue;
            }
            let unit: u64 = match c {
                's' => 1,
                'm' => 60,
                'h' => 60 * 60,
                'd' => 24 * 60 * 60,
                _ => return Err(invalid()),
            };
            let n: u64 = digits.parse().map_err(|_| invalid())?;
            total = n
                .checked_mul(unit)
                .and_then(|secs| total.checked_add(secs))
                .ok_or_else(invalid)?;
            digits.clear();
            groups += 1;
        }
        if groups == 0 || !digits.is_empty() {
            return Err(invalid());
        }
        Ok(Self(Duration::from_secs(total)))
    }
}

impl TryFrom<String> for Overlap {
    type Error = InvalidOverlap;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for Overlap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut secs = self.0.as_secs();
        if secs == 0 {
            return f.write_str("0s");
        }
        for (unit, size) in [("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)] {
            if secs >= size {
                write!(f, "{}{unit}", secs / size)?;
                secs %= size;
            }
        }
        Ok(())
    }
}

/// The MVP providers, as written in name mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    /// AWS IAM access keys.
    Aws,
    /// GitHub personal access tokens.
    Github,
    /// npm access tokens.
    Npm,
    /// OpenAI API keys.
    Openai,
}

/// Where to look for GitHub Actions secrets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum ActionsTarget {
    /// Repository secrets of `owner/repo`.
    Repo {
        /// Owner login.
        owner: String,
        /// Repository name.
        repo: String,
    },
    /// Organization secrets, written `org:<name>`.
    Org(String),
}

/// A target that is neither `owner/repo` nor `org:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid target {0:?}: expected owner/repo or org:<name>")]
pub struct InvalidTarget(String);

fn valid_github_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

impl TryFrom<String> for ActionsTarget {
    type Error = InvalidTarget;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some(org) = value.strip_prefix("org:") {
            if valid_github_name(org) {
                return Ok(Self::Org(org.to_owned()));
            }
        } else if let Some((owner, repo)) = value.split_once('/') {
            if valid_github_name(owner) && valid_github_name(repo) {
                return Ok(Self::Repo {
                    owner: owner.to_owned(),
                    repo: repo.to_owned(),
                });
            }
        }
        Err(InvalidTarget(value))
    }
}

impl fmt::Display for ActionsTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionsTarget::Repo { owner, repo } => write!(f, "{owner}/{repo}"),
            ActionsTarget::Org(org) => write!(f, "org:{org}"),
        }
    }
}

/// Default `providers.github.api_url`.
pub const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com";
/// Default `providers.npm.registry`.
pub const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";
/// Default `providers.openai.api_url`.
pub const DEFAULT_OPENAI_API_URL: &str = "https://api.openai.com";

/// An API base URL (SHA-287): `https://`, or `http://` only to a loopback
/// host (`127.0.0.0/8`, `::1` or `localhost`), never with a user name or
/// password. Every setting that names an endpoint rotate sends secrets or
/// operator credentials to must use this type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct ApiUrl(String);

impl ApiUrl {
    /// The URL as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The parsed URL without a trailing `/`, for comparing with a default.
    fn normalized(&self) -> String {
        url::Url::parse(&self.0)
            .map_or_else(|_| self.0.clone(), |u| u.to_string())
            .trim_end_matches('/')
            .to_owned()
    }
}

/// Why an endpoint URL was refused. No variant holds the URL as written, so
/// a password in it never reaches an error message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidUrl {
    /// Not an absolute URL with a host.
    #[error("not a URL: expected https://host[:port][/path]")]
    NotAUrl,
    /// A scheme other than https or http.
    #[error("unsupported scheme {scheme:?}: only https:// is accepted")]
    Scheme {
        /// The parsed scheme.
        scheme: String,
    },
    /// A user name or password in the URL. The message names neither, and
    /// avoids the word, so a check for a leaked credential stays simple.
    #[error("must not embed credentials: give tokens through the environment, not in the URL")]
    Userinfo,
    /// A query string or fragment, even an empty one (SHA-332): the
    /// endpoint warning prints the URL as written, so a token there would
    /// reach stderr, and providers append paths to the base URL.
    #[error("must not have a query string or fragment: expected https://host[:port][/path]")]
    QueryOrFragment,
    /// Plain http to a host that is not loopback.
    #[error(
        "{origin} is neither https nor loopback: only https:// is accepted, except http:// to 127.0.0.1, ::1 or localhost"
    )]
    NotHttps {
        /// `scheme://host[:port]` from the parsed URL.
        origin: String,
    },
}

impl TryFrom<String> for ApiUrl {
    type Error = InvalidUrl;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parsed = url::Url::parse(&value).map_err(|_| InvalidUrl::NotAUrl)?;
        // Before anything that could show the URL.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(InvalidUrl::Userinfo);
        }
        if parsed.cannot_be_a_base() {
            return Err(InvalidUrl::NotAUrl);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(InvalidUrl::QueryOrFragment);
        }
        let Some(host) = parsed.host() else {
            return Err(InvalidUrl::NotAUrl);
        };
        match parsed.scheme() {
            "https" => Ok(Self(value)),
            "http" => {
                let loopback = match host {
                    url::Host::Ipv4(ip) => ip.is_loopback(),
                    url::Host::Ipv6(ip) => ip.is_loopback(),
                    url::Host::Domain(name) => name == "localhost",
                };
                if loopback {
                    Ok(Self(value))
                } else {
                    let origin = parsed.origin().ascii_serialization();
                    Err(InvalidUrl::NotHttps { origin })
                }
            }
            other => Err(InvalidUrl::Scheme {
                scheme: other.to_owned(),
            }),
        }
    }
}

impl fmt::Display for ApiUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `consumers.github_actions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GithubActionsConfig {
    /// Repositories and organizations whose secrets are searched.
    pub targets: Vec<ActionsTarget>,
    /// Extra secret names, per provider, that hold the secret or token.
    /// Added to the provider's naming convention (decision D4).
    pub secret_names: BTreeMap<ProviderName, Vec<String>>,
    /// Extra secret names, per provider, that hold an access key id.
    pub key_id_names: BTreeMap<ProviderName, Vec<String>>,
}

/// One `consumers.aws_secrets_manager.tag_filters` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagFilter {
    /// Tag key.
    pub key: String,
    /// Accepted values; empty means any value.
    #[serde(default)]
    pub values: Vec<String>,
}

/// `consumers.aws_secrets_manager`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsManagerConfig {
    /// Secret names or ARNs to compare.
    pub secrets: Vec<String>,
    /// Secrets selected by tag.
    pub tag_filters: Vec<TagFilter>,
    /// JSON keys compared and updated in JSON secrets. `None` means every
    /// top-level string value.
    pub json_keys: Option<Vec<String>>,
}

/// `consumers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsumersConfig {
    /// GitHub Actions repository and organization secrets.
    pub github_actions: GithubActionsConfig,
    /// AWS Secrets Manager entries.
    pub aws_secrets_manager: SecretsManagerConfig,
}

/// `providers.aws`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AwsConfig {
    /// Region for IAM, STS and Secrets Manager calls. `None` falls back to
    /// the AWS environment.
    pub region: Option<String>,
    /// Sends STS, IAM and Secrets Manager calls to this URL instead of AWS,
    /// for LocalStack or a test server (SHA-264). `None` uses AWS.
    pub endpoint_url: Option<ApiUrl>,
}

/// `providers.github`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GithubConfig {
    /// REST API base URL; change it for GitHub Enterprise Server.
    pub api_url: ApiUrl,
}

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            api_url: ApiUrl(DEFAULT_GITHUB_API_URL.into()),
        }
    }
}

/// `providers.npm`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NpmConfig {
    /// Registry base URL.
    pub registry: ApiUrl,
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            registry: ApiUrl(DEFAULT_NPM_REGISTRY.into()),
        }
    }
}

/// `providers.openai`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenAiConfig {
    /// Name of the environment variable holding the Admin API key.
    pub admin_key_env: String,
    /// API base URL, without `/v1`.
    pub api_url: ApiUrl,
    /// Let rotate create the replacement as a service account even though
    /// it gets all permissions in the project, which may be broader than
    /// the leaked key (SHA-291). Off by default: the operator pastes a
    /// restricted key. `--allow-broader-replacement` sets it for one run.
    pub allow_broader_replacement: bool,
}

impl Default for OpenAiConfig {
    fn default() -> Self {
        Self {
            admin_key_env: "OPENAI_ADMIN_KEY".into(),
            api_url: ApiUrl(DEFAULT_OPENAI_API_URL.into()),
            allow_broader_replacement: false,
        }
    }
}

/// `providers`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProvidersConfig {
    /// AWS settings.
    pub aws: AwsConfig,
    /// GitHub settings.
    pub github: GithubConfig,
    /// npm settings.
    pub npm: NpmConfig,
    /// OpenAI settings.
    pub openai: OpenAiConfig,
}

impl ProvidersConfig {
    /// One line per endpoint that differs from its provider's default
    /// (SHA-287), for the plan to show before anything is sent there. Any
    /// `providers.aws.endpoint_url` counts: by default rotate uses AWS's own
    /// endpoints.
    pub fn endpoint_warnings(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(url) = &self.aws.endpoint_url {
            lines.push(format!(
                "providers.aws.endpoint_url is {url} (default: AWS's own endpoints)"
            ));
        }
        for (field, url, default) in [
            (
                "providers.github.api_url",
                &self.github.api_url,
                DEFAULT_GITHUB_API_URL,
            ),
            (
                "providers.npm.registry",
                &self.npm.registry,
                DEFAULT_NPM_REGISTRY,
            ),
            (
                "providers.openai.api_url",
                &self.openai.api_url,
                DEFAULT_OPENAI_API_URL,
            ),
        ] {
            let default_url = ApiUrl(default.to_owned());
            if url.normalized() != default_url.normalized() {
                lines.push(format!("{field} is {url} (default {default})"));
            }
        }
        lines
    }
}

/// `rotate.yaml` as written. Settings that flags and environment variables
/// can override are `Option` so resolution can tell "absent" from "default".
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    /// See [`Overlap`].
    pub overlap_window: Option<Overlap>,
    /// Audit log path.
    pub audit_log: Option<PathBuf>,
    /// State file path.
    pub state_file: Option<PathBuf>,
    /// Where secrets are used.
    pub consumers: ConsumersConfig,
    /// Per-provider settings.
    pub providers: ProvidersConfig,
}

/// Values given on the command line. Each beats its environment variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `--config`.
    pub config: Option<PathBuf>,
    /// `--audit-log`.
    pub audit_log: Option<PathBuf>,
    /// `--state-file`.
    pub state_file: Option<PathBuf>,
    /// `--overlap`.
    pub overlap_window: Option<Overlap>,
}

/// The resolved configuration every command runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Overlap window between consumer update and revoke.
    pub overlap_window: Overlap,
    /// Audit log path, absolute.
    pub audit_log: PathBuf,
    /// State file path, absolute.
    pub state_file: PathBuf,
    /// Where secrets are used.
    pub consumers: ConsumersConfig,
    /// Per-provider settings.
    pub providers: ProvidersConfig,
    /// The config file that was read, if any.
    pub source: Option<PathBuf>,
}

/// A config that could not be loaded. Exit code 2.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("could not read config {}: {source}", path.display())]
    Read {
        /// The config path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file is not valid YAML or does not match the schema.
    #[error("{}: {field}{}: {message}", path.display(), location(*line, *column))]
    Invalid {
        /// The config path.
        path: PathBuf,
        /// Dotted path to the offending field; `(top level)` for the root.
        field: String,
        /// 1-based line, when known.
        line: Option<usize>,
        /// 1-based column, when known.
        column: Option<usize>,
        /// What is wrong.
        message: String,
    },
    /// An environment variable holds an invalid value.
    #[error("{var}: {message}")]
    Env {
        /// The variable's name.
        var: &'static str,
        /// What is wrong.
        message: String,
    },
}

fn location(line: Option<usize>, column: Option<usize>) -> String {
    match (line, column) {
        (Some(line), Some(column)) => format!(" at line {line}, column {column}"),
        (Some(line), None) => format!(" at line {line}"),
        _ => String::new(),
    }
}

/// Parses config text. `path` is used in error messages only. A file that
/// is empty or holds only comments is valid and sets nothing.
pub fn parse(text: &str, path: &Path) -> Result<FileConfig, ConfigError> {
    let deserializer = serde_norway::Deserializer::from_str(text);
    match serde_path_to_error::deserialize::<_, Option<FileConfig>>(deserializer) {
        Ok(file) => Ok(file.unwrap_or_default()),
        Err(err) => {
            let field = match err.path().to_string() {
                root if root == "." => "(top level)".to_owned(),
                field => field,
            };
            let inner = err.into_inner();
            let (line, column) = inner
                .location()
                .map_or((None, None), |l| (Some(l.line()), Some(l.column())));
            Err(ConfigError::Invalid {
                path: path.to_path_buf(),
                field,
                line,
                column,
                message: strip_location(&inner.to_string()),
            })
        }
    }
}

/// serde_norway appends ` at line N column M`; the error carries the
/// location separately.
fn strip_location(message: &str) -> String {
    match message.rfind(" at line ") {
        Some(at) => message[..at].to_owned(),
        None => message.to_owned(),
    }
}

impl Config {
    /// Resolves the configuration from `flags`, the process environment and
    /// the current directory.
    pub fn load(flags: &Overrides) -> Result<Config, ConfigError> {
        let cwd = std::env::current_dir().map_err(|source| ConfigError::Read {
            path: PathBuf::from("."),
            source,
        })?;
        Self::load_with(flags, |var| std::env::var(var).ok(), &cwd)
    }

    /// Resolves the configuration with an injected environment lookup and
    /// working directory. An empty environment variable counts as unset.
    pub fn load_with(
        flags: &Overrides,
        env: impl Fn(&str) -> Option<String>,
        cwd: &Path,
    ) -> Result<Config, ConfigError> {
        let env = |var: &str| env(var).filter(|v| !v.is_empty());

        let (file, source) = match flags
            .config
            .clone()
            .or_else(|| env(ENV_CONFIG).map(PathBuf::from))
        {
            Some(path) => {
                let path = cwd.join(path);
                (read_file(&path)?, Some(path))
            }
            None => {
                let path = cwd.join(DEFAULT_CONFIG);
                if path.is_file() {
                    (read_file(&path)?, Some(path))
                } else {
                    (FileConfig::default(), None)
                }
            }
        };

        let overlap_window = match flags.overlap_window {
            Some(overlap) => overlap,
            None => match env(ENV_OVERLAP) {
                Some(value) => value
                    .parse()
                    .map_err(|err: InvalidOverlap| ConfigError::Env {
                        var: ENV_OVERLAP,
                        message: err.to_string(),
                    })?,
                None => file.overlap_window.unwrap_or_default(),
            },
        };
        let path_setting =
            |flag: &Option<PathBuf>, var: &str, file: Option<PathBuf>, default: &str| {
                let chosen = flag
                    .clone()
                    .or_else(|| env(var).map(PathBuf::from))
                    .or(file)
                    .unwrap_or_else(|| PathBuf::from(default));
                cwd.join(chosen)
            };

        Ok(Config {
            overlap_window,
            audit_log: path_setting(
                &flags.audit_log,
                ENV_AUDIT_LOG,
                file.audit_log,
                DEFAULT_AUDIT_LOG,
            ),
            state_file: path_setting(
                &flags.state_file,
                ENV_STATE_FILE,
                file.state_file,
                DEFAULT_STATE_FILE,
            ),
            consumers: file.consumers,
            providers: file.providers,
            source,
        })
    }
}

fn read_file(path: &Path) -> Result<FileConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&text, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = include_str!("../tests/fixtures/config/full.yaml");
    const BAD_DURATION: &str = include_str!("../tests/fixtures/config/bad_duration.yaml");
    const UNKNOWN_KEY: &str = include_str!("../tests/fixtures/config/unknown_key.yaml");
    const EXAMPLE: &str = include_str!("../docs/rotate.example.yaml");

    fn overlap(s: &str) -> Overlap {
        s.parse().unwrap()
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn invalid(text: &str) -> (String, Option<usize>, String) {
        match parse(text, Path::new("rotate.yaml")).unwrap_err() {
            ConfigError::Invalid {
                field,
                line,
                message,
                ..
            } => (field, line, message),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn overlap_parses_and_displays() {
        for (input, secs, shown) in [
            ("0s", 0, "0s"),
            ("45s", 45, "45s"),
            ("90m", 5_400, "1h30m"),
            ("1h30m", 5_400, "1h30m"),
            (" 7d ", 604_800, "7d"),
            ("1d2h3m4s", 93_784, "1d2h3m4s"),
        ] {
            let parsed = overlap(input);
            assert_eq!(parsed.as_duration(), Duration::from_secs(secs), "{input}");
            assert_eq!(parsed.to_string(), shown, "{input}");
        }
        for bad in [
            "soon",
            "10",
            "1x",
            "-1s",
            "",
            "m",
            "1.5h",
            "99999999999999999999d",
        ] {
            assert!(bad.parse::<Overlap>().is_err(), "{bad:?} accepted");
        }
        assert_eq!(Overlap::default(), overlap("0s"));
    }

    // T1 (AC1)
    #[test]
    fn no_file_means_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_with(&Overrides::default(), no_env, dir.path()).unwrap();
        assert_eq!(config.overlap_window, overlap("0s"));
        assert_eq!(config.audit_log, dir.path().join(".rotate/audit.jsonl"));
        assert_eq!(config.state_file, dir.path().join(".rotate/state.json"));
        assert_eq!(config.consumers, ConsumersConfig::default());
        assert_eq!(
            config.providers.github.api_url.as_str(),
            "https://api.github.com"
        );
        assert_eq!(
            config.providers.npm.registry.as_str(),
            "https://registry.npmjs.org"
        );
        assert_eq!(config.providers.openai.admin_key_env, "OPENAI_ADMIN_KEY");
        assert_eq!(
            config.providers.openai.api_url.as_str(),
            "https://api.openai.com"
        );
        assert!(!config.providers.openai.allow_broader_replacement);
        assert_eq!(config.providers.aws.region, None);
        assert_eq!(config.source, None);
    }

    // T2 (AC2)
    #[test]
    fn full_fixture_sets_every_field() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("rotate.yaml"), FULL).unwrap();
        let config = Config::load_with(&Overrides::default(), no_env, dir.path()).unwrap();

        assert_eq!(config.source, Some(dir.path().join("rotate.yaml")));
        assert_eq!(config.overlap_window, overlap("1h30m"));
        assert_eq!(config.audit_log, dir.path().join("logs/rotate-audit.jsonl"));
        assert_eq!(
            config.state_file,
            PathBuf::from("/var/lib/rotate/state.json")
        );

        let gha = &config.consumers.github_actions;
        assert_eq!(
            gha.targets,
            [
                ActionsTarget::Repo {
                    owner: "acme".into(),
                    repo: "api".into()
                },
                ActionsTarget::Org("acme".into())
            ]
        );
        assert_eq!(
            gha.secret_names[&ProviderName::Github],
            ["GH_PAT", "RELEASE_TOKEN"]
        );
        assert_eq!(gha.secret_names[&ProviderName::Aws], ["CI_AWS_SECRET"]);
        assert_eq!(gha.key_id_names[&ProviderName::Aws], ["CI_AWS_KEY_ID"]);

        let sm = &config.consumers.aws_secrets_manager;
        assert_eq!(
            sm.secrets,
            [
                "prod/api",
                "arn:aws:secretsmanager:us-east-1:000000000000:secret:ci-AbCdEf"
            ]
        );
        assert_eq!(
            sm.tag_filters,
            [TagFilter {
                key: "team".into(),
                values: vec!["payments".into()]
            }]
        );
        assert_eq!(
            sm.json_keys.as_deref(),
            Some(&["AWS_SECRET_ACCESS_KEY".to_owned()][..])
        );

        let providers = &config.providers;
        assert_eq!(providers.aws.region.as_deref(), Some("eu-west-1"));
        assert_eq!(
            providers.github.api_url.as_str(),
            "https://github.example.com/api/v3"
        );
        assert_eq!(providers.npm.registry.as_str(), "https://npm.example.com");
        assert_eq!(providers.openai.admin_key_env, "ROTATE_OPENAI_ADMIN");
        assert!(providers.openai.allow_broader_replacement);
    }

    #[test]
    fn aws_endpoint_url_parses_and_is_checked() {
        let file = parse(
            "providers:\n  aws:\n    endpoint_url: http://127.0.0.1:4566\n",
            Path::new("rotate.yaml"),
        )
        .unwrap();
        assert_eq!(
            file.providers.aws.endpoint_url.as_ref().map(ApiUrl::as_str),
            Some("http://127.0.0.1:4566")
        );
        assert_eq!(FileConfig::default().providers.aws.endpoint_url, None);
        let (field, _, _) = invalid("providers:\n  aws:\n    endpoint_url: localhost\n");
        assert!(field.contains("endpoint_url"), "{field}");
    }

    // T3 (AC3)
    #[test]
    fn bad_duration_names_field_and_line() {
        let (field, line, message) = invalid(BAD_DURATION);
        assert_eq!(field, "overlap_window");
        assert_eq!(line, Some(2));
        assert!(message.contains("invalid duration \"soon\""), "{message}");
        let err = parse(BAD_DURATION, Path::new("rotate.yaml")).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("rotate.yaml: overlap_window at line 2, column"),
            "{err}"
        );
    }

    // T3 (AC3)
    #[test]
    fn unknown_key_names_field_and_line() {
        let (field, line, message) = invalid(UNKNOWN_KEY);
        assert_eq!(field, "unknown_key");
        assert_eq!(line, Some(3));
        assert!(message.contains("unknown field `unknown_key`"), "{message}");

        let (field, line, message) = invalid("consumers:\n  github_actions:\n    repos: [a/b]\n");
        assert_eq!(field, "consumers.github_actions.repos");
        assert_eq!(line, Some(3));
        assert!(message.contains("unknown field `repos`"), "{message}");
    }

    // T4 (AC4)
    #[test]
    fn flag_beats_env_beats_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rotate.yaml"),
            "overlap_window: 1m\naudit_log: file.jsonl\nstate_file: file.json\n",
        )
        .unwrap();
        let env = |var: &str| match var {
            ENV_OVERLAP => Some("2m".to_owned()),
            ENV_AUDIT_LOG => Some("env.jsonl".to_owned()),
            ENV_STATE_FILE => Some("env.json".to_owned()),
            _ => None,
        };
        let flags = Overrides {
            config: None,
            audit_log: Some("flag.jsonl".into()),
            state_file: Some("flag.json".into()),
            overlap_window: Some(overlap("3m")),
        };

        let config = Config::load_with(&flags, env, dir.path()).unwrap();
        assert_eq!(config.overlap_window, overlap("3m"));
        assert_eq!(config.audit_log, dir.path().join("flag.jsonl"));
        assert_eq!(config.state_file, dir.path().join("flag.json"));

        let config = Config::load_with(&Overrides::default(), env, dir.path()).unwrap();
        assert_eq!(config.overlap_window, overlap("2m"));
        assert_eq!(config.audit_log, dir.path().join("env.jsonl"));
        assert_eq!(config.state_file, dir.path().join("env.json"));

        let config = Config::load_with(&Overrides::default(), no_env, dir.path()).unwrap();
        assert_eq!(config.overlap_window, overlap("1m"));
        assert_eq!(config.audit_log, dir.path().join("file.jsonl"));
        assert_eq!(config.state_file, dir.path().join("file.json"));

        let empty = |_: &str| Some(String::new());
        let config = Config::load_with(&Overrides::default(), empty, dir.path()).unwrap();
        assert_eq!(
            config.overlap_window,
            overlap("1m"),
            "empty env var counts as unset"
        );
    }

    // T5 (AC5)
    #[test]
    fn example_config_parses() {
        let file = parse(EXAMPLE, Path::new("docs/rotate.example.yaml")).unwrap();
        // The example must show every field so it cannot drift from the schema.
        assert!(file.overlap_window.is_some());
        assert!(file.audit_log.is_some());
        assert!(file.state_file.is_some());
        let gha = &file.consumers.github_actions;
        assert!(!gha.targets.is_empty());
        assert!(!gha.secret_names.is_empty());
        assert!(!gha.key_id_names.is_empty());
        let sm = &file.consumers.aws_secrets_manager;
        assert!(!sm.secrets.is_empty());
        assert!(!sm.tag_filters.is_empty());
        assert!(sm.json_keys.is_some());
        assert!(file.providers.aws.region.is_some());
        for key in [
            "api_url:",
            "registry:",
            "admin_key_env:",
            "endpoint_url:",
            "allow_broader_replacement:",
        ] {
            assert!(EXAMPLE.contains(key), "example is missing {key}");
        }
    }

    #[test]
    fn empty_and_comment_only_files_are_valid() {
        for text in ["", "\n", "# nothing here\n"] {
            assert_eq!(
                parse(text, Path::new("rotate.yaml")).unwrap(),
                FileConfig::default()
            );
        }
    }

    #[test]
    fn bad_env_overlap_names_variable() {
        let dir = tempfile::tempdir().unwrap();
        let env = |var: &str| (var == ENV_OVERLAP).then(|| "later".to_owned());
        let err = Config::load_with(&Overrides::default(), env, dir.path()).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Env {
                var: ENV_OVERLAP,
                ..
            }
        ));
        assert!(
            err.to_string()
                .starts_with("ROTATE_OVERLAP: invalid duration"),
            "{err}"
        );
    }

    #[test]
    fn explicit_missing_config_errors() {
        let dir = tempfile::tempdir().unwrap();
        let flags = Overrides {
            config: Some("missing.yaml".into()),
            ..Overrides::default()
        };
        let err = Config::load_with(&flags, no_env, dir.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
        assert!(err.to_string().contains("missing.yaml"), "{err}");
    }

    #[test]
    fn rotate_config_env_selects_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("other.yaml"), "overlap_window: 5m\n").unwrap();
        std::fs::write(dir.path().join("rotate.yaml"), "overlap_window: 9m\n").unwrap();
        let env = |var: &str| (var == ENV_CONFIG).then(|| "other.yaml".to_owned());
        let config = Config::load_with(&Overrides::default(), env, dir.path()).unwrap();
        assert_eq!(config.overlap_window, overlap("5m"));
        assert_eq!(config.source, Some(dir.path().join("other.yaml")));
    }

    #[test]
    fn targets_reject_bad_shape() {
        for bad in [
            "acme",
            "org:",
            "/repo",
            "acme/",
            "a/b/c",
            "org:a b",
            "acme/ap i",
        ] {
            let (field, _, message) = invalid(&format!(
                "consumers:\n  github_actions:\n    targets: [\"{bad}\"]\n"
            ));
            assert_eq!(field, "consumers.github_actions.targets[0]", "{bad}");
            assert!(
                message.contains("expected owner/repo or org:<name>"),
                "{message}"
            );
        }
        let target = ActionsTarget::try_from("my-org.io/repo_1".to_owned()).unwrap();
        assert_eq!(target.to_string(), "my-org.io/repo_1");
    }

    #[test]
    fn unknown_provider_key_fails() {
        let (field, line, message) =
            invalid("consumers:\n  github_actions:\n    secret_names:\n      gitlab: [X]\n");
        assert!(
            field.starts_with("consumers.github_actions.secret_names"),
            "{field}"
        );
        assert_eq!(line, Some(4));
        assert!(message.contains("unknown variant `gitlab`"), "{message}");
    }

    /// The four endpoint fields as YAML paths, each with a value slot.
    const URL_FIELDS: [(&str, &str); 4] = [
        (
            "providers.aws.endpoint_url",
            "providers:\n  aws:\n    endpoint_url: \"{}\"\n",
        ),
        (
            "providers.github.api_url",
            "providers:\n  github:\n    api_url: \"{}\"\n",
        ),
        (
            "providers.npm.registry",
            "providers:\n  npm:\n    registry: \"{}\"\n",
        ),
        (
            "providers.openai.api_url",
            "providers:\n  openai:\n    api_url: \"{}\"\n",
        ),
    ];

    fn yaml(template: &str, url: &str) -> String {
        template.replace("{}", url)
    }

    /// SHA-287 T1 (AC1, AC4): plain http to any other host fails, naming
    /// its own field and the rule.
    #[test]
    fn sha287_t1_non_loopback_http_names_its_field() {
        for (name, template) in URL_FIELDS {
            let text = yaml(template, "http://api.example.com");
            let (field, _, message) = invalid(&text);
            assert_eq!(field, name);
            assert!(message.contains("https://"), "{message}");
            assert!(message.contains("localhost"), "{message}");
            let shown = parse(&text, Path::new("rotate.yaml"))
                .unwrap_err()
                .to_string();
            assert!(
                shown.starts_with(&format!("rotate.yaml: {name} at line")),
                "{shown}"
            );
        }
    }

    /// SHA-287 T2 (AC2): http to loopback is accepted and kept as written.
    #[test]
    fn sha287_t2_loopback_http_is_accepted() {
        for url in [
            "http://127.0.0.1:4566",
            "http://[::1]:8080",
            "http://localhost:4873",
            "http://LOCALHOST:4873",
            "HTTP://127.0.0.1",
            "http://127.0.0.1:4566/",
            "http://127.0.0.2:9000",
            "https://npm.example.com",
        ] {
            for (name, template) in URL_FIELDS {
                let file = parse(&yaml(template, url), Path::new("r"))
                    .unwrap_or_else(|e| panic!("{name} {url}: {e}"));
                let p = file.providers;
                let got = match name {
                    "providers.aws.endpoint_url" => p.aws.endpoint_url.unwrap(),
                    "providers.github.api_url" => p.github.api_url,
                    "providers.npm.registry" => p.npm.registry,
                    _ => p.openai.api_url,
                };
                assert_eq!(got.as_str(), url, "{name}");
            }
        }
    }

    /// SHA-287 T3 (AC3): host confusion, userinfo and non-URLs are refused,
    /// and no message shows the user name or password.
    #[test]
    fn sha287_t3_host_confusion_and_userinfo_are_refused() {
        for url in [
            "http://127.0.0.1.evil.example",
            "http://localhost@evil.example",
            "http://evil.example/127.0.0.1",
            "https://user:pass@api.example.com",
            "https://u5er-canary:pa55-canary@api.example.com",
            "http://u5er-canary@localhost",
            "https://:pa55-canary@api.example.com",
            "ftp://x",
            "https://",
            "api.github.com",
            "mailto:x@example.com",
        ] {
            for (name, template) in URL_FIELDS {
                let text = yaml(template, url);
                let (field, _, message) = invalid(&text);
                assert_eq!(field, name, "{url}");
                let shown = parse(&text, Path::new("rotate.yaml"))
                    .unwrap_err()
                    .to_string();
                for secret in ["pass", "user@", "localhost@", "u5er-canary", "pa55-canary"] {
                    assert!(!shown.contains(secret), "{url}: {shown}");
                    assert!(!message.contains(secret), "{url}: {message}");
                }
            }
        }
    }

    /// SHA-332 T1 (AC1): a query string or fragment, empty or not, is
    /// refused for every endpoint field, and no part of it is shown.
    #[test]
    fn sha332_t1_query_and_fragment_are_refused() {
        for url in [
            "https://api.example.com/?a=qcanary",
            "https://api.example.com?",
            "https://api.example.com/#fcanary",
            "https://api.example.com#",
            "https://ghe.example.com/api/v3?x=qcanary#fcanary",
            "http://127.0.0.1:4566/?token=qcanary",
        ] {
            for (name, template) in URL_FIELDS {
                let text = yaml(template, url);
                let (field, _, message) = invalid(&text);
                assert_eq!(field, name, "{url}");
                assert!(
                    message.contains("query string or fragment"),
                    "{url}: {message}"
                );
                let shown = parse(&text, Path::new("rotate.yaml"))
                    .unwrap_err()
                    .to_string();
                for canary in ["qcanary", "fcanary", "a=", "x=", "token="] {
                    assert!(!shown.contains(canary), "{url}: {shown}");
                    assert!(!message.contains(canary), "{url}: {message}");
                }
            }
        }
    }

    /// SHA-287 (AC5, AC6): one warning per non-default endpoint; defaults,
    /// spelled out with a trailing slash or in capitals, warn nothing.
    #[test]
    fn endpoint_warnings_name_field_and_url() {
        assert!(ProvidersConfig::default().endpoint_warnings().is_empty());
        let same = parse(
            "providers:\n  github:\n    api_url: https://api.github.com/\n  npm:\n    registry: HTTPS://REGISTRY.NPMJS.ORG\n  openai:\n    api_url: https://api.openai.com\n",
            Path::new("r"),
        )
        .unwrap();
        assert!(same.providers.endpoint_warnings().is_empty());

        let npm = parse(
            "providers:\n  npm:\n    registry: https://npm.example.com\n",
            Path::new("r"),
        )
        .unwrap();
        assert_eq!(
            npm.providers.endpoint_warnings(),
            ["providers.npm.registry is https://npm.example.com (default https://registry.npmjs.org)"]
        );

        let all = parse(
            "providers:\n  aws:\n    endpoint_url: http://localhost:4566\n  github:\n    api_url: https://ghe.example.com/api/v3\n  npm:\n    registry: https://npm.example.com\n  openai:\n    api_url: https://openai.example.com\n",
            Path::new("r"),
        )
        .unwrap();
        assert_eq!(
            all.providers.endpoint_warnings(),
            [
                "providers.aws.endpoint_url is http://localhost:4566 (default: AWS's own endpoints)",
                "providers.github.api_url is https://ghe.example.com/api/v3 (default https://api.github.com)",
                "providers.npm.registry is https://npm.example.com (default https://registry.npmjs.org)",
                "providers.openai.api_url is https://openai.example.com (default https://api.openai.com)",
            ]
        );
    }
}
