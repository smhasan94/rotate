//! Assessment (SHA-248): which provider owns each finding, collapse
//! duplicates, and check what is still valid (FR3 to FR6, NFR9).
//!
//! Every call made here is read-only: `check_valid` and `describe_scope`.
//! Checks run concurrently under a semaphore and retry rate limits and
//! transient failures with exponential backoff. A failure never aborts the
//! run; it becomes `Validity::Unknown` with the error text as the reason.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::finding::{Finding, SourceLocation, ACCESS_KEY_ID, IS_CANARY};
use crate::provider::{Confidence, Credential, ProviderError, ProviderRegistry, Scope, Validity};
use crate::secret::Fingerprint;

/// gitleaks rule that matches only the access key id half of an AWS pair.
const GITLEAKS_AWS_KEY_ID_RULE: &str = "aws-access-token";

/// Scanner detector names (TruffleHog) and rule ids (gitleaks) that name a
/// provider. Compared ignoring ASCII case.
const DETECTOR_HINTS: &[(&str, &str)] = &[
    ("AWS", "aws"),
    ("Github", "github"),
    ("GitHubOauth2", "github"),
    ("github-pat", "github"),
    ("github-fine-grained-pat", "github"),
    ("github-oauth", "github"),
    ("github-app-token", "github"),
    ("NpmToken", "npm"),
    ("NpmTokenV2", "npm"),
    ("npm-access-token", "npm"),
    ("OpenAI", "openai"),
    ("OpenAIAdminKey", "openai"),
    ("openai-api-key", "openai"),
];

/// Tuning for [`assess`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssessOptions {
    /// Most provider checks in flight at once (`--concurrency`).
    pub concurrency: usize,
    /// Attempts per call, including the first.
    pub attempts: u32,
    /// Backoff before the second attempt; doubled for each one after.
    pub base_delay: Duration,
    /// Provider every finding is assigned to, skipping hints and patterns
    /// (`--provider` with `--stdin`). Canary and key-id-only findings are
    /// still not rotatable. Ignored when the name is not registered.
    pub force_provider: Option<&'static str>,
}

impl Default for AssessOptions {
    fn default() -> Self {
        Self {
            concurrency: 8,
            attempts: 3,
            base_delay: Duration::from_millis(500),
            force_provider: None,
        }
    }
}

/// What rotate can do with a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// A registered provider owns it.
    Supported {
        /// The provider's name.
        provider: &'static str,
        /// How sure identification was. A detector hint counts as `High`.
        confidence: Confidence,
    },
    /// No registered provider claims it.
    Unsupported {
        /// Why, when there is more to say than "no match" (a tie between
        /// providers).
        reason: Option<String>,
    },
    /// It looks like a supported credential but cannot be rotated from this
    /// input, and is never sent to the provider.
    NotRotatable {
        /// What to do instead.
        reason: String,
    },
}

/// One distinct secret after dedupe, identification and checking.
///
/// Holds the credential for the plan and apply stages, so it has no
/// `Serialize`; [`render_json`] goes through a view with fingerprints only.
#[derive(Debug, Clone)]
pub struct Assessed {
    /// Fingerprint of the secret half.
    pub fingerprint: Fingerprint,
    /// The credential, with its key id when any finding carried one.
    pub credential: Credential,
    /// Who owns it.
    pub disposition: Disposition,
    /// Result of `check_valid`; `None` when it was not checked.
    pub validity: Option<Validity>,
    /// Result of `describe_scope` for a valid secret.
    pub scope: Option<Scope>,
    /// Why `describe_scope` failed, when it did.
    pub scope_error: Option<String>,
    /// Every detector that reported it, in first-seen order.
    pub detectors: Vec<String>,
    /// Every location that held it, in report order.
    pub sources: Vec<SourceLocation>,
}

/// Findings that share a fingerprint.
struct Group {
    finding: Finding,
    detectors: Vec<String>,
    sources: Vec<SourceLocation>,
    canary: bool,
}

/// Identifies, dedupes and checks `findings`. Results come back in the order
/// each fingerprint was first seen. Never fails: per-secret problems are
/// recorded on the result.
pub async fn assess(
    findings: Vec<Finding>,
    registry: &ProviderRegistry,
    opts: &AssessOptions,
) -> Vec<Assessed> {
    let mut assessed: Vec<Assessed> = group(findings)
        .into_iter()
        .map(|group| {
            let disposition = identify(&group, registry, opts.force_provider);
            Assessed {
                fingerprint: group.finding.fingerprint(),
                credential: group.finding.credential(),
                disposition,
                validity: None,
                scope: None,
                scope_error: None,
                detectors: group.detectors,
                sources: group.sources,
            }
        })
        .collect();
    check_all(&mut assessed, registry, *opts).await;
    assessed
}

/// Collapses findings by fingerprint, keeping every source. The credential
/// comes from the first finding with an access key id, else the first.
fn group(findings: Vec<Finding>) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    let mut index: HashMap<Fingerprint, usize> = HashMap::new();
    for finding in findings {
        let canary = finding.extra.get(IS_CANARY).map(String::as_str) == Some("true");
        let fingerprint = finding.fingerprint();
        let Some(&at) = index.get(&fingerprint) else {
            index.insert(fingerprint, groups.len());
            groups.push(Group {
                detectors: vec![finding.detector.clone()],
                sources: vec![finding.source.clone()],
                canary,
                finding,
            });
            continue;
        };
        let group = &mut groups[at];
        if !group.detectors.contains(&finding.detector) {
            group.detectors.push(finding.detector.clone());
        }
        group.sources.push(finding.source.clone());
        group.canary |= canary;
        if !group.finding.extra.contains_key(ACCESS_KEY_ID)
            && finding.extra.contains_key(ACCESS_KEY_ID)
        {
            group.finding = finding;
        }
    }
    groups
}

/// Provider named by a detector hint, if any.
fn hint(detector: &str) -> Option<&'static str> {
    DETECTOR_HINTS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(detector))
        .map(|(_, provider)| *provider)
}

fn identify(group: &Group, registry: &ProviderRegistry, forced: Option<&str>) -> Disposition {
    if group.canary {
        return Disposition::NotRotatable {
            reason: "canary token: any API call alerts whoever planted it, so it is not checked"
                .into(),
        };
    }
    let key_id_only = group
        .detectors
        .iter()
        .any(|d| d.eq_ignore_ascii_case(GITLEAKS_AWS_KEY_ID_RULE))
        && !group.finding.extra.contains_key(ACCESS_KEY_ID);
    if key_id_only {
        return Disposition::NotRotatable {
            reason: "gitleaks reports only the AWS access key id; use a TruffleHog report or \
                     `rotate plan --stdin` with KEY_ID:SECRET"
                .into(),
        };
    }

    if let Some(provider) = forced.and_then(|name| registry.get(name)) {
        return Disposition::Supported {
            provider: provider.name(),
            confidence: Confidence::High,
        };
    }

    let pattern = registry.identify(&group.finding);
    let hinted = group
        .detectors
        .iter()
        .filter_map(|d| hint(d))
        .find_map(|name| registry.get(name).map(|p| p.name()));

    match (hinted, pattern) {
        (Some(provider), pattern) => {
            if let Ok(Some(by_pattern)) = &pattern {
                let pattern_name = by_pattern.provider.name();
                if pattern_name != provider {
                    tracing::warn!(
                        fingerprint = %group.finding.fingerprint(),
                        hint = provider,
                        pattern = pattern_name,
                        "detector hint and value pattern disagree; using the hint"
                    );
                }
            }
            Disposition::Supported {
                provider,
                confidence: Confidence::High,
            }
        }
        (None, Ok(Some(identified))) => Disposition::Supported {
            provider: identified.provider.name(),
            confidence: identified.confidence,
        },
        (None, Ok(None)) => Disposition::Unsupported { reason: None },
        (None, Err(ambiguous)) => Disposition::Unsupported {
            reason: Some(ambiguous.to_string()),
        },
    }
}

/// What one check task produced.
struct Checked {
    validity: Validity,
    scope: Option<Scope>,
    scope_error: Option<String>,
}

/// Checks every supported secret, at most `opts.concurrency` at a time.
async fn check_all(assessed: &mut [Assessed], registry: &ProviderRegistry, opts: AssessOptions) {
    let semaphore = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut tasks = JoinSet::new();
    let mut task_index = HashMap::new();

    for (index, item) in assessed.iter().enumerate() {
        let Disposition::Supported { provider, .. } = item.disposition else {
            continue;
        };
        let Some(provider) = registry.get(provider).cloned() else {
            continue;
        };
        let credential = item.credential.clone();
        let semaphore = Arc::clone(&semaphore);
        let handle = tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .expect("the semaphore is never closed");
            let validity = match with_retry(opts, || provider.check_valid(&credential)).await {
                Ok(validity) => validity,
                Err(err) => Validity::Unknown {
                    reason: err.to_string(),
                },
            };
            let (scope, scope_error) = if validity == Validity::Valid {
                match with_retry(opts, || provider.describe_scope(&credential)).await {
                    Ok(scope) => (Some(scope), None),
                    Err(err) => (None, Some(err.to_string())),
                }
            } else {
                (None, None)
            };
            Checked {
                validity,
                scope,
                scope_error,
            }
        });
        task_index.insert(handle.id(), index);
    }

    while let Some(joined) = tasks.join_next_with_id().await {
        let (id, checked) = match joined {
            Ok((id, checked)) => (id, checked),
            Err(err) => (
                err.id(),
                Checked {
                    validity: Validity::Unknown {
                        reason: "the provider check panicked".into(),
                    },
                    scope: None,
                    scope_error: None,
                },
            ),
        };
        if let Some(&index) = task_index.get(&id) {
            let item = &mut assessed[index];
            item.validity = Some(checked.validity);
            item.scope = checked.scope;
            item.scope_error = checked.scope_error;
        }
    }
}

/// Runs `call` up to `opts.attempts` times, retrying only errors for which
/// [`ProviderError::is_retryable`] holds. Waits the provider's `retry_after`
/// when it gives one, else `base_delay * 2^(attempt - 1)`.
async fn with_retry<T, F, Fut>(opts: AssessOptions, mut call: F) -> Result<T, ProviderError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ProviderError>>,
{
    let attempts = opts.attempts.max(1);
    let mut attempt = 1;
    loop {
        match call().await {
            Ok(value) => return Ok(value),
            Err(err) if err.is_retryable() && attempt < attempts => {
                let delay = match &err {
                    ProviderError::RateLimited {
                        retry_after: Some(after),
                    } => *after,
                    _ => opts.base_delay.saturating_mul(1 << (attempt - 1)),
                };
                tracing::debug!(attempt, error = %err, "retrying provider call");
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Status word and optional reason, shared by the table and JSON.
fn status(item: &Assessed) -> (&'static str, Option<String>) {
    match &item.disposition {
        Disposition::Unsupported { reason } => ("unsupported", reason.clone()),
        Disposition::NotRotatable { reason } => ("not rotatable", Some(reason.clone())),
        Disposition::Supported { .. } => match &item.validity {
            Some(Validity::Valid) => ("valid", None),
            Some(Validity::Invalid) => ("invalid", None),
            Some(Validity::Unknown { reason }) => ("unknown", Some(reason.clone())),
            None => ("unchecked", None),
        },
    }
}

fn provider_name(item: &Assessed) -> Option<&'static str> {
    match item.disposition {
        Disposition::Supported { provider, .. } => Some(provider),
        _ => None,
    }
}

/// Human-readable table, one row per distinct secret. Reasons (why a
/// secret is unknown, unsupported or not rotatable) follow the table as
/// notes so long text does not widen every row.
pub fn render_table(assessed: &[Assessed]) -> String {
    let header = ["PROVIDER", "FINGERPRINT", "STATUS", "SOURCE", "IDENTITY"];
    let mut notes: Vec<String> = Vec::new();
    let rows: Vec<[String; 5]> = assessed
        .iter()
        .map(|item| {
            let (word, reason) = status(item);
            if let Some(reason) = reason {
                notes.push(format!("  {}  {word}: {reason}", item.fingerprint));
            }
            let status = word.to_owned();
            let source = match item.sources.split_first() {
                Some((first, [])) => first.to_string(),
                Some((first, rest)) => format!("{first} (+{} more)", rest.len()),
                None => "-".to_owned(),
            };
            [
                provider_name(item).unwrap_or("-").to_owned(),
                item.fingerprint.to_string(),
                status,
                source,
                item.scope
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), |s| s.identity.to_string()),
            ]
        })
        .collect();

    let mut widths = header.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let mut out = String::new();
    let mut line = |cells: [&str; 5]| {
        let mut text = String::new();
        for (i, (cell, width)) in cells.iter().zip(widths).enumerate() {
            if i + 1 == cells.len() {
                text.push_str(cell);
            } else {
                // Writing to a String cannot fail.
                let _ = write!(text, "{cell:<width$}  ");
            }
        }
        out.push_str(text.trim_end());
        out.push('\n');
    };
    line(header);
    for row in &rows {
        line([&row[0], &row[1], &row[2], &row[3], &row[4]]);
    }
    if !notes.is_empty() {
        out.push_str("\nNotes:\n");
        for note in notes {
            out.push_str(&note);
            out.push('\n');
        }
    }
    out
}

/// JSON view of one [`Assessed`]: fingerprints and metadata, never values.
#[derive(Serialize)]
struct AssessedView<'a> {
    provider: Option<&'static str>,
    fingerprint: &'a Fingerprint,
    status: &'static str,
    reason: Option<String>,
    detectors: &'a [String],
    sources: Vec<String>,
    scope: Option<ScopeView<'a>>,
    scope_error: Option<&'a str>,
}

#[derive(Serialize)]
struct ScopeView<'a> {
    identity: &'a str,
    lines: &'a [String],
}

/// Pretty-printed JSON array with one object per distinct secret. Field
/// names are part of the CLI contract.
pub fn render_json(assessed: &[Assessed]) -> String {
    let views: Vec<AssessedView<'_>> = assessed
        .iter()
        .map(|item| {
            let (status, reason) = status(item);
            AssessedView {
                provider: provider_name(item),
                fingerprint: &item.fingerprint,
                status,
                reason,
                detectors: &item.detectors,
                sources: item.sources.iter().map(ToString::to_string).collect(),
                scope: item.scope.as_ref().map(|scope| ScopeView {
                    identity: &scope.identity.0,
                    lines: &scope.lines,
                }),
                scope_error: item.scope_error.as_deref(),
            }
        })
        .collect();
    serde_json::to_string_pretty(&views).expect("the view holds only strings and lists")
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::calls::CallLog;
    use crate::provider::mock::MockProvider;
    use crate::provider::{Identity, Provider};
    use crate::secret::SecretValue;

    fn opts() -> AssessOptions {
        AssessOptions {
            base_delay: Duration::from_millis(1),
            ..AssessOptions::default()
        }
    }

    fn finding(value: &str, detector: &str, file: &str) -> Finding {
        Finding::new(
            SecretValue::from(value),
            detector,
            SourceLocation::file(file),
        )
    }

    fn registry(mocks: Vec<Arc<MockProvider>>) -> ProviderRegistry {
        let mut registry = ProviderRegistry::new();
        for mock in mocks {
            registry.register(mock);
        }
        registry
    }

    fn calls_to(log: &CallLog, method: &str) -> usize {
        log.calls().iter().filter(|c| c.method == method).count()
    }

    // T1 (AC1), T6 (AC6)
    #[tokio::test]
    async fn same_secret_three_files_is_one_assessment() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .log(log.clone()),
        );
        let findings = vec![
            finding("mock_same", "Mock", "a.env"),
            finding("mock_same", "Mock", "b.env"),
            finding("mock_same", "other-rule", "c.env"),
        ];
        let assessed = assess(findings, &registry(vec![mock]), &opts()).await;

        assert_eq!(assessed.len(), 1);
        let item = &assessed[0];
        assert_eq!(item.sources.len(), 3);
        assert_eq!(item.detectors, ["Mock", "other-rule"]);
        assert_eq!(item.validity, Some(Validity::Valid));
        assert_eq!(calls_to(&log, "check_valid"), 1);
        log.assert_no_mutations();
    }

    // T2 (AC2), T6 (AC6)
    #[tokio::test]
    async fn unknown_finding_is_unsupported() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .log(log.clone()),
        );
        let findings = vec![
            finding("zzz_unknown", "SomeScanner", "a.env"),
            finding("mock_known", "Mock", "b.env"),
        ];
        let assessed = assess(findings, &registry(vec![mock]), &opts()).await;

        assert_eq!(
            assessed[0].disposition,
            Disposition::Unsupported { reason: None }
        );
        assert_eq!(assessed[0].validity, None);
        assert_eq!(assessed[1].validity, Some(Validity::Valid));
        assert_eq!(calls_to(&log, "check_valid"), 1);
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn forced_provider_skips_identification() {
        let log = CallLog::new();
        let aws = Arc::new(MockProvider::new("aws").log(log.clone()));
        let github = Arc::new(
            MockProvider::new("github")
                .identify_prefix("ghp_")
                .log(log.clone()),
        );
        let reg = registry(vec![aws, github]);
        let forced = AssessOptions {
            force_provider: Some("aws"),
            ..opts()
        };
        let assessed = assess(vec![finding("ghp_x", "stdin", "stdin")], &reg, &forced).await;
        assert!(matches!(
            assessed[0].disposition,
            Disposition::Supported {
                provider: "aws",
                ..
            }
        ));
        assert_eq!(assessed[0].validity, Some(Validity::Valid));

        let unknown = AssessOptions {
            force_provider: Some("nope"),
            ..opts()
        };
        let assessed = assess(vec![finding("ghp_x", "stdin", "stdin")], &reg, &unknown).await;
        assert!(matches!(
            assessed[0].disposition,
            Disposition::Supported {
                provider: "github",
                ..
            }
        ));
        log.assert_no_mutations();
    }

    // T3 (AC3), T6 (AC6)
    #[tokio::test]
    async fn concurrency_is_bounded() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .validity(Validity::Invalid)
                .latency(Duration::from_millis(100))
                .log(log.clone()),
        );
        let findings = (0..20)
            .map(|i| finding(&format!("mock_{i}"), "Mock", "a.env"))
            .collect();
        let options = AssessOptions {
            concurrency: 4,
            ..opts()
        };

        let started = Instant::now();
        let assessed = assess(findings, &registry(vec![mock.clone()]), &options).await;
        let elapsed = started.elapsed();

        assert_eq!(assessed.len(), 20);
        assert!(assessed
            .iter()
            .all(|a| a.validity == Some(Validity::Invalid)));
        assert!(
            mock.max_in_flight() <= 4,
            "max in flight {}",
            mock.max_in_flight()
        );
        assert!(mock.max_in_flight() >= 2, "checks did not overlap");
        assert!(elapsed < Duration::from_secs(1), "took {elapsed:?}");
        log.assert_no_mutations();
    }

    // T4 (AC4), T6 (AC6)
    #[tokio::test]
    async fn retries_rate_limit_then_valid() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .log(log.clone()),
        );
        let limited = ProviderError::RateLimited { retry_after: None };
        mock.fail_next("check_valid", limited.clone());
        mock.fail_next("check_valid", limited);

        let assessed = assess(
            vec![finding("mock_x", "Mock", "a.env")],
            &registry(vec![mock]),
            &opts(),
        )
        .await;
        assert_eq!(assessed[0].validity, Some(Validity::Valid));
        assert_eq!(calls_to(&log, "check_valid"), 3);
        log.assert_no_mutations();
    }

    // T5 (AC5), T6 (AC6)
    #[tokio::test]
    async fn persistent_failure_is_unknown_others_continue() {
        let log = CallLog::new();
        let broken = Arc::new(
            MockProvider::new("broken")
                .identify_prefix("broken_")
                .log(log.clone()),
        );
        broken.fail_always(
            "check_valid",
            ProviderError::Transient("connection reset by peer".into()),
        );
        let good = Arc::new(
            MockProvider::new("good")
                .identify_prefix("good_")
                .log(log.clone()),
        );

        let assessed = assess(
            vec![
                finding("broken_x", "Mock", "a.env"),
                finding("good_x", "Mock", "b.env"),
            ],
            &registry(vec![broken, good]),
            &opts(),
        )
        .await;
        match &assessed[0].validity {
            Some(Validity::Unknown { reason }) => {
                assert!(reason.contains("connection reset by peer"), "{reason}")
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        assert_eq!(assessed[1].validity, Some(Validity::Valid));
        assert_eq!(calls_to(&log, "check_valid"), 3 + 1);
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn non_retryable_error_is_not_retried() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .log(log.clone()),
        );
        mock.fail_always(
            "check_valid",
            ProviderError::Permanent("401 bad credentials".into()),
        );

        let assessed = assess(
            vec![finding("mock_x", "Mock", "a.env")],
            &registry(vec![mock]),
            &opts(),
        )
        .await;
        assert_eq!(
            assessed[0].validity,
            Some(Validity::Unknown {
                reason: "401 bad credentials".into()
            })
        );
        assert_eq!(calls_to(&log, "check_valid"), 1);
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn retry_honours_retry_after() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .log(log.clone()),
        );
        mock.fail_next(
            "check_valid",
            ProviderError::RateLimited {
                retry_after: Some(Duration::from_millis(5)),
            },
        );
        // A base delay this long would time the test out if retry_after
        // were ignored.
        let options = AssessOptions {
            base_delay: Duration::from_secs(60),
            ..opts()
        };
        let started = Instant::now();
        let assessed = assess(
            vec![finding("mock_x", "Mock", "a.env")],
            &registry(vec![mock]),
            &options,
        )
        .await;
        assert_eq!(assessed[0].validity, Some(Validity::Valid));
        assert!(started.elapsed() < Duration::from_secs(5));
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn gitleaks_aws_key_id_is_not_rotatable_and_not_checked() {
        let log = CallLog::new();
        let aws = Arc::new(
            MockProvider::new("aws")
                .identify_prefix("AKIA")
                .log(log.clone()),
        );
        let assessed = assess(
            vec![finding("AKIAIOSFODNN7EXAMPLE", "aws-access-token", "a.env")],
            &registry(vec![aws]),
            &opts(),
        )
        .await;
        match &assessed[0].disposition {
            Disposition::NotRotatable { reason } => {
                assert!(reason.contains("--stdin"), "{reason}")
            }
            other => panic!("expected NotRotatable, got {other:?}"),
        }
        assert_eq!(assessed[0].validity, None);
        assert_eq!(calls_to(&log, "check_valid"), 0);
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn canary_is_not_rotatable_and_not_checked() {
        let log = CallLog::new();
        let aws = Arc::new(MockProvider::new("aws").log(log.clone()));
        let canary = finding("mock_secret", "AWS", "a.env")
            .with_extra(ACCESS_KEY_ID, "AKIAMOCK")
            .with_extra(IS_CANARY, "true");
        let assessed = assess(vec![canary], &registry(vec![aws]), &opts()).await;
        assert!(matches!(
            assessed[0].disposition,
            Disposition::NotRotatable { .. }
        ));
        assert_eq!(calls_to(&log, "check_valid"), 0);
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn dedupe_prefers_finding_with_key_id() {
        let log = CallLog::new();
        let aws = Arc::new(MockProvider::new("aws").log(log.clone()));
        let findings = vec![
            finding("mock_aws_secret", "generic-api-key", "gitleaks.env"),
            finding("mock_aws_secret", "AWS", "trufflehog.env")
                .with_extra(ACCESS_KEY_ID, "AKIAMOCK"),
        ];
        let assessed = assess(findings, &registry(vec![aws]), &opts()).await;

        assert_eq!(assessed.len(), 1);
        assert_eq!(assessed[0].credential.key_id(), Some("AKIAMOCK"));
        assert_eq!(assessed[0].detectors, ["generic-api-key", "AWS"]);
        assert_eq!(
            assessed[0].disposition,
            Disposition::Supported {
                provider: "aws",
                confidence: Confidence::High
            }
        );
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn hint_for_unregistered_provider_falls_back_to_pattern() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("ghp_")
                .log(log.clone()),
        );
        let assessed = assess(
            vec![finding("ghp_x", "Github", "a.env")],
            &registry(vec![mock]),
            &opts(),
        )
        .await;
        assert_eq!(
            assessed[0].disposition,
            Disposition::Supported {
                provider: "mock",
                confidence: Confidence::High
            }
        );
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn ambiguous_pattern_is_unsupported_with_reason() {
        let log = CallLog::new();
        let one = Arc::new(
            MockProvider::new("one")
                .identify_prefix("tok_")
                .log(log.clone()),
        );
        let two = Arc::new(
            MockProvider::new("two")
                .identify_prefix("tok_")
                .log(log.clone()),
        );
        let assessed = assess(
            vec![finding("tok_x", "Scanner", "a.env")],
            &registry(vec![one, two]),
            &opts(),
        )
        .await;
        match &assessed[0].disposition {
            Disposition::Unsupported {
                reason: Some(reason),
            } => {
                assert!(reason.contains("one") && reason.contains("two"), "{reason}")
            }
            other => panic!("expected Unsupported with a reason, got {other:?}"),
        }
        assert_eq!(calls_to(&log, "check_valid"), 0);
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn scope_failure_keeps_validity() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .log(log.clone()),
        );
        mock.fail_always(
            "describe_scope",
            ProviderError::Permanent("iam:ListAttachedUserPolicies denied".into()),
        );
        let assessed = assess(
            vec![finding("mock_x", "Mock", "a.env")],
            &registry(vec![mock]),
            &opts(),
        )
        .await;
        assert_eq!(assessed[0].validity, Some(Validity::Valid));
        assert_eq!(assessed[0].scope, None);
        assert_eq!(
            assessed[0].scope_error.as_deref(),
            Some("iam:ListAttachedUserPolicies denied")
        );
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn valid_secret_gets_scope() {
        let log = CallLog::new();
        let mock = Arc::new(
            MockProvider::new("mock")
                .identify_prefix("mock_")
                .log(log.clone()),
        );
        let assessed = assess(
            vec![finding("mock_x", "Mock", "a.env")],
            &registry(vec![mock]),
            &opts(),
        )
        .await;
        let scope = assessed[0].scope.as_ref().unwrap();
        assert_eq!(scope.identity, Identity("mock-user".into()));
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn render_table_shows_every_status() {
        let log = CallLog::new();
        let good = Arc::new(
            MockProvider::new("good")
                .identify_prefix("good_")
                .log(log.clone()),
        );
        let findings = vec![
            finding("good_x", "Mock", "a.env"),
            finding("good_x", "Mock", "b.env"),
            finding("zzz", "Scanner", "c.env"),
            finding("AKIAIOSFODNN7EXAMPLE", "aws-access-token", "d.env"),
        ];
        let assessed = assess(findings, &registry(vec![good]), &opts()).await;
        let table = render_table(&assessed);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 7, "{table}");
        assert!(lines[3].contains("not rotatable"), "{table}");
        assert!(
            !lines[3].contains("gitleaks reports"),
            "reason belongs in the notes"
        );
        assert_eq!(lines[5], "Notes:");
        assert!(
            lines[6].contains(assessed[2].fingerprint.as_str()),
            "{table}"
        );
        assert!(
            lines[6].contains("not rotatable: gitleaks reports only"),
            "{table}"
        );
        assert!(lines[0].starts_with("PROVIDER"));
        assert!(lines[1].starts_with("good"), "{table}");
        assert!(lines[1].contains("valid"));
        assert!(lines[1].contains("a.env (+1 more)"));
        assert!(lines[1].contains("good-user"));
        assert!(lines[2].starts_with('-'), "{table}");
        assert!(lines[2].contains("unsupported"));
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn json_schema_fields_stable() {
        let log = CallLog::new();
        let good = Arc::new(
            MockProvider::new("good")
                .identify_prefix("good_")
                .log(log.clone()),
        );
        let assessed = assess(
            vec![
                finding("good_x", "Mock", "a.env"),
                finding("zzz", "Scanner", "c.env"),
            ],
            &registry(vec![good]),
            &opts(),
        )
        .await;
        let json: serde_json::Value = serde_json::from_str(&render_json(&assessed)).unwrap();
        let rows = json.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            let mut keys: Vec<&str> = row
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "detectors",
                    "fingerprint",
                    "provider",
                    "reason",
                    "scope",
                    "scope_error",
                    "sources",
                    "status"
                ]
            );
        }
        assert_eq!(rows[0]["provider"], "good");
        assert_eq!(rows[0]["status"], "valid");
        assert_eq!(rows[0]["scope"]["identity"], "good-user");
        assert_eq!(rows[0]["sources"][0], "a.env");
        assert_eq!(rows[1]["provider"], serde_json::Value::Null);
        assert_eq!(rows[1]["status"], "unsupported");
        log.assert_no_mutations();
    }

    #[tokio::test]
    async fn mock_latency_tracks_in_flight() {
        let mock = Arc::new(MockProvider::new("mock").latency(Duration::from_millis(20)));
        let cred = Credential::Token(SecretValue::from("mock_x"));
        let (a, b) = tokio::join!(mock.check_valid(&cred), mock.check_valid(&cred));
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(mock.max_in_flight(), 2);
    }
}
