//! Betterleaks reports (SHA-202), from Betterleaks 1.x and 2.x.
//!
//! - v1 (`--report-format json`, 1.9.0): one JSON array. Each finding has
//!   the gitleaks fields (`RuleID`, `Secret`, `File`, `StartLine`,
//!   `Commit`) plus `ComponentSets`.
//! - v2 (`--output report.json`, 2.0.0-rc.1): one object with
//!   `schema_version`, `findings` and `scan`. With `--output report.jsonl`
//!   it is one `{"schema_version":"1","finding":{...}}` record per line and
//!   a final `scan` record. Findings use `rule_id`, `match.value`,
//!   `location.path`, `location.start_line`, `attributes["git.sha"]` and
//!   `component_sets`.
//!
//! The rule ids are the gitleaks ones, so the detector hints are shared.
//! Unlike gitleaks, Betterleaks pairs an AWS key: `aws-access-token`
//! matches the access key id and requires an `aws-secret-access-key`
//! component within five lines, reported in `component_sets`. Each set is
//! one candidate pair. The secret half comes from the only distinct
//! candidate; when Betterleaks validated the sets, only the ones it marked
//! `valid` count. Component sets are parsed only for that rule, so an
//! odd shape cannot drop another rule's finding. Several candidates
//! (even several marked valid) are skipped: as for GitHub alerts,
//! rotate never tries a candidate against AWS to find the pair
//! (`docs/plans/SHA-198.md`, maintainer decision 5).
//!
//! Sources: `report/finding.go` and `config/betterleaks.toml` at the
//! v1.9.0 tag and at v2.0.0-rc.1 of github.com/betterleaks/betterleaks,
//! and its `docs/schemas/findings.schema.json` (2.x).
//!
//! The format is never detected: a v1 report starts with `[` like
//! gitleaks, and v2 starts with `{` like TruffleHog, so it must be named
//! with `--format betterleaks`. Each top-level value is split into raw
//! elements borrowed from the input first, so one bad finding is skipped
//! with a warning instead of failing the document. `Match`,
//! `match.full`, captures and context are never read: they hold the secret
//! plus surrounding text.

use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;

use super::{
    line_of, non_empty, ParsedReport, ReportError, ReportFormat, SkipReason, UNKNOWN_FILE,
};
use crate::finding::{Finding, SourceLocation, ACCESS_KEY_ID};
use crate::secret::SecretValue;

/// Rule that matches the access key id half of an AWS key pair.
const AWS_KEY_ID_RULE: &str = "aws-access-token";

/// Component rule that matches the secret access key half.
const AWS_SECRET_RULE: &str = "aws-secret-access-key";

/// Validation status of a component set Betterleaks confirmed.
const VALID: &str = "valid";

/// What `--redact` (100%) writes in place of a value.
const REDACTED: &[u8] = b"REDACTED";

/// What `--redact=N` (below 100%) appends to the kept prefix.
const PARTIAL_MASK: &[u8] = b"...";

const FORMAT: ReportFormat = ReportFormat::Betterleaks;

// --- v1 ---------------------------------------------------------------------

/// A v1 finding. Only these fields are read; everything else (including
/// `Match`, `MatchContext`, `CaptureGroups` and `Attributes`) is skipped
/// by serde without a copy.
#[derive(Deserialize)]
struct V1Finding<'a> {
    #[serde(rename = "RuleID")]
    rule: String,
    #[serde(rename = "Secret", default)]
    secret: Option<SecretValue>,
    #[serde(rename = "File", default)]
    file: Option<String>,
    #[serde(rename = "StartLine", default)]
    line: Option<u64>,
    #[serde(rename = "Commit", default)]
    commit: Option<String>,
    /// Kept raw and read only for `aws-access-token` ([`Sets`]).
    #[serde(rename = "ComponentSets", borrow, default)]
    sets: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct V1Set {
    #[serde(default)]
    components: Option<Vec<Option<V1Component>>>,
    #[serde(rename = "validationStatus", default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct V1Component {
    #[serde(rename = "RuleID")]
    rule: String,
    #[serde(rename = "Secret", default)]
    secret: Option<SecretValue>,
}

// --- v2 ---------------------------------------------------------------------

/// A top-level v2 object: a JSON report (`findings`), a JSON lines
/// finding record (`finding`) or the scan record (`scan`). The findings
/// stay raw, borrowed from the input.
#[derive(Deserialize)]
struct V2Record<'a> {
    #[serde(borrow, default)]
    findings: Option<Vec<&'a RawValue>>,
    #[serde(borrow, default)]
    finding: Option<&'a RawValue>,
    #[serde(default)]
    scan: Option<IgnoredAny>,
}

#[derive(Deserialize)]
struct V2Finding<'a> {
    rule_id: String,
    #[serde(rename = "match", default)]
    matched: Option<V2Match>,
    #[serde(default)]
    location: Option<V2Location>,
    #[serde(default)]
    attributes: Option<V2Attributes>,
    /// Kept raw and read only for `aws-access-token` ([`Sets`]).
    #[serde(borrow, default)]
    component_sets: Option<&'a RawValue>,
}

/// `match`: only `value` is read.
#[derive(Deserialize)]
struct V2Match {
    #[serde(default)]
    value: Option<SecretValue>,
}

#[derive(Deserialize)]
struct V2Location {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    start_line: Option<u64>,
}

/// `attributes`: only the commit is read.
#[derive(Deserialize)]
struct V2Attributes {
    #[serde(rename = "git.sha", default)]
    commit: Option<String>,
}

#[derive(Deserialize)]
struct V2Set {
    #[serde(default)]
    components: Option<Vec<Option<V2Component>>>,
    #[serde(default)]
    analysis: Option<V2Analysis>,
}

#[derive(Deserialize)]
struct V2Component {
    rule_id: String,
    #[serde(rename = "match", default)]
    matched: Option<V2Match>,
}

#[derive(Deserialize)]
struct V2Analysis {
    #[serde(default)]
    status: Option<String>,
}

// --- common -----------------------------------------------------------------

/// A finding of either version, reduced to what rotate reads.
struct Leak<'a> {
    rule: String,
    secret: Option<SecretValue>,
    source: SourceLocation,
    sets: Sets<'a>,
}

/// The raw component sets of a finding. They are only read for
/// `aws-access-token`: no other rule rotate supports has components, and
/// an unexpected shape must not drop another rule's finding.
enum Sets<'a> {
    None,
    V1(&'a RawValue),
    V2(&'a RawValue),
}

/// One component set: one candidate combination of component values.
struct Set {
    valid: bool,
    components: Vec<(String, Option<SecretValue>)>,
}

impl Sets<'_> {
    fn read(self) -> Result<Vec<Set>, serde_json::Error> {
        Ok(match self {
            Sets::None => Vec::new(),
            Sets::V1(raw) => serde_json::from_str::<Option<Vec<V1Set>>>(raw.get())?
                .unwrap_or_default()
                .into_iter()
                .map(|set| Set {
                    valid: set.status.as_deref() == Some(VALID),
                    components: set
                        .components
                        .unwrap_or_default()
                        .into_iter()
                        .flatten()
                        .map(|c| (c.rule, c.secret))
                        .collect(),
                })
                .collect(),
            Sets::V2(raw) => serde_json::from_str::<Option<Vec<V2Set>>>(raw.get())?
                .unwrap_or_default()
                .into_iter()
                .map(|set| Set {
                    valid: set.analysis.and_then(|a| a.status).as_deref() == Some(VALID),
                    components: set
                        .components
                        .unwrap_or_default()
                        .into_iter()
                        .flatten()
                        .map(|c| (c.rule_id, c.matched.and_then(|m| m.value)))
                        .collect(),
                })
                .collect(),
        })
    }
}

impl<'a> From<V1Finding<'a>> for Leak<'a> {
    fn from(f: V1Finding<'a>) -> Self {
        Leak {
            rule: f.rule,
            secret: f.secret,
            source: source(f.file, f.line, f.commit),
            sets: f.sets.map_or(Sets::None, Sets::V1),
        }
    }
}

impl<'a> From<V2Finding<'a>> for Leak<'a> {
    fn from(f: V2Finding<'a>) -> Self {
        let (file, line) = f.location.map_or((None, None), |l| (l.path, l.start_line));
        Leak {
            rule: f.rule_id,
            secret: f.matched.and_then(|m| m.value),
            source: source(file, line, f.attributes.and_then(|a| a.commit)),
            sets: f.component_sets.map_or(Sets::None, Sets::V2),
        }
    }
}

fn source(file: Option<String>, line: Option<u64>, commit: Option<String>) -> SourceLocation {
    SourceLocation {
        file: file
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| UNKNOWN_FILE.to_owned()),
        line,
        commit: commit.filter(|c| !c.is_empty()),
    }
}

/// A finding element and the version that wrote it.
enum Element<'a> {
    V1(&'a RawValue),
    V2(&'a RawValue),
}

pub(super) fn parse(body: &[u8]) -> Result<ParsedReport, ReportError> {
    let mut report = ParsedReport::new(FORMAT);
    for (line, element) in elements(body, &mut report)? {
        let leak = match element {
            Element::V1(raw) => decode::<V1Finding<'_>>(&mut report, line, raw).map(Leak::from),
            Element::V2(raw) => decode::<V2Finding<'_>>(&mut report, line, raw).map(Leak::from),
        };
        if let Some(leak) = leak {
            match leak.into_finding() {
                Ok(finding) => report.findings.push(finding),
                Err(reason) => report.skip(FORMAT, line, reason),
            }
        }
    }
    Ok(report)
}

/// Deserializes one finding that starts on `line`, or records why it was
/// skipped.
fn decode<'a, T: Deserialize<'a>>(
    report: &mut ParsedReport,
    line: usize,
    raw: &'a RawValue,
) -> Option<T> {
    match serde_json::from_str::<T>(raw.get()) {
        Ok(value) => Some(value),
        Err(err) => {
            // serde counts lines from the start of the element.
            let line = line + err.line().saturating_sub(1);
            report.skip(FORMAT, line, SkipReason::from_json(&err));
            None
        }
    }
}

/// Every finding in the document with the line it starts on.
///
/// A document that is not a sequence of JSON values is refused by line and
/// column; serde_json's message is never used because it can repeat the
/// input. A well-formed value that is not a v1 array or a v2 report,
/// finding or scan record is refused when it comes first (the input is not
/// Betterleaks at all) and skipped with a warning after that (a record
/// kind a later Betterleaks may add to its JSON lines).
fn elements<'a>(
    body: &'a [u8],
    report: &mut ParsedReport,
) -> Result<Vec<(usize, Element<'a>)>, ReportError> {
    let at = |raw: &RawValue| line_of(body, raw.get());
    let mut out = Vec::new();
    let mut known = false;
    for value in serde_json::Deserializer::from_slice(body).into_iter::<&RawValue>() {
        let value = value.map_err(|err| ReportError::Malformed {
            format: FORMAT,
            line: err.line(),
            column: err.column(),
        })?;
        let line = at(value);
        let found = match value.get().as_bytes().first() {
            Some(b'[') => serde_json::from_str::<Vec<&RawValue>>(value.get())
                .ok()
                .map(|items| items.into_iter().map(|i| (at(i), Element::V1(i))).collect()),
            Some(b'{') => match serde_json::from_str::<V2Record<'_>>(value.get()) {
                Ok(V2Record {
                    findings: Some(findings),
                    ..
                }) => Some(
                    findings
                        .into_iter()
                        .map(|f| (at(f), Element::V2(f)))
                        .collect(),
                ),
                Ok(V2Record {
                    finding: Some(finding),
                    ..
                }) => Some(vec![(at(finding), Element::V2(finding))]),
                Ok(V2Record { scan: Some(_), .. }) => Some(Vec::new()),
                _ => None,
            },
            _ => None,
        };
        match found {
            Some(elements) => {
                known = true;
                out.extend(elements);
            }
            None if known => report.skip(FORMAT, line, SkipReason::UnknownRecord),
            None => return Err(ReportError::NotBetterleaks { line }),
        }
    }
    Ok(out)
}

impl Leak<'_> {
    fn into_finding(self) -> Result<Finding, SkipReason> {
        let secret = usable(self.secret)?;
        if self.rule != AWS_KEY_ID_RULE {
            return Ok(Finding::new(secret, self.rule, self.source));
        }
        // The primary value is the access key id. It is not secret, so a
        // plain copy is fine.
        let key_id = secret
            .expose_secret_str(str::to_owned)
            .map_err(|_| SkipReason::AwsIncomplete)?;
        let sets = self
            .sets
            .read()
            .map_err(|err| SkipReason::from_json(&err))?;
        let secret_key = aws_secret(sets)?;
        Ok(Finding::new(secret_key, self.rule, self.source).with_extra(ACCESS_KEY_ID, key_id))
    }
}

/// A non-empty value that `--redact` did not mask.
fn usable(value: Option<SecretValue>) -> Result<SecretValue, SkipReason> {
    let value = non_empty(value).ok_or(SkipReason::EmptySecret)?;
    if value.expose_secret(|b| b == REDACTED || b.ends_with(PARTIAL_MASK)) {
        return Err(SkipReason::Redacted);
    }
    Ok(value)
}

/// The secret access key of an `aws-access-token` finding: the only
/// distinct `aws-secret-access-key` value across its component sets, or
/// across the sets marked valid when there are any.
fn aws_secret(sets: Vec<Set>) -> Result<SecretValue, SkipReason> {
    let any_valid = sets.iter().any(|s| s.valid);
    let mut candidates: Vec<SecretValue> = Vec::new();
    for set in sets.into_iter().filter(|s| s.valid || !any_valid) {
        for (rule, value) in set.components {
            if rule != AWS_SECRET_RULE {
                continue;
            }
            let Some(value) = non_empty(value) else {
                continue;
            };
            let value = usable(Some(value))?;
            if !candidates.contains(&value) {
                candidates.push(value);
            }
        }
    }
    match candidates.len() {
        0 => Err(SkipReason::AwsIncomplete),
        1 => Ok(candidates.remove(0)),
        n => Err(SkipReason::AwsAmbiguous { candidates: n }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assess::hint;
    use crate::report::parse_report;

    const V1: &[u8] = include_bytes!("../../tests/fixtures/betterleaks.json");
    const V2: &[u8] = include_bytes!("../../tests/fixtures/betterleaks_v2.json");
    const V2_JSONL: &[u8] = include_bytes!("../../tests/fixtures/betterleaks_v2.jsonl");
    const TRUFFLEHOG: &[u8] = include_bytes!("../../tests/fixtures/trufflehog.ndjson");

    const AWS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const OTHER_SECRET: &str = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY";
    const COMMIT: &str = "9f2c1e4b7a3d5f6e8c0b1a2d3e4f5a6b7c8d9e0f";

    fn parse(input: &[u8]) -> ParsedReport {
        parse_report(input, Some(ReportFormat::Betterleaks)).unwrap()
    }

    /// `(detector hint, fingerprint, access key id)` of each finding.
    fn hinted(report: &ParsedReport) -> Vec<(Option<&'static str>, String, Option<String>)> {
        report
            .findings
            .iter()
            .map(|f| {
                (
                    hint(&f.detector),
                    f.fingerprint().to_string(),
                    f.extra.get(ACCESS_KEY_ID).cloned(),
                )
            })
            .collect()
    }

    // SHA-202 T1 (AC1): each Betterleaks fixture yields the TruffleHog
    // fixture's findings: same fingerprints (the AWS one is the secret
    // access key's) and the same detector hints.
    #[test]
    fn sha202_t1_fixtures_match_the_trufflehog_findings() {
        let expected = hinted(&parse_report(TRUFFLEHOG, None).unwrap());
        assert_eq!(
            expected
                .iter()
                .map(|(h, _, _)| h.unwrap_or("none"))
                .collect::<Vec<_>>(),
            ["aws", "github", "npm"]
        );
        for (name, fixture) in [("v1", V1), ("v2", V2), ("v2 jsonl", V2_JSONL)] {
            let report = parse(fixture);
            assert_eq!(report.format, Some(ReportFormat::Betterleaks), "{name}");
            assert!(report.warnings.is_empty(), "{name}: {:?}", report.warnings);
            assert_eq!(hinted(&report), expected, "{name}");
            let detectors: Vec<&str> = report.findings.iter().map(|f| &*f.detector).collect();
            assert_eq!(
                detectors,
                ["aws-access-token", "github-pat", "npm-access-token"],
                "{name}"
            );
            let sources: Vec<String> = report
                .findings
                .iter()
                .map(|f| f.source.to_string())
                .collect();
            assert_eq!(
                sources,
                ["deploy/aws.env:3", "src/app.js:12", ".npmrc:1"],
                "{name}"
            );
            let aws = &report.findings[0];
            assert_eq!(aws.raw, SecretValue::from(AWS_SECRET), "{name}");
            assert_eq!(aws.credential().key_id(), Some(AWS_KEY_ID), "{name}");
        }
    }

    // SHA-202 T1 (AC1): every rule id of the four providers is a hint.
    #[test]
    fn sha202_t1_rule_ids_are_detector_hints() {
        for (rule, provider) in [
            ("aws-access-token", "aws"),
            ("github-pat", "github"),
            ("github-fine-grained-pat", "github"),
            ("github-oauth", "github"),
            ("github-app-token", "github"),
            ("npm-access-token", "npm"),
            ("openai-api-key", "openai"),
        ] {
            assert_eq!(hint(rule), Some(provider), "{rule}");
        }
        assert_eq!(hint("github-refresh-token"), None);
        assert_eq!(hint(AWS_SECRET_RULE), None);
    }

    #[test]
    fn never_detected() {
        // v1 looks like gitleaks; v2 starts like TruffleHog.
        let v1 = parse_report(V1, None).unwrap();
        assert_eq!(v1.format, Some(ReportFormat::Gitleaks));
        assert!(v1.findings[0].extra.is_empty());
        assert_eq!(
            super::super::detect_format(V2),
            super::super::Detected::Format(ReportFormat::Trufflehog)
        );
    }

    #[test]
    fn empty_inputs() {
        for input in [
            &b""[..],
            b" \n",
            b"[]",
            b"{\"schema_version\":\"1\",\"scan\":{}}",
        ] {
            let report = parse(input);
            assert!(report.findings.is_empty() && report.warnings.is_empty());
        }
        let report = parse(br#"{"schema_version":"1","findings":[],"scan":{}}"#);
        assert!(report.findings.is_empty() && report.warnings.is_empty());
    }

    #[test]
    fn v1_commit_and_v2_git_sha_are_read() {
        let v1 = format!(
            r#"[{{"RuleID":"github-pat","Secret":"ghp_a","File":"a.js","StartLine":4,"Commit":"{COMMIT}"}}]"#
        );
        let v2 = format!(
            r#"{{"schema_version":"1","finding":{{"rule_id":"github-pat","match":{{"full":"x","value":"ghp_a"}},"attributes":{{"git.sha":"{COMMIT}","git.message":"ghp_CANARY"}},"location":{{"path":"a.js","start_line":4}}}}}}"#
        );
        for input in [v1, v2] {
            let report = parse(input.as_bytes());
            assert!(report.warnings.is_empty(), "{:?}", report.warnings);
            assert_eq!(
                report.findings[0].source.to_string(),
                format!("a.js:4@{COMMIT}")
            );
        }
    }

    /// The report versions, for tests that build findings of both.
    #[derive(Clone, Copy, Debug)]
    enum Version {
        V1,
        V2,
    }

    const VERSIONS: [Version; 2] = [Version::V1, Version::V2];

    /// An `aws-access-token` finding on line 1 with `sets` as its raw
    /// component sets.
    fn aws_finding(version: Version, sets: &str) -> Vec<u8> {
        match version {
            Version::V1 => format!(
                r#"[{{"RuleID":"aws-access-token","Match":"{AWS_KEY_ID}","Secret":"{AWS_KEY_ID}","File":"a.env","StartLine":1,"ComponentSets":{sets}}}]"#
            ),
            Version::V2 => format!(
                r#"{{"schema_version":"1","finding":{{"rule_id":"aws-access-token","match":{{"full":"{AWS_KEY_ID}","value":"{AWS_KEY_ID}"}},"location":{{"path":"a.env","start_line":1}},"component_sets":{sets}}}}}"#
            ),
        }
        .into_bytes()
    }

    /// One component set holding `secret`, with Betterleaks' validation
    /// status when given.
    fn set(version: Version, secret: &str, status: Option<&str>) -> String {
        match version {
            Version::V1 => {
                let status =
                    status.map_or(String::new(), |s| format!(r#","validationStatus":"{s}""#));
                format!(
                    r#"{{"components":[{{"RuleID":"aws-secret-access-key","Optional":false,"Match":"k={secret}","Secret":"{secret}"}}]{status}}}"#
                )
            }
            Version::V2 => {
                let analysis = status.map_or(String::new(), |s| {
                    format!(r#","analysis":{{"status":"{s}"}}"#)
                });
                format!(
                    r#"{{"components":[{{"rule_id":"aws-secret-access-key","match":{{"full":"k={secret}","value":"{secret}"}}}}]{analysis}}}"#
                )
            }
        }
    }

    fn sets(version: Version, entries: &[(&str, Option<&str>)]) -> String {
        let sets: Vec<String> = entries
            .iter()
            .map(|(secret, status)| set(version, secret, *status))
            .collect();
        format!("[{}]", sets.join(","))
    }

    #[test]
    fn aws_pair_uses_the_only_or_the_valid_candidate() {
        for version in VERSIONS {
            let cases = [
                // The same secret in two sets is one candidate.
                vec![(AWS_SECRET, None), (AWS_SECRET, None)],
                // Only the set Betterleaks marked valid counts.
                vec![(OTHER_SECRET, Some("invalid")), (AWS_SECRET, Some("valid"))],
                vec![(AWS_SECRET, Some("valid")), (OTHER_SECRET, Some("unknown"))],
            ];
            for entries in cases {
                let report = parse(&aws_finding(version, &sets(version, &entries)));
                assert!(
                    report.warnings.is_empty(),
                    "{version:?}: {:?}",
                    report.warnings
                );
                let aws = &report.findings[0];
                assert_eq!(aws.raw, SecretValue::from(AWS_SECRET), "{version:?}");
                assert_eq!(aws.credential().key_id(), Some(AWS_KEY_ID), "{version:?}");
            }
        }
    }

    #[test]
    fn aws_without_one_pair_is_skipped() {
        for version in VERSIONS {
            let cases = [
                ("[]".to_owned(), SkipReason::AwsIncomplete),
                ("null".to_owned(), SkipReason::AwsIncomplete),
                (
                    r#"[{"components":null},{"components":[null]}]"#.to_owned(),
                    SkipReason::AwsIncomplete,
                ),
                (
                    sets(version, &[(AWS_SECRET, None), (OTHER_SECRET, None)]),
                    SkipReason::AwsAmbiguous { candidates: 2 },
                ),
                // Two sets marked valid are still two candidates.
                (
                    sets(
                        version,
                        &[(AWS_SECRET, Some("valid")), (OTHER_SECRET, Some("valid"))],
                    ),
                    SkipReason::AwsAmbiguous { candidates: 2 },
                ),
            ];
            for (sets, reason) in cases {
                let report = parse(&aws_finding(version, &sets));
                assert!(report.findings.is_empty(), "{version:?}");
                assert_eq!(report.warnings[0].reason, reason, "{version:?}");
                assert_eq!(report.warnings[0].line, 1);
                let rendered = report.warnings[0].to_string();
                assert!(!rendered.contains("EXAMPLEKEY"), "{rendered}");
            }
        }
        let rendered = SkipReason::AwsAmbiguous { candidates: 2 }.to_string();
        assert!(rendered.contains("if any"), "{rendered}");
    }

    #[test]
    fn redacted_values_are_skipped() {
        for value in ["REDACTED", "ghp_aB3d..."] {
            let input = format!(r#"[{{"RuleID":"github-pat","Secret":"{value}","File":"a"}}]"#);
            let report = parse(input.as_bytes());
            assert!(report.findings.is_empty());
            assert_eq!(report.warnings[0].reason, SkipReason::Redacted);
        }
        for version in VERSIONS {
            for value in ["REDACTED", "wJalrXUtnFEMI/K7..."] {
                let input = aws_finding(version, &sets(version, &[(value, None)]));
                let report = parse(&input);
                assert!(report.findings.is_empty(), "{version:?}");
                assert_eq!(report.warnings[0].reason, SkipReason::Redacted);
            }
        }
    }

    // Component sets are only read for AWS: an odd shape on another rule
    // does not drop its finding.
    #[test]
    fn odd_component_sets_only_matter_for_aws() {
        for odd in [
            r#""weird""#,
            "7",
            r#"{"components":1}"#,
            r#"[{"components":"x"}]"#,
        ] {
            let v1 = format!(
                r#"[{{"RuleID":"github-pat","Secret":"ghp_a","File":"a.js","ComponentSets":{odd}}}]"#
            );
            let v2 = format!(
                r#"{{"schema_version":"1","finding":{{"rule_id":"github-pat","match":{{"full":"x","value":"ghp_a"}},"component_sets":{odd}}}}}"#
            );
            for input in [v1, v2] {
                let report = parse(input.as_bytes());
                assert!(report.warnings.is_empty(), "{odd}: {:?}", report.warnings);
                assert_eq!(report.findings.len(), 1, "{odd}");
            }
            for version in VERSIONS {
                let report = parse(&aws_finding(version, odd));
                assert!(report.findings.is_empty());
                assert!(
                    matches!(report.warnings[0].reason, SkipReason::WrongShape { .. }),
                    "{odd}: {:?}",
                    report.warnings
                );
            }
        }
    }

    #[test]
    fn bad_finding_is_skipped_with_its_line() {
        let input = br#"{"schema_version":"1","findings":[
 {"rule_id":"github-pat","match":{"full":"x","value":"ghp_a"}},
 {"rule_id":"github-pat",
  "match":{"full":"ghp_CANARYbadFinding","value":7}},
 {"rule_id":"npm-access-token","match":{"full":"","value":""}}
],"scan":{}}"#;
        let report = parse(input);
        assert_eq!(report.findings.len(), 1);
        let warnings: Vec<_> = report.warnings.iter().map(|w| (w.line, w.reason)).collect();
        assert_eq!(warnings[0].0, 4);
        assert!(matches!(warnings[0].1, SkipReason::WrongShape { .. }));
        assert_eq!(warnings[1], (5, SkipReason::EmptySecret));
        assert!(!format!("{:?}", report.warnings).contains("CANARY"));
    }

    fn jsonl_lines() -> Vec<&'static [u8]> {
        V2_JSONL
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .collect()
    }

    #[test]
    fn jsonl_blank_lines_and_missing_scan_record() {
        let lines = jsonl_lines();
        assert_eq!(lines.len(), 4);
        // Blank lines (and CRLF) between records.
        let spaced = [
            &b"\r\n"[..],
            lines[0],
            b"\r\n\r\n",
            lines[1],
            b"\n\n\n",
            lines[2],
            b"\n",
            lines[3],
            b"\n\n",
        ]
        .concat();
        // No final scan record, as when the scan was cut short.
        let unfinished = [lines[0], b"\n", lines[1], b"\n", lines[2], b"\n"].concat();
        for input in [spaced, unfinished] {
            let report = parse(&input);
            assert!(report.warnings.is_empty(), "{:?}", report.warnings);
            assert_eq!(hinted(&report), hinted(&parse(V2_JSONL)));
        }

        // A bad record keeps its own line number past the blank lines.
        let bad = [&b"\n\n"[..], lines[0], b"\n\n", br#"{"schema_version":"1","finding":{"rule_id":"github-pat","match":{"full":"ghp_CANARY","value":7}}}"#, b"\n"].concat();
        let report = parse(&bad);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.warnings[0].line, 5);
        assert!(!format!("{:?}", report.warnings).contains("CANARY"));
    }

    #[test]
    fn jsonl_unknown_record_kind_is_skipped_after_a_known_one() {
        let lines = jsonl_lines();
        let unknown = br#"{"schema_version":"2","note":"ghp_CANARYunknownKind"}"#;
        let input = [
            lines[0],
            b"\n",
            unknown,
            b"\n",
            lines[1],
            b"\n",
            b"\"ghp_CANARYstring\"",
            b"\n",
            lines[2],
            b"\n",
            lines[3],
            b"\n",
        ]
        .concat();
        let report = parse(&input);
        assert_eq!(report.findings.len(), 3);
        let warnings: Vec<_> = report.warnings.iter().map(|w| (w.line, w.reason)).collect();
        assert_eq!(
            warnings,
            [
                (2, SkipReason::UnknownRecord),
                (4, SkipReason::UnknownRecord)
            ]
        );
        let rendered = format!("{:?} {}", report.warnings, report.warnings[0]);
        assert!(!rendered.contains("CANARY"), "{rendered}");

        // TruffleHog lines after Betterleaks ones are skipped the same way.
        let mut mixed = V2_JSONL.to_vec();
        mixed.extend_from_slice(TRUFFLEHOG);
        let report = parse(&mixed);
        assert_eq!(report.findings.len(), 3);
        let lines: Vec<usize> = report.warnings.iter().map(|w| w.line).collect();
        assert_eq!(lines, [5, 6, 7]);
    }

    #[test]
    fn malformed_and_foreign_documents_are_refused() {
        let cut = &V2[..V2.windows(4).position(|w| w == b"ghp_").unwrap() + 8];
        let err = parse_report(cut, Some(ReportFormat::Betterleaks)).unwrap_err();
        assert!(matches!(
            err,
            ReportError::Malformed {
                format: ReportFormat::Betterleaks,
                ..
            }
        ));
        assert!(!err.to_string().contains("ghp_"), "{err}");

        // Malformed JSON after known records is still refused.
        let mut jsonl_then_cut = V2_JSONL.to_vec();
        jsonl_then_cut.extend_from_slice(b"{\"finding\":{\"rule_id\":\"ghp_CANARY");
        let err = parse_report(&jsonl_then_cut, Some(ReportFormat::Betterleaks)).unwrap_err();
        assert!(
            matches!(err, ReportError::Malformed { line: 5, .. }),
            "{err:?}"
        );
        assert!(!err.to_string().contains("CANARY"));

        // An unknown first record means the input is not Betterleaks.
        for (input, line) in [
            (TRUFFLEHOG, 1),
            (&b"\n\"ghp_CANARY\""[..], 2),
            (
                &b"{\"schema_version\":\"1\",\"note\":\"ghp_CANARY\"}\n"[..],
                1,
            ),
        ] {
            let err = parse_report(input, Some(ReportFormat::Betterleaks)).unwrap_err();
            assert!(
                matches!(err, ReportError::NotBetterleaks { line: l } if l == line),
                "{err:?}"
            );
            let text = err.to_string();
            assert!(
                !text.contains("CANARY") && !text.contains(AWS_KEY_ID),
                "{text}"
            );
        }
    }
}
