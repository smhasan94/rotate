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
//! `valid` count. Several candidates are skipped: as for GitHub alerts,
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
struct V1Finding {
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
    #[serde(rename = "ComponentSets", default)]
    sets: Option<Vec<V1Set>>,
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
struct V2Finding {
    rule_id: String,
    #[serde(rename = "match", default)]
    matched: Option<V2Match>,
    #[serde(default)]
    location: Option<V2Location>,
    #[serde(default)]
    attributes: Option<V2Attributes>,
    #[serde(default)]
    component_sets: Option<Vec<V2Set>>,
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
struct Leak {
    rule: String,
    secret: Option<SecretValue>,
    source: SourceLocation,
    sets: Vec<Set>,
}

/// One component set: one candidate combination of component values.
struct Set {
    valid: bool,
    components: Vec<(String, Option<SecretValue>)>,
}

impl From<V1Finding> for Leak {
    fn from(f: V1Finding) -> Self {
        let sets = f.sets.unwrap_or_default().into_iter().map(|set| Set {
            valid: set.status.as_deref() == Some(VALID),
            components: set
                .components
                .unwrap_or_default()
                .into_iter()
                .flatten()
                .map(|c| (c.rule, c.secret))
                .collect(),
        });
        Leak {
            rule: f.rule,
            secret: f.secret,
            source: source(f.file, f.line, f.commit),
            sets: sets.collect(),
        }
    }
}

impl From<V2Finding> for Leak {
    fn from(f: V2Finding) -> Self {
        let sets = f
            .component_sets
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
            });
        let (file, line) = f.location.map_or((None, None), |l| (l.path, l.start_line));
        Leak {
            rule: f.rule_id,
            secret: f.matched.and_then(|m| m.value),
            source: source(file, line, f.attributes.and_then(|a| a.commit)),
            sets: sets.collect(),
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
    for (line, element) in elements(body)? {
        let leak = match element {
            Element::V1(raw) => decode::<V1Finding>(&mut report, line, raw).map(Leak::from),
            Element::V2(raw) => decode::<V2Finding>(&mut report, line, raw).map(Leak::from),
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

/// Every finding in the document with the line it starts on. A document
/// that is not a sequence of v1 arrays and v2 records is refused by line
/// and column; serde_json's message is never used because it can repeat
/// the input.
fn elements(body: &[u8]) -> Result<Vec<(usize, Element<'_>)>, ReportError> {
    let malformed = |line: usize, column: usize| ReportError::Malformed {
        format: FORMAT,
        line,
        column,
    };
    let at = |raw: &RawValue| line_of(body, raw.get());
    let mut out = Vec::new();
    for value in serde_json::Deserializer::from_slice(body).into_iter::<&RawValue>() {
        let value = value.map_err(|err| malformed(err.line(), err.column()))?;
        let line = at(value);
        let not_betterleaks = || ReportError::NotBetterleaks { line };
        match value.get().as_bytes().first() {
            Some(b'[') => {
                let items: Vec<&RawValue> =
                    serde_json::from_str(value.get()).map_err(|_| malformed(line, 1))?;
                out.extend(items.into_iter().map(|item| (at(item), Element::V1(item))));
            }
            Some(b'{') => {
                let record: V2Record<'_> =
                    serde_json::from_str(value.get()).map_err(|_| not_betterleaks())?;
                match record {
                    V2Record {
                        findings: Some(findings),
                        ..
                    } => out.extend(findings.into_iter().map(|f| (at(f), Element::V2(f)))),
                    V2Record {
                        finding: Some(finding),
                        ..
                    } => out.push((at(finding), Element::V2(finding))),
                    V2Record { scan: Some(_), .. } => {}
                    _ => return Err(not_betterleaks()),
                }
            }
            _ => return Err(not_betterleaks()),
        }
    }
    Ok(out)
}

impl Leak {
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
        let secret_key = aws_secret(self.sets)?;
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

    fn v2_aws(sets: &str) -> Vec<u8> {
        format!(
            r#"{{"schema_version":"1","finding":{{"rule_id":"aws-access-token","match":{{"full":"{AWS_KEY_ID}","value":"{AWS_KEY_ID}"}},"location":{{"path":"a.env","start_line":1}},"component_sets":{sets}}}}}"#
        )
        .into_bytes()
    }

    fn v2_set(secret: &str, status: Option<&str>) -> String {
        let analysis = status.map_or(String::new(), |s| {
            format!(r#","analysis":{{"status":"{s}"}}"#)
        });
        format!(
            r#"{{"components":[{{"rule_id":"aws-secret-access-key","match":{{"full":"k={secret}","value":"{secret}"}}}}]{analysis}}}"#
        )
    }

    #[test]
    fn aws_pair_uses_the_only_or_the_valid_candidate() {
        let same = format!(
            "[{},{}]",
            v2_set(AWS_SECRET, None),
            v2_set(AWS_SECRET, None)
        );
        let valid = format!(
            "[{},{}]",
            v2_set(OTHER_SECRET, Some("invalid")),
            v2_set(AWS_SECRET, Some("valid"))
        );
        for sets in [same, valid] {
            let report = parse(&v2_aws(&sets));
            assert!(report.warnings.is_empty(), "{:?}", report.warnings);
            let aws = &report.findings[0];
            assert_eq!(aws.raw, SecretValue::from(AWS_SECRET));
            assert_eq!(aws.credential().key_id(), Some(AWS_KEY_ID));
        }
    }

    #[test]
    fn aws_without_one_pair_is_skipped() {
        let two = format!(
            "[{},{}]",
            v2_set(AWS_SECRET, None),
            v2_set(OTHER_SECRET, None)
        );
        let cases = [
            ("[]".to_owned(), SkipReason::AwsIncomplete),
            (
                r#"[{"components":null},{"components":[null]}]"#.to_owned(),
                SkipReason::AwsIncomplete,
            ),
            (two, SkipReason::AwsAmbiguous { candidates: 2 }),
        ];
        for (sets, reason) in cases {
            let report = parse(&v2_aws(&sets));
            assert!(report.findings.is_empty());
            assert_eq!(report.warnings[0].reason, reason);
            assert_eq!(report.warnings[0].line, 1);
            let rendered = report.warnings[0].to_string();
            assert!(!rendered.contains("EXAMPLEKEY"), "{rendered}");
        }
    }

    #[test]
    fn redacted_values_are_skipped() {
        for value in ["REDACTED", "ghp_aB3d..."] {
            let input = format!(r#"[{{"RuleID":"github-pat","Secret":"{value}","File":"a"}}]"#);
            let report = parse(input.as_bytes());
            assert!(report.findings.is_empty());
            assert_eq!(report.warnings[0].reason, SkipReason::Redacted);
        }
        let report = parse(&v2_aws(&format!("[{}]", v2_set("REDACTED", None))));
        assert_eq!(report.warnings[0].reason, SkipReason::Redacted);
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

        let mut jsonl_then_trufflehog = V2_JSONL.to_vec();
        jsonl_then_trufflehog.extend_from_slice(TRUFFLEHOG);
        for (input, line) in [
            (TRUFFLEHOG, 1),
            (&jsonl_then_trufflehog[..], 5),
            (&b"\n\"ghp_CANARY\""[..], 2),
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
