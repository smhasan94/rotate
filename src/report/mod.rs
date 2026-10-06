//! Scanner report parsers (SHA-223): TruffleHog JSON lines and gitleaks JSON
//! arrays into [`Finding`]s, plus GitHub secret-scanning alerts from the
//! REST API (SHA-337).
//!
//! Secret fields deserialize straight into [`SecretValue`], and
//! [`read_report`] and [`read_report_from`] hold the input in a zeroized
//! buffer, so the plain
//! text exists only in memory that is wiped on drop. Entries that cannot be
//! used are skipped with a [`ParseWarning`] built from the line, column and
//! a fixed reason. serde_json's own error text is never used because its
//! data errors repeat the input (`invalid type: string "..."`).
//!
//! Field mapping and tested scanner versions: `docs/report-formats.md`.

mod github_alert;
mod gitleaks;
mod trufflehog;

pub use github_alert::{AWS_KEY_ID_TYPE, AWS_SECRET_TYPE};

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::finding::Finding;
use crate::secret::SecretValue;

/// UTF-8 byte order mark, skipped before format detection.
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// File name used when a scanner reports no file for a finding.
pub const UNKNOWN_FILE: &str = "<unknown>";

/// A supported scanner report format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportFormat {
    /// TruffleHog `--json`: one JSON object per line.
    Trufflehog,
    /// gitleaks `-f json`: one JSON array.
    Gitleaks,
    /// GitHub secret-scanning alerts from the REST API: one alert object or
    /// an array of them. Never detected; it must be named.
    GithubAlert,
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReportFormat::Trufflehog => "trufflehog",
            ReportFormat::Gitleaks => "gitleaks",
            ReportFormat::GithubAlert => "github-alert",
        })
    }
}

/// What [`detect_format`] concluded from the first non-space byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detected {
    /// Nothing but whitespace.
    Empty,
    /// `[` for gitleaks, `{` for TruffleHog.
    Format(ReportFormat),
    /// Anything else.
    Unrecognized,
}

/// Detects the format from the first byte that is not whitespace, after an
/// optional UTF-8 byte order mark.
pub fn detect_format(input: &[u8]) -> Detected {
    let body = input.strip_prefix(BOM).unwrap_or(input);
    match body.iter().find(|b| !b.is_ascii_whitespace()) {
        None => Detected::Empty,
        Some(b'[') => Detected::Format(ReportFormat::Gitleaks),
        Some(b'{') => Detected::Format(ReportFormat::Trufflehog),
        Some(_) => Detected::Unrecognized,
    }
}

/// The findings in one report plus the entries that were skipped.
#[derive(Debug, Default)]
pub struct ParsedReport {
    /// Format the report was parsed as; `None` for an empty input.
    pub format: Option<ReportFormat>,
    /// Usable findings in report order.
    pub findings: Vec<Finding>,
    /// One entry per skipped record.
    pub warnings: Vec<ParseWarning>,
}

impl ParsedReport {
    fn new(format: ReportFormat) -> Self {
        Self {
            format: Some(format),
            ..Self::default()
        }
    }

    fn skip(&mut self, format: ReportFormat, line: usize, reason: SkipReason) {
        self.warnings.push(ParseWarning {
            format,
            line,
            reason,
        });
    }
}

/// A record that was skipped. Its text never includes the record's content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseWarning {
    /// Format of the report.
    pub format: ReportFormat,
    /// 1-based line where the problem is.
    pub line: usize,
    /// Why it was skipped.
    pub reason: SkipReason,
}

impl fmt::Display for ParseWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} line {} skipped: {}",
            self.format, self.line, self.reason
        )
    }
}

/// Why a record was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The record is not well-formed JSON.
    InvalidJson {
        /// 1-based column of the error.
        column: usize,
    },
    /// Well-formed JSON, but a field is missing or has the wrong type.
    WrongShape {
        /// 1-based column of the error.
        column: usize,
    },
    /// The secret field is missing or empty.
    EmptySecret,
    /// An AWS record without both the access key id and the secret half.
    AwsIncomplete,
    /// A GitHub alert whose `state` is `resolved`.
    AlertResolved {
        /// The alert number.
        number: u64,
    },
    /// A GitHub alert without a `secret` (the webhook payload, or the REST
    /// API with `hide_secret=true`).
    AlertWithoutSecret {
        /// The alert number.
        number: u64,
    },
    /// A GitHub alert marked `is_base64_encoded` whose secret does not
    /// decode.
    AlertBadBase64 {
        /// The alert number.
        number: u64,
    },
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkipReason::InvalidJson { column } => write!(f, "not valid JSON (column {column})"),
            SkipReason::WrongShape { column } => {
                write!(f, "missing field or wrong field type (column {column})")
            }
            SkipReason::EmptySecret => f.write_str("no secret value"),
            SkipReason::AwsIncomplete => {
                f.write_str("AWS finding without both the access key id and the secret key")
            }
            SkipReason::AlertResolved { number } => write!(f, "alert #{number} is resolved"),
            SkipReason::AlertWithoutSecret { number } => write!(
                f,
                "alert #{number} has no `secret` field (the webhook payload and \
                 `hide_secret=true` leave it out); fetch the alert with the REST API"
            ),
            SkipReason::AlertBadBase64 { number } => write!(
                f,
                "alert #{number} is marked base64 encoded but its secret does not decode"
            ),
        }
    }
}

impl SkipReason {
    /// Classifies a serde_json error without using its message.
    fn from_json(err: &serde_json::Error) -> Self {
        let column = err.column();
        match err.classify() {
            serde_json::error::Category::Data => SkipReason::WrongShape { column },
            _ => SkipReason::InvalidJson { column },
        }
    }
}

/// A report that could not be parsed at all.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// The file could not be read.
    #[error("could not read report {}: {source}", path.display())]
    Io {
        /// The report path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A format was forced that does not match the content.
    #[error("--format {requested} was given but the report looks like {detected}")]
    FormatMismatch {
        /// The forced format.
        requested: ReportFormat,
        /// The format detected from the content.
        detected: ReportFormat,
    },
    /// The first byte is neither `[` nor `{`.
    #[error("unrecognized report format: expected a gitleaks JSON array or TruffleHog JSON lines")]
    Unrecognized,
    /// Standard input could not be read.
    #[error("could not read the report from stdin: {0}")]
    Stdin(#[source] io::Error),
    /// A gitleaks report that is not a valid JSON array, or a GitHub alert
    /// document that is not valid JSON.
    #[error("{format} report is not valid JSON at line {line}, column {column}")]
    Malformed {
        /// Format of the report.
        format: ReportFormat,
        /// 1-based line of the error.
        line: usize,
        /// 1-based column of the error.
        column: usize,
    },
    /// A GitHub alert document holding a JSON value that is neither an
    /// alert object nor an array of alerts.
    #[error("github-alert input at line {line} is not an alert object or an array of alerts")]
    NotAlerts {
        /// 1-based line where the value starts.
        line: usize,
    },
}

/// Parses a report held in memory. `format` forces a format; it must match
/// the detected one, except [`ReportFormat::GithubAlert`], which is never
/// detected and is parsed as named. Empty or whitespace-only input is an
/// empty report whatever the format. Each warning is also logged at `warn`
/// level.
pub fn parse_report(
    input: &[u8],
    format: Option<ReportFormat>,
) -> Result<ParsedReport, ReportError> {
    let body = input.strip_prefix(BOM).unwrap_or(input);
    if format == Some(ReportFormat::GithubAlert) {
        if detect_format(input) == Detected::Empty {
            return Ok(ParsedReport::default());
        }
        return Ok(log_warnings(github_alert::parse(body)?));
    }
    let detected = match detect_format(input) {
        Detected::Empty => return Ok(ParsedReport::default()),
        Detected::Unrecognized => return Err(ReportError::Unrecognized),
        Detected::Format(detected) => detected,
    };
    if let Some(requested) = format.filter(|&f| f != detected) {
        return Err(ReportError::FormatMismatch {
            requested,
            detected,
        });
    }

    let report = match detected {
        ReportFormat::Trufflehog => trufflehog::parse(body),
        ReportFormat::Gitleaks => gitleaks::parse(body)?,
        // detect_format never yields it; handled above.
        ReportFormat::GithubAlert => github_alert::parse(body)?,
    };
    Ok(log_warnings(report))
}

fn log_warnings(report: ParsedReport) -> ParsedReport {
    for warning in &report.warnings {
        tracing::warn!(%warning, "report entry skipped");
    }
    report
}

/// Reads a report file into a zeroized buffer and parses it.
pub fn read_report(path: &Path, format: Option<ReportFormat>) -> Result<ParsedReport, ReportError> {
    let io_error = |source| ReportError::Io {
        path: path.to_path_buf(),
        source,
    };
    let mut file = File::open(path).map_err(io_error)?;
    // Size the buffer up front: growing it would free an unwiped copy.
    let len = file.metadata().map_or(0, |m| m.len());
    let capacity = usize::try_from(len).unwrap_or(0).saturating_add(1);
    let mut buf = Zeroizing::new(Vec::with_capacity(capacity));
    file.read_to_end(&mut buf).map_err(io_error)?;
    parse_report(&buf, format)
}

/// Reads a whole report from `reader` (stdin with `--stdin --format`) into
/// a zeroized buffer and parses it. The buffer grows by copying into a new
/// zeroized buffer, so a reallocation never frees an unwiped copy.
pub fn read_report_from(
    reader: impl Read,
    format: Option<ReportFormat>,
) -> Result<ParsedReport, ReportError> {
    let buf = read_zeroized(reader).map_err(ReportError::Stdin)?;
    parse_report(&buf, format)
}

/// First buffer size for [`read_report_from`]: a few alerts fit.
const READ_CHUNK: usize = 64 * 1024;

fn read_zeroized(mut reader: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(READ_CHUNK));
    loop {
        if buf.len() == buf.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity(buf.capacity() * 2));
            bigger.extend_from_slice(&buf);
            buf = bigger;
        }
        let filled = buf.len();
        let capacity = buf.capacity();
        // Within capacity, so this never reallocates.
        buf.resize(capacity, 0);
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                buf.truncate(filled);
                return Ok(buf);
            }
            Ok(n) => buf.truncate(filled + n),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => buf.truncate(filled),
            Err(err) => return Err(err),
        }
    }
}

/// 1-based line in `body` where `element`, a slice borrowed from it, starts.
fn line_of(body: &[u8], element: &str) -> usize {
    let offset = (element.as_ptr() as usize).saturating_sub(body.as_ptr() as usize);
    let newlines = body[..offset.min(body.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count();
    newlines + 1
}

/// `None` when the value is absent or empty.
fn non_empty(value: Option<SecretValue>) -> Option<SecretValue> {
    value.filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{SourceLocation, ACCESS_KEY_ID, IS_CANARY};

    const TRUFFLEHOG: &[u8] = include_bytes!("../../tests/fixtures/trufflehog.ndjson");
    const TRUFFLEHOG_AWS_LEGACY: &[u8] =
        include_bytes!("../../tests/fixtures/trufflehog_aws_legacy.ndjson");
    const GITLEAKS: &[u8] = include_bytes!("../../tests/fixtures/gitleaks.json");
    const EMPTY: &[u8] = include_bytes!("../../tests/fixtures/empty.json");

    const AWS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const FP_AWS_SECRET: &str = "sha256:78314b11be2e5815";
    const FP_AWS_KEY_ID: &str = "sha256:1a5d44a2dca19669";
    const FP_AWS_RAW_V2: &str = "sha256:f2cffaa2a0953819";
    const FP_LEGACY_SECRET: &str = "sha256:e21b597ba6b9cafa";
    const FP_GITHUB: &str = "sha256:49188246df2b1be9";
    const FP_NPM: &str = "sha256:932d895510e2d416";
    const COMMIT: &str = "9f2c1e4b7a3d5f6e8c0b1a2d3e4f5a6b7c8d9e0f";

    fn summary(report: &ParsedReport) -> Vec<(String, String, String)> {
        report
            .findings
            .iter()
            .map(|f| {
                (
                    f.detector.clone(),
                    f.source.to_string(),
                    f.fingerprint().to_string(),
                )
            })
            .collect()
    }

    fn row(detector: &str, source: &str, fp: &str) -> (String, String, String) {
        (detector.into(), source.into(), fp.into())
    }

    fn trufflehog_line(fields: &str) -> Vec<u8> {
        format!(r#"{{"DetectorName":"Github",{fields}}}"#).into_bytes()
    }

    // T1 (AC1)
    #[test]
    fn trufflehog_fixture_parses_three_findings() {
        let report = parse_report(TRUFFLEHOG, None).unwrap();
        assert_eq!(report.format, Some(ReportFormat::Trufflehog));
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(
            summary(&report),
            vec![
                row("AWS", &format!("deploy/aws.env:3@{COMMIT}"), FP_AWS_SECRET),
                row("Github", "src/app.js:12", FP_GITHUB),
                row("NpmToken", ".npmrc:1", FP_NPM),
            ]
        );
    }

    // T2 (AC2)
    #[test]
    fn gitleaks_fixture_parses_three_findings() {
        let report = parse_report(GITLEAKS, None).unwrap();
        assert_eq!(report.format, Some(ReportFormat::Gitleaks));
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        assert_eq!(
            summary(&report),
            vec![
                row("aws-access-token", "deploy/aws.env:2", FP_AWS_KEY_ID),
                row("github-pat", &format!("src/app.js:12@{COMMIT}"), FP_GITHUB),
                row("npm-access-token", ".npmrc:1", FP_NPM),
            ]
        );
        // gitleaks only ever reports the key id half of an AWS pair.
        assert!(report.findings[0].extra.is_empty());
    }

    // T3 (AC3)
    #[test]
    fn detects_format_from_first_byte() {
        let gitleaks = Detected::Format(ReportFormat::Gitleaks);
        let trufflehog = Detected::Format(ReportFormat::Trufflehog);
        assert_eq!(detect_format(GITLEAKS), gitleaks);
        assert_eq!(detect_format(TRUFFLEHOG), trufflehog);
        assert_eq!(detect_format(b"\xEF\xBB\xBF  \n\t[]"), gitleaks);
        assert_eq!(detect_format(b"\r\n{}"), trufflehog);
        assert_eq!(detect_format(b" \n"), Detected::Empty);
        assert_eq!(detect_format(b"key: value"), Detected::Unrecognized);
    }

    // T3 (AC3)
    #[test]
    fn forced_wrong_format_names_both() {
        let err = parse_report(TRUFFLEHOG, Some(ReportFormat::Gitleaks)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "--format gitleaks was given but the report looks like trufflehog"
        );
        let err = parse_report(GITLEAKS, Some(ReportFormat::Trufflehog)).unwrap_err();
        assert!(matches!(
            err,
            ReportError::FormatMismatch {
                requested: ReportFormat::Trufflehog,
                detected: ReportFormat::Gitleaks
            }
        ));
        let report = parse_report(GITLEAKS, Some(ReportFormat::Gitleaks)).unwrap();
        assert_eq!(report.findings.len(), 3);
    }

    #[test]
    fn unrecognized_first_byte_errors() {
        let err = parse_report(b"AKIA-not-a-report", None).unwrap_err();
        assert!(matches!(err, ReportError::Unrecognized));
        assert!(!err.to_string().contains("AKIA"));
    }

    // T5 (AC5)
    #[test]
    fn trufflehog_aws_has_key_id_in_extra() {
        let report = parse_report(TRUFFLEHOG, None).unwrap();
        let aws = &report.findings[0];
        assert_eq!(
            aws.extra.get(ACCESS_KEY_ID).map(String::as_str),
            Some(AWS_KEY_ID)
        );
        assert_eq!(aws.fingerprint().as_str(), FP_AWS_SECRET);
        assert_eq!(aws.credential().key_id(), Some(AWS_KEY_ID));
        assert!(!aws.extra.contains_key(IS_CANARY));
    }

    // T5 (AC5)
    #[test]
    fn trufflehog_aws_legacy_uses_raw_v2() {
        let report = parse_report(TRUFFLEHOG_AWS_LEGACY, None).unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
        let aws = &report.findings[0];
        assert_eq!(
            aws.extra.get(ACCESS_KEY_ID).map(String::as_str),
            Some("AKIAI44QH8DHBEXAMPLE")
        );
        assert_eq!(aws.fingerprint().as_str(), FP_LEGACY_SECRET);
        assert_eq!(aws.extra.get(IS_CANARY).map(String::as_str), Some("true"));
    }

    #[test]
    fn aws_raw_v2_without_separator_is_split() {
        let input = br#"{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","RawV2":"AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}"#;
        let report = parse_report(input, None).unwrap();
        let aws = &report.findings[0];
        assert_eq!(aws.fingerprint().as_str(), FP_AWS_SECRET);
        assert_ne!(aws.fingerprint().as_str(), FP_AWS_RAW_V2);
        assert_eq!(aws.source, SourceLocation::file(UNKNOWN_FILE));
    }

    #[test]
    fn aws_without_both_halves_is_skipped() {
        let input = b"{\"DetectorName\":\"AWS\",\"Raw\":\"AKIAIOSFODNN7EXAMPLE\",\"RawV2\":\"\"}\n\
                      {\"DetectorName\":\"AWS\",\"SecretParts\":{\"secret_access_key\":\"abc\"}}\n";
        let report = parse_report(input, None).unwrap();
        assert!(report.findings.is_empty());
        let reasons: Vec<_> = report.warnings.iter().map(|w| (w.line, w.reason)).collect();
        assert_eq!(
            reasons,
            vec![
                (1, SkipReason::AwsIncomplete),
                (2, SkipReason::AwsIncomplete)
            ]
        );
    }

    #[test]
    fn empty_trufflehog_raw_is_skipped() {
        let report = parse_report(&trufflehog_line(r#""Raw":"""#), None).unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.warnings[0].reason, SkipReason::EmptySecret);
    }

    #[test]
    fn wrong_type_field_does_not_echo_input() {
        let canary = "ghp_CANARYwrongTypeMustNotPrint";
        let input = trufflehog_line(&format!(
            r#""Raw":"x","SourceMetadata":{{"Data":{{"Filesystem":{{"file":"a","line":"{canary}"}}}}}}"#
        ));
        let report = parse_report(&input, None).unwrap();
        assert!(report.findings.is_empty());
        let warning = report.warnings[0];
        assert!(matches!(warning.reason, SkipReason::WrongShape { .. }));
        let rendered = format!("{warning} {warning:?}");
        assert!(rendered.contains("line 1"), "{rendered}");
        assert!(!rendered.contains("CANARY"), "warning echoed the input");
    }

    #[test]
    fn crlf_and_blank_lines_keep_line_numbers() {
        let mut input = b"\r\n".to_vec();
        input.extend(trufflehog_line(r#""Raw":"ghp_a""#));
        input.extend(b"\r\n\r\n{not json\r\n");
        let report = parse_report(&input, None).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].line, 4);
    }

    #[test]
    fn gitleaks_bad_element_skipped_with_line() {
        let input = br#"[
 {"RuleID": "github-pat", "Secret": "ghp_a", "File": "a.js", "StartLine": 1, "Commit": ""},
 {"RuleID": "github-pat",
  "Secret": "ghp_CANARYbadElement", "File": "b.js", "StartLine": "nine"},
 {"RuleID": "npm-access-token", "Secret": "", "File": "c", "StartLine": 3}
]"#;
        let report = parse_report(input, None).unwrap();
        assert_eq!(report.findings.len(), 1);
        let warnings: Vec<_> = report.warnings.iter().map(|w| (w.line, w.reason)).collect();
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0].0, 4);
        assert!(matches!(warnings[0].1, SkipReason::WrongShape { .. }));
        assert_eq!(warnings[1], (5, SkipReason::EmptySecret));
        assert!(!format!("{:?}", report.warnings).contains("CANARY"));
    }

    #[test]
    fn gitleaks_not_an_array_is_malformed() {
        let err =
            parse_report(b"[\n {\"RuleID\": \"x\", \"Secret\": \"ghp_CANARY", None).unwrap_err();
        assert!(matches!(
            err,
            ReportError::Malformed {
                format: ReportFormat::Gitleaks,
                line: 2,
                ..
            }
        ));
        assert!(!err.to_string().contains("CANARY"));
    }

    #[test]
    fn gitleaks_empty_commit_is_none() {
        let report = parse_report(GITLEAKS, None).unwrap();
        assert_eq!(report.findings[0].source.commit, None);
        assert_eq!(report.findings[1].source.commit.as_deref(), Some(COMMIT));
    }

    // T6 (AC6)
    #[test]
    fn empty_input_is_empty_report() {
        let inputs: [&[u8]; 5] = [EMPTY, b"", b"  \n\n", b"[]", b"[ ]\n"];
        for input in inputs {
            for format in [None, Some(ReportFormat::Gitleaks)] {
                let report = parse_report(input, format).unwrap();
                assert!(report.findings.is_empty());
                assert!(report.warnings.is_empty());
            }
        }
        let report = parse_report(EMPTY, Some(ReportFormat::Trufflehog)).unwrap();
        assert!(report.findings.is_empty());
    }

    #[test]
    fn read_report_reads_file() {
        let dir = std::env::temp_dir().join(format!("rotate-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        std::fs::write(&path, GITLEAKS).unwrap();
        let report = read_report(&path, None).unwrap();
        assert_eq!(report.findings.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();

        let err = read_report(&dir.join("missing.json"), None).unwrap_err();
        assert!(matches!(err, ReportError::Io { .. }));
        assert!(err.to_string().contains("missing.json"));
    }

    #[test]
    fn findings_hold_secret_values() {
        let report = parse_report(GITLEAKS, None).unwrap();
        assert_eq!(
            report.findings[1].raw,
            SecretValue::from("ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001")
        );
    }
}
