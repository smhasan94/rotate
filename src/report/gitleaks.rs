//! gitleaks `-f json` output: one JSON array of findings.
//!
//! The array is split into raw elements borrowed from the input first, so
//! one bad element is skipped with a warning instead of failing the file.
//! `Match` is not read: it is the secret plus surrounding text.

use serde::Deserialize;
use serde_json::value::RawValue;

use super::{non_empty, ParsedReport, ReportError, ReportFormat, SkipReason, UNKNOWN_FILE};
use crate::finding::{Finding, SourceLocation};
use crate::secret::SecretValue;

#[derive(Deserialize)]
struct Leak {
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
}

pub(super) fn parse(body: &[u8]) -> Result<ParsedReport, ReportError> {
    let format = ReportFormat::Gitleaks;
    let elements: Vec<&RawValue> =
        serde_json::from_slice(body).map_err(|err| ReportError::Malformed {
            format,
            line: err.line(),
            column: err.column(),
        })?;

    let mut report = ParsedReport::new(format);
    for element in elements {
        let start_line = line_of(body, element.get());
        match serde_json::from_str::<Leak>(element.get()) {
            Ok(leak) => match leak.into_finding() {
                Ok(finding) => report.findings.push(finding),
                Err(reason) => report.skip(format, start_line, reason),
            },
            Err(err) => {
                // serde counts lines from the start of the element.
                let line = start_line + err.line().saturating_sub(1);
                report.skip(format, line, SkipReason::from_json(&err));
            }
        }
    }
    Ok(report)
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

impl Leak {
    fn into_finding(self) -> Result<Finding, SkipReason> {
        let secret = non_empty(self.secret).ok_or(SkipReason::EmptySecret)?;
        let source = SourceLocation {
            file: self
                .file
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| UNKNOWN_FILE.to_owned()),
            line: self.line,
            commit: self.commit.filter(|c| !c.is_empty()),
        };
        Ok(Finding::new(secret, self.rule, source))
    }
}
