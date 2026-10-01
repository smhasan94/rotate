//! TruffleHog `--json` output: one JSON object per line.
//!
//! For AWS, `Raw` is the access key id, not the secret. The secret half is
//! `SecretParts.secret_access_key` (TruffleHog 3.9x) or, on versions without
//! `SecretParts`, the part of `RawV2` after the key id and an optional `:`.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::{non_empty, ParsedReport, ReportFormat, SkipReason, UNKNOWN_FILE};
use crate::finding::{Finding, SourceLocation, ACCESS_KEY_ID, IS_CANARY};
use crate::secret::SecretValue;

/// `DetectorName` of TruffleHog's AWS access key detector.
const AWS_DETECTOR: &str = "AWS";

#[derive(Deserialize)]
struct Record {
    #[serde(rename = "DetectorName")]
    detector: String,
    #[serde(rename = "Raw", default)]
    raw: Option<SecretValue>,
    #[serde(rename = "RawV2", default)]
    raw_v2: Option<SecretValue>,
    #[serde(rename = "SecretParts", default)]
    parts: Option<AwsParts>,
    #[serde(rename = "ExtraData", default)]
    extra: Option<ExtraData>,
    #[serde(rename = "SourceMetadata", default)]
    source: Option<SourceMetadata>,
}

/// The AWS keys of `SecretParts`. Other detectors' keys (`key` and so on)
/// are skipped by serde without being copied.
#[derive(Deserialize, Default)]
struct AwsParts {
    access_key_id: Option<String>,
    secret_access_key: Option<SecretValue>,
}

#[derive(Deserialize)]
struct ExtraData {
    is_canary: Option<String>,
}

#[derive(Deserialize)]
struct SourceMetadata {
    #[serde(rename = "Data", default)]
    data: Option<BTreeMap<String, Location>>,
}

/// The location fields shared by the `Git`, `Github` and `Filesystem`
/// sources.
#[derive(Deserialize)]
struct Location {
    file: Option<String>,
    line: Option<u64>,
    commit: Option<String>,
}

pub(super) fn parse(body: &[u8]) -> ParsedReport {
    let format = ReportFormat::Trufflehog;
    let mut report = ParsedReport::new(format);
    for (index, line) in body.split(|&b| b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let line_no = index + 1;
        let finding = serde_json::from_slice::<Record>(line)
            .map_err(|err| SkipReason::from_json(&err))
            .and_then(Record::into_finding);
        match finding {
            Ok(finding) => report.findings.push(finding),
            Err(reason) => report.skip(format, line_no, reason),
        }
    }
    report
}

impl Record {
    fn into_finding(self) -> Result<Finding, SkipReason> {
        let Record {
            detector,
            raw,
            raw_v2,
            parts,
            extra,
            source,
        } = self;

        let (secret, key_id) = if detector == AWS_DETECTOR {
            let (secret, key_id) = aws_halves(raw, raw_v2, parts.unwrap_or_default())?;
            (secret, Some(key_id))
        } else {
            (non_empty(raw).ok_or(SkipReason::EmptySecret)?, None)
        };

        let location = source
            .and_then(|s| s.data)
            .and_then(|data| data.into_values().next())
            .map_or_else(|| SourceLocation::file(UNKNOWN_FILE), Location::into_source);
        let mut finding = Finding::new(secret, detector, location);
        if let Some(key_id) = key_id {
            finding = finding.with_extra(ACCESS_KEY_ID, key_id);
        }
        if extra.and_then(|e| e.is_canary).as_deref() == Some("true") {
            finding = finding.with_extra(IS_CANARY, "true");
        }
        Ok(finding)
    }
}

/// The secret access key and the access key id of an AWS record.
fn aws_halves(
    raw: Option<SecretValue>,
    raw_v2: Option<SecretValue>,
    parts: AwsParts,
) -> Result<(SecretValue, String), SkipReason> {
    // `Raw` holds the key id; it is not secret, so a plain copy is fine.
    let key_id = parts
        .access_key_id
        .filter(|id| !id.is_empty())
        .or_else(|| non_empty(raw).and_then(|r| r.expose_secret_str(str::to_owned).ok()))
        .ok_or(SkipReason::AwsIncomplete)?;

    if let Some(secret) = non_empty(parts.secret_access_key) {
        return Ok((secret, key_id));
    }
    let secret = non_empty(raw_v2)
        .and_then(|joined| {
            joined.expose_secret(|bytes| {
                let rest = bytes.strip_prefix(key_id.as_bytes())?;
                let rest = rest.strip_prefix(b":").unwrap_or(rest);
                (!rest.is_empty()).then(|| SecretValue::from(rest))
            })
        })
        .ok_or(SkipReason::AwsIncomplete)?;
    Ok((secret, key_id))
}

impl Location {
    fn into_source(self) -> SourceLocation {
        SourceLocation {
            file: self
                .file
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| UNKNOWN_FILE.to_owned()),
            line: self.line,
            commit: self.commit.filter(|c| !c.is_empty()),
        }
    }
}
