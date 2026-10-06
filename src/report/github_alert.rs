//! GitHub secret-scanning alerts (SHA-337): the REST alert object returned
//! by `GET /repos/{owner}/{repo}/secret-scanning/alerts[/{number}]`.
//!
//! The input is one alert object, an array of alerts (the list endpoint),
//! or several of either back to back. Each top-level value is split into
//! raw elements borrowed from the input first, so one bad alert is skipped
//! with a warning instead of failing the document. Alerts deserialize into
//! typed records with a [`SecretValue`] field, never through
//! `serde_json::Value`, which would copy the secret into memory that is
//! not wiped.
//!
//! GitHub reports an AWS key pair as two alerts, `aws_access_key_id` and
//! `aws_secret_access_key`. A secret-key alert pairs with the key-id alert
//! whose `first_location_detected` has the same `path` and `commit_sha`;
//! otherwise with the only open key-id alert in the input; otherwise it is
//! left unpaired, and assessment marks it not rotatable. No candidate is
//! ever tried against AWS (`docs/plans/SHA-198.md`, decision 5).
//!
//! The format is never detected: an alert document starts with `{` or `[`
//! like the two scanner formats, so it must be named with
//! `--format github-alert`.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::{
    line_of, non_empty, ParsedReport, ReportError, ReportFormat, SkipReason, UNKNOWN_FILE,
};
use crate::finding::{Finding, SourceLocation, ACCESS_KEY_ID};
use crate::secret::{Fingerprint, SecretValue};

/// `secret_type` of the access key id half of an AWS key pair.
pub const AWS_KEY_ID_TYPE: &str = "aws_access_key_id";

/// `secret_type` of the secret access key half of an AWS key pair.
pub const AWS_SECRET_TYPE: &str = "aws_secret_access_key";

/// `state` of an alert that was closed.
const RESOLVED: &str = "resolved";

/// Standard alphabet, padding optional: GitHub documents the encoding but
/// not the padding.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The fields of a REST alert rotate reads. Everything else, including
/// `validity` (rotate checks validity itself), is skipped by serde without
/// a copy.
#[derive(Deserialize)]
struct Alert {
    number: u64,
    secret_type: String,
    #[serde(default)]
    secret: Option<SecretValue>,
    #[serde(default)]
    is_base64_encoded: Option<bool>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    first_location_detected: Option<Location>,
}

/// `first_location_detected`. Only a `commit` location has `path`; the
/// other kinds (issue, pull request, discussion, wiki) leave it `None`.
#[derive(Deserialize)]
struct Location {
    path: Option<String>,
    start_line: Option<u64>,
    commit_sha: Option<String>,
}

/// An alert that passed the state and secret checks.
struct Usable {
    number: u64,
    secret_type: String,
    secret: SecretValue,
    source: SourceLocation,
    /// `(path, commit_sha)` of a commit location, for AWS pairing.
    place: Option<(String, String)>,
}

pub(super) fn parse(body: &[u8]) -> Result<ParsedReport, ReportError> {
    let format = ReportFormat::GithubAlert;
    let mut report = ParsedReport::new(format);
    let mut usable = Vec::new();
    for (line, element) in elements(body)? {
        match serde_json::from_str::<Alert>(element.get()) {
            Ok(alert) => match alert.into_usable() {
                Ok(alert) => usable.push(alert),
                Err(reason) => report.skip(format, line, reason),
            },
            Err(err) => {
                // serde counts lines from the start of the element.
                let line = line + err.line().saturating_sub(1);
                report.skip(format, line, SkipReason::from_json(&err));
            }
        }
    }
    report.findings = pair_aws(usable);
    Ok(report)
}

/// Every alert in the document with the line it starts on. A document that
/// is not a sequence of JSON objects and arrays is refused by line and
/// column; serde_json's message is never used because it can repeat the
/// input.
fn elements(body: &[u8]) -> Result<Vec<(usize, &RawValue)>, ReportError> {
    let format = ReportFormat::GithubAlert;
    let malformed = |line: usize, column: usize| ReportError::Malformed {
        format,
        line,
        column,
    };
    let mut out = Vec::new();
    for value in serde_json::Deserializer::from_slice(body).into_iter::<&RawValue>() {
        let value = value.map_err(|err| malformed(err.line(), err.column()))?;
        let text = value.get();
        let line = line_of(body, text);
        match text.as_bytes().first() {
            Some(b'{') => out.push((line, value)),
            Some(b'[') => {
                // Already checked as JSON, so this only fails on a shape
                // serde accepted above; report it at the array.
                let items: Vec<&RawValue> =
                    serde_json::from_str(text).map_err(|_| malformed(line, 1))?;
                out.extend(
                    items
                        .into_iter()
                        .map(|item| (line_of(body, item.get()), item)),
                );
            }
            _ => return Err(ReportError::NotAlerts { line }),
        }
    }
    Ok(out)
}

impl Alert {
    /// Applies the skip rules: resolved alerts, alerts without a secret,
    /// and base64 values that do not decode.
    fn into_usable(self) -> Result<Usable, SkipReason> {
        let number = self.number;
        if self.state.as_deref() == Some(RESOLVED) {
            return Err(SkipReason::AlertResolved { number });
        }
        let mut secret = non_empty(self.secret).ok_or(SkipReason::AlertWithoutSecret { number })?;
        if self.is_base64_encoded == Some(true) {
            secret = decode_base64(&secret).ok_or(SkipReason::AlertBadBase64 { number })?;
        }
        let location = self.first_location_detected;
        let place = location.as_ref().and_then(|l| {
            let path = l.path.clone().filter(|p| !p.is_empty())?;
            let commit = l.commit_sha.clone().filter(|c| !c.is_empty())?;
            Some((path, commit))
        });
        let source = SourceLocation {
            file: self
                .html_url
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| UNKNOWN_FILE.to_owned()),
            line: location.as_ref().and_then(|l| l.start_line),
            commit: location
                .and_then(|l| l.commit_sha)
                .filter(|c| !c.is_empty()),
        };
        Ok(Usable {
            number,
            secret_type: self.secret_type,
            secret,
            source,
            place,
        })
    }
}

/// Decodes a base64 secret into a new zeroized buffer sized up front, so
/// no unwiped copy is left by a reallocation. `None` when the value is not
/// base64 or decodes to nothing.
fn decode_base64(encoded: &SecretValue) -> Option<SecretValue> {
    encoded.expose_secret(|bytes| {
        let mut buf = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(bytes.len())]);
        let len = BASE64.decode_slice(bytes, &mut buf[..]).ok()?;
        if len == 0 {
            return None;
        }
        buf.truncate(len);
        // Moves the allocation; the truncated tail is wiped with it on drop.
        Some(SecretValue::new(std::mem::take(&mut *buf)))
    })
}

/// An access key id when the value looks like one. It is not secret, so a
/// plain copy is fine.
fn key_id_of(alert: &Usable) -> Option<String> {
    alert.secret.expose_secret(|bytes| {
        (!bytes.is_empty() && bytes.iter().all(u8::is_ascii_alphanumeric))
            .then(|| String::from_utf8_lossy(bytes).into_owned())
    })
}

/// Turns usable alerts into findings, in input order, pairing the two AWS
/// halves. A paired key-id alert is consumed by its secret-key alert; an
/// unpaired one stays a finding of its own, which assessment marks not
/// rotatable, like an unpaired secret-key alert.
fn pair_aws(alerts: Vec<Usable>) -> Vec<Finding> {
    // Key-id alerts: index -> key id.
    let key_ids: BTreeMap<usize, String> = alerts
        .iter()
        .enumerate()
        .filter(|(_, a)| a.secret_type == AWS_KEY_ID_TYPE)
        .filter_map(|(i, a)| key_id_of(a).map(|id| (i, id)))
        .collect();
    let secrets: Vec<usize> = alerts
        .iter()
        .enumerate()
        .filter(|(_, a)| a.secret_type == AWS_SECRET_TYPE)
        .map(|(i, _)| i)
        .collect();

    // Rule 1: the key-id alert at the same path and commit. Several key ids
    // at one place, or one key id claimed by different secrets, pair
    // nothing: a wrong pair is worse than none.
    let mut paired: BTreeMap<usize, usize> = BTreeMap::new();
    for &s in &secrets {
        let Some(place) = &alerts[s].place else {
            continue;
        };
        let at_place: Vec<usize> = key_ids
            .keys()
            .copied()
            .filter(|&k| alerts[k].place.as_ref() == Some(place))
            .collect();
        let distinct: BTreeSet<&String> = at_place.iter().map(|k| &key_ids[k]).collect();
        if distinct.len() == 1 {
            paired.insert(s, at_place[0]);
        }
    }
    let mut claims: BTreeMap<&String, HashSet<Fingerprint>> = BTreeMap::new();
    for (&s, k) in &paired {
        claims
            .entry(&key_ids[k])
            .or_default()
            .insert(alerts[s].secret.fingerprint());
    }
    paired.retain(|_, k| claims[&key_ids[k]].len() == 1);

    // Rule 2: the only open key id in the input, when it is not already
    // paired and exactly one secret is left to pair with it.
    let distinct: BTreeSet<&String> = key_ids.values().collect();
    let claimed: BTreeSet<&String> = paired.values().map(|k| &key_ids[k]).collect();
    let left: Vec<usize> = secrets
        .iter()
        .copied()
        .filter(|s| !paired.contains_key(s))
        .collect();
    let left_secrets: HashSet<Fingerprint> = left
        .iter()
        .map(|&s| alerts[s].secret.fingerprint())
        .collect();
    let only = match distinct.iter().collect::<Vec<_>>().as_slice() {
        [only] if left_secrets.len() == 1 && !claimed.contains(*only) => {
            key_ids.iter().find(|(_, id)| id == *only).map(|(&k, _)| k)
        }
        _ => None,
    };
    if let Some(k) = only {
        for &s in &left {
            paired.insert(s, k);
        }
    }

    // Every key-id alert holding a paired key id is consumed, including a
    // repeat of the same alert from a second document.
    let used: BTreeSet<&String> = paired.values().map(|k| &key_ids[k]).collect();
    let consumed: BTreeSet<usize> = key_ids
        .iter()
        .filter(|(_, id)| used.contains(id))
        .map(|(&k, _)| k)
        .collect();
    let mut findings = Vec::new();
    for (i, alert) in alerts.into_iter().enumerate() {
        if consumed.contains(&i) {
            continue;
        }
        let key_id = paired.get(&i).map(|k| key_ids[k].clone());
        if let Some(k) = paired.get(&i) {
            tracing::debug!(
                alert = alert.number,
                key_id_alert = k,
                "paired AWS secret access key alert with its access key id alert"
            );
        }
        let mut finding = Finding::new(alert.secret, alert.secret_type, alert.source);
        if let Some(key_id) = key_id {
            finding = finding.with_extra(ACCESS_KEY_ID, key_id);
        }
        findings.push(finding);
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::super::{parse_report, ParseWarning};
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/github_alerts.json");

    const URL: &str = "https://github.com/acme/api/security/secret-scanning";
    const COMMIT: &str = "9f2c1e4b7a3d5f6e8c0b1a2d3e4f5a6b7c8d9e0f";
    const OTHER_COMMIT: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b";
    const KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
    const OTHER_KEY_ID: &str = "AKIAI44QH8DHBEXAMPLE";
    const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const GITHUB: &str = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0001";
    const NPM: &str = "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake0002";
    const OPENAI: &str = "sk-proj-FAKEfakeFAKEfakeFAKEfakeFAKEfake0003";
    const DECODED: &str = "ghp_FAKEfakeFAKEfakeFAKEfakeFAKEfake0006";
    const SSH: &str = "FAKE-ssh-private-key-body-not-a-key-0009";

    fn parse(input: &[u8]) -> ParsedReport {
        parse_report(input, Some(ReportFormat::GithubAlert)).unwrap()
    }

    fn fp(value: &str) -> String {
        SecretValue::from(value).fingerprint().to_string()
    }

    /// `(detector, source, fingerprint, key id)` per finding.
    fn summary(report: &ParsedReport) -> Vec<(String, String, String, Option<String>)> {
        report
            .findings
            .iter()
            .map(|f| {
                (
                    f.detector.clone(),
                    f.source.to_string(),
                    f.fingerprint().to_string(),
                    f.extra.get(ACCESS_KEY_ID).cloned(),
                )
            })
            .collect()
    }

    fn row(
        detector: &str,
        source: &str,
        value: &str,
        key_id: Option<&str>,
    ) -> (String, String, String, Option<String>) {
        (
            detector.into(),
            source.into(),
            fp(value),
            key_id.map(str::to_owned),
        )
    }

    /// One alert object. `secret: None` leaves the field out.
    fn alert(
        number: u64,
        secret_type: &str,
        secret: Option<&str>,
        path: &str,
        commit: &str,
    ) -> serde_json::Value {
        let mut alert = serde_json::json!({
            "number": number,
            "state": "open",
            "secret_type": secret_type,
            "html_url": format!("{URL}/{number}"),
            "first_location_detected": {
                "path": path, "start_line": 1, "end_line": 1,
                "start_column": 1, "end_column": 40,
                "blob_sha": "b", "blob_url": "u",
                "commit_sha": commit, "commit_url": "u"
            }
        });
        if let Some(secret) = secret {
            alert["secret"] = secret.into();
        }
        alert
    }

    fn doc(alerts: &[serde_json::Value]) -> Vec<u8> {
        serde_json::to_vec_pretty(alerts).unwrap()
    }

    // T1 (AC1, AC2, AC3): every record kind in the fixture.
    #[test]
    fn sha337_fixture_every_record_kind() {
        let report = parse(FIXTURE);
        assert_eq!(report.format, Some(ReportFormat::GithubAlert));
        let src = |n: u64, line: u64, file_commit: &str| format!("{URL}/{n}:{line}@{file_commit}");
        assert_eq!(
            summary(&report),
            vec![
                row(
                    "github_personal_access_token",
                    &src(1, 12, COMMIT),
                    GITHUB,
                    None
                ),
                row("npm_access_token", &src(2, 1, COMMIT), NPM, None),
                row("openai_api_key", &src(3, 4, COMMIT), OPENAI, None),
                // AC2: paired by path and commit with alert 5, which is
                // consumed; alert 6 at another path stays unpaired.
                row(
                    "aws_secret_access_key",
                    &src(4, 3, COMMIT),
                    AWS_SECRET,
                    Some(KEY_ID)
                ),
                row(
                    "aws_access_key_id",
                    &src(6, 2, OTHER_COMMIT),
                    OTHER_KEY_ID,
                    None
                ),
                // AC3: decoded before fingerprinting.
                row(
                    "github_personal_access_token",
                    &src(8, 7, COMMIT),
                    DECODED,
                    None
                ),
                row("github_ssh_private_key", &src(10, 1, COMMIT), SSH, None),
            ]
        );
        // AC3: fixed reasons naming the alert number, never the value.
        let warnings: Vec<String> = report.warnings.iter().map(ToString::to_string).collect();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings[0].ends_with("skipped: alert #7 is resolved"),
            "{warnings:?}"
        );
        assert!(
            warnings[1].contains("skipped: alert #9 has no `secret` field"),
            "{warnings:?}"
        );
        assert!(warnings[1].contains("REST API"), "{warnings:?}");
        let rendered = format!("{warnings:?} {:?}", report.warnings);
        for value in [GITHUB, NPM, OPENAI, AWS_SECRET, DECODED, SSH, "FAKE"] {
            assert!(!rendered.contains(value), "warning echoed a value");
        }
    }

    // T1 (AC3)
    #[test]
    fn sha337_resolved_and_secretless_alerts_skipped_by_number() {
        let mut resolved = alert(41, "npm_access_token", Some(NPM), "a", COMMIT);
        resolved["state"] = "resolved".into();
        let secretless = alert(42, "npm_access_token", None, "a", COMMIT);
        let mut empty = alert(43, "npm_access_token", Some(""), "a", COMMIT);
        empty["state"] = serde_json::Value::Null;
        let report = parse(&doc(&[resolved, secretless, empty]));
        assert!(report.findings.is_empty());
        let reasons: Vec<SkipReason> = report.warnings.iter().map(|w| w.reason).collect();
        assert_eq!(
            reasons,
            vec![
                SkipReason::AlertResolved { number: 41 },
                SkipReason::AlertWithoutSecret { number: 42 },
                SkipReason::AlertWithoutSecret { number: 43 },
            ]
        );
    }

    // T1 (AC3)
    #[test]
    fn sha337_base64_value_is_decoded() {
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
        let token = "npm_FAKEfakeFAKEfakeFAKEfakeFAKEfake00b6";
        let mut padded = alert(
            1,
            "npm_access_token",
            Some(&STANDARD.encode(token)),
            "a",
            COMMIT,
        );
        padded["is_base64_encoded"] = true.into();
        let mut bare = alert(
            2,
            "npm_access_token",
            Some(&STANDARD_NO_PAD.encode("x")),
            "a",
            COMMIT,
        );
        bare["is_base64_encoded"] = true.into();
        let mut bad = alert(3, "npm_access_token", Some("not base64!"), "a", COMMIT);
        bad["is_base64_encoded"] = true.into();
        let mut plain = alert(4, "npm_access_token", Some(token), "a", COMMIT);
        plain["is_base64_encoded"] = false.into();
        let report = parse(&doc(&[padded, bare, bad, plain]));
        let fps: Vec<String> = report
            .findings
            .iter()
            .map(|f| f.fingerprint().to_string())
            .collect();
        assert_eq!(fps, vec![fp(token), fp("x"), fp(token)]);
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(
            report.warnings[0].reason,
            SkipReason::AlertBadBase64 { number: 3 }
        );
    }

    // T1 (AC1): the source is the alert URL with the line and commit.
    #[test]
    fn sha337_source_is_alert_url_with_line_and_commit() {
        let mut issue = alert(5, "npm_access_token", Some(NPM), "a", COMMIT);
        issue["first_location_detected"] = serde_json::json!({ "issue_title_url": "u" });
        let mut bare = alert(6, "npm_access_token", Some(GITHUB), "a", COMMIT);
        bare.as_object_mut().unwrap().remove("html_url");
        bare.as_object_mut()
            .unwrap()
            .remove("first_location_detected");
        let report = parse(&doc(&[issue, bare]));
        let sources: Vec<SourceLocation> =
            report.findings.iter().map(|f| f.source.clone()).collect();
        assert_eq!(
            sources,
            vec![
                SourceLocation::file(format!("{URL}/5")),
                SourceLocation::file(UNKNOWN_FILE),
            ]
        );
    }

    fn aws_pairs(alerts: &[serde_json::Value]) -> Vec<(String, Option<String>)> {
        parse(&doc(alerts))
            .findings
            .iter()
            .map(|f| (f.detector.clone(), f.extra.get(ACCESS_KEY_ID).cloned()))
            .collect()
    }

    fn pair(detector: &str, key_id: Option<&str>) -> (String, Option<String>) {
        (detector.to_owned(), key_id.map(str::to_owned))
    }

    // T1 (AC2): rule 1, same path and commit, wins over input order.
    #[test]
    fn sha337_aws_pairs_by_path_and_commit() {
        let alerts = [
            alert(1, AWS_KEY_ID_TYPE, Some(OTHER_KEY_ID), "other.env", COMMIT),
            alert(2, AWS_KEY_ID_TYPE, Some(KEY_ID), "aws.env", COMMIT),
            alert(3, AWS_SECRET_TYPE, Some(AWS_SECRET), "aws.env", COMMIT),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_SECRET_TYPE, Some(KEY_ID)),
            ]
        );
        // Same path in another commit is not the same place.
        let alerts = [
            alert(1, AWS_KEY_ID_TYPE, Some(OTHER_KEY_ID), "other.env", COMMIT),
            alert(2, AWS_KEY_ID_TYPE, Some(KEY_ID), "aws.env", OTHER_COMMIT),
            alert(3, AWS_SECRET_TYPE, Some(AWS_SECRET), "aws.env", COMMIT),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_SECRET_TYPE, None),
            ]
        );
    }

    // T1 (AC2): rule 2, the only open key-id alert in the input.
    #[test]
    fn sha337_aws_pairs_with_the_only_open_key_id() {
        let mut resolved = alert(1, AWS_KEY_ID_TYPE, Some(OTHER_KEY_ID), "x.env", COMMIT);
        resolved["state"] = "resolved".into();
        let alerts = [
            resolved,
            alert(2, AWS_KEY_ID_TYPE, Some(KEY_ID), "config.yml", COMMIT),
            alert(
                3,
                AWS_SECRET_TYPE,
                Some(AWS_SECRET),
                "aws.env",
                OTHER_COMMIT,
            ),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![pair(AWS_SECRET_TYPE, Some(KEY_ID))]
        );
        // The same key id in two alerts is still one key id.
        let alerts = [
            alert(2, AWS_KEY_ID_TYPE, Some(KEY_ID), "config.yml", COMMIT),
            alert(
                3,
                AWS_SECRET_TYPE,
                Some(AWS_SECRET),
                "aws.env",
                OTHER_COMMIT,
            ),
            alert(2, AWS_KEY_ID_TYPE, Some(KEY_ID), "config.yml", COMMIT),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![pair(AWS_SECRET_TYPE, Some(KEY_ID))]
        );
    }

    // T1 (AC2): otherwise unpaired; no guessing between candidates.
    #[test]
    fn sha337_aws_unpaired_when_the_rule_does_not_decide() {
        // Two open key ids elsewhere.
        let alerts = [
            alert(1, AWS_KEY_ID_TYPE, Some(KEY_ID), "a.env", COMMIT),
            alert(2, AWS_KEY_ID_TYPE, Some(OTHER_KEY_ID), "b.env", COMMIT),
            alert(3, AWS_SECRET_TYPE, Some(AWS_SECRET), "c.env", COMMIT),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_SECRET_TYPE, None),
            ]
        );
        // No key id at all.
        let alerts = [alert(3, AWS_SECRET_TYPE, Some(AWS_SECRET), "c.env", COMMIT)];
        assert_eq!(aws_pairs(&alerts), vec![pair(AWS_SECRET_TYPE, None)]);
        // The only key id already belongs to a secret at its own place.
        let other_secret = "FAKEawsSecretAccessKeyEXAMPLE0000000002";
        let alerts = [
            alert(1, AWS_KEY_ID_TYPE, Some(KEY_ID), "a.env", COMMIT),
            alert(2, AWS_SECRET_TYPE, Some(AWS_SECRET), "a.env", COMMIT),
            alert(3, AWS_SECRET_TYPE, Some(other_secret), "c.env", COMMIT),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![
                pair(AWS_SECRET_TYPE, Some(KEY_ID)),
                pair(AWS_SECRET_TYPE, None),
            ]
        );
        // Two different secrets left for one key id: neither is paired.
        let alerts = [
            alert(1, AWS_KEY_ID_TYPE, Some(KEY_ID), "a.env", COMMIT),
            alert(2, AWS_SECRET_TYPE, Some(AWS_SECRET), "b.env", COMMIT),
            alert(3, AWS_SECRET_TYPE, Some(other_secret), "c.env", COMMIT),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_SECRET_TYPE, None),
                pair(AWS_SECRET_TYPE, None),
            ]
        );
        // Two key ids at the same place: ambiguous.
        let alerts = [
            alert(1, AWS_KEY_ID_TYPE, Some(KEY_ID), "a.env", COMMIT),
            alert(2, AWS_KEY_ID_TYPE, Some(OTHER_KEY_ID), "a.env", COMMIT),
            alert(3, AWS_SECRET_TYPE, Some(AWS_SECRET), "a.env", COMMIT),
        ];
        assert_eq!(
            aws_pairs(&alerts),
            vec![
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_KEY_ID_TYPE, None),
                pair(AWS_SECRET_TYPE, None),
            ]
        );
    }

    #[test]
    fn sha337_single_object_and_concatenated_documents() {
        let one =
            serde_json::to_vec(&alert(1, "npm_access_token", Some(NPM), "a", COMMIT)).unwrap();
        assert_eq!(parse(&one).findings.len(), 1);

        let mut two = doc(&[alert(1, "npm_access_token", Some(NPM), "a", COMMIT)]);
        two.extend(b"\n");
        two.extend(&one);
        two.extend(b"\n[]\n");
        let report = parse(&two);
        assert_eq!(report.findings.len(), 2);

        for empty in [&b""[..], b"  \n", b"[]", b"[]\n[]"] {
            let report = parse(empty);
            assert!(report.findings.is_empty() && report.warnings.is_empty());
        }
    }

    // T1 (AC4): a malformed document is refused by line and column only.
    #[test]
    fn sha337_malformed_document_refused_without_body_text() {
        let canary = "ghp_CANARYmalformedAlertMustNotPrint0000";
        let input = format!("[\n {{\"number\": 1, \"secret_type\": \"x\", \"secret\": \"{canary}");
        let err = parse_report(input.as_bytes(), Some(ReportFormat::GithubAlert)).unwrap_err();
        assert!(
            matches!(
                err,
                ReportError::Malformed {
                    format: ReportFormat::GithubAlert,
                    line: 2,
                    ..
                }
            ),
            "{err:?}"
        );
        let text = format!("{err} {err:?}");
        assert!(text.contains("line 2, column"), "{text}");
        assert!(!text.contains("CANARY"), "{text}");

        // A raw token piped in by mistake is not JSON.
        let err = parse_report(canary.as_bytes(), Some(ReportFormat::GithubAlert)).unwrap_err();
        assert!(
            matches!(err, ReportError::Malformed { line: 1, .. }),
            "{err:?}"
        );
        assert!(!err.to_string().contains("CANARY"));

        // Valid JSON that is not an alert or an array of alerts.
        let err = parse_report(
            format!("[]\n\"{canary}\"").as_bytes(),
            Some(ReportFormat::GithubAlert),
        )
        .unwrap_err();
        assert!(matches!(err, ReportError::NotAlerts { line: 2 }), "{err:?}");
        assert!(!err.to_string().contains("CANARY"));
    }

    #[test]
    fn sha337_wrong_shape_alert_skipped_with_line() {
        let canary = "ghp_CANARYwrongShapeAlert0000000000000000";
        let input = format!(
            "[\n {{\"number\": 1, \"secret_type\": \"npm_access_token\", \"secret\": \"{NPM}\"}},\n {{\"number\": \"{canary}\",\n  \"secret_type\": \"x\"}}\n]"
        );
        let report = parse(input.as_bytes());
        assert_eq!(report.findings.len(), 1);
        let warning: ParseWarning = report.warnings[0];
        assert_eq!(warning.line, 3);
        assert!(matches!(warning.reason, SkipReason::WrongShape { .. }));
        assert!(!format!("{warning} {warning:?}").contains("CANARY"));
    }

    #[test]
    fn sha337_never_detected() {
        // The scanner formats are still detected; github-alert must be named.
        let report = parse_report(FIXTURE, None).unwrap();
        assert_eq!(report.format, Some(ReportFormat::Gitleaks));
        assert!(report.findings.is_empty());
    }
}
