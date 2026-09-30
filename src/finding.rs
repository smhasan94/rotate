//! The common finding model: one leaked secret at one source location
//! (SHA-221; the parsers that produce findings arrive with SHA-223).

use std::collections::BTreeMap;
use std::fmt;

use crate::provider::Credential;
use crate::secret::{Fingerprint, SecretPair, SecretValue};

/// Key in [`Finding::extra`] under which report parsers store an AWS access
/// key id. Its presence turns the finding's credential into a key pair.
pub const ACCESS_KEY_ID: &str = "access_key_id";

/// Where a finding was seen. Every field is optional except the file
/// because scanners differ in what they report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceLocation {
    /// Path as the scanner reported it.
    pub file: String,
    /// 1-based line number when known.
    pub line: Option<u64>,
    /// Commit hash when the scanner walked history.
    pub commit: Option<String>,
}

impl SourceLocation {
    /// A location with only a file.
    pub fn file(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line: None,
            commit: None,
        }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.file)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        if let Some(commit) = &self.commit {
            write!(f, "@{commit}")?;
        }
        Ok(())
    }
}

/// One leaked secret as reported by a scanner.
///
/// The value lives in [`raw`](Self::raw) and nowhere else. `extra` holds
/// non-secret metadata a provider may need, such as [`ACCESS_KEY_ID`]; a
/// parser must never put a second secret in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The leaked value.
    pub raw: SecretValue,
    /// The scanner's detector or rule name, for example `AWS` or
    /// `github-pat`. Used as the first identification hint.
    pub detector: String,
    /// Where it was found.
    pub source: SourceLocation,
    /// Non-secret metadata keyed by name.
    pub extra: BTreeMap<String, String>,
}

impl Finding {
    /// A finding with no extra metadata.
    pub fn new(raw: SecretValue, detector: impl Into<String>, source: SourceLocation) -> Self {
        Self {
            raw,
            detector: detector.into(),
            source,
            extra: BTreeMap::new(),
        }
    }

    /// Adds one metadata entry. The value must not be a secret.
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Fingerprint of the raw value.
    pub fn fingerprint(&self) -> Fingerprint {
        self.raw.fingerprint()
    }

    /// The credential a provider operates on: a key pair when
    /// [`ACCESS_KEY_ID`] is present in `extra`, a bare token otherwise.
    pub fn credential(&self) -> Credential {
        match self.extra.get(ACCESS_KEY_ID) {
            Some(key_id) => Credential::KeyPair(SecretPair::new(key_id.clone(), self.raw.clone())),
            None => Credential::Token(self.raw.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_credential_is_pair_when_access_key_id_present() {
        let raw = SecretValue::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        let token = Finding::new(raw.clone(), "AWS", SourceLocation::file("a.env"));
        assert_eq!(token.credential(), Credential::Token(raw.clone()));
        assert_eq!(token.credential().key_id(), None);

        let pair = token
            .clone()
            .with_extra(ACCESS_KEY_ID, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            pair.credential(),
            Credential::KeyPair(SecretPair::new("AKIAIOSFODNN7EXAMPLE", raw.clone()))
        );
        assert_eq!(pair.credential().key_id(), Some("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(pair.credential().fingerprint(), raw.fingerprint());
        assert_eq!(pair.fingerprint(), raw.fingerprint());
    }

    #[test]
    fn source_location_display_omits_missing_parts() {
        let mut loc = SourceLocation::file("src/config.rs");
        assert_eq!(loc.to_string(), "src/config.rs");
        loc.line = Some(42);
        assert_eq!(loc.to_string(), "src/config.rs:42");
        loc.commit = Some("abc123".into());
        assert_eq!(loc.to_string(), "src/config.rs:42@abc123");
    }

    #[test]
    fn finding_debug_shows_fingerprint_not_value() {
        let finding = Finding::new(
            SecretValue::from("hunter2-abc"),
            "Mock",
            SourceLocation::file("x"),
        );
        let rendered = format!("{finding:?}");
        assert!(!rendered.contains("hunter2-abc"));
        assert!(rendered.contains(finding.fingerprint().as_str()));
    }
}
