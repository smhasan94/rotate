//! Append-only JSONL audit log (SHA-219, FR20, FR21).
//!
//! Every step of every rotation appends one JSON object per line to the
//! audit log (default `.rotate/audit.jsonl`, decision D5). Auditors read it
//! after an incident; `status` and the idempotency checks read it through
//! [`read_all`] during one.
//!
//! The log holds fingerprints and public identifiers, never a secret value:
//! [`AuditEvent`] and [`AuditEntry`] take [`Fingerprint`]s, and
//! [`SecretValue`](crate::secret::SecretValue) has no `Serialize` impl. The
//! only free text, `error`, is a [`RedactedText`], which can only be built
//! through [`redact`](crate::redact::redact).
//!
//! The file is created with mode 0600 inside a 0700 directory, and an
//! existing file with a wider mode is refused (NFR6). Each entry is one
//! `write_all` of a complete line on an `O_APPEND` descriptor followed by
//! `sync_data`, so a killed process leaves whole lines behind.
//!
//! Linux and macOS only, like [`fsutil`].

#![cfg(unix)]

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use time::OffsetDateTime;

use crate::fsutil::{self, FsError};
use crate::provider::ReplacementMode;
use crate::redact::redact;
use crate::secret::Fingerprint;

/// Schema version this build reads and writes.
pub const AUDIT_VERSION: u32 = 1;

/// Environment variable overriding the actor.
pub const ENV_ACTOR: &str = "ROTATE_ACTOR";

/// Actor part used when a user or host name cannot be found.
const UNKNOWN: &str = "unknown";

/// What a line records. Named `AuditStep` so it does not clash with
/// [`state::Step`](crate::state::Step); the JSON field is `step`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStep {
    /// The provider of a finding was identified.
    Identify,
    /// The secret was checked for validity.
    Check,
    /// A plan was made.
    Plan,
    /// A replacement was created.
    Create,
    /// A consumer was updated.
    Update,
    /// The replacement was verified.
    Verify,
    /// The old secret was revoked.
    Revoke,
    /// A change was rolled back.
    Rollback,
    /// The operator passed `--force` (NFR5).
    Force,
}

/// Which undo a `rollback` entry records (SHA-259). The JSON field is
/// `action`; it appears on `rollback` entries only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackAction {
    /// The provider reactivated the old secret.
    RestoreOld,
    /// A consumer got the old value back; `consumer` names it.
    RestoreConsumer,
    /// The replacement was revoked.
    RevokeReplacement,
}

/// How the step ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It succeeded.
    Ok,
    /// It failed; `error` says why.
    Failed,
    /// It was not attempted.
    Skipped,
}

/// Text that has been passed through [`redact`]. The only way to build one
/// is [`RedactedText::new`], and reading one back from JSON redacts again,
/// so raw text cannot reach the log through this type.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RedactedText(String);

impl RedactedText {
    /// Redacts `text`: every live secret value and every provider-shaped
    /// token is replaced by a marker.
    pub fn new(text: &str) -> Self {
        Self(redact(text).into_owned())
    }

    /// The redacted text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RedactedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RedactedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<'de> Deserialize<'de> for RedactedText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::new(&raw))
    }
}

/// What the caller records. [`AuditLog::append`] adds the version, time
/// and actor.
///
/// Fingerprint fields take a [`Fingerprint`], so a secret value cannot be
/// passed in their place:
///
/// ```compile_fail
/// use rotate::audit::{AuditEvent, AuditStep, Outcome};
/// use rotate::secret::SecretValue;
/// let value = SecretValue::from("not-a-real-secret-value");
/// let _ = AuditEvent::new("rot-1", "aws", value, AuditStep::Create, Outcome::Ok);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Rotation identifier chosen by the engine.
    pub rotation_id: String,
    /// Provider name, for example `aws`.
    pub provider: String,
    /// Fingerprint of the secret being rotated.
    pub fingerprint: Fingerprint,
    /// Fingerprint of the replacement, once there is one.
    pub replacement_fingerprint: Option<Fingerprint>,
    /// The consumer's reference, for example `org/repo:AWS_SECRET_ACCESS_KEY`.
    /// A public identifier, never a value.
    pub consumer: Option<String>,
    /// How the replacement was obtained, on `create` entries (SHA-257).
    pub replacement_mode: Option<ReplacementMode>,
    /// Which undo, on `rollback` entries (SHA-259).
    pub action: Option<RollbackAction>,
    /// The step.
    pub step: AuditStep,
    /// How it ended.
    pub outcome: Outcome,
    /// Why it failed, redacted.
    pub error: Option<RedactedText>,
}

impl AuditEvent {
    /// An event with no replacement, consumer or error.
    pub fn new(
        rotation_id: impl Into<String>,
        provider: impl Into<String>,
        fingerprint: Fingerprint,
        step: AuditStep,
        outcome: Outcome,
    ) -> Self {
        Self {
            rotation_id: rotation_id.into(),
            provider: provider.into(),
            fingerprint,
            replacement_fingerprint: None,
            consumer: None,
            replacement_mode: None,
            action: None,
            step,
            outcome,
            error: None,
        }
    }

    /// Sets the replacement's fingerprint.
    pub fn with_replacement(mut self, fingerprint: Fingerprint) -> Self {
        self.replacement_fingerprint = Some(fingerprint);
        self
    }

    /// Sets the consumer reference.
    pub fn with_consumer(mut self, consumer: impl Into<String>) -> Self {
        self.consumer = Some(consumer.into());
        self
    }

    /// Sets how the replacement was obtained.
    pub fn with_mode(mut self, mode: ReplacementMode) -> Self {
        self.replacement_mode = Some(mode);
        self
    }

    /// Sets the rollback action.
    pub fn with_action(mut self, action: RollbackAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Sets the error, redacting it.
    pub fn with_error(mut self, error: &str) -> Self {
        self.error = Some(RedactedText::new(error));
        self
    }
}

/// One line of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    /// Schema version, [`AUDIT_VERSION`].
    pub version: u32,
    /// When the line was written, UTC. Never earlier than the line before.
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    /// Who ran rotate: `ROTATE_ACTOR`, else `user@hostname`.
    pub actor: String,
    /// Rotation identifier.
    pub rotation_id: String,
    /// Provider name.
    pub provider: String,
    /// Fingerprint of the secret being rotated.
    pub fingerprint: Fingerprint,
    /// Fingerprint of the replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_fingerprint: Option<Fingerprint>,
    /// Consumer reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    /// `automatic` or `manual`, on `create` entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_mode: Option<ReplacementMode>,
    /// `restore_old`, `restore_consumer` or `revoke_replacement`, on
    /// `rollback` entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RollbackAction>,
    /// The step.
    pub step: AuditStep,
    /// How it ended.
    pub outcome: Outcome,
    /// Why it failed, redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RedactedText>,
}

/// Why the audit log could not be used. Messages name paths, line numbers
/// and modes, never line contents.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The existing file lets other users in.
    #[error(
        "audit log {} has mode {mode:04o}, but it must be 0600 (owner only); check who could have read it, then run `chmod 600` on it",
        path.display()
    )]
    WideMode {
        /// The audit log.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// A line is not a valid entry.
    #[error("audit log {} line {line} is not valid: {reason}", path.display())]
    Corrupt {
        /// The audit log.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// What is wrong, by position only.
        reason: String,
    },
    /// A line was written by a newer rotate.
    #[error(
        "audit log {} line {line} has schema version {found}, but this rotate supports up to version {AUDIT_VERSION}; upgrade to a newer rotate version",
        path.display()
    )]
    NewerVersion {
        /// The audit log.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// Version on the line.
        found: u64,
    },
    /// A file operation failed, or the path is not a regular file.
    #[error(transparent)]
    Fs(FsError),
}

impl From<FsError> for AuditError {
    fn from(err: FsError) -> Self {
        match err {
            FsError::WideMode { path, mode } => AuditError::WideMode { path, mode },
            other => AuditError::Fs(other),
        }
    }
}

impl AuditError {
    /// True when the operator has to fix something before retrying (a wide
    /// mode, a symlink, a newer or broken line). The CLI maps these to exit
    /// code 2. Plain I/O failures are not usage errors.
    pub fn is_usage(&self) -> bool {
        !matches!(self, AuditError::Fs(FsError::Io { .. }))
    }

    fn io(op: &'static str, path: &Path, source: io::Error) -> Self {
        AuditError::Fs(FsError::Io {
            op,
            path: path.to_owned(),
            source,
        })
    }
}

/// The audit log opened for appending.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: File,
    actor: String,
    last_ts: Option<OffsetDateTime>,
}

impl AuditLog {
    /// Opens `path` for appending, creating it with mode 0600 and its
    /// parent directories with mode 0700. An existing file with a wider
    /// mode is refused with [`AuditError::WideMode`] and nothing is written.
    ///
    /// Reads the existing lines once to keep `ts` non-decreasing, and ends
    /// a final line cut short by a crash so the next entry starts on its own
    /// line. The actor is resolved here with [`resolve_actor`].
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        Self::open_as(path, resolve_actor())
    }

    /// [`open`](Self::open) with an explicit actor.
    pub fn open_as(path: impl Into<PathBuf>, actor: impl Into<String>) -> Result<Self, AuditError> {
        let path = path.into();
        let mut file = fsutil::open_private(
            &path,
            OpenOptions::new().read(true).append(true).create(true),
        )?;
        let last_ts = read_entries(&path, &file)?
            .filter_map(Result::ok)
            .map(|e| e.ts)
            .max();
        terminate_partial_line(&path, &mut file)?;
        Ok(Self {
            path,
            file,
            actor: actor.into(),
            last_ts,
        })
    }

    /// Appends one entry: stamps the version, the time (never earlier than
    /// the previous line) and the actor, writes the whole line at once and
    /// syncs it to disk. Returns what was written.
    pub fn append(&mut self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        let now = OffsetDateTime::now_utc();
        let ts = match self.last_ts {
            Some(last) if last > now => last,
            _ => now,
        };
        let entry = AuditEntry {
            version: AUDIT_VERSION,
            ts,
            actor: self.actor.clone(),
            rotation_id: event.rotation_id,
            provider: event.provider,
            fingerprint: event.fingerprint,
            replacement_fingerprint: event.replacement_fingerprint,
            consumer: event.consumer,
            replacement_mode: event.replacement_mode,
            action: event.action,
            step: event.step,
            outcome: event.outcome,
            error: event.error,
        };
        let mut line = serde_json::to_vec(&entry)
            .map_err(|e| AuditError::io("serialize", &self.path, io::Error::other(e)))?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .map_err(|e| AuditError::io("append to", &self.path, e))?;
        self.file
            .sync_data()
            .map_err(|e| AuditError::io("sync", &self.path, e))?;
        self.last_ts = Some(ts);
        tracing::debug!(
            rotation_id = %entry.rotation_id,
            step = ?entry.step,
            outcome = ?entry.outcome,
            fingerprint = %entry.fingerprint,
            "audit entry appended"
        );
        Ok(entry)
    }

    /// The audit log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The actor stamped on every entry.
    pub fn actor(&self) -> &str {
        &self.actor
    }
}

/// Writes `\n` if the file is non-empty and does not end with one.
fn terminate_partial_line(path: &Path, file: &mut File) -> Result<(), AuditError> {
    let len = file
        .metadata()
        .map_err(|e| AuditError::io("inspect", path, e))?
        .len();
    if len == 0 {
        return Ok(());
    }
    let mut last = [0u8; 1];
    file.seek(SeekFrom::Start(len - 1))
        .and_then(|_| file.read_exact(&mut last))
        .map_err(|e| AuditError::io("read", path, e))?;
    if last[0] != b'\n' {
        file.write_all(b"\n")
            .and_then(|()| file.sync_data())
            .map_err(|e| AuditError::io("append to", path, e))?;
    }
    Ok(())
}

/// Reads every complete line of the audit log at `path`, for `status` and
/// idempotency checks. A missing file yields nothing. Each item is one line:
/// a bad line is an [`AuditError::Corrupt`] or [`AuditError::NewerVersion`]
/// item and reading goes on. A final line without a newline (a write cut
/// short) is skipped. A file with a wide mode is refused.
pub fn read_all(path: &Path) -> Result<AuditEntries, AuditError> {
    if !fsutil::check_private(path)? {
        return Ok(AuditEntries::empty(path));
    }
    let file = fsutil::open_private(path, OpenOptions::new().read(true))?;
    read_entries(path, &file)
}

fn read_entries(path: &Path, file: &File) -> Result<AuditEntries, AuditError> {
    let reader = file
        .try_clone()
        .and_then(|mut f| f.seek(SeekFrom::Start(0)).map(|_| f))
        .map_err(|e| AuditError::io("read", path, e))?;
    Ok(AuditEntries {
        path: path.to_owned(),
        reader: Some(BufReader::new(reader)),
        line: 0,
    })
}

/// Iterator over the lines of an audit log; see [`read_all`].
#[derive(Debug)]
pub struct AuditEntries {
    path: PathBuf,
    reader: Option<BufReader<File>>,
    line: usize,
}

impl AuditEntries {
    fn empty(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            reader: None,
            line: 0,
        }
    }
}

impl Iterator for AuditEntries {
    type Item = Result<AuditEntry, AuditError>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        let mut buf = Vec::new();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => {
                self.reader = None;
                None
            }
            Ok(_) if buf.last() != Some(&b'\n') => {
                // A write cut short: not a complete line.
                self.reader = None;
                None
            }
            Ok(_) => {
                self.line += 1;
                Some(parse_line(&self.path, self.line, &buf))
            }
            Err(e) => {
                self.reader = None;
                Some(Err(AuditError::io("read", &self.path, e)))
            }
        }
    }
}

#[derive(Deserialize)]
struct VersionProbe {
    version: Option<serde_json::Value>,
}

fn parse_line(path: &Path, line: usize, bytes: &[u8]) -> Result<AuditEntry, AuditError> {
    let corrupt = |reason: String| AuditError::Corrupt {
        path: path.to_owned(),
        line,
        reason,
    };
    let probe: VersionProbe = serde_json::from_slice(bytes).map_err(|e| corrupt(describe(&e)))?;
    match probe.version.as_ref().and_then(serde_json::Value::as_u64) {
        Some(v) if v == u64::from(AUDIT_VERSION) => {}
        Some(v) if v > u64::from(AUDIT_VERSION) => {
            return Err(AuditError::NewerVersion {
                path: path.to_owned(),
                line,
                found: v,
            })
        }
        _ => {
            return Err(corrupt(format!(
                "missing or unsupported \"version\" (expected {AUDIT_VERSION})"
            )))
        }
    }
    serde_json::from_slice(bytes).map_err(|e| corrupt(describe(&e)))
}

/// Describes a JSON error by category and column. serde_json's own message
/// can quote the input, so it is not used.
fn describe(err: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let what = match err.classify() {
        Category::Io => "read error",
        Category::Syntax => "malformed JSON",
        Category::Data => "unexpected field or value",
        Category::Eof => "line ends early",
    };
    format!("{what} at column {}", err.column())
}

/// The actor for new entries: `ROTATE_ACTOR` if set and not blank, else
/// `user@hostname`. Informational, not an authentication claim.
pub fn resolve_actor() -> String {
    actor_from(|name| std::env::var(name).ok(), hostname)
}

fn actor_from(
    env: impl Fn(&str) -> Option<String>,
    host: impl FnOnce() -> Option<String>,
) -> String {
    let non_blank = |v: Option<String>| v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    if let Some(actor) = non_blank(env(ENV_ACTOR)) {
        return actor;
    }
    let user = non_blank(env("USER"))
        .or_else(|| non_blank(env("LOGNAME")))
        .unwrap_or_else(|| UNKNOWN.to_owned());
    let host = non_blank(host()).unwrap_or_else(|| UNKNOWN.to_owned());
    format!("{user}@{host}")
}

/// The host name, from `/proc` on Linux or `/bin/hostname` elsewhere.
/// `gethostname(2)` would need `unsafe`, which the crate denies.
fn hostname() -> Option<String> {
    if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        return Some(name);
    }
    let out = std::process::Command::new("/bin/hostname")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use time::Duration;

    fn fp(text: &str) -> Fingerprint {
        Fingerprint::of(text.as_bytes())
    }

    fn event(step: AuditStep) -> AuditEvent {
        AuditEvent::new("rot-0001", "aws", fp("old"), step, Outcome::Ok)
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o777
    }

    fn entries(path: &Path) -> Vec<AuditEntry> {
        read_all(path).unwrap().map(Result::unwrap).collect()
    }

    #[test]
    fn first_append_creates_private_file_and_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".rotate/audit.jsonl");
        let mut log = AuditLog::open_as(&path, "tester@host").unwrap();
        log.append(event(AuditStep::Plan)).unwrap();
        assert!(path.exists());
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn wide_mode_refused_names_path_and_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = AuditLog::open_as(&path, "a@b").unwrap_err();
        assert!(
            matches!(err, AuditError::WideMode { mode: 0o644, .. }),
            "{err}"
        );
        let msg = err.to_string();
        assert!(msg.contains(&path.display().to_string()), "{msg}");
        assert!(msg.contains("0600"), "{msg}");
        assert!(err.is_usage());
        assert_eq!(fs::read(&path).unwrap(), b"");
        assert!(matches!(read_all(&path), Err(AuditError::WideMode { .. })));
    }

    #[test]
    fn three_entries_parse_with_required_fields_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open_as(&path, "tester@host").unwrap();
        log.append(event(AuditStep::Create).with_replacement(fp("new")))
            .unwrap();
        log.append(
            event(AuditStep::Update)
                .with_replacement(fp("new"))
                .with_consumer("org/repo:API_KEY"),
        )
        .unwrap();
        let mut failed = event(AuditStep::Verify).with_error("verify failed: 403");
        failed.outcome = Outcome::Failed;
        log.append(failed).unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        let mut previous: Option<OffsetDateTime> = None;
        for line in lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            for key in [
                "version",
                "ts",
                "actor",
                "rotation_id",
                "provider",
                "fingerprint",
                "step",
                "outcome",
            ] {
                assert!(value.get(key).is_some(), "missing {key}");
            }
            assert_eq!(value["version"], 1);
            assert_eq!(value["actor"], "tester@host");
            let ts = OffsetDateTime::parse(
                value["ts"].as_str().unwrap(),
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap();
            assert_eq!(ts.offset(), time::UtcOffset::UTC);
            if let Some(p) = previous {
                assert!(ts >= p);
            }
            previous = Some(ts);
        }
        let read = entries(&path);
        assert_eq!(read[1].consumer.as_deref(), Some("org/repo:API_KEY"));
        assert_eq!(read[2].outcome, Outcome::Failed);
        assert_eq!(
            read[2].error.as_ref().map(RedactedText::as_str),
            Some("verify failed: 403")
        );
    }

    #[test]
    fn ts_never_goes_backwards() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open_as(&path, "a@b").unwrap();
        let mut future = log.append(event(AuditStep::Plan)).unwrap();
        future.ts += Duration::hours(1);
        let mut line = serde_json::to_vec(&future).unwrap();
        line.push(b'\n');
        drop(log);
        let mut file = fsutil::open_private(&path, OpenOptions::new().append(true)).unwrap();
        file.write_all(&line).unwrap();

        let mut log = AuditLog::open_as(&path, "a@b").unwrap();
        let next = log.append(event(AuditStep::Create)).unwrap();
        assert_eq!(next.ts, future.ts);
    }

    #[test]
    fn registered_secret_in_error_is_redacted() {
        let canary = "audit-unit-canary-3f8e-not-a-real-value";
        let secret = SecretValue::from(canary);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open_as(&path, "a@b").unwrap();
        let written = log
            .append(event(AuditStep::Create).with_error(&format!("boom {canary}")))
            .unwrap();
        let error = written.error.unwrap();
        assert!(error.as_str().contains("[REDACTED"), "{error}");
        assert!(!error.as_str().contains(canary));

        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(canary));
        assert!(text.contains(secret.fingerprint().as_str()));
        let read = entries(&path);
        assert!(read[0]
            .error
            .as_ref()
            .unwrap()
            .as_str()
            .contains("[REDACTED"));
    }

    #[test]
    fn redacted_text_deserialize_redacts() {
        let canary = "audit-unit-canary-91c4-hand-edited";
        let _secret = SecretValue::from(canary);
        let text: RedactedText = serde_json::from_str(&format!("\"x {canary}\"")).unwrap();
        assert!(!text.as_str().contains(canary));
        assert!(text.as_str().contains("[REDACTED"));
    }

    #[test]
    fn actor_resolution_rules() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        let host = || Some("box\n".to_owned());
        assert_eq!(
            actor_from(env(&[("ROTATE_ACTOR", "ci-bot"), ("USER", "u")]), host),
            "ci-bot"
        );
        assert_eq!(
            actor_from(env(&[("ROTATE_ACTOR", "  "), ("USER", "u")]), host),
            "u@box"
        );
        assert_eq!(actor_from(env(&[("LOGNAME", "l")]), host), "l@box");
        assert_eq!(actor_from(env(&[]), || None), "unknown@unknown");
    }

    #[test]
    fn partial_tail_skipped_and_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open_as(&path, "a@b").unwrap();
        log.append(event(AuditStep::Plan)).unwrap();
        drop(log);
        let mut file = fsutil::open_private(&path, OpenOptions::new().append(true)).unwrap();
        file.write_all(b"{\"version\":1,\"ts\":\"20").unwrap();
        drop(file);

        assert_eq!(entries(&path).len(), 1, "fragment is skipped");

        let mut log = AuditLog::open_as(&path, "a@b").unwrap();
        log.append(event(AuditStep::Create)).unwrap();
        let items: Vec<_> = read_all(&path).unwrap().collect();
        assert_eq!(items.len(), 3);
        assert!(items[0].is_ok());
        assert!(matches!(items[1], Err(AuditError::Corrupt { line: 2, .. })));
        assert_eq!(items[2].as_ref().unwrap().step, AuditStep::Create);
    }

    #[test]
    fn corrupt_line_reports_line_number_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let marker = "audit-corrupt-line-text-77";
        fs::write(&path, format!("{{\"version\":1,\"{marker}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let err = read_all(&path).unwrap().next().unwrap().unwrap_err();
        assert!(matches!(err, AuditError::Corrupt { line: 1, .. }), "{err}");
        assert!(err.is_usage());
        assert!(!err.to_string().contains(marker), "{err}");
        assert!(!format!("{err:?}").contains(marker));
    }

    #[test]
    fn newer_version_line_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        fs::write(&path, b"{\"version\":99}\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let err = read_all(&path).unwrap().next().unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                AuditError::NewerVersion {
                    found: 99,
                    line: 1,
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("newer rotate"));
    }

    #[test]
    fn unknown_field_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open_as(&path, "a@b").unwrap();
        let entry = log.append(event(AuditStep::Plan)).unwrap();
        drop(log);
        let mut value = serde_json::to_value(&entry).unwrap();
        value["extra"] = serde_json::json!(1);
        let mut file = fsutil::open_private(&path, OpenOptions::new().append(true)).unwrap();
        writeln!(file, "{value}").unwrap();
        let items: Vec<_> = read_all(&path).unwrap().collect();
        assert!(items[0].is_ok());
        assert!(matches!(items[1], Err(AuditError::Corrupt { line: 2, .. })));
    }

    #[test]
    fn missing_file_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_all(&dir.path().join("absent.jsonl")).unwrap().count(),
            0
        );
    }

    #[test]
    fn symlink_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = AuditLog::open_as(&link, "a@b").unwrap_err();
        assert!(
            matches!(err, AuditError::Fs(FsError::NotRegular { .. })),
            "{err}"
        );
        assert!(err.is_usage());
    }

    #[test]
    fn step_and_outcome_json_names() {
        let steps = [
            (AuditStep::Identify, "identify"),
            (AuditStep::Check, "check"),
            (AuditStep::Plan, "plan"),
            (AuditStep::Create, "create"),
            (AuditStep::Update, "update"),
            (AuditStep::Verify, "verify"),
            (AuditStep::Revoke, "revoke"),
            (AuditStep::Rollback, "rollback"),
            (AuditStep::Force, "force"),
        ];
        for (step, name) in steps {
            assert_eq!(serde_json::to_value(step).unwrap(), name);
        }
        for (outcome, name) in [
            (Outcome::Ok, "ok"),
            (Outcome::Failed, "failed"),
            (Outcome::Skipped, "skipped"),
        ] {
            assert_eq!(serde_json::to_value(outcome).unwrap(), name);
        }
    }

    #[test]
    fn optional_fields_omitted_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open_as(&path, "a@b").unwrap();
        log.append(event(AuditStep::Plan)).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        for key in ["replacement_fingerprint", "consumer", "error"] {
            assert!(!text.contains(key), "{key} present: {text}");
        }
    }
}
