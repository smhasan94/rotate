//! Rotation state store (SHA-220): resume, status and rollback.
//!
//! `apply` records each rotation's progress here after every step (FR15),
//! so an interrupted run resumes without repeating a state-changing step,
//! a pending revoke can be finished by a later run (FR16), `status` can list
//! what is in progress (FR19), and `rollback` knows what to undo.
//!
//! The file (default `.rotate/state.json`, decision D5) is one JSON
//! document, `{"version": 1, "rotations": [...]}`, rewritten whole through
//! [`fsutil::write_atomic`] on every [`StateStore::upsert`]. It holds
//! fingerprints and provider-side identifiers only, never a secret value:
//! [`SecretValue`](crate::secret::SecretValue) has no `Serialize` impl, so a
//! field of that type would not compile.
//!
//! Writers take an exclusive advisory lock on `<state file>.lock` through
//! [`StateStore::open`]; a second writer fails at once with
//! [`StateError::Locked`]. Readers such as `status` use [`StateStore::read`],
//! which needs no lock because the file is only ever replaced by rename.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::fsutil::{self, FsError, LockFile};
use crate::secret::Fingerprint;

/// Schema version this build reads and writes.
pub const STATE_VERSION: u32 = 1;

/// Suffix of the lock file next to the state file.
const LOCK_SUFFIX: &str = ".lock";

/// How far a rotation has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Recorded, nothing changed yet.
    Planned,
    /// The replacement exists at the provider.
    Created,
    /// Consumers hold the replacement.
    ConsumersUpdated,
    /// The replacement was checked to work.
    Verified,
    /// Waiting for the overlap window before revoking the old secret.
    PendingRevoke,
    /// The old secret is revoked; the rotation is finished.
    Revoked,
    /// A step failed before revoke; the old secret is still valid.
    Failed,
    /// Rolled back; the rotation is finished.
    RolledBack,
}

impl Step {
    /// True for steps after which nothing is left to do: `revoked` and
    /// `rolled_back`. A `failed` rotation is not finished: it still needs a
    /// resume or a rollback.
    pub fn is_terminal(self) -> bool {
        matches!(self, Step::Revoked | Step::RolledBack)
    }
}

/// What happened to one consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerStatus {
    /// It now holds the replacement.
    Updated,
    /// Updating it failed.
    Failed,
    /// It was not updated, for example because it cannot be automatically.
    Skipped,
}

/// One consumer of the rotated secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerState {
    /// Name of the consumer plugin, for example `github-actions`.
    pub consumer: String,
    /// The consumer's own reference, for example `org/repo:AWS_SECRET_ACCESS_KEY`.
    pub consumer_ref: String,
    /// Outcome.
    pub status: ConsumerStatus,
}

/// One rotation's recorded progress. Holds no secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    /// Identifier chosen by the engine; opaque to the store, never empty.
    pub rotation_id: String,
    /// Provider name, for example `aws`.
    pub provider: String,
    /// Fingerprint of the secret being rotated.
    pub fingerprint: Fingerprint,
    /// Fingerprint of the replacement, once created.
    pub replacement_fingerprint: Option<Fingerprint>,
    /// Provider-side identifier of the replacement, such as an AWS access
    /// key id or a token id. Never a secret value.
    pub replacement_ref: Option<String>,
    /// Step reached.
    pub step: Step,
    /// Consumers touched so far.
    pub consumers: Vec<ConsumerState>,
    /// Earliest time the old secret may be revoked (FR16).
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoke_not_before: Option<OffsetDateTime>,
    /// When the rotation was first recorded. Kept from the stored record on
    /// every upsert.
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    /// When the rotation was last recorded. Set by [`StateStore::upsert`].
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    /// The operator passed `--force` (NFR5).
    pub force: bool,
}

impl Rotation {
    /// A new rotation at step `planned`, started now.
    pub fn new(
        rotation_id: impl Into<String>,
        provider: impl Into<String>,
        fingerprint: Fingerprint,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            rotation_id: rotation_id.into(),
            provider: provider.into(),
            fingerprint,
            replacement_fingerprint: None,
            replacement_ref: None,
            step: Step::Planned,
            consumers: Vec::new(),
            revoke_not_before: None,
            started_at: now,
            updated_at: now,
            force: false,
        }
    }

    /// True until the rotation reaches a terminal step.
    pub fn is_in_progress(&self) -> bool {
        !self.step.is_terminal()
    }
}

/// Why the state store could not be used. Messages name paths and versions,
/// never file contents.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Another rotate process holds the lock.
    #[error(
        "another rotate process is using the state file (lock {}); wait for it to finish and try again",
        lock.display()
    )]
    Locked {
        /// The lock file.
        lock: PathBuf,
    },
    /// The file was written by a newer rotate.
    #[error(
        "state file {} has schema version {found}, but this rotate supports up to version {supported}; upgrade to a newer rotate version",
        path.display()
    )]
    NewerVersion {
        /// The state file.
        path: PathBuf,
        /// Version in the file.
        found: u64,
        /// [`STATE_VERSION`].
        supported: u32,
    },
    /// The file is not a valid state file.
    #[error("state file {} is not valid: {reason}", path.display())]
    Corrupt {
        /// The state file.
        path: PathBuf,
        /// What is wrong, by position only.
        reason: String,
    },
    /// A rotation passed to [`StateStore::upsert`] is not valid.
    #[error("invalid rotation: {0}")]
    InvalidRotation(&'static str),
    /// A file operation failed or a file's mode is too wide.
    #[error(transparent)]
    Fs(#[from] FsError),
}

impl StateError {
    /// True when the operator has to fix something before retrying (a held
    /// lock, a newer or broken file, a wide file mode). The CLI maps these
    /// to exit code 2. Plain I/O failures are not usage errors.
    pub fn is_usage(&self) -> bool {
        !matches!(self, StateError::Fs(FsError::Io { .. }))
    }
}

/// The lock file guarding `state_file`: `state_file` plus `.lock`.
pub fn lock_path(state_file: &Path) -> PathBuf {
    let mut name = state_file.as_os_str().to_owned();
    name.push(LOCK_SUFFIX);
    PathBuf::from(name)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u32,
    rotations: Vec<Rotation>,
}

#[derive(Deserialize)]
struct VersionProbe {
    version: Option<serde_json::Value>,
}

/// Rotations loaded from the state file, sorted by `rotation_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateSnapshot {
    rotations: Vec<Rotation>,
}

impl StateSnapshot {
    /// Every rotation, sorted by `rotation_id`.
    pub fn rotations(&self) -> &[Rotation] {
        &self.rotations
    }

    /// The rotation with this id.
    pub fn get(&self, rotation_id: &str) -> Option<&Rotation> {
        self.position(rotation_id).ok().map(|i| &self.rotations[i])
    }

    /// Rotations not yet at a terminal step (FR19).
    pub fn list_in_progress(&self) -> Vec<&Rotation> {
        self.rotations
            .iter()
            .filter(|r| r.is_in_progress())
            .collect()
    }

    fn position(&self, rotation_id: &str) -> Result<usize, usize> {
        self.rotations
            .binary_search_by(|r| r.rotation_id.as_str().cmp(rotation_id))
    }

    fn load(path: &Path) -> Result<Self, StateError> {
        if !fsutil::check_private(path)? {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path).map_err(|source| FsError::Io {
            op: "read",
            path: path.to_owned(),
            source,
        })?;
        let corrupt = |err: serde_json::Error| StateError::Corrupt {
            path: path.to_owned(),
            reason: describe(&err),
        };

        let probe: VersionProbe = serde_json::from_slice(&bytes).map_err(corrupt)?;
        let found = match probe.version {
            Some(serde_json::Value::Number(n)) => n.as_u64(),
            _ => None,
        };
        match found {
            Some(v) if v > u64::from(STATE_VERSION) => {
                return Err(StateError::NewerVersion {
                    path: path.to_owned(),
                    found: v,
                    supported: STATE_VERSION,
                })
            }
            Some(v) if v == u64::from(STATE_VERSION) => {}
            _ => {
                return Err(StateError::Corrupt {
                    path: path.to_owned(),
                    reason: format!(
                        "missing or unsupported \"version\" (expected {STATE_VERSION})"
                    ),
                })
            }
        }

        let file: StateFile = serde_json::from_slice(&bytes).map_err(corrupt)?;
        let mut rotations = file.rotations;
        rotations.sort_by(|a, b| a.rotation_id.cmp(&b.rotation_id));
        if rotations
            .windows(2)
            .any(|w| w[0].rotation_id == w[1].rotation_id)
        {
            return Err(StateError::Corrupt {
                path: path.to_owned(),
                reason: "duplicate rotation_id".to_owned(),
            });
        }
        Ok(Self { rotations })
    }
}

/// Describes a JSON error by category and position. serde_json's own
/// message can quote the input, so it is not used.
fn describe(err: &serde_json::Error) -> String {
    use serde_json::error::Category;
    let what = match err.classify() {
        Category::Io => "read error",
        Category::Syntax => "malformed JSON",
        Category::Data => "unexpected field or value",
        Category::Eof => "file ends early",
    };
    format!("{what} at line {} column {}", err.line(), err.column())
}

/// The state file opened for writing, holding its lock until dropped.
#[derive(Debug)]
pub struct StateStore {
    path: PathBuf,
    lock: LockFile,
    snapshot: StateSnapshot,
}

impl StateStore {
    /// Takes the lock on `path`, removes a temp file left by an interrupted
    /// write, and loads the state. A missing file is an empty state; the
    /// file is created by the first [`upsert`](Self::upsert).
    ///
    /// Fails at once with [`StateError::Locked`] if another process holds
    /// the lock, and with [`StateError::NewerVersion`] if a newer rotate
    /// wrote the file.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StateError> {
        let path = path.into();
        let lock = LockFile::try_acquire(&lock_path(&path)).map_err(|err| match err {
            FsError::Locked { path } => StateError::Locked { lock: path },
            other => StateError::Fs(other),
        })?;
        fsutil::remove_stale_temp(&path)?;
        let snapshot = StateSnapshot::load(&path)?;
        Ok(Self {
            path,
            lock,
            snapshot,
        })
    }

    /// Loads the state without taking the lock, for read-only commands such
    /// as `status`. A temp file left by an interrupted write is ignored.
    pub fn read(path: &Path) -> Result<StateSnapshot, StateError> {
        StateSnapshot::load(path)
    }

    /// The state file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The lock file this store holds.
    pub fn lock_path(&self) -> &Path {
        self.lock.path()
    }

    /// The loaded state.
    pub fn snapshot(&self) -> &StateSnapshot {
        &self.snapshot
    }

    /// Every rotation, sorted by `rotation_id`.
    pub fn rotations(&self) -> &[Rotation] {
        self.snapshot.rotations()
    }

    /// The rotation with this id.
    pub fn get(&self, rotation_id: &str) -> Option<&Rotation> {
        self.snapshot.get(rotation_id)
    }

    /// Rotations not yet at a terminal step (FR19).
    pub fn list_in_progress(&self) -> Vec<&Rotation> {
        self.snapshot.list_in_progress()
    }

    /// Inserts or replaces the rotation with the same id and writes the
    /// file atomically. `updated_at` is set to now, and kept strictly later
    /// than the stored value; `started_at` is kept from the stored record.
    /// On error the in-memory state is unchanged.
    pub fn upsert(&mut self, mut rotation: Rotation) -> Result<&Rotation, StateError> {
        if rotation.rotation_id.is_empty() {
            return Err(StateError::InvalidRotation("rotation_id is empty"));
        }
        let position = self.snapshot.position(&rotation.rotation_id);
        let mut now = OffsetDateTime::now_utc();
        if let Ok(i) = position {
            let stored = &self.snapshot.rotations[i];
            rotation.started_at = stored.started_at;
            let floor = stored.updated_at + Duration::nanoseconds(1);
            if now < floor {
                now = floor;
            }
        }
        rotation.updated_at = now;

        let mut rotations = self.snapshot.rotations.clone();
        let index = match position {
            Ok(i) => {
                rotations[i] = rotation;
                i
            }
            Err(i) => {
                rotations.insert(i, rotation);
                i
            }
        };
        let file = StateFile {
            version: STATE_VERSION,
            rotations,
        };
        let mut bytes = serde_json::to_vec_pretty(&file).map_err(|err| StateError::Corrupt {
            path: self.path.clone(),
            reason: describe(&err),
        })?;
        bytes.push(b'\n');
        fsutil::write_atomic(&self.path, &bytes)?;

        self.snapshot.rotations = file.rotations;
        let saved = &self.snapshot.rotations[index];
        tracing::debug!(
            rotation_id = %saved.rotation_id,
            provider = %saved.provider,
            fingerprint = %saved.fingerprint,
            step = ?saved.step,
            "state saved"
        );
        Ok(saved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn fp(text: &str) -> Fingerprint {
        Fingerprint::of(text.as_bytes())
    }

    fn state_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join(".rotate/state.json")
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn upsert_creates_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(&dir);
        let mut store = StateStore::open(&path).unwrap();
        assert!(!path.exists());
        store
            .upsert(Rotation::new("rot-0001", "aws", fp("old")))
            .unwrap();

        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let text = std::fs::read_to_string(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["rotations"][0]["rotation_id"], "rot-0001");
        assert_eq!(json["rotations"][0]["step"], "planned");
    }

    #[test]
    fn upsert_moves_step_and_updated_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(&dir);
        let mut store = StateStore::open(&path).unwrap();
        let mut rotation = Rotation::new("rot-0001", "aws", fp("old"));
        rotation.step = Step::Created;
        let first = store.upsert(rotation).unwrap().clone();

        let mut next = first.clone();
        next.step = Step::ConsumersUpdated;
        next.started_at = OffsetDateTime::UNIX_EPOCH;
        store.upsert(next).unwrap();
        drop(store);

        let snapshot = StateStore::read(&path).unwrap();
        let loaded = snapshot.get("rot-0001").unwrap();
        assert_eq!(loaded.step, Step::ConsumersUpdated);
        assert!(loaded.updated_at > first.updated_at);
        assert_eq!(loaded.started_at, first.started_at);

        let reopened = StateStore::open(&path).unwrap();
        assert_eq!(reopened.get("rot-0001"), Some(loaded));
    }

    #[test]
    fn stale_temp_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(&dir);
        let mut store = StateStore::open(&path).unwrap();
        store
            .upsert(Rotation::new("rot-0001", "aws", fp("old")))
            .unwrap();
        let valid = store.snapshot().clone();
        drop(store);

        let temp = path.with_file_name("state.json.tmp");
        std::fs::write(&temp, b"{ garbage").unwrap();

        assert_eq!(StateStore::read(&path).unwrap(), valid);
        assert!(temp.exists(), "a reader leaves the temp file alone");
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.snapshot(), &valid);
        assert!(!temp.exists(), "the writer removes the stale temp file");
    }

    #[test]
    fn second_open_in_process_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(&dir);
        let held = StateStore::open(&path).unwrap();
        let err = StateStore::open(&path).unwrap_err();
        assert!(matches!(err, StateError::Locked { .. }), "{err}");
        assert!(err.is_usage());
        assert!(err
            .to_string()
            .contains(&lock_path(&path).display().to_string()));
        assert_eq!(held.lock_path(), lock_path(&path));
    }

    #[test]
    fn read_without_lock_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(&dir);
        let mut store = StateStore::open(&path).unwrap();
        store
            .upsert(Rotation::new("rot-0001", "aws", fp("old")))
            .unwrap();
        assert_eq!(StateStore::read(&path).unwrap().rotations().len(), 1);
    }

    #[test]
    fn list_in_progress_skips_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(state_path(&dir)).unwrap();
        let mut done = Rotation::new("rot-done", "aws", fp("a"));
        done.step = Step::Revoked;
        let mut pending = Rotation::new("rot-pending", "aws", fp("b"));
        pending.step = Step::PendingRevoke;
        pending.revoke_not_before = Some(OffsetDateTime::now_utc() + Duration::hours(1));
        store.upsert(done).unwrap();
        store.upsert(pending).unwrap();

        let in_progress = store.list_in_progress();
        assert_eq!(in_progress.len(), 1);
        assert_eq!(in_progress[0].rotation_id, "rot-pending");
    }

    #[test]
    fn newer_version_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        crate::fsutil::write_atomic(&path, br#"{"version": 99}"#).unwrap();
        for err in [
            StateStore::open(&path).unwrap_err(),
            StateStore::read(&path).unwrap_err(),
        ] {
            assert!(matches!(err, StateError::NewerVersion { found: 99, .. }));
            let msg = err.to_string();
            assert!(msg.contains("version 99"), "{msg}");
            assert!(msg.contains("newer rotate"), "{msg}");
            assert!(err.is_usage());
        }
    }

    #[test]
    fn missing_version_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        crate::fsutil::write_atomic(&path, br#"{"rotations": []}"#).unwrap();
        let err = StateStore::read(&path).unwrap_err();
        assert!(matches!(err, StateError::Corrupt { .. }), "{err}");
    }

    #[test]
    fn corrupt_file_reports_position_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let body = br#"{"version": 1, "rotations": [{"rotation_id": "contents-canary"}]}"#;
        crate::fsutil::write_atomic(&path, body).unwrap();
        let err = StateStore::read(&path).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, StateError::Corrupt { .. }), "{msg}");
        assert!(msg.contains("line 1"), "{msg}");
        assert!(!msg.contains("contents-canary"), "{msg}");
    }

    #[test]
    fn unknown_field_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        crate::fsutil::write_atomic(&path, br#"{"version": 1, "rotations": [], "extra": 1}"#)
            .unwrap();
        assert!(matches!(
            StateStore::read(&path),
            Err(StateError::Corrupt { .. })
        ));
    }

    #[test]
    fn wide_mode_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, br#"{"version": 1, "rotations": []}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = StateStore::open(&path).unwrap_err();
        assert!(
            matches!(err, StateError::Fs(FsError::WideMode { .. })),
            "{err}"
        );
        assert!(err.is_usage());
    }

    #[test]
    fn empty_rotation_id_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(state_path(&dir)).unwrap();
        let err = store.upsert(Rotation::new("", "aws", fp("a"))).unwrap_err();
        assert!(matches!(err, StateError::InvalidRotation(_)));
        assert!(store.rotations().is_empty());
    }

    #[test]
    fn step_json_names() {
        let names: Vec<String> = [
            Step::Planned,
            Step::Created,
            Step::ConsumersUpdated,
            Step::Verified,
            Step::PendingRevoke,
            Step::Revoked,
            Step::Failed,
            Step::RolledBack,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
        assert_eq!(
            names,
            [
                "\"planned\"",
                "\"created\"",
                "\"consumers_updated\"",
                "\"verified\"",
                "\"pending_revoke\"",
                "\"revoked\"",
                "\"failed\"",
                "\"rolled_back\""
            ]
        );
        assert!(!Step::Failed.is_terminal());
        assert!(Step::RolledBack.is_terminal());
    }

    #[test]
    fn full_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = state_path(&dir);
        let mut store = StateStore::open(&path).unwrap();
        let mut rotation = Rotation::new("rot-0001", "aws", fp("old"));
        rotation.replacement_fingerprint = Some(fp("new"));
        rotation.replacement_ref = Some("key-id-0002".to_owned());
        rotation.step = Step::PendingRevoke;
        rotation.consumers = vec![ConsumerState {
            consumer: "github-actions".to_owned(),
            consumer_ref: "org/repo:AWS_SECRET_ACCESS_KEY".to_owned(),
            status: ConsumerStatus::Updated,
        }];
        rotation.revoke_not_before = Some(OffsetDateTime::now_utc() + Duration::minutes(15));
        rotation.force = true;
        let saved = store.upsert(rotation).unwrap().clone();
        drop(store);
        assert_eq!(
            StateStore::read(&path).unwrap().get("rot-0001"),
            Some(&saved)
        );
    }
}
