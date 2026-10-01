//! Owner-only files for local state (SHA-220) and the audit log (SHA-219).
//!
//! Every file rotate keeps on disk is created with mode 0600 inside a
//! directory created with mode 0700 (NFR6). An existing file whose mode lets
//! a group or other users in is refused rather than silently tightened: a
//! wide mode means someone may already have read it, and the operator should
//! know. Symlinks and other non-regular files are refused too.
//!
//! The helpers:
//! - [`ensure_private_dir`] creates a missing directory with mode 0700.
//! - [`check_private`] checks an existing file's type and mode.
//! - [`open_private`] opens or creates a file with mode 0600, for example
//!   with `append(true)` for an append-only log.
//! - [`write_atomic`] replaces a file through a temp file, `fsync` and
//!   `rename`, so a reader sees the old contents or the new, never half.
//! - [`LockFile`] is an exclusive advisory lock (flock) that the kernel
//!   releases when the process exits, even after a crash.
//!
//! Linux and macOS only. flock is not reliable on every network file system,
//! so a state directory on NFS is unsupported.

#![cfg(unix)]

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Mode of every file rotate creates.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Mode of every directory rotate creates.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Permission bits that must be clear on an existing file.
const GROUP_OTHER_BITS: u32 = 0o077;

/// Suffix of the temp file [`write_atomic`] writes before renaming.
const TEMP_SUFFIX: &str = ".tmp";

/// Why a private-file operation failed. Messages name paths and modes only,
/// never file contents.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// An I/O call failed.
    #[error("could not {op} {}: {source}", path.display())]
    Io {
        /// What was being done, for example "write".
        op: &'static str,
        /// The file or directory involved.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// An existing file can be read or written by other users.
    #[error(
        "{} has mode {mode:04o}, which lets other users read it; check who could have seen it, then run `chmod 600` on it",
        path.display()
    )]
    WideMode {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The path exists but is a symlink, directory or other non-regular file.
    #[error("{} is not a regular file", path.display())]
    NotRegular {
        /// The path.
        path: PathBuf,
    },
    /// Another process holds the lock.
    #[error("{} is locked by another process", path.display())]
    Locked {
        /// The lock file.
        path: PathBuf,
    },
}

impl FsError {
    fn io(op: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            op,
            path: path.to_owned(),
            source,
        }
    }
}

/// Creates `dir` and any missing parents with mode 0700. Existing
/// directories are left as they are. An empty path (the parent of a bare
/// file name) means the working directory and is a no-op.
pub fn ensure_private_dir(dir: &Path) -> Result<(), FsError> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(PRIVATE_DIR_MODE)
        .create(dir)
        .map_err(|e| FsError::io("create directory", dir, e))
}

/// Checks that `path`, if it exists, is a regular file (not a symlink) with
/// no group or other permission bits. Returns `false` when it does not exist.
pub fn check_private(path: &Path) -> Result<bool, FsError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            check_metadata(path, &meta)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(FsError::io("inspect", path, e)),
    }
}

fn check_metadata(path: &Path, meta: &fs::Metadata) -> Result<(), FsError> {
    if !meta.file_type().is_file() {
        return Err(FsError::NotRegular {
            path: path.to_owned(),
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & GROUP_OTHER_BITS != 0 {
        return Err(FsError::WideMode {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

/// Opens `path` with `options`, creating it with mode 0600 (and its parent
/// directory with mode 0700) if `options` allows creation. An existing file
/// with a wider mode, or one that is not a regular file, is refused.
///
/// The audit log (SHA-219) opens with
/// `OpenOptions::new().append(true).create(true)`, then calls
/// [`File::sync_data`] after each line.
pub fn open_private(path: &Path, options: &OpenOptions) -> Result<File, FsError> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    check_private(path)?;
    let file = options
        .clone()
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .map_err(|e| FsError::io("open", path, e))?;
    // Check the opened file too: something could have replaced the path
    // between the check above and the open.
    let meta = file
        .metadata()
        .map_err(|e| FsError::io("inspect", path, e))?;
    check_metadata(path, &meta)?;
    Ok(file)
}

/// The temp file [`write_atomic`] uses for `path`: `path` plus `.tmp`.
pub fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(TEMP_SUFFIX);
    PathBuf::from(name)
}

/// Deletes a temp file left behind by an interrupted [`write_atomic`].
/// Call it only while holding the lock that guards `path`.
pub fn remove_stale_temp(path: &Path) -> Result<(), FsError> {
    let temp = temp_path(path);
    match fs::remove_file(&temp) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(FsError::io("remove", &temp, e)),
    }
}

/// Replaces the contents of `path` with `bytes` atomically, with mode 0600.
///
/// Writes `path.tmp` (removing a stale one first), `fsync`s it, renames it
/// over `path`, then `fsync`s the directory so the rename survives a power
/// cut. The temp name is fixed, so the caller must hold a lock that keeps
/// other writers out. An existing `path` with a wide mode is refused.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), FsError> {
    let parent = path.parent().unwrap_or(Path::new(""));
    ensure_private_dir(parent)?;
    check_private(path)?;
    remove_stale_temp(path)?;

    let temp = temp_path(path);
    let result = write_new(&temp, bytes)
        .and_then(|()| fs::rename(&temp, path).map_err(|e| FsError::io("rename", &temp, e)));
    if result.is_err() {
        // Best effort: a leftover temp file is removed by the next writer.
        let _ = fs::remove_file(&temp);
    }
    result?;
    sync_dir(parent)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), FsError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .map_err(|e| FsError::io("create", path, e))?;
    file.write_all(bytes)
        .map_err(|e| FsError::io("write", path, e))?;
    file.sync_all().map_err(|e| FsError::io("sync", path, e))
}

fn sync_dir(dir: &Path) -> Result<(), FsError> {
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| FsError::io("sync directory", dir, e))
}

/// An exclusive advisory lock on a lock file, held until this value is
/// dropped or the process exits.
///
/// The lock is flock(2): it does not wait, and the kernel releases it when
/// the holder's file descriptor closes, including when the process is
/// killed, so a crash never leaves a stale lock. The lock file is left in
/// place on release; deleting it would let a third process lock a new file
/// while a second still holds the old one.
#[derive(Debug)]
pub struct LockFile {
    path: PathBuf,
    _file: File,
}

impl LockFile {
    /// Creates `path` (mode 0600) if needed and takes the lock without
    /// waiting. Returns [`FsError::Locked`] at once if another process, or
    /// another open handle in this one, holds it.
    pub fn try_acquire(path: &Path) -> Result<Self, FsError> {
        let file = open_private(path, OpenOptions::new().read(true).write(true).create(true))?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                path: path.to_owned(),
                _file: file,
            }),
            Err(TryLockError::WouldBlock) => Err(FsError::Locked {
                path: path.to_owned(),
            }),
            Err(TryLockError::Error(e)) => Err(FsError::io("lock", path, e)),
        }
    }

    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn write_atomic_creates_private_file_and_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/state.json");
        write_atomic(&path, b"one").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert!(!temp_path(&path).exists());
    }

    #[test]
    fn write_atomic_replaces_and_keeps_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, b"one").unwrap();
        fs::write(temp_path(&path), b"stale").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(mode(&path), 0o600);
        assert!(!temp_path(&path).exists());
    }

    #[test]
    fn write_atomic_refuses_wide_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = write_atomic(&path, b"new").unwrap_err();
        assert!(
            matches!(err, FsError::WideMode { mode: 0o644, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("chmod 600"));
        assert_eq!(fs::read(&path).unwrap(), b"old");
    }

    #[test]
    fn open_private_append_creates_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".rotate/audit.jsonl");
        let options = {
            let mut o = OpenOptions::new();
            o.append(true).create(true);
            o
        };
        let mut file = open_private(&path, &options).unwrap();
        file.write_all(b"line\n").unwrap();
        drop(file);
        let mut file = open_private(&path, &options).unwrap();
        file.write_all(b"line\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"line\nline\n");
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn open_private_append_refuses_0644() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = open_private(&path, OpenOptions::new().append(true).create(true)).unwrap_err();
        assert!(matches!(err, FsError::WideMode { .. }), "{err}");
    }

    #[test]
    fn symlink_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            check_private(&link),
            Err(FsError::NotRegular { .. })
        ));
    }

    #[test]
    fn check_private_missing_is_false() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!check_private(&dir.path().join("absent")).unwrap());
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json.lock");
        let held = LockFile::try_acquire(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        let err = LockFile::try_acquire(&path).unwrap_err();
        assert!(matches!(err, FsError::Locked { .. }), "{err}");
        drop(held);
        LockFile::try_acquire(&path).unwrap();
        assert!(path.exists());
    }
}
