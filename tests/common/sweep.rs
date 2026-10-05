//! The leak sweep (SHA-265), shared by the leakage audit and the live
//! tests (SHA-268): random canary secrets, and a search for every canary in
//! every encoding over buffers, file names and directory trees. A hit names
//! the place and byte offset, never the bytes.

use std::collections::HashMap;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine as _;

// ---------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------

/// The alphabet of an AWS secret access key. `/` and `+` make the
/// URL-encoded form differ from the raw one.
pub const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

/// A fresh pseudo-random generator per call: clock, process id and a
/// counter, mixed with splitmix64.
pub fn rng() -> impl FnMut() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut state = nanos
        ^ (u64::from(std::process::id()) << 32)
        ^ COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9E37_79B9);
    move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// A unique canary of `len` chars from [`ALPHABET`], always holding a `/`
/// and a `+`.
pub fn canary_of(len: usize) -> String {
    assert!(len >= 8);
    let mut next = rng();
    let mut bytes: Vec<u8> = (0..len)
        .map(|_| ALPHABET[(next() % ALPHABET.len() as u64) as usize])
        .collect();
    bytes[3] = b'/';
    bytes[len - 4] = b'+';
    String::from_utf8(bytes).unwrap()
}

/// A unique 32-char canary.
pub fn canary() -> String {
    canary_of(32)
}

/// A value to search for, with the name failures use for it.
#[derive(Clone)]
pub struct Canary {
    pub label: String,
    pub value: String,
}

impl Canary {
    pub fn new(label: &str, value: &str) -> Self {
        Self {
            label: label.to_owned(),
            value: value.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// One match: where, and which canary in which encoding. Never the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub place: String,
    pub offset: usize,
    pub label: String,
    pub encoding: &'static str,
}

impl fmt::Display for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at byte {}: {} ({})",
            self.place, self.offset, self.label, self.encoding
        )
    }
}

/// The part of the base64 encoding of `value` that does not depend on its
/// neighbours when it starts `align` bytes into a 3-byte group: what any
/// base64 blob holding `value` at that alignment contains.
pub fn base64_core(engine: &base64::engine::GeneralPurpose, value: &[u8], align: usize) -> String {
    let mut padded = vec![0u8; align];
    padded.extend_from_slice(value);
    let encoded = engine.encode(&padded);
    let start = (align * 8).div_ceil(6);
    let end = (padded.len() * 8) / 6;
    encoded[start..end].to_owned()
}

/// Every encoding of `value` the sweep looks for.
pub fn encodings(value: &str) -> Vec<(&'static str, String)> {
    let bytes = value.as_bytes();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut out = vec![
        ("raw", value.to_owned()),
        ("url-encoded", urlencoding::encode(value).into_owned()),
        ("hex", hex.clone()),
        ("HEX", hex.to_uppercase()),
    ];
    for align in 0..3 {
        out.push(("base64", base64_core(&STANDARD, bytes, align)));
        out.push(("base64url", base64_core(&URL_SAFE, bytes, align)));
    }
    out
}

/// Searches buffers and directory trees for every canary in every
/// encoding, with one regex alternation (Aho-Corasick underneath).
pub struct Sweep {
    regex: regex::bytes::Regex,
    needles: HashMap<Vec<u8>, (String, &'static str)>,
}

impl Sweep {
    pub fn new(canaries: &[Canary]) -> Self {
        let mut needles = HashMap::new();
        let mut patterns = Vec::new();
        for canary in canaries {
            for (encoding, needle) in encodings(&canary.value) {
                if needles.contains_key(needle.as_bytes()) {
                    continue;
                }
                patterns.push(regex::escape(&needle));
                needles.insert(needle.into_bytes(), (canary.label.clone(), encoding));
            }
        }
        let regex = regex::bytes::RegexBuilder::new(&patterns.join("|"))
            .unicode(false)
            .size_limit(1 << 26)
            .build()
            .unwrap();
        Self { regex, needles }
    }

    /// Every match in `bytes`, labelled `place`.
    pub fn scan(&self, place: &str, bytes: &[u8]) -> Vec<Hit> {
        self.regex
            .find_iter(bytes)
            .map(|m| {
                let (label, encoding) = &self.needles[m.as_bytes()];
                Hit {
                    place: place.to_owned(),
                    offset: m.start(),
                    label: label.clone(),
                    encoding,
                }
            })
            .collect()
    }

    /// Every match in the names and contents of the files under `root`,
    /// except those under a `skip` path. Symlinks are not followed; files
    /// are read in parallel.
    pub fn scan_dir(&self, root: &Path, skip: &[PathBuf]) -> Vec<Hit> {
        let mut files = Vec::new();
        let mut hits = Vec::new();
        let mut dirs = vec![root.to_path_buf()];
        while let Some(dir) = dirs.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => panic!("cannot list {}: {err}", dir.display()),
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if skip.iter().any(|s| path.starts_with(s)) {
                    continue;
                }
                let name = path.file_name().unwrap().as_encoded_bytes();
                hits.extend(self.scan(&format!("name of {}", path.display()), name));
                let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                if kind.is_dir() {
                    dirs.push(path);
                } else if kind.is_file() {
                    files.push(path);
                }
            }
        }
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let chunk = files.len().div_ceil(threads).max(1);
        std::thread::scope(|scope| {
            let workers: Vec<_> = files
                .chunks(chunk)
                .map(|paths| {
                    scope.spawn(move || {
                        let mut found = Vec::new();
                        for path in paths {
                            let bytes = std::fs::read(path).unwrap_or_else(|err| {
                                panic!("cannot read {}: {err}", path.display())
                            });
                            found.extend(self.scan(&path.display().to_string(), &bytes));
                        }
                        found
                    })
                })
                .collect();
            for worker in workers {
                hits.extend(worker.join().unwrap());
            }
        });
        hits
    }
}

/// Fails with every hit by place, offset, canary and encoding.
pub fn assert_no_hits(what: &str, hits: &[Hit]) {
    if hits.is_empty() {
        return;
    }
    let list: Vec<String> = hits.iter().map(|h| format!("  {h}")).collect();
    panic!(
        "LEAK: {} canary match(es) after {what}:\n{}",
        hits.len(),
        list.join("\n")
    );
}

/// Every file under `<work>/.rotate` is 0600 and the directory 0700 (AC3).
/// Returns the file names found.
pub fn assert_private_state(work: &Path) -> Vec<String> {
    let dir = work.join(".rotate");
    let Ok(meta) = std::fs::metadata(&dir) else {
        return Vec::new();
    };
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o700,
        "{} is not 0700",
        dir.display()
    );
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let meta = std::fs::symlink_metadata(entry.path()).unwrap();
        assert!(
            meta.file_type().is_file(),
            "{} is not a regular file",
            entry.path().display()
        );
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "{} is not 0600",
            entry.path().display()
        );
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    names
}
