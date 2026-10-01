//! Process-wide registry of live secret values (SHA-218).
//!
//! Every [`SecretValue`](crate::secret::SecretValue) holds a
//! [`Registration`]. Clones of one value share one [`Entry`], counted by
//! reference; the entry is removed when the last registration drops. Each
//! entry keeps the value and its encoded forms in zeroized memory so the
//! matcher can find them in log text without copying them anywhere else.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::secret::Fingerprint;

/// Values and forms shorter than this are not matched: a short value would
/// replace common words in every log line. Real tokens are 20 bytes or more.
pub const MIN_LEN: usize = 8;

type Key = [u8; 32];

/// One distinct registered value: its marker and every form it is matched in.
pub(crate) struct Entry {
    pub(crate) marker: String,
    pub(crate) forms: Vec<Zeroizing<String>>,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Key, (Arc<Entry>, usize)>,
}

static INNER: OnceLock<Mutex<Inner>> = OnceLock::new();

/// Bumped on every insert and removal so the matcher knows to rebuild.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Locks the registry. A poisoned lock is recovered: the map is only ever
/// changed by whole-statement inserts and removals, and a drop running
/// during a panic must not panic again.
fn lock() -> MutexGuard<'static, Inner> {
    INNER
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// Snapshot of the current entries and the generation it was taken at.
pub(crate) fn snapshot() -> (u64, Vec<Arc<Entry>>) {
    let inner = lock();
    let generation = generation();
    let entries = inner.entries.values().map(|(e, _)| Arc::clone(e)).collect();
    (generation, entries)
}

/// Number of distinct registered values. For tests.
#[cfg(test)]
pub(crate) fn distinct_count_for(bytes: &[u8]) -> usize {
    let key: Key = Sha256::digest(bytes).into();
    lock().entries.get(&key).map_or(0, |(_, count)| *count)
}

/// Keeps one value in the registry while it is alive.
pub(crate) struct Registration {
    key: Key,
}

impl Registration {
    /// Registers `bytes`, or returns `None` when they are too short or not
    /// valid UTF-8 to ever be matched in log text.
    pub(crate) fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MIN_LEN {
            return None;
        }
        let text = std::str::from_utf8(bytes).ok()?;
        let key: Key = Sha256::digest(bytes).into();
        let mut inner = lock();
        if let Some((_, count)) = inner.entries.get_mut(&key) {
            *count += 1;
        } else {
            let entry = Arc::new(Entry::build(text, Fingerprint::of(bytes)));
            inner.entries.insert(key, (entry, 1));
            GENERATION.fetch_add(1, Ordering::AcqRel);
        }
        Some(Self { key })
    }
}

impl Clone for Registration {
    fn clone(&self) -> Self {
        let mut inner = lock();
        if let Some((_, count)) = inner.entries.get_mut(&self.key) {
            *count += 1;
        }
        Self { key: self.key }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut inner = lock();
        let remove = match inner.entries.get_mut(&self.key) {
            Some((_, count)) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if remove {
            inner.entries.remove(&self.key);
            GENERATION.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Entry {
    fn build(text: &str, fingerprint: Fingerprint) -> Self {
        let mut forms: Vec<Zeroizing<String>> = Vec::with_capacity(7);
        let mut push = |form: Zeroizing<String>| {
            if form.len() >= MIN_LEN && !forms.iter().any(|f| f.as_str() == form.as_str()) {
                forms.push(form);
            }
        };
        push(Zeroizing::new(text.to_owned()));
        push(debug_escaped(text));
        push(percent_encoded(text));
        for (alphabet, pad) in [
            (STANDARD, true),
            (STANDARD, false),
            (URL_SAFE, true),
            (URL_SAFE, false),
        ] {
            push(base64(text.as_bytes(), alphabet, pad));
        }
        Self {
            marker: format!("[REDACTED {fingerprint}]"),
            forms,
        }
    }
}

/// What `{:?}` prints for the value, without the surrounding quotes: the
/// form a `&str` field takes in the fmt layer's output.
fn debug_escaped(text: &str) -> Zeroizing<String> {
    // Worst case is `\u{10ffff}` (10 bytes) per char; reserving it up front
    // means the buffer never reallocates and leaves no unwiped copy.
    let mut out = Zeroizing::new(String::with_capacity(text.chars().count() * 10 + 2));
    let _ = write!(out, "{text:?}");
    Zeroizing::new(out[1..out.len() - 1].to_owned())
}

/// RFC 3986 percent-encoding: unreserved characters kept, everything else
/// as `%XX` with uppercase hex, as `urlencoding::encode` does.
fn percent_encoded(text: &str) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Zeroizing::new(String::with_capacity(text.len() * 3));
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
    }
    out
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(3) * 4));
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextets = [n >> 18, n >> 12, n >> 6, n];
        let used = chunk.len() + 1;
        for (i, s) in sextets.iter().enumerate() {
            if i < used {
                out.push(char::from(alphabet[(s & 0x3f) as usize]));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoders_match_known_answers() {
        assert_eq!(
            base64(b"any carnal pleas", STANDARD, true).as_str(),
            "YW55IGNhcm5hbCBwbGVhcw=="
        );
        assert_eq!(
            base64(b"any carnal pleas", STANDARD, false).as_str(),
            "YW55IGNhcm5hbCBwbGVhcw"
        );
        assert_eq!(base64(b"\xfb\xff", URL_SAFE, true).as_str(), "-_8=");
        assert_eq!(percent_encoded("a b/c~").as_str(), "a%20b%2Fc~");
        assert_eq!(debug_escaped("a\"b\\c").as_str(), "a\\\"b\\\\c");
    }

    #[test]
    fn short_and_non_utf8_values_not_registered() {
        assert!(Registration::new(b"short").is_none());
        assert!(Registration::new(&[0xff; 16]).is_none());
        assert!(Registration::new(b"long-enough-value").is_some());
    }

    #[test]
    fn clones_share_one_entry_and_drop_last_removes() {
        let value = b"registry-clone-test-value";
        let first = Registration::new(value).unwrap();
        let second = first.clone();
        let third = Registration::new(value).unwrap();
        assert_eq!(distinct_count_for(value), 3);
        drop(first);
        drop(third);
        assert_eq!(distinct_count_for(value), 1);
        drop(second);
        assert_eq!(distinct_count_for(value), 0);
    }

    #[test]
    fn forms_are_deduplicated() {
        // Nothing to escape or percent-encode: raw, debug and percent forms
        // are identical and kept once.
        let entry = Entry::build("plainvalue123", Fingerprint::of(b"plainvalue123"));
        let raw = entry
            .forms
            .iter()
            .filter(|f| f.as_str() == "plainvalue123")
            .count();
        assert_eq!(raw, 1);
        assert!(entry.marker.starts_with("[REDACTED sha256:"));
    }
}
