//! Redaction of secret values from text (SHA-218, NFR2).
//!
//! [`redact`] replaces two kinds of content:
//!
//! - every live [`SecretValue`](crate::secret::SecretValue) of 8 bytes or
//!   more, in raw, `Debug`-escaped, percent-encoded and base64 forms, with
//!   `[REDACTED sha256:<16 hex>]` (the value's fingerprint);
//! - provider-shaped tokens (GitHub, npm, OpenAI, and AWS secret keys that
//!   follow a key id) with `[REDACTED <provider>]`, whether or not they were
//!   ever registered.
//!
//! Values register themselves when a `SecretValue` is built and leave the
//! registry when the last copy drops. [`layer`] and [`subscriber`] apply
//! [`redact`] to every tracing event; the audit log (SHA-219) and the console
//! (SHA-246) call [`redact`] directly.
//!
//! Not caught: a value base64-encoded together with other bytes (for example
//! HTTP Basic auth of `user:token`), and values shorter than 8 bytes.

mod layer;
mod patterns;
pub(crate) mod registry;

use std::borrow::Cow;
use std::cell::Cell;
use std::sync::{Arc, PoisonError, RwLock};

use zeroize::Zeroizing;

pub use layer::{layer, level_for, subscriber, RedactingMakeWriter, RedactingWriter};
pub use registry::MIN_LEN;

use registry::Entry;

/// Returns `text` with every registered secret value and every
/// provider-shaped token replaced by a marker. Borrows when nothing matched.
pub fn redact(text: &str) -> Cow<'_, str> {
    let _busy = Busy::enter();
    match matcher().replace(text) {
        Cow::Borrowed(t) => patterns::redact(t),
        Cow::Owned(s) => {
            let s = Zeroizing::new(s);
            Cow::Owned(patterns::redact(&s).into_owned())
        }
    }
}

thread_local! {
    static BUSY: Cell<bool> = const { Cell::new(false) };
}

/// Marks this thread as inside [`redact`] until dropped, so a panic raised
/// by the redactor can be reported without calling back into it.
pub(crate) struct Busy(bool);

impl Busy {
    fn enter() -> Self {
        Self(BUSY.with(|busy| busy.replace(true)))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let was = self.0;
        BUSY.with(|busy| busy.set(was));
    }
}

/// Marks this thread as redacting, for tests of the panic hook.
#[cfg(test)]
pub(crate) fn busy_for_test() -> Busy {
    Busy::enter()
}

/// True while this thread is inside [`redact`]. The panic hook (SHA-246)
/// checks it: redacting a panic raised by the redactor would re-enter a
/// half-initialized pattern and block forever.
pub fn in_progress() -> bool {
    BUSY.with(Cell::get)
}

/// The current matcher, rebuilt when the registry has changed since the
/// cached one was built.
fn matcher() -> Arc<Matcher> {
    static CACHE: RwLock<Option<Arc<Matcher>>> = RwLock::new(None);
    let current = registry::generation();
    if let Some(m) = CACHE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
    {
        if m.generation == current {
            return Arc::clone(m);
        }
    }
    let built = Arc::new(Matcher::build());
    let mut cache = CACHE.write().unwrap_or_else(PoisonError::into_inner);
    let newer = cache
        .as_ref()
        .is_some_and(|m| m.generation > built.generation);
    if !newer {
        *cache = Some(Arc::clone(&built));
    }
    built
}

/// One needle: entry index and form index.
type Needle = (usize, usize);

/// Finds registered forms in one left-to-right pass.
///
/// Needles are indexed by their first two bytes; a 65,536-bit bitmap rejects
/// most positions with one load. It holds `Arc<Entry>` rather than copies of
/// the needles, so every copy of a value stays in zeroized memory.
struct Matcher {
    generation: u64,
    entries: Vec<Arc<Entry>>,
    bitmap: Box<[u64; 1024]>,
    /// Candidates per two-byte prefix, longest needle first.
    candidates: std::collections::HashMap<u16, Vec<Needle>>,
}

impl Matcher {
    fn build() -> Self {
        let (generation, entries) = registry::snapshot();
        let mut bitmap = Box::new([0u64; 1024]);
        let mut candidates: std::collections::HashMap<u16, Vec<Needle>> = Default::default();
        for (e, entry) in entries.iter().enumerate() {
            for (f, form) in entry.forms.iter().enumerate() {
                let b = form.as_bytes();
                let key = u16::from_le_bytes([b[0], b[1]]);
                bitmap[usize::from(key >> 6)] |= 1 << (key & 63);
                candidates.entry(key).or_default().push((e, f));
            }
        }
        for list in candidates.values_mut() {
            list.sort_by_key(|&(e, f)| std::cmp::Reverse(entries[e].forms[f].len()));
        }
        Self {
            generation,
            entries,
            bitmap,
            candidates,
        }
    }

    fn replace<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.entries.is_empty() {
            return Cow::Borrowed(text);
        }
        let bytes = text.as_bytes();
        let mut out: Option<String> = None;
        let mut copied = 0;
        let mut i = 0;
        while i + 1 < bytes.len() {
            let key = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if self.bitmap[usize::from(key >> 6)] & (1 << (key & 63)) == 0 {
                i += 1;
                continue;
            }
            let hit = self.candidates.get(&key).and_then(|list| {
                list.iter().find_map(|&(e, f)| {
                    let form = self.entries[e].forms[f].as_bytes();
                    bytes[i..].starts_with(form).then_some((e, form.len()))
                })
            });
            match hit {
                Some((e, len)) => {
                    // Needles are valid UTF-8 and so is `text`, so a match
                    // starts and ends on char boundaries.
                    let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
                    buf.push_str(&text[copied..i]);
                    buf.push_str(&self.entries[e].marker);
                    i += len;
                    copied = i;
                }
                None => i += 1,
            }
        }
        match out {
            None => Cow::Borrowed(text),
            Some(mut buf) => {
                buf.push_str(&text[copied..]);
                Cow::Owned(buf)
            }
        }
    }
}

#[cfg(test)]
mod tests;
