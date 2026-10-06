//! Keeps secret values out of core dumps and swap (SHA-204).
//!
//! Two protections, both best effort:
//!
//! - [`harden_process`], the first call in `main`, sets the core file size
//!   limit to 0, soft and hard, on Unix, and on Linux clears the dumpable
//!   flag (`prctl(PR_SET_DUMPABLE, 0)`). A crash then writes no core file,
//!   and other processes of the same user can no longer attach to rotate or
//!   read its memory through `/proc`.
//! - Every [`SecretValue`](crate::secret::SecretValue) buffer is locked in
//!   RAM with `mlock` while it lives, so the kernel never writes it to
//!   swap. Locks do not nest and small buffers share pages, so the
//!   process-wide [`Locker`] counts the live buffers on each page and
//!   unlocks a page only when its last buffer is gone. When the OS refuses
//!   (`RLIMIT_MEMLOCK` reached or 0), the buffer stays unlocked, the secret
//!   works as before, and the first refusal of the process logs one
//!   warning.
//!
//! What this module does not lock: the redaction registry's copies of each
//! value and copies made by libraries (the HTTP client, the TLS stack, the
//! AWS SDK). The core-dump switch is process wide and covers them; swap
//! does not. Windows is not supported.
//!
//! The only `unsafe` outside tests is the two rustix calls in
//! [`SystemPages`], behind a bounds check against the buffer's capacity.

use std::collections::HashMap;
use std::io;
use std::ops::{Range, RangeInclusive};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

/// Disables core dumps for this process. Call once, first thing in `main`.
///
/// On Unix: `RLIMIT_CORE` soft and hard 0, so neither rotate nor a child
/// can raise it again. On Linux also `PR_SET_DUMPABLE` 0. Each step runs
/// even if the other failed. Errors are ignored: lowering a limit and
/// clearing the flag do not fail for an unprivileged process, and logging is
/// not installed yet when this runs.
pub fn harden_process() {
    #[cfg(unix)]
    {
        let _ = rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        );
        #[cfg(target_os = "linux")]
        let _ =
            rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
    }
    #[cfg(feature = "test-commands")]
    write_test_report();
}

/// Test hook (`test-commands` only, never in releases): when
/// `ROTATE_TEST_HARDENING_REPORT` names a file, writes the core limits and,
/// on Linux, the dumpable flag there, so `tests/hardening.rs` can check them
/// on macOS, which has no `/proc`.
#[cfg(feature = "test-commands")]
fn write_test_report() {
    use std::fmt::Write as _;

    let Some(path) = std::env::var_os("ROTATE_TEST_HARDENING_REPORT") else {
        return;
    };
    let mut report = String::new();
    #[cfg(unix)]
    {
        let show = |limit: Option<u64>| limit.map_or_else(|| "unlimited".into(), |n| n.to_string());
        let core = rustix::process::getrlimit(rustix::process::Resource::Core);
        let _ = writeln!(
            report,
            "core_soft={} core_hard={}",
            show(core.current),
            show(core.maximum)
        );
    }
    #[cfg(target_os = "linux")]
    {
        let dumpable = match rustix::process::dumpable_behavior() {
            Ok(rustix::process::DumpableBehavior::NotDumpable) => "0",
            Ok(_) => "1",
            Err(_) => "unknown",
        };
        let _ = writeln!(report, "dumpable={dumpable}");
    }
    let _ = std::fs::write(path, report);
}

/// Text of the one warning logged when the OS refuses to lock a buffer.
/// Holds the OS error only: no value, fingerprint, length or address.
const REFUSED: &str = "could not lock secret values in memory";

/// The locked range of one buffer: the address and capacity of its
/// allocation when it was locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    addr: usize,
    len: usize,
}

/// The OS calls behind a [`Locker`], replaceable in tests.
///
/// `range` is a byte range inside the allocation of `buf` (offsets from its
/// start, within its capacity). Implementations must not touch the bytes.
pub(crate) trait PageOps: Send {
    /// Locks the pages holding `range` of `buf`'s allocation.
    fn lock(&mut self, buf: &mut Vec<u8>, range: Range<usize>) -> io::Result<()>;
    /// Unlocks the pages holding `range` of `buf`'s allocation.
    fn unlock(&mut self, buf: &mut Vec<u8>, range: Range<usize>) -> io::Result<()>;
}

/// A refused lock: the OS error, and whether it is the first refusal this
/// locker has seen (the one that is logged).
pub(crate) struct Refused {
    pub(crate) error: io::Error,
    pub(crate) first: bool,
}

/// Locks buffers and counts, per page, how many locked buffers it holds.
pub(crate) struct Locker {
    ops: Box<dyn PageOps>,
    page_size: usize,
    pages: HashMap<usize, usize>,
    refused: bool,
}

impl Locker {
    /// A locker over `ops` for pages of `page_size` bytes.
    pub(crate) fn new(ops: Box<dyn PageOps>, page_size: usize) -> Self {
        Self {
            ops,
            page_size: page_size.max(1),
            pages: HashMap::new(),
            refused: false,
        }
    }

    /// Locks the whole allocation of `buf`. `Ok(None)` when it has none.
    /// The caller must not grow or shrink `buf` until [`unlock`](Self::unlock).
    pub(crate) fn lock(&mut self, buf: &mut Vec<u8>) -> Result<Option<Span>, Refused> {
        let len = buf.capacity();
        if len == 0 {
            return Ok(None);
        }
        match self.ops.lock(buf, 0..len) {
            Ok(()) => {
                let span = Span {
                    addr: buf.as_ptr() as usize,
                    len,
                };
                for page in self.pages_of(span) {
                    *self.pages.entry(page).or_insert(0) += 1;
                }
                Ok(Some(span))
            }
            Err(error) => {
                let first = !self.refused;
                self.refused = true;
                Err(Refused { error, first })
            }
        }
    }

    /// Releases `buf`'s hold on its pages and unlocks those no other locked
    /// buffer is on. Wipe `buf` first. Does nothing when `span` is not
    /// `buf`'s current allocation, so it can never unlock pages that belong
    /// to something else.
    pub(crate) fn unlock(&mut self, buf: &mut Vec<u8>, span: Span) {
        if buf.as_ptr() as usize != span.addr || buf.capacity() != span.len {
            return;
        }
        let released: Vec<usize> = self
            .pages_of(span)
            .filter(|&page| self.release(page))
            .collect();
        let mut i = 0;
        while i < released.len() {
            let first = released[i];
            let mut end = first + 1;
            while released.get(i + 1) == Some(&end) {
                end += 1;
                i += 1;
            }
            i += 1;
            // The run of pages, clipped to this buffer's own allocation.
            let from = first.saturating_mul(self.page_size).max(span.addr) - span.addr;
            let to = end.saturating_mul(self.page_size).min(span.addr + span.len) - span.addr;
            let _ = self.ops.unlock(buf, from..to);
        }
    }

    /// Drops one hold on `page`; true when it was the last.
    fn release(&mut self, page: usize) -> bool {
        match self.pages.get_mut(&page) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => {
                self.pages.remove(&page);
                true
            }
            None => false,
        }
    }

    fn pages_of(&self, span: Span) -> RangeInclusive<usize> {
        span.addr / self.page_size..=(span.addr + span.len - 1) / self.page_size
    }

    /// Number of pages currently held. For tests.
    #[cfg(test)]
    pub(crate) fn held_pages(&self) -> usize {
        self.pages.len()
    }
}

/// `mlock` and `munlock` through rustix.
struct SystemPages;

/// Pointer and length of `range` inside `buf`'s allocation, or an error
/// when the range is empty or reaches past its capacity.
#[cfg(unix)]
fn raw_range(buf: &mut Vec<u8>, range: Range<usize>) -> io::Result<(*mut std::ffi::c_void, usize)> {
    if range.start >= range.end || range.end > buf.capacity() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "range outside the buffer",
        ));
    }
    Ok((
        buf.as_mut_ptr().wrapping_add(range.start).cast(),
        range.len(),
    ))
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl PageOps for SystemPages {
    fn lock(&mut self, buf: &mut Vec<u8>, range: Range<usize>) -> io::Result<()> {
        let (ptr, len) = raw_range(buf, range)?;
        // SAFETY: `raw_range` checked that `ptr..ptr + len` is non-empty and
        // inside the allocation of `buf`, which is live and exclusively
        // borrowed for this call. The pages that range rounds out to are
        // mapped, because the allocation lies in them. mlock neither reads
        // nor writes through the pointer.
        unsafe { rustix::mm::mlock(ptr, len) }.map_err(io::Error::from)
    }

    fn unlock(&mut self, buf: &mut Vec<u8>, range: Range<usize>) -> io::Result<()> {
        let (ptr, len) = raw_range(buf, range)?;
        // SAFETY: as for `lock`: a checked, non-empty range of the live
        // allocation of `buf`, whose pages are mapped. munlock neither reads
        // nor writes through the pointer.
        unsafe { rustix::mm::munlock(ptr, len) }.map_err(io::Error::from)
    }
}

#[cfg(not(unix))]
impl PageOps for SystemPages {
    fn lock(&mut self, _: &mut Vec<u8>, _: Range<usize>) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn unlock(&mut self, _: &mut Vec<u8>, _: Range<usize>) -> io::Result<()> {
        Ok(())
    }
}

fn page_size() -> usize {
    #[cfg(unix)]
    {
        rustix::param::page_size()
    }
    #[cfg(not(unix))]
    {
        4096
    }
}

static LOCKER: OnceLock<Mutex<Locker>> = OnceLock::new();

/// The process-wide locker every [`SecretValue`](crate::secret::SecretValue)
/// uses.
pub(crate) fn locker() -> &'static Mutex<Locker> {
    LOCKER.get_or_init(|| Mutex::new(Locker::new(Box::new(SystemPages), page_size())))
}

/// A poisoned lock is recovered: the page table is changed only by whole
/// calls, and unlock runs in `Drop`, which must not panic during a panic.
fn guard(locker: &Mutex<Locker>) -> MutexGuard<'_, Locker> {
    locker.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Locks `buf` with `locker`. On the locker's first refusal logs one
/// warning, after the mutex is released, and returns `None` like every
/// later refusal: the buffer stays usable, only unlocked.
pub(crate) fn lock(locker: &Mutex<Locker>, buf: &mut Vec<u8>) -> Option<Span> {
    let result = guard(locker).lock(buf);
    match result {
        Ok(span) => span,
        Err(Refused { error, first }) => {
            if first {
                tracing::warn!(
                    "{REFUSED} ({error}); they may be written to swap. Raise the locked-memory limit (ulimit -l) to remove this warning"
                );
            }
            None
        }
    }
}

/// Unlocks a buffer locked by [`lock`]. Wipe it first.
pub(crate) fn unlock(locker: &Mutex<Locker>, buf: &mut Vec<u8>, span: Span) {
    guard(locker).unlock(buf, span);
}

/// Test doubles shared with `secret.rs`.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    /// Refuses every lock, as `mlock` does over `RLIMIT_MEMLOCK`.
    pub(crate) struct Refusing;

    impl PageOps for Refusing {
        fn lock(&mut self, _: &mut Vec<u8>, _: Range<usize>) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "simulated mlock refusal",
            ))
        }

        fn unlock(&mut self, _: &mut Vec<u8>, _: Range<usize>) -> io::Result<()> {
            Ok(())
        }
    }

    /// One call seen by [`Recording`]. Addresses are absolute.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Call {
        Lock {
            addr: usize,
            len: usize,
        },
        Unlock {
            addr: usize,
            len: usize,
            wiped: bool,
        },
    }

    /// Accepts every call and records it. `wiped` on an unlock is whether
    /// the buffer was already cleared by zeroize at that moment.
    #[derive(Clone, Default)]
    pub(crate) struct Recording(Arc<Mutex<Vec<Call>>>);

    impl Recording {
        pub(crate) fn calls(&self) -> Vec<Call> {
            self.0.lock().unwrap().clone()
        }
    }

    impl PageOps for Recording {
        fn lock(&mut self, buf: &mut Vec<u8>, range: Range<usize>) -> io::Result<()> {
            self.0.lock().unwrap().push(Call::Lock {
                addr: buf.as_ptr() as usize + range.start,
                len: range.len(),
            });
            Ok(())
        }

        fn unlock(&mut self, buf: &mut Vec<u8>, range: Range<usize>) -> io::Result<()> {
            self.0.lock().unwrap().push(Call::Unlock {
                addr: buf.as_ptr() as usize + range.start,
                len: range.len(),
                wiped: buf.is_empty(),
            });
            Ok(())
        }
    }

    /// A locker that lives for the rest of the test process, as the global
    /// one does, so secrets built with it can hold a `'static` reference.
    pub(crate) fn leaked(ops: impl PageOps + 'static, page_size: usize) -> &'static Mutex<Locker> {
        Box::leak(Box::new(Mutex::new(Locker::new(Box::new(ops), page_size))))
    }

    /// The smallest power-of-two page size at which every allocation in
    /// `bufs` falls in one page, so the test controls page sharing without
    /// controlling the allocator.
    pub(crate) fn shared_page_size(bufs: &[&Vec<u8>]) -> usize {
        let lo = bufs.iter().map(|b| b.as_ptr() as usize).min().unwrap();
        let hi = bufs
            .iter()
            .map(|b| b.as_ptr() as usize + b.capacity() - 1)
            .max()
            .unwrap();
        let mut size = 1usize;
        while lo / size != hi / size {
            size <<= 1;
        }
        size
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Sink {
        type Writer = Sink;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `f` with a plain, not redacting, subscriber on this thread and
    /// returns everything it logged, so a value in a message would show.
    pub(crate) fn capture_raw(f: impl FnOnce()) -> String {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = sink.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    /// Number of WARN lines in a [`capture_raw`] output.
    pub(crate) fn warnings(log: &str) -> usize {
        log.lines().filter(|line| line.contains(" WARN ")).count()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn buffer(capacity: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(b"sha204-locker-test");
        buf
    }

    // T3 (AC2), locker level: every refusal is reported, only the first is
    // marked as the one to log, and nothing is counted as held.
    #[test]
    fn refusals_are_first_once() {
        let mut locker = Locker::new(Box::new(Refusing), 4096);
        let firsts: Vec<bool> = (0..3)
            .map(|_| match locker.lock(&mut buffer(64)) {
                Err(refused) => refused.first,
                Ok(_) => panic!("refusing ops locked a buffer"),
            })
            .collect();
        assert_eq!(firsts, [true, false, false]);
        assert_eq!(locker.held_pages(), 0);
    }

    // T3 (AC2): through `lock`, three refusals log exactly one warning
    // without the OS error being lost.
    #[test]
    fn lock_warns_once_per_locker() {
        let locker = leaked(Refusing, 4096);
        let log = capture_raw(|| {
            for _ in 0..3 {
                assert_eq!(lock(locker, &mut buffer(64)), None);
            }
        });
        assert_eq!(warnings(&log), 1, "{log}");
        assert!(log.contains(REFUSED));
        assert!(log.contains("simulated mlock refusal"));
        assert!(log.contains("ulimit -l"));
    }

    // T5 (AC4): two buffers on one page. The first unlock keeps the page;
    // the second unlocks it, clipped to the second buffer's allocation.
    #[test]
    fn shared_page_is_unlocked_by_the_last_buffer() {
        let mut a = buffer(48);
        let mut b = buffer(48);
        let page = shared_page_size(&[&a, &b]);
        let rec = Recording::default();
        let mut locker = Locker::new(Box::new(rec.clone()), page);

        let span_a = locker.lock(&mut a).ok().flatten().unwrap();
        let span_b = locker.lock(&mut b).ok().flatten().unwrap();
        assert_eq!(locker.held_pages(), 1);

        locker.unlock(&mut a, span_a);
        assert!(
            !rec.calls().iter().any(|c| matches!(c, Call::Unlock { .. })),
            "a page another buffer is on was unlocked"
        );
        assert_eq!(locker.held_pages(), 1);

        b.clear();
        locker.unlock(&mut b, span_b);
        assert_eq!(
            rec.calls().last(),
            Some(&Call::Unlock {
                addr: b.as_ptr() as usize,
                len: b.capacity(),
                wiped: true,
            })
        );
        assert_eq!(locker.held_pages(), 0);
    }

    // T6 (AC4): no sharing (page size 1). One lock and one unlock of the
    // same range; a span that is not the buffer's own unlocks nothing.
    #[test]
    fn unlock_matches_lock_and_ignores_foreign_spans() {
        let rec = Recording::default();
        let mut locker = Locker::new(Box::new(rec.clone()), 1);
        let mut buf = buffer(32);
        let mut other = buffer(32);
        let span = locker.lock(&mut buf).ok().flatten().unwrap();
        let (addr, len) = (buf.as_ptr() as usize, buf.capacity());

        locker.unlock(&mut other, span);
        assert_eq!(rec.calls().len(), 1, "a foreign span unlocked something");
        assert_eq!(locker.held_pages(), len);

        locker.unlock(&mut buf, span);
        assert_eq!(
            rec.calls(),
            [
                Call::Lock { addr, len },
                Call::Unlock {
                    addr,
                    len,
                    wiped: false
                },
            ]
        );
        assert_eq!(locker.held_pages(), 0);
    }

    #[test]
    fn empty_allocation_is_not_locked() {
        let rec = Recording::default();
        let mut locker = Locker::new(Box::new(rec.clone()), 4096);
        assert_eq!(locker.lock(&mut Vec::new()).ok(), Some(None));
        assert!(rec.calls().is_empty());
    }

    // The real calls on this host. A refusal (a CI runner with a locked
    // memory limit of 0) is allowed; a lock that succeeds must unlock.
    #[cfg(unix)]
    #[test]
    fn system_pages_lock_and_unlock() {
        let mut buf = buffer(256);
        let len = buf.capacity();
        if SystemPages.lock(&mut buf, 0..len).is_ok() {
            SystemPages.unlock(&mut buf, 0..len).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn system_pages_reject_ranges_outside_the_buffer() {
        let mut buf = buffer(16);
        let len = buf.capacity();
        for range in [0..len + 1, 4..4, len..len + 1] {
            let err = SystemPages.lock(&mut buf, range.clone()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{range:?}");
            let err = SystemPages.unlock(&mut buf, range).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        assert!(raw_range(&mut Vec::new(), 0..1).is_err());
    }
}
