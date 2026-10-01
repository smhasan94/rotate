//! Tracing output with every event passed through [`redact`] (SHA-218).
//!
//! The fmt layer formats an event into one line and hands it to a writer.
//! [`RedactingWriter`] buffers that line and writes [`redact`] of it when it
//! is dropped, so the message, every field and every span field are covered,
//! and a value split across `write` calls is still caught whole.

use std::borrow::Cow;
use std::io::{self, Write};

use tracing::{Metadata, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::format::{DefaultFields, Format};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer as _;
use zeroize::Zeroizing;

use super::redact;

/// Wraps a [`MakeWriter`] so that everything written through it is redacted.
#[derive(Debug, Clone, Default)]
pub struct RedactingMakeWriter<M> {
    inner: M,
}

impl<M> RedactingMakeWriter<M> {
    /// Redacts everything written through `inner`.
    pub fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer())
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        RedactingWriter::new(self.inner.make_writer_for(meta))
    }
}

/// Buffers one event and writes it, redacted, to the inner writer on drop.
///
/// `flush` does not write the buffer: flushing half an event could split a
/// secret across two redaction passes. Errors writing on drop are ignored,
/// as the fmt layer ignores them.
pub struct RedactingWriter<W: Write> {
    inner: W,
    buf: Zeroizing<Vec<u8>>,
}

impl<W: Write> RedactingWriter<W> {
    /// A writer that redacts into `inner`.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buf: Zeroizing::new(Vec::with_capacity(256)),
        }
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(&self.buf);
        let text = match text {
            Cow::Borrowed(t) => Zeroizing::new(redact(t).into_owned()),
            Cow::Owned(t) => {
                let t = Zeroizing::new(t);
                Zeroizing::new(redact(&t).into_owned())
            }
        };
        let _ = self.inner.write_all(text.as_bytes());
        let _ = self.inner.flush();
    }
}

/// The fmt layer used for rotate's logs: plain text, no ANSI colours, every
/// event redacted before it reaches `make_writer`.
pub fn layer<S, M>(
    make_writer: M,
) -> tracing_subscriber::fmt::Layer<S, DefaultFields, Format, RedactingMakeWriter<M>>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    M: for<'a> MakeWriter<'a> + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(RedactingMakeWriter::new(make_writer))
}

/// A complete subscriber: [`layer`] filtered to `level`. `main` installs it
/// with `std::io::stderr` as the writer.
pub fn subscriber<M>(level: LevelFilter, make_writer: M) -> impl Subscriber + Send + Sync
where
    M: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    tracing_subscriber::registry().with(layer(make_writer).with_filter(level))
}

/// Log level for the `-v` count: none is warnings and errors, `-v` info,
/// `-vv` debug, `-vvv` and more trace.
pub fn level_for(verbose: u8) -> LevelFilter {
    match verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}
