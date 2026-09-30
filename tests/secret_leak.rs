//! SHA-217 T7: a secret value never reaches stdout, stderr, tracing output or
//! a panic message through any formatting path the crate offers.
//!
//! Stdout and stderr are exercised through an in-memory `fmt::Write`, which
//! is the same `Display` and `Debug` path `println!` and `eprintln!` use.
//! Tracing output is captured by a subscriber writing into a shared buffer.

use std::fmt::Write as _;
use std::io;
use std::panic;
use std::sync::{Arc, Mutex};

use rotate::secret::{Fingerprint, SecretPair, SecretValue};
use tracing_subscriber::fmt::MakeWriter;

const PLAINTEXT: &str = "hunter2-abc-canary-9f2c";

/// Buffer shared between the test and the tracing subscriber.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn assert_hidden(label: &str, text: &str, fingerprint: &Fingerprint) {
    assert!(
        !text.contains(PLAINTEXT),
        "{label}: secret value leaked into output"
    );
    assert!(
        text.contains(fingerprint.as_str()),
        "{label}: fingerprint missing from output: {text}"
    );
}

#[test]
fn secret_never_reaches_stdout_or_stderr_paths() {
    let value = SecretValue::from(PLAINTEXT);
    let pair = SecretPair::new("AKIAIOSFODNN7EXAMPLE", value.clone());
    let fingerprint = value.fingerprint();

    let mut console = String::new();
    write!(
        console,
        "{value} {value:?} {value:#?} {pair:?} {pair:#?} {fingerprint} {fingerprint:?}"
    )
    .unwrap();

    assert_hidden("console", &console, &fingerprint);
}

#[test]
fn secret_never_reaches_tracing_output() {
    let value = SecretValue::from(PLAINTEXT);
    let pair = SecretPair::new("AKIAIOSFODNN7EXAMPLE", value.clone());
    let fingerprint = value.fingerprint();

    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            secret = ?value,
            secret_display = %value,
            pair = ?pair,
            fingerprint = %fingerprint,
            "rotating secret"
        );
    });

    let logs = capture.contents();
    assert!(
        logs.contains("rotating secret"),
        "event not captured: {logs}"
    );
    assert_hidden("tracing", &logs, &fingerprint);
}

#[test]
fn secret_never_reaches_panic_message() {
    let value = SecretValue::from(PLAINTEXT);
    let fingerprint = value.fingerprint();

    let previous = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let payload = panic::catch_unwind(|| panic!("unexpected secret state: {value:?}")).unwrap_err();
    panic::set_hook(previous);

    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("panic payload is text");
    assert_hidden("panic", &message, &fingerprint);
}
