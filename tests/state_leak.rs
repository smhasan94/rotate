//! SHA-220 T7: a secret value never reaches the state file, its temp or
//! lock file, or any output the store produces.
//!
//! Stdout and stderr are exercised through `Display` and `Debug` into a
//! string, the same path `println!` and `eprintln!` use. Tracing output is
//! captured with `common::LogCapture` at TRACE level.

#![cfg(unix)]

mod common;

use std::fmt::Write as _;

use rotate::secret::SecretValue;
use rotate::state::{ConsumerState, ConsumerStatus, Rotation, StateStore, Step};

/// Fake, and shaped like no real provider's token.
const CANARY: &str = "rotate-state-canary-7d1e-not-a-real-token";
const REPLACEMENT: &str = "rotate-state-canary-replacement-41b9";

#[test]
fn secret_value_never_reaches_state_file_or_output() {
    let dirs = common::TestDirs::new();
    let state = dirs.rotate_dir.join("state.json");
    let old = SecretValue::from(CANARY);
    let new = SecretValue::from(REPLACEMENT);

    let capture = common::LogCapture::default();
    let mut console = String::new();
    // `LogCapture::subscriber` stops at INFO; the store logs saves at DEBUG.
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut store = StateStore::open(&state).unwrap();
        let mut rotation = Rotation::new("rot-0001", "aws", old.fingerprint());
        rotation.replacement_fingerprint = Some(new.fingerprint());
        rotation.replacement_ref = Some("key-id-0002".to_owned());
        rotation.step = Step::ConsumersUpdated;
        rotation.consumers.push(ConsumerState {
            consumer: "github-actions".to_owned(),
            consumer_ref: "org/repo:AWS_SECRET_ACCESS_KEY".to_owned(),
            status: ConsumerStatus::Updated,
        });
        let saved = store.upsert(rotation).unwrap().clone();
        write!(console, "{saved:?} {saved:#?} {store:?}").unwrap();

        let err = StateStore::open(&state).unwrap_err();
        write!(console, "{err} {err:?}").unwrap();
    });

    let file = std::fs::read_to_string(&state).unwrap();
    let mut lock = state.as_os_str().to_owned();
    lock.push(".lock");
    let lock = std::fs::read_to_string(lock).unwrap();
    let logs = capture.contents();

    for (label, text) in [
        ("state file", &file),
        ("lock file", &lock),
        ("stdout/stderr", &console),
        ("tracing", &logs),
    ] {
        for value in [CANARY, REPLACEMENT] {
            assert!(!text.contains(value), "{label}: secret value leaked");
        }
    }
    let mut temp = state.as_os_str().to_owned();
    temp.push(".tmp");
    assert!(!std::path::Path::new(&temp).exists());

    assert!(file.contains(old.fingerprint().as_str()));
    assert!(file.contains(new.fingerprint().as_str()));
    assert!(logs.contains(old.fingerprint().as_str()), "{logs}");
}
