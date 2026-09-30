//! Shared helpers for integration tests (SHA-216).
//!
//! Every test binary under `tests/` includes this module with `mod common;`.
//! Not every binary uses every helper, hence the dead-code allowance.
//!
//! Three kinds of test live in this repo:
//! - unit tests inside `src/`, next to the code;
//! - integration tests here, talking HTTP only to a wiremock server started
//!   with [`CallRecorder::start`];
//! - live tests, marked `#[ignore]`, that call real provider APIs and run
//!   only when `ROTATE_LIVE_TESTS=1` (see [`live_guard!`]).

#![allow(dead_code, unused_imports, unused_macros)]

use std::fmt;
use std::path::PathBuf;

use tempfile::TempDir;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Decides that a request is read-only even though its HTTP method is one
/// that normally changes state. Needed because AWS sends every call as a
/// POST, including `GetCallerIdentity` and `ListAccessKeys`.
pub type ReadOnlyPredicate = Box<dyn Fn(&Request) -> bool + Send + Sync>;

/// One request the mock server saw.
///
/// The body is kept because later tests must inspect what was sent (for
/// example a `PutSecretValue` payload), but it is never printed: `Debug`
/// shows its length only, and [`assert_no_mutations_in`] names calls by
/// method and path. Call [`RecordedCall::body`] when a test needs the bytes.
pub struct RecordedCall {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    body: Vec<u8>,
    /// True when the call would change state on a real provider.
    pub mutating: bool,
}

impl RecordedCall {
    /// Raw request body. Only assert on it; never print it.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Body as UTF-8 for assertions on text payloads.
    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    fn label(&self) -> String {
        match &self.query {
            Some(q) => format!("{} {}?{}", self.method, self.path, q),
            None => format!("{} {}", self.method, self.path),
        }
    }
}

impl fmt::Debug for RecordedCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedCall")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &self.query)
            .field("body_len", &self.body.len())
            .field("mutating", &self.mutating)
            .finish()
    }
}

/// A wiremock server that answers every request with 200 unless a test
/// mounts something more specific, and classifies what it received.
pub struct CallRecorder {
    server: MockServer,
    read_only: Vec<ReadOnlyPredicate>,
}

impl CallRecorder {
    /// Start a recording server with a catch-all 200 responder.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Self {
            server,
            read_only: Vec::new(),
        }
    }

    /// Base URL of the server, for example `http://127.0.0.1:53211`.
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// The underlying server, for mounting specific mocks.
    pub fn server(&self) -> &MockServer {
        &self.server
    }

    /// Treat requests matching `pred` as read-only regardless of method.
    pub fn mark_read_only<F>(&mut self, pred: F)
    where
        F: Fn(&Request) -> bool + Send + Sync + 'static,
    {
        self.read_only.push(Box::new(pred));
    }

    fn is_mutating(&self, req: &Request) -> bool {
        let method_mutates = matches!(req.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
        method_mutates && !self.read_only.iter().any(|p| p(req))
    }

    /// Every request received so far, in order.
    pub async fn calls(&self) -> Vec<RecordedCall> {
        self.server
            .received_requests()
            .await
            .expect("MockServer::start records requests")
            .iter()
            .map(|req| RecordedCall {
                method: req.method.as_str().to_owned(),
                path: req.url.path().to_owned(),
                query: req.url.query().map(str::to_owned),
                body: req.body.clone(),
                mutating: self.is_mutating(req),
            })
            .collect()
    }

    /// Panic if any recorded call would have changed state.
    pub async fn assert_no_mutations(&self) {
        let calls = self.calls().await;
        assert_no_mutations_in(&calls);
    }
}

/// Synchronous form of [`CallRecorder::assert_no_mutations`] for use inside
/// `catch_unwind`. The panic message names calls by method and path only.
pub fn assert_no_mutations_in(calls: &[RecordedCall]) {
    let mutating: Vec<String> = calls
        .iter()
        .filter(|c| c.mutating)
        .map(RecordedCall::label)
        .collect();
    assert!(
        mutating.is_empty(),
        "expected no state-changing calls, found {}: {}",
        mutating.len(),
        mutating.join(", ")
    );
}

/// A temporary working directory with an empty `.rotate/` inside it.
pub struct TestDirs {
    pub root: TempDir,
    pub rotate_dir: PathBuf,
}

impl TestDirs {
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("create temp dir");
        let rotate_dir = root.path().join(".rotate");
        std::fs::create_dir(&rotate_dir).expect("create .rotate dir");
        Self { root, rotate_dir }
    }

    pub fn path(&self) -> &std::path::Path {
        self.root.path()
    }
}

impl Default for TestDirs {
    fn default() -> Self {
        Self::new()
    }
}

/// True when live tests are enabled with `ROTATE_LIVE_TESTS=1`.
pub fn live_enabled() -> bool {
    std::env::var("ROTATE_LIVE_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Read an environment variable a live test needs, if present.
pub fn require_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Return early from a live test unless `ROTATE_LIVE_TESTS=1`.
///
/// Live tests are also marked `#[ignore]`, so the default `cargo test` never
/// reaches them; this guard covers `cargo test -- --ignored` without the
/// variable.
macro_rules! live_guard {
    () => {
        if !$crate::common::live_enabled() {
            eprintln!("skipped: ROTATE_LIVE_TESTS not set");
            return;
        }
    };
}
pub(crate) use live_guard;
