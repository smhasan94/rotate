//! SHA-265: the leakage audit. Canary secrets go through every command and
//! mode; afterwards everything the process could have written is searched
//! for every canary in every encoding.
//!
//! - [`Sweep`] holds the needles (raw, URL-encoded, lower and upper hex,
//!   standard and URL-safe base64 at each byte alignment) and searches
//!   buffers, file names and whole directory trees. A hit names the place
//!   and byte offset, never the bytes.
//! - [`MockRun`] runs the binary against the `test-providers` mocks (the
//!   npm mock), in a temp root holding the working directory, `TMPDIR`,
//!   `HOME` and the mocks' outputs; only `inputs/` (what the test wrote) is
//!   not swept.
//! - The real-plugin runs reuse the `tests/e2e` harness (IAM, Secrets
//!   Manager and GitHub Actions on wiremock) with canary values; its own
//!   checks run too.
//!
//! Every run is `-vvv` with `RUST_LOG=trace` (one plan run is `-v` with no
//! `RUST_LOG`), so stderr is the full log capture. After each run the files
//! under `.rotate/` must be 0600 and the directory 0700 (AC3).
//!
//! SHA-293 adds the revoke-by-hand runs (`revoke_manual`, its `status`
//! hint and the re-runs) and `plan --check-permissions` with probe errors
//! that echo the operator's AWS secret and GitHub token.
//!
//! SHA-294 adds a revoke resumed in a new process (after the overlap
//! window, and `--wait`) whose error echoes the replacement, and a re-run
//! of apply while the overlap window of the real AWS plugin is open.

#![cfg(all(unix, feature = "test-providers", feature = "test-commands"))]

mod common;
mod e2e;

use std::collections::HashMap;
use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine as _;
use rotate::secret::SecretValue;
use serde_json::{json, Value};

use crate::e2e::{E2e, E2eValues};

// ---------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------

/// The alphabet of an AWS secret access key. `/` and `+` make the
/// URL-encoded form differ from the raw one.
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

/// A fresh pseudo-random generator per call: clock, process id and a
/// counter, mixed with splitmix64.
fn rng() -> impl FnMut() -> u64 {
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
fn canary_of(len: usize) -> String {
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
fn canary() -> String {
    canary_of(32)
}

/// A value to search for, with the name failures use for it.
#[derive(Clone)]
struct Canary {
    label: String,
    value: String,
}

impl Canary {
    fn new(label: &str, value: &str) -> Self {
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
struct Hit {
    place: String,
    offset: usize,
    label: String,
    encoding: &'static str,
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
fn base64_core(engine: &base64::engine::GeneralPurpose, value: &[u8], align: usize) -> String {
    let mut padded = vec![0u8; align];
    padded.extend_from_slice(value);
    let encoded = engine.encode(&padded);
    let start = (align * 8).div_ceil(6);
    let end = (padded.len() * 8) / 6;
    encoded[start..end].to_owned()
}

/// Every encoding of `value` the sweep looks for.
fn encodings(value: &str) -> Vec<(&'static str, String)> {
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
struct Sweep {
    regex: regex::bytes::Regex,
    needles: HashMap<Vec<u8>, (String, &'static str)>,
}

impl Sweep {
    fn new(canaries: &[Canary]) -> Self {
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
    fn scan(&self, place: &str, bytes: &[u8]) -> Vec<Hit> {
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
    fn scan_dir(&self, root: &Path, skip: &[PathBuf]) -> Vec<Hit> {
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
fn assert_no_hits(what: &str, hits: &[Hit]) {
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
fn assert_private_state(work: &Path) -> Vec<String> {
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

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The exit code with the tail of stderr, for assertion messages. Safe to
/// show only after the sweep passed.
fn shown(output: &Output) -> String {
    e2e::shown(output)
}

// ---------------------------------------------------------------------------
// Mock runs
// ---------------------------------------------------------------------------

/// What the npm mock mints for the first replacement in a process.
const MOCK_REPLACEMENT: &str = "npm_npm-replacement-1";
const GHA: &str = "gha:org/repo:NPM_TOKEN";
const SM: &str = "sm:prod/npm-publish";

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

/// A temp root for one sequence of runs against the npm mock:
/// `work/` (the working directory), `tmp/` (`TMPDIR`), `home/`, `out/`
/// (the mocks' call log and consumer state) and `inputs/` (the scenario
/// and any replacement file; the only part not swept).
struct MockRun {
    root: tempfile::TempDir,
    /// The leaked npm token: `npm_` and 28 canary chars.
    old: String,
    /// The manual-mode replacement an operator pastes.
    pasted: String,
    sweep: Sweep,
    scenario: Value,
}

impl MockRun {
    fn new() -> Self {
        Self::with_old(&format!("npm_{}", canary_of(28)))
    }

    fn with_old(old: &str) -> Self {
        let pasted = canary();
        let canaries = [
            Canary::new("old secret", old),
            Canary::new("pasted replacement", &pasted),
            Canary::new("mock replacement", MOCK_REPLACEMENT),
        ];
        let root = tempfile::tempdir().unwrap();
        for dir in ["work", "tmp", "home", "out", "inputs"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        let mut run = Self {
            root,
            old: old.to_owned(),
            pasted,
            sweep: Sweep::new(&canaries),
            scenario: Value::Null,
        };
        run.consumers_hold(&run.old.clone());
        run
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn work(&self) -> PathBuf {
        self.path("work")
    }

    /// Both consumers hold `value`; confirmation must come from
    /// `--confirm`.
    fn consumers_hold(&mut self, value: &str) {
        self.scenario = json!({
            "consumers": [
                { "name": "github-actions", "matches": [
                    { "fingerprint": fp(value), "ref": GHA, "method": "by_name" } ] },
                { "name": "aws-secrets-manager", "matches": [
                    { "fingerprint": fp(value), "ref": SM } ] }
            ],
            "call_log": self.path("out/calls.jsonl"),
            "consumer_state": self.path("out/held.json"),
            "prompt": "panic",
        });
        self.write_scenario();
    }

    fn set(&mut self, edit: impl FnOnce(&mut Value)) {
        edit(&mut self.scenario);
        self.write_scenario();
    }

    fn write_scenario(&self) {
        std::fs::write(self.path("inputs/scenario.json"), self.scenario.to_string()).unwrap();
    }

    fn command(&self, args: &[&str], trace: bool) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("rotate"));
        cmd.env_clear()
            .current_dir(self.work())
            .env("HOME", self.path("home"))
            .env("TMPDIR", self.path("tmp"))
            .env("ROTATE_ACTOR", "leak@runner")
            .env("ROTATE_TEST_SCENARIO", self.path("inputs/scenario.json"));
        if trace {
            cmd.env("RUST_LOG", "trace").arg("-vvv");
        } else {
            cmd.arg("-v");
        }
        cmd.args(args);
        cmd
    }

    /// Runs `rotate <args>` with `stdin` (the old secret by default), then
    /// sweeps and checks the state file modes.
    fn run_full(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        env: &[(&str, &str)],
        trace: bool,
    ) -> Output {
        let mut cmd = self.command(args, trace);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            let mut pipe = child.stdin.take().unwrap();
            // A command that never reads stdin may close it first.
            let _ = pipe.write_all(format!("{}\n", stdin.unwrap_or(&self.old)).as_bytes());
        }
        let output = child.wait_with_output().unwrap();
        self.check(&args.join(" "), &output);
        output
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_full(args, None, &[], true)
    }

    /// Runs and expects exit `code`.
    fn expect(&self, code: i32, args: &[&str]) -> Output {
        let output = self.run(args);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{args:?}: {}",
            shown(&output)
        );
        output
    }

    /// The sweep of one run: stdout, stderr and every file under the root
    /// except `inputs/`; then the `.rotate/` modes.
    fn check(&self, label: &str, output: &Output) {
        let mut hits = self
            .sweep
            .scan(&format!("`{label}` stdout"), &output.stdout);
        hits.extend(
            self.sweep
                .scan(&format!("`{label}` stderr"), &output.stderr),
        );
        hits.extend(
            self.sweep
                .scan_dir(self.root.path(), &[self.path("inputs")]),
        );
        assert_no_hits(&format!("`rotate {label}`"), &hits);
        assert_private_state(&self.work());
    }

    fn planned_id(&self) -> String {
        let output = self.expect(0, &["--json", "plan", "--stdin"]);
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        plan["rotations"][0]["rotation_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no rotation planned: {plan}"))
            .to_owned()
    }

    fn step(&self, id: &str) -> String {
        let state: Value =
            serde_json::from_slice(&std::fs::read(self.work().join(".rotate/state.json")).unwrap())
                .unwrap();
        state["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rotation_id"] == id)
            .map(|r| r["step"].as_str().unwrap().to_owned())
            .unwrap_or_else(|| panic!("no rotation {id}"))
    }
}

// T1 (AC1), T3 (AC3): plan, automatic apply, status and rollback.
#[test]
fn t1_mock_automatic_apply_status_and_rollback() {
    let mut run = MockRun::new();
    let table = run.expect(0, &["plan", "--stdin"]);
    assert!(text(&table.stdout).contains("Dry run"), "{}", shown(&table));
    run.run_full(&["plan", "--stdin"], None, &[], false);
    let id = run.planned_id();
    // apply and rollback refuse --json; the refusal is swept too.
    run.expect(2, &["--json", "apply", "--stdin", "--confirm", &id]);
    run.expect(2, &["--json", "rollback", "--stdin", "--confirm", &id]);

    run.expect(
        0,
        &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
    );
    assert_eq!(run.step(&id), "revoked");
    run.expect(0, &["status"]);
    run.expect(0, &["--json", "status"]);
    run.expect(0, &["status", "--all"]);
    // Re-running is idempotent and must stay clean too.
    run.expect(0, &["--overlap", "0s", "apply", "--stdin", "--all"]);

    run.consumers_hold(MOCK_REPLACEMENT);
    run.expect(0, &["rollback", "--stdin", "--confirm", &id]);
    assert_eq!(run.step(&id), "rolled_back");
    run.expect(0, &["--json", "status", "--all"]);
    let files = assert_private_state(&run.work());
    assert!(files.contains(&"state.json".to_owned()), "{files:?}");
    assert!(files.contains(&"audit.jsonl".to_owned()), "{files:?}");
}

// T1 (AC1): an apply left pending by the overlap window, then `status`.
#[test]
fn t1_mock_pending_revoke_and_status() {
    let run = MockRun::new();
    let id = run.planned_id();
    run.expect(
        3,
        &["--overlap", "1h", "apply", "--stdin", "--confirm", &id],
    );
    run.expect(3, &["status"]);
    run.expect(3, &["--json", "status", "--all"]);
}

// T1 (AC1): manual mode, the pasted value through the prompt, an
// environment variable and a file.
#[test]
fn t1_mock_manual_mode_every_source() {
    let manual = |run: &mut MockRun| {
        run.set(|s| s["providers"] = json!({ "npm": { "mode": "manual" } }));
    };

    let mut run = MockRun::new();
    manual(&mut run);
    let id = run.planned_id();
    let pasted = run.pasted.clone();
    run.set(|s| s["prompt"] = json!({ "answers": [pasted] }));
    run.expect(
        0,
        &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
    );
    assert_eq!(run.step(&id), "revoked");
    run.expect(0, &["status", "--all"]);

    let mut run = MockRun::new();
    manual(&mut run);
    let id = run.planned_id();
    let output = run.run_full(
        &[
            "--overlap",
            "0s",
            "apply",
            "--stdin",
            "--confirm",
            &id,
            "--replacement-from-env",
            "LEAK_TEST_REPLACEMENT",
        ],
        None,
        &[("LEAK_TEST_REPLACEMENT", &run.pasted)],
        true,
    );
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(run.step(&id), "revoked");

    let mut run = MockRun::new();
    manual(&mut run);
    let id = run.planned_id();
    let file = run.path("inputs/replacement.txt");
    std::fs::write(&file, format!("{}\n", run.pasted)).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    run.expect(
        0,
        &[
            "--overlap",
            "0s",
            "apply",
            "--stdin",
            "--confirm",
            &id,
            "--replacement-file",
            file.to_str().unwrap(),
        ],
    );
    assert_eq!(run.step(&id), "revoked");

    // A pasted value that belongs to someone else fails verify.
    let mut run = MockRun::new();
    manual(&mut run);
    let foreign = fp(&run.pasted);
    run.set(|s| s["providers"]["npm"]["foreign"] = json!([foreign]));
    let id = run.planned_id();
    let pasted = run.pasted.clone();
    run.set(|s| s["prompt"] = json!({ "answers": [pasted] }));
    run.expect(
        1,
        &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
    );
}

// T1 (AC1): a failure injected at each step. Every error text holds the
// old secret, as an upstream that echoes it would.
#[test]
fn t1_mock_failure_at_each_step() {
    let provider_steps = [
        "check_valid",
        "describe_scope",
        "create_replacement",
        "verify",
        "revoke",
    ];
    for method in provider_steps {
        let mut run = MockRun::new();
        let echo = format!("upstream echoed {} in {method}", run.old);
        run.set(|s| s["providers"] = json!({ "npm": { "fail": { method: echo } } }));
        run.run(&["plan", "--stdin"]);
        let plan = run.run(&["--json", "plan", "--stdin"]);
        let plan: Value = serde_json::from_slice(&plan.stdout).unwrap();
        let Some(id) = plan["rotations"][0]["rotation_id"].as_str() else {
            continue;
        };
        let output = run.run(&["--overlap", "0s", "apply", "--stdin", "--confirm", id]);
        assert_ne!(
            output.status.code(),
            Some(0),
            "{method}: {}",
            shown(&output)
        );
        assert_ne!(run.step(id), "revoked", "{method}");
        run.run(&["status", "--all"]);
    }
    for (method, field) in [("find", "fail_find"), ("update", "fail")] {
        let mut run = MockRun::new();
        let echo = format!("upstream echoed {} in {method}", run.old);
        run.set(|s| {
            s["consumers"][0][field] = if field == "fail" {
                json!({ method: echo })
            } else {
                json!(echo)
            };
        });
        run.run(&["plan", "--stdin"]);
        let plan = run.run(&["--json", "plan", "--stdin"]);
        let plan: Value = serde_json::from_slice(&plan.stdout).unwrap();
        let id = plan["rotations"][0]["rotation_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let output = run.run(&["--overlap", "0s", "apply", "--stdin", "--confirm", &id]);
        assert_ne!(
            output.status.code(),
            Some(0),
            "{method}: {}",
            shown(&output)
        );
        assert_ne!(run.step(&id), "revoked", "{method}");
        run.run(&["status", "--all"]);
        if method == "update" {
            // Recovery from a failed update is a rollback; the restore
            // fails as well and echoes the secret too.
            run.set(|s| s["consumers"][0]["fail"]["restore"] = json!(echo));
            run.run(&["rollback", "--stdin", "--confirm", &id]);
            run.run(&["--json", "status", "--all"]);
        }
    }
}

// T1 (AC1): rollback where the provider cannot restore the old secret.
#[test]
fn t1_mock_rollback_unsupported_restore() {
    let mut run = MockRun::new();
    let id = run.planned_id();
    run.expect(
        0,
        &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
    );
    run.consumers_hold(MOCK_REPLACEMENT);
    run.set(|s| s["providers"] = json!({ "npm": { "restore": "unsupported" } }));
    // SHA-290 T8 (AC1): the old secret stays revoked, so exit 1.
    run.expect(1, &["rollback", "--stdin", "--confirm", &id]);
    assert_eq!(run.step(&id), "rolled_back");
    let status = run.expect(0, &["status", "--all"]);
    assert!(
        text(&status.stdout).contains("the old secret stays revoked"),
        "{}",
        shown(&status)
    );
    run.expect(0, &["--json", "status", "--all"]);
}

// SHA-290 T8 (AC2): a rotation revoked by hand (no restore handle) rolled
// back: consumers restored, replacement revoked, exit 1; every run swept.
#[test]
fn sha290_t8_rollback_after_revoke_by_hand_exits_1() {
    let mut run = MockRun::new();
    let said = echoing_instructions(&run, "manual_revoke");
    run.set(|s| s["providers"] = json!({ "npm": { "manual_revoke": said } }));
    let id = run.planned_id();
    run.expect(
        4,
        &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
    );
    // Deleted by hand: apply records it revoked, with no handle.
    run.set(|s| s["providers"]["npm"]["validity"] = json!("invalid"));
    run.expect(0, &["apply", "--stdin", "--confirm", &id]);
    assert_eq!(run.step(&id), "revoked");

    let providers = run.scenario["providers"].clone();
    run.consumers_hold(MOCK_REPLACEMENT);
    run.set(|s| s["providers"] = providers);
    let output = run.expect(1, &["rollback", "--stdin", "--confirm", &id]);
    let out = text(&output.stdout);
    assert!(out.contains("rollback will exit 1"), "{}", shown(&output));
    assert!(
        out.contains("1 with the old secret still revoked"),
        "{}",
        shown(&output)
    );
    assert_eq!(run.step(&id), "rolled_back");
    run.expect(0, &["status", "--all"]);
    run.expect(0, &["--json", "status", "--all"]);
    // Finished: a second rollback has nothing to do.
    run.expect(0, &["rollback", "--stdin", "--confirm", &id]);
}

// T1 (AC1): the panic and error paths. `__test-console` prints, fails or
// panics with the secret it read; an apply whose prompt panics does so
// with every secret of the plan in memory.
#[test]
fn t1_panic_and_error_paths() {
    let run = MockRun::new();
    for (mode, code) in [("out", 0), ("error", 1), ("panic", 101), ("json", 0)] {
        run.expect(code, &["__test-console", mode]);
    }
    let output = run.run(&["apply", "--stdin"]);
    assert_eq!(output.status.code(), Some(101), "{}", shown(&output));
    assert!(text(&output.stderr).contains("panic"), "{}", shown(&output));
}

// ---------------------------------------------------------------------------
// SHA-293 T1 (AC1): revoke by hand (SHA-289)
// ---------------------------------------------------------------------------

/// The two ways a provider asks for a revoke by hand: `manual_revoke`
/// says so before any call, `unsupported.revoke` refuses the call. Either
/// way the text is printed, stored as `revoke_instructions`, written to
/// the skipped `revoke` audit entry and shown as the `status` hint.
const BY_HAND: [&str; 2] = ["manual_revoke", "unsupported"];

/// Instructions that quote the old secret, as an upstream that echoes the
/// key it refused would. A refused revoke (`unsupported`) runs after the
/// replacement exists, so its text quotes that too; `manual_revoke` is
/// known before apply (the plan prints it as a blocker), when there is no
/// replacement to quote.
fn echoing_instructions(run: &MockRun, how: &str) -> String {
    let mut said = format!("delete {} by hand at https://example.test/tokens", run.old);
    if how == "unsupported" {
        said.push_str(&format!("; keep {MOCK_REPLACEMENT}"));
    }
    said
}

/// apply stops at `revoke_manual` (exit 4); `status` in every format; a
/// re-apply while the old secret is still valid (exit 4 again); then the
/// operator deletes it: plan skips it as revoked by hand and apply records
/// it revoked.
#[test]
fn sha293_t1_revoke_manual_status_and_reruns() {
    for how in BY_HAND {
        let mut run = MockRun::new();
        let said = echoing_instructions(&run, how);
        run.set(|s| {
            s["providers"] = match how {
                "manual_revoke" => json!({ "npm": { "manual_revoke": said } }),
                _ => json!({ "npm": { "unsupported": { "revoke": said } } }),
            };
        });
        run.expect(0, &["plan", "--stdin"]);
        let id = run.planned_id();
        let output = run.expect(
            4,
            &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
        );
        assert_eq!(run.step(&id), "revoke_manual", "{how}");
        assert!(
            text(&output.stdout).contains("revoke by hand"),
            "{how}: {}",
            shown(&output)
        );
        // The echoed instructions reached stdout, redacted.
        assert!(
            text(&output.stdout).contains("[REDACTED"),
            "{how}: {}",
            shown(&output)
        );

        run.expect(3, &["status"]);
        run.expect(3, &["status", "--all"]);
        let status = run.expect(3, &["--json", "status"]);
        let rows: Value = serde_json::from_slice(&status.stdout).unwrap();
        assert_eq!(rows[0]["step"], "revoke_manual", "{how}: {rows}");
        run.expect(3, &["--json", "status", "--all"]);

        // Still valid: only the read-only check, and exit 4 again.
        run.expect(
            4,
            &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
        );
        assert_eq!(run.step(&id), "revoke_manual", "{how}");
        run.expect(3, &["status"]);

        // Deleted by hand: the plan skips it, apply records it revoked.
        run.set(|s| s["providers"]["npm"]["validity"] = json!("invalid"));
        run.expect(0, &["plan", "--stdin"]);
        let plan = run.expect(0, &["--json", "plan", "--stdin"]);
        let plan: Value = serde_json::from_slice(&plan.stdout).unwrap();
        assert_eq!(
            plan["skipped"][0]["reason"], "revoked by hand",
            "{how}: {plan}"
        );
        run.expect(0, &["apply", "--stdin", "--confirm", &id]);
        assert_eq!(run.step(&id), "revoked", "{how}");
        run.expect(0, &["status", "--all"]);
        run.expect(0, &["--json", "status", "--all"]);
        run.expect(0, &["apply", "--stdin", "--all"]);
    }
}

/// A revoke by hand the operator then rolls back: rollback treats the old
/// secret as never revoked.
#[test]
fn sha293_t1_revoke_manual_then_rollback() {
    for how in BY_HAND {
        let mut run = MockRun::new();
        let said = echoing_instructions(&run, how);
        run.set(|s| {
            s["providers"] = match how {
                "manual_revoke" => json!({ "npm": { "manual_revoke": said } }),
                _ => json!({ "npm": { "unsupported": { "revoke": said } } }),
            };
        });
        let id = run.planned_id();
        run.expect(
            4,
            &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
        );
        let providers = run.scenario["providers"].clone();
        run.consumers_hold(MOCK_REPLACEMENT);
        run.set(|s| s["providers"] = providers);
        run.expect(0, &["rollback", "--stdin", "--confirm", &id]);
        assert_eq!(run.step(&id), "rolled_back", "{how}");
        run.expect(0, &["--json", "status", "--all"]);
    }
}

// ---------------------------------------------------------------------------
// SHA-294 T3, T5, T7 (AC3, AC5): a revoke resumed in a new process
// ---------------------------------------------------------------------------

/// A revoke error as npm's would read, echoing the replacement (which no
/// redactor pattern matches) and the old secret.
fn echoing_revoke_error(run: &MockRun) -> String {
    format!(
        "DELETE /-/npm/v1/tokens/token: npm returned 403: E403 refused {}; keep {MOCK_REPLACEMENT}",
        run.old
    )
}

/// The safe summary a resumed revoke keeps of [`echoing_revoke_error`].
fn resumed_summary(kind: &str) -> String {
    format!(
        "npm revoke {kind}; operation DELETE /-/npm/v1/tokens/token; HTTP 403; code E403; \
         provider message not kept: this run did not hold the replacement"
    )
}

/// The revoke failing (`fail`, exit 1) or refused (`unsupported`, exit
/// 4) in a process that never held the replacement: after the overlap
/// window (the clock moved on), and with `--wait` in a new process. Only
/// the safe summary reaches stdout, the state file and the audit log, and
/// `status` shows the pending revoke as a hint, then the real failure as
/// the last error.
#[test]
fn sha294_t5_resumed_revoke_keeps_only_a_safe_summary() {
    for (how, resume) in [
        ("fail", "after"),
        ("unsupported", "after"),
        ("fail", "wait"),
        ("unsupported", "wait"),
    ] {
        let mut run = MockRun::new();
        let id = run.planned_id();
        let overlap = if resume == "wait" { "2s" } else { "1h" };
        run.expect(
            3,
            &["--overlap", overlap, "apply", "--stdin", "--confirm", &id],
        );
        assert_eq!(run.step(&id), "pending_revoke", "{how} {resume}");

        // AC3: waiting is a hint, not a last error.
        let status = run.expect(3, &["status"]);
        let table = text(&status.stdout);
        assert!(!table.contains("last error"), "{how} {resume}: {table}");
        assert!(table.contains("re-run `rotate apply` after"), "{table}");
        let rows: Value =
            serde_json::from_slice(&run.expect(3, &["--json", "status"]).stdout).unwrap();
        assert_eq!(rows[0]["error"], Value::Null, "{rows}");

        let said = echoing_revoke_error(&run);
        run.set(|s| {
            s["providers"] = match how {
                "fail" => json!({ "npm": { "fail": { "revoke": said } } }),
                _ => json!({ "npm": { "unsupported": { "revoke": said } } }),
            };
            if resume == "after" {
                s["clock_offset_secs"] = json!(7200);
            }
        });
        let args: Vec<&str> = match resume {
            "wait" => vec!["apply", "--stdin", "--confirm", &id, "--wait"],
            _ => vec!["apply", "--stdin", "--confirm", &id],
        };
        let (code, step, kind) = match how {
            "fail" => (1, "failed", "failed"),
            _ => (4, "revoke_manual", "not supported by the provider"),
        };
        let output = run.expect(code, &args);
        assert_eq!(run.step(&id), step, "{how} {resume}");
        let summary = resumed_summary(kind);
        let stdout = text(&output.stdout);
        assert!(
            stdout.contains(&summary),
            "{how} {resume}: {}",
            shown(&output)
        );
        assert!(
            !stdout.contains("refused"),
            "{how} {resume}: upstream text kept"
        );

        let state = std::fs::read_to_string(run.work().join(".rotate/state.json")).unwrap();
        assert!(!state.contains("refused"), "{how} {resume}: {state}");
        if how == "unsupported" {
            assert!(state.contains(&summary), "{how} {resume}: {state}");
        }
        let audit = std::fs::read_to_string(run.work().join(".rotate/audit.jsonl")).unwrap();
        let last: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(last["step"], "revoke", "{last}");
        let error = last["error"].as_str().unwrap();
        assert!(error.contains(&summary), "{how} {resume}: {error}");
        assert!(
            !audit.contains("refused"),
            "{how} {resume}: upstream text in the audit log"
        );

        // AC3: a revoke that really failed is still the last error.
        let status = run.expect(3, &["status"]);
        let table = text(&status.stdout);
        if how == "fail" {
            assert!(table.contains("last error (revoke"), "{table}");
            assert!(table.contains(&summary), "{table}");
        } else {
            assert!(table.contains("revoke by hand"), "{table}");
        }
        run.expect(3, &["--json", "status", "--all"]);
    }
}

// ---------------------------------------------------------------------------
// Real plugins (tests/e2e)
// ---------------------------------------------------------------------------

/// Canary values for the e2e harness. AWS secret access keys are 40
/// chars, so each is an 8-char tag and a 32-char canary core; the cores
/// are searched for on their own too.
struct RealCanaries {
    values: E2eValues,
    canaries: Vec<Canary>,
}

impl RealCanaries {
    fn new() -> Self {
        let mut canaries = Vec::new();
        let mut aws = |label: &str, tag: &str| {
            let core = canary();
            let value = format!("{tag}{core}");
            canaries.push(Canary::new(label, &value));
            canaries.push(Canary::new(&format!("{label} (core)"), &core));
            value
        };
        let leaked_secret = aws("old secret", "lkdOld01");
        let new_secret = aws("replacement", "lkdNew01");
        let second_secret = aws("second replacement", "lkd2nd01");
        let operator_secret = aws("operator AWS secret", "lkdOper1");
        let github_token = canary();
        canaries.push(Canary::new("operator GitHub token", &github_token));
        Self {
            values: E2eValues {
                operator_secret,
                leaked_secret,
                new_secret,
                second_secret,
                github_token,
            },
            canaries,
        }
    }
}

struct RealRun {
    e2e: E2e,
    sweep: Sweep,
}

impl RealRun {
    async fn start() -> Self {
        let RealCanaries { values, canaries } = RealCanaries::new();
        let e2e = E2e::start_with_github_values(values).await;
        Self {
            e2e,
            sweep: Sweep::new(&canaries),
        }
    }

    /// `E2e::run` (its own checks included), then the full sweep: stdout,
    /// stderr and every file under the run's directory, `TMPDIR` among
    /// them, except the report the test wrote.
    fn run(&self, args: &[&str]) -> Output {
        let output = self.e2e.run(args);
        let label = args.join(" ");
        let mut hits = self
            .sweep
            .scan(&format!("`{label}` stdout"), &output.stdout);
        hits.extend(
            self.sweep
                .scan(&format!("`{label}` stderr"), &output.stderr),
        );
        hits.extend(
            self.sweep
                .scan_dir(self.e2e.path(), &[self.e2e.file("report.ndjson")]),
        );
        assert_no_hits(&format!("`rotate {label}`"), &hits);
        assert_private_state(self.e2e.path());
        output
    }

    fn expect(&self, code: i32, args: &[&str]) -> Output {
        let output = self.run(args);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{args:?}: {}",
            shown(&output)
        );
        output
    }

    fn rotation_id(&self) -> String {
        let output = self.expect(0, &["--json", "plan", "report.ndjson"]);
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        plan["rotations"][0]["rotation_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The requests the mocks received carry no secret where they should
    /// not (the harness check), and no operator credential in a body.
    async fn assert_requests_clean(&self) {
        self.e2e.assert_requests_clean().await;
        let requests = self.e2e.rec.server().received_requests().await.unwrap();
        let operator = Sweep::new(&[
            Canary::new("operator AWS secret", &self.e2e.operator_secret),
            Canary::new("operator GitHub token", &self.e2e.github_token),
        ]);
        let mut hits = Vec::new();
        for (i, req) in requests.iter().enumerate() {
            hits.extend(operator.scan(&format!("request {i} body"), &req.body));
            hits.extend(operator.scan(&format!("request {i} url"), req.url.as_str().as_bytes()));
        }
        assert_no_hits("the requests", &hits);
    }
}

// T1 (AC1), T3 (AC3): the real AWS and GitHub plugins, plan then apply.
#[tokio::test(flavor = "multi_thread")]
async fn t1_real_plugins_plan_apply_status() {
    let run = RealRun::start().await;
    run.expect(0, &["plan", "report.ndjson"]);
    let id = run.rotation_id();
    run.expect(
        0,
        &[
            "--overlap",
            "0s",
            "apply",
            "report.ndjson",
            "--confirm",
            &id,
        ],
    );
    assert_eq!(run.e2e.rotation(&id)["step"], "revoked");
    run.expect(0, &["status", "--all"]);
    run.expect(0, &["--json", "status", "--all"]);
    run.assert_requests_clean().await;
    let files = assert_private_state(run.e2e.path());
    assert!(files.contains(&"state.json".to_owned()), "{files:?}");
    assert!(files.contains(&"audit.jsonl".to_owned()), "{files:?}");
}

/// SHA-294 T2 (AC2), T3 (AC3), T7: the real AWS plugin with its two
/// Actions secrets and the Secrets Manager entry. After apply records a
/// pending revoke (exit 3), plan and a second apply (default overlap, 0s)
/// show no two-key warning for the rotation's own replacement, all three
/// recorded consumers and the recorded revoke time, and apply exits 3
/// again; `status` shows the wait as a hint only. Then, with the clock
/// past the window, apply revokes.
#[tokio::test(flavor = "multi_thread")]
async fn sha294_t2_reapply_during_the_overlap_window() {
    let run = RealRun::start().await;
    let id = run.rotation_id();
    run.expect(
        3,
        &[
            "--overlap",
            "1h",
            "apply",
            "report.ndjson",
            "--confirm",
            &id,
        ],
    );
    assert_eq!(run.e2e.rotation(&id)["step"], "pending_revoke");
    let refs = [
        e2e::PAIR_REF.to_owned(),
        format!("github-actions:{}:{}", e2e::REPO, e2e::GH_KEY_ID_NAME),
        format!("github-actions:{}:{}", e2e::REPO, e2e::GH_SECRET_NAME),
    ];
    let check = |table: &str, label: &str| {
        assert!(!table.contains("access keys ("), "{label}: {table}");
        assert!(
            !table.contains("will not create a replacement"),
            "{label}: {table}"
        );
        assert!(!table.contains("warning:"), "{label}: {table}");
        for consumer_ref in &refs {
            let row = table
                .lines()
                .find(|l| {
                    l.contains(consumer_ref.as_str()) && !l.contains(&format!("{consumer_ref}_"))
                })
                .unwrap_or_else(|| panic!("{label}: no row for {consumer_ref}: {table}"));
            assert!(row.contains("updated (recorded)"), "{label}: {row}");
        }
        let overlap = table
            .lines()
            .find(|l| l.trim_start().starts_with("overlap:"))
            .unwrap();
        assert!(
            overlap.contains("recorded by an earlier run"),
            "{label}: {overlap}"
        );
        assert!(
            overlap.contains("(in 5") || overlap.contains("(in 1h"),
            "{label}: {overlap}"
        );
    };
    let plan = run.expect(0, &["plan", "report.ndjson"]);
    check(&text(&plan.stdout), "plan");
    let json = run.expect(0, &["--json", "plan", "report.ndjson"]);
    let json: Value = serde_json::from_slice(&json.stdout).unwrap();
    let recorded = &json["rotations"][0]["recorded"];
    assert_eq!(recorded["consumers"].as_array().unwrap().len(), 3, "{json}");
    assert!(recorded["revoke_not_before"].is_string(), "{json}");
    let own = format!("replacement: {}, created by rotation {id}", run.e2e.new_id);
    let lines = json["rotations"][0]["scope"]["lines"].as_array().unwrap();
    assert!(lines.iter().any(|l| l == &json!(own)), "{json}");
    assert!(
        !lines
            .iter()
            .any(|l| l.as_str().unwrap().starts_with("warning: ")),
        "{json}"
    );

    let again = run.expect(3, &["apply", "report.ndjson", "--confirm", &id]);
    check(&text(&again.stdout), "apply");
    assert!(
        text(&again.stdout).contains("1 pending revoke"),
        "{}",
        shown(&again)
    );
    assert_eq!(run.e2e.model.count("CreateAccessKey"), 1);
    assert_eq!(run.e2e.model.count("UpdateAccessKey"), 0);

    let status = run.expect(3, &["status"]);
    let table = text(&status.stdout);
    assert!(!table.contains("last error"), "{table}");
    assert!(table.contains("re-run `rotate apply` after"), "{table}");
    run.expect(3, &["--json", "status"]);

    // Past the window: the revoke happens.
    let scenario = json!({ "real_plugins": true, "prompt": "panic", "clock_offset_secs": 7200 });
    std::fs::write(run.e2e.file("scenario.json"), scenario.to_string()).unwrap();
    run.expect(0, &["apply", "report.ndjson", "--confirm", &id]);
    assert_eq!(run.e2e.rotation(&id)["step"], "revoked");
    assert_eq!(run.e2e.model.status(&run.e2e.leaked.id), Some("Inactive"));
    run.expect(0, &["status", "--all"]);
    run.assert_requests_clean().await;
}

// T1 (AC1): a consumer update denied at each consumer stops before revoke;
// rollback recovers.
#[tokio::test(flavor = "multi_thread")]
async fn t1_real_plugins_failed_update_then_rollback() {
    for consumer in ["github-actions", "aws-secrets-manager"] {
        let run = RealRun::start().await;
        match consumer {
            "github-actions" => run.e2e.gh().state().deny_put = true,
            _ => run.e2e.model.state().deny_put = true,
        }
        let id = run.rotation_id();
        run.expect(
            1,
            &[
                "--overlap",
                "0s",
                "apply",
                "report.ndjson",
                "--confirm",
                &id,
            ],
        );
        assert_ne!(run.e2e.rotation(&id)["step"], "revoked", "{consumer}");
        run.run(&["status"]);
        run.e2e.gh().state().deny_put = false;
        run.e2e.model.state().deny_put = false;
        run.expect(0, &["rollback", "report.ndjson", "--confirm", &id]);
        run.expect(0, &["--json", "status", "--all"]);
        run.assert_requests_clean().await;
    }
}

// ---------------------------------------------------------------------------
// SHA-293 T2 (AC2): plan --check-permissions (SHA-270)
// ---------------------------------------------------------------------------

/// The actions of the minimal IAM policy in `docs/permissions.md`.
fn documented_policy() -> std::collections::BTreeSet<String> {
    const DOC: &str = include_str!("../docs/permissions.md");
    let start = DOC.find("### Minimal IAM policy").unwrap();
    let rest = &DOC[start..];
    let open = rest.find("```json\n").unwrap() + "```json\n".len();
    let close = rest[open..].find("```").unwrap();
    let policy: Value = serde_json::from_str(&rest[open..open + close]).unwrap();
    let mut actions = std::collections::BTreeSet::new();
    for statement in policy["Statement"].as_array().unwrap() {
        match &statement["Action"] {
            Value::String(a) => {
                actions.insert(a.clone());
            }
            Value::Array(list) => {
                actions.extend(list.iter().map(|a| a.as_str().unwrap().to_owned()));
            }
            other => panic!("unexpected Action {other}"),
        }
    }
    actions
}

impl RealRun {
    /// `plan --check-permissions` as a table and as JSON, both swept;
    /// returns the stderr of the table run and the JSON plan. Both exit 0.
    fn check_permissions(&self) -> (String, Value) {
        let table = self.expect(0, &["plan", "report.ndjson", "--check-permissions"]);
        let json = self.expect(
            0,
            &["--json", "plan", "report.ndjson", "--check-permissions"],
        );
        (
            text(&table.stderr),
            serde_json::from_slice(&json.stdout).unwrap(),
        )
    }
}

/// All allowed, then one action denied: the denial is a blocker.
#[tokio::test(flavor = "multi_thread")]
async fn sha293_t2_check_permissions_allowed_and_denied() {
    let run = RealRun::start().await;
    run.e2e.model.state().policy = Some(documented_policy());
    let (_, plan) = run.check_permissions();
    assert_eq!(plan["rotations"][0]["blockers"], json!([]), "{plan}");
    assert_eq!(run.e2e.model.state().simulations.len(), 2);

    let mut policy = documented_policy();
    policy.remove("iam:CreateAccessKey");
    run.e2e.model.state().policy = Some(policy);
    let (_, plan) = run.check_permissions();
    let blockers = plan["rotations"][0]["blockers"].to_string();
    assert!(
        blockers.contains("operator lacks iam:CreateAccessKey"),
        "{plan}"
    );
    run.e2e.rec.assert_no_mutations().await;
    run.assert_requests_clean().await;
}

/// The simulation fails with an error that echoes the operator's AWS
/// secret access key (and the other secrets): a warning, swept.
#[tokio::test(flavor = "multi_thread")]
async fn sha293_t2_check_permissions_simulate_error_echoes_operator_secret() {
    for status in [400, 500] {
        let run = RealRun::start().await;
        run.e2e.model.state().policy = Some(documented_policy());
        let echo = format!(
            "signature for {} with {} failed; old {} new {}",
            run.e2e.operator_id, run.e2e.operator_secret, run.e2e.leaked.secret, run.e2e.new_secret
        );
        run.e2e.model.state().simulate_error = Some((status, echo));
        let (stderr, plan) = run.check_permissions();
        assert!(
            stderr.contains("warning: AWS permissions not checked"),
            "{status}: {stderr}"
        );
        // The echoed message reached the warning, redacted.
        assert!(stderr.contains("[REDACTED"), "{status}: {stderr}");
        assert_eq!(plan["rotations"][0]["blockers"], json!([]), "{plan}");
        run.e2e.rec.assert_no_mutations().await;
        run.assert_requests_clean().await;
    }
}

/// The GitHub public-key read answers 403 or 500 with the operator token
/// (and the leaked secret) in its body.
#[tokio::test(flavor = "multi_thread")]
async fn sha293_t2_check_permissions_public_key_error_echoes_token() {
    for status in [403, 500] {
        let run = RealRun::start().await;
        run.e2e.model.state().policy = Some(documented_policy());
        let echo = format!(
            "token {} may not read this key (Bearer {}); secret {}",
            run.e2e.github_token, run.e2e.github_token, run.e2e.leaked.secret
        );
        run.e2e.gh().state().public_key_error = Some((status, echo));
        let (stderr, plan) = run.check_permissions();
        let consumers = plan["rotations"][0]["consumers"].to_string();
        match status {
            403 => assert!(
                consumers.contains(rotate::consumer::github_actions::LACKS_SECRETS_WRITE),
                "{plan}"
            ),
            _ => {
                assert!(
                    stderr.contains("write permission not checked"),
                    "{status}: {stderr}"
                );
                assert!(stderr.contains("[REDACTED"), "{status}: {stderr}");
            }
        }
        run.e2e.rec.assert_no_mutations().await;
        run.assert_requests_clean().await;
    }
}

// ---------------------------------------------------------------------------
// T2 (AC2): a planted leak fails the sweep without showing the canary
// ---------------------------------------------------------------------------

/// The child half of T2: does nothing unless `ROTATE_LEAK_CHILD` names
/// where the binary should plant the leak. Then it runs `plan --stdin`
/// with the `leak-canary-test` hook on, and the sweep must fail.
#[cfg(feature = "leak-canary-test")]
#[test]
fn t2_child_planted_leak() {
    let Ok(target) = std::env::var("ROTATE_LEAK_CHILD") else {
        return;
    };
    let old = std::env::var("ROTATE_LEAK_CHILD_SECRET").unwrap();
    let run = MockRun::with_old(&old);
    run.run_full(
        &["plan", "--stdin"],
        None,
        &[("ROTATE_TEST_PLANT_LEAK", &target)],
        true,
    );
}

#[cfg(feature = "leak-canary-test")]
#[test]
fn t2_planted_leak_fails_and_names_place_not_canary() {
    for (target, place) in [
        ("stdout", "`plan --stdin` stdout at byte "),
        ("stderr", "`plan --stdin` stderr at byte "),
        (
            "planted.txt",
            "/work/planted.txt at byte 0: old secret (raw)",
        ),
    ] {
        let old = format!("npm_{}", canary_of(28));
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "t2_child_planted_leak",
                "--exact",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env("ROTATE_LEAK_CHILD", target)
            .env("ROTATE_LEAK_CHILD_SECRET", &old)
            .output()
            .unwrap();
        let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
        let sweep = Sweep::new(&[Canary::new("planted canary", &old)]);
        // Checked first: on failure the output below is safe to show.
        assert_no_hits(
            &format!("the child test's own output ({target})"),
            &sweep.scan("child output", &combined),
        );
        let shown_child = text(&combined);
        assert!(!output.status.success(), "{target}: {shown_child}");
        assert!(shown_child.contains("LEAK: "), "{target}: {shown_child}");
        assert!(shown_child.contains(place), "{target}: {shown_child}");
        assert!(
            shown_child.contains("old secret (raw)"),
            "{target}: {shown_child}"
        );
    }
}

// ---------------------------------------------------------------------------
// T3 (AC3): every file under .rotate/ is 0600
// ---------------------------------------------------------------------------

#[test]
fn t3_rotate_dir_files_are_0600_after_apply_and_rollback() {
    let mut run = MockRun::new();
    let id = run.planned_id();
    run.expect(
        0,
        &["--overlap", "0s", "apply", "--stdin", "--confirm", &id],
    );
    run.consumers_hold(MOCK_REPLACEMENT);
    run.expect(0, &["rollback", "--stdin", "--confirm", &id]);
    let files = assert_private_state(&run.work());
    for name in ["audit.jsonl", "state.json"] {
        assert!(files.contains(&name.to_owned()), "{files:?}");
    }
}

// ---------------------------------------------------------------------------
// T4 (AC4): 1,000 files of 1 MiB in under 30 seconds
// ---------------------------------------------------------------------------

#[test]
fn t4_sweep_of_1000_files_of_1mib_is_under_30s() {
    const FILES: usize = 1000;
    const SIZE: usize = 1 << 20;
    const PLANTED_FILE: usize = 737;
    const PLANTED_AT: usize = 123_457;
    let canaries = [
        Canary::new("old secret", &canary()),
        Canary::new("replacement", &canary()),
        Canary::new("operator credential", &canary()),
        Canary::new("pasted replacement", &canary()),
    ];
    let dir = tempfile::tempdir().unwrap();
    let printable = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=:{}\" \n";
    let mut next = rng();
    let mut buffer: Vec<u8> = (0..SIZE)
        .map(|_| printable[(next() % printable.len() as u64) as usize])
        .collect();
    for i in 0..FILES {
        buffer.rotate_left(7919);
        let path = dir.path().join(format!("f{i:04}.log"));
        if i == PLANTED_FILE {
            let mut planted = buffer.clone();
            let value = canaries[2].value.as_bytes();
            planted[PLANTED_AT..PLANTED_AT + value.len()].copy_from_slice(value);
            std::fs::write(&path, planted).unwrap();
        } else {
            std::fs::write(&path, &buffer).unwrap();
        }
    }
    drop(buffer);

    let started = Instant::now();
    let sweep = Sweep::new(&canaries);
    let hits = sweep.scan_dir(dir.path(), &[]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(30),
        "the sweep took {elapsed:?}"
    );
    let planted = dir.path().join(format!("f{PLANTED_FILE:04}.log"));
    assert_eq!(
        hits,
        [Hit {
            place: planted.display().to_string(),
            offset: PLANTED_AT,
            label: "operator credential".into(),
            encoding: "raw",
        }],
        "the sweep took {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// The sweep itself
// ---------------------------------------------------------------------------

#[test]
fn sweep_finds_every_encoding_at_every_alignment() {
    let value = canary();
    let sweep = Sweep::new(&[Canary::new("c", &value)]);
    let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
    let cases = [
        ("raw", value.clone()),
        ("url-encoded", urlencoding::encode(&value).into_owned()),
        ("hex", hex.clone()),
        ("HEX", hex.to_uppercase()),
    ];
    for (encoding, form) in cases {
        let hits = sweep.scan("s", format!("x{form}y").as_bytes());
        assert_eq!(hits.len(), 1, "{encoding}");
        assert_eq!(hits[0].encoding, encoding);
        assert_eq!(hits[0].offset, 1);
    }
    for prefix in ["", "a", "ab", "abc", "abcd"] {
        let embedded = format!("{prefix}{value}tail");
        for (engine, name) in [(&STANDARD, "base64"), (&URL_SAFE, "base64url")] {
            let blob = engine.encode(embedded.as_bytes());
            let hits = sweep.scan("s", blob.as_bytes());
            assert!(
                // Both alphabets give the same text when it has no `+`,
                // `/`, `-` or `_`; the needle is then stored once.
                hits.iter().any(|h| h.encoding.starts_with("base64")),
                "{name} with prefix {prefix:?}: {hits:?}"
            );
        }
    }
    assert!(sweep.scan("s", b"nothing to see").is_empty());
    let hit = &sweep.scan("place", value.as_bytes())[0];
    assert!(!hit.to_string().contains(&value));
}
