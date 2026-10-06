//! SHA-340: the README demo cannot rot or leak.
//!
//! Each test runs `scripts/demo.sh`, the script the recording
//! (`docs/demo/demo.tape`) plays, exactly as a maintainer would: with
//! `bash`, the `test-providers` build of this test run as `ROTATE_BIN`, and
//! a run directory (`DEMO_DIR`) in a temp root. The environment is cleared
//! but for `PATH`; `HOME` and `TMPDIR` are inside the root, no AWS or
//! GitHub credential is set, and every proxy variable points at a closed
//! loopback port, so a request that left the process would fail. The fake
//! leaked secret is a canary made here.
//!
//! T1 checks the exit status, the confirmation, the apply summary, the
//! status row and the mocks' call logs; T2 sweeps everything the run
//! printed and wrote for the canary. T3 (the README image) waits for the
//! rendered GIF.

#![cfg(all(unix, feature = "test-providers"))]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use regex::Regex;
use rotate::secret::SecretValue;
use serde_json::Value;

use crate::common::sweep::{assert_no_hits, assert_private_state, canary_of, Canary, Sweep};

/// What the mock AWS provider mints as the first replacement's secret half.
const MOCK_REPLACEMENT: &str = "mock_aws_aws-replacement-1";

/// Every name the `test-providers` scenario registers a mock under.
const MOCKS: &[&str] = &[
    "aws",
    "github",
    "npm",
    "openai",
    "github-actions",
    "aws-secrets-manager",
];

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

/// One run of `scripts/demo.sh` in a fresh temp root.
struct Demo {
    root: tempfile::TempDir,
    secret: String,
    output: Output,
}

impl Demo {
    fn run() -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in ["home", "tmp"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        let secret = canary_of(40);
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        let closed = "http://127.0.0.1:9";
        let output = Command::new("bash")
            .arg(repo.join("scripts/demo.sh"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", root.path().join("home"))
            .env("TMPDIR", root.path().join("tmp"))
            .env("NO_COLOR", "1")
            .env("ROTATE_BIN", assert_cmd::cargo::cargo_bin("rotate"))
            .env("DEMO_DIR", root.path().join("run"))
            .env("DEMO_KEY_ID", "AKIADEMOTESTKEY00340")
            .env("DEMO_SECRET", &secret)
            .env("HTTP_PROXY", closed)
            .env("HTTPS_PROXY", closed)
            .env("ALL_PROXY", closed)
            .env("http_proxy", closed)
            .env("https_proxy", closed)
            .env("all_proxy", closed)
            .env("NO_PROXY", "")
            .current_dir(root.path())
            .output()
            .unwrap();
        let demo = Self {
            root,
            secret,
            output,
        };
        // Nothing is shown before the sweep has passed.
        demo.sweep();
        demo
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join("run").join(rel)
    }

    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }

    /// The sweep over both streams and every file under the root but the
    /// input report, which holds the fake key by design.
    fn sweep(&self) {
        let sweep = Sweep::new(&[
            Canary::new("leaked secret", &self.secret),
            Canary::new("mock replacement", MOCK_REPLACEMENT),
        ]);
        let mut hits = sweep.scan("demo stdout", &self.output.stdout);
        hits.extend(sweep.scan("demo stderr", &self.output.stderr));
        hits.extend(sweep.scan_dir(self.root.path(), &[self.path("work/trufflehog.json")]));
        assert_no_hits("scripts/demo.sh", &hits);
    }

    /// One mock call log: `(target.method, mutating)` per call.
    fn calls(&self, command: &str) -> Vec<(String, bool)> {
        let text = std::fs::read_to_string(self.path(&format!("mock/{command}.jsonl")))
            .unwrap_or_else(|err| panic!("no call log for {command}: {err}"));
        text.lines()
            .map(|line| {
                let call: Value = serde_json::from_str(line).unwrap();
                let target = call["target"].as_str().unwrap();
                assert!(MOCKS.contains(&target), "{command}: call to {target}");
                (
                    format!("{target}.{}", call["method"].as_str().unwrap()),
                    call["mutating"] == true,
                )
            })
            .collect()
    }
}

// T1 (AC1)
#[test]
fn t1_demo_runs_plan_apply_and_status() {
    let demo = Demo::run();
    let out = demo.stdout();
    assert_eq!(
        demo.output.status.code(),
        Some(0),
        "stdout:\n{out}\nstderr:\n{}",
        demo.stderr()
    );

    assert!(out.contains("Simulated:"), "{out}");
    assert!(out.contains("$ rotate plan trufflehog.json"), "{out}");
    assert!(out.contains("Dry run: nothing was changed."), "{out}");
    let id = Regex::new(r"Rotation (rot-[0-9a-f]{8})  aws  ")
        .unwrap()
        .captures(&out)
        .unwrap_or_else(|| panic!("no rotation in the plan: {out}"))[1]
        .to_owned();
    assert!(out.contains("$ rotate apply trufflehog.json"), "{out}");
    assert!(
        out.contains(&format!("Type the rotation id {id} to continue: {id}\n")),
        "{out}"
    );
    assert!(out.contains("Apply: 1 revoked, 0 pending revoke"), "{out}");
    assert!(out.contains("$ rotate status --all"), "{out}");
    let row = out
        .lines()
        .skip_while(|l| !l.contains("$ rotate status --all"))
        .find(|l| l.starts_with(&id))
        .unwrap_or_else(|| panic!("no status row for {id}: {out}"));
    assert!(row.contains(" revoked "), "{row}");
    assert!(row.contains(" 2/2 "), "{row}");
    assert!(row.trim_end().ends_with("done"), "{row}");
    for step in ["plan", "create", "update", "verify", "revoke"] {
        assert!(
            out.lines()
                .any(|l| l.trim_start().starts_with(&format!("{step} ")) && l.contains(" ok ")),
            "no audit row for {step}: {out}"
        );
    }

    let plan = demo.calls("plan");
    assert!(!plan.is_empty());
    assert!(
        plan.iter().all(|(_, mutating)| !mutating),
        "plan changed state: {plan:?}"
    );
    let mutating: Vec<String> = demo
        .calls("apply")
        .into_iter()
        .filter(|(_, mutating)| *mutating)
        .map(|(call, _)| call)
        .collect();
    assert_eq!(
        mutating,
        [
            "aws.create_replacement",
            "github-actions.update",
            "aws-secrets-manager.update",
            "aws.revoke",
        ]
    );
    assert!(demo.calls("status").is_empty());

    assert_private_state(&demo.path("work"));
}

// T2 (AC2)
#[test]
fn t2_demo_shows_no_secret_and_only_fingerprints() {
    // The sweep runs inside `Demo::run`.
    let demo = Demo::run();
    assert_eq!(demo.output.status.code(), Some(0));
    let out = demo.stdout();
    let shape = Regex::new(r"^sha256:[0-9a-f]{16}$").unwrap();
    let shown: Vec<&str> = Regex::new(r"sha256:[0-9A-Za-z+/=_-]*")
        .unwrap()
        .find_iter(&out)
        .map(|m| m.as_str())
        .collect();
    assert!(!shown.is_empty());
    for fingerprint in &shown {
        assert!(
            shape.is_match(fingerprint),
            "not a fingerprint: {fingerprint}"
        );
    }
    assert!(shown.contains(&fp(&demo.secret).as_str()));
    assert!(shown.contains(&fp(MOCK_REPLACEMENT).as_str()));
}
