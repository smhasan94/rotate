//! The GitHub Action (SHA-198): `action/run.sh` and `action/install.sh` run
//! as the composite steps in `action.yml` run them, against the
//! `test-providers` binary and a wiremock server that plays the GitHub
//! secret-scanning alerts API and the release download.
//!
//! T1 to T6 and T8 are here; T7 is `.github/workflows/action.yml` and T9
//! the `action-install` job of the release workflow.
//!
//! SHA-338 (apply behind an environment approval) adds `sha338_t1` to
//! `sha338_t5`: a plan job, its state directory handed over as the
//! artifact download leaves it, and an apply job in a fresh runner temp.
//!
//! The scripts need bash, curl and jq. Without them a test prints why and
//! returns, except under CI (`CI` set), where a missing tool fails.

#![cfg(unix)]
// T1 to T3 and T6 need the mock providers; T4, T5 and T8 do not.
#![cfg_attr(not(feature = "test-providers"), allow(dead_code, unused_imports))]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

use crate::common::sweep::{assert_no_hits, assert_private_state, rng, Canary, Sweep};
use crate::common::CallRecorder;

const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");
const ALERTS_PATH: &str = "/repos/acme/api/secret-scanning/alerts";
const ALERT_URL: &str = "https://github.com/acme/api/security/secret-scanning";
const PERMISSION: &str = "Secret scanning alerts: read; GITHUB_TOKEN cannot read alerts";
const SUPPORTED_TYPES: &str = "aws_secret_access_key,aws_access_key_id,\
github_personal_access_token,github_oauth_access_token,npm_access_token,openai_api_key";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// True when bash, curl and jq are installed. Under CI a missing tool is a
/// failure, so the tests can never skip there.
fn tools_present() -> bool {
    let missing: Vec<&str> = ["bash", "curl", "jq", "tar"]
        .into_iter()
        .filter(|tool| {
            !Command::new("sh")
                .args(["-c", &format!("command -v {tool}")])
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .collect();
    if missing.is_empty() {
        return true;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "the Action tests need {missing:?} on CI"
    );
    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "skipped: {missing:?} not installed");
    }
    false
}

/// `ghp_` plus 36 letters and digits holding `FAKE`: the mock `github`
/// provider identifies it, and it is unique per run.
fn ghp_canary() -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut next = rng();
    let tail: String = (0..32)
        .map(|_| ALNUM[(next() % ALNUM.len() as u64) as usize] as char)
        .collect();
    format!("ghp_FAKE{tail}")
}

/// A token for the alerts API, unique per run, so the sweep can prove it is
/// never written anywhere either.
fn token_canary() -> String {
    ghp_canary().replacen("ghp_", "ghs_", 1)
}

fn fp(value: &str) -> String {
    rotate::secret::SecretValue::from(value)
        .fingerprint()
        .to_string()
}

/// One composite-action run: a temp root holding `runner_temp/`, `work/`
/// (the workspace, with `rotate.yaml`), `inputs/` (scenario and call log)
/// and the files the runner hands a step.
struct ActionRun {
    root: tempfile::TempDir,
    env: Vec<(String, String)>,
}

impl ActionRun {
    fn new(api_url: &str, token: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in ["runner_temp", "work", "inputs", "home"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        std::fs::write(root.path().join("work/rotate.yaml"), "overlap_window: 1h\n").unwrap();
        for file in ["summary.md", "output"] {
            std::fs::write(root.path().join(file), "").unwrap();
        }
        let p = |rel: &str| root.path().join(rel).display().to_string();
        let env = vec![
            ("RUNNER_TEMP", p("runner_temp")),
            ("GITHUB_STEP_SUMMARY", p("summary.md")),
            ("GITHUB_OUTPUT", p("output")),
            ("GITHUB_SERVER_URL", "https://github.com".into()),
            ("GITHUB_REPOSITORY", "acme/api".into()),
            ("GITHUB_RUN_ID", "1234".into()),
            ("ROTATE_BIN", env!("CARGO_BIN_EXE_rotate").into()),
            ("ROTATE_TEST_SCENARIO", p("inputs/scenario.json")),
            ("RUST_LOG", "trace".into()),
            ("HOME", p("home")),
            ("ALERT_NUMBER", "42".into()),
            ("REPOSITORY", "acme/api".into()),
            ("ALERTS_TOKEN", token.into()),
            ("API_URL", api_url.into()),
            ("ROTATE_CONFIG_PATH", "rotate.yaml".into()),
            ("MODE", "plan".into()),
            ("VERBOSE", "3".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let run = Self { root, env };
        run.scenario(json!({}));
        run
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    fn set(&mut self, key: &str, value: &str) {
        self.env.retain(|(k, _)| k != key);
        self.env.push((key.to_owned(), value.to_owned()));
    }

    /// Writes the scenario, adding the call log path. Also writes the
    /// variants `rotate_shim` gives the `plan` and `status` runs of an apply
    /// step, each with its own call log, so the status run after apply
    /// cannot overwrite apply's.
    fn scenario(&self, mut scenario: Value) {
        for cmd in ["plan", "status"] {
            scenario["call_log"] = json!(self.path(&format!("inputs/calls.{cmd}.jsonl")));
            std::fs::write(
                self.path(&format!("inputs/scenario.{cmd}.json")),
                scenario.to_string(),
            )
            .unwrap();
        }
        scenario["call_log"] = json!(self.call_log());
        std::fs::write(self.path("inputs/scenario.json"), scenario.to_string()).unwrap();
    }

    fn call_log(&self) -> PathBuf {
        self.path("inputs/calls.jsonl")
    }

    /// Runs `bash action/<script> [args]` in `work/` with only the
    /// variables a runner would give the step.
    fn run(&self, script: &str, args: &[&str]) -> Output {
        Command::new("bash")
            .arg(Path::new(REPO_ROOT).join("action").join(script))
            .args(args)
            .current_dir(self.path("work"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .output()
            .unwrap()
    }

    fn summary(&self) -> String {
        std::fs::read_to_string(self.path("summary.md")).unwrap()
    }

    /// `GITHUB_OUTPUT` as `name -> value`; a later line wins.
    fn outputs(&self) -> std::collections::BTreeMap<String, String> {
        std::fs::read_to_string(self.path("output"))
            .unwrap()
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn state_dir(&self) -> PathBuf {
        self.path("runner_temp/rotate/state")
    }

    fn plan(&self) -> Value {
        let text = std::fs::read(self.path("runner_temp/rotate/plan.json")).unwrap();
        serde_json::from_slice(&text).unwrap()
    }

    /// The mock providers' and consumers' calls; `None` when rotate never
    /// ran.
    fn calls(&self) -> Option<Vec<Value>> {
        let text = std::fs::read_to_string(self.call_log()).ok()?;
        Some(
            text.lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
        )
    }

    /// AC4: no canary in any encoding in the step's streams or in any file
    /// name or content under the run's root (runner temp, workspace,
    /// summary, outputs), except the test's own inputs.
    fn sweep(&self, output: &Output, canaries: &[Canary]) {
        let sweep = Sweep::new(canaries);
        let mut hits = sweep.scan("stdout", &output.stdout);
        hits.extend(sweep.scan("stderr", &output.stderr));
        hits.extend(sweep.scan_dir(self.root.path(), &[self.path("inputs")]));
        assert_no_hits("the Action run", &hits);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A REST alert as `GET .../alerts/{number}` returns it.
fn alert(number: u64, secret_type: &str, secret: Option<&str>) -> Value {
    let mut alert = json!({
        "number": number,
        "url": format!("https://api.github.com{ALERTS_PATH}/{number}"),
        "html_url": format!("{ALERT_URL}/{number}"),
        "state": "open",
        "resolution": null,
        "secret_type": secret_type,
        "validity": "active",
        "is_base64_encoded": false,
        "first_location_detected": {
            "path": "src/app.js", "start_line": 3, "end_line": 3,
            "start_column": 1, "end_column": 41,
            "blob_sha": "af5626b4a114abcb82d63db7c8082c3c4756e51b",
            "commit_sha": "9f2c1e4b7a3d5f6e8c0b1a2d3e4f5a6b7c8d9e0f"
        },
        "has_more_locations": false
    });
    if let Some(secret) = secret {
        alert["secret"] = json!(secret);
    }
    alert
}

/// The alerts of `tests/fixtures/github_alerts.json` with these numbers.
fn fixture_alerts(numbers: &[u64]) -> Vec<Value> {
    let text =
        std::fs::read_to_string(Path::new(REPO_ROOT).join("tests/fixtures/github_alerts.json"))
            .unwrap();
    let all: Vec<Value> = serde_json::from_str(&text).unwrap();
    numbers
        .iter()
        .map(|n| {
            all.iter()
                .find(|a| a["number"] == *n)
                .unwrap_or_else(|| panic!("fixture has no alert {n}"))
                .clone()
        })
        .collect()
}

/// Serves one alert at `.../alerts/{number}`, only to the right token.
async fn serve_alert(rec: &CallRecorder, token: &str, alert: &Value) {
    let number = alert["number"].as_u64().unwrap();
    Mock::given(method("GET"))
        .and(path(format!("{ALERTS_PATH}/{number}")))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(alert))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

/// Serves the open `aws_access_key_id` alerts list (pairing material).
async fn serve_key_ids(rec: &CallRecorder, token: &str, alerts: Value) {
    Mock::given(method("GET"))
        .and(path(ALERTS_PATH))
        .and(query_param("state", "open"))
        .and(query_param("secret_type", "aws_access_key_id"))
        .and(query_param("per_page", "100"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(alerts))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

/// Serves the poll-mode list of open alerts of the six supported types.
async fn serve_open_alerts(rec: &CallRecorder, token: &str, alerts: Value) {
    Mock::given(method("GET"))
        .and(path(ALERTS_PATH))
        .and(query_param("state", "open"))
        .and(query_param("secret_type", SUPPORTED_TYPES))
        .and(query_param("per_page", "100"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(alerts))
        .with_priority(1)
        .mount(rec.server())
        .await;
}

/// `method path?query` of every request the server saw.
async fn requests(rec: &CallRecorder) -> Vec<String> {
    rec.calls()
        .await
        .iter()
        .map(|c| match &c.query {
            Some(q) => format!("{} {}?{}", c.method, c.path, q),
            None => format!("{} {}", c.method, c.path),
        })
        .collect()
}

fn rotation_ids(plan: &Value) -> Vec<String> {
    plan["rotations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["rotation_id"].as_str().unwrap().to_owned())
        .collect()
}

fn assert_no_mutating_call(calls: &[Value]) {
    assert!(!calls.is_empty(), "rotate made no provider call at all");
    let mutating: Vec<&Value> = calls.iter().filter(|c| c["mutating"] == true).collect();
    assert!(mutating.is_empty(), "state-changing calls: {mutating:?}");
}

// ---------------------------------------------------------------------------
// T1 (AC1, AC4): one alert, planned with zero mutations, leaking nothing
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha198_t1_plans_one_alert_get_only_and_leaks_nothing() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    serve_alert(
        &rec,
        &token,
        &alert(42, "github_personal_access_token", Some(&secret)),
    )
    .await;
    serve_key_ids(&rec, &token, json!([])).await;

    let run = ActionRun::new(&rec.uri(), &token);
    let consumer_ref = "gha:acme/api:GH_TOKEN";
    run.scenario(json!({
        "consumers": [{
            "name": "github-actions",
            "matches": [{ "fingerprint": fp(&secret), "ref": consumer_ref, "method": "by_name" }]
        }]
    }));
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    // The plan and the outputs.
    let plan = run.plan();
    let ids = rotation_ids(&plan);
    assert_eq!(ids.len(), 1, "{plan}");
    let rotation = &plan["rotations"][0];
    assert_eq!(rotation["provider"], "github");
    assert_eq!(rotation["fingerprint"], fp(&secret));
    let outputs = run.outputs();
    assert_eq!(outputs["rotation-ids"], ids[0]);
    assert_eq!(
        outputs["plan-path"],
        run.path("runner_temp/rotate/plan.json")
            .display()
            .to_string()
    );
    assert_eq!(outputs["state-dir"], run.state_dir().display().to_string());
    assert_eq!(outputs["exit-code"], "0");
    let summary_path = PathBuf::from(&outputs["summary-path"]);
    assert_eq!(
        std::fs::read_to_string(summary_path).unwrap(),
        run.summary()
    );

    // The summary: id, provider, fingerprint, scope identity, consumer,
    // blockers and the alert link.
    let summary = run.summary();
    let identity = rotation["scope"]["identity"].as_str().unwrap();
    for needle in [
        ids[0].as_str(),
        "| github |",
        &fp(&secret),
        identity,
        consumer_ref,
        "github-actions",
        "updatable",
        "Blockers",
        &format!("[#42]({ALERT_URL}/42)"),
        "Dry run: nothing was changed.",
    ] {
        assert!(
            summary.contains(needle),
            "summary lacks {needle:?}:\n{summary}"
        );
    }
    // Printed to the log too.
    assert!(text(&output.stdout).contains(&ids[0]));

    // GET only, to the alert and the key-id list, with empty bodies.
    let calls = rec.calls().await;
    assert!(calls
        .iter()
        .all(|c| c.method == "GET" && c.body().is_empty()));
    assert_eq!(
        requests(&rec).await,
        vec![
            format!("GET {ALERTS_PATH}/42"),
            format!("GET {ALERTS_PATH}?state=open&secret_type=aws_access_key_id&per_page=100"),
        ]
    );
    // Zero state-changing calls to any provider or consumer.
    assert_no_mutating_call(&run.calls().expect("rotate ran"));

    // AC4: the canary and the token appear nowhere.
    run.sweep(
        &output,
        &[
            Canary::new("alert secret", &secret),
            Canary::new("alerts token", &token),
        ],
    );
    let names = assert_private_state(&run.state_dir());
    assert!(names.contains(&"state.json".to_owned()), "{names:?}");
}

// ---------------------------------------------------------------------------
// T2 (AC2): poll mode
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha198_t2_poll_mode_plans_every_open_alert() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    // GitHub, npm, OpenAI, and an AWS secret key with its key id.
    serve_open_alerts(&rec, &token, json!(fixture_alerts(&[1, 2, 3, 4, 5]))).await;
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("ALERT_NUMBER", "");
    let output = run.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    let plan = run.plan();
    let providers: Vec<&str> = plan["rotations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["provider"].as_str().unwrap())
        .collect();
    assert_eq!(providers, ["github", "npm", "openai", "aws"]);
    let ids = rotation_ids(&plan);
    assert_eq!(run.outputs()["rotation-ids"], ids.join(","));
    let summary = run.summary();
    for id in &ids {
        assert!(summary.contains(id.as_str()), "{summary}");
    }
    assert!(summary.contains("open alerts of the six supported secret types"));
    // One request, per_page 100, the six types.
    assert_eq!(
        requests(&rec).await,
        vec![format!(
            "GET {ALERTS_PATH}?state=open&per_page=100&secret_type={SUPPORTED_TYPES}"
        )]
    );
    assert_no_mutating_call(&run.calls().expect("rotate ran"));

    // No open alert: the summary says so, exit 0, empty rotation-ids.
    let rec = CallRecorder::start().await;
    serve_open_alerts(&rec, &token, json!([])).await;
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("ALERT_NUMBER", "");
    let output = run.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let summary = run.summary();
    assert!(
        summary.contains("No open secret-scanning alerts of the supported types."),
        "{summary}"
    );
    assert!(!summary.contains("### Rotations"), "{summary}");
    let outputs = run.outputs();
    assert_eq!(outputs["rotation-ids"], "");
    assert_eq!(outputs["exit-code"], "0");
    assert_eq!(requests(&rec).await.len(), 1);
}

// ---------------------------------------------------------------------------
// T3 (AC3): alerts rotate skips are listed with their reason and link
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha198_t3_skipped_alerts_listed_with_reason_and_link() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    // 3: OpenAI, invalid (the scenario says so); 7: resolved; 9: no
    // `secret`; 10: github_ssh_private_key, unsupported.
    let mut alerts = fixture_alerts(&[3, 7, 9, 10]);
    alerts[0]["validity"] = json!("inactive");
    for alert in &alerts {
        serve_alert(&rec, &token, alert).await;
    }
    serve_key_ids(&rec, &token, json!([])).await;
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("ALERT_NUMBER", "3,7,9,10");
    run.scenario(json!({ "providers": { "openai": { "validity": "invalid" } } }));
    let output = run.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    let summary = run.summary();
    let skipped = summary
        .split("### Skipped")
        .nth(1)
        .unwrap_or_else(|| panic!("no Skipped table:\n{summary}"));
    let row = |n: u32| {
        let link = format!("[#{n}]({ALERT_URL}/{n})");
        skipped
            .lines()
            .find(|l| l.starts_with(&format!("| {link} |")))
            .unwrap_or_else(|| panic!("no Skipped row for alert {n}:\n{summary}"))
            .to_owned()
    };
    assert!(row(3).contains("| invalid |"), "{}", row(3));
    assert!(row(3).contains("| openai |"), "{}", row(3));
    assert!(row(7).contains("| resolved |"), "{}", row(7));
    assert!(row(9).contains("| no secret |"), "{}", row(9));
    assert!(row(9).contains("REST API"), "{}", row(9));
    assert!(row(10).contains("| unsupported |"), "{}", row(10));
    assert!(summary.contains("0 to rotate, 4 skipped."), "{summary}");
    assert_eq!(run.outputs()["rotation-ids"], "");
    // Every alert was fetched with GET, one request each, then the key ids.
    let reqs = requests(&rec).await;
    assert_eq!(reqs.len(), 5, "{reqs:?}");
    assert!(reqs.iter().all(|r| r.starts_with("GET ")));
}

// ---------------------------------------------------------------------------
// T4 (AC4, AC5): install.sh downloads and checks the release
// ---------------------------------------------------------------------------

/// The release target name for this machine, as `install.sh` picks it.
fn target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        other => panic!("no release target for {other:?}"),
    }
}

/// A release tarball whose `rotate` is a script that prints the version
/// and, when `ROTATE_RAN_MARKER` is set, creates that file.
fn release_tarball(dir: &Path, version: &str) -> Vec<u8> {
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    let bin = stage.join("rotate");
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nif [ -n \"${{ROTATE_RAN_MARKER:-}}\" ]; then : > \"$ROTATE_RAN_MARKER\"; fi\necho \"rotate {version}\"\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let tarball = dir.join("release.tar.gz");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(&stage)
        .arg("rotate")
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::read(tarball).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every regular file under `dir` named `rotate`.
fn binaries_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.file_name().is_some_and(|n| n == "rotate") {
                found.push(path);
            }
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread")]
async fn sha198_t4_install_verifies_the_checksum_before_running() {
    if !tools_present() {
        return;
    }
    let version = env!("CARGO_PKG_VERSION");
    let name = format!("rotate-{version}-{}.tar.gz", target());
    let scratch = tempfile::tempdir().unwrap();
    let tarball = release_tarball(scratch.path(), version);
    let good = hex(&Sha256::digest(&tarball));
    let wrong = hex(&Sha256::digest(b"tampered"));
    let other = format!(
        "{}  rotate-{version}-other-target.tar.gz\n",
        hex(&[7u8; 32])
    );
    // (SHA256SUMS, None for a good install or the expected error)
    let cases: Vec<(String, Option<&str>)> = vec![
        (format!("{other}{good}  {name}\n"), None),
        (format!("{good} *{name}\n"), None),
        (format!("{wrong}  {name}\n"), Some("checksum mismatch")),
        (other.clone(), Some("SHA256SUMS has no line for")),
        (format!("{}  {name}\n", &good[..40]), Some("malformed line")),
        (
            format!("zz{}  {name}\n", &good[2..]),
            Some("malformed line"),
        ),
        (
            format!("{good}  {name}\n{wrong}  {name}\n"),
            Some("2 lines for"),
        ),
        (
            format!("{wrong}  {name}\n{good}  {name}\n"),
            Some("2 lines for"),
        ),
    ];

    for (sums, error) in cases {
        let token = token_canary();
        let rec = CallRecorder::start().await;
        let base = format!("/download/v{version}");
        Mock::given(method("GET"))
            .and(path(format!("{base}/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
            .with_priority(1)
            .mount(rec.server())
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/SHA256SUMS")))
            .respond_with(ResponseTemplate::new(200).set_body_string(sums.clone()))
            .with_priority(1)
            .mount(rec.server())
            .await;
        let mut run = ActionRun::new(&rec.uri(), &token);
        run.set("ROTATE_VERSION", version);
        run.set("ROTATE_BINARY", "");
        run.set("ROTATE_RELEASE_BASE", &format!("{}{base}", rec.uri()));
        let marker = run.path("ran");
        run.set("ROTATE_RAN_MARKER", &marker.display().to_string());

        // The composite action: install, and only on success the plan step.
        let install = run.run("install.sh", &[]);
        let stdout = text(&install.stdout);
        let stderr = text(&install.stderr);
        if install.status.success() {
            let bin = run.outputs()["path"].clone();
            run.set("ROTATE_BIN", &bin);
            let _ = run.run("run.sh", &[]);
        }

        if let Some(error) = error {
            assert_eq!(install.status.code(), Some(1), "{sums}: {stderr}");
            assert!(stderr.contains(error), "{sums}: {stderr}");
            assert_eq!(stderr.lines().count(), 1, "{stderr}");
            assert!(!marker.exists(), "the binary ran despite a bad SHA256SUMS");
            assert!(!run.outputs().contains_key("path"));
            assert_eq!(
                binaries_under(&run.path("runner_temp")),
                Vec::<PathBuf>::new()
            );
            let reqs = requests(&rec).await;
            assert!(
                reqs.iter().all(|r| !r.contains("/secret-scanning/")),
                "alerts fetched after a failed install: {reqs:?}"
            );
            assert_eq!(reqs.len(), 2, "{reqs:?}");
        } else {
            assert_eq!(install.status.code(), Some(0), "{sums}: {stderr}");
            assert!(stdout.contains("checksum ok"), "{stdout}");
            assert!(
                stdout.lines().any(|l| l == format!("rotate {version}")),
                "{stdout}"
            );
            let bin = run.path("runner_temp/rotate/bin/rotate");
            assert_eq!(run.outputs()["path"], bin.display().to_string());
            assert!(marker.exists(), "the installed binary was not run");
            let binaries = binaries_under(&run.path("runner_temp"));
            assert_eq!(binaries, vec![bin]);
        }
    }
}

// ---------------------------------------------------------------------------
// T5 (AC6): bad inputs exit 2 before any request
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sha198_t5_bad_inputs_exit_2_before_any_request() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let cases: &[(&str, &str, &str)] = &[
        ("ALERT_NUMBER", "42;id", "alert-number"),
        ("ALERT_NUMBER", "4 2", "alert-number"),
        ("ALERT_NUMBER", "42,", "alert-number"),
        ("ALERT_NUMBER", "#42", "alert-number"),
        ("REPOSITORY", "acme", "repository"),
        ("REPOSITORY", "acme/api/x", "repository"),
        ("REPOSITORY", "../..", "repository"),
        ("REPOSITORY", "acme/$(id)", "repository"),
        ("ALERTS_TOKEN", "", "alerts-token"),
        ("ALERTS_TOKEN", "a b", "alerts-token"),
        // SHA-338: apply needs the rotation ids to confirm.
        ("MODE", "apply", "confirm"),
        ("MODE", "destroy", "mode"),
        ("OVERLAP", "soon", "overlap"),
        ("OVERLAP", "1h\n::warning::injected", "overlap"),
        ("MAX_WAIT", "1 h", "max-wait"),
        ("FORCE", "yes", "force"),
        ("UPLOAD_AUDIT", "no", "upload-audit"),
        ("REPLACEMENT_ENV", "NEW-TOKEN", "replacement-env"),
        ("REPLACEMENT_ENV", "$(id)", "replacement-env"),
        // Apply-only inputs are refused in plan mode.
        ("CONFIRM", "rot-1a2b3c4d", "confirm"),
        ("PLAN_STATE_DIR", "state", "state-dir"),
        ("REPLACEMENT_ENV", "NEW_TOKEN", "replacement-env"),
        ("FORCE", "true", "force"),
        ("API_URL", "http://example.com", "api-url"),
        ("VERBOSE", "9", "verbose"),
        ("ROTATE_CONFIG_PATH", "missing.yaml", "config"),
        (
            "ROTATE_CONFIG_PATH",
            "rotate.yaml\n::warning::injected",
            "config",
        ),
        ("ROTATE_CONFIG_PATH", "a\rb.yaml", "config"),
        ("API_URL", "http://127.0.0.1.evil.com", "api-url"),
        ("API_URL", "http://127.0.0.1@evil.com", "api-url"),
        ("API_URL", "https://x@evil", "api-url"),
        ("API_URL", "http://localhost.evil.com", "api-url"),
        ("API_URL", "http://localhost@evil", "api-url"),
        ("API_URL", "http://[::1].evil.com", "api-url"),
        ("API_URL", "https://evil.com\\@api.github.com", "api-url"),
    ];
    for (key, value, input) in cases {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.set(key, value);
            if *key == "ROTATE_CONFIG_PATH" && value.chars().any(char::is_control) {
                // The file exists: only the control character is wrong.
                std::fs::write(run.path("work").join(value), "").unwrap();
            }
            let output = run.run("run.sh", args);
            let stderr = text(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{key}={value:?}: {stderr}");
            let lines: Vec<&str> = stderr.lines().collect();
            assert_eq!(lines.len(), 1, "{key}={value:?}: {stderr}");
            assert!(
                lines[0].contains(&format!("input {input}:")),
                "{key}={value:?}: {stderr}"
            );
            assert!(!stderr.contains("injected"), "input echoed: {stderr}");
            assert!(output.stdout.is_empty());
            assert!(run.calls().is_none(), "rotate ran for {key}={value:?}");
        }
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // rotate-binary is never echoed and cannot reach GITHUB_OUTPUT with a
    // newline in it.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("ROTATE_BINARY", "bin/rotate\n::warning::injected");
    let output = run.run("install.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("input rotate-binary:"), "{stderr}");
    assert!(!stderr.contains("injected"), "{stderr}");
    assert!(!run.outputs().contains_key("path"));

    // mode: apply (SHA-338) with confirmed ids but no plan state.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("MODE", "apply");
    run.set("CONFIRM", "rot-1a2b3c4d");
    for (dir, why) in [("", "is empty"), ("missing", "has no .rotate/state.json")] {
        run.set("PLAN_STATE_DIR", dir);
        let output = run.run("run.sh", &[]);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(
            stderr.contains(&format!("input state-dir: {why}")),
            "{stderr}"
        );
        assert!(run.calls().is_none());
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // The inputs that pass.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("ALERT_NUMBER", "42,43");
    run.set("REPOSITORY", "acme-corp/api.v2_x");
    let output = run.run("run.sh", &["--check-inputs"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(requests(&rec).await, Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// T6 (AC7): the alerts API refuses
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha198_t6_api_refusal_names_the_permission_and_skips_rotate() {
    if !tools_present() {
        return;
    }
    for status in [401u16, 403, 404] {
        let token = token_canary();
        let rec = CallRecorder::start().await;
        Mock::given(method("GET"))
            .and(path(format!("{ALERTS_PATH}/42")))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({ "message": "nope" })))
            .with_priority(1)
            .mount(rec.server())
            .await;
        let run = ActionRun::new(&rec.uri(), &token);
        let output = run.run("run.sh", &[]);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{status}: {stderr}");
        assert!(stderr.contains(&format!("HTTP {status}")), "{stderr}");
        assert!(stderr.contains(PERMISSION), "{stderr}");
        // rotate never ran.
        assert!(run.calls().is_none(), "{status}: rotate ran");
        assert!(!run.state_dir().join(".rotate").exists());
        assert!(!run.path("runner_temp/rotate/plan.json").exists());
        // The summary holds the message only.
        let summary = run.summary();
        assert_eq!(summary.lines().count(), 1, "{summary}");
        assert!(summary.contains(&format!("HTTP {status}")), "{summary}");
        assert!(summary.contains(PERMISSION), "{summary}");
        let outputs = run.outputs();
        assert_eq!(outputs["exit-code"], "1");
        assert!(!outputs.contains_key("rotation-ids"));
        // Nothing is fetched after the first failure.
        assert_eq!(requests(&rec).await, vec![format!("GET {ALERTS_PATH}/42")]);
        run.sweep(&output, &[Canary::new("alerts token", &token)]);
    }

    // A later request fails: rotate refuses the whole input before any
    // provider call or state write, and the step fails the same way.
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    serve_alert(
        &rec,
        &token,
        &alert(42, "github_personal_access_token", Some(&secret)),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(format!("{ALERTS_PATH}/43")))
        .respond_with(ResponseTemplate::new(404))
        .with_priority(1)
        .mount(rec.server())
        .await;
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("ALERT_NUMBER", "42,43");
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("HTTP 404"), "{stderr}");
    assert_eq!(run.calls().unwrap_or_default(), Vec::<Value>::new());
    assert!(!run.state_dir().join(".rotate/state.json").exists());
    assert_eq!(run.summary().lines().count(), 1);
    run.sweep(
        &output,
        &[
            Canary::new("alert secret", &secret),
            Canary::new("alerts token", &token),
        ],
    );
}

// rotate exits on a bad rotate.yaml before reading its input. With a body
// bigger than a pipe buffer, curl then cannot write; that is not an API
// failure, and rotate's own error must reach the summary.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha198_t6_rotate_config_error_is_not_an_api_failure() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let template = fixture_alerts(&[2]).remove(0);
    let alerts: Vec<Value> = (1..=200)
        .map(|n| {
            let mut alert = template.clone();
            alert["number"] = json!(n);
            alert["html_url"] = json!(format!("{ALERT_URL}/{n}"));
            alert
        })
        .collect();
    let body = serde_json::to_vec(&alerts).unwrap();
    assert!(body.len() > 128 * 1024, "{} bytes", body.len());
    serve_open_alerts(&rec, &token, json!(alerts)).await;
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("ALERT_NUMBER", "");
    std::fs::write(run.path("work/rotate.yaml"), "overlap_window: soon\n").unwrap();
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    let summary = run.summary();
    assert!(summary.contains("rotate exited with code 2"), "{summary}");
    assert!(summary.contains("invalid duration"), "{summary}");
    assert!(!summary.contains("HTTP"), "{summary}");
    assert!(!stderr.contains("alerts API"), "{stderr}");
    let outputs = run.outputs();
    assert_eq!(outputs["exit-code"], "2");
    assert_eq!(outputs["rotation-ids"], "");
    assert!(!outputs.contains_key("plan-path"));
    assert_eq!(requests(&rec).await.len(), 1);
}

// ---------------------------------------------------------------------------
// T8 (AC8): action.yml, install.sh, the README and the doc agree
// ---------------------------------------------------------------------------

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(REPO_ROOT).join(rel)).unwrap()
}

fn action_yml() -> Value {
    serde_norway::from_str(&read("action.yml")).unwrap()
}

fn keys(value: &Value) -> Vec<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

/// `Linux-x86_64) TARGET=... ;;` lines, trimmed, in order.
fn target_table(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            (l.starts_with("Linux-") || l.starts_with("Darwin-")) && l.contains(") TARGET=")
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn sha198_t8_action_version_targets_and_doc_agree() {
    let action = action_yml();

    // The default version is the crate's.
    assert_eq!(
        action["inputs"]["version"]["default"],
        env!("CARGO_PKG_VERSION"),
        "action.yml's version default must equal Cargo.toml's version"
    );

    // install.sh picks targets exactly as the README install block does.
    let readme = read("README.md");
    let block = readme
        .split("<!-- install:start -->")
        .nth(1)
        .and_then(|rest| rest.split("<!-- install:end -->").next())
        .expect("README.md has an install block");
    let readme_targets = target_table(block);
    assert_eq!(readme_targets.len(), 4, "{readme_targets:?}");
    assert_eq!(target_table(&read("action/install.sh")), readme_targets);

    // The inputs and outputs in scope, each documented.
    let inputs = keys(&action["inputs"]);
    let outputs = keys(&action["outputs"]);
    let mut want_inputs = vec![
        "alert-number",
        "repository",
        "alerts-token",
        "api-url",
        "version",
        "rotate-binary",
        "config",
        "mode",
        "verbose",
        // SHA-338
        "confirm",
        "force",
        "overlap",
        "replacement-env",
        "state-dir",
        "max-wait",
        "upload-audit",
    ];
    let mut want_outputs = vec![
        "rotation-ids",
        "plan-path",
        "summary-path",
        "state-dir",
        "exit-code",
    ];
    let mut sorted_inputs = inputs.clone();
    sorted_inputs.sort();
    want_inputs.sort_unstable();
    assert_eq!(sorted_inputs, want_inputs);
    let mut sorted_outputs = outputs.clone();
    sorted_outputs.sort();
    want_outputs.sort_unstable();
    assert_eq!(sorted_outputs, want_outputs);
    let doc = read("docs/github-action.md");
    for name in inputs.iter().chain(&outputs) {
        assert!(
            doc.contains(&format!("| `{name}` |")),
            "docs/github-action.md has no table row for `{name}`"
        );
    }

    // Inputs are checked before the install step downloads anything (AC6),
    // and no input is interpolated into a `run:` script.
    let steps = action["runs"]["steps"].as_array().unwrap();
    let ids: Vec<&str> = steps.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["inputs", "install", "rotate", "audit"]);
    assert_eq!(action["runs"]["using"], "composite");
    for step in &steps[..3] {
        let script = step["run"].as_str().unwrap();
        assert!(!script.contains("${{"), "expression in run: {script}");
        assert_eq!(step["shell"], "bash");
    }

    // SHA-338: the audit artifact. Uploaded after apply, also when apply
    // failed, unless upload-audit is false; kept 30 days; the action is
    // pinned to a full commit SHA.
    let audit = &steps[3];
    assert!(audit.get("run").is_none());
    let uses = audit["uses"].as_str().unwrap();
    let (name, sha) = uses.split_once('@').unwrap();
    assert_eq!(name, "actions/upload-artifact");
    assert!(
        sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "{uses}"
    );
    let condition = audit["if"].as_str().unwrap();
    for needle in [
        "always()",
        "inputs.mode == 'apply'",
        "inputs.upload-audit == 'true'",
    ] {
        assert!(condition.contains(needle), "{condition}");
    }
    let with = &audit["with"];
    assert!(with["name"]
        .as_str()
        .unwrap()
        .starts_with("rotate-audit-${{ github.run_id }}"));
    assert!(with["path"].as_str().unwrap().ends_with("/.rotate/"));
    assert_eq!(with["retention-days"], 30);
    assert_eq!(with["include-hidden-files"], true);
    assert_eq!(action["inputs"]["upload-audit"]["default"], "true");

    // The caller workflow in the doc: the state hand-off and the approval.
    for needle in [
        "environment: rotate-apply",
        "name: rotate-state-${{ github.run_id }}-${{ github.run_attempt }}",
        "retention-days: 1",
        "include-hidden-files: true",
        "actions/download-artifact",
        "mode: apply",
        "confirm: ${{ needs.plan.outputs.rotation-ids }}",
        "Prevent self-review",
    ] {
        assert!(
            doc.contains(needle),
            "docs/github-action.md lacks {needle:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// SHA-338: apply behind an environment approval
// ---------------------------------------------------------------------------

/// Stands in for rotate in an apply step: each subcommand but `apply`
/// runs with its scenario variant (`ActionRun::scenario`), so the call log
/// of `apply` survives the overlap probe before it and the status runs
/// around it. It also keeps a copy of `GITHUB_OUTPUT` as each subcommand
/// starts (`inputs/output-before-<cmd>`).
const ROTATE_SHIM: &str = r#"#!/bin/sh
cmd=
for arg in "$@"; do
  case $arg in
    plan | apply | status) cmd=$arg; break ;;
  esac
done
if [ -n "$cmd" ] && [ -n "${GITHUB_OUTPUT:-}" ]; then
  cp "$GITHUB_OUTPUT" "${ROTATE_TEST_SCENARIO%/*}/output-before-$cmd"
fi
variant="${ROTATE_TEST_SCENARIO%.json}.$cmd.json"
if [ "$cmd" != apply ] && [ -f "$variant" ]; then
  ROTATE_TEST_SCENARIO=$variant
  export ROTATE_TEST_SCENARIO
fi
exec "$ROTATE_SHIM_TARGET" "$@"
"#;

/// `rotate --json status --all` as the apply step left it.
fn status_rows(run: &ActionRun) -> Vec<Value> {
    let text = std::fs::read(run.path("runner_temp/rotate/status.json")).unwrap();
    serde_json::from_slice(&text).unwrap()
}

impl ActionRun {
    /// Makes this run the apply job of the caller workflow (docs): the plan
    /// job's state directory as `actions/download-artifact` leaves it
    /// (0755 directories, 0644 files) under this runner's temp, mode
    /// apply, the confirmed ids, and `ROTATE_SHIM` in front of rotate.
    fn apply_job(&mut self, plan: &ActionRun, ids: &str) {
        let download = self.path("runner_temp/rotate-plan-state");
        let dot = download.join(".rotate");
        std::fs::create_dir_all(&dot).unwrap();
        for name in ["state.json", "audit.jsonl"] {
            let from = plan.state_dir().join(".rotate").join(name);
            if from.exists() {
                std::fs::copy(&from, dot.join(name)).unwrap();
                std::fs::set_permissions(dot.join(name), std::fs::Permissions::from_mode(0o644))
                    .unwrap();
            }
        }
        for dir in [&download, &dot] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let shim = self.path("inputs/rotate-shim");
        std::fs::write(&shim, ROTATE_SHIM).unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        self.set("ROTATE_SHIM_TARGET", env!("CARGO_BIN_EXE_rotate"));
        self.set("ROTATE_BIN", &shim.display().to_string());
        self.set("MODE", "apply");
        self.set("CONFIRM", ids);
        self.set("PLAN_STATE_DIR", &download.display().to_string());
    }

    /// `GITHUB_OUTPUT` as it was when the step first ran rotate (the
    /// overlap probe, `plan`); `None` if rotate never ran.
    fn output_before_rotate(&self) -> Option<String> {
        std::fs::read_to_string(self.path("inputs/output-before-plan")).ok()
    }

    /// The calls of one of the apply step's other rotate runs: `plan` (the
    /// overlap probe) or `status`.
    fn calls_of(&self, cmd: &str) -> Vec<Value> {
        std::fs::read_to_string(self.path(&format!("inputs/calls.{cmd}.jsonl")))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

/// The scenario both jobs share: `github-actions` holds the leaked token
/// as `GH_TOKEN`, found by name.
fn consumer_scenario(secret: &str) -> Value {
    json!({
        "consumers": [{
            "name": "github-actions",
            "matches": [{ "fingerprint": fp(secret), "ref": "gha:acme/api:GH_TOKEN", "method": "by_name" }]
        }]
    })
}

/// The plan job for alert 42 holding `secret`: runs it and returns the run
/// and the one rotation id.
async fn plan_job(rec: &CallRecorder, token: &str, secret: &str) -> (ActionRun, String, Output) {
    serve_alert(
        rec,
        token,
        &alert(42, "github_personal_access_token", Some(secret)),
    )
    .await;
    serve_key_ids(rec, token, json!([])).await;
    let run = ActionRun::new(&rec.uri(), token);
    run.scenario(consumer_scenario(secret));
    let output = run.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let ids = run.outputs()["rotation-ids"].clone();
    assert!(ids.starts_with("rot-") && !ids.contains(','), "{ids:?}");
    (run, ids, output)
}

/// The scenario of the apply job: the plan job's, plus `extra`, and a
/// prompt that fails the run if apply asks anything.
fn apply_scenario(secret: &str, extra: Value) -> Value {
    let mut scenario = consumer_scenario(secret);
    scenario["prompt"] = json!("panic");
    for (key, value) in extra.as_object().unwrap() {
        scenario[key] = value.clone();
    }
    scenario
}

/// `target.method` of the create, update, verify and revoke calls, in
/// order.
fn rotation_steps(calls: &[Value]) -> Vec<String> {
    calls
        .iter()
        .map(|c| {
            format!(
                "{}.{}",
                c["target"].as_str().unwrap(),
                c["method"].as_str().unwrap()
            )
        })
        .filter(|c| {
            ["create_replacement", "update", "verify", "revoke"]
                .iter()
                .any(|m| c.ends_with(&format!(".{m}")))
        })
        .collect()
}

/// The plan job for `secret` on `rec`, then an apply job for its rotation
/// in a fresh runner temp, with an overlap of `0s` and `extra` in the
/// scenario. Returns the apply run (not yet run) and the rotation id.
async fn apply_after_plan(
    rec: &CallRecorder,
    token: &str,
    secret: &str,
    extra: Value,
) -> (ActionRun, String) {
    let (plan, id, _) = plan_job(rec, token, secret).await;
    let mut run = ActionRun::new(&rec.uri(), token);
    run.apply_job(&plan, &id);
    run.set("OVERLAP", "0s");
    run.scenario(apply_scenario(secret, extra));
    (run, id)
}

fn assert_no_mutating(run: &ActionRun) {
    let calls = run.calls().unwrap_or_default();
    let mutating: Vec<&Value> = calls.iter().filter(|c| c["mutating"] == true).collect();
    assert!(mutating.is_empty(), "state-changing calls: {mutating:?}");
}

fn assert_no_revoke(calls: &[Value]) {
    let revokes: Vec<&Value> = calls
        .iter()
        .filter(|c| c["method"].as_str().unwrap().starts_with("revoke"))
        .collect();
    assert!(revokes.is_empty(), "revoke called: {revokes:?}");
}

// ---------------------------------------------------------------------------
// SHA-338 T1 (AC1): the planned rotation applied end to end, revoke last
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_t1_apply_runs_every_step_in_order_without_a_prompt() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (plan, id, _) = plan_job(&rec, &token, &secret).await;
    let planned = requests(&rec).await.len();

    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_job(&plan, &id);
    // A short window, so --wait is seen to wait and then revoke.
    run.set("OVERLAP", "2s");
    run.scenario(apply_scenario(&secret, json!({})));
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    // No prompt: the scenario's prompt panics if apply asks.
    assert!(!stderr.contains("Type the rotation id"), "{stderr}");
    assert!(stderr.contains("waiting until"), "{stderr}");

    let calls = run.calls().expect("rotate apply ran");
    assert_eq!(
        rotation_steps(&calls),
        [
            "github.create_replacement",
            "github-actions.update",
            "github.verify",
            "github.revoke",
        ]
    );
    // Revoke is the last state-changing call.
    let last = calls.iter().rev().find(|c| c["mutating"] == true).unwrap();
    assert_eq!(last["method"], "revoke", "{calls:?}");
    // The overlap probe and the status run made no call at all.
    assert_eq!(run.calls_of("plan"), Vec::<Value>::new());
    assert_eq!(run.calls_of("status"), Vec::<Value>::new());

    // The alerts were fetched again, GET only, the same two requests.
    let reqs = requests(&rec).await;
    assert_eq!(reqs[..planned], reqs[planned..], "{reqs:?}");
    assert!(rec
        .calls()
        .await
        .iter()
        .all(|c| c.method == "GET" && c.body().is_empty()));

    // The summary comes from `rotate status`: done, revoked.
    let rows = status_rows(&run);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["rotation_id"], id.as_str());
    assert_eq!(rows[0]["step"], "revoked");
    let summary = run.summary();
    for needle in [
        "## rotate apply: acme/api",
        &format!("[#42]({ALERT_URL}/42)"),
        &format!("Confirmed: `{id}`."),
        "**Done.**",
        "| revoked |",
        "| 1/1 |",
        &fp(&secret),
    ] {
        assert!(
            summary.contains(needle),
            "summary lacks {needle:?}:\n{summary}"
        );
    }
    let outputs = run.outputs();
    assert_eq!(outputs["exit-code"], "0");
    assert_eq!(outputs["state-dir"], run.state_dir().display().to_string());
    assert!(!outputs.contains_key("rotation-ids"));
    // state-dir was set before rotate first ran, so the audit upload has
    // it even if the step is killed during --wait.
    let before = run.output_before_rotate().expect("rotate ran");
    assert!(
        before.contains(&format!("state-dir={}\n", run.state_dir().display())),
        "{before}"
    );

    // The state the plan job handed over was used: same id, a private
    // copy, and its audit trail continues in the apply job's audit log.
    let names = assert_private_state(&run.state_dir());
    assert!(names.contains(&"audit.jsonl".to_owned()), "{names:?}");
    let audit = std::fs::read_to_string(run.state_dir().join(".rotate/audit.jsonl")).unwrap();
    let steps: Vec<String> = audit
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["step"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    // The plan job's entry first.
    assert_eq!(steps.first().map(String::as_str), Some("plan"), "{steps:?}");
    assert_eq!(
        steps.last().map(String::as_str),
        Some("revoke"),
        "{steps:?}"
    );
}

// ---------------------------------------------------------------------------
// SHA-338 T2 (AC2): a consumer update fails, nothing is revoked
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_t2_failed_update_never_revokes_and_exits_1() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (plan, id, _) = plan_job(&rec, &token, &secret).await;

    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_job(&plan, &id);
    run.set("OVERLAP", "0s");
    let mut scenario = apply_scenario(&secret, json!({}));
    scenario["consumers"][0]["fail"] = json!({ "update": "403 secret update denied" });
    run.scenario(scenario);
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("::error title=rotate::rotate apply failed; the old secret is still valid"),
        "{stderr}"
    );

    let calls = run.calls().expect("rotate apply ran");
    assert_no_revoke(&calls);
    assert_eq!(
        rotation_steps(&calls),
        ["github.create_replacement", "github-actions.update"]
    );

    let summary = run.summary();
    for needle in [
        "**Failed: the old secret is still valid.**",
        "| failed |",
        "403 secret update denied",
        "consumer gha:acme/api:GH_TOKEN failed",
    ] {
        assert!(
            summary.contains(needle),
            "summary lacks {needle:?}:\n{summary}"
        );
    }
    assert_eq!(run.outputs()["exit-code"], "1");
}

// ---------------------------------------------------------------------------
// SHA-338 T3 (AC3): a window longer than the job (exit 3), a revoke by
// hand (exit 4)
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_t3_long_window_exits_3_and_revoke_by_hand_exits_4() {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (plan, id, _) = plan_job(&rec, &token, &secret).await;

    // A 2h window and a job that waits at most 1h: create, update and
    // verify, no revoke, exit 3 with the revoke time. rotate's clock runs
    // a day ahead, so the time shown is rotate's, not the script's.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_job(&plan, &id);
    run.set("OVERLAP", "2h");
    run.set("MAX_WAIT", "1h");
    run.scenario(apply_scenario(
        &secret,
        json!({ "clock_offset_secs": 86_400 }),
    ));
    let started = OffsetDateTime::now_utc();
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        OffsetDateTime::now_utc() - started < time::Duration::minutes(1),
        "the step waited"
    );
    let calls = run.calls().expect("rotate apply ran");
    assert_no_revoke(&calls);
    assert_eq!(
        rotation_steps(&calls),
        [
            "github.create_replacement",
            "github-actions.update",
            "github.verify",
        ]
    );
    let rows = status_rows(&run);
    assert_eq!(rows[0]["step"], "pending_revoke");
    let at = rows[0]["revoke_not_before"].as_str().unwrap().to_owned();
    let when = OffsetDateTime::parse(&at, &Rfc3339).unwrap();
    assert!(
        when > started + time::Duration::hours(25),
        "{at} is not rotate's clock plus the window"
    );
    let summary = run.summary();
    for needle in [
        "**Not revoked: the overlap window is longer than this job may wait.**",
        "the old secret is still valid",
        &format!("ends at `{at}`"),
        "`max-wait` (`1h`)",
        "(`2h`)",
        "| pending_revoke |",
    ] {
        assert!(
            summary.contains(needle),
            "summary lacks {needle:?}:\n{summary}"
        );
    }
    assert!(
        stderr.contains(&format!(
            "The overlap window ends at {at}, after max-wait (1h)"
        )),
        "{stderr}"
    );
    assert_eq!(run.outputs()["exit-code"], "3");

    // The provider can only have the old secret deleted by hand: exit 4
    // with its instructions in the summary.
    let instructions = "delete the token at https://github.com/settings/tokens";
    let secret = ghp_canary();
    let rec = CallRecorder::start().await;
    let (plan, id, _) = plan_job(&rec, &token, &secret).await;
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_job(&plan, &id);
    run.set("OVERLAP", "0s");
    run.scenario(apply_scenario(
        &secret,
        json!({ "providers": { "github": { "manual_revoke": instructions } } }),
    ));
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert_no_revoke(&run.calls().expect("rotate apply ran"));
    assert!(stderr.contains("revoke it by hand"), "{stderr}");
    let rows = status_rows(&run);
    assert_eq!(rows[0]["step"], "revoke_manual");
    let summary = run.summary();
    let line = format!("- `{id}`: revoke by hand: ");
    for needle in [
        "**Revoke by hand.**",
        line.as_str(),
        instructions,
        "| revoke_manual |",
    ] {
        assert!(
            summary.contains(needle),
            "summary lacks {needle:?}:\n{summary}"
        );
    }
    assert_eq!(run.outputs()["exit-code"], "4");
}

// ---------------------------------------------------------------------------
// SHA-338 T4 (AC4): a bad confirm input exits 2 before any request
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sha338_t4_bad_confirm_exits_2_before_any_request() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let scratch = tempfile::tempdir().unwrap();
    // A state directory that passes, so only confirm is wrong.
    std::fs::create_dir_all(scratch.path().join(".rotate")).unwrap();
    std::fs::write(scratch.path().join(".rotate/state.json"), "{}").unwrap();
    for value in [
        "",
        "rot-1a2b3c4",
        "rot-1a2b3c4d5",
        "rot-1A2B3C4D",
        "rot-1a2b3c4g",
        "1a2b3c4d",
        "rot-1a2b3c4d,",
        ",rot-1a2b3c4d",
        "rot-1a2b3c4d,,rot-5e6f7a8b",
        "rot-1a2b3c4d rot-5e6f7a8b",
        "rot-1a2b3c4d;id",
        "rot-1a2b3c4d\n::warning::injected",
        "rot-1a2b3c4d\r",
        "--all",
    ] {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.set("MODE", "apply");
            run.set("PLAN_STATE_DIR", &scratch.path().display().to_string());
            run.set("CONFIRM", value);
            let output = run.run("run.sh", args);
            let stderr = text(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{value:?}: {stderr}");
            assert_eq!(stderr.lines().count(), 1, "{value:?}: {stderr}");
            assert!(
                stderr.starts_with("::error title=rotate::input confirm:"),
                "{value:?}: {stderr}"
            );
            assert!(!stderr.contains("injected"), "input echoed: {stderr}");
            assert!(output.stdout.is_empty());
            assert!(run.calls().is_none(), "rotate ran for {value:?}");
        }
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // A state-dir whose .rotate, or whose state.json, is a symbolic link
    // is refused the same way.
    let linked_dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(
        scratch.path().join(".rotate"),
        linked_dir.path().join(".rotate"),
    )
    .unwrap();
    let linked_file = tempfile::tempdir().unwrap();
    std::fs::create_dir(linked_file.path().join(".rotate")).unwrap();
    std::os::unix::fs::symlink(
        scratch.path().join(".rotate/state.json"),
        linked_file.path().join(".rotate/state.json"),
    )
    .unwrap();
    for dir in [linked_dir.path(), linked_file.path()] {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.set("MODE", "apply");
            run.set("CONFIRM", "rot-1a2b3c4d");
            run.set("PLAN_STATE_DIR", &dir.display().to_string());
            let output = run.run("run.sh", args);
            let stderr = text(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{stderr}");
            assert_eq!(stderr.lines().count(), 1, "{stderr}");
            assert!(
                stderr.starts_with("::error title=rotate::input state-dir:"),
                "{stderr}"
            );
            assert!(run.calls().is_none());
        }
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // The same state directory with good ids passes the checks.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("MODE", "apply");
    run.set("PLAN_STATE_DIR", &scratch.path().display().to_string());
    for ids in ["rot-1a2b3c4d", "rot-1a2b3c4d,rot-5e6f7a8b"] {
        run.set("CONFIRM", ids);
        let output = run.run("run.sh", &["--check-inputs"]);
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// SHA-338 T5 (AC5): no canary anywhere, the artifacts included
// ---------------------------------------------------------------------------

#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_t5_apply_leaks_no_secret_anywhere() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let pasted = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (plan, id, plan_output) = plan_job(&rec, &token, &secret).await;

    // Manual replacement mode, the pasted value from replacement-env, at
    // the highest verbosity.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_job(&plan, &id);
    run.set("OVERLAP", "0s");
    run.set("VERBOSE", "3");
    run.set("REPLACEMENT_ENV", "ROTATE_NEW_GH_TOKEN");
    run.set("ROTATE_NEW_GH_TOKEN", &pasted);
    run.scenario(apply_scenario(
        &secret,
        json!({ "providers": { "github": { "mode": "manual" } } }),
    ));
    let output = run.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    // The pasted value is checked first, then used: no create call.
    assert_eq!(
        rotation_steps(&run.calls().unwrap()),
        [
            "github.verify",
            "github-actions.update",
            "github.verify",
            "github.revoke",
        ]
    );

    let canaries = [
        Canary::new("leaked secret", &secret),
        Canary::new("pasted replacement", &pasted),
        Canary::new("alerts token", &token),
    ];
    // Every stream, the summary, GITHUB_OUTPUT and every file under the
    // runner temp and workspace of the apply job, which hold the state
    // artifact as downloaded and the audit artifact's directory.
    run.sweep(&output, &canaries);
    // And of the plan job, whose state-dir is the state artifact.
    plan.sweep(&plan_output, &canaries);
    let sweep = Sweep::new(&canaries);
    let artifacts = [
        PathBuf::from(&plan.outputs()["state-dir"]),
        run.path("runner_temp/rotate-plan-state"),
        PathBuf::from(&run.outputs()["state-dir"]).join(".rotate"),
    ];
    for dir in &artifacts {
        assert_no_hits(
            &format!("artifact {}", dir.display()),
            &sweep.scan_dir(dir, &[]),
        );
        assert!(
            std::fs::read_dir(dir).unwrap().next().is_some(),
            "{} is empty",
            dir.display()
        );
    }
    let names = assert_private_state(&run.state_dir());
    assert!(
        names.contains(&"audit.jsonl".to_owned()) && names.contains(&"state.json".to_owned()),
        "{names:?}"
    );

    // Automatic mode: the replacement rotate creates (the mock's value)
    // appears nowhere either.
    let secret = ghp_canary();
    let rec = CallRecorder::start().await;
    let (plan, id, plan_output) = plan_job(&rec, &token, &secret).await;
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_job(&plan, &id);
    run.set("OVERLAP", "0s");
    run.set("VERBOSE", "3");
    run.scenario(apply_scenario(&secret, json!({})));
    let output = run.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(
        rotation_steps(&run.calls().unwrap())[0],
        "github.create_replacement"
    );
    let canaries = [
        Canary::new("leaked secret", &secret),
        Canary::new("created replacement", MOCK_GITHUB_REPLACEMENT),
        Canary::new("alerts token", &token),
    ];
    run.sweep(&output, &canaries);
    plan.sweep(&plan_output, &canaries);
    let sweep = Sweep::new(&canaries);
    for dir in [
        run.path("runner_temp/rotate-plan-state"),
        run.state_dir().join(".rotate"),
    ] {
        assert_no_hits(
            &format!("artifact {}", dir.display()),
            &sweep.scan_dir(&dir, &[]),
        );
    }
}

/// The first replacement the mock `github` provider creates in a run
/// (`src/provider/mock.rs`: identify prefix, name, `-replacement-1`).
const MOCK_GITHUB_REPLACEMENT: &str = "ghp_github-replacement-1";

// ---------------------------------------------------------------------------
// SHA-338 review: rotate exits 0 without applying, fetch failures, an
// unknown id, the max-wait boundary, a probe config error, a recorded
// revoke time
// ---------------------------------------------------------------------------

/// The alert was resolved while the job waited for approval: rotate finds
/// nothing to apply and exits 0. The step must not report Done.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_exit_0_without_applying_is_not_done() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (plan, id, _) = plan_job(&rec, &token, &secret).await;

    // The apply job's alerts API: alert 42 is now resolved.
    let later = CallRecorder::start().await;
    let mut resolved = alert(42, "github_personal_access_token", Some(&secret));
    resolved["state"] = json!("resolved");
    resolved["resolution"] = json!("revoked");
    serve_alert(&later, &token, &resolved).await;
    serve_key_ids(&later, &token, json!([])).await;
    let mut run = ActionRun::new(&later.uri(), &token);
    run.apply_job(&plan, &id);
    run.set("OVERLAP", "0s");
    run.scenario(apply_scenario(&secret, json!({})));
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "::error title=rotate::The confirmed rotations {id} were not applied"
        )),
        "{stderr}"
    );
    assert_no_mutating(&run);
    let summary = run.summary();
    assert!(!summary.contains("**Done.**"), "{summary}");
    assert!(
        summary.contains(&format!(
            "**Not applied.** rotate apply exited 0 but did not apply `{id}`"
        )),
        "{summary}"
    );
    assert_eq!(run.outputs()["exit-code"], "2");
}

/// Apply-mode fetch failures: the second alert fails (the poison byte:
/// rotate refuses the whole input), or the first does (rotate apply never
/// starts). Exit 1, no provider or consumer call, and state-dir is set
/// for the audit upload all the same.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_fetch_failure_in_apply_calls_nothing() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (mut run, _) = apply_after_plan(&rec, &token, &secret, json!({})).await;
    Mock::given(method("GET"))
        .and(path(format!("{ALERTS_PATH}/43")))
        .respond_with(ResponseTemplate::new(404))
        .with_priority(1)
        .mount(rec.server())
        .await;

    run.set("ALERT_NUMBER", "42,43");
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("HTTP 404"), "{stderr}");
    // rotate apply read the input and refused it: no call at all.
    assert_eq!(run.calls().unwrap_or_default(), Vec::<Value>::new());
    assert_eq!(status_rows_or_none(&run), None);
    let outputs = run.outputs();
    assert_eq!(outputs["exit-code"], "1");
    assert_eq!(outputs["state-dir"], run.state_dir().display().to_string());
    assert!(run
        .output_before_rotate()
        .unwrap()
        .contains(&format!("state-dir={}\n", run.state_dir().display())));
    run.sweep(
        &output,
        &[
            Canary::new("alert secret", &secret),
            Canary::new("alerts token", &token),
        ],
    );

    // The first request fails: rotate apply is never started.
    let _ = std::fs::remove_file(run.call_log());
    run.set("ALERT_NUMBER", "43");
    let output = run.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
    assert!(run.calls().is_none(), "rotate apply ran");
    assert_eq!(
        run.outputs()["state-dir"],
        run.state_dir().display().to_string()
    );
}

fn status_rows_or_none(run: &ActionRun) -> Option<Vec<Value>> {
    let text = std::fs::read(run.path("runner_temp/rotate/status.json")).ok()?;
    Some(serde_json::from_slice(&text).unwrap())
}

/// A well-formed id that is not in the plan: rotate exits 2, nothing is
/// changed.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_unknown_confirmed_id_exits_2() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (mut run, id) = apply_after_plan(&rec, &token, &secret, json!({})).await;
    let unknown = if id == "rot-00000000" {
        "rot-11111111"
    } else {
        "rot-00000000"
    };
    run.set("CONFIRM", unknown);
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert_no_mutating(&run);
    let summary = run.summary();
    assert!(summary.contains("**Nothing was changed.**"), "{summary}");
    assert!(summary.contains("- error: "), "{summary}");
    assert!(!summary.contains("**Done.**"), "{summary}");
    assert_eq!(run.outputs()["exit-code"], "2");
}

/// A window equal to max-wait is waited out; one second more is not.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_max_wait_boundary() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    for (overlap, code, waits) in [("2s", 0, true), ("3s", 3, false)] {
        let secret = ghp_canary();
        let rec = CallRecorder::start().await;
        let (mut run, _) = apply_after_plan(&rec, &token, &secret, json!({})).await;
        run.set("OVERLAP", overlap);
        run.set("MAX_WAIT", "2s");
        let output = run.run("run.sh", &[]);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(code), "{overlap}: {stderr}");
        assert_eq!(stderr.contains("waiting until"), waits, "{stderr}");
        assert_eq!(
            stderr.contains(&format!(
                "The overlap window ({overlap}) is longer than max-wait (2s)"
            )),
            !waits,
            "{stderr}"
        );
        if !waits {
            assert_no_revoke(&run.calls().unwrap());
        }
    }
}

/// A bad rotate.yaml stops apply mode at the overlap probe: exit 2,
/// before any request, nothing changed.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_probe_config_error_stops_before_any_request() {
    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (mut run, _) = apply_after_plan(&rec, &token, &secret, json!({})).await;
    let planned = requests(&rec).await.len();
    run.set("OVERLAP", "");
    std::fs::write(run.path("work/rotate.yaml"), "overlap_window: soon\n").unwrap();
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("::error title=rotate::rotate apply did not start (exit 2)"),
        "{stderr}"
    );
    assert_eq!(
        requests(&rec).await.len(),
        planned,
        "the alerts were fetched"
    );
    assert!(run.calls().is_none(), "rotate apply ran");
    let summary = run.summary();
    assert!(summary.contains("**Nothing was changed.**"), "{summary}");
    assert!(summary.contains("invalid duration"), "{summary}");
    let outputs = run.outputs();
    assert_eq!(outputs["exit-code"], "2");
    assert_eq!(outputs["state-dir"], run.state_dir().display().to_string());
}

/// The state handed over already records a revoke time for the confirmed
/// rotation (an earlier apply exited 3). This run's window is 0s, but
/// rotate keeps the recorded time, so the step must not wait for it when
/// it is more than max-wait away.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha338_recorded_revoke_time_beyond_max_wait_is_not_waited_for() {
    use time::OffsetDateTime;

    if !tools_present() {
        return;
    }
    let secret = ghp_canary();
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let (mut first, id) = apply_after_plan(&rec, &token, &secret, json!({})).await;
    first.set("OVERLAP", "2h");
    first.set("MAX_WAIT", "1h");
    let output = first.run("run.sh", &[]);
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stderr));

    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_job(&first, &id);
    run.set("OVERLAP", "0s");
    run.set("MAX_WAIT", "1h");
    run.scenario(apply_scenario(&secret, json!({})));
    let started = OffsetDateTime::now_utc();
    let output = run.run("run.sh", &[]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        OffsetDateTime::now_utc() - started < time::Duration::minutes(1),
        "the step waited"
    );
    assert!(
        stderr.contains("revoke time recorded more than max-wait (1h) from now"),
        "{stderr}"
    );
    assert!(!stderr.contains("waiting until"), "{stderr}");
    assert_no_revoke(&run.calls().unwrap());
    assert_eq!(status_rows(&run)[0]["step"], "pending_revoke");
}
