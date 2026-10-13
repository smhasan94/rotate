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
//! SHA-389 (release attestations) adds `sha389_*`: `install.sh` with a
//! stand-in `gh` on a `PATH` the test controls, and the release workflow,
//! `scripts/verify-release.sh` and the README checked as text.
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
            // SHA-348: as action.yml passes it from the event of a private
            // repository, so upload-audit auto needs no API request.
            ("REPOSITORY_VISIBILITY", "private".into()),
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
/// and, when `ROTATE_RAN_MARKER` is set, writes that file: `token:set`
/// when it saw `GH_TOKEN`, else `token:` (SHA-389).
fn release_tarball(dir: &Path, version: &str) -> Vec<u8> {
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    let bin = stage.join("rotate");
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nif [ -n \"${{ROTATE_RAN_MARKER:-}}\" ]; then echo \"token:${{GH_TOKEN:+set}}\" > \"$ROTATE_RAN_MARKER\"; fi\necho \"rotate {version}\"\n"
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
        // SHA-348
        ("UPLOAD_AUDIT", "AUTO", "upload-audit"),
        ("AUDIT_SUFFIX", "a b", "audit-suffix"),
        ("AUDIT_SUFFIX", "x", "audit-suffix"),
        ("REPLACEMENT_ENV", "ROTATE_GITHUB_TOKEN", "replacement-env"),
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
        // SHA-348
        "audit-suffix",
        // SHA-389
        "verify-attestation",
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
    // failed, when run.sh decided so (SHA-348: upload-audit auto, true or
    // false); kept 30 days; the action is pinned to a full commit SHA.
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
        "steps.rotate.outputs.upload-audit == 'true'",
        "steps.rotate.outputs.state-dir != ''",
    ] {
        assert!(condition.contains(needle), "{condition}");
    }
    assert!(!condition.contains("inputs.upload-audit"), "{condition}");
    let with = &audit["with"];
    assert!(with["name"]
        .as_str()
        .unwrap()
        .starts_with("rotate-audit-${{ github.run_id }}"));
    assert!(with["path"].as_str().unwrap().ends_with("/.rotate/"));
    assert_eq!(with["retention-days"], 30);
    assert_eq!(with["include-hidden-files"], true);
    assert_eq!(action["inputs"]["upload-audit"]["default"], "auto");

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
/// nothing to apply. The confirmed id is only `planned` in the state file,
/// so rotate itself refuses it with exit 2 (SHA-348). The step must not
/// report Done.
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
        stderr
            .contains("error: a --confirm id is a rotation that is not finished in the state file"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "::error title=rotate::rotate apply exited with code 2; nothing was changed. \
             Not applied: {id}. See the job summary."
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("Nothing to apply."), "{stderr}");
    assert_no_mutating(&run);
    let summary = run.summary();
    assert!(!summary.contains("**Done.**"), "{summary}");
    assert!(summary.contains("**Nothing was changed.**"), "{summary}");
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
    // SHA-348: the annotation lists the confirmed ids not applied.
    assert!(
        stderr.contains(&format!("nothing was changed. Not applied: {unknown}.")),
        "{stderr}"
    );
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

// ---------------------------------------------------------------------------
// SHA-348: audit-suffix, upload-audit auto, replacement-env refusals
// ---------------------------------------------------------------------------

impl ActionRun {
    /// Mode apply with good confirm and state-dir inputs (a state directory
    /// in `scratch`), so only the input under test can be wrong.
    fn apply_inputs(&mut self, scratch: &Path) {
        std::fs::create_dir_all(scratch.join(".rotate")).unwrap();
        std::fs::write(scratch.join(".rotate/state.json"), "{}").unwrap();
        self.set("MODE", "apply");
        self.set("CONFIRM", "rot-1a2b3c4d");
        self.set("PLAN_STATE_DIR", &scratch.display().to_string());
    }
}

/// The step named `id` in action.yml.
fn action_step(action: &Value, id: &str) -> Value {
    action["runs"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("no step {id}"))
        .clone()
}

/// One line naming `input`, exit 2, the value never repeated, and neither
/// rotate nor any request run.
fn assert_bad_input(run: &ActionRun, output: &Output, input: &str, value: &str) {
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{value:?}: {stderr}");
    assert_eq!(stderr.lines().count(), 1, "{value:?}: {stderr}");
    assert!(
        stderr.starts_with(&format!("::error title=rotate::input {input}:")),
        "{value:?}: {stderr}"
    );
    if !value.is_empty() {
        assert!(!stderr.contains(value), "value echoed: {stderr}");
    }
    assert!(!stderr.contains("injected"), "value echoed: {stderr}");
    assert!(output.stdout.is_empty());
    assert!(run.calls().is_none(), "rotate ran for {value:?}");
    assert!(!run.outputs().contains_key("state-dir"), "{value:?}");
}

// SHA-348 T4 (AC4): audit-suffix is checked like every other input, is
// apply only, and names the artifact.
#[tokio::test(flavor = "multi_thread")]
async fn sha348_t4_audit_suffix_validated_and_names_the_artifact() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let scratch = tempfile::tempdir().unwrap();
    let longest = "a".repeat(40);
    for good in ["prod", "eu-west-1", "job_2.retry", longest.as_str()] {
        let mut run = ActionRun::new(&rec.uri(), &token);
        run.apply_inputs(scratch.path());
        run.set("AUDIT_SUFFIX", good);
        let output = run.run("run.sh", &["--check-inputs"]);
        assert_eq!(output.status.code(), Some(0), "{good}: {:?}", output);
        assert!(output.stderr.is_empty(), "{good}");
    }
    let too_long = "a".repeat(41);
    for bad in [
        too_long.as_str(),
        "a b",
        "a/b",
        "../x",
        "a:b",
        "$(id)",
        "é",
        "prod\n::warning::injected",
        "prod\r",
    ] {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.apply_inputs(scratch.path());
            run.set("AUDIT_SUFFIX", bad);
            let output = run.run("run.sh", args);
            assert_bad_input(&run, &output, "audit-suffix", bad);
        }
    }
    // Plan mode refuses it, even when well formed.
    for args in [&[][..], &["--check-inputs"][..]] {
        let mut run = ActionRun::new(&rec.uri(), &token);
        run.set("AUDIT_SUFFIX", "prod");
        let output = run.run("run.sh", args);
        assert_bad_input(&run, &output, "audit-suffix", "");
        assert!(text(&output.stderr).contains("only with mode: apply"));
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // action.yml: the input, both steps get it through env:, and the
    // artifact is rotate-audit-<run id>-<attempt>[-<suffix>].
    let action = action_yml();
    assert_eq!(action["inputs"]["audit-suffix"]["default"], "");
    for id in ["inputs", "rotate"] {
        assert_eq!(
            action_step(&action, id)["env"]["AUDIT_SUFFIX"],
            "${{ inputs.audit-suffix }}",
            "{id}"
        );
    }
    assert_eq!(
        action_step(&action, "audit")["with"]["name"],
        "rotate-audit-${{ github.run_id }}-${{ github.run_attempt }}\
         ${{ inputs.audit-suffix != '' && format('-{0}', inputs.audit-suffix) || '' }}"
    );
}

/// `run.sh --upload-decision` in apply mode against `api`, with
/// `visibility` as the event's and `upload` as the input (`None`: unset).
/// Returns the run, its output and the upload-audit output.
fn upload_decision(
    api: &str,
    token: &str,
    scratch: &Path,
    visibility: &str,
    upload: Option<&str>,
) -> (ActionRun, Output, String) {
    let mut run = ActionRun::new(api, token);
    run.apply_inputs(scratch);
    run.set("REPOSITORY_VISIBILITY", visibility);
    if let Some(upload) = upload {
        run.set("UPLOAD_AUDIT", upload);
    }
    let output = run.run("run.sh", &["--upload-decision"]);
    assert_eq!(output.status.code(), Some(0), "{:?}", output);
    assert!(output.stdout.is_empty());
    assert!(run.calls().is_none(), "rotate ran");
    let decision = run
        .outputs()
        .get("upload-audit")
        .cloned()
        .expect("no upload-audit output");
    (run, output, decision)
}

/// Serves `GET /repos/acme/api` (the run's repository) with `body`, only to
/// the alerts token.
async fn serve_repository(rec: &CallRecorder, token: &str, body: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path("/repos/acme/api"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(body)
        .with_priority(1)
        .mount(rec.server())
        .await;
}

// SHA-348 T5 (AC5): auto uploads to a private or internal repository and
// not to a public or unknown one; true and false are taken as given.
#[tokio::test(flavor = "multi_thread")]
async fn sha348_t5_upload_decision_fails_closed() {
    if !tools_present() {
        return;
    }
    // Many awaits, then a MockServer drop, also on a failed assert: run
    // outside the coop budget so a failure fails instead of hanging.
    crate::common::without_coop_budget(upload_decision_cases()).await;
}

async fn upload_decision_cases() {
    let token = token_canary();
    let scratch = tempfile::tempdir().unwrap();
    // One server for the whole test, reset between cases.
    let rec = CallRecorder::start().await;
    let public_notice = "::notice title=rotate::The audit artifact will not be uploaded: \
                         the repository is public";
    let unknown_notice = "::notice title=rotate::The audit artifact will not be uploaded: \
                          the repository's visibility could not be read";

    // The event's visibility decides, with no request; auto is the default.
    for upload in [None, Some("auto")] {
        for (visibility, want) in [
            ("private", "true"),
            ("internal", "true"),
            ("public", "false"),
        ] {
            rec.server().reset().await;
            let (_, output, decision) =
                upload_decision(&rec.uri(), &token, scratch.path(), visibility, upload);
            assert_eq!(decision, want, "{visibility} {upload:?}");
            let stderr = text(&output.stderr);
            if want == "true" {
                assert!(stderr.is_empty(), "{stderr}");
            } else {
                assert_eq!(stderr.lines().count(), 1, "{stderr}");
                assert!(stderr.starts_with(public_notice), "{stderr}");
            }
            assert_eq!(requests(&rec).await, Vec::<String>::new());
        }
    }

    // No event visibility (a schedule run), or one that is not a known
    // value: the API decides; what it cannot answer is treated as public.
    let cases: Vec<(ResponseTemplate, &str, Option<&str>)> = vec![
        (
            ResponseTemplate::new(200).set_body_json(json!({ "visibility": "private" })),
            "true",
            None,
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!({ "visibility": "internal" })),
            "true",
            None,
        ),
        (
            ResponseTemplate::new(200)
                .set_body_json(json!({ "visibility": "public", "private": false })),
            "false",
            Some(public_notice),
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!({ "private": true })),
            "true",
            None,
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!({ "visibility": "secret" })),
            "false",
            Some(unknown_notice),
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!({ "name": "api" })),
            "false",
            Some(unknown_notice),
        ),
        (
            ResponseTemplate::new(200).set_body_string("not json"),
            "false",
            Some(unknown_notice),
        ),
        (ResponseTemplate::new(404), "false", Some(unknown_notice)),
        (ResponseTemplate::new(403), "false", Some(unknown_notice)),
        (ResponseTemplate::new(500), "false", Some(unknown_notice)),
    ];
    for (body, want, notice) in cases {
        for visibility in ["", "Public", "\n::warning::injected"] {
            rec.server().reset().await;
            serve_repository(&rec, &token, body.clone()).await;
            let (run, output, decision) =
                upload_decision(&rec.uri(), &token, scratch.path(), visibility, None);
            assert_eq!(decision, want, "{visibility:?} {body:?}");
            let stderr = text(&output.stderr);
            match notice {
                None => assert!(stderr.is_empty(), "{stderr}"),
                Some(notice) => {
                    assert_eq!(stderr.lines().count(), 1, "{stderr}");
                    assert!(stderr.starts_with(notice), "{stderr}");
                }
            }
            assert!(!stderr.contains("injected"), "{stderr}");
            assert_eq!(requests(&rec).await, ["GET /repos/acme/api"]);
            run.sweep(&output, &[Canary::new("alerts token", &token)]);
        }
    }

    // The API is unreachable, or answers only another token.
    rec.server().reset().await;
    serve_repository(
        &rec,
        "ghs_another_token",
        ResponseTemplate::new(200).set_body_json(json!({ "visibility": "private" })),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/api"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(2)
        .mount(rec.server())
        .await;
    for api in [rec.uri(), "http://127.0.0.1:1".to_owned()] {
        let (_, output, decision) = upload_decision(&api, &token, scratch.path(), "", None);
        assert_eq!(decision, "false", "{api}");
        assert!(text(&output.stderr).starts_with(unknown_notice));
    }

    // The lookup is for the run's repository (GITHUB_REPOSITORY), and a
    // value that is not owner/repo, or has a `.` or `..` segment, is not
    // requested at all: unknown, no upload.
    for repo in [
        "acme/..",
        "../api",
        "./api",
        "acme/.",
        "acme",
        "acme/api/x",
        "",
    ] {
        rec.server().reset().await;
        serve_repository(
            &rec,
            &token,
            ResponseTemplate::new(200).set_body_json(json!({ "visibility": "private" })),
        )
        .await;
        let mut run = ActionRun::new(&rec.uri(), &token);
        run.apply_inputs(scratch.path());
        run.set("REPOSITORY_VISIBILITY", "");
        run.set("GITHUB_REPOSITORY", repo);
        let output = run.run("run.sh", &["--upload-decision"]);
        assert_eq!(output.status.code(), Some(0), "{repo}: {output:?}");
        assert_eq!(run.outputs()["upload-audit"], "false", "{repo}");
        assert!(text(&output.stderr).starts_with(unknown_notice), "{repo}");
        assert_eq!(requests(&rec).await, Vec::<String>::new(), "{repo}");
    }

    // Explicit true and false are taken as given, with no request.
    for (upload, visibility) in [
        ("true", "public"),
        ("true", ""),
        ("false", "private"),
        ("false", ""),
    ] {
        rec.server().reset().await;
        let (_, output, decision) =
            upload_decision(&rec.uri(), &token, scratch.path(), visibility, Some(upload));
        assert_eq!(decision, upload, "{visibility:?}");
        assert!(output.stderr.is_empty(), "{:?}", text(&output.stderr));
        assert_eq!(requests(&rec).await, Vec::<String>::new());
    }

    // Any other value is a bad input, before any request.
    rec.server().reset().await;
    for bad in ["yes", "AUTO", "1", "true\n::warning::injected"] {
        for args in [&["--upload-decision"][..], &["--check-inputs"][..], &[][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.apply_inputs(scratch.path());
            run.set("UPLOAD_AUDIT", bad);
            let output = run.run("run.sh", args);
            assert_bad_input(&run, &output, "upload-audit", bad);
        }
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // action.yml: the default, the event's visibility through env: (never
    // in run: text), and the upload step reads run.sh's decision.
    let action = action_yml();
    assert_eq!(action["inputs"]["upload-audit"]["default"], "auto");
    let rotate = action_step(&action, "rotate");
    assert_eq!(
        rotate["env"]["REPOSITORY_VISIBILITY"],
        "${{ github.event.repository.visibility }}"
    );
    assert_eq!(rotate["env"]["UPLOAD_AUDIT"], "${{ inputs.upload-audit }}");
    let condition = action_step(&action, "audit")["if"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        condition.contains("steps.rotate.outputs.upload-audit == 'true'"),
        "{condition}"
    );
}

// SHA-348 T5 (AC5): in a full apply step the decision is an output before
// rotate first runs, so the upload step has it even if the step is killed.
#[cfg(feature = "test-providers")]
#[tokio::test(flavor = "multi_thread")]
async fn sha348_t5_apply_step_decides_upload_before_rotate_runs() {
    if !tools_present() {
        return;
    }
    // A MockServer dropped each round: see common::without_coop_budget.
    crate::common::without_coop_budget(apply_step_upload_cases()).await;
}

#[cfg(feature = "test-providers")]
async fn apply_step_upload_cases() {
    let secret = ghp_canary();
    let token = token_canary();
    for (visibility, want) in [("private", "true"), ("public", "false")] {
        let rec = CallRecorder::start().await;
        let (mut run, _) = apply_after_plan(&rec, &token, &secret, json!({})).await;
        run.set("REPOSITORY_VISIBILITY", visibility);
        let output = run.run("run.sh", &[]);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stderr}");
        assert!(run
            .output_before_rotate()
            .unwrap()
            .contains(&format!("upload-audit={want}\n")));
        assert_eq!(run.outputs()["upload-audit"], want);
        assert_eq!(
            stderr.contains("::notice title=rotate::The audit artifact will not be uploaded"),
            want == "false",
            "{stderr}"
        );
    }
}

// SHA-348 T6 (AC6): replacement-env naming a credential, a runner
// variable or not a name exits 2 before any download or request, and
// never repeats the name.
#[tokio::test(flavor = "multi_thread")]
async fn sha348_t6_replacement_env_refused_before_any_request() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let scratch = tempfile::tempdir().unwrap();
    let sentinel = "npm_action_sha348_sentinel_value";
    let mut names: Vec<&str> = rotate::input::DENIED_REPLACEMENT_VARS.to_vec();
    names.extend([
        "ALERTS_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "RUNNER_TEMP",
        "RUNNER_TOOL_CACHE",
    ]);
    for name in names {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.apply_inputs(scratch.path());
            run.set("REPLACEMENT_ENV", name);
            if name != "ALERTS_TOKEN" && name != "RUNNER_TEMP" {
                run.set(name, sentinel);
            }
            let output = run.run("run.sh", args);
            assert_bad_input(&run, &output, "replacement-env", name);
            let stderr = text(&output.stderr);
            assert!(stderr.contains("such as NEW_TOKEN"), "{stderr}");
            assert!(!stderr.contains(sentinel), "{stderr}");
            assert!(!stderr.contains(&token), "{stderr}");
        }
    }
    for bad in [
        "NEW-TOKEN",
        "1NEW",
        "npm-action-sha348-pasted-value",
        "NEW TOKEN",
        "NEW_TOKEN\n::warning::injected",
    ] {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.apply_inputs(scratch.path());
            run.set("REPLACEMENT_ENV", bad);
            let output = run.run("run.sh", args);
            assert_bad_input(&run, &output, "replacement-env", bad);
        }
    }
    // install.sh never ran: the inputs step stops the job first; and
    // run.sh made no request of its own.
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // A name of the operator's own passes.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.apply_inputs(scratch.path());
    for good in [
        "NEW_TOKEN",
        "ROTATE_REPLACEMENT",
        "MY_GITHUB_TOKEN",
        "github_token",
    ] {
        run.set("REPLACEMENT_ENV", good);
        let output = run.run("run.sh", &["--check-inputs"]);
        assert_eq!(output.status.code(), Some(0), "{good}: {output:?}");
    }
    let action = action_yml();
    let ids: Vec<String> = action["runs"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids[..2], ["inputs", "install"]);
    assert_eq!(
        action_step(&action, "inputs")["env"]["REPLACEMENT_ENV"],
        "${{ inputs.replacement-env }}"
    );
}

// ---------------------------------------------------------------------------
// SHA-389: build provenance, checked on install
// ---------------------------------------------------------------------------

/// The first release with attestations.
const ATTESTED: &str = "0.4.0";
const SIGNER_WORKFLOW: &str = "smhasan94/rotate/.github/workflows/release.yml";

/// The certificate identity a release's attestation must carry.
fn cert_identity(version: &str) -> String {
    format!("https://github.com/{SIGNER_WORKFLOW}@refs/tags/v{version}")
}

/// What `install.sh` runs, `gh` aside. Each is linked into a directory of
/// its own so a test decides whether `gh` is on `PATH`.
const INSTALL_TOOLS: &str = "bash sh curl tar gzip uname mktemp rm mkdir sed grep install \
sha256sum shasum perl cat cut tr head env dirname chmod sleep";

/// An install run of `version` against a release on `rec` with a good
/// `SHA256SUMS` (or `sums`), `GH_TOKEN` set to `token`, no wait between
/// attestation retries, and `PATH` holding only the tools above: no `gh`
/// until `stub_gh` adds one.
struct Install {
    run: ActionRun,
    name: String,
}

impl Install {
    async fn new(rec: &CallRecorder, token: &str, version: &str, sums: Option<&str>) -> Self {
        let name = format!("rotate-{version}-{}.tar.gz", target());
        let scratch = tempfile::tempdir().unwrap();
        let tarball = release_tarball(scratch.path(), version);
        let sums = match sums {
            Some(sums) => sums.to_owned(),
            None => format!("{}  {name}\n", hex(&Sha256::digest(&tarball))),
        };
        let base = format!("/download/v{version}");
        Mock::given(method("GET"))
            .and(path(format!("{base}/{name}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
            .with_priority(1)
            .mount(rec.server())
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/SHA256SUMS")))
            .respond_with(ResponseTemplate::new(200).set_body_string(sums))
            .with_priority(1)
            .mount(rec.server())
            .await;
        let mut run = ActionRun::new(&rec.uri(), token);
        run.set("ROTATE_VERSION", version);
        run.set("ROTATE_BINARY", "");
        run.set("ROTATE_RELEASE_BASE", &format!("{}{base}", rec.uri()));
        run.set("GH_TOKEN", token);
        run.set("ROTATE_ATTEST_BACKOFF", "0 0");
        let marker = run.path("ran");
        run.set("ROTATE_RAN_MARKER", &marker.display().to_string());
        let bin = run.path("inputs/bin");
        std::fs::create_dir(&bin).unwrap();
        let path = std::env::var_os("PATH").unwrap_or_default();
        for tool in INSTALL_TOOLS.split_whitespace() {
            if let Some(found) = std::env::split_paths(&path)
                .map(|dir| dir.join(tool))
                .find(|p| p.is_file())
            {
                std::os::unix::fs::symlink(found, bin.join(tool)).unwrap();
            }
        }
        run.set("PATH", &bin.display().to_string());
        Self { run, name }
    }

    /// Puts a stand-in `gh` on `PATH`. `gh attestation verify --help`
    /// prints the flags `install.sh` needs (without
    /// `--deny-self-hosted-runners` when `old`); `gh attestation verify
    /// <file> ...` exits `code`. Every call appends its argv, whether
    /// `GH_TOKEN` was set and `GH_HOST` to `gh.log`.
    fn stub_gh(&self, code: i32, old: bool) {
        self.stub_gh_failing_first(code, old, 0);
    }

    /// `stub_gh`, but the first `fails` verify calls exit 1.
    fn stub_gh_failing_first(&self, code: i32, old: bool, fails: u32) {
        let flags = if old {
            "--repo --cert-identity"
        } else {
            "--repo --cert-identity --deny-self-hosted-runners"
        };
        let counter = self.run.path("inputs/gh.fails");
        std::fs::write(&counter, fails.to_string()).unwrap();
        let script = format!(
            r#"#!/bin/sh
{{
  printf 'argv:'
  for arg in "$@"; do printf ' %s' "$arg"; done
  printf '\ntoken:%s host:%s\n' "${{GH_TOKEN:+set}}" "${{GH_HOST:-}}"
}} >> '{log}'
case " $* " in
  *" --help "*) echo "{flags}"; exit 0 ;;
esac
[ -f "$3" ] || {{ echo "stub gh: no file $3" >&2; exit 3; }}
fails=$(cat '{counter}')
if [ "$fails" -gt 0 ]; then
  echo $((fails - 1)) > '{counter}'
  echo "stub gh: transient failure" >&2
  exit 1
fi
echo "stub gh: exit {code}" >&2
exit {code}
"#,
            log = self.gh_log().display(),
            counter = counter.display(),
        );
        let gh = self.run.path("inputs/bin/gh");
        std::fs::write(&gh, script).unwrap();
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn gh_log(&self) -> PathBuf {
        self.run.path("inputs/gh.log")
    }

    /// The stand-in's log; `None` when `gh` was never called.
    fn gh_calls(&self) -> Option<String> {
        std::fs::read_to_string(self.gh_log()).ok()
    }

    fn install(&self) -> Output {
        self.run.run("install.sh", &[])
    }

    fn marker(&self) -> Option<String> {
        std::fs::read_to_string(self.run.path("ran")).ok()
    }

    /// `token` (the `GH_TOKEN` canary) nowhere in the streams or the files.
    fn sweep(&self, output: &Output, token: &str) {
        self.run.sweep(output, &[Canary::new("GH_TOKEN", token)]);
    }

    /// Installed: exit 0, the binary under `$RUNNER_TEMP/rotate/bin`, run,
    /// and without `GH_TOKEN` in its environment.
    fn assert_installed(&self, output: &Output) {
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{stderr}");
        assert!(text(&output.stdout).contains("checksum ok"));
        let bin = self.run.path("runner_temp/rotate/bin/rotate");
        assert_eq!(self.run.outputs()["path"], bin.display().to_string());
        assert_eq!(binaries_under(&self.run.path("runner_temp")), vec![bin]);
        assert_eq!(self.marker().as_deref(), Some("token:\n"));
    }

    /// Nothing installed or run, and no download left behind.
    fn assert_nothing_installed(&self) {
        assert_eq!(self.marker(), None, "the binary ran");
        assert!(!self.run.outputs().contains_key("path"));
        let mut files = Vec::new();
        let mut dirs = vec![self.run.path("runner_temp")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files.push(path);
                }
            }
        }
        assert_eq!(files, Vec::<PathBuf>::new(), "left behind");
    }
}

/// The `::notice` line of an install, if any (never more than one).
fn notice(output: &Output) -> Option<String> {
    let stderr = text(&output.stderr);
    let notices: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("::notice"))
        .collect();
    assert!(notices.len() <= 1, "{stderr}");
    notices.first().map(|l| (*l).to_owned())
}

/// The `argv:` lines of the stand-in `gh`'s log.
fn gh_argv(calls: &str) -> Vec<&str> {
    calls.lines().filter(|l| l.starts_with("argv:")).collect()
}

// T1 (AC4): auto (or true), an attested release and gh present: gh
// verifies the download after the checksum; a failed check installs and
// runs nothing. The token reaches gh through its environment only, and the
// installed binary never sees it.
#[tokio::test(flavor = "multi_thread")]
async fn sha389_t1_auto_verifies_after_the_checksum() {
    if !tools_present() {
        return;
    }
    for (mode, code) in [("auto", 0), ("", 0), ("true", 0), ("auto", 1), ("true", 1)] {
        let token = token_canary();
        let rec = CallRecorder::start().await;
        let mut install = Install::new(&rec, &token, ATTESTED, None).await;
        install.stub_gh(code, false);
        install.run.set("ROTATE_VERIFY_ATTESTATION", mode);
        let output = install.install();
        let stderr = text(&output.stderr);
        let stdout = text(&output.stdout);
        let calls = install.gh_calls().expect("gh was not called");
        let argv = gh_argv(&calls);
        // One try, or three when every try fails.
        let tries = if code == 0 { 1 } else { 3 };
        assert_eq!(argv.len(), 1 + tries, "{calls}");
        assert_eq!(argv[0], "argv: attestation verify --help");
        assert!(argv[1..].iter().all(|l| *l == argv[1]), "{calls}");
        let args: Vec<&str> = argv[1].split(' ').collect();
        assert_eq!(args[1..3], ["attestation", "verify"], "{calls}");
        let download = install.run.path("runner_temp/rotate");
        assert!(
            args[3].starts_with(&format!("{}/download.", download.display())),
            "{calls}"
        );
        assert!(args[3].ends_with(&format!("/{}", install.name)), "{calls}");
        let identity = cert_identity(ATTESTED);
        for (flag, value) in [
            ("--repo", "smhasan94/rotate"),
            ("--cert-identity", identity.as_str()),
        ] {
            let at = args.iter().position(|a| *a == flag).expect(flag);
            assert_eq!(args[at + 1], value, "{calls}");
        }
        assert!(args.contains(&"--deny-self-hosted-runners"), "{calls}");
        assert_eq!(args.len(), 9, "{calls}");
        // The verify call had the token and the host in its environment.
        let env = calls.lines().skip_while(|l| *l != argv[1]).nth(1);
        assert_eq!(env, Some("token:set host:github.com"), "{calls}");
        assert!(!calls.contains(&token), "token in gh's argv: {calls}");
        assert_eq!(notice(&output), None, "{stderr}");
        if code == 0 {
            install.assert_installed(&output);
            assert!(
                stdout.contains(&format!("attestation ok: {}", install.name)),
                "{stdout}"
            );
        } else {
            assert_eq!(stdout.matches("; retrying in 0s").count(), 2, "{stdout}");
            assert_eq!(output.status.code(), Some(1), "{stderr}");
            assert_eq!(stderr.lines().count(), 1, "{stderr}");
            assert!(
                stderr.contains(&format!(
                    "attestation check failed for {}; nothing was installed",
                    install.name
                )),
                "{stderr}"
            );
            // gh's own output reaches the log, on stdout.
            assert!(stdout.contains("stub gh: exit 1"), "{stdout}");
            install.assert_nothing_installed();
        }
        install.sweep(&output, &token);
    }

    // The checksum comes first: a mismatch stops before gh verifies.
    let token = token_canary();
    let rec = CallRecorder::start().await;
    let name = format!("rotate-{ATTESTED}-{}.tar.gz", target());
    let wrong = format!("{}  {name}\n", hex(&Sha256::digest(b"tampered")));
    let mut install = Install::new(&rec, &token, ATTESTED, Some(&wrong)).await;
    install.stub_gh(0, false);
    install.run.set("ROTATE_VERIFY_ATTESTATION", "true");
    let output = install.install();
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("checksum mismatch"), "{stderr}");
    let calls = install.gh_calls().unwrap_or_default();
    assert_eq!(
        gh_argv(&calls),
        ["argv: attestation verify --help"],
        "{calls}"
    );
    install.assert_nothing_installed();
}

// A transient failure (the attestations API or Sigstore's TUF CDN) is
// retried: a gh that fails once and then succeeds still installs, after
// waiting the backoff (ROTATE_ATTEST_BACKOFF).
#[tokio::test(flavor = "multi_thread")]
async fn sha389_attestation_check_retries_a_transient_failure() {
    if !tools_present() {
        return;
    }
    for fails in [1, 2] {
        let token = token_canary();
        let rec = CallRecorder::start().await;
        let mut install = Install::new(&rec, &token, ATTESTED, None).await;
        install.stub_gh_failing_first(0, false, fails);
        install.run.set("ROTATE_VERIFY_ATTESTATION", "auto");
        install.run.set("ROTATE_ATTEST_BACKOFF", "1 0");
        let started = std::time::Instant::now();
        let output = install.install();
        let stdout = text(&output.stdout);
        install.assert_installed(&output);
        assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
        let calls = install.gh_calls().unwrap();
        assert_eq!(gh_argv(&calls).len(), 2 + fails as usize, "{calls}");
        assert!(stdout.contains("stub gh: transient failure"), "{stdout}");
        assert!(stdout.contains("; retrying in 1s"), "{stdout}");
        assert!(started.elapsed() >= std::time::Duration::from_secs(1));
        assert!(stdout.contains(&format!("attestation ok: {}", install.name)));
        install.sweep(&output, &token);
    }
}

/// (version, stand-in gh: `None`, or `Some(old)`, GITHUB_SERVER_URL,
/// GH_TOKEN set, the reason the attestation cannot be checked).
const UNCHECKABLE: &[(&str, Option<bool>, &str, bool, &str)] = &[
    (
        ATTESTED,
        None,
        "https://github.com",
        true,
        "gh is not installed",
    ),
    (
        "0.3.0",
        Some(false),
        "https://github.com",
        true,
        "before 0.4.0",
    ),
    ("0.1.0", None, "https://github.com", true, "before 0.4.0"),
    (
        ATTESTED,
        Some(false),
        "https://ghes.example.com",
        true,
        "not on github.com",
    ),
    (
        ATTESTED,
        Some(true),
        "https://github.com",
        true,
        "update gh",
    ),
    (
        ATTESTED,
        Some(false),
        "https://github.com",
        false,
        "GH_TOKEN is empty",
    ),
];

// T2 (AC5): auto when the attestation cannot be checked: a notice says so
// and why, and the release installs on its checksum. gh is never asked to
// verify, and not asked at all for a release without attestations or off
// github.com.
#[tokio::test(flavor = "multi_thread")]
async fn sha389_t2_auto_without_gh_or_attestation_notices_and_installs() {
    if !tools_present() {
        return;
    }
    for (version, gh, server, has_token, reason) in UNCHECKABLE {
        let token = token_canary();
        let rec = CallRecorder::start().await;
        let mut install = Install::new(&rec, &token, version, None).await;
        if let Some(old) = gh {
            install.stub_gh(0, *old);
        }
        if !has_token {
            install.run.set("GH_TOKEN", "");
        }
        install.run.set("GITHUB_SERVER_URL", server);
        install.run.set("ROTATE_VERIFY_ATTESTATION", "auto");
        let output = install.install();
        let stderr = text(&output.stderr);
        install.assert_installed(&output);
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        let notice = notice(&output).unwrap_or_else(|| panic!("{version}: no notice: {stderr}"));
        assert!(
            notice.contains(&format!("attestation of {} was not checked", install.name)),
            "{notice}"
        );
        assert!(notice.contains(reason), "{version}: {notice}");
        assert!(notice.contains("SHA256SUMS"), "{notice}");
        let calls = install.gh_calls();
        if reason.contains("gh") {
            let calls = calls.unwrap_or_default();
            assert!(
                gh_argv(&calls)
                    .iter()
                    .all(|l| *l == "argv: attestation verify --help"),
                "{calls}"
            );
        } else {
            assert_eq!(calls, None, "{version}: gh was called");
        }
        install.sweep(&output, &token);
    }
}

// T3 (AC6): true when the attestation cannot be checked exits 2 before
// anything is downloaded; false never asks gh and says nothing.
#[tokio::test(flavor = "multi_thread")]
async fn sha389_t3_true_refuses_and_false_skips() {
    if !tools_present() {
        return;
    }
    for (version, gh, server, has_token, reason) in UNCHECKABLE {
        let token = token_canary();
        let rec = CallRecorder::start().await;
        let mut install = Install::new(&rec, &token, version, None).await;
        if let Some(old) = gh {
            install.stub_gh(0, *old);
        }
        if !has_token {
            install.run.set("GH_TOKEN", "");
        }
        install.run.set("GITHUB_SERVER_URL", server);
        install.run.set("ROTATE_VERIFY_ATTESTATION", "true");
        let output = install.install();
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{version}: {stderr}");
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(
            stderr.starts_with("::error title=rotate install::input verify-attestation:"),
            "{stderr}"
        );
        assert!(stderr.contains(reason), "{version}: {stderr}");
        assert_eq!(requests(&rec).await, Vec::<String>::new(), "{version}");
        install.assert_nothing_installed();
        if !reason.contains("gh") {
            assert_eq!(install.gh_calls(), None, "{version}: gh was called");
        }
    }

    // false: no gh call, no notice, installed on the checksum.
    for (version, gh) in [(ATTESTED, true), (ATTESTED, false), ("0.3.0", true)] {
        let token = token_canary();
        let rec = CallRecorder::start().await;
        let mut install = Install::new(&rec, &token, version, None).await;
        if gh {
            install.stub_gh(0, false);
        }
        install.run.set("ROTATE_VERIFY_ATTESTATION", "false");
        let output = install.install();
        install.assert_installed(&output);
        assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
        assert_eq!(install.gh_calls(), None, "{version}: gh was called");
    }
}

// The version gate (decision 3): a release is attested when its version
// without the pre-release suffix is above 0.3.0, with no API request. Told
// apart by the reason `true` gives with no gh on PATH. A component of more
// than 9 digits is not a version (it would overflow the arithmetic).
#[tokio::test(flavor = "multi_thread")]
async fn sha389_version_gate() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    // Some(attested), or None: refused as input version.
    for (version, attested) in [
        ("0.0.1", Some(false)),
        ("0.2.9", Some(false)),
        ("0.3.0", Some(false)),
        ("0.3.0-rc.1", Some(false)),
        ("00.03.00", Some(false)),
        ("000000000.000000003.000000000", Some(false)),
        ("0.3.1", Some(true)),
        ("0.3.10", Some(true)),
        ("0.4.0-rc.1", Some(true)),
        ("0.4.0", Some(true)),
        ("0.10.0", Some(true)),
        ("0.08.0", Some(true)),
        ("1.0.0", Some(true)),
        ("1.0.0-alpha", Some(true)),
        ("999999999.999999999.999999999", Some(true)),
        ("1234567890.0.0", None),
        ("0.1234567890.0", None),
        ("0.0.1234567890", None),
        ("18446744073709551616.0.0", None),
        ("0.3.00000000000000000001", None),
    ] {
        let mut install = Install::new(&rec, &token, version, None).await;
        install.run.set("ROTATE_VERIFY_ATTESTATION", "true");
        let output = install.install();
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{version}: {stderr}");
        assert_eq!(stderr.lines().count(), 1, "{version}: {stderr}");
        let want = match attested {
            Some(true) => "gh is not installed",
            Some(false) => "before 0.4.0",
            None => "input version: expected a release version",
        };
        assert!(stderr.contains(want), "{version}: {stderr}");
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());
}

// T4 (AC7): a bad verify-attestation exits 2 with one line naming the
// input, in the inputs step and in install.sh, before any request.
#[tokio::test(flavor = "multi_thread")]
async fn sha389_t4_bad_verify_attestation_exits_2_before_any_request() {
    if !tools_present() {
        return;
    }
    let token = token_canary();
    let rec = CallRecorder::start().await;
    for bad in ["maybe", "AUTO", "TRUE", "1", "auto\n::warning::injected"] {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.set("VERIFY_ATTESTATION", bad);
            let output = run.run("run.sh", args);
            assert_bad_input(&run, &output, "verify-attestation", bad);
            assert!(text(&output.stderr).contains("must be auto, true or false"));
        }
        let mut install = Install::new(&rec, &token, ATTESTED, None).await;
        install.stub_gh(0, false);
        install.run.set("ROTATE_VERIFY_ATTESTATION", bad);
        let output = install.install();
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{bad:?}: {stderr}");
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(
            stderr.starts_with(
                "::error title=rotate install::input verify-attestation: must be auto, true or false"
            ),
            "{stderr}"
        );
        assert!(!stderr.contains("injected") && !stderr.contains("maybe"));
        assert_eq!(install.gh_calls(), None);
        install.assert_nothing_installed();
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());
    for good in ["auto", "true", "false", ""] {
        let mut run = ActionRun::new(&rec.uri(), &token);
        run.set("VERIFY_ATTESTATION", good);
        let output = run.run("run.sh", &["--check-inputs"]);
        assert_eq!(output.status.code(), Some(0), "{good}: {output:?}");
    }

    // action.yml: the input, checked by the inputs step and used by the
    // install step, with the workflow token in env: and nothing in run:.
    let action = action_yml();
    assert_eq!(action["inputs"]["verify-attestation"]["default"], "auto");
    assert_eq!(
        action_step(&action, "inputs")["env"]["VERIFY_ATTESTATION"],
        "${{ inputs.verify-attestation }}"
    );
    let install = action_step(&action, "install");
    assert_eq!(
        install["env"]["ROTATE_VERIFY_ATTESTATION"],
        "${{ inputs.verify-attestation }}"
    );
    assert_eq!(install["env"]["GH_TOKEN"], "${{ github.token }}");
    assert!(!install["run"].as_str().unwrap().contains("${{"));
}

fn release_workflow() -> Value {
    serde_norway::from_str(&read(".github/workflows/release.yml")).unwrap()
}

/// A job's `needs`, as a list.
fn needs(job: &Value) -> Vec<String> {
    match &job["needs"] {
        Value::String(one) => vec![one.clone()],
        Value::Array(many) => many
            .iter()
            .map(|n| n.as_str().unwrap().to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

// T5 (AC1, AC2): the attest job runs on tag pushes only, after the
// checksums and before publish, pins every action it uses by commit SHA,
// and is the only job that can mint an OIDC token or write attestations.
// The jobs that verify may read them.
#[test]
fn sha389_t5_release_workflow_attests_on_tags_only() {
    let workflow = release_workflow();
    let text = read(".github/workflows/release.yml");
    // Pull requests run the workflow, so the job's condition matters.
    assert!(!workflow["on"]["pull_request"].is_null());
    let jobs = workflow["jobs"].as_object().unwrap();
    let attest = &jobs["attest"];
    let condition = attest["if"].as_str().unwrap();
    assert!(
        condition.contains("github.event_name == 'push'")
            && condition.contains("github.ref_type == 'tag'"),
        "{condition}"
    );
    assert!(!condition.contains("||"), "{condition}");
    assert!(needs(attest).contains(&"checksums".to_owned()));
    assert!(needs(&jobs["publish"]).contains(&"attest".to_owned()));

    // Every action the job uses is pinned by commit SHA, with a version
    // comment.
    let steps = attest["steps"].as_array().unwrap();
    let all_uses: Vec<&str> = steps.iter().filter_map(|s| s["uses"].as_str()).collect();
    assert_eq!(all_uses.len(), 4, "{all_uses:?}");
    for reference in &all_uses {
        let sha = reference.split_once('@').unwrap().1;
        assert!(
            sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
            "{reference}"
        );
        let line = text.lines().find(|l| l.contains(reference)).unwrap();
        assert!(line.contains(" # v"), "no version comment: {line}");
    }
    assert_eq!(
        all_uses
            .iter()
            .filter(|u| u.starts_with("actions/download-artifact@"))
            .count(),
        2
    );

    // Two subjects: the four tarballs by SHA256SUMS, and SHA256SUMS.
    let uses: Vec<&Value> = steps
        .iter()
        .filter(|s| {
            s["uses"]
                .as_str()
                .is_some_and(|u| u.starts_with("actions/attest-build-provenance@"))
        })
        .collect();
    assert_eq!(uses.len(), 2);
    assert_eq!(uses[0]["with"]["subject-checksums"], "dist/SHA256SUMS");
    assert_eq!(uses[1]["with"]["subject-path"], "dist/SHA256SUMS");

    // The two write permissions: the attest job's alone.
    let permissions = attest["permissions"].as_object().unwrap();
    assert_eq!(permissions["id-token"], "write");
    assert_eq!(permissions["attestations"], "write");
    assert_eq!(permissions["contents"], "read");
    assert_eq!(permissions.len(), 3);
    let top = workflow["permissions"].as_object().unwrap();
    assert!(!top.contains_key("id-token") && !top.contains_key("attestations"));
    for (name, job) in jobs {
        if name == "attest" {
            continue;
        }
        if let Some(permissions) = job["permissions"].as_object() {
            for key in ["id-token", "attestations"] {
                assert_ne!(permissions.get(key), Some(&json!("write")), "{name}");
            }
            assert_ne!(permissions.get("id-token"), Some(&json!("read")), "{name}");
        }
    }
    // The jobs that verify the published attestations may read them.
    for name in ["verify", "action-install"] {
        let permissions = jobs[name]["permissions"].as_object().unwrap();
        assert_eq!(permissions["contents"], "read", "{name}");
        assert_eq!(permissions["attestations"], "read", "{name}");
        assert_eq!(permissions.len(), 2, "{name}");
    }
}

/// `gh attestation verify` with the repository and the exact certificate
/// identity (the signer workflow at the tag) pinned, as `text` spells it
/// on one logical line.
fn assert_pinned_verify(what: &str, text: &str, repo: &str, identity: &str) {
    let joined = text.replace("\\\n", " ");
    let line = joined
        .lines()
        .find(|l| l.contains("gh attestation verify ") && l.contains(" --repo "))
        .unwrap_or_else(|| panic!("{what} has no gh attestation verify --repo"));
    let args: Vec<&str> = line.split_whitespace().collect();
    for flag in ["--signer-workflow", "--source-ref", "--cert-identity-regex"] {
        assert!(!args.contains(&flag), "{what}: {flag}: {line}");
    }
    for (flag, value) in [("--repo", repo), ("--cert-identity", identity)] {
        let at = args
            .iter()
            .position(|a| *a == flag)
            .unwrap_or_else(|| panic!("{what}: no {flag}: {line}"));
        assert_eq!(args[at + 1], value, "{what}: {line}");
    }
    assert!(
        args.contains(&"--deny-self-hosted-runners"),
        "{what}: {line}"
    );
}

// T6 (AC3), the part that runs without a release: the verify job runs
// scripts/verify-release.sh, which verifies every tarball and SHA256SUMS
// with the repository and the exact identity (release.yml at the tag)
// pinned; the Action install job requires the attestation. The live run
// is the next tag's release.
#[test]
fn sha389_t6_verify_release_pins_repo_and_workflow() {
    let script = read("scripts/verify-release.sh");
    assert_pinned_verify(
        "scripts/verify-release.sh",
        &script,
        "\"$repo\"",
        "\"https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag\"",
    );
    assert!(
        script.contains("[[ $tag =~ ^v[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}(-[0-9A-Za-z.]+)?$ ]]")
    );
    assert!(script.contains("for file in $tarballs SHA256SUMS; do"));
    let workflow = release_workflow();
    let verify = &workflow["jobs"]["verify"];
    assert_eq!(verify["env"]["GH_TOKEN"], "${{ github.token }}");
    assert!(verify["steps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["run"].as_str() == Some("scripts/verify-release.sh \"$TAG\"")));
    let step = workflow["jobs"]["action-install"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.contains("action/install.sh"))
        })
        .unwrap()
        .clone();
    assert_eq!(step["env"]["ROTATE_VERIFY_ATTESTATION"], "true");
    assert_eq!(step["env"]["GH_TOKEN"], "${{ github.token }}");
    let install = read("action/install.sh");
    assert_pinned_verify(
        "action/install.sh",
        &install,
        "\"$REPO\"",
        "\"https://github.com/$SIGNER_WORKFLOW@refs/tags/v$VERSION\"",
    );
    assert!(install.contains("\nREPO=smhasan94/rotate\n"));
    assert!(install.contains("\nSIGNER_WORKFLOW=$REPO/.github/workflows/release.yml\n"));
}

// T7 (AC8): the README's tested install block stays checksum-only and the
// optional verify command follows it; the Action doc explains it.
#[test]
fn sha389_t7_readme_has_the_optional_verify_command() {
    let readme = read("README.md");
    let (before, after) = readme.split_once("<!-- install:end -->").unwrap();
    let block = before.split("<!-- install:start -->").nth(1).unwrap();
    assert!(!block.contains("attestation"), "{block}");
    let section = &after[..after.find("\n### ").unwrap()];
    assert_pinned_verify(
        "README.md",
        section,
        "smhasan94/rotate",
        &format!("\"https://github.com/{SIGNER_WORKFLOW}@refs/tags/v$VERSION\""),
    );
    // It says when the block runs the binary, and how to check first.
    for needle in ["already extracted, installed and run", "before 0.4.0"] {
        assert!(section.contains(needle), "README.md lacks {needle}");
    }
    let doc = read("docs/github-action.md");
    for needle in [
        "gh attestation verify",
        "--cert-identity",
        "Sigstore",
        "attestation check failed for <tarball>; nothing was installed",
        "was not checked",
        "api.github.com",
        "tuf-repo-cdn.sigstore.dev",
        "attestations: read",
    ] {
        assert!(doc.contains(needle), "docs/github-action.md lacks {needle}");
    }
}

// The consumer's case, run on pull requests that change the Action: a job
// whose workflow token has `contents: read` only verifies another
// repository's public attestation with the flags install.sh uses.
#[test]
fn sha389_pr_ci_verifies_with_a_contents_read_token() {
    let workflow: Value = serde_norway::from_str(&read(".github/workflows/action.yml")).unwrap();
    assert!(!workflow["on"]["pull_request"].is_null());
    let top = workflow["permissions"].as_object().unwrap();
    assert_eq!(top.len(), 1);
    assert_eq!(top["contents"], "read");
    let job = &workflow["jobs"]["attestation-token"];
    let permissions = job["permissions"].as_object().unwrap();
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions["contents"], "read");
    let env = &job["env"];
    assert_eq!(env["GH_TOKEN"], "${{ github.token }}");
    let url = env["URL"].as_str().unwrap();
    assert!(
        url.starts_with("https://github.com/cli/cli/releases/download/v"),
        "{url}"
    );
    assert!(url.ends_with(&format!("/{}", env["ASSET"].as_str().unwrap())));
    let sha = env["SHA256"].as_str().unwrap();
    assert!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()));
    let script = job["steps"][0]["run"].as_str().unwrap();
    assert!(!script.contains("${{"), "{script}");
    assert!(script.contains("sha256sum -c -"), "{script}");
    assert_pinned_verify("attestation-token", script, "cli/cli", "\"$IDENTITY\"");
}
