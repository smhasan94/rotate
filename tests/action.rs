//! The GitHub Action (SHA-198): `action/run.sh` and `action/install.sh` run
//! as the composite steps in `action.yml` run them, against the
//! `test-providers` binary and a wiremock server that plays the GitHub
//! secret-scanning alerts API and the release download.
//!
//! T1 to T6 and T8 are here; T7 is `.github/workflows/action.yml` and T9
//! the `action-install` job of the release workflow.
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

    /// Writes the scenario, adding the call log path.
    fn scenario(&self, mut scenario: Value) {
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
    let good_sums = format!("{}  {name}\n", hex(&Sha256::digest(&tarball)));
    let bad_sums = format!("{}  {name}\n", hex(&Sha256::digest(b"tampered")));

    for (sums, good) in [(good_sums, true), (bad_sums, false)] {
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
            .respond_with(ResponseTemplate::new(200).set_body_string(sums))
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

        if good {
            assert_eq!(install.status.code(), Some(0), "{stderr}");
            assert!(stdout.contains("checksum ok"), "{stdout}");
            assert!(
                stdout.lines().any(|l| l == format!("rotate {version}")),
                "{stdout}"
            );
            let bin = run.path("runner_temp/rotate/bin/rotate");
            assert_eq!(run.outputs()["path"], bin.display().to_string());
            assert!(marker.exists(), "the installed binary was not run");
            assert_eq!(binaries_under(&run.path("runner_temp")), vec![bin]);
        } else {
            assert_eq!(install.status.code(), Some(1), "{stderr}");
            assert!(stderr.contains("checksum mismatch"), "{stderr}");
            assert!(!marker.exists(), "the binary ran despite a bad checksum");
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
        ("MODE", "apply", "mode"),
        ("MODE", "destroy", "mode"),
        ("API_URL", "http://example.com", "api-url"),
        ("VERBOSE", "9", "verbose"),
        ("ROTATE_CONFIG_PATH", "missing.yaml", "config"),
    ];
    for (key, value, input) in cases {
        for args in [&[][..], &["--check-inputs"][..]] {
            let mut run = ActionRun::new(&rec.uri(), &token);
            run.set(key, value);
            let output = run.run("run.sh", args);
            let stderr = text(&output.stderr);
            assert_eq!(output.status.code(), Some(2), "{key}={value:?}: {stderr}");
            let lines: Vec<&str> = stderr.lines().collect();
            assert_eq!(lines.len(), 1, "{key}={value:?}: {stderr}");
            assert!(
                lines[0].contains(&format!("input {input}:")),
                "{key}={value:?}: {stderr}"
            );
            assert!(output.stdout.is_empty());
            assert!(run.calls().is_none(), "rotate ran for {key}={value:?}");
        }
    }
    assert_eq!(requests(&rec).await, Vec::<String>::new());

    // mode: apply names the follow-up.
    let mut run = ActionRun::new(&rec.uri(), &token);
    run.set("MODE", "apply");
    let stderr = text(&run.run("run.sh", &[]).stderr);
    assert!(stderr.contains("SHA-338"), "{stderr}");

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
    assert_eq!(ids, ["inputs", "install", "plan"]);
    assert_eq!(action["runs"]["using"], "composite");
    for step in steps {
        let script = step["run"].as_str().unwrap();
        assert!(!script.contains("${{"), "expression in run: {script}");
        assert_eq!(step["shell"], "bash");
    }
}
