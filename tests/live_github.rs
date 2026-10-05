//! SHA-268: the GitHub Actions consumer against a real repository.
//!
//! Live tests run only with `ROTATE_LIVE_TESTS=1` and `--ignored`; setup is
//! in `docs/live-tests.md`. They drive the consumer as a library (`find`,
//! `update`, `restore`) on one secret of the test repository, and prove each
//! write by dispatching the repository's `fingerprint.yml` workflow, which
//! prints `fingerprint=sha256:<16 hex>` of the secret, the same shape as
//! [`Fingerprint`]. The value itself never leaves GitHub.
//!
//! The harness always restores the secret to the value the test seeded,
//! even after a failure. When that restore fails too, the error ends with
//! `left behind: ...` naming what to fix by hand.
//!
//! Every value the test handles (the seeded value, the replacement and the
//! token) is a canary: the captured trace log, every error text and every
//! match are swept for it before anything is shown.

#![cfg(unix)]

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rotate::config::{ActionsTarget, ConsumersConfig, GithubConfig};
use rotate::consumer::github_actions::GithubActionsConsumer;
use rotate::consumer::{Consumer, ConsumerMatch, MatchMethod, SecretRef};
use rotate::provider::Credential;
use rotate::secret::{Fingerprint, SecretValue};
use serde_json::{json, Value};

use common::sweep::{assert_no_hits, canary, Canary, Sweep};
use common::LogCapture;

const API: &str = "https://api.github.com";
const DEFAULT_SECRET: &str = "ROTATE_LIVE_CANARY";
const DEFAULT_WORKFLOW: &str = "fingerprint.yml";
/// Upper bound on waiting for one dispatched run to finish.
const RUN_BUDGET: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_secs(10);

/// The live tests share one secret, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// Where the scenario fails on purpose (`ROTATE_LIVE_FAIL_AFTER`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum FailAfter {
    Nowhere,
    /// Right after the secret is overwritten with the replacement.
    Update,
}

impl FailAfter {
    fn from_env() -> Self {
        match std::env::var("ROTATE_LIVE_FAIL_AFTER").as_deref() {
            Ok("update") => Self::Update,
            Ok("") | Err(_) => Self::Nowhere,
            Ok(other) => panic!("ROTATE_LIVE_FAIL_AFTER={other}: expected `update`"),
        }
    }
}

/// What a live run needs from the environment.
struct Live {
    repo: String,
    secret: String,
    workflow: String,
    token: String,
}

impl Live {
    /// `None`, after printing `skipped: <NAME> not set`, when a required
    /// variable is missing.
    fn from_env() -> Option<Self> {
        let token = common::live_env("ROTATE_GITHUB_TOKEN")?;
        let repo = common::live_env("ROTATE_LIVE_GITHUB_REPO")?;
        Some(Self {
            repo,
            secret: common::require_env("ROTATE_LIVE_GITHUB_SECRET")
                .unwrap_or_else(|| DEFAULT_SECRET.to_owned()),
            workflow: common::require_env("ROTATE_LIVE_GITHUB_WORKFLOW")
                .unwrap_or_else(|| DEFAULT_WORKFLOW.to_owned()),
            token,
        })
    }

    fn consumer(&self) -> GithubActionsConsumer {
        let mut consumers = ConsumersConfig::default();
        consumers.github_actions.targets =
            vec![ActionsTarget::try_from(self.repo.clone()).expect("ROTATE_LIVE_GITHUB_REPO")];
        GithubActionsConsumer::from_config(&consumers, &GithubConfig::default())
    }
}

/// The two values a run writes. Both are random canaries.
struct Values {
    original: String,
    replacement: String,
}

impl Values {
    fn new() -> Self {
        Self {
            original: canary(),
            replacement: canary(),
        }
    }
}

fn token(value: &str) -> Credential {
    Credential::Token(SecretValue::from(value))
}

fn fp(value: &str) -> String {
    Fingerprint::of(value.as_bytes()).as_str().to_owned()
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic with a non-text payload".to_owned()
    }
}

/// Combines how the scenario ended with what cleanup could not undo.
fn outcome(scenario: Result<(), String>, leftovers: &[String]) -> Result<(), String> {
    match (scenario, leftovers.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => Err(format!(
            "scenario passed but cleanup failed; left behind: {}",
            leftovers.join(", ")
        )),
        (Err(message), true) => Err(message),
        (Err(message), false) => Err(format!("{message}; left behind: {}", leftovers.join(", "))),
    }
}

// ---------------------------------------------------------------------------
// Proof by dispatch
// ---------------------------------------------------------------------------

/// Plain REST calls the consumer does not make: dispatching the workflow and
/// reading its log.
struct Dispatcher<'a> {
    live: &'a Live,
    http: reqwest::Client,
}

impl<'a> Dispatcher<'a> {
    fn new(live: &'a Live) -> Self {
        let http = reqwest::Client::builder()
            .user_agent("rotate-live-tests")
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        Self { live, http }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{API}/repos/{}{path}", self.live.repo))
            .bearer_auth(&self.live.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    async fn get_json(&self, path: &str) -> Value {
        let response = self
            .request(reqwest::Method::GET, path)
            .send()
            .await
            .unwrap_or_else(|err| panic!("GET {path}: {err}"));
        let status = response.status();
        assert!(status.is_success(), "GET {path}: HTTP {status}");
        response.json().await.unwrap()
    }

    /// Dispatches the workflow for the secret and returns the fingerprint
    /// the run printed.
    async fn fingerprint(&self, step: &str) -> String {
        let nonce = format!(
            "live-{step}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let repo = self.get_json("").await;
        let branch = repo["default_branch"].as_str().expect("default_branch");
        let path = format!("/actions/workflows/{}/dispatches", self.live.workflow);
        let response = self
            .request(reqwest::Method::POST, &path)
            .json(&json!({
                "ref": branch,
                "inputs": { "nonce": nonce, "secret_name": self.live.secret },
            }))
            .send()
            .await
            .unwrap_or_else(|err| panic!("POST {path}: {err}"));
        let status = response.status();
        assert!(status.is_success(), "POST {path}: HTTP {status}");

        let title = format!("fingerprint {nonce}");
        let started = Instant::now();
        let run_id = loop {
            tokio::time::sleep(POLL).await;
            let runs = self
                .get_json("/actions/runs?event=workflow_dispatch&per_page=20")
                .await;
            let run = runs["workflow_runs"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| r["display_title"] == title.as_str());
            if let Some(run) = run {
                if run["status"] == "completed" {
                    assert_eq!(
                        run["conclusion"], "success",
                        "run {} ({title}) did not succeed",
                        run["id"]
                    );
                    break run["id"].as_u64().unwrap();
                }
            }
            assert!(
                started.elapsed() < RUN_BUDGET,
                "run `{title}` not finished after {}s",
                RUN_BUDGET.as_secs()
            );
        };

        let jobs = self.get_json(&format!("/actions/runs/{run_id}/jobs")).await;
        let job_id = jobs["jobs"][0]["id"].as_u64().expect("the run has a job");
        // The log endpoint redirects to plain text on another host; reqwest
        // drops the Authorization header on that redirect. The log can lag
        // the run's completion by a few seconds.
        let pattern = regex::Regex::new(r"fingerprint=(sha256:[0-9a-f]{16})").unwrap();
        for _ in 0..6 {
            let response = self
                .request(
                    reqwest::Method::GET,
                    &format!("/actions/jobs/{job_id}/logs"),
                )
                .send()
                .await
                .unwrap();
            if response.status().is_success() {
                let log = response.text().await.unwrap();
                if let Some(found) = pattern.captures(&log) {
                    return found[1].to_owned();
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        panic!("no fingerprint in the log of run {run_id} ({title})");
    }
}

// ---------------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------------

/// Seeds `values.original`, overwrites it with `values.replacement`, proves
/// the write, restores and proves the restore. Cleanup always restores
/// `values.original` once anything was written; then the log and every text
/// the run produced are swept for the canaries.
fn run_scenario(live: &Live, values: &Values, fail_after: FailAfter) -> Result<(), String> {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let consumer = live.consumer();
    // Set before the first write: from then on cleanup must restore.
    let written: Mutex<Option<ConsumerMatch>> = Mutex::new(None);
    let mut texts: Vec<String> = Vec::new();

    let scenario = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async {
            let dispatch = Dispatcher::new(live);
            let original = token(&values.original);
            let wanted = SecretRef::new("npm", &original).with_names([live.secret.clone()]);
            let found = consumer
                .find(&wanted)
                .await
                .unwrap_or_else(|e| panic!("find: {e}"));
            let expected = format!("github-actions:{}:{}", live.repo, live.secret);
            assert_eq!(found.len(), 1, "find returned {found:?}");
            let target = found.into_iter().next().unwrap();
            assert_eq!(target.consumer_ref, expected);
            assert_eq!(target.match_method, MatchMethod::ByName);
            assert!(target.is_updatable(), "{target:?}");

            *written.lock().unwrap() = Some(target.clone());
            consumer
                .update(&target, &original)
                .await
                .unwrap_or_else(|e| panic!("seed: {e}"));
            let receipt = consumer
                .update(&target, &token(&values.replacement))
                .await
                .unwrap_or_else(|e| panic!("update: {e}"));
            assert_eq!(receipt.consumer_ref, expected);
            if fail_after == FailAfter::Update {
                panic!("injected failure after update (ROTATE_LIVE_FAIL_AFTER=update)");
            }
            assert_eq!(
                dispatch.fingerprint("update").await,
                fp(&values.replacement),
                "after update the secret does not hold the replacement"
            );

            consumer
                .restore(&target, &original)
                .await
                .unwrap_or_else(|e| panic!("restore: {e}"));
            assert_eq!(
                dispatch.fingerprint("restore").await,
                fp(&values.original),
                "after restore the secret does not hold the original"
            );
            format!("{target:?} {receipt:?}")
        })
    }));
    let scenario = match scenario {
        Ok(debug) => {
            texts.push(debug);
            Ok(())
        }
        Err(payload) => {
            let message = panic_text(payload.as_ref());
            texts.push(message.clone());
            Err(message)
        }
    };

    // Cleanup: put the seeded value back. `left` names the place only;
    // `left_detail` adds the error and is shown only after the sweep.
    let mut left = Vec::new();
    let mut left_detail = Vec::new();
    if let Some(target) = written.into_inner().unwrap() {
        let original = token(&values.original);
        let restored = runtime.block_on(async {
            let mut last = String::new();
            for _ in 0..3 {
                match consumer.restore(&target, &original).await {
                    Ok(()) => return Ok(()),
                    Err(err) => last = err.to_string(),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(last)
        });
        if let Err(err) = restored {
            texts.push(err.clone());
            left.push(format!("{} holds a test value", target.consumer_ref));
            left_detail.push(format!(
                "{} holds a test value ({err})",
                target.consumer_ref
            ));
        }
    }

    // Nothing reaches the output before the sweep has passed on it.
    let sweep = Sweep::new(&[
        Canary::new("seeded value", &values.original),
        Canary::new("replacement", &values.replacement),
        Canary::new("token", &live.token),
    ]);
    let mut hits = sweep.scan("trace log", capture.contents().as_bytes());
    for (i, text) in texts.iter().enumerate() {
        hits.extend(sweep.scan(&format!("error or match text {i}"), text.as_bytes()));
    }
    if !hits.is_empty() {
        let report = catch_unwind(|| assert_no_hits("the live GitHub run", &hits))
            .expect_err("hits were found");
        return outcome(Err(panic_text(report.as_ref())), &left);
    }
    outcome(scenario, &left_detail)
}

/// Runs `f` with `SERIAL` held and the panic hook silenced, so a panic
/// message is printed only after the sweep has passed on it.
fn serially<T>(f: impl FnOnce() -> T) -> T {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(hook);
    result.unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// T3, T6: update and restore one Actions secret, each proven by dispatch.
#[test]
#[ignore]
fn live_github_actions_update_and_restore() {
    common::live_guard!();
    let Some(live) = Live::from_env() else {
        return;
    };
    let values = Values::new();
    if let Err(message) = serially(|| run_scenario(&live, &values, FailAfter::from_env())) {
        panic!("{message}");
    }
}

/// T5: a failure right after the update still leaves the seeded value in
/// place, proven by one more dispatch.
#[test]
#[ignore]
fn live_github_cleanup_after_injected_failure() {
    common::live_guard!();
    let Some(live) = Live::from_env() else {
        return;
    };
    let values = Values::new();
    let message = serially(|| run_scenario(&live, &values, FailAfter::Update))
        .expect_err("the injected failure must fail the scenario");
    assert!(
        message.contains("injected failure after update"),
        "unexpected failure: {message}"
    );
    assert!(!message.contains("left behind"), "{message}");
    let after = serially(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(Dispatcher::new(&live).fingerprint("cleanup"))
    });
    assert_eq!(
        after,
        fp(&values.original),
        "cleanup did not restore the seeded value"
    );
}

/// T2: with the live gate open but no token, the test skips and says which
/// variable is missing. No network.
#[test]
fn t2_skips_naming_the_missing_variable() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "live_github_actions_update_and_restore",
            "--nocapture",
        ])
        .env_clear()
        .env("ROTATE_LIVE_TESTS", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("skipped: ROTATE_GITHUB_TOKEN not set"),
        "{stderr}"
    );
}

/// T5: the failure message names what cleanup left behind.
#[test]
fn run_scenario_reports_leftovers() {
    let left = vec!["github-actions:o/r:S holds a test value (HTTP 500)".to_owned()];
    assert_eq!(outcome(Ok(()), &[]), Ok(()));
    assert_eq!(outcome(Err("boom".into()), &[]), Err("boom".into()));
    assert_eq!(
        outcome(Err("boom".into()), &left),
        Err("boom; left behind: github-actions:o/r:S holds a test value (HTTP 500)".into())
    );
    let passed = outcome(Ok(()), &left).unwrap_err();
    assert!(
        passed.starts_with("scenario passed but cleanup failed; left behind: github-actions:o/r:S"),
        "{passed}"
    );
}
