//! SHA-292: the npm operator token requirement matches npm.
//!
//! npm's token list accepts only an `npm login` session token (the research
//! is in `docs/plans/SHA-292.md`). T2, T3 and T5 run the real `rotate plan`
//! binary with the real npm provider (`real_plugins`) against a wiremock
//! registry named by `providers.npm.registry`, in a cleared environment, at
//! `-vvv` with `RUST_LOG=trace` so tracing output lands on stderr. T1 and T4
//! read checked-in docs.
//!
//! Tokens are built at runtime with unique tags so no literal matches a
//! secret scanner and every test can search for its own values.

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::{json, Value};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

use rotate::provider::npm::{LIST_REFUSED, NOT_VISIBLE, NO_OPERATOR, OPERATOR_REQUIREMENT};

use common::CallRecorder;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// An npm token carrying `tag`: `npm_` plus 36 alphanumerics.
fn npm_token(tag: &str) -> String {
    assert!(tag.chars().all(|c| c.is_ascii_alphanumeric()));
    let pad = "Qw7".repeat(36);
    format!("{}{tag}{}", ["np", "m_"].concat(), &pad[..36 - tag.len()])
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(ROOT).join(rel)).unwrap()
}

/// `text` with every run of whitespace collapsed to one space, so a
/// sentence wrapped across Markdown lines still matches.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// One `rotate plan` run: a temp dir with the report, `rotate.yaml` and
/// the scenario, and a wiremock registry.
struct Run {
    dir: tempfile::TempDir,
    rec: CallRecorder,
    leaked: String,
}

impl Run {
    /// A registry where `GET /-/whoami` signed with the leaked token
    /// answers `alice`.
    async fn start(tag: &str) -> Self {
        let rec = CallRecorder::start().await;
        let leaked = npm_token(tag);
        Mock::given(method("GET"))
            .and(path("/-/whoami"))
            .and(header("authorization", format!("Bearer {leaked}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "username": "alice" })))
            .with_priority(2)
            .mount(rec.server())
            .await;
        let run = Self {
            dir: tempfile::tempdir().unwrap(),
            rec,
            leaked,
        };
        run.write_inputs();
        run
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write_inputs(&self) {
        let report = json!([{
            "RuleID": "npm-access-token",
            "Description": "npm token",
            "StartLine": 1,
            "EndLine": 1,
            "StartColumn": 1,
            "EndColumn": 40,
            "Match": self.leaked,
            "Secret": self.leaked,
            "File": ".npmrc",
            "SymlinkFile": "",
            "Commit": "",
            "Entropy": 4.5,
            "Author": "",
            "Email": "",
            "Date": "",
            "Message": "",
            "Tags": [],
            "Fingerprint": ".npmrc:npm-access-token:1",
        }]);
        std::fs::write(self.file("report.json"), report.to_string()).unwrap();
        let uri = self.rec.uri();
        std::fs::write(
            self.file("rotate.yaml"),
            format!("providers:\n  npm:\n    registry: {uri}\n"),
        )
        .unwrap();
        let scenario = json!({ "real_plugins": true, "prompt": "panic" });
        std::fs::write(self.file("scenario.json"), scenario.to_string()).unwrap();
    }

    /// `rotate -vvv [--json] plan report.json` with only `env` added to a
    /// cleared environment. Checks that no value in `secrets` is in stdout,
    /// stderr (tracing included), the audit log or the state file (T5).
    fn plan(&self, json: bool, env: &[(&str, &str)], secrets: &[&str]) -> Output {
        let home = self.file("home");
        let tmp = self.file("tmp");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("rotate"));
        command
            .env_clear()
            .current_dir(self.dir.path())
            .env("HOME", &home)
            .env("TMPDIR", &tmp)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("ROTATE_ACTOR", "tester@host")
            .env("ROTATE_TEST_SCENARIO", self.file("scenario.json"))
            .env("RUST_LOG", "trace")
            .envs(env.iter().copied())
            .arg("-vvv");
        if json {
            command.arg("--json");
        }
        let output = command
            .args(["plan", "report.json"])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let mut places = vec![
            ("stdout", output.stdout.clone()),
            ("stderr", output.stderr.clone()),
        ];
        for name in [".rotate/audit.jsonl", ".rotate/state.json"] {
            if let Ok(bytes) = std::fs::read(self.file(name)) {
                places.push((name, bytes));
            }
        }
        for (place, bytes) in &places {
            let text = String::from_utf8_lossy(bytes);
            for secret in secrets {
                assert!(!text.contains(secret), "a token is in {place}");
            }
        }
        assert_eq!(
            output.status.code(),
            Some(0),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// The one rotation of a `--json` plan.
    fn rotation(output: &Output) -> Value {
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        let rotations = plan["rotations"].as_array().unwrap();
        assert_eq!(rotations.len(), 1, "{plan}");
        rotations[0].clone()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The table's blocker lines.
fn blocker_lines(table: &str) -> Vec<&str> {
    table
        .lines()
        .skip_while(|l| l.trim() != "blockers:")
        .skip(1)
        .take_while(|l| l.starts_with("    - "))
        .collect()
}

// T1 (AC1): the plan file records which token kinds can list and delete
// tokens, with sources.
#[test]
fn plan_file_has_research_outcome() {
    let plan = read("docs/plans/SHA-292.md");
    assert!(
        plan.contains("\n## Research outcome\n"),
        "no outcome section"
    );
    for kind in [
        "`npm login` session token",
        "Granular access token, no 2FA bypass",
        "Granular access token with `bypass_2fa`",
    ] {
        assert!(plan.contains(kind), "the outcome does not cover {kind}");
    }
    for header in [
        "`GET /-/npm/v1/tokens`",
        "`DELETE /-/npm/v1/tokens/token/{key}`",
    ] {
        assert!(plan.contains(header), "the outcome does not cover {header}");
    }
    for source in [
        "https://api-docs.npmjs.com/",
        "https://github.blog/changelog/2026-07-31-restricting-npm-bypass-2fa-granular-access-tokens/",
    ] {
        assert!(plan.contains(source), "source {source} missing");
    }
}

// T2 (AC2), T5: no operator token. The revoke row has a blocker naming
// ROTATE_NPM_TOKEN and the session token kind, the plan makes no
// state-changing call, and the leaked token is in no output or file.
#[tokio::test]
async fn no_operator_token_is_a_blocker() {
    let run = Run::start("t2NoOp").await;
    let secrets = [run.leaked.as_str()];

    let table = stdout(&run.plan(false, &[], &secrets));
    let lines = blocker_lines(&table);
    assert_eq!(lines.len(), 1, "{table}");
    let blocker = lines[0];
    assert!(blocker.contains(NO_OPERATOR), "{blocker}");
    assert!(blocker.contains("ROTATE_NPM_TOKEN"), "{blocker}");
    assert!(blocker.contains("`npm login` session token"), "{blocker}");
    assert!(blocker.contains("two hours"), "{blocker}");
    assert!(blocker.contains("fresh `npm login`"), "{blocker}");
    // The blocker belongs to the revoke row: it follows it.
    let revoke = table.find("  revoke:").unwrap();
    assert!(table.find("  blockers:").unwrap() > revoke, "{table}");

    let rotation = Run::rotation(&run.plan(true, &[], &secrets));
    let blockers = rotation["blockers"].as_array().unwrap();
    assert_eq!(blockers.len(), 1, "{rotation}");
    assert!(
        blockers[0].as_str().unwrap().contains("ROTATE_NPM_TOKEN"),
        "{rotation}"
    );

    let calls = run.rec.calls().await;
    assert!(calls.iter().all(|c| c.method == "GET"), "{calls:?}");
    assert!(
        calls.iter().all(|c| c.path == "/-/whoami"),
        "nothing but whoami without an operator token: {calls:?}"
    );
    run.rec.assert_no_mutations().await;
}

// T3 (AC3), T5: an operator token npm refuses on the list (a granular
// token). The scope line names the kind needed, the revoke row has a
// blocker, only GETs are sent, and neither token is in any output or file.
#[tokio::test]
async fn refused_operator_token_names_the_kind() {
    let run = Run::start("t3Leak").await;
    let operator = npm_token("t3Gat");
    Mock::given(method("GET"))
        .and(path("/-/npm/v1/tokens"))
        .and(header(
            "authorization",
            format!("Bearer {operator}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({ "error": "Forbidden" })))
        .with_priority(2)
        .mount(run.rec.server())
        .await;
    let env = [("ROTATE_NPM_TOKEN", operator.as_str())];
    let secrets = [run.leaked.as_str(), operator.as_str()];

    let rotation = Run::rotation(&run.plan(true, &env, &secrets));
    let lines = rotation["scope"]["lines"].as_array().unwrap();
    let line = lines
        .iter()
        .filter_map(Value::as_str)
        .find(|l| l.starts_with(NOT_VISIBLE))
        .unwrap_or_else(|| panic!("no {NOT_VISIBLE:?} line: {rotation}"));
    assert!(line.contains("403"), "{line}");
    assert!(line.contains(LIST_REFUSED), "{line}");
    assert!(line.contains("not a granular access token"), "{line}");
    assert!(line.contains("two hours"), "{line}");
    let blockers = rotation["blockers"].as_array().unwrap();
    assert_eq!(blockers.len(), 1, "{rotation}");
    let blocker = blockers[0].as_str().unwrap();
    assert!(blocker.contains("ROTATE_NPM_TOKEN"), "{blocker}");
    assert!(blocker.contains("`npm login` session token"), "{blocker}");

    let table = stdout(&run.plan(false, &env, &secrets));
    assert_eq!(
        blocker_lines(&table),
        [format!("    - {blocker}")],
        "{table}"
    );

    let calls = run.rec.calls().await;
    assert!(
        calls.iter().any(|c| c.path == "/-/npm/v1/tokens"),
        "the list was asked: {calls:?}"
    );
    assert!(
        calls.iter().all(|c| c.method == "GET"),
        "only GETs: {calls:?}"
    );
    run.rec.assert_no_mutations().await;
}

// T5 control: with a session token npm accepts, there is no blocker, so
// the blockers above come from the operator token and nothing else.
#[tokio::test]
async fn accepted_operator_token_has_no_blocker() {
    let run = Run::start("t5Leak").await;
    let operator = npm_token("t5Sess");
    let leaked = run.leaked.clone();
    Mock::given(method("GET"))
        .and(path("/-/npm/v1/tokens"))
        .and(header(
            "authorization",
            format!("Bearer {operator}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "objects": [{
                "key": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "token": format!("{}...{}", &leaked[..8], &leaked[leaked.len() - 4..]),
                "name": "ci",
                "readonly": false,
            }],
            "total": 1,
            "urls": {},
        })))
        .with_priority(2)
        .mount(run.rec.server())
        .await;
    let env = [("ROTATE_NPM_TOKEN", operator.as_str())];
    let rotation = Run::rotation(&run.plan(true, &env, &[&leaked, &operator]));
    assert_eq!(rotation["blockers"], json!([]), "{rotation}");
    run.rec.assert_no_mutations().await;
}

// T4 (AC4): the three docs carry the same token-kind sentence, and none
// says a granular or automation token can list tokens.
#[test]
fn docs_agree_on_operator_token_kind() {
    let sentence = flat(OPERATOR_REQUIREMENT);
    for doc in [
        "docs/permissions.md",
        "docs/providers.md",
        "docs/backlog.md",
    ] {
        let text = flat(&read(doc));
        assert!(
            text.contains(&sentence),
            "{doc} lacks the npm operator token sentence: {sentence}"
        );
        let lower = text.to_ascii_lowercase();
        for wrong in [
            "automation token is enough",
            "granular token is enough",
            "granular access token is enough",
            "granular token with token-management",
        ] {
            assert!(!lower.contains(wrong), "{doc} says {wrong:?}");
        }
    }
}
