//! SHA-257: manual replacement mode end to end against the `test-providers`
//! mocks.
//!
//! The npm mock is switched to manual mode by the scenario. The scripted
//! prompt's answers are the confirmation (when not passed with `--confirm`)
//! followed by the pasted secrets; the pseudo-terminal test drives the real
//! hidden prompt instead. Test values are fake, unique per test, and shaped
//! so no secret scanner matches them.

#![cfg(all(unix, feature = "test-providers"))]

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use rotate::secret::SecretValue;
use serde_json::{json, Value};

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

const MANUAL: &str = r#"{ "mode": "manual" }"#;

struct Run {
    dir: tempfile::TempDir,
    value: String,
}

impl Run {
    /// A temp dir for one leaked npm secret, the npm mock in manual mode
    /// and two consumers holding the secret.
    fn new(value: &str) -> Self {
        let run = Self {
            dir: tempfile::tempdir().unwrap(),
            value: value.to_owned(),
        };
        run.scenario(json!({}));
        run
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn scenario(&self, extra: Value) {
        let mut scenario = json!({
            "providers": { "npm": serde_json::from_str::<Value>(MANUAL).unwrap() },
            "consumers": [
                { "name": "github-actions", "matches": [
                    { "fingerprint": fp(&self.value), "ref": "gha:org/repo:NPM_TOKEN", "method": "by_name" } ] },
                { "name": "aws-secrets-manager", "matches": [
                    { "fingerprint": fp(&self.value), "ref": "sm:prod/npm-publish" } ] }
            ],
            "call_log": self.file("calls.jsonl"),
            "consumer_state": self.file("held.json"),
        });
        for (key, value) in extra.as_object().unwrap() {
            if key == "npm" {
                for (k, v) in value.as_object().unwrap() {
                    scenario["providers"]["npm"][k] = v.clone();
                }
            } else {
                scenario[key] = value.clone();
            }
        }
        std::fs::write(
            self.file("scenario.json"),
            serde_json::to_string(&scenario).unwrap(),
        )
        .unwrap();
    }

    fn command(&self, args: &[&str]) -> std::process::Command {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("rotate"));
        cmd.current_dir(self.dir.path())
            .env_remove("ROTATE_CONFIG")
            .env_remove("ROTATE_STATE_FILE")
            .env_remove("ROTATE_AUDIT_LOG")
            .env_remove("ROTATE_OVERLAP")
            .env("ROTATE_ACTOR", "ci@runner")
            .env("ROTATE_TEST_SCENARIO", self.file("scenario.json"))
            .args(args);
        cmd
    }

    fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::from_std(self.command(args));
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.write_stdin(format!("{}\n", self.value))
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_env(args, &[])
    }

    fn planned_id(&self) -> String {
        let output = self.run(&["--json", "plan", "--stdin"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(plan["rotations"][0]["replacement"]["mode"], "manual");
        plan["rotations"][0]["rotation_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let c: Value = serde_json::from_str(line).unwrap();
                format!(
                    "{}.{}",
                    c["target"].as_str().unwrap(),
                    c["method"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn mutating(&self) -> Vec<String> {
        std::fs::read_to_string(self.file("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|c| c["mutating"] == true)
            .map(|c| {
                format!(
                    "{}.{}",
                    c["target"].as_str().unwrap(),
                    c["method"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn held(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.file("held.json")).unwrap()).unwrap()
    }

    fn rotation(&self, id: &str) -> Value {
        let state: Value = serde_json::from_str(
            &std::fs::read_to_string(self.file(".rotate/state.json")).unwrap(),
        )
        .unwrap();
        state["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rotation_id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("no rotation {id} in {state}"))
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file(".rotate/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn assert_holds(&self, value: &str) {
        let held = self.held();
        assert_eq!(held["github-actions"]["gha:org/repo:NPM_TOKEN"], fp(value));
        assert_eq!(
            held["aws-secrets-manager"]["sm:prod/npm-publish"],
            fp(value)
        );
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// T1 (AC1)
#[test]
fn manual_mode_prints_instructions_and_prompts_without_create() {
    let pasted = "npm_applymanual_t1_pasted";
    let run = Run::new("npm_applymanual_t1_leaked");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": { "answers": [id, pasted] } }));
    let output = run.run(&["apply", "--stdin"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let out = stdout(&output);
    assert!(
        out.contains("npm cannot create the replacement itself"),
        "{out}"
    );
    assert!(
        out.contains("Create a new npm credential for npm-user with the same access"),
        "{out}"
    );
    let err = stderr(&output);
    assert!(
        err.contains(&format!("Type the rotation id {id} to continue: ")),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "Paste the new secret for rotation {id} (input is hidden)"
        )),
        "{err}"
    );
    let calls = run.calls();
    assert!(
        !calls.iter().any(|c| c.ends_with(".create_replacement")),
        "{calls:?}"
    );
}

// T2 (AC2)
#[test]
fn pasted_replacement_updates_consumers_and_revokes() {
    let leaked = "npm_applymanual_t2_leaked";
    let pasted = "npm_applymanual_t2_pasted";
    let run = Run::new(leaked);
    let id = run.planned_id();
    run.scenario(json!({ "prompt": { "answers": [pasted] } }));
    let output = run.run(&["apply", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    run.assert_holds(pasted);
    assert_eq!(
        run.mutating(),
        [
            "github-actions.update",
            "aws-secrets-manager.update",
            "npm.revoke"
        ]
    );
    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "revoked");
    assert_eq!(rotation["replacement_ref"], "manual");
    assert_eq!(rotation["replacement_fingerprint"], fp(pasted));

    let audit = run.audit();
    let create = audit.iter().find(|e| e["step"] == "create").unwrap();
    assert_eq!(create["replacement_mode"], "manual");
    assert_eq!(create["outcome"], "ok");
    assert_eq!(create["replacement_fingerprint"], fp(pasted));
    let revoke = audit.iter().find(|e| e["step"] == "revoke").unwrap();
    assert_eq!(revoke["outcome"], "ok");
    assert_eq!(revoke["fingerprint"], fp(leaked));
}

// T3 (AC3)
#[test]
fn three_mismatches_fail_at_create_without_update() {
    let foreign = [
        "npm_applymanual_t3_foreign_a",
        "npm_applymanual_t3_foreign_b",
        "npm_applymanual_t3_foreign_c",
    ];
    let run = Run::new("npm_applymanual_t3_leaked");
    let id = run.planned_id();
    run.scenario(json!({
        "npm": { "foreign": foreign.iter().map(|v| fp(v)).collect::<Vec<_>>() },
        "prompt": { "answers": foreign },
    }));
    let output = run.run(&["apply", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));

    let calls = run.calls();
    let verifies = calls.iter().filter(|c| *c == "npm.verify").count();
    assert_eq!(verifies, 3, "{calls:?}");
    assert!(!calls.iter().any(|c| c.ends_with(".update")), "{calls:?}");
    assert!(run.mutating().is_empty(), "{calls:?}");

    let err = stderr(&output);
    assert!(
        err.contains("did not verify as npm-user: credential belongs to someone-else"),
        "{err}"
    );
    assert!(
        err.contains("attempt 2 of 3") && err.contains("attempt 3 of 3"),
        "{err}"
    );
    let out = stdout(&output);
    assert!(out.contains("failed at create"), "{out}");
    assert!(out.contains("rejected 3 times"), "{out}");

    let rotation = run.rotation(&id);
    assert_eq!(rotation["step"], "failed");
    assert!(rotation["consumers"]
        .as_array()
        .is_none_or(|c| c.is_empty()));
    let audit = run.audit();
    let create = audit.iter().find(|e| e["step"] == "create").unwrap();
    assert_eq!(create["outcome"], "failed");
    assert_eq!(create["replacement_mode"], "manual");
    run.assert_holds("npm_applymanual_t3_leaked");
}

// T4 (AC4)
#[test]
fn replacement_from_env_needs_no_prompt() {
    let pasted = "npm_applymanual_t4_from_env";
    let run = Run::new("npm_applymanual_t4_leaked");
    let id = run.planned_id();
    // The scripted prompt panics if apply asks anything.
    run.scenario(json!({ "prompt": "panic" }));
    let output = run.run_env(
        &[
            "apply",
            "--stdin",
            "--confirm",
            &id,
            "--replacement-from-env",
            "SHA257_NEW_TOKEN",
        ],
        &[("SHA257_NEW_TOKEN", pasted)],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    run.assert_holds(pasted);
    assert!(!stderr(&output).contains("input is hidden"));
    assert_eq!(run.rotation(&id)["step"], "revoked");
}

#[test]
fn unset_replacement_env_exits_2_without_calls() {
    let run = Run::new("npm_applymanual_unset_leaked");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": "panic" }));
    let output = run.run(&[
        "apply",
        "--stdin",
        "--confirm",
        &id,
        "--replacement-from-env",
        "SHA257_NOT_SET_ANYWHERE",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("variable is not set"), "{err}");
    assert!(!err.contains("SHA257_NOT_SET_ANYWHERE"), "{err}");
    assert!(run.calls().is_empty());
}

// T5 (AC5)
#[test]
fn wide_replacement_file_is_refused_without_calls() {
    let run = Run::new("npm_applymanual_t5_leaked");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": "panic" }));
    let path = run.file("replacement-t5.txt");
    std::fs::write(&path, "npm_applymanual_t5_pasted\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let output = run.run(&[
        "apply",
        "--stdin",
        "--confirm",
        &id,
        "--replacement-file",
        path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let err = stderr(&output);
    assert!(err.contains("permissions 0644"), "{err}");
    assert!(err.contains("chmod 600"), "{err}");
    assert!(!err.contains("replacement-t5"), "path echoed: {err}");
    // Not a single provider or consumer call, mutating or not.
    assert!(run.calls().is_empty(), "{:?}", run.calls());
    assert_eq!(run.rotation(&id)["step"], "planned");
}

#[test]
fn private_replacement_file_is_used() {
    let pasted = "npm_applymanual_file_pasted";
    let run = Run::new("npm_applymanual_file_leaked");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": "panic" }));
    let path = run.file("replacement.txt");
    std::fs::write(&path, format!("{pasted}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = run.run(&[
        "apply",
        "--stdin",
        "--confirm",
        &id,
        "--replacement-file",
        path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    run.assert_holds(pasted);
}

#[test]
fn no_terminal_for_manual_fails_at_create() {
    let run = Run::new("npm_applymanual_notty_leaked");
    let id = run.planned_id();
    run.scenario(json!({ "prompt": "no_tty" }));
    let output = run.run(&["apply", "--stdin", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let out = stdout(&output);
    assert!(
        out.contains("no terminal to paste the replacement on"),
        "{out}"
    );
    assert!(run.mutating().is_empty());
    assert!(!run.calls().iter().any(|c| c == "npm.verify"));
    assert_eq!(run.rotation(&id)["step"], "failed");
}

#[test]
fn supplied_value_for_two_manual_rotations_exits_2() {
    let values = [
        "npm_applymanual_two_leaked_a",
        "npm_applymanual_two_leaked_b",
    ];
    let run = Run::new(values[0]);
    let findings: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(i, value)| {
            json!({
                "RuleID": "npm-access-token", "Description": "fixture",
                "StartLine": 1, "EndLine": 1, "StartColumn": 1, "EndColumn": 10,
                "Match": value, "Secret": value, "File": format!("ci/npmrc{i}"),
                "SymlinkFile": "", "Commit": "", "Entropy": 4.0, "Author": "",
                "Email": "", "Date": "", "Message": "", "Tags": [],
                "Fingerprint": format!("ci/npmrc{i}:npm-access-token:1"),
            })
        })
        .collect();
    let report = run.file("report.json");
    std::fs::write(&report, serde_json::to_string(&findings).unwrap()).unwrap();
    run.scenario(json!({ "prompt": { "answers": ["all"] } }));
    let output = run.run_env(
        &[
            "apply",
            report.to_str().unwrap(),
            "--all",
            "--replacement-from-env",
            "SHA257_TWO_TOKEN",
        ],
        &[("SHA257_TWO_TOKEN", "npm_applymanual_two_pasted")],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("2 manual rotations are confirmed"));
    assert!(run.mutating().is_empty());
    assert!(!run.calls().iter().any(|c| c == "npm.verify"));
}

// T7 (AC2, AC4)
#[test]
fn manual_replacement_never_leaks() {
    for (flow, leaked, pasted) in [
        (
            "prompt",
            "npm_applymanual_t7_leaked_p",
            "npm_applymanual_t7_canary_prompt",
        ),
        (
            "env",
            "npm_applymanual_t7_leaked_e",
            "npm_applymanual_t7_canary_env",
        ),
    ] {
        let run = Run::new(leaked);
        let id = run.planned_id();
        let output = if flow == "prompt" {
            run.scenario(json!({ "prompt": { "answers": [pasted] } }));
            run.run(&["-vvv", "apply", "--stdin", "--confirm", &id])
        } else {
            run.scenario(json!({ "prompt": "panic" }));
            run.run_env(
                &[
                    "-vvv",
                    "apply",
                    "--stdin",
                    "--confirm",
                    &id,
                    "--replacement-from-env",
                    "SHA257_T7_TOKEN",
                ],
                &[("SHA257_T7_TOKEN", pasted)],
            )
        };
        assert_eq!(output.status.code(), Some(0), "{flow}: {}", stderr(&output));
        run.assert_holds(pasted);
        let captures = [
            ("stdout", stdout(&output)),
            ("stderr and tracing", stderr(&output)),
            (
                "audit log",
                std::fs::read_to_string(run.file(".rotate/audit.jsonl")).unwrap(),
            ),
            (
                "state file",
                std::fs::read_to_string(run.file(".rotate/state.json")).unwrap(),
            ),
            (
                "call log",
                std::fs::read_to_string(run.file("calls.jsonl")).unwrap(),
            ),
        ];
        assert!(
            captures[1].1.contains("audit entry appended"),
            "{flow}: tracing not captured"
        );
        for (name, text) in &captures {
            assert!(!text.is_empty(), "{flow}: {name} is empty");
            assert!(!text.contains(pasted), "{flow}: new value in {name}");
            assert!(!text.contains(leaked), "{flow}: old value in {name}");
        }
    }
}

/// Bytes read from a file descriptor by a background thread.
fn collect(mut from: impl Read + Send + 'static) -> Arc<Mutex<Vec<u8>>> {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 512];
        while let Ok(n) = from.read(&mut chunk) {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&chunk[..n]);
        }
    });
    buf
}

fn wait_for(buf: &Mutex<Vec<u8>>, needle: &str, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if String::from_utf8_lossy(&buf.lock().unwrap()).contains(needle) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "timed out waiting for {what}: {}",
        String::from_utf8_lossy(&buf.lock().unwrap())
    );
}

/// Opens a pseudo-terminal: the master side, and the slave's device path.
fn open_pty() -> (File, PathBuf) {
    use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
    use std::os::unix::ffi::OsStrExt;

    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(name.as_bytes()));
    (File::from(master), path)
}

fn open_slave(path: &Path) -> File {
    let noctty = i32::try_from(rustix::fs::OFlags::NOCTTY.bits()).unwrap();
    File::options()
        .read(true)
        .write(true)
        .custom_flags(noctty)
        .open(path)
        .unwrap()
}

// T6 (AC6)
#[test]
fn pasted_value_is_not_echoed_on_the_terminal() {
    let pasted = "npm_applymanual_t6_typed_on_tty";
    let run = Run::new("npm_applymanual_t6_leaked");
    let id = run.planned_id();
    let (mut master, slave_path) = open_pty();
    let transcript = collect(master.try_clone().unwrap());

    // Control: the transcript captures echo. A line typed while the
    // terminal is in its default mode comes back on the master side. The
    // slave stays open so the terminal outlives rotate's own open and close.
    let slave = open_slave(&slave_path);
    master.write_all(b"echo-control-line\n").unwrap();
    wait_for(&transcript, "echo-control-line", "the control echo");
    let mut line = String::new();
    BufReader::new(&slave).read_line(&mut line).unwrap();
    assert_eq!(line, "echo-control-line\n");

    run.scenario(json!({ "prompt": { "tty": slave_path } }));
    let mut child = run
        .command(&["apply", "--stdin", "--confirm", &id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(format!("{}\n", run.value).as_bytes())
        .unwrap();
    drop(stdin);
    let out = collect(child.stdout.take().unwrap());
    let err = collect(child.stderr.take().unwrap());

    // rotate turns echo off, then asks; type only after the question.
    wait_for(&err, "(input is hidden)", "the hidden prompt");
    master.write_all(format!("{pasted}\n").as_bytes()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("rotate did not exit");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Let the reader threads drain.
    std::thread::sleep(Duration::from_millis(200));
    let err = String::from_utf8_lossy(&err.lock().unwrap()).into_owned();
    let out = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
    assert_eq!(status.code(), Some(0), "{err}");
    // The value typed on the terminal is what rotate rotated to.
    run.assert_holds(pasted);

    let terminal = String::from_utf8_lossy(&transcript.lock().unwrap()).into_owned();
    assert!(!terminal.contains(pasted), "echoed: {terminal:?}");
    assert!(!terminal.contains("npm_applymanual_t6"), "{terminal:?}");
    assert!(!out.contains(pasted) && !err.contains(pasted));
    drop(slave);
}
