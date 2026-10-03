//! SHA-264: an AWS key rotated end to end through the `rotate` binary.
//!
//! The real AWS provider and the real Secrets Manager consumer run against
//! one wiremock server playing STS, IAM and Secrets Manager. Behind every
//! route is [`AwsModel`], an in-memory account whose answers change as calls
//! happen: `CreateAccessKey` adds a key that STS then accepts,
//! `UpdateAccessKey` flips a key's status, `PutSecretValue` adds a secret
//! version. `rotate.yaml` points `providers.aws.endpoint_url` at the server.
//!
//! In a `test-providers` build (CI tests with `--all-features`) the scenario
//! sets `real_plugins`, so the binary registers the real plugins exactly as
//! a release build does; without the feature it registers them anyway.
//! Each child process gets a cleared environment holding fake operator
//! credentials only, so nothing can reach real AWS or a local profile.
//!
//! Every command runs at `-vvv` with `RUST_LOG=trace`, and every run is
//! checked for both secret access keys (T8): stdout, stderr, the audit log,
//! the state file, and every request the server recorded except the
//! `PutSecretValue` bodies, which must carry a pair. Key ids and secrets are
//! built at runtime so no literal here matches a secret-scanning pattern.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use wiremock::matchers::any;
use wiremock::{Mock, Request, Respond, ResponseTemplate};

use rotate::secret::SecretValue;

use common::CallRecorder;

const ACCOUNT: &str = "000000000000";
const USER: &str = "deploy-bot";
const SECRET_ID: &str = "prod/app";
const REGION: &str = "us-east-1";
const SM_TARGET: &str = "x-amz-target";
const PAIR_REF: &str = "aws-secrets-manager:prod/app#$.AWS_SECRET_ACCESS_KEY|$.AWS_ACCESS_KEY_ID";
const FIXTURE: &str = include_str!("fixtures/trufflehog_aws_e2e.ndjson");

/// A 20-char key id: `AKIA`, 9 chars of the documentation example, then a
/// 7-char tag, so it is never the example itself (which rotate reports
/// invalid without a call).
fn key_id(tag: &str) -> String {
    assert_eq!(tag.len(), 7);
    let doc = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    format!("AKIA{}{tag}", &doc[4..13])
}

/// A 40-char secret access key with an 8-char tag.
fn secret(tag: &str) -> String {
    assert_eq!(tag.len(), 8);
    ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", tag, "Q0"].concat()
}

fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

fn user_arn() -> String {
    format!("arn:aws:iam::{ACCOUNT}:user/{USER}")
}

/// The JSON a Secrets Manager entry holds for a key pair.
fn pair_json(id: &str, secret: &str) -> String {
    json!({
        "AWS_ACCESS_KEY_ID": id,
        "AWS_SECRET_ACCESS_KEY": secret,
        "DATABASE_HOST": "db.internal",
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    id: String,
    secret: String,
    status: &'static str,
}

struct State {
    operator: String,
    keys: Vec<Key>,
    /// What the next `CreateAccessKey` mints.
    next_key: (String, String),
    /// Versions of `prod/app`, oldest first.
    versions: Vec<(String, String)>,
    tokens: BTreeMap<String, String>,
    deny_put: bool,
    /// Every operation in order, as `Action` or the Secrets Manager target
    /// without its prefix.
    ops: Vec<String>,
}

/// An AWS account with one IAM user and one Secrets Manager entry.
#[derive(Clone)]
struct AwsModel(Arc<Mutex<State>>);

impl AwsModel {
    fn new(operator: &str, leaked: &Key, next_key: (String, String)) -> Self {
        Self(Arc::new(Mutex::new(State {
            operator: operator.to_owned(),
            keys: vec![leaked.clone()],
            next_key,
            versions: vec![("v1".into(), pair_json(&leaked.id, &leaked.secret))],
            tokens: BTreeMap::new(),
            deny_put: false,
            ops: Vec::new(),
        })))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    fn status(&self, id: &str) -> Option<&'static str> {
        self.state()
            .keys
            .iter()
            .find(|k| k.id == id)
            .map(|k| k.status)
    }

    fn key_ids(&self) -> Vec<String> {
        self.state().keys.iter().map(|k| k.id.clone()).collect()
    }

    /// The current value of `prod/app`, parsed.
    fn secret_json(&self) -> Value {
        let state = self.state();
        serde_json::from_str(&state.versions.last().unwrap().1).unwrap()
    }

    fn versions(&self) -> usize {
        self.state().versions.len()
    }

    fn ops(&self) -> Vec<String> {
        self.state().ops.clone()
    }

    fn count(&self, op: &str) -> usize {
        self.state().ops.iter().filter(|o| *o == op).count()
    }

    /// Everything the model holds, for "unchanged" comparisons.
    fn snapshot(&self) -> (Vec<Key>, Vec<(String, String)>) {
        let state = self.state();
        (state.keys.clone(), state.versions.clone())
    }
}

fn xml(status: u16, body: String) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "text/xml")
        .set_body_string(body)
}

fn query_error(status: u16, code: &str) -> ResponseTemplate {
    xml(
        status,
        format!(
            "<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code>\
             <Message>{code}</Message></Error><RequestId>req-e</RequestId></ErrorResponse>"
        ),
    )
}

fn query_ok(ns: &str, action: &str, result: &str) -> ResponseTemplate {
    xml(
        200,
        format!(
            "<{action}Response xmlns=\"{ns}\"><{action}Result>{result}</{action}Result>\
             <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></{action}Response>"
        ),
    )
}

fn iam_ok(action: &str, result: &str) -> ResponseTemplate {
    query_ok("https://iam.amazonaws.com/doc/2010-05-08/", action, result)
}

fn sm_json(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "application/x-amz-json-1.1")
        .set_body_string(body.to_string())
}

fn sm_error(kind: &str) -> ResponseTemplate {
    sm_json(400, json!({ "__type": kind, "message": kind }))
}

/// The key id a request was signed with (SigV4 `Credential=<id>/...`).
fn signer(req: &Request) -> Option<String> {
    let auth = req.headers.get("authorization")?.to_str().ok()?;
    let rest = auth.split("Credential=").nth(1)?;
    rest.split('/').next().map(str::to_owned)
}

fn sm_target(req: &Request) -> Option<&str> {
    req.headers
        .get(SM_TARGET)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| t.strip_prefix("secretsmanager."))
}

/// Decoded fields of a query-protocol form body.
fn fields(body: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| {
            let decode = |s: &str| {
                urlencoding::decode(&s.replace('+', " "))
                    .map(|c| c.into_owned())
                    .unwrap_or_default()
            };
            (decode(k), decode(v))
        })
        .collect()
}

impl State {
    fn key(&self, id: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.id == id)
    }

    fn sts(&self, signer: &str) -> ResponseTemplate {
        match self.key(signer) {
            Some(key) if key.status == "Active" => query_ok(
                "https://sts.amazonaws.com/doc/2011-06-15/",
                "GetCallerIdentity",
                &format!(
                    "<Arn>{}</Arn><UserId>AIDAE2EUSERID</UserId><Account>{ACCOUNT}</Account>",
                    user_arn()
                ),
            ),
            _ => query_error(403, "InvalidClientTokenId"),
        }
    }

    fn key_member(key: &Key) -> String {
        format!(
            "<member><UserName>{USER}</UserName><AccessKeyId>{}</AccessKeyId>\
             <Status>{}</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate></member>",
            key.id, key.status
        )
    }

    fn iam(&mut self, action: &str, form: &BTreeMap<String, String>) -> ResponseTemplate {
        let key_id = form.get("AccessKeyId").cloned().unwrap_or_default();
        match action {
            "GetAccessKeyLastUsed" => {
                if self.key(&key_id).is_none() {
                    return query_error(404, "NoSuchEntity");
                }
                iam_ok(
                    action,
                    &format!(
                        "<UserName>{USER}</UserName><AccessKeyLastUsed>\
                         <LastUsedDate>2026-09-01T10:00:00Z</LastUsedDate>\
                         <ServiceName>s3</ServiceName><Region>{REGION}</Region>\
                         </AccessKeyLastUsed>"
                    ),
                )
            }
            "GetUser" => iam_ok(
                action,
                &format!(
                    "<User><Path>/</Path><UserName>{USER}</UserName><UserId>AIDAE2EUSERID</UserId>\
                     <Arn>{}</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate></User>",
                    user_arn()
                ),
            ),
            "ListAttachedUserPolicies" => iam_ok(
                action,
                "<AttachedPolicies><member><PolicyName>DeployBucketWrite</PolicyName>\
                 <PolicyArn>arn:aws:iam::000000000000:policy/DeployBucketWrite</PolicyArn>\
                 </member></AttachedPolicies><IsTruncated>false</IsTruncated>",
            ),
            "ListUserPolicies" => iam_ok(
                action,
                "<PolicyNames><member>inline-ci</member></PolicyNames>\
                 <IsTruncated>false</IsTruncated>",
            ),
            "ListGroupsForUser" => iam_ok(
                action,
                "<Groups><member><Path>/</Path><GroupName>deployers</GroupName>\
                 <GroupId>AGPAE2EGROUPID</GroupId>\
                 <Arn>arn:aws:iam::000000000000:group/deployers</Arn>\
                 <CreateDate>2020-01-01T00:00:00Z</CreateDate></member></Groups>\
                 <IsTruncated>false</IsTruncated>",
            ),
            "ListAccessKeys" => {
                let members: String = self.keys.iter().map(Self::key_member).collect();
                iam_ok(
                    action,
                    &format!(
                        "<AccessKeyMetadata>{members}</AccessKeyMetadata>\
                         <IsTruncated>false</IsTruncated>"
                    ),
                )
            }
            "CreateAccessKey" => {
                if self.keys.len() >= 2 {
                    return query_error(409, "LimitExceeded");
                }
                let (id, secret) = self.next_key.clone();
                self.keys.push(Key {
                    id: id.clone(),
                    secret: secret.clone(),
                    status: "Active",
                });
                iam_ok(
                    action,
                    &format!(
                        "<AccessKey><UserName>{USER}</UserName><AccessKeyId>{id}</AccessKeyId>\
                         <Status>Active</Status><SecretAccessKey>{secret}</SecretAccessKey>\
                         <CreateDate>2026-10-01T00:00:00Z</CreateDate></AccessKey>"
                    ),
                )
            }
            "UpdateAccessKey" => {
                let status = match form.get("Status").map(String::as_str) {
                    Some("Active") => "Active",
                    Some("Inactive") => "Inactive",
                    _ => return query_error(400, "ValidationError"),
                };
                match self.keys.iter_mut().find(|k| k.id == key_id) {
                    Some(key) => {
                        key.status = status;
                        xml(
                            200,
                            "<UpdateAccessKeyResponse \
                             xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">\
                             <ResponseMetadata><RequestId>req-u</RequestId></ResponseMetadata>\
                             </UpdateAccessKeyResponse>"
                                .to_owned(),
                        )
                    }
                    None => query_error(404, "NoSuchEntity"),
                }
            }
            _ => query_error(400, "InvalidAction"),
        }
    }

    fn secrets_manager(&mut self, op: &str, body: &[u8]) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        if body["SecretId"] != SECRET_ID {
            return sm_error("ResourceNotFoundException");
        }
        match op {
            "GetSecretValue" => {
                let (version, value) = self.versions.last().unwrap();
                sm_json(
                    200,
                    json!({
                        "ARN": format!("arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:{SECRET_ID}"),
                        "Name": SECRET_ID,
                        "VersionId": version,
                        "SecretString": value,
                        "VersionStages": ["AWSCURRENT"],
                    }),
                )
            }
            "PutSecretValue" => {
                if self.deny_put {
                    return sm_error("AccessDeniedException");
                }
                let token = body["ClientRequestToken"].as_str().unwrap_or("").to_owned();
                if let Some(version) = self.tokens.get(&token) {
                    return sm_json(200, json!({ "Name": SECRET_ID, "VersionId": version }));
                }
                let version = format!("v{}", self.versions.len() + 1);
                let value = body["SecretString"].as_str().unwrap_or("").to_owned();
                self.versions.push((version.clone(), value));
                self.tokens.insert(token, version.clone());
                sm_json(200, json!({ "Name": SECRET_ID, "VersionId": version }))
            }
            _ => sm_error("UnknownOperationException"),
        }
    }
}

impl Respond for AwsModel {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let signer = signer(req).unwrap_or_default();
        let mut state = self.state();
        if let Some(op) = sm_target(req) {
            state.ops.push(op.to_owned());
            if signer != state.operator {
                return sm_error("AccessDeniedException");
            }
            return state.secrets_manager(op, &req.body);
        }
        let form = fields(&req.body);
        let action = form.get("Action").cloned().unwrap_or_default();
        state.ops.push(action.clone());
        if action == "GetCallerIdentity" {
            return state.sts(&signer);
        }
        // Decision D3: only the operator's own credentials touch IAM.
        if signer != state.operator {
            return query_error(403, "AccessDenied");
        }
        state.iam(&action, &form)
    }
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// Calls that change state. Everything else the model answers is a read.
const MUTATING: &[&str] = &["CreateAccessKey", "UpdateAccessKey", "PutSecretValue"];

struct E2e {
    rec: CallRecorder,
    model: AwsModel,
    dir: tempfile::TempDir,
    operator_id: String,
    operator_secret: String,
    leaked: Key,
    new_id: String,
    new_secret: String,
}

impl E2e {
    /// A user holding only the leaked key, referenced by `prod/app`.
    async fn start() -> Self {
        let operator_id = key_id("OPERATR");
        let operator_secret = ["operatorSecretFromTheChain", "0000000000000x"].concat();
        let leaked = Key {
            id: key_id("E2ELEAK"),
            secret: secret("e2eLeak1"),
            status: "Active",
        };
        let (new_id, new_secret) = (key_id("E2ENEWK"), secret("e2eNewK1"));
        let model = AwsModel::new(&operator_id, &leaked, (new_id.clone(), new_secret.clone()));
        let mut rec = CallRecorder::start().await;
        Mock::given(any())
            .respond_with(model.clone())
            .with_priority(1)
            .mount(rec.server())
            .await;
        rec.mark_read_only(|req| {
            if let Some(op) = sm_target(req) {
                return !MUTATING.contains(&op);
            }
            let action = fields(&req.body).get("Action").cloned().unwrap_or_default();
            !MUTATING.contains(&action.as_str())
        });
        let e2e = Self {
            rec,
            model,
            dir: tempfile::tempdir().unwrap(),
            operator_id,
            operator_secret,
            leaked,
            new_id,
            new_secret,
        };
        e2e.write_inputs();
        e2e
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    /// The report (the fixture with this run's key), `rotate.yaml` naming
    /// the Secrets Manager entry and the endpoint, and the scenario.
    fn write_inputs(&self) {
        let report = FIXTURE
            .replace("@KEY_ID@", &self.leaked.id)
            .replace("@SECRET@", &self.leaked.secret);
        std::fs::write(self.file("report.ndjson"), report).unwrap();
        let config = format!(
            "consumers:\n  aws_secrets_manager:\n    secrets: [{SECRET_ID}]\n\
             providers:\n  aws:\n    region: {REGION}\n    endpoint_url: {}\n",
            self.rec.uri()
        );
        std::fs::write(self.file("rotate.yaml"), config).unwrap();
        let scenario = json!({ "real_plugins": true, "prompt": "panic" });
        std::fs::write(self.file("scenario.json"), scenario.to_string()).unwrap();
    }

    /// Runs `rotate -vvv <args>` in a cleared environment and checks its
    /// stdout and stderr, and the audit log and state file, for both secret
    /// access keys (T8).
    fn run(&self, args: &[&str]) -> Output {
        let home = self.file("home");
        std::fs::create_dir_all(&home).unwrap();
        // Empty AWS files: no profile, and no "file not found" warnings.
        for name in ["aws-config", "aws-credentials"] {
            std::fs::write(home.join(name), "").unwrap();
        }
        let output = std::process::Command::new(assert_cmd::cargo::cargo_bin("rotate"))
            .current_dir(self.path())
            .env_clear()
            .env("HOME", &home)
            .env("AWS_ACCESS_KEY_ID", &self.operator_id)
            .env("AWS_SECRET_ACCESS_KEY", &self.operator_secret)
            .env("AWS_REGION", REGION)
            .env("AWS_CONFIG_FILE", home.join("aws-config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", home.join("aws-credentials"))
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("ROTATE_ACTOR", "e2e@runner")
            .env("ROTATE_TEST_SCENARIO", self.file("scenario.json"))
            .env("RUST_LOG", "trace")
            .arg("-vvv")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let label = args.join(" ");
        self.assert_clean(&format!("{label}: stdout"), &output.stdout);
        self.assert_clean(&format!("{label}: stderr"), &output.stderr);
        for name in [".rotate/audit.jsonl", ".rotate/state.json"] {
            if let Ok(bytes) = std::fs::read(self.file(name)) {
                self.assert_clean(&format!("{label}: {name}"), &bytes);
            }
        }
        output
    }

    /// `rotate --json plan` and the one rotation's id.
    fn rotation_id(&self) -> String {
        let output = self.run(&["--json", "plan", "report.ndjson"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(plan["rotations"].as_array().unwrap().len(), 1, "{plan}");
        plan["rotations"][0]["rotation_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Plans, then applies with `--confirm`; returns the id and the apply
    /// output.
    fn apply(&self) -> (String, Output) {
        let id = self.rotation_id();
        let output = self.run(&["apply", "report.ndjson", "--confirm", &id]);
        (id, output)
    }

    fn secrets(&self) -> [(&'static str, &str); 2] {
        [
            ("leaked secret", self.leaked.secret.as_str()),
            ("new secret", self.new_secret.as_str()),
        ]
    }

    /// Neither secret access key, raw or URL-encoded, is in `bytes`. The
    /// failure message names where, never the value.
    fn assert_clean(&self, place: &str, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for (name, value) in self.secrets() {
            let encoded = urlencoding::encode(value).into_owned();
            assert!(
                !text.contains(value) && !text.contains(&encoded),
                "{place} contains the {name}"
            );
        }
    }

    /// No recorded request carries a secret access key in a header or a
    /// body, except `PutSecretValue` bodies, which must carry a pair; each
    /// of those must hold exactly one of the two pairs. Returns the pairs
    /// written, in order, as "leaked" or "new".
    async fn assert_requests_clean(&self) -> Vec<&'static str> {
        let requests = self.rec.server().received_requests().await.unwrap();
        let mut written = Vec::new();
        for (i, req) in requests.iter().enumerate() {
            let op = sm_target(req)
                .map(str::to_owned)
                .unwrap_or_else(|| fields(&req.body).get("Action").cloned().unwrap_or_default());
            for (name, value) in req.headers.iter() {
                let value = value.to_str().unwrap_or("");
                self.assert_clean(
                    &format!("request {i} ({op}) header {name}"),
                    value.as_bytes(),
                );
            }
            if op == "PutSecretValue" {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                let stored: Value =
                    serde_json::from_str(body["SecretString"].as_str().unwrap()).unwrap();
                let leaked = stored["AWS_SECRET_ACCESS_KEY"] == self.leaked.secret.as_str()
                    && stored["AWS_ACCESS_KEY_ID"] == self.leaked.id.as_str();
                let new = stored["AWS_SECRET_ACCESS_KEY"] == self.new_secret.as_str()
                    && stored["AWS_ACCESS_KEY_ID"] == self.new_id.as_str();
                assert!(
                    leaked ^ new,
                    "request {i}: PutSecretValue holds neither pair"
                );
                let other = if leaked {
                    &self.new_secret
                } else {
                    &self.leaked.secret
                };
                assert!(
                    !String::from_utf8_lossy(&req.body).contains(other.as_str()),
                    "request {i}: PutSecretValue carries both secrets"
                );
                assert_eq!(stored["DATABASE_HOST"], "db.internal", "request {i}");
                written.push(if leaked { "leaked" } else { "new" });
                continue;
            }
            self.assert_clean(&format!("request {i} ({op}) body"), &req.body);
            let decoded: String = fields(&req.body)
                .into_iter()
                .map(|(k, v)| format!("{k}={v}&"))
                .collect();
            self.assert_clean(
                &format!("request {i} ({op}) decoded body"),
                decoded.as_bytes(),
            );
        }
        written
    }

    /// Requests signed by a key other than the operator's, as
    /// `signer: action`.
    async fn non_operator_calls(&self) -> Vec<String> {
        let requests = self.rec.server().received_requests().await.unwrap();
        requests
            .iter()
            .filter_map(|req| {
                let signer = signer(req)?;
                if signer == self.operator_id {
                    return None;
                }
                let who = if signer == self.leaked.id {
                    "leaked"
                } else if signer == self.new_id {
                    "new"
                } else {
                    "other"
                };
                let action = fields(&req.body).get("Action").cloned().unwrap_or_default();
                Some(format!("{who}: {action}"))
            })
            .collect()
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file(".rotate/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn rotation(&self, id: &str) -> Value {
        let text = std::fs::read_to_string(self.file(".rotate/state.json")).unwrap();
        let state: Value = serde_json::from_str(&text).unwrap();
        state["rotations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["rotation_id"] == id)
            .unwrap_or_else(|| panic!("no rotation {id} in the state file"))
            .clone()
    }

    /// `prod/app` holds the pair `(id, secret)` and its other field.
    fn assert_secret_holds(&self, id: &str, secret: &str) {
        let stored = self.model.secret_json();
        assert_eq!(stored["AWS_ACCESS_KEY_ID"], id);
        assert!(
            stored["AWS_SECRET_ACCESS_KEY"] == secret,
            "prod/app does not hold the expected secret"
        );
        assert_eq!(stored["DATABASE_HOST"], "db.internal");
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// stdout and the tail of stderr (`-vvv` makes it long), for failures.
fn shown(output: &Output) -> String {
    let err = stderr(output);
    let tail: String = err
        .lines()
        .rev()
        .take(30)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "status {:?}\nstdout:\n{}\nstderr (tail):\n{tail}",
        output.status,
        stdout(output)
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// T1 (AC1)
#[tokio::test(flavor = "multi_thread")]
async fn t1_plan_lists_user_entry_and_deactivate_without_mutations() {
    let e2e = E2e::start().await;
    let before = e2e.model.snapshot();

    let output = e2e.run(&["plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    assert!(table.contains("Dry run: nothing was changed."), "{table}");
    assert!(table.contains("1 to rotate, 0 skipped"), "{table}");
    assert!(table.contains(&user_arn()), "{table}");
    assert!(table.contains(&fp(&e2e.leaked.secret)), "{table}");
    let row = table
        .lines()
        .find(|l| l.contains(PAIR_REF))
        .unwrap_or_else(|| panic!("no Secrets Manager row: {table}"));
    assert!(row.contains("aws-secrets-manager"), "{row}");
    assert!(row.contains("by value"), "{row}");
    assert!(row.contains("update"), "{row}");
    assert!(
        table.contains("deactivate the access key (not deleted; rollback can reactivate it)"),
        "{table}"
    );

    let output = e2e.run(&["--json", "plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    let rotation = &plan["rotations"][0];
    assert_eq!(rotation["provider"], "aws");
    assert_eq!(rotation["validity"], "valid");
    assert_eq!(rotation["scope"]["identity"], user_arn());
    let lines: Vec<&str> = rotation["scope"]["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(lines.contains(&"user: deploy-bot"), "{lines:?}");
    assert!(lines.contains(&"access keys: 1 of 2 used"), "{lines:?}");
    assert_eq!(rotation["replacement"]["mode"], "automatic");
    assert_eq!(
        rotation["consumers"],
        json!([{
            "consumer": "aws-secrets-manager",
            "consumer_ref": PAIR_REF,
            "match_method": "by_value",
            "holds": "key_pair",
            "updatable": true,
            "reason": null,
        }])
    );
    assert!(rotation["revoke_action"]
        .as_str()
        .unwrap()
        .starts_with("deactivate the access key"));
    assert_eq!(rotation["blockers"], json!([]));

    // Zero mutating requests, and the model is exactly as it started.
    e2e.rec.assert_no_mutations().await;
    assert_eq!(e2e.model.snapshot(), before);
    for op in MUTATING {
        assert_eq!(e2e.model.count(op), 0, "{op}");
    }
    // The leaked key signed exactly one call per plan: GetCallerIdentity.
    assert_eq!(
        e2e.non_operator_calls().await,
        ["leaked: GetCallerIdentity", "leaked: GetCallerIdentity"]
    );
    assert!(e2e.assert_requests_clean().await.is_empty());
}

// T2 (AC2)
#[tokio::test(flavor = "multi_thread")]
async fn t2_apply_rotates_key_and_secret() {
    let e2e = E2e::start().await;
    let (_, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert!(stdout(&output).contains("1 revoked"), "{}", shown(&output));

    assert_eq!(
        e2e.model.key_ids(),
        [e2e.leaked.id.clone(), e2e.new_id.clone()]
    );
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Active"));
    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Inactive"));
    e2e.assert_secret_holds(&e2e.new_id, &e2e.new_secret);
    assert_eq!(e2e.model.versions(), 2);
    assert_eq!(e2e.model.count("CreateAccessKey"), 1);
    assert_eq!(e2e.model.count("PutSecretValue"), 1);
    // Create, write the secret, then revoke last.
    let mutations: Vec<String> = e2e
        .model
        .ops()
        .into_iter()
        .filter(|op| MUTATING.contains(&op.as_str()))
        .collect();
    assert_eq!(
        mutations,
        ["CreateAccessKey", "PutSecretValue", "UpdateAccessKey"]
    );
    // The leaked key only ever proved itself; the new one only verified.
    let signed = e2e.non_operator_calls().await;
    assert!(
        signed
            .iter()
            .all(|c| c == "leaked: GetCallerIdentity" || c == "new: GetCallerIdentity"),
        "{signed:?}"
    );
    assert!(signed.contains(&"new: GetCallerIdentity".to_owned()));
    assert_eq!(e2e.assert_requests_clean().await, ["new"]);
}

// T3 (AC3)
#[tokio::test(flavor = "multi_thread")]
async fn t3_audit_has_every_step_with_both_fingerprints() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let leaked = fp(&e2e.leaked.secret);
    let new = fp(&e2e.new_secret);
    let audit = e2e.audit();
    let steps: Vec<&str> = audit.iter().map(|e| e["step"].as_str().unwrap()).collect();
    assert_eq!(
        steps,
        ["plan", "create", "update", "verify", "revoke"],
        "{audit:?}"
    );
    for entry in &audit {
        assert_eq!(entry["outcome"], "ok", "{entry}");
        assert_eq!(entry["rotation_id"], id.as_str(), "{entry}");
        assert_eq!(entry["provider"], "aws", "{entry}");
        assert_eq!(entry["fingerprint"], leaked.as_str(), "{entry}");
        assert_eq!(entry["actor"], "e2e@runner", "{entry}");
        if entry["step"] != "plan" {
            assert_eq!(entry["replacement_fingerprint"], new.as_str(), "{entry}");
        }
    }
    let update = audit.iter().find(|e| e["step"] == "update").unwrap();
    assert_eq!(update["consumer"], PAIR_REF, "{update}");
    e2e.assert_requests_clean().await;
}

// T4 (AC4): the record `rotate status` reads.
#[tokio::test(flavor = "multi_thread")]
async fn t4_state_records_revoked() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let rotation = e2e.rotation(&id);
    assert_eq!(rotation["step"], "revoked", "{rotation}");
    assert_eq!(rotation["provider"], "aws");
    assert_eq!(rotation["fingerprint"], fp(&e2e.leaked.secret).as_str());
    assert_eq!(
        rotation["replacement_fingerprint"],
        fp(&e2e.new_secret).as_str()
    );
    assert_eq!(rotation["replacement_ref"], e2e.new_id.as_str());
    assert!(rotation["revoke_not_before"].is_null(), "{rotation}");
    let consumers = rotation["consumers"].as_array().unwrap();
    assert_eq!(consumers.len(), 1, "{rotation}");
    assert_eq!(consumers[0]["consumer_ref"], PAIR_REF);
    assert_eq!(consumers[0]["status"], "updated");
}

// T4 (AC4): the command itself.
#[tokio::test(flavor = "multi_thread")]
async fn t4_status_all_shows_revoked() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let calls = e2e.rec.calls().await.len();

    let output = e2e.run(&["status", "--all"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let table = stdout(&output);
    let row = table
        .lines()
        .find(|l| l.contains(&id))
        .unwrap_or_else(|| panic!("no row for {id}: {table}"));
    assert!(row.contains("revoked"), "{row}");
    assert_eq!(e2e.rec.calls().await.len(), calls, "status made a call");
}

// T5 (AC5)
#[tokio::test(flavor = "multi_thread")]
async fn t5_rollback_restores_old_key_and_secret() {
    let e2e = E2e::start().await;
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    let output = e2e.run(&["rollback", "report.ndjson", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));

    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));
    assert_eq!(e2e.model.status(&e2e.new_id), Some("Inactive"));
    e2e.assert_secret_holds(&e2e.leaked.id, &e2e.leaked.secret);
    assert_eq!(e2e.model.versions(), 3);
    // Nothing was deleted and no second replacement was minted.
    assert_eq!(e2e.model.key_ids().len(), 2);
    assert_eq!(e2e.model.count("CreateAccessKey"), 1);

    assert_eq!(e2e.rotation(&id)["step"], "rolled_back");
    let rollback: Vec<Value> = e2e
        .audit()
        .into_iter()
        .filter(|e| e["step"] == "rollback")
        .collect();
    let actions: Vec<&str> = rollback
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    for action in ["restore_old", "restore_consumer", "revoke_replacement"] {
        assert!(actions.contains(&action), "{actions:?}");
    }
    assert!(
        rollback.iter().all(|e| e["outcome"] == "ok"),
        "{rollback:?}"
    );
    // Apply wrote the new pair, rollback the old one; nothing else carried
    // a secret.
    assert_eq!(e2e.assert_requests_clean().await, ["new", "leaked"]);
}

// T6 (AC6)
#[tokio::test(flavor = "multi_thread")]
async fn t6_two_keys_refused_before_create() {
    let e2e = E2e::start().await;
    let other = Key {
        id: key_id("E2EOTHR"),
        secret: secret("e2eOthr1"),
        status: "Active",
    };
    e2e.model.state().keys.push(other.clone());
    let before = e2e.model.snapshot();

    let (_, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(1), "{}", shown(&output));
    let text = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        text.contains("already has 2 access keys"),
        "{}",
        shown(&output)
    );
    assert!(text.contains(&other.id), "{}", shown(&output));

    assert_eq!(e2e.model.count("CreateAccessKey"), 0);
    assert_eq!(e2e.model.count("PutSecretValue"), 0);
    assert_eq!(e2e.model.count("UpdateAccessKey"), 0);
    assert_eq!(e2e.model.snapshot(), before);
    e2e.rec.assert_no_mutations().await;
    e2e.assert_secret_holds(&e2e.leaked.id, &e2e.leaked.secret);
    assert!(e2e.assert_requests_clean().await.is_empty());
}

// T7 (AC7)
#[tokio::test(flavor = "multi_thread")]
async fn t7_put_denied_stops_before_revoke() {
    let e2e = E2e::start().await;
    e2e.model.state().deny_put = true;

    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(1), "{}", shown(&output));
    let summary = stdout(&output);
    assert!(
        summary.contains("stopped before revoke; old secret still valid"),
        "{}",
        shown(&output)
    );

    assert_eq!(e2e.model.status(&e2e.leaked.id), Some("Active"));
    assert_eq!(e2e.model.count("PutSecretValue"), 1);
    assert_eq!(
        e2e.model.count("UpdateAccessKey"),
        0,
        "revoke must not be attempted"
    );
    e2e.assert_secret_holds(&e2e.leaked.id, &e2e.leaked.secret);
    assert_eq!(e2e.model.versions(), 1);
    assert_eq!(e2e.rotation(&id)["step"], "failed");
    let audit = e2e.audit();
    assert!(audit.iter().all(|e| e["step"] != "revoke"), "{audit:?}");
    assert!(audit
        .iter()
        .any(|e| e["step"] == "update" && e["outcome"] == "failed"));
    // The denied write carried the new pair; nothing else carried a secret.
    assert_eq!(e2e.assert_requests_clean().await, ["new"]);
}

// T8 (AC2, AC5)
#[tokio::test(flavor = "multi_thread")]
async fn t8_no_secret_in_any_output() {
    let e2e = E2e::start().await;
    // `run` checks stdout, stderr (at -vvv, RUST_LOG=trace), the audit log
    // and the state file of every command.
    let output = e2e.run(&["plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let (id, output) = e2e.apply();
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    // The trace output really is at trace level, SDK events included, so
    // the absence checks above mean something.
    let err = stderr(&output);
    assert!(err.contains("TRACE"), "stderr is not at trace level");
    assert!(err.contains("aws_smithy"), "no SDK events in the trace");
    let output = e2e.run(&["rollback", "report.ndjson", "--confirm", &id]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    let output = e2e.run(&["--json", "plan", "report.ndjson"]);
    assert_eq!(output.status.code(), Some(0), "{}", shown(&output));
    assert_eq!(e2e.assert_requests_clean().await, ["new", "leaked"]);

    // The files exist and name both secrets by fingerprint only.
    for name in [".rotate/audit.jsonl", ".rotate/state.json"] {
        let text = std::fs::read_to_string(e2e.file(name)).unwrap();
        assert!(text.contains(&fp(&e2e.leaked.secret)), "{name}");
        assert!(text.contains(&fp(&e2e.new_secret)), "{name}");
    }
}
