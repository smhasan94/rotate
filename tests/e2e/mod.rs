//! The end-to-end harness shared by `e2e_aws.rs` (SHA-264) and
//! `acceptance_mvp.rs` (SHA-267).
//!
//! One wiremock server plays every API the real plugins call:
//!
//! - [`AwsModel`]: STS, IAM and Secrets Manager for one IAM user and the
//!   Secrets Manager entry `prod/app`, at priority 2 on every request.
//! - [`GithubModel`] (only with [`E2e::start_with_github`]): the Actions
//!   secrets of `acme/api`, at priority 1 on `/repos/` and `/orgs/` paths
//!   so it answers ahead of the AWS model. It holds a `crypto_box` key pair,
//!   serves the public half, and opens every sealed `PUT` with the private
//!   half, so a test can check what was written.
//!
//! [`E2e::run`] runs the binary in a cleared environment at `-vvv` with
//! `RUST_LOG=trace` and checks stdout, stderr, the audit log and the state
//! file for both secret access keys (and the GitHub token) on every run.
//!
//! Each test binary that uses this module also declares `mod common;`.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Value};
use wiremock::matchers::{any, path_regex};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

use rotate::secret::SecretValue;

use crate::common::CallRecorder;

pub const ACCOUNT: &str = "000000000000";
pub const USER: &str = "deploy-bot";
pub const SECRET_ID: &str = "prod/app";
pub const REGION: &str = "us-east-1";
pub const SM_TARGET: &str = "x-amz-target";
pub const PAIR_REF: &str =
    "aws-secrets-manager:prod/app#$.AWS_SECRET_ACCESS_KEY|$.AWS_ACCESS_KEY_ID";
pub const FIXTURE: &str = include_str!("../fixtures/trufflehog_aws_e2e.ndjson");

/// A 20-char key id: `AKIA`, 9 chars of the documentation example, then a
/// 7-char tag, so it is never the example itself (which rotate reports
/// invalid without a call).
pub fn key_id(tag: &str) -> String {
    assert_eq!(tag.len(), 7);
    let doc = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
    format!("AKIA{}{tag}", &doc[4..13])
}

/// A 40-char secret access key with an 8-char tag.
pub fn secret(tag: &str) -> String {
    assert_eq!(tag.len(), 8);
    ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", tag, "Q0"].concat()
}

pub fn fp(value: &str) -> String {
    SecretValue::from(value).fingerprint().to_string()
}

pub fn user_arn() -> String {
    format!("arn:aws:iam::{ACCOUNT}:user/{USER}")
}

/// The IAM user the operator's credentials belong to.
pub fn operator_arn() -> String {
    format!("arn:aws:iam::{ACCOUNT}:user/rotate-operator")
}

/// The JSON a Secrets Manager entry holds for a key pair.
pub fn pair_json(id: &str, secret: &str) -> String {
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
pub struct Key {
    pub id: String,
    pub secret: String,
    pub status: &'static str,
}

pub struct State {
    pub operator: String,
    pub keys: Vec<Key>,
    /// What the next `CreateAccessKey` mints.
    pub next_key: (String, String),
    /// Versions of `prod/app`, oldest first.
    pub versions: Vec<(String, String)>,
    pub tokens: BTreeMap<String, String>,
    pub deny_put: bool,
    /// Every operation in order, as `Action` or the Secrets Manager target
    /// without its prefix.
    pub ops: Vec<String>,
    /// The operator's IAM policy as a set of actions (`iam:CreateAccessKey`).
    /// When set, every operator call outside it is denied and
    /// `SimulatePrincipalPolicy` answers from it (SHA-270). When unset,
    /// every operator call is allowed and the simulation is denied.
    pub policy: Option<BTreeSet<String>>,
    /// Every `SimulatePrincipalPolicy` request, as `(principal, actions,
    /// resources)`.
    pub simulations: Vec<(String, Vec<String>, Vec<String>)>,
}

/// An AWS account with one IAM user and one Secrets Manager entry.
#[derive(Clone)]
pub struct AwsModel(Arc<Mutex<State>>);

impl AwsModel {
    pub fn new(operator: &str, leaked: &Key, next_key: (String, String)) -> Self {
        Self(Arc::new(Mutex::new(State {
            operator: operator.to_owned(),
            keys: vec![leaked.clone()],
            next_key,
            versions: vec![("v1".into(), pair_json(&leaked.id, &leaked.secret))],
            tokens: BTreeMap::new(),
            deny_put: false,
            ops: Vec::new(),
            policy: None,
            simulations: Vec::new(),
        })))
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    pub fn status(&self, id: &str) -> Option<&'static str> {
        self.state()
            .keys
            .iter()
            .find(|k| k.id == id)
            .map(|k| k.status)
    }

    pub fn key_ids(&self) -> Vec<String> {
        self.state().keys.iter().map(|k| k.id.clone()).collect()
    }

    /// The current value of `prod/app`, parsed.
    pub fn secret_json(&self) -> Value {
        let state = self.state();
        serde_json::from_str(&state.versions.last().unwrap().1).unwrap()
    }

    pub fn versions(&self) -> usize {
        self.state().versions.len()
    }

    pub fn ops(&self) -> Vec<String> {
        self.state().ops.clone()
    }

    pub fn count(&self, op: &str) -> usize {
        self.state().ops.iter().filter(|o| *o == op).count()
    }

    /// Everything the model holds, for "unchanged" comparisons.
    pub fn snapshot(&self) -> (Vec<Key>, Vec<(String, String)>) {
        let state = self.state();
        (state.keys.clone(), state.versions.clone())
    }
}

pub fn xml(status: u16, body: String) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "text/xml")
        .set_body_string(body)
}

pub fn query_error(status: u16, code: &str) -> ResponseTemplate {
    xml(
        status,
        format!(
            "<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code>\
             <Message>{code}</Message></Error><RequestId>req-e</RequestId></ErrorResponse>"
        ),
    )
}

pub fn query_ok(ns: &str, action: &str, result: &str) -> ResponseTemplate {
    xml(
        200,
        format!(
            "<{action}Response xmlns=\"{ns}\"><{action}Result>{result}</{action}Result>\
             <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></{action}Response>"
        ),
    )
}

pub fn iam_ok(action: &str, result: &str) -> ResponseTemplate {
    query_ok("https://iam.amazonaws.com/doc/2010-05-08/", action, result)
}

pub fn sm_json(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "application/x-amz-json-1.1")
        .set_body_string(body.to_string())
}

pub fn sm_error(kind: &str) -> ResponseTemplate {
    sm_json(400, json!({ "__type": kind, "message": kind }))
}

/// The key id a request was signed with (SigV4 `Credential=<id>/...`).
pub fn signer(req: &Request) -> Option<String> {
    let auth = req.headers.get("authorization")?.to_str().ok()?;
    let rest = auth.split("Credential=").nth(1)?;
    rest.split('/').next().map(str::to_owned)
}

pub fn sm_target(req: &Request) -> Option<&str> {
    req.headers
        .get(SM_TARGET)
        .and_then(|v| v.to_str().ok())
        .and_then(|t| t.strip_prefix("secretsmanager."))
}

/// Decoded fields of a query-protocol form body.
pub fn fields(body: &[u8]) -> BTreeMap<String, String> {
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
    pub fn key(&self, id: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.id == id)
    }

    pub fn sts(&self, signer: &str) -> ResponseTemplate {
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

    pub fn key_member(key: &Key) -> String {
        format!(
            "<member><UserName>{USER}</UserName><AccessKeyId>{}</AccessKeyId>\
             <Status>{}</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate></member>",
            key.id, key.status
        )
    }

    pub fn iam(&mut self, action: &str, form: &BTreeMap<String, String>) -> ResponseTemplate {
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
            "SimulatePrincipalPolicy" => {
                let list = |prefix: &str| -> Vec<String> {
                    form.iter()
                        .filter(|(k, _)| k.starts_with(prefix))
                        .map(|(_, v)| v.clone())
                        .collect()
                };
                let actions = list("ActionNames.member.");
                let resources = list("ResourceArns.member.");
                let principal = form.get("PolicySourceArn").cloned().unwrap_or_default();
                self.simulations
                    .push((principal, actions.clone(), resources.clone()));
                let allowed = self.policy.clone().unwrap_or_default();
                let resource = resources.first().cloned().unwrap_or_else(|| "*".into());
                let members: String = actions
                    .iter()
                    .map(|a| {
                        let decision = if allowed.contains(a) {
                            "allowed"
                        } else {
                            "implicitDeny"
                        };
                        format!(
                            "<member><EvalActionName>{a}</EvalActionName>\
                             <EvalResourceName>{resource}</EvalResourceName>\
                             <EvalDecision>{decision}</EvalDecision>\
                             <MatchedStatements/><MissingContextValues/></member>"
                        )
                    })
                    .collect();
                iam_ok(
                    action,
                    &format!(
                        "<EvaluationResults>{members}</EvaluationResults>\
                         <IsTruncated>false</IsTruncated>"
                    ),
                )
            }
            _ => query_error(400, "InvalidAction"),
        }
    }

    /// False when a policy is set and does not allow `action`.
    pub fn allows(&self, action: &str) -> bool {
        self.policy.as_ref().is_none_or(|p| p.contains(action))
    }

    pub fn secrets_manager(&mut self, op: &str, body: &[u8]) -> ResponseTemplate {
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
            if signer != state.operator || !state.allows(&format!("secretsmanager:{op}")) {
                return sm_error("AccessDeniedException");
            }
            return state.secrets_manager(op, &req.body);
        }
        let form = fields(&req.body);
        let action = form.get("Action").cloned().unwrap_or_default();
        state.ops.push(action.clone());
        if action == "GetCallerIdentity" {
            // The operator asks for its own ARN (`--check-permissions`).
            // GetCallerIdentity needs no permission.
            if signer == state.operator {
                return query_ok(
                    "https://sts.amazonaws.com/doc/2011-06-15/",
                    "GetCallerIdentity",
                    &format!(
                        "<Arn>{}</Arn><UserId>AIDAE2EOPERATOR</UserId><Account>{ACCOUNT}</Account>",
                        operator_arn()
                    ),
                );
            }
            return state.sts(&signer);
        }
        // Decision D3: only the operator's own credentials touch IAM.
        if signer != state.operator {
            return query_error(403, "AccessDenied");
        }
        let simulation_denied = action == "SimulatePrincipalPolicy" && state.policy.is_none();
        if simulation_denied || !state.allows(&format!("iam:{action}")) {
            return query_error(403, "AccessDenied");
        }
        state.iam(&action, &form)
    }
}

// ---------------------------------------------------------------------------
// The GitHub model
// ---------------------------------------------------------------------------

/// The repository whose Actions secrets the model holds.
pub const REPO: &str = "acme/api";
/// The Actions secrets path of [`REPO`].
pub const REPO_SECRETS: &str = "/repos/acme/api/actions/secrets";
/// The id GitHub gives the repository's public key.
pub const GH_KEY_ID: &str = "568250167242549743";
/// The Actions secret names the AWS convention (decision D4) looks for.
pub const GH_KEY_ID_NAME: &str = "AWS_ACCESS_KEY_ID";
pub const GH_SECRET_NAME: &str = "AWS_SECRET_ACCESS_KEY";
/// A secret in the repository that has nothing to do with AWS.
pub const GH_UNRELATED: &str = "SLACK_WEBHOOK";

pub struct GithubState {
    token: String,
    secret_key: crypto_box::SecretKey,
    /// Current plaintext per secret name. Actions secrets cannot be read
    /// back through the API; only the test sees these.
    pub values: BTreeMap<String, String>,
    /// Every accepted `PUT`, in order, as `(name, plaintext)`.
    pub puts: Vec<(String, String)>,
    /// Answer every `PUT` with 403.
    pub deny_put: bool,
    /// Answer `GET .../public-key` with 403 (SHA-270).
    pub deny_public_key: bool,
    /// The `x-oauth-scopes` header of every answer, as for a classic token.
    pub scopes: Option<String>,
    /// Every request, as `METHOD path`.
    pub ops: Vec<String>,
}

/// The Actions secrets of [`REPO`], with the repository's sealed-box key
/// pair.
#[derive(Clone)]
pub struct GithubModel(Arc<Mutex<GithubState>>);

impl GithubModel {
    /// `REPO` holding `key_id` and `secret` under the convention names, plus
    /// an unrelated secret; requests must carry `Bearer <token>`.
    pub fn new(token: &str, key_id: &str, secret: &str) -> Self {
        let values = [
            (GH_KEY_ID_NAME, key_id),
            (GH_SECRET_NAME, secret),
            (GH_UNRELATED, "https://hooks.example.invalid/x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        Self(Arc::new(Mutex::new(GithubState {
            token: token.to_owned(),
            secret_key: crypto_box::SecretKey::from([0x5a; 32]),
            values,
            puts: Vec::new(),
            deny_put: false,
            deny_public_key: false,
            scopes: None,
            ops: Vec::new(),
        })))
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, GithubState> {
        self.0.lock().unwrap()
    }

    /// The current plaintext of `name`.
    pub fn value(&self, name: &str) -> String {
        self.state().values[name].clone()
    }

    pub fn puts(&self) -> Vec<(String, String)> {
        self.state().puts.clone()
    }

    /// The names written by `PUT`, in order.
    pub fn put_names(&self) -> Vec<String> {
        self.puts().into_iter().map(|(n, _)| n).collect()
    }

    /// Opens a sealed `encrypted_value` with the repository's private key.
    pub fn open(&self, encrypted_b64: &str) -> Option<String> {
        let bytes = BASE64.decode(encrypted_b64).ok()?;
        let plain = self.state().secret_key.unseal(&bytes).ok()?;
        String::from_utf8(plain).ok()
    }
}

fn gh_json(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "application/json")
        .set_body_string(body.to_string())
}

fn gh_error(status: u16, message: &str) -> ResponseTemplate {
    gh_json(status, json!({ "message": message }))
}

/// True for a request the GitHub model owns.
pub fn is_github(req: &Request) -> bool {
    let path = req.url.path();
    path.starts_with("/repos/") || path.starts_with("/orgs/")
}

impl Respond for GithubModel {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let response = self.answer(req);
        match self.state().scopes.clone() {
            Some(scopes) => response.insert_header("x-oauth-scopes", scopes.as_str()),
            None => response,
        }
    }
}

impl GithubModel {
    fn answer(&self, req: &Request) -> ResponseTemplate {
        let method = req.method.as_str().to_owned();
        let path = req.url.path().to_owned();
        let mut state = self.0.lock().unwrap();
        state.ops.push(format!("{method} {path}"));
        let bearer = req
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if bearer != Some(state.token.as_str()) {
            return gh_error(401, "Bad credentials");
        }
        let Some(rest) = path.strip_prefix(REPO_SECRETS) else {
            return gh_error(404, "Not Found");
        };
        match (method.as_str(), rest) {
            ("GET", "") => {
                let secrets: Vec<Value> = state
                    .values
                    .keys()
                    .map(|name| {
                        json!({
                            "name": name,
                            "created_at": "2026-01-01T00:00:00Z",
                            "updated_at": "2026-01-01T00:00:00Z",
                        })
                    })
                    .collect();
                gh_json(
                    200,
                    json!({ "total_count": secrets.len(), "secrets": secrets }),
                )
            }
            ("GET", "/public-key") => {
                if state.deny_public_key {
                    return gh_error(403, "Resource not accessible by personal access token");
                }
                let key = BASE64.encode(state.secret_key.public_key().as_bytes());
                gh_json(200, json!({ "key_id": GH_KEY_ID, "key": key }))
            }
            ("PUT", name) => {
                let name = name.trim_start_matches('/').to_owned();
                if state.deny_put {
                    return gh_error(403, "Resource not accessible by integration");
                }
                let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                if body["key_id"] != GH_KEY_ID {
                    return gh_error(422, "key_id does not match the repository key");
                }
                let sealed = body["encrypted_value"].as_str().unwrap_or("");
                let plain = BASE64
                    .decode(sealed)
                    .ok()
                    .and_then(|b| state.secret_key.unseal(&b).ok())
                    .and_then(|p| String::from_utf8(p).ok());
                let Some(plain) = plain else {
                    return gh_error(422, "encrypted_value is not sealed for this key");
                };
                let created = !state.values.contains_key(&name);
                state.values.insert(name.clone(), plain.clone());
                state.puts.push((name, plain));
                ResponseTemplate::new(if created { 201 } else { 204 })
            }
            _ => gh_error(404, "Not Found"),
        }
    }
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// Calls that change state. Everything else the model answers is a read.
pub const MUTATING: &[&str] = &["CreateAccessKey", "UpdateAccessKey", "PutSecretValue"];

pub struct E2e {
    pub rec: CallRecorder,
    pub model: AwsModel,
    /// The Actions secrets, when started with [`E2e::start_with_github`].
    pub github: Option<GithubModel>,
    pub github_token: String,
    pub dir: tempfile::TempDir,
    pub operator_id: String,
    pub operator_secret: String,
    pub leaked: Key,
    pub new_id: String,
    pub new_secret: String,
    /// What a second `CreateAccessKey` mints, after
    /// [`E2e::next_replacement`].
    pub second_id: String,
    pub second_secret: String,
    /// The variable [`E2e::run`] passes the GitHub token in.
    pub token_var: Mutex<&'static str>,
}

impl E2e {
    /// A user holding only the leaked key, referenced by `prod/app`.
    pub async fn start() -> Self {
        Self::start_inner(false).await
    }

    /// As [`E2e::start`], and the leaked pair is also held by the Actions
    /// secrets of `acme/api`, which `rotate.yaml` lists.
    pub async fn start_with_github() -> Self {
        Self::start_inner(true).await
    }

    /// The `GithubModel`; panics without one.
    pub fn gh(&self) -> &GithubModel {
        self.github.as_ref().expect("started with_github")
    }

    /// Makes the next `CreateAccessKey` mint the second pair.
    pub fn next_replacement(&self) {
        self.model.state().next_key = (self.second_id.clone(), self.second_secret.clone());
    }

    async fn start_inner(with_github: bool) -> Self {
        let operator_id = key_id("OPERATR");
        let operator_secret = ["operatorSecretFromTheChain", "0000000000000x"].concat();
        let leaked = Key {
            id: key_id("E2ELEAK"),
            secret: secret("e2eLeak1"),
            status: "Active",
        };
        let (new_id, new_secret) = (key_id("E2ENEWK"), secret("e2eNewK1"));
        let model = AwsModel::new(&operator_id, &leaked, (new_id.clone(), new_secret.clone()));
        let github_token = ["e2e-operator-gh-token-", "7c41d0"].concat();
        let mut rec = CallRecorder::start().await;
        // Priority 1 is wiremock's highest: the GitHub routes answer ahead
        // of the AWS model, which takes everything else.
        let github = if with_github {
            let gh = GithubModel::new(&github_token, &leaked.id, &leaked.secret);
            Mock::given(path_regex("^/(repos|orgs)/"))
                .respond_with(gh.clone())
                .with_priority(1)
                .mount(rec.server())
                .await;
            Some(gh)
        } else {
            None
        };
        Mock::given(any())
            .respond_with(model.clone())
            .with_priority(2)
            .mount(rec.server())
            .await;
        // AWS sends every call as a POST; only the ones in MUTATING change
        // state. GitHub requests are classified by method (a PUT mutates).
        rec.mark_read_only(|req| {
            if is_github(req) {
                return false;
            }
            if let Some(op) = sm_target(req) {
                return !MUTATING.contains(&op);
            }
            let action = fields(&req.body).get("Action").cloned().unwrap_or_default();
            !MUTATING.contains(&action.as_str())
        });
        let e2e = Self {
            rec,
            model,
            github,
            github_token,
            dir: tempfile::tempdir().unwrap(),
            operator_id,
            operator_secret,
            leaked,
            new_id,
            new_secret,
            second_id: key_id("E2E2NDK"),
            second_secret: secret("e2e2ndK1"),
            token_var: Mutex::new("ROTATE_GITHUB_TOKEN"),
        };
        e2e.write_inputs();
        e2e
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.path().join(name)
    }

    /// The report (the fixture with this run's key), `rotate.yaml` naming
    /// the Secrets Manager entry and the endpoint, and the scenario.
    pub fn write_inputs(&self) {
        let report = FIXTURE
            .replace("@KEY_ID@", &self.leaked.id)
            .replace("@SECRET@", &self.leaked.secret);
        std::fs::write(self.file("report.ndjson"), report).unwrap();
        let uri = self.rec.uri();
        let config = if self.github.is_some() {
            format!(
                "consumers:\n  aws_secrets_manager:\n    secrets: [{SECRET_ID}]\n\
                 \x20 github_actions:\n    targets: [{REPO}]\n\
                 providers:\n  aws:\n    region: {REGION}\n    endpoint_url: {uri}\n\
                 \x20 github:\n    api_url: {uri}\n"
            )
        } else {
            format!(
                "consumers:\n  aws_secrets_manager:\n    secrets: [{SECRET_ID}]\n\
                 providers:\n  aws:\n    region: {REGION}\n    endpoint_url: {uri}\n"
            )
        };
        std::fs::write(self.file("rotate.yaml"), config).unwrap();
        let scenario = json!({ "real_plugins": true, "prompt": "panic" });
        std::fs::write(self.file("scenario.json"), scenario.to_string()).unwrap();
    }

    /// Runs `rotate -vvv <args>` in a cleared environment and checks its
    /// stdout and stderr, and the audit log and state file, for both secret
    /// access keys (T8).
    pub fn run(&self, args: &[&str]) -> Output {
        let home = self.file("home");
        std::fs::create_dir_all(&home).unwrap();
        // Empty AWS files: no profile, and no "file not found" warnings.
        for name in ["aws-config", "aws-credentials"] {
            std::fs::write(home.join(name), "").unwrap();
        }
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("rotate"));
        command.env_clear();
        if self.github.is_some() {
            let var = *self.token_var.lock().unwrap();
            command.env(var, &self.github_token);
        }
        let output = command
            .current_dir(self.path())
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
        let mut places = vec![
            (format!("{label}: stdout"), output.stdout.clone()),
            (format!("{label}: stderr"), output.stderr.clone()),
        ];
        for name in [".rotate/audit.jsonl", ".rotate/state.json"] {
            if let Ok(bytes) = std::fs::read(self.file(name)) {
                places.push((format!("{label}: {name}"), bytes));
            }
        }
        for (place, bytes) in &places {
            self.assert_clean(place, bytes);
            self.assert_no_token(place, bytes);
        }
        output
    }

    /// The GitHub operator token is not in `bytes`. Only requests may carry
    /// it, in their `authorization` header.
    pub fn assert_no_token(&self, place: &str, bytes: &[u8]) {
        assert!(
            !String::from_utf8_lossy(bytes).contains(&self.github_token),
            "{place} contains the GitHub token"
        );
    }

    /// `rotate --json plan` and the one rotation's id.
    pub fn rotation_id(&self) -> String {
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
    pub fn apply(&self) -> (String, Output) {
        let id = self.rotation_id();
        let output = self.run(&["apply", "report.ndjson", "--confirm", &id]);
        (id, output)
    }

    pub fn secrets(&self) -> [(&'static str, &str); 3] {
        [
            ("leaked secret", self.leaked.secret.as_str()),
            ("new secret", self.new_secret.as_str()),
            ("second new secret", self.second_secret.as_str()),
        ]
    }

    /// The key pairs a consumer may be written with, by label.
    fn pairs(&self) -> [(&'static str, &str, &str); 3] {
        [
            (
                "leaked",
                self.leaked.id.as_str(),
                self.leaked.secret.as_str(),
            ),
            ("new", self.new_id.as_str(), self.new_secret.as_str()),
            (
                "second",
                self.second_id.as_str(),
                self.second_secret.as_str(),
            ),
        ]
    }

    /// No secret access key, raw or URL-encoded, is in `bytes`. The
    /// failure message names where, never the value.
    pub fn assert_clean(&self, place: &str, bytes: &[u8]) {
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
    /// of those must hold exactly one pair. GitHub `PUT` bodies are sealed,
    /// so they are checked like any other body. No body carries the GitHub
    /// token. Returns the pairs written to Secrets Manager, in order, as
    /// "leaked", "new" or "second".
    pub async fn assert_requests_clean(&self) -> Vec<&'static str> {
        let requests = self.rec.server().received_requests().await.unwrap();
        let mut written = Vec::new();
        for (i, req) in requests.iter().enumerate() {
            let op = if is_github(req) {
                format!("{} {}", req.method, req.url.path())
            } else {
                sm_target(req)
                    .map(str::to_owned)
                    .unwrap_or_else(|| fields(&req.body).get("Action").cloned().unwrap_or_default())
            };
            for (name, value) in req.headers.iter() {
                let value = value.to_str().unwrap_or("");
                self.assert_clean(
                    &format!("request {i} ({op}) header {name}"),
                    value.as_bytes(),
                );
            }
            self.assert_no_token(&format!("request {i} ({op}) body"), &req.body);
            if op == "PutSecretValue" {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                let stored: Value =
                    serde_json::from_str(body["SecretString"].as_str().unwrap()).unwrap();
                let held: Vec<_> = self
                    .pairs()
                    .into_iter()
                    .filter(|(_, id, secret)| {
                        stored["AWS_ACCESS_KEY_ID"] == *id
                            && stored["AWS_SECRET_ACCESS_KEY"] == *secret
                    })
                    .collect();
                assert_eq!(
                    held.len(),
                    1,
                    "request {i}: PutSecretValue holds no known pair"
                );
                let (label, _, own) = held[0];
                let text = String::from_utf8_lossy(&req.body);
                for (_, other) in self.secrets() {
                    assert!(
                        other == own || !text.contains(other),
                        "request {i}: PutSecretValue carries two secrets"
                    );
                }
                assert_eq!(stored["DATABASE_HOST"], "db.internal", "request {i}");
                written.push(label);
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
    pub async fn non_operator_calls(&self) -> Vec<String> {
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

    pub fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.file(".rotate/audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    pub fn rotation(&self, id: &str) -> Value {
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
    pub fn assert_secret_holds(&self, id: &str, secret: &str) {
        let stored = self.model.secret_json();
        assert_eq!(stored["AWS_ACCESS_KEY_ID"], id);
        assert!(
            stored["AWS_SECRET_ACCESS_KEY"] == secret,
            "prod/app does not hold the expected secret"
        );
        assert_eq!(stored["DATABASE_HOST"], "db.internal");
    }
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// stdout and the tail of stderr (`-vvv` makes it long), for failures.
pub fn shown(output: &Output) -> String {
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
