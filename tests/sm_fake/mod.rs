//! Shared by the SHA-252 test binaries: a minimal Secrets Manager speaking
//! the AWS JSON protocol on a wiremock server, keeping secret versions.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aws_sdk_secretsmanager::config::retry::RetryConfig;
use aws_sdk_secretsmanager::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_secretsmanager::Client;
use serde_json::{json, Value};
use wiremock::matchers::any;
use wiremock::{Mock, Request, Respond, ResponseTemplate};

use rotate::config::SecretsManagerConfig;
use rotate::consumer::aws_secrets_manager::SecretsManagerConsumer;
use rotate::provider::Credential;
use rotate::secret::{SecretPair, SecretValue};

use crate::common;

pub const TARGET: &str = "x-amz-target";
pub const GET: &str = "secretsmanager.GetSecretValue";
pub const PUT: &str = "secretsmanager.PutSecretValue";
pub const LIST: &str = "secretsmanager.ListSecrets";

pub fn pair(key_id: &str, secret: &str) -> Credential {
    Credential::KeyPair(SecretPair::new(key_id, SecretValue::from(secret)))
}

pub fn token(secret: &str) -> Credential {
    Credential::Token(SecretValue::from(secret))
}

/// One stored secret: its versions in order and the denial, if any.
#[derive(Default)]
struct Entry {
    versions: Vec<(String, String)>,
    denied: bool,
}

#[derive(Default)]
struct State {
    secrets: BTreeMap<String, Entry>,
    /// `ListSecrets` pages, each a list of `SecretListEntry` JSON objects.
    pages: Vec<Vec<Value>>,
    /// Tokens already used, with the version each created.
    tokens: BTreeMap<String, String>,
}

/// A minimal Secrets Manager: versions per secret, denials, paged listing.
#[derive(Clone, Default)]
pub struct FakeSecretsManager(Arc<Mutex<State>>);

impl FakeSecretsManager {
    pub fn put(&self, id: &str, value: &str) -> &Self {
        let mut state = self.0.lock().unwrap();
        let entry = state.secrets.entry(id.to_owned()).or_default();
        let version = format!("v{}", entry.versions.len() + 1);
        entry.versions.push((version, value.to_owned()));
        self
    }

    pub fn deny(&self, id: &str) -> &Self {
        let mut state = self.0.lock().unwrap();
        state.secrets.entry(id.to_owned()).or_default().denied = true;
        self
    }

    pub fn pages(&self, pages: Vec<Vec<Value>>) -> &Self {
        self.0.lock().unwrap().pages = pages;
        self
    }

    pub fn current(&self, id: &str) -> Option<String> {
        let state = self.0.lock().unwrap();
        state
            .secrets
            .get(id)?
            .versions
            .last()
            .map(|(_, v)| v.clone())
    }
}

pub fn aws_json(status: u16, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "application/x-amz-json-1.1")
        .set_body_string(body.to_string())
}

pub fn aws_error(kind: &str, message: &str) -> ResponseTemplate {
    aws_json(400, json!({ "__type": kind, "message": message }))
}

pub fn target(req: &Request) -> &str {
    req.headers
        .get(TARGET)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

impl Respond for FakeSecretsManager {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let id = body["SecretId"].as_str().unwrap_or("").to_owned();
        let mut state = self.0.lock().unwrap();
        match target(req) {
            GET => match state.secrets.get(&id) {
                Some(entry) if entry.denied => aws_error(
                    "AccessDeniedException",
                    "User is not authorized to perform secretsmanager:GetSecretValue",
                ),
                Some(entry) if !entry.versions.is_empty() => {
                    let (version, value) = entry.versions.last().unwrap();
                    aws_json(
                        200,
                        json!({
                            "ARN": format!("arn:aws:secretsmanager:us-east-1:000000000000:secret:{id}"),
                            "Name": id,
                            "VersionId": version,
                            "SecretString": value,
                            "VersionStages": ["AWSCURRENT"],
                        }),
                    )
                }
                _ => aws_error(
                    "ResourceNotFoundException",
                    "Secrets Manager can't find the specified secret.",
                ),
            },
            PUT => {
                let token = body["ClientRequestToken"].as_str().unwrap_or("").to_owned();
                let value = body["SecretString"].as_str().unwrap_or("").to_owned();
                if let Some(version) = state.tokens.get(&token).cloned() {
                    return aws_json(200, json!({ "Name": id, "VersionId": version }));
                }
                let Some(entry) = state.secrets.get_mut(&id) else {
                    return aws_error("ResourceNotFoundException", "not found");
                };
                let version = format!("v{}", entry.versions.len() + 1);
                entry.versions.push((version.clone(), value));
                state.tokens.insert(token, version.clone());
                aws_json(200, json!({ "Name": id, "VersionId": version }))
            }
            LIST => {
                let page = match body["NextToken"].as_str() {
                    None => 0,
                    Some(t) => t.trim_start_matches('p').parse().unwrap_or(usize::MAX),
                };
                let entries = state.pages.get(page).cloned().unwrap_or_default();
                let mut out = json!({ "SecretList": entries });
                if page + 1 < state.pages.len() {
                    out["NextToken"] = json!(format!("p{}", page + 1));
                }
                aws_json(200, out)
            }
            _ => aws_error("UnknownOperationException", "unknown operation"),
        }
    }
}

/// A recorder with the fake mounted ahead of its catch-all, and
/// `GetSecretValue` and `ListSecrets` marked read-only.
pub async fn server(fake: &FakeSecretsManager) -> common::CallRecorder {
    let mut rec = common::CallRecorder::start().await;
    Mock::given(any())
        .respond_with(fake.clone())
        .with_priority(2)
        .mount(rec.server())
        .await;
    rec.mark_read_only(|req| matches!(target(req), GET | LIST));
    rec
}

pub fn client(uri: &str) -> Client {
    let config = aws_sdk_secretsmanager::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(uri)
        .credentials_provider(Credentials::new(
            "test-access-key",
            "test-secret-key",
            None,
            None,
            "test",
        ))
        .retry_config(RetryConfig::disabled())
        .build();
    Client::from_conf(config)
}

pub fn names(secrets: &[&str]) -> SecretsManagerConfig {
    SecretsManagerConfig {
        secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
        ..SecretsManagerConfig::default()
    }
}

pub fn consumer(
    rec: &common::CallRecorder,
    config: SecretsManagerConfig,
) -> SecretsManagerConsumer {
    SecretsManagerConsumer::with_client(config, client(&rec.uri()))
}

/// Bodies of every `PutSecretValue` the server received, parsed.
pub async fn puts(rec: &common::CallRecorder) -> Vec<Value> {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| target(r) == PUT)
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

pub async fn count(rec: &common::CallRecorder, operation: &str) -> usize {
    rec.server()
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| target(r) == operation)
        .count()
}

pub fn pair_json(key_id: &str, secret: &str) -> String {
    json!({ "AWS_ACCESS_KEY_ID": key_id, "AWS_SECRET_ACCESS_KEY": secret, "other": "x" })
        .to_string()
}

pub const PAIR_REF: &str =
    "aws-secrets-manager:prod/app#$.AWS_SECRET_ACCESS_KEY|$.AWS_ACCESS_KEY_ID";
