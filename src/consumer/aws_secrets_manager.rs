//! AWS Secrets Manager consumer (SHA-252).
//!
//! Secrets Manager values can be read back, so entries are matched by the
//! fingerprint of their value (decision D4), never by name. A plain entry
//! matches when its whole value is the secret (path `$`). A JSON object
//! entry matches when a top-level string field holds the secret; when the
//! secret is an AWS key pair, the field holding the access key id is
//! recorded too and both are rewritten in one `PutSecretValue`.
//!
//! The paths are part of the consumer ref, so `update` and `restore` work
//! from the ref alone, also in a later process after an overlap window:
//!
//! ```text
//! aws-secrets-manager:prod/app#$.AWS_SECRET_ACCESS_KEY|$.AWS_ACCESS_KEY_ID
//! aws-secrets-manager:prod/token#$
//! ```
//!
//! Secret ids never contain `#`. In a key, `%`, `,` and `|` are written as
//! `%25`, `%2C` and `%7C`. An entry rotate cannot read is listed without
//! paths (`aws-secrets-manager:prod/locked`), matched by name and not
//! updatable.
//!
//! Construction makes no call and loads no credentials. The SDK client is
//! built from the standard AWS environment on the first call that needs it,
//! and an empty `consumers.aws_secrets_manager` section makes no call at all.

use std::fmt;

use async_trait::async_trait;
use aws_sdk_secretsmanager::config::{BehaviorVersion, Region};
use aws_sdk_secretsmanager::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_secretsmanager::primitives::Blob;
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType, SecretListEntry};
use aws_sdk_secretsmanager::Client;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use zeroize::Zeroizing;

use super::{Consumer, ConsumerError, ConsumerMatch, Holds, SecretRef, UpdateReceipt};
use crate::config::{SecretsManagerConfig, TagFilter};
use crate::provider::Credential;
use crate::secret::SecretValue;

/// The consumer's name in plans, config and the audit log.
pub const NAME: &str = "aws-secrets-manager";

/// Prefix of every client request token rotate sends.
const TOKEN_PREFIX: &str = "rotate-";
/// Hex characters of the digest kept in a token (AWS allows 32 to 64).
const TOKEN_HEX_LEN: usize = 40;

/// Secrets Manager entries named in `rotate.yaml` or selected by tag.
pub struct SecretsManagerConsumer {
    config: SecretsManagerConfig,
    region: Option<String>,
    endpoint_url: Option<String>,
    client: OnceCell<Client>,
}

impl SecretsManagerConsumer {
    /// A consumer for `config`, using `region` (or the AWS environment's
    /// region when `None`). Makes no call and loads no credentials.
    pub fn new(config: SecretsManagerConfig, region: Option<String>) -> Self {
        Self {
            config,
            region,
            endpoint_url: None,
            client: OnceCell::new(),
        }
    }

    /// Sends Secrets Manager calls to `url` instead of AWS
    /// (`providers.aws.endpoint_url`, SHA-264). Makes no call.
    pub fn with_endpoint_url(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    /// A consumer that uses `client` instead of building one, for tests
    /// against a local server.
    pub fn with_client(config: SecretsManagerConfig, client: Client) -> Self {
        Self {
            config,
            region: None,
            endpoint_url: None,
            client: OnceCell::new_with(Some(client)),
        }
    }

    async fn client(&self) -> &Client {
        self.client
            .get_or_init(|| async {
                let mut loader = aws_config::defaults(BehaviorVersion::latest());
                if let Some(region) = &self.region {
                    loader = loader.region(Region::new(region.clone()));
                }
                if let Some(url) = &self.endpoint_url {
                    loader = loader.endpoint_url(url.clone());
                }
                Client::new(&loader.load().await)
            })
            .await
    }

    /// Configured names first, then every entry a tag filter selects,
    /// without duplicates.
    async fn candidates(&self, client: &Client) -> Result<Vec<String>, ConsumerError> {
        let mut ids: Vec<String> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for id in &self.config.secrets {
            if !seen.contains(id) {
                seen.push(id.clone());
                ids.push(id.clone());
            }
        }
        for filter in &self.config.tag_filters {
            for entry in list_tagged(client, filter).await? {
                let (Some(name), arn) = (entry.name, entry.arn) else {
                    continue;
                };
                let known = seen.contains(&name) || arn.as_ref().is_some_and(|a| seen.contains(a));
                if known {
                    continue;
                }
                seen.push(name.clone());
                if let Some(arn) = arn {
                    seen.push(arn);
                }
                ids.push(name);
            }
        }
        Ok(ids)
    }

    /// Writes `credential` at the paths in `target`'s ref.
    async fn write(
        &self,
        target: &ConsumerMatch,
        credential: &Credential,
    ) -> Result<UpdateReceipt, ConsumerError> {
        if let Err(reason) = &target.updatable {
            return Err(ConsumerError::NotUpdatable(reason.clone()));
        }
        target.value_fingerprint(credential)?;
        let location = Location::parse(&target.consumer_ref)?;
        if !location.key_id_paths.is_empty() && credential.key_id().is_none() {
            return Err(ConsumerError::Unsupported(format!(
                "{} stores an access key id but the credential is a single token",
                target.consumer_ref
            )));
        }
        let client = self.client().await;
        let current = match read(client, &location.secret_id).await {
            Ok(Some(current)) => current,
            Ok(None) => {
                return Err(ConsumerError::Permanent(format!(
                    "{}: the secret no longer exists; re-run plan",
                    location.secret_id
                )))
            }
            Err(ReadError::Unreadable(reason)) => return Err(ConsumerError::Permanent(reason)),
            Err(ReadError::Failed(err)) => return Err(err),
        };
        let Current {
            version_id,
            mut stored,
            binary,
        } = current;
        let changed = stored.substitute(&location, credential)?;
        if !changed {
            tracing::debug!(
                consumer = NAME,
                secret_id = %location.secret_id,
                "value already in place; nothing written"
            );
            return Ok(UpdateReceipt {
                consumer_ref: target.consumer_ref.clone(),
                version: version_id,
            });
        }
        let token = client_token(&target.consumer_ref, version_id.as_deref(), credential);
        let mut payload = stored.render()?;
        let request = client
            .put_secret_value()
            .secret_id(&location.secret_id)
            .client_request_token(token);
        // The SDK owns the value from here; its copy in the request body is
        // outside rotate's control.
        let request = if binary {
            request.secret_binary(Blob::new(std::mem::take(&mut *payload)))
        } else {
            match String::from_utf8(std::mem::take(&mut *payload)) {
                Ok(text) => request.secret_string(text),
                Err(err) => {
                    // Wipe the bytes the failed conversion hands back.
                    drop(Zeroizing::new(err.into_bytes()));
                    return Err(ConsumerError::Unsupported(format!(
                        "{}: the value is not UTF-8 text",
                        target.consumer_ref
                    )));
                }
            }
        };
        let output = request
            .send()
            .await
            .map_err(|err| failure("PutSecretValue", &location.secret_id, &err))?;
        tracing::debug!(
            consumer = NAME,
            secret_id = %location.secret_id,
            version = output.version_id().unwrap_or("-"),
            "wrote a new secret version"
        );
        Ok(UpdateReceipt {
            consumer_ref: target.consumer_ref.clone(),
            version: output.version_id,
        })
    }
}

impl fmt::Debug for SecretsManagerConsumer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretsManagerConsumer")
            .field("config", &self.config)
            .field("region", &self.region)
            .field("endpoint_url", &self.endpoint_url)
            .field("client_built", &self.client.initialized())
            .finish()
    }
}

#[async_trait]
impl Consumer for SecretsManagerConsumer {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn find(&self, secret: &SecretRef) -> Result<Vec<ConsumerMatch>, ConsumerError> {
        if self.config.secrets.is_empty() && self.config.tag_filters.is_empty() {
            return Ok(Vec::new());
        }
        let client = self.client().await;
        let candidates = self.candidates(client).await?;
        tracing::debug!(
            consumer = NAME,
            candidates = candidates.len(),
            fingerprint = %secret.fingerprint,
            "comparing Secrets Manager entries"
        );
        let mut found = Vec::new();
        for id in candidates {
            let current = match read(client, &id).await {
                Ok(Some(current)) => current,
                Ok(None) => {
                    tracing::warn!(consumer = NAME, secret_id = %id, "secret not found; skipped");
                    continue;
                }
                Err(ReadError::Unreadable(reason)) => {
                    found.push(
                        ConsumerMatch::by_name(format!("{NAME}:{id}"))
                            .not_updatable(format!("cannot read the value to compare: {reason}")),
                    );
                    continue;
                }
                Err(ReadError::Failed(err)) => return Err(err),
            };
            let keys = self.config.json_keys.as_deref();
            if let Some((secret_paths, key_id_paths)) = current.stored.locate(secret, keys) {
                let holds = if key_id_paths.is_empty() {
                    Holds::Secret
                } else {
                    Holds::KeyPair
                };
                let location = Location {
                    secret_id: id,
                    secret_paths,
                    key_id_paths,
                };
                found.push(ConsumerMatch::by_value(location.to_ref()).holding(holds));
            }
        }
        Ok(found)
    }

    async fn update(
        &self,
        target: &ConsumerMatch,
        new: &Credential,
    ) -> Result<UpdateReceipt, ConsumerError> {
        self.write(target, new).await
    }

    async fn restore(&self, target: &ConsumerMatch, old: &Credential) -> Result<(), ConsumerError> {
        self.write(target, old).await.map(|_| ())
    }
}

/// Every entry one tag filter selects, across all `ListSecrets` pages. AWS
/// applies `tag-key` and `tag-value` to any tag, so each entry is checked
/// for one tag that has both.
async fn list_tagged(
    client: &Client,
    filter: &TagFilter,
) -> Result<Vec<SecretListEntry>, ConsumerError> {
    let mut filters = vec![Filter::builder()
        .key(FilterNameStringType::TagKey)
        .values(filter.key.clone())
        .build()];
    if !filter.values.is_empty() {
        filters.push(
            Filter::builder()
                .key(FilterNameStringType::TagValue)
                .set_values(Some(filter.values.clone()))
                .build(),
        );
    }
    let mut entries = Vec::new();
    let mut next: Option<String> = None;
    loop {
        let page = client
            .list_secrets()
            .set_filters(Some(filters.clone()))
            .set_next_token(next.take())
            .send()
            .await
            .map_err(|err| failure("ListSecrets", &format!("tag {}", filter.key), &err))?;
        let accepted = page
            .secret_list
            .unwrap_or_default()
            .into_iter()
            .filter(|e| {
                e.tags().iter().any(|t| {
                    t.key() == Some(filter.key.as_str())
                        && (filter.values.is_empty()
                            || t.value()
                                .is_some_and(|v| filter.values.iter().any(|w| w == v)))
                })
            });
        entries.extend(accepted);
        match page.next_token {
            Some(token) if !token.is_empty() => next = Some(token),
            _ => break,
        }
    }
    Ok(entries)
}

/// The current value of a secret and its version.
struct Current {
    version_id: Option<String>,
    stored: Stored,
    binary: bool,
}

enum ReadError {
    /// The operator may not read it; the reason names the AWS error.
    Unreadable(String),
    /// Anything else; `find` fails with it.
    Failed(ConsumerError),
}

/// `GetSecretValue`. `None` when the secret does not exist or is scheduled
/// for deletion. The value goes into a [`SecretValue`] before anything else.
async fn read(client: &Client, id: &str) -> Result<Option<Current>, ReadError> {
    let output = match client.get_secret_value().secret_id(id).send().await {
        Ok(output) => output,
        Err(err) => {
            return match err.code() {
                Some("ResourceNotFoundException" | "InvalidRequestException") => Ok(None),
                Some("AccessDeniedException" | "DecryptionFailure") => {
                    Err(ReadError::Unreadable(error_text(&err)))
                }
                _ => Err(ReadError::Failed(failure("GetSecretValue", id, &err))),
            }
        }
    };
    let mut output = output;
    let version_id = output.version_id.take();
    let (value, binary) = match (output.secret_string.take(), output.secret_binary.take()) {
        (Some(text), _) => (SecretValue::from(text), false),
        (None, Some(blob)) => (SecretValue::from(blob.into_inner()), true),
        (None, None) => (SecretValue::from(""), false),
    };
    Ok(Some(Current {
        version_id,
        stored: Stored::parse(value, binary),
        binary,
    }))
}

/// `<code>: <message>` from an AWS error, never a request body.
fn error_text<E, R>(err: &SdkError<E, R>) -> String
where
    E: ProvideErrorMetadata,
{
    match (err.code(), err.message()) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code.to_owned(),
        _ => match err {
            SdkError::TimeoutError(_) => "request timed out".to_owned(),
            SdkError::DispatchFailure(_) => {
                "could not reach Secrets Manager (network or credentials)".to_owned()
            }
            SdkError::ConstructionFailure(_) => "could not build the request".to_owned(),
            SdkError::ResponseError(_) => "unreadable response from Secrets Manager".to_owned(),
            _ => "Secrets Manager call failed".to_owned(),
        },
    }
}

/// Maps an SDK error to the consumer contract's classes.
fn failure<E, R>(operation: &str, id: &str, err: &SdkError<E, R>) -> ConsumerError
where
    E: ProvideErrorMetadata,
{
    let text = format!("{operation} {id}: {}", error_text(err));
    match err.code() {
        Some(
            "ThrottlingException"
            | "Throttling"
            | "TooManyRequestsException"
            | "RequestLimitExceeded",
        ) => ConsumerError::RateLimited { retry_after: None },
        Some("InternalServiceError" | "InternalFailure" | "ServiceUnavailable") => {
            ConsumerError::Transient(text)
        }
        Some(_) => ConsumerError::Permanent(text),
        None => match err {
            SdkError::ConstructionFailure(_) => ConsumerError::Permanent(text),
            _ => ConsumerError::Transient(text),
        },
    }
}

/// Client request token for writing `credential` over the version
/// `version_id` of the entry `consumer_ref`. The same write over the same
/// version gets the same token, so a retry is one write to AWS.
fn client_token(consumer_ref: &str, version_id: Option<&str>, credential: &Credential) -> String {
    let mut hash = Sha256::new();
    for part in [
        consumer_ref,
        version_id.unwrap_or(""),
        credential.fingerprint().as_str(),
        credential.key_id().unwrap_or(""),
    ] {
        hash.update(part.as_bytes());
        hash.update(b"\n");
    }
    let mut token = String::with_capacity(TOKEN_PREFIX.len() + TOKEN_HEX_LEN);
    token.push_str(TOKEN_PREFIX);
    for byte in &hash.finalize()[..TOKEN_HEX_LEN / 2] {
        token.push_str(&format!("{byte:02x}"));
    }
    token
}

/// Where in an entry the credential sits.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Path {
    /// The whole value.
    Whole,
    /// A top-level key of a JSON object.
    Key(String),
}

/// An entry and the paths holding the secret and the key id.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Location {
    secret_id: String,
    secret_paths: Vec<Path>,
    key_id_paths: Vec<Path>,
}

impl Location {
    fn to_ref(&self) -> String {
        let join = |paths: &[Path]| {
            paths
                .iter()
                .map(|p| match p {
                    Path::Whole => "$".to_owned(),
                    Path::Key(key) => format!("$.{}", escape(key)),
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut text = format!("{NAME}:{}#{}", self.secret_id, join(&self.secret_paths));
        if !self.key_id_paths.is_empty() {
            text.push('|');
            text.push_str(&join(&self.key_id_paths));
        }
        text
    }

    fn parse(consumer_ref: &str) -> Result<Self, ConsumerError> {
        let invalid = || {
            ConsumerError::Permanent(format!(
                "{consumer_ref} is not a Secrets Manager reference with field paths; re-run plan"
            ))
        };
        let rest = consumer_ref
            .strip_prefix(NAME)
            .and_then(|r| r.strip_prefix(':'))
            .ok_or_else(invalid)?;
        let (secret_id, paths) = rest.split_once('#').ok_or_else(invalid)?;
        if secret_id.is_empty() {
            return Err(invalid());
        }
        let (secret_part, key_id_part) = match paths.split_once('|') {
            Some((s, k)) => (s, Some(k)),
            None => (paths, None),
        };
        let parse_list = |text: &str| -> Option<Vec<Path>> {
            text.split(',')
                .map(|p| match p {
                    "$" => Some(Path::Whole),
                    _ => p.strip_prefix("$.").and_then(unescape).map(Path::Key),
                })
                .collect()
        };
        let secret_paths = parse_list(secret_part).ok_or_else(invalid)?;
        let key_id_paths = match key_id_part {
            Some(text) => parse_list(text).ok_or_else(invalid)?,
            None => Vec::new(),
        };
        Ok(Self {
            secret_id: secret_id.to_owned(),
            secret_paths,
            key_id_paths,
        })
    }
}

fn escape(key: &str) -> String {
    key.replace('%', "%25")
        .replace(',', "%2C")
        .replace('|', "%7C")
}

fn unescape(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let code = rest.get(at + 1..at + 3)?;
        out.push(match code {
            "25" => '%',
            "2C" => ',',
            "7C" => '|',
            _ => return None,
        });
        rest = &rest[at + 3..];
    }
    if rest.contains([',', '|']) {
        return None;
    }
    out.push_str(rest);
    Some(out)
}

/// A secret's value: plain, or a JSON object whose strings are secrets.
enum Stored {
    Plain(SecretValue),
    Json(Document),
}

impl Stored {
    /// JSON when the text is a JSON object, plain otherwise. Binary values
    /// are always plain.
    fn parse(value: SecretValue, binary: bool) -> Self {
        if binary {
            return Stored::Plain(value);
        }
        let looks_like_object =
            value.expose_secret(|b| b.trim_ascii_start().first() == Some(&b'{'));
        if looks_like_object {
            if let Ok(document) = value.expose_secret(|b| serde_json::from_slice::<Document>(b)) {
                return Stored::Json(document);
            }
        }
        Stored::Plain(value)
    }

    /// The secret paths and key id paths when this value holds `secret`.
    fn locate(
        &self,
        secret: &SecretRef,
        keys: Option<&[String]>,
    ) -> Option<(Vec<Path>, Vec<Path>)> {
        match self {
            Stored::Plain(value) => {
                (value.fingerprint() == secret.fingerprint).then(|| (vec![Path::Whole], Vec::new()))
            }
            Stored::Json(document) => {
                let considered = |key: &str| keys.is_none_or(|k| k.iter().any(|c| c == key));
                let mut secret_paths = Vec::new();
                let mut key_id_paths = Vec::new();
                for (key, field) in &document.fields {
                    let Field::Secret(value) = field else {
                        continue;
                    };
                    if !considered(key) {
                        continue;
                    }
                    let path = Path::Key(key.clone());
                    if value.fingerprint() == secret.fingerprint {
                        if !secret_paths.contains(&path) {
                            secret_paths.push(path);
                        }
                    } else if let Some(key_id) = &secret.key_id {
                        if value.expose_secret(|b| b == key_id.as_bytes())
                            && !key_id_paths.contains(&path)
                        {
                            key_id_paths.push(path);
                        }
                    }
                }
                if secret_paths.is_empty() {
                    None
                } else {
                    Some((secret_paths, key_id_paths))
                }
            }
        }
    }

    /// Puts `credential` at the paths in `location`. True when anything
    /// changed.
    fn substitute(
        &mut self,
        location: &Location,
        credential: &Credential,
    ) -> Result<bool, ConsumerError> {
        let stale = |what: &str| {
            ConsumerError::Permanent(format!("{}: {what}; re-run plan", location.secret_id))
        };
        match self {
            Stored::Plain(value) => {
                if location.secret_paths != [Path::Whole] || !location.key_id_paths.is_empty() {
                    return Err(stale("the value is no longer a JSON object"));
                }
                let changed = value != credential.secret();
                *value = credential.secret().clone();
                Ok(changed)
            }
            Stored::Json(document) => {
                let key_id = credential.key_id().map(SecretValue::from);
                let mut changed = false;
                let writes = location
                    .secret_paths
                    .iter()
                    .map(|p| (p, credential.secret()))
                    .chain(
                        key_id
                            .iter()
                            .flat_map(|k| location.key_id_paths.iter().map(move |p| (p, k))),
                    );
                for (path, new) in writes {
                    let Path::Key(key) = path else {
                        return Err(stale("the value is now a JSON object"));
                    };
                    let mut hit = false;
                    for (k, field) in document.fields.iter_mut().filter(|(k, _)| k == key) {
                        let Field::Secret(value) = field else {
                            return Err(stale(&format!("key {k} no longer holds a string")));
                        };
                        changed |= value != new;
                        *value = new.clone();
                        hit = true;
                    }
                    if !hit {
                        return Err(stale(&format!("key {key} is missing")));
                    }
                }
                Ok(changed)
            }
        }
    }

    /// The bytes to write, in a buffer wiped on drop.
    fn render(&self) -> Result<Zeroizing<Vec<u8>>, ConsumerError> {
        match self {
            Stored::Plain(value) => Ok(Zeroizing::new(value.expose_secret(<[u8]>::to_vec))),
            Stored::Json(document) => document.render(),
        }
    }
}

/// A JSON object in key order. Strings are [`SecretValue`]s; other values
/// (numbers, nested objects) are kept as they were and never compared.
struct Document {
    fields: Vec<(String, Field)>,
}

enum Field {
    Secret(SecretValue),
    Other(serde_json::Value),
}

impl Document {
    fn render(&self) -> Result<Zeroizing<Vec<u8>>, ConsumerError> {
        let estimate: usize = self
            .fields
            .iter()
            .map(|(k, f)| {
                let value = match f {
                    Field::Secret(v) => v.len(),
                    Field::Other(_) => 64,
                };
                2 * (k.len() + value) + 8
            })
            .sum();
        let mut buf = Zeroizing::new(Vec::with_capacity(estimate + 2));
        buf.push(b'{');
        for (i, (key, field)) in self.fields.iter().enumerate() {
            if i > 0 {
                buf.push(b',');
            }
            serde_json::to_writer(&mut *buf, key).map_err(render_error)?;
            buf.push(b':');
            match field {
                Field::Secret(value) => value
                    .expose_secret_str(|s| serde_json::to_writer(&mut *buf, s))
                    .map_err(|_| {
                        ConsumerError::Unsupported(format!(
                            "the value for key {key} is not UTF-8 text"
                        ))
                    })?
                    .map_err(render_error)?,
                Field::Other(value) => {
                    serde_json::to_writer(&mut *buf, value).map_err(render_error)?
                }
            }
        }
        buf.push(b'}');
        Ok(buf)
    }
}

fn render_error(err: serde_json::Error) -> ConsumerError {
    ConsumerError::Permanent(format!("could not write the JSON value: {err}"))
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DocumentVisitor;

        impl<'de> Visitor<'de> for DocumentVisitor {
            type Value = Document;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Document, A::Error> {
                let mut fields = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    let field: Field = map.next_value()?;
                    fields.push((key, field));
                }
                Ok(Document { fields })
            }
        }

        deserializer.deserialize_map(DocumentVisitor)
    }
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Field, E> {
                Ok(Field::Secret(SecretValue::from(v)))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Field, E> {
                Ok(Field::Secret(SecretValue::from(v)))
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Field, E> {
                Ok(Field::Other(v.into()))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Field, E> {
                Ok(Field::Other(v.into()))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Field, E> {
                Ok(Field::Other(v.into()))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Field, E> {
                Ok(Field::Other(v.into()))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Field, E> {
                Ok(Field::Other(serde_json::Value::Null))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Field, A::Error> {
                serde_json::Value::deserialize(de::value::SeqAccessDeserializer::new(seq))
                    .map(Field::Other)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Field, A::Error> {
                serde_json::Value::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(Field::Other)
            }
        }

        deserializer.deserialize_any(FieldVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretPair;

    fn pair(key_id: &str, secret: &str) -> Credential {
        Credential::KeyPair(SecretPair::new(key_id, SecretValue::from(secret)))
    }

    fn json(text: &str) -> Stored {
        Stored::parse(SecretValue::from(text), false)
    }

    fn rendered(stored: &Stored) -> String {
        String::from_utf8(stored.render().unwrap().to_vec()).unwrap()
    }

    #[test]
    fn ref_round_trips_with_escapes() {
        let location = Location {
            secret_id: "arn:aws:secretsmanager:eu-west-1:000000000000:secret:prod/app-AbCdEf"
                .into(),
            secret_paths: vec![Path::Key("a,b|c%d".into()), Path::Key("$.x".into())],
            key_id_paths: vec![Path::Key("AWS_ACCESS_KEY_ID".into())],
        };
        let text = location.to_ref();
        assert!(text.starts_with("aws-secrets-manager:arn:aws:"));
        assert!(text.contains("#$.a%2Cb%7Cc%25d,$.$.x|$.AWS_ACCESS_KEY_ID"));
        assert_eq!(Location::parse(&text).unwrap(), location);

        let whole = Location {
            secret_id: "prod/token".into(),
            secret_paths: vec![Path::Whole],
            key_id_paths: vec![],
        };
        assert_eq!(whole.to_ref(), "aws-secrets-manager:prod/token#$");
        assert_eq!(Location::parse(&whole.to_ref()).unwrap(), whole);
    }

    #[test]
    fn malformed_refs_rejected() {
        for bad in [
            "aws-secrets-manager:prod/locked",
            "github-actions:org/repo#$",
            "aws-secrets-manager:#$",
            "aws-secrets-manager:x#",
            "aws-secrets-manager:x#KEY",
            "aws-secrets-manager:x#$.a%ZZ",
        ] {
            let err = Location::parse(bad).unwrap_err();
            assert!(matches!(err, ConsumerError::Permanent(_)), "{bad}");
        }
    }

    #[test]
    fn document_keeps_order_and_non_strings() {
        let stored =
            json(r#" {"b":"x","a":1,"n":{"deep":"y"},"l":[1,"z"],"t":true,"u":null,"f":1.5}"#);
        assert!(matches!(stored, Stored::Json(_)));
        assert_eq!(
            rendered(&stored),
            r#"{"b":"x","a":1,"n":{"deep":"y"},"l":[1,"z"],"t":true,"u":null,"f":1.5}"#
        );
    }

    #[test]
    fn non_object_values_are_plain() {
        for text in ["plain-token", "[1,2]", "{not json", "\"quoted\""] {
            assert!(matches!(json(text), Stored::Plain(_)), "{text}");
        }
    }

    #[test]
    fn locate_respects_json_keys_and_key_id() {
        let cred = pair("KEYIDFORUNITTEST", "unit-secret-7c1d");
        let secret = SecretRef::new("aws", &cred);
        let stored = json(
            r#"{"ID":"KEYIDFORUNITTEST","SECRET":"unit-secret-7c1d","COPY":"unit-secret-7c1d","o":"x"}"#,
        );
        let (s, k) = stored.locate(&secret, None).unwrap();
        assert_eq!(s, [Path::Key("SECRET".into()), Path::Key("COPY".into())]);
        assert_eq!(k, [Path::Key("ID".into())]);

        let only = ["COPY".to_owned()];
        let (s, k) = stored.locate(&secret, Some(&only)).unwrap();
        assert_eq!(s, [Path::Key("COPY".into())]);
        assert!(k.is_empty());

        let none = ["o".to_owned()];
        assert!(stored.locate(&secret, Some(&none)).is_none());

        let key_id_only = json(r#"{"ID":"KEYIDFORUNITTEST"}"#);
        assert!(key_id_only.locate(&secret, None).is_none());
    }

    #[test]
    fn substitute_writes_both_halves_and_reports_change() {
        let old = pair("KEYIDOLD", "unit-old-secret-1");
        let new = pair("KEYIDNEW", "unit-new-secret-2");
        let mut stored = json(r#"{"K":"KEYIDOLD","S":"unit-old-secret-1","o":"x"}"#);
        let location = Location {
            secret_id: "s".into(),
            secret_paths: vec![Path::Key("S".into())],
            key_id_paths: vec![Path::Key("K".into())],
        };
        assert!(stored.substitute(&location, &new).unwrap());
        assert_eq!(
            rendered(&stored),
            r#"{"K":"KEYIDNEW","S":"unit-new-secret-2","o":"x"}"#
        );
        assert!(!stored.substitute(&location, &new).unwrap());
        assert!(stored.substitute(&location, &old).unwrap());

        let gone = Location {
            secret_paths: vec![Path::Key("MISSING".into())],
            ..location
        };
        let err = stored.substitute(&gone, &new).unwrap_err();
        assert!(err.to_string().contains("key MISSING is missing"));
        assert!(!err.to_string().contains("unit-"));
    }

    #[test]
    fn substitute_rejects_shape_change() {
        let cred = Credential::Token(SecretValue::from("unit-token-3"));
        let mut plain = json("plain-old");
        let keyed = Location {
            secret_id: "s".into(),
            secret_paths: vec![Path::Key("S".into())],
            key_id_paths: vec![],
        };
        assert!(plain.substitute(&keyed, &cred).is_err());
        let mut object = json(r#"{"S":1}"#);
        assert!(object.substitute(&keyed, &cred).is_err());
    }

    #[test]
    fn token_is_stable_and_depends_on_version() {
        let cred = pair("KEYIDNEW", "unit-new-secret-4");
        let a = client_token("aws-secrets-manager:s#$", Some("v1"), &cred);
        assert_eq!(
            a,
            client_token("aws-secrets-manager:s#$", Some("v1"), &cred)
        );
        assert_ne!(
            a,
            client_token("aws-secrets-manager:s#$", Some("v2"), &cred)
        );
        assert!(a.starts_with("rotate-"));
        assert!((32..=64).contains(&a.len()));
        assert!(!a.contains("unit-new"));
    }
}
