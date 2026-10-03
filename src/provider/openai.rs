//! OpenAI API keys (SHA-262): project keys (`sk-proj-`), service-account
//! keys (`sk-svcacct-`) and legacy user keys (`sk-`), checked with
//! `GET /v1/models` and managed through the organization Admin API.
//!
//! The leaked key signs only `GET /v1/models`, in
//! [`OpenAiProvider::check_valid`] and, without an admin key,
//! [`OpenAiProvider::describe_scope`]. Everything that lists, creates or
//! deletes keys is signed with the operator's Admin API key, read from the
//! environment variable `providers.openai.admin_key_env` names
//! (`OPENAI_ADMIN_KEY` by default) when the call is made. rotate never uses
//! the leaked key as its operator credential (decision D3): an admin key
//! equal to the leaked one is refused.
//!
//! With an admin key the provider runs in automatic mode:
//! - scope: `GET /v1/organization/projects`, then each project's
//!   `api_keys` listing, matching the leaked key by its `redacted_value`
//!   (head and tail). The identity is the project id.
//! - replacement: `POST /v1/organization/projects/{id}/service_accounts`
//!   in the same project, named `rotate-<fingerprint hex>`. OpenAI returns
//!   the new key's value in that response only.
//! - revoke: OpenAI's `DELETE .../api_keys/{key_id}` deletes user-owned
//!   keys and refuses service-account keys. A service-account key is
//!   removed by deleting its service account, which rotate does only when
//!   the listing shows it is that account's only key; otherwise the revoke
//!   is manual ([`Provider::manual_revoke`]). 404 is already gone.
//! - `revoke_replacement` deletes the service account rotate created.
//!
//! Without an admin key the provider runs in manual mode (decision D1):
//! the scope is the `openai-organization` response header of `GET
//! /v1/models`, the operator pastes the replacement, and revoke is
//! `Unsupported`, which the plan shows. Revoked keys cannot come back, so
//! [`OpenAiProvider::restore`] is always `Unsupported`.
//!
//! Admin (`sk-admin-`) keys are identified so they are not mistaken for
//! another provider's, but cannot call `GET /v1/models`; `check_valid`
//! reports them `Unknown` without a call and the plan skips them.
//!
//! Nothing happens at construction: no call, no credential read, no HTTP
//! client. Errors carry the endpoint, the status and OpenAI's short
//! `error.code` or `error.type`, never `error.message`: OpenAI's 401
//! message echoes part of the key.

use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    Confidence, Credential, Identity, Provider, ProviderError, Replacement, ReplacementMode,
    RestoreOutcome, Revoked, Scope, Validity,
};
use crate::finding::Finding;
use crate::secret::SecretValue;

/// Name used in plans, config and the audit log.
pub const NAME: &str = "openai";

/// The public API, without `/v1`.
pub const DEFAULT_API_URL: &str = "https://api.openai.com";

/// Where keys are managed by hand.
pub const KEYS_PAGE: &str = "https://platform.openai.com/api-keys";

/// Where admin keys are managed by hand.
pub const ADMIN_KEYS_PAGE: &str = "https://platform.openai.com/settings/organization/admin-keys";

/// Default environment variable for the Admin API key.
pub const DEFAULT_ADMIN_KEY_ENV: &str = "OPENAI_ADMIN_KEY";

/// `Unknown` reason for an admin key.
pub const ADMIN_KEY_NO_CHECK: &str = "admin key: Admin API keys cannot call GET /v1/models and \
     rotate does not rotate them; rotate it at \
     https://platform.openai.com/settings/organization/admin-keys";

/// Scope line written for a key the Admin API cannot delete.
pub const UNDELETABLE_WARNING: &str = "warning: the Admin API cannot delete this key: its \
     service account holds other keys; delete it at https://platform.openai.com/api-keys";

/// Plan revoke row without an admin key.
pub const REVOKE_NEEDS_ADMIN: &str = "manual: without an Admin API key rotate cannot delete \
     OpenAI keys; delete it at https://platform.openai.com/api-keys";

/// Plan revoke row for a key the Admin API cannot delete.
pub const REVOKE_UNDELETABLE: &str = "manual: the Admin API cannot delete this key (its \
     service account holds other keys); delete it at https://platform.openai.com/api-keys";

/// Scope line about permissions, which the Admin API does not expose.
pub const PERMISSIONS_NOTE: &str = "permissions: not readable through the Admin API; a \
     replacement is a service account with the member role and all permissions";

/// Scope warning in manual mode.
pub const MANUAL_VERIFY_WARNING: &str = "warning: without an Admin API key rotate can check \
     only that a pasted key works in the same organization, not that it is in the same project";

/// Prefix of every service account rotate creates.
pub const SERVICE_ACCOUNT_PREFIX: &str = "rotate-";

/// Prefix of a `replacement_ref`.
const REF_PREFIX: &str = "openai:";

/// Detector names and gitleaks rule ids that name OpenAI.
const HINTS: &[&str] = &["OpenAI", "OpenAIAdminKey", "openai-api-key"];

const MODELS: &str = "GET /v1/models";
const PROJECTS: &str = "GET /v1/organization/projects";
const KEYS: &str = "GET /v1/organization/projects/{id}/api_keys";
const CREATE: &str = "POST /v1/organization/projects/{id}/service_accounts";
const DELETE_KEY: &str = "DELETE /v1/organization/projects/{id}/api_keys/{key_id}";
const DELETE_SA: &str = "DELETE /v1/organization/projects/{id}/service_accounts/{id}";

/// Shortest and longest key body after a known prefix.
const MIN_BODY: usize = 20;
const MAX_BODY: usize = 255;
/// Body length of a legacy `sk-` user key.
const LEGACY_BODY: usize = 48;

const PAGE_LIMIT: u32 = 100;
const MAX_PAGES: usize = 100;
const MAX_NAME: usize = 100;
const MAX_CODE: usize = 64;
const MAX_ID: usize = 128;
const TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Attempts at `GET /v1/models` with a new key in `verify`: a service
/// account key can take a moment to be accepted.
const VERIFY_ATTEMPTS: u32 = 3;

/// What kind of OpenAI key a value is, from its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// `sk-proj-`: a project key owned by a user.
    Project,
    /// `sk-svcacct-`: a project service-account key.
    ServiceAccount,
    /// `sk-admin-`: an organization Admin API key.
    Admin,
    /// `sk-` and 48 alphanumerics: a legacy user key.
    Legacy,
}

/// Prefixes, longest first.
const PREFIXES: &[(&str, KeyKind)] = &[
    ("sk-svcacct-", KeyKind::ServiceAccount),
    ("sk-admin-", KeyKind::Admin),
    ("sk-proj-", KeyKind::Project),
];

impl KeyKind {
    /// The kind of `key`: a known prefix with a `[A-Za-z0-9_-]` body of 20
    /// to 255 bytes, or `sk-` and exactly 48 alphanumerics. Other vendors
    /// use `sk-` too (`sk-ant-`, `sk-or-`), so nothing looser is claimed.
    pub fn of(key: &[u8]) -> Option<KeyKind> {
        for (prefix, kind) in PREFIXES {
            if let Some(body) = key.strip_prefix(prefix.as_bytes()) {
                let shaped = (MIN_BODY..=MAX_BODY).contains(&body.len())
                    && body
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
                return shaped.then_some(*kind);
            }
        }
        let body = key.strip_prefix(b"sk-")?;
        (body.len() == LEGACY_BODY && body.iter().all(u8::is_ascii_alphanumeric))
            .then_some(KeyKind::Legacy)
    }
}

/// Where the operator's Admin API key comes from.
#[derive(Clone)]
pub enum AdminKey {
    /// The named environment variable, read when an admin call is made. An
    /// empty value counts as unset.
    Env(String),
    /// A key held in memory (tests).
    Value(SecretValue),
    /// No admin key: manual mode.
    None,
}

impl fmt::Debug for AdminKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminKey::Env(name) => f.debug_tuple("Env").field(name).finish(),
            AdminKey::Value(_) => f.write_str("Value([set])"),
            AdminKey::None => f.write_str("None"),
        }
    }
}

impl AdminKey {
    fn read(&self) -> Option<SecretValue> {
        match self {
            AdminKey::Env(name) => std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .map(SecretValue::from),
            AdminKey::Value(value) => Some(value.clone()),
            AdminKey::None => None,
        }
    }

    fn is_set(&self) -> bool {
        match self {
            AdminKey::Env(name) => std::env::var_os(name).is_some_and(|v| !v.is_empty()),
            AdminKey::Value(_) => true,
            AdminKey::None => false,
        }
    }

    fn name(&self) -> &str {
        match self {
            AdminKey::Env(name) => name,
            _ => DEFAULT_ADMIN_KEY_ENV,
        }
    }
}

/// The OpenAI API key provider.
pub struct OpenAiProvider {
    base: String,
    admin: AdminKey,
    verify_delay: Duration,
    http: OnceLock<Result<reqwest::Client, String>>,
}

impl fmt::Debug for OpenAiProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiProvider")
            .field("base", &self.base)
            .field("admin", &self.admin)
            .finish()
    }
}

/// One HTTP response, body in zeroized memory.
struct Reply {
    status: u16,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
struct Page<T> {
    data: Vec<T>,
    #[serde(default)]
    has_more: bool,
    last_id: Option<String>,
}

#[derive(Deserialize)]
struct Project {
    id: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct ApiKey {
    id: String,
    name: Option<String>,
    redacted_value: Option<String>,
    created_at: Option<i64>,
    last_used_at: Option<i64>,
    owner: Option<Owner>,
}

#[derive(Deserialize)]
struct Owner {
    #[serde(rename = "type")]
    kind: Option<String>,
    user: Option<User>,
    service_account: Option<ServiceAccount>,
}

#[derive(Deserialize)]
struct User {
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct ServiceAccount {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Created {
    id: String,
    api_key: CreatedKey,
}

#[derive(Deserialize)]
struct CreatedKey {
    id: String,
    value: SecretValue,
}

/// The leaked key as the Admin API lists it.
struct Found {
    project_id: String,
    project_name: String,
    key: ApiKey,
    /// Other keys in the project owned by the same service account.
    siblings: usize,
}

/// What revoke deletes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// A user-owned key: `DELETE .../api_keys/{key_id}`.
    UserKey { project: String, key: String },
    /// The only key of a service account: `DELETE
    /// .../service_accounts/{id}`.
    ServiceAccount { project: String, account: String },
    /// Nothing the Admin API can delete.
    Manual,
}

impl Found {
    fn owner_kind(&self) -> Option<&str> {
        self.key.owner.as_ref()?.kind.as_deref()
    }

    fn account_id(&self) -> Option<&str> {
        self.key
            .owner
            .as_ref()?
            .service_account
            .as_ref()?
            .id
            .as_deref()
    }

    fn target(&self) -> Target {
        match self.owner_kind() {
            Some("user") if safe_id(&self.key.id) => Target::UserKey {
                project: self.project_id.clone(),
                key: self.key.id.clone(),
            },
            Some("service_account") if self.siblings == 0 => match self.account_id() {
                Some(account) if safe_id(account) => Target::ServiceAccount {
                    project: self.project_id.clone(),
                    account: account.to_owned(),
                },
                _ => Target::Manual,
            },
            _ => Target::Manual,
        }
    }

    fn lines(&self) -> Vec<String> {
        let key_name = clean(self.key.name.as_deref().unwrap_or("unnamed"));
        let owner = match (self.owner_kind(), &self.key.owner) {
            (Some("user"), Some(owner)) => {
                let user = owner.user.as_ref();
                let name = clean(user.and_then(|u| u.name.as_deref()).unwrap_or(""));
                let email = clean(user.and_then(|u| u.email.as_deref()).unwrap_or(""));
                match (name.is_empty(), email.is_empty()) {
                    (false, false) => format!("owner: user {name} <{email}>"),
                    (false, true) => format!("owner: user {name}"),
                    (true, false) => format!("owner: user <{email}>"),
                    (true, true) => "owner: user".to_owned(),
                }
            }
            (Some("service_account"), Some(owner)) => {
                let account = owner.service_account.as_ref();
                let name = clean(account.and_then(|a| a.name.as_deref()).unwrap_or("unnamed"));
                let id = clean(account.and_then(|a| a.id.as_deref()).unwrap_or("?"));
                format!("owner: service account {name} ({id})")
            }
            _ => "owner: unknown".to_owned(),
        };
        let mut lines = vec![
            format!("project: {} ({})", self.project_name, self.project_id),
            format!("key: {key_name} ({})", clean(&self.key.id)),
            owner,
            format!("created: {}", timestamp(self.key.created_at)),
            format!("last used: {}", timestamp(self.key.last_used_at)),
            PERMISSIONS_NOTE.to_owned(),
        ];
        match self.target() {
            Target::UserKey { .. } => {}
            Target::ServiceAccount { .. } => lines.push(
                "revoke: deletes the key's service account, which holds no other key".to_owned(),
            ),
            Target::Manual => lines.push(UNDELETABLE_WARNING.to_owned()),
        }
        lines
    }
}

impl OpenAiProvider {
    /// A provider for the API at `api_url` (`providers.openai.api_url`,
    /// [`DEFAULT_API_URL`] by default) with the admin key from `admin`.
    /// Makes no call and reads no credential.
    pub fn new(api_url: &str, admin: AdminKey) -> Self {
        Self {
            base: api_url.trim_end_matches('/').to_owned(),
            admin,
            verify_delay: Duration::from_secs(1),
            http: OnceLock::new(),
        }
    }

    /// The pause between `verify` attempts (tests set zero).
    pub fn with_verify_delay(mut self, delay: Duration) -> Self {
        self.verify_delay = delay;
        self
    }

    /// The API base URL without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// True when an admin key is configured (its value is not read).
    pub fn has_admin_key(&self) -> bool {
        self.admin.is_set()
    }

    fn http(&self) -> Result<&reqwest::Client, ProviderError> {
        self.http
            .get_or_init(|| {
                reqwest::Client::builder()
                    .timeout(TIMEOUT)
                    .connect_timeout(CONNECT_TIMEOUT)
                    .build()
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| ProviderError::Transient(format!("OpenAI client: {e}")))
    }

    /// The admin key, refused when it is any of `not` (decision D3).
    fn admin_key(&self, not: &[&SecretValue]) -> Result<SecretValue, ProviderError> {
        let admin = self.admin.read().ok_or_else(|| {
            ProviderError::Unsupported(format!(
                "no OpenAI Admin API key: set {} to let rotate list, create and delete keys",
                self.admin.name()
            ))
        })?;
        if not.iter().any(|v| **v == admin) {
            return Err(ProviderError::Permanent(
                "the Admin API key is the key being rotated; rotate never uses a leaked key as \
                 its operator credential"
                    .into(),
            ));
        }
        Ok(admin)
    }

    /// One request signed with `key`, any status.
    async fn send(
        &self,
        method: Method,
        path: &str,
        key: &SecretValue,
        body: Option<Zeroizing<Vec<u8>>>,
        op: &str,
    ) -> Result<Reply, ProviderError> {
        let mut headers = HeaderMap::new();
        let mut auth = key.expose_secret(|k| {
            let mut bytes = Zeroizing::new(Vec::with_capacity(k.len() + 7));
            bytes.extend_from_slice(b"Bearer ");
            bytes.extend_from_slice(k);
            HeaderValue::from_bytes(&bytes).map_err(|_| {
                ProviderError::Permanent(format!("{op}: the key is not a valid HTTP header value"))
            })
        })?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("rotate/", env!("CARGO_PKG_VERSION"))),
        );
        let mut request = self
            .http()?
            .request(method, format!("{}{path}", self.base))
            .headers(headers);
        if let Some(body) = body {
            request = request
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(body.to_vec());
        }
        let response = request
            .send()
            .await
            .map_err(|e| ProviderError::Transient(format!("{op}: {}", e.without_url())))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ProviderError::Transient(format!("{op}: {}", e.without_url())))?;
        Ok(Reply {
            status,
            headers,
            body: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// A GET signed with the admin key, decoded when it succeeds.
    async fn admin_get<T: DeserializeOwned>(
        &self,
        path: &str,
        admin: &SecretValue,
        op: &str,
    ) -> Result<T, ProviderError> {
        let reply = self.send(Method::GET, path, admin, None, op).await?;
        if !is_success(reply.status) {
            return Err(status_error(op, &reply));
        }
        decode(op, &reply.body)
    }

    /// Every item of a cursor-paged Admin API list.
    async fn list<T: DeserializeOwned>(
        &self,
        path: &str,
        admin: &SecretValue,
        op: &str,
    ) -> Result<Vec<T>, ProviderError> {
        let mut items = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let url = match &after {
                Some(after) => format!("{path}?limit={PAGE_LIMIT}&after={after}"),
                None => format!("{path}?limit={PAGE_LIMIT}"),
            };
            let page: Page<T> = self.admin_get(&url, admin, op).await?;
            items.extend(page.data);
            match page.last_id {
                Some(last) if page.has_more && safe_id(&last) => after = Some(last),
                Some(_) if page.has_more => {
                    return Err(ProviderError::Permanent(format!(
                        "{op}: unexpected pagination cursor"
                    )))
                }
                _ => return Ok(items),
            }
        }
        Err(ProviderError::Permanent(format!(
            "{op}: more than {MAX_PAGES} pages; stopping"
        )))
    }

    /// Every key in `project`.
    async fn project_keys(
        &self,
        project: &str,
        admin: &SecretValue,
    ) -> Result<Vec<ApiKey>, ProviderError> {
        if !safe_id(project) {
            return Err(ProviderError::Permanent(format!(
                "{KEYS}: not an OpenAI project id"
            )));
        }
        self.list(
            &format!("/v1/organization/projects/{project}/api_keys"),
            admin,
            KEYS,
        )
        .await
    }

    /// Finds `key` in the organization by `redacted_value`. No match, or
    /// more than one, is an error: rotate never guesses.
    async fn find(&self, key: &SecretValue, admin: &SecretValue) -> Result<Found, ProviderError> {
        let projects: Vec<Project> = self
            .list("/v1/organization/projects", admin, PROJECTS)
            .await?;
        let mut found: Vec<Found> = Vec::new();
        for project in projects.into_iter().filter(|p| safe_id(&p.id)) {
            let keys = self.project_keys(&project.id, admin).await?;
            let mut hits = Vec::new();
            let mut accounts: Vec<Option<String>> = Vec::new();
            for listed in keys {
                accounts.push(account_of(&listed));
                if listed
                    .redacted_value
                    .as_deref()
                    .is_some_and(|r| key.expose_secret(|k| redacted_matches(r, k)))
                {
                    hits.push(listed);
                }
            }
            for hit in hits {
                let siblings = match account_of(&hit) {
                    Some(account) => accounts
                        .iter()
                        .filter(|a| a.as_deref() == Some(account.as_str()))
                        .count()
                        .saturating_sub(1),
                    None => 0,
                };
                found.push(Found {
                    project_id: project.id.clone(),
                    project_name: clean(project.name.as_deref().unwrap_or("unnamed")),
                    key: hit,
                    siblings,
                });
            }
        }
        match found.len() {
            1 => Ok(found.remove(0)),
            0 => Err(ProviderError::Permanent(format!(
                "the key is in no project the Admin API key can list (a legacy user key, or \
                 another organization); delete it at {KEYS_PAGE}"
            ))),
            n => Err(ProviderError::Permanent(format!(
                "{n} keys in the organization match this key's redacted value; rotate will not \
                 guess which one: delete it at {KEYS_PAGE}"
            ))),
        }
    }

    /// `GET /v1/models` signed with `key`.
    async fn models(&self, key: &SecretValue) -> Result<Reply, ProviderError> {
        self.send(Method::GET, "/v1/models", key, None, MODELS)
            .await
    }

    /// A DELETE signed with the admin key; 2xx and 404 are done.
    async fn delete(&self, path: &str, admin: &SecretValue, op: &str) -> Result<(), ProviderError> {
        let reply = self.send(Method::DELETE, path, admin, None, op).await?;
        if is_success(reply.status) || reply.status == 404 {
            Ok(())
        } else {
            Err(status_error(op, &reply))
        }
    }

    /// Scope without an admin key, from the leaked key's own read.
    async fn manual_scope(&self, key: &SecretValue) -> Result<Scope, ProviderError> {
        let reply = self.models(key).await?;
        match liveness(&reply) {
            Live::Yes => {}
            Live::No => {
                return Err(ProviderError::Permanent(format!(
                    "{MODELS}: OpenAI did not accept the key (401)"
                )))
            }
            Live::Other => return Err(status_error(MODELS, &reply)),
        }
        let identity = header_identity(&reply.headers);
        Ok(Scope {
            identity: Identity(identity.clone()),
            lines: vec![
                format!("scope unavailable: set {}", self.admin.name()),
                format!("organization: {identity}"),
                MANUAL_VERIFY_WARNING.to_owned(),
            ],
        })
    }
}

/// The service account id that owns `key`, if any.
fn account_of(key: &ApiKey) -> Option<String> {
    let owner = key.owner.as_ref()?;
    if owner.kind.as_deref() != Some("service_account") {
        return None;
    }
    owner.service_account.as_ref()?.id.clone()
}

/// Whether `key` fits OpenAI's `redacted_value`: a head, a mask of `...`,
/// `…` or `*`, then a tail. Head and tail must each be at least three
/// characters and the key must start with the head and end with the tail.
pub fn redacted_matches(redacted: &str, key: &[u8]) -> bool {
    let is_mask = |c: char| c == '*' || c == '.' || c == '…';
    let Some(start) = redacted.find(is_mask) else {
        return false;
    };
    let Some(end) = redacted.rfind(is_mask) else {
        return false;
    };
    let head = &redacted[..start];
    let tail = &redacted[end + redacted[end..].chars().next().map_or(1, char::len_utf8)..];
    head.len() >= 3
        && tail.len() >= 3
        && key.len() > head.len() + tail.len()
        && key.starts_with(head.as_bytes())
        && key.ends_with(tail.as_bytes())
}

/// Identity in manual mode: the `openai-organization` response header,
/// plus `openai-project` when OpenAI sends it.
fn header_identity(headers: &HeaderMap) -> String {
    let read = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(clean)
            .filter(|v| !v.is_empty())
    };
    match (read("openai-organization"), read("openai-project")) {
        (Some(org), Some(project)) => format!("{org}/{project}"),
        (Some(org), None) => org,
        (None, Some(project)) => format!("unknown organization/{project}"),
        (None, None) => "unknown organization".to_owned(),
    }
}

/// How `GET /v1/models` answered.
enum Live {
    /// 200, 429, or a 401 for missing scopes: the key authenticated.
    Yes,
    /// 401: revoked or never real.
    No,
    /// Anything else.
    Other,
}

fn liveness(reply: &Reply) -> Live {
    match reply.status {
        200..=299 | 429 => Live::Yes,
        401 if missing_scopes(&reply.body) => Live::Yes,
        401 => Live::No,
        _ => Live::Other,
    }
}

/// A 401 for a restricted key without the models read permission. The
/// message is read here only; it is never copied into an error.
fn missing_scopes(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let message = value
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    message.contains("insufficient permissions") || message.contains("missing scopes")
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// OpenAI's short `error.code`, else `error.type`, limited to id-like
/// characters. Never `error.message`.
fn error_code(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error")?;
    let code = error
        .get("code")
        .and_then(serde_json::Value::as_str)
        .or_else(|| error.get("type").and_then(serde_json::Value::as_str))?;
    let code: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(MAX_CODE)
        .collect();
    (!code.is_empty()).then_some(code)
}

/// The error for a non-success `reply` to `op`, keeping its retry class.
fn status_error(op: &str, reply: &Reply) -> ProviderError {
    if reply.status == 429 {
        let retry_after = reply
            .headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        return ProviderError::RateLimited { retry_after };
    }
    let text = match error_code(&reply.body) {
        Some(code) => format!("{op}: OpenAI returned {} ({code})", reply.status),
        None => format!("{op}: OpenAI returned {}", reply.status),
    };
    if reply.status >= 500 {
        ProviderError::Transient(text)
    } else {
        ProviderError::Permanent(text)
    }
}

fn decode<T: DeserializeOwned>(op: &str, body: &[u8]) -> Result<T, ProviderError> {
    // serde_json's own message can quote the offending value, which in the
    // create response may be the new key: keep only the category and
    // position.
    serde_json::from_slice(body).map_err(|e| {
        ProviderError::Permanent(format!(
            "{op}: unexpected response ({:?} error at line {} column {})",
            e.classify(),
            e.line(),
            e.column()
        ))
    })
}

/// An OpenAI object id safe to put in a URL path.
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A name from OpenAI: no control characters, capped.
fn clean(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// RFC 3339 for a Unix time, `never` for none or zero.
fn timestamp(secs: Option<i64>) -> String {
    use time::format_description::well_known::Rfc3339;
    match secs.filter(|s| *s > 0) {
        None => "never".to_owned(),
        Some(secs) => time::OffsetDateTime::from_unix_timestamp(secs)
            .ok()
            .and_then(|t| t.format(&Rfc3339).ok())
            .unwrap_or_else(|| secs.to_string()),
    }
}

/// The single key in `credential`.
fn token(credential: &Credential) -> Result<&SecretValue, ProviderError> {
    match credential {
        Credential::Token(token) => Ok(token),
        Credential::KeyPair(_) => Err(ProviderError::Unsupported(
            "an OpenAI key is a single value, not a key pair".into(),
        )),
    }
}

/// The kind of an OpenAI-shaped key; anything else is refused before any
/// call, so rotate never sends an unrecognised value to OpenAI.
fn kind(key: &SecretValue) -> Result<KeyKind, ProviderError> {
    key.expose_secret(KeyKind::of).ok_or_else(|| {
        ProviderError::Unsupported("the value does not have an OpenAI key format".into())
    })
}

/// A key rotate can rotate: not an admin key.
fn rotatable(key: &SecretValue) -> Result<KeyKind, ProviderError> {
    match kind(key)? {
        KeyKind::Admin => Err(ProviderError::Unsupported(ADMIN_KEY_NO_CHECK.into())),
        other => Ok(other),
    }
}

/// `openai:<project>:<service account>:<key>` for a replacement.
fn replacement_ref(project: &str, account: &str, key: &str) -> String {
    format!("{REF_PREFIX}{project}:{account}:{key}")
}

/// The project and service account in a [`replacement_ref`].
fn parse_ref(reference: &str) -> Option<(&str, &str)> {
    let rest = reference.strip_prefix(REF_PREFIX)?;
    let mut parts = rest.split(':');
    let (project, account, key) = (parts.next()?, parts.next()?, parts.next()?);
    (parts.next().is_none() && safe_id(project) && safe_id(account) && safe_id(key))
        .then_some((project, account))
}

#[async_trait]
impl Provider for OpenAiProvider {
    fn name(&self) -> &'static str {
        NAME
    }

    /// Automatic with an admin key, manual without.
    fn replacement_mode(&self) -> ReplacementMode {
        if self.has_admin_key() {
            ReplacementMode::Automatic
        } else {
            ReplacementMode::Manual
        }
    }

    fn manual_instructions(&self, scope: &Scope) -> String {
        format!(
            "Create a new secret key for OpenAI organization {} at {KEYS_PAGE}, in the same \
             project and with the same permissions as the leaked one, then paste it at the \
             prompt.",
            scope.identity
        )
    }

    /// Manual without an admin key, and for a key the Admin API cannot
    /// delete.
    fn manual_revoke(&self, scope: Option<&Scope>) -> Option<&'static str> {
        if !self.has_admin_key() {
            return Some(REVOKE_NEEDS_ADMIN);
        }
        scope
            .is_some_and(|s| s.lines.iter().any(|l| l == UNDELETABLE_WARNING))
            .then_some(REVOKE_UNDELETABLE)
    }

    fn identify(&self, finding: &Finding) -> Option<Confidence> {
        let Credential::Token(raw) = finding.credential() else {
            return None;
        };
        raw.expose_secret(KeyKind::of)?;
        let hinted = HINTS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&finding.detector));
        Some(if hinted {
            Confidence::High
        } else {
            Confidence::Medium
        })
    }

    /// `GET /v1/models` signed with the key: 200 and 429 valid, 401
    /// invalid (unless it is a restricted key missing the models scope),
    /// 5xx retryable, anything else unknown. Admin keys make no call.
    async fn check_valid(&self, credential: &Credential) -> Result<Validity, ProviderError> {
        let key = token(credential)?;
        if kind(key)? == KeyKind::Admin {
            return Ok(Validity::Unknown {
                reason: ADMIN_KEY_NO_CHECK.into(),
            });
        }
        let reply = self.models(key).await?;
        match liveness(&reply) {
            Live::Yes => Ok(Validity::Valid),
            Live::No => Ok(Validity::Invalid),
            Live::Other if reply.status >= 500 => Err(status_error(MODELS, &reply)),
            Live::Other => Ok(Validity::Unknown {
                reason: status_error(MODELS, &reply).to_string(),
            }),
        }
    }

    /// With an admin key: the project, key name, owner, created and last
    /// used, from the Admin API. Without: the organization header and
    /// "scope unavailable: set OPENAI_ADMIN_KEY".
    async fn describe_scope(&self, credential: &Credential) -> Result<Scope, ProviderError> {
        let key = token(credential)?;
        rotatable(key)?;
        if !self.has_admin_key() {
            return self.manual_scope(key).await;
        }
        let admin = self.admin_key(&[key])?;
        let found = self.find(key, &admin).await?;
        Ok(Scope {
            identity: Identity(found.project_id.clone()),
            lines: found.lines(),
        })
    }

    /// A service account named `rotate-<fingerprint hex>` in the leaked
    /// key's project, whose key is the replacement. Mutating.
    async fn create_replacement(
        &self,
        credential: &Credential,
    ) -> Result<Replacement, ProviderError> {
        let key = token(credential)?;
        rotatable(key)?;
        let admin = self.admin_key(&[key])?;
        let found = self.find(key, &admin).await?;
        let fingerprint = credential.fingerprint();
        let hex = fingerprint
            .as_str()
            .rsplit(':')
            .next()
            .unwrap_or_default()
            .to_owned();
        let name = format!("{SERVICE_ACCOUNT_PREFIX}{hex}");
        let body = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({ "name": name }))
                .map_err(|e| ProviderError::Permanent(format!("{CREATE}: {e}")))?,
        );
        let path = format!(
            "/v1/organization/projects/{}/service_accounts",
            found.project_id
        );
        let reply = self
            .send(Method::POST, &path, &admin, Some(body), CREATE)
            .await?;
        if !is_success(reply.status) {
            return Err(status_error(CREATE, &reply));
        }
        let created: Created = decode(CREATE, &reply.body)?;
        if !safe_id(&created.id) || !safe_id(&created.api_key.id) {
            return Err(ProviderError::Permanent(format!(
                "{CREATE}: unexpected service account or key id"
            )));
        }
        if created.api_key.value.is_empty() {
            return Err(ProviderError::Permanent(format!(
                "{CREATE}: OpenAI returned no key"
            )));
        }
        Ok(Replacement {
            credential: Credential::Token(created.api_key.value),
            replacement_ref: replacement_ref(&found.project_id, &created.id, &created.api_key.id),
        })
    }

    /// `GET /v1/models` with the new key, then: with an admin key, the key
    /// must be listed in project `identity`; without, the organization
    /// header must match.
    async fn verify(
        &self,
        credential: &Credential,
        identity: &Identity,
    ) -> Result<(), ProviderError> {
        let key = token(credential)?;
        rotatable(key)?;
        let mut reply = self.models(key).await?;
        for _ in 1..VERIFY_ATTEMPTS {
            if !matches!(liveness(&reply), Live::No) {
                break;
            }
            tokio::time::sleep(self.verify_delay).await;
            reply = self.models(key).await?;
        }
        match liveness(&reply) {
            Live::Yes => {}
            Live::No => {
                return Err(ProviderError::Permanent(format!(
                    "{MODELS}: OpenAI did not accept the replacement key (401)"
                )))
            }
            Live::Other => return Err(status_error(MODELS, &reply)),
        }
        if !self.has_admin_key() {
            let got = header_identity(&reply.headers);
            return if got == identity.0 {
                Ok(())
            } else {
                Err(ProviderError::Permanent(format!(
                    "the replacement key belongs to {got} but the leaked key belongs to {identity}"
                )))
            };
        }
        let admin = self.admin_key(&[key])?;
        let listed = self.project_keys(&identity.0, &admin).await?;
        let hits = listed
            .iter()
            .filter(|k| {
                k.redacted_value
                    .as_deref()
                    .is_some_and(|r| key.expose_secret(|v| redacted_matches(r, v)))
            })
            .count();
        if hits == 1 {
            Ok(())
        } else {
            Err(ProviderError::Permanent(format!(
                "the replacement key is not listed in project {identity}"
            )))
        }
    }

    /// Deletes the leaked key with the admin key: a user key by key id, the
    /// only key of a service account by deleting the account. 404 is
    /// already gone, and so is a key no longer listed that OpenAI rejects.
    /// Never restorable. `Unsupported`, with no state-changing call, without
    /// an admin key or when the Admin API cannot delete the key.
    async fn revoke(&self, credential: &Credential) -> Result<Revoked, ProviderError> {
        let key = token(credential)?;
        rotatable(key)?;
        if !self.has_admin_key() {
            return Err(ProviderError::Unsupported(REVOKE_NEEDS_ADMIN.into()));
        }
        let admin = self.admin_key(&[key])?;
        let found = match self.find(key, &admin).await {
            Ok(found) => found,
            Err(err @ ProviderError::Permanent(_)) => {
                // Not listed: already deleted if OpenAI rejects it.
                let reply = self.models(key).await?;
                return match liveness(&reply) {
                    Live::No => Ok(Revoked { restore_ref: None }),
                    _ => Err(err),
                };
            }
            Err(err) => return Err(err),
        };
        match found.target() {
            Target::UserKey { project, key } => {
                self.delete(
                    &format!("/v1/organization/projects/{project}/api_keys/{key}"),
                    &admin,
                    DELETE_KEY,
                )
                .await?
            }
            Target::ServiceAccount { project, account } => {
                self.delete(
                    &format!("/v1/organization/projects/{project}/service_accounts/{account}"),
                    &admin,
                    DELETE_SA,
                )
                .await?
            }
            Target::Manual => return Err(ProviderError::Unsupported(REVOKE_UNDELETABLE.into())),
        }
        Ok(Revoked { restore_ref: None })
    }

    /// OpenAI cannot bring a deleted key back.
    async fn restore(&self, _restore_ref: &str) -> Result<RestoreOutcome, ProviderError> {
        Ok(RestoreOutcome::Unsupported)
    }

    /// Deletes the service account rotate created for the replacement.
    /// 404 is already gone. Mutating.
    async fn revoke_replacement(&self, reference: &str) -> Result<(), ProviderError> {
        let (project, account) = parse_ref(reference).ok_or_else(|| {
            ProviderError::Permanent(
                "not an OpenAI replacement reference (openai:<project>:<service account>:<key>)"
                    .into(),
            )
        })?;
        let admin = self.admin_key(&[])?;
        self.delete(
            &format!("/v1/organization/projects/{project}/service_accounts/{account}"),
            &admin,
            DELETE_SA,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{SourceLocation, ACCESS_KEY_ID};

    /// A key built at runtime so no literal here matches a secret scanner.
    fn key(prefix: [&str; 2], len: usize) -> String {
        format!(
            "{}{}",
            prefix.concat(),
            "Ab1-".repeat(len / 4 + 1)[..len].to_owned()
        )
    }

    fn legacy() -> String {
        format!("{}{}", ["s", "k-"].concat(), "Ab12".repeat(12))
    }

    fn finding(value: &str, detector: &str) -> Finding {
        Finding::new(
            SecretValue::from(value),
            detector,
            SourceLocation::file("a.env"),
        )
    }

    fn manual() -> OpenAiProvider {
        OpenAiProvider::new("http://127.0.0.1:1", AdminKey::None)
    }

    // T1 (AC1)
    #[test]
    fn identify_prefixes_and_not_others() {
        let p = manual();
        let cases = [
            (key(["sk-", "proj-"], 156), KeyKind::Project),
            (key(["sk-", "svcacct-"], 156), KeyKind::ServiceAccount),
            (key(["sk-", "admin-"], 80), KeyKind::Admin),
            (legacy(), KeyKind::Legacy),
        ];
        for (value, want) in &cases {
            assert_eq!(KeyKind::of(value.as_bytes()), Some(*want), "{want:?}");
            for hint in ["OpenAI", "openai-api-key", "OpenAIAdminKey"] {
                assert_eq!(
                    p.identify(&finding(value, hint)),
                    Some(Confidence::High),
                    "{want:?} {hint}"
                );
            }
            assert_eq!(
                p.identify(&finding(value, "stdin")),
                Some(Confidence::Medium),
                "{want:?}"
            );
        }

        // An npm token, GitHub token, AWS pair and other vendors' sk- keys.
        let npm = key(["np", "m_"], 36);
        assert_eq!(p.identify(&finding(&npm, "NpmToken")), None);
        assert_eq!(p.identify(&finding(&npm, "OpenAI")), None);
        assert_eq!(p.identify(&finding(&key(["gh", "p_"], 36), "Github")), None);
        let pair = finding("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01", "AWS")
            .with_extra(ACCESS_KEY_ID, ["AKIA", "IOSFODNN7EXAMPLE"].concat());
        assert_eq!(p.identify(&pair), None);
        assert_eq!(
            p.identify(&finding(&key(["sk-", "ant-api03-"], 90), "")),
            None
        );
        assert_eq!(p.identify(&finding(&key(["sk-", "or-v1-"], 64), "")), None);
        // Wrong lengths and characters.
        assert_eq!(p.identify(&finding("", "OpenAI")), None);
        assert_eq!(
            p.identify(&finding(&key(["sk-", "proj-"], 5), "OpenAI")),
            None
        );
        assert_eq!(p.identify(&finding(&legacy()[..40], "OpenAI")), None);
        let dashed = format!("{}{}", ["s", "k-"].concat(), "a-b1".repeat(12));
        assert_eq!(p.identify(&finding(&dashed, "OpenAI")), None);
        let spaced = format!("{}{}", ["sk-", "proj-"].concat(), "a b1".repeat(10));
        assert_eq!(p.identify(&finding(&spaced, "OpenAI")), None);
    }

    #[test]
    fn redacted_value_matching() {
        let value = format!(
            "{}abcdefghijklmnopqrstuvwxyz0123WXYZ",
            ["sk-", "proj-"].concat()
        );
        let v = value.as_bytes();
        assert!(redacted_matches("sk-proj-abc...WXYZ", v));
        assert!(redacted_matches("sk-proj-********WXYZ", v));
        assert!(redacted_matches("sk-pr…XYZ", v));
        assert!(!redacted_matches("sk-proj-abc...WXYA", v));
        assert!(!redacted_matches("sk-svcacct-abc...WXYZ", v));
        // Too little to match on.
        assert!(!redacted_matches("sk...Z", v));
        assert!(!redacted_matches("sk-proj-abcWXYZ", v));
        assert!(!redacted_matches("", v));
    }

    // T4 (AC4)
    #[test]
    fn no_admin_key_scope_message_and_manual_mode() {
        let unset = format!("ROTATE_TEST_UNSET_OPENAI_ADMIN_{}", std::process::id());
        let p = OpenAiProvider::new("http://127.0.0.1:1", AdminKey::Env(unset.clone()));
        assert!(!p.has_admin_key());
        assert_eq!(p.replacement_mode(), ReplacementMode::Manual);
        assert_eq!(p.manual_revoke(None), Some(REVOKE_NEEDS_ADMIN));
        let with = OpenAiProvider::new(
            "http://127.0.0.1:1",
            AdminKey::Value(SecretValue::from(key(["sk-", "admin-"], 60))),
        );
        assert_eq!(with.replacement_mode(), ReplacementMode::Automatic);
        assert_eq!(with.manual_revoke(None), None);
        let undeletable = Scope {
            identity: Identity("proj_1".into()),
            lines: vec![UNDELETABLE_WARNING.to_owned()],
        };
        assert_eq!(
            with.manual_revoke(Some(&undeletable)),
            Some(REVOKE_UNDELETABLE)
        );
        let debug = format!("{with:?}");
        assert!(debug.contains("Value([set])"), "{debug}");
        assert!(!debug.contains("sk-"), "{debug}");
    }

    // T8 (AC8)
    #[tokio::test]
    async fn restore_unsupported() {
        assert_eq!(
            manual().restore("anything").await.unwrap(),
            RestoreOutcome::Unsupported
        );
    }

    #[tokio::test]
    async fn refusals_make_no_call() {
        // An unroutable base: any call would fail with a transport error.
        let p = manual();
        let admin = Credential::Token(SecretValue::from(key(["sk-", "admin-"], 60)));
        assert_eq!(
            p.check_valid(&admin).await.unwrap(),
            Validity::Unknown {
                reason: ADMIN_KEY_NO_CHECK.into()
            }
        );
        let project = Credential::Token(SecretValue::from(key(["sk-", "proj-"], 60)));
        assert_eq!(
            p.revoke(&project).await.unwrap_err(),
            ProviderError::Unsupported(REVOKE_NEEDS_ADMIN.into())
        );
        assert!(matches!(
            p.create_replacement(&project).await,
            Err(ProviderError::Unsupported(_))
        ));
        assert!(matches!(
            p.revoke_replacement("openai:proj_1:svc_1:key_1").await,
            Err(ProviderError::Unsupported(_))
        ));
        let other = Credential::Token(SecretValue::from("not-an-openai-key-canary-83"));
        for err in [
            p.check_valid(&other).await.unwrap_err(),
            p.describe_scope(&other).await.unwrap_err(),
            p.revoke(&other).await.unwrap_err(),
            p.verify(&other, &Identity("x".into())).await.unwrap_err(),
        ] {
            assert!(matches!(err, ProviderError::Unsupported(_)), "{err}");
            assert!(!err.to_string().contains("canary-83"));
        }
    }

    #[tokio::test]
    async fn admin_key_equal_to_leaked_is_refused() {
        let leaked = SecretValue::from(key(["sk-", "proj-"], 60));
        let p = OpenAiProvider::new("http://127.0.0.1:1", AdminKey::Value(leaked.clone()));
        let err = p
            .describe_scope(&Credential::Token(leaked))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("never uses a leaked key"), "{err}");
    }

    #[test]
    fn replacement_ref_round_trip() {
        let r = replacement_ref("proj_a", "svc_acct_b", "key_c");
        assert_eq!(r, "openai:proj_a:svc_acct_b:key_c");
        assert_eq!(parse_ref(&r), Some(("proj_a", "svc_acct_b")));
        for bad in [
            "manual",
            "openai:proj_a:svc",
            "openai:proj_a:svc:key:extra",
            "openai:proj/a:svc:key",
            "openai::svc:key",
        ] {
            assert_eq!(parse_ref(bad), None, "{bad}");
        }
    }

    #[test]
    fn error_text_never_has_the_message() {
        let body = serde_json::json!({
            "error": {
                "message": "Incorrect API key provided: sk-proj-****WXYZ.",
                "type": "invalid_request_error",
                "code": "invalid_api_key"
            }
        });
        let reply = Reply {
            status: 403,
            headers: HeaderMap::new(),
            body: Zeroizing::new(serde_json::to_vec(&body).unwrap()),
        };
        let text = status_error(MODELS, &reply).to_string();
        assert_eq!(
            text,
            "GET /v1/models: OpenAI returned 403 (invalid_api_key)"
        );
        let missing = serde_json::json!({
            "error": { "message": "You have insufficient permissions for this operation. Missing scopes: api.model.read." }
        });
        assert!(missing_scopes(&serde_json::to_vec(&missing).unwrap()));
        assert!(!missing_scopes(&serde_json::to_vec(&body).unwrap()));
    }

    #[test]
    fn decode_errors_never_quote_the_body() {
        let value = key(["sk-", "svcacct-"], 60);
        let body = serde_json::json!({ "id": "svc_1", "api_key": value }).to_string();
        let Err(err) = decode::<Created>(CREATE, body.as_bytes()) else {
            panic!("decoded a malformed create response");
        };
        let text = err.to_string();
        assert!(text.starts_with(CREATE), "{text}");
        assert!(!text.contains(&value), "{text}");
        assert!(!text.contains("svcacct"), "{text}");
    }

    #[test]
    fn timestamps_and_names() {
        assert_eq!(timestamp(None), "never");
        assert_eq!(timestamp(Some(0)), "never");
        assert_eq!(timestamp(Some(1_700_000_000)), "2023-11-14T22:13:20Z");
        assert_eq!(clean("a\nb"), "ab");
        assert_eq!(clean(&"x".repeat(500)).len(), MAX_NAME);
        assert!(safe_id("proj_abc-1"));
        assert!(!safe_id("proj/abc"));
        assert!(!safe_id(""));
    }
}
