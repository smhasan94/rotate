//! npm access tokens (SHA-261): granular access tokens and `npm login`
//! session tokens, both `npm_` plus 36 alphanumerics. npm revoked every
//! classic token on 2025-12-09.
//!
//! The leaked token signs one read-only call, `GET /-/whoami`, in
//! [`NpmProvider::check_valid`], [`NpmProvider::describe_scope`] and the
//! already-deleted check of [`NpmProvider::revoke`]. Nothing that changes
//! state is ever signed with it (decision D3). The replacement signs `GET
//! /-/whoami` in [`NpmProvider::verify`].
//!
//! The operator token (`ROTATE_NPM_TOKEN`, then `NPM_TOKEN`) signs the token
//! list, `GET /-/npm/v1/tokens`, and the delete, `DELETE
//! /-/npm/v1/tokens/token/{key}`. npm accepts only an `npm login` session
//! token on the list ([`OPERATOR_REQUIREMENT`]; SHA-292 records the npm
//! sources); a granular token without 2FA bypass may delete but not list,
//! and one with 2FA bypass gets a 403 on both. Session tokens expire after
//! two hours, so an unattended run needs a fresh `npm login` first. The plan
//! shows a blocker ([`NpmProvider::revoke_blocker`]) when no usable operator
//! token is set or npm refused it on the list. Revoke finds the leaked token's entry in that list and
//! deletes it by the entry's `key`, so the token value is never put in a
//! URL. An entry matches when its `key` is the sha512 hex of the token
//! (npm's old key scheme, see [`token_key`]) or when the redacted `token`
//! (`npm_aBcD...7890`, first 8 and last 4 characters) fits the token.
//!
//! npm cannot create a token without the account password and a one-time
//! password, so the provider runs in manual replacement mode (decision D1).
//! A deleted token cannot be reactivated, so [`NpmProvider::restore`] is
//! always `Unsupported`. Deleting a token may need a one-time password;
//! that is out of scope, and revoke fails naming the page to delete it on.
//!
//! Nothing happens at construction: the HTTP client is built and the
//! operator token read on first use. Error text carries the endpoint, the
//! status and npm's capped `error` or `message`, never a token.

use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::{Method, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use super::{
    Confidence, Credential, Identity, Provider, ProviderError, Replacement, ReplacementMode,
    RestoreOutcome, Revoked, Scope, Validity,
};
use crate::finding::Finding;
use crate::secret::SecretValue;

/// Name used in plans, config and the audit log.
pub const NAME: &str = "npm";

/// Environment variables holding the operator token, in order of
/// preference (FR24). The rotate-specific one wins: in CI, `NPM_TOKEN` is
/// often the very token being rotated.
pub const TOKEN_VARS: [&str; 2] = ["ROTATE_NPM_TOKEN", "NPM_TOKEN"];

/// Scope line, and the start of the revoke error, when the operator's token
/// list has no entry for the leaked token (AC5).
pub const NOT_VISIBLE: &str = "token not visible to operator account";

/// The operator token kind npm requires, as the docs state it. The same
/// sentence is in `docs/permissions.md`, `docs/providers.md` and
/// `docs/backlog.md` (SHA-292, kept in step by a test).
pub const OPERATOR_REQUIREMENT: &str = "The npm operator token must be an `npm login` session \
     token for the same account as the leaked token: npm's token list accepts no other kind, \
     granular access tokens included.";

/// Start of the plan blocker when no operator token is set (SHA-292).
pub const NO_OPERATOR: &str = "no npm operator token";

/// What the scope line says when npm refused the operator token on the
/// token list (401 or 403).
pub const LIST_REFUSED: &str = "listing tokens needs an `npm login` session token";

/// Session token lifetime, for blockers and scope lines.
const SESSION_EXPIRY: &str = "session tokens expire after two hours, so an unattended run needs a \
     fresh `npm login` shortly before it";

/// End of every revoke blocker.
const REVOKE_FAILS: &str = "without it apply stops at revoke and the leaked token stays valid";

/// The public registry, whose website is [`PUBLIC_WEB`].
pub const PUBLIC_REGISTRY: &str = "https://registry.npmjs.org";

/// The website of the public registry.
pub const PUBLIC_WEB: &str = "https://www.npmjs.com";

/// Detector names and gitleaks rule ids that name npm.
const HINTS: &[&str] = &["NpmToken", "NpmTokenV2", "npm-access-token"];

const PREFIX: &[u8] = b"npm_";
/// Body length of a current token after `npm_`.
const BODY: usize = 36;
/// Longest body accepted from a hinted finding.
const MAX_BODY: usize = 255;

const WHOAMI: &str = "GET /-/whoami";
const LIST: &str = "GET /-/npm/v1/tokens";
const DELETE: &str = "DELETE /-/npm/v1/tokens/token";

const PER_PAGE: u32 = 100;
/// Upper bound on followed pages, so a looping `next` link cannot hang.
const MAX_PAGES: usize = 50;
const MAX_MESSAGE: usize = 200;
const MAX_ERROR_BODY: usize = 8 * 1024;
/// Longest name or list item kept in a scope line.
const MAX_FIELD: usize = 100;
/// Most list items kept in one scope line.
const MAX_ITEMS: usize = 50;
/// Shortest redacted prefix and suffix that may identify a token.
const MIN_REDACTED_PREFIX: usize = 8;
const MIN_REDACTED_SUFFIX: usize = 4;
const TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads the operator token with `lookup`: [`TOKEN_VARS`] in order, an
/// empty value counting as unset.
pub fn operator_token(lookup: impl Fn(&str) -> Option<String>) -> Option<SecretValue> {
    TOKEN_VARS
        .iter()
        .find_map(|name| lookup(name).filter(|v| !v.is_empty()))
        .map(SecretValue::from)
}

/// npm's old token key: the sha512 of the token, as lowercase hex. One-way,
/// so it may appear in a URL and a log.
pub fn token_key(token: &[u8]) -> String {
    Sha512::digest(token)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// True for an npm token id: a UUID (current tokens) or a 128-hex sha512
/// key (old tokens). Anything else, a token value above all, is never put
/// in a delete path.
pub fn is_token_id(id: &str) -> bool {
    let b = id.as_bytes();
    let uuid = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        });
    let key = b.len() == 128 && b.iter().all(u8::is_ascii_hexdigit);
    uuid || key
}

/// The body length after `npm_` when `token` is `npm_` plus alphanumerics
/// of a plausible length.
fn body_len(token: &[u8]) -> Option<usize> {
    let body = token.strip_prefix(PREFIX)?;
    let shaped =
        (BODY..=MAX_BODY).contains(&body.len()) && body.iter().all(|b| b.is_ascii_alphanumeric());
    shaped.then_some(body.len())
}

/// Why an npm call failed. Never holds a token or a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NpmError {
    /// The token has bytes that cannot go in an HTTP header.
    InvalidToken,
    /// HTTP 429.
    RateLimited { retry_after: Option<Duration> },
    /// Any other non-success status, with npm's message.
    Status {
        status: u16,
        message: String,
        /// npm asked for a one-time password.
        otp: bool,
    },
    /// The request did not complete.
    Transport(String),
    /// The response did not have the expected shape.
    Decode(String),
}

impl fmt::Display for NpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NpmError::InvalidToken => f.write_str("the npm token is not a valid HTTP header value"),
            NpmError::RateLimited { .. } => f.write_str("rate limited by npm"),
            NpmError::Status {
                status, message, ..
            } => write!(f, "npm returned {status}: {message}"),
            NpmError::Transport(e) => write!(f, "npm request failed: {e}"),
            NpmError::Decode(e) => write!(f, "unexpected npm response: {e}"),
        }
    }
}

/// `err` as a provider error with the endpoint in front.
fn op_error(op: &str, err: NpmError) -> ProviderError {
    match err {
        NpmError::RateLimited { retry_after } => ProviderError::RateLimited { retry_after },
        NpmError::Status { status, .. } if status >= 500 => {
            ProviderError::Transient(format!("{op}: {err}"))
        }
        NpmError::Transport(_) => ProviderError::Transient(format!("{op}: {err}")),
        other => ProviderError::Permanent(format!("{op}: {other}")),
    }
}

/// One entry of `GET /-/npm/v1/tokens`. Every field is optional: the
/// registry has changed this shape before (`cidr_whitelist` became `cidr`,
/// `automation` gave way to `bypass_2fa`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TokenEntry {
    /// Token id: a UUID, or the sha512 hex key for old tokens.
    pub key: Option<String>,
    /// The token redacted by npm, `npm_aBcD...7890`. Never printed.
    pub token: Option<String>,
    /// Human-readable name.
    pub name: Option<String>,
    /// Read-only token.
    pub readonly: Option<bool>,
    /// Old automation token.
    pub automation: Option<bool>,
    /// Granular token that skips 2FA for automation.
    pub bypass_2fa: Option<bool>,
    /// Allowed IP ranges.
    pub cidr: Option<Vec<String>>,
    /// Allowed IP ranges, old field name.
    pub cidr_whitelist: Option<Vec<String>>,
    /// Granted permissions.
    pub permissions: Option<Vec<Permission>>,
    /// Packages, scopes and orgs it reaches.
    pub scopes: Option<Vec<TokenScope>>,
    /// Creation time.
    pub created: Option<String>,
    /// Expiry time.
    pub expiry: Option<String>,
    /// Revocation time, when already revoked.
    pub revoked: Option<String>,
}

/// One permission of a granular token.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Permission {
    /// For example `package`.
    pub name: Option<String>,
    /// `read` or `write`.
    pub action: Option<String>,
}

/// One scope of a granular token.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TokenScope {
    /// For example `package` or `org`.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Package, scope or org name.
    pub name: Option<String>,
}

#[derive(Deserialize)]
struct TokenPage {
    #[serde(default)]
    objects: Vec<TokenEntry>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    urls: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Deserialize)]
struct Whoami {
    username: String,
}

/// How an entry was matched to the leaked token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedBy {
    /// Its `key` is the token's sha512 hex: an old-scheme token.
    Key,
    /// Its redacted `token` fits the leaked token.
    Redacted,
}

/// What the operator's token list says about the leaked token.
#[derive(Debug, Clone)]
pub enum Lookup {
    /// One entry is the leaked token.
    Found(Box<TokenEntry>, MatchedBy),
    /// No entry could be tied to it, and why.
    Missing(String),
}

/// True when npm's redacted form `redacted` fits `token`.
fn redaction_fits(redacted: &str, token: &[u8]) -> bool {
    let Some((prefix, suffix)) = redacted
        .split_once("...")
        .or_else(|| redacted.split_once('\u{2026}'))
    else {
        return false;
    };
    prefix.len() >= MIN_REDACTED_PREFIX
        && suffix.len() >= MIN_REDACTED_SUFFIX
        && token.len() >= prefix.len() + suffix.len()
        && token.starts_with(prefix.as_bytes())
        && token.ends_with(suffix.as_bytes())
}

/// The entry for `token` in `entries`. A `key` match is exact; a redaction
/// match counts only when exactly one entry fits.
pub fn find_entry(entries: &[TokenEntry], token: &SecretValue) -> Lookup {
    let key = token.expose_secret(token_key);
    if let Some(entry) = entries.iter().find(|e| {
        e.key
            .as_deref()
            .is_some_and(|k| k.eq_ignore_ascii_case(&key))
    }) {
        return Lookup::Found(Box::new(entry.clone()), MatchedBy::Key);
    }
    let fits: Vec<&TokenEntry> = entries
        .iter()
        .filter(|e| {
            e.token
                .as_deref()
                .is_some_and(|r| token.expose_secret(|t| redaction_fits(r, t)))
        })
        .collect();
    match fits.as_slice() {
        [one] => Lookup::Found(Box::new((*one).clone()), MatchedBy::Redacted),
        [] => Lookup::Missing(format!(
            "none of the operator account's {} tokens match",
            entries.len()
        )),
        many => Lookup::Missing(format!(
            "{} of the operator account's tokens match the redacted form; delete it by hand",
            many.len()
        )),
    }
}

/// A name or list item: no control characters, capped.
fn clean(text: &str) -> String {
    let text: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FIELD)
        .collect();
    crate::redact::redact(text.trim()).into_owned()
}

fn list_line(name: &str, items: Vec<String>) -> Option<String> {
    let items: Vec<String> = items
        .into_iter()
        .map(|i| clean(&i))
        .filter(|i| !i.is_empty())
        .take(MAX_ITEMS)
        .collect();
    (!items.is_empty()).then(|| format!("{name}: {}", items.join(", ")))
}

/// The token type for the scope: old-scheme entries were publish,
/// automation or read-only tokens; current ones are granular.
fn token_type(entry: &TokenEntry, by: MatchedBy) -> &'static str {
    match by {
        MatchedBy::Key if entry.automation == Some(true) => "automation",
        MatchedBy::Key if entry.readonly == Some(true) => "read-only",
        MatchedBy::Key => "publish",
        MatchedBy::Redacted => "granular",
    }
}

/// Scope lines for a matched entry. Pure, so unit-tested. Never includes
/// the redacted token.
pub fn entry_lines(entry: &TokenEntry, by: MatchedBy) -> Vec<String> {
    let mut lines = vec![format!("type: {}", token_type(entry, by))];
    if let Some(name) = entry.name.as_deref().map(clean).filter(|n| !n.is_empty()) {
        lines.push(format!("name: {name}"));
    }
    if let Some(readonly) = entry.readonly {
        lines.push(format!(
            "access: {}",
            if readonly { "read-only" } else { "read-write" }
        ));
    }
    if let Some(automation) = entry.automation {
        lines.push(format!("automation: {automation}"));
    }
    if let Some(bypass) = entry.bypass_2fa {
        lines.push(format!("bypass_2fa: {bypass}"));
    }
    let cidr = entry
        .cidr
        .clone()
        .or_else(|| entry.cidr_whitelist.clone())
        .unwrap_or_default();
    lines.push(list_line("cidr", cidr).unwrap_or_else(|| "cidr: any".to_owned()));
    let permissions = entry
        .permissions
        .iter()
        .flatten()
        .map(|p| {
            format!(
                "{}:{}",
                p.name.as_deref().unwrap_or("?"),
                p.action.as_deref().unwrap_or("?")
            )
        })
        .collect();
    lines.extend(list_line("permissions", permissions));
    let scopes = entry
        .scopes
        .iter()
        .flatten()
        .map(|s| {
            format!(
                "{}:{}",
                s.kind.as_deref().unwrap_or("?"),
                s.name.as_deref().unwrap_or("?")
            )
        })
        .collect();
    lines.extend(list_line("scopes", scopes));
    for (label, value) in [("created", &entry.created), ("expires", &entry.expiry)] {
        if let Some(value) = value.as_deref().map(clean).filter(|v| !v.is_empty()) {
            lines.push(format!("{label}: {value}"));
        }
    }
    lines
}

/// The npm token provider.
pub struct NpmProvider {
    base: String,
    operator: OnceLock<Option<SecretValue>>,
    http: OnceLock<Result<reqwest::Client, String>>,
}

impl fmt::Debug for NpmProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operator = match self.operator.get() {
            None => "[not loaded]",
            Some(None) => "[unset]",
            Some(Some(_)) => "[set]",
        };
        f.debug_struct("NpmProvider")
            .field("base", &self.base)
            .field("operator", &operator)
            .finish()
    }
}

impl NpmProvider {
    /// A provider for the registry at `registry_url`
    /// (`providers.npm.registry`, [`PUBLIC_REGISTRY`] by default). The
    /// operator token is read from [`TOKEN_VARS`] on first use. Makes no
    /// call.
    pub fn new(registry_url: &str) -> Self {
        Self {
            base: registry_url.trim_end_matches('/').to_owned(),
            operator: OnceLock::new(),
            http: OnceLock::new(),
        }
    }

    /// Uses `token` as the operator token instead of the environment.
    pub fn with_operator_token(self, token: Option<SecretValue>) -> Self {
        let operator = OnceLock::new();
        let _ = operator.set(token);
        Self { operator, ..self }
    }

    /// The registry base URL without a trailing slash.
    pub fn registry_url(&self) -> &str {
        &self.base
    }

    /// The website for the registry, when rotate knows it: the public
    /// registry's is [`PUBLIC_WEB`].
    pub fn web_url(&self) -> Option<&'static str> {
        (self.base == PUBLIC_REGISTRY).then_some(PUBLIC_WEB)
    }

    /// Where `user` (or, when unknown, the account owner) deletes tokens
    /// by hand.
    fn tokens_page(&self, user: Option<&str>) -> String {
        match (self.web_url(), user) {
            (Some(web), Some(user)) => format!("{web}/settings/{user}/tokens"),
            (Some(web), None) => format!("{web}/settings/<username>/tokens"),
            (None, Some(user)) => format!("the token settings of {user} on {}", self.base),
            (None, None) => format!("the account's token settings on {}", self.base),
        }
    }

    fn operator(&self) -> Option<&SecretValue> {
        self.operator
            .get_or_init(|| operator_token(|name| std::env::var(name).ok()))
            .as_ref()
    }

    fn http(&self) -> Result<&reqwest::Client, NpmError> {
        self.http
            .get_or_init(|| {
                reqwest::Client::builder()
                    .timeout(TIMEOUT)
                    .connect_timeout(CONNECT_TIMEOUT)
                    .build()
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| NpmError::Transport(e.clone()))
    }

    /// Sends one request signed with `token` to an absolute `url` and
    /// returns the response when its status is a success.
    async fn send(
        &self,
        method: Method,
        url: &str,
        token: &SecretValue,
    ) -> Result<Response, NpmError> {
        let response = self
            .http()?
            .request(method, url)
            .headers(headers(token)?)
            .send()
            .await
            .map_err(|e| NpmError::Transport(e.without_url().to_string()))?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(error_from(response).await)
        }
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        token: &SecretValue,
    ) -> Result<T, NpmError> {
        let response = self.send(Method::GET, url, token).await?;
        let bytes = response
            .bytes()
            .await
            .map_err(|e| NpmError::Transport(e.without_url().to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| NpmError::Decode(e.to_string()))
    }

    /// `GET /-/whoami` signed with `token`: the username.
    async fn whoami(&self, token: &SecretValue) -> Result<String, NpmError> {
        let who: Whoami = self
            .get_json(&format!("{}/-/whoami", self.base), token)
            .await?;
        let user = clean(&who.username);
        if user.is_empty() {
            return Err(NpmError::Decode(
                "GET /-/whoami returned no username".into(),
            ));
        }
        Ok(user)
    }

    /// Every entry of the operator's token list, following `urls.next`
    /// while it stays under the registry URL.
    async fn list(&self, operator: &SecretValue) -> Result<Vec<TokenEntry>, NpmError> {
        let page_url = |page: usize| {
            format!(
                "{}/-/npm/v1/tokens?page={page}&perPage={PER_PAGE}",
                self.base
            )
        };
        let mut url = page_url(0);
        let mut entries = Vec::new();
        for page in 0..MAX_PAGES {
            let body: TokenPage = self.get_json(&url, operator).await?;
            let empty = body.objects.is_empty();
            entries.extend(body.objects);
            let next = body
                .urls
                .as_ref()
                .and_then(|u| u.get("next"))
                .and_then(serde_json::Value::as_str)
                .filter(|n| !n.is_empty());
            url = match next {
                Some(next) if next.starts_with('/') => format!("{}{next}", self.base),
                Some(next) if self.is_under_base(next) => next.to_owned(),
                Some(_) => {
                    return Err(NpmError::Decode(
                        "pagination link points outside the registry URL".into(),
                    ))
                }
                None if !empty && body.total.is_some_and(|t| t > entries.len() as u64) => {
                    page_url(page + 1)
                }
                None => return Ok(entries),
            };
        }
        Err(NpmError::Decode(format!(
            "more than {MAX_PAGES} pages of tokens; stopping"
        )))
    }

    fn is_under_base(&self, url: &str) -> bool {
        url.strip_prefix(&self.base)
            .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('?'))
    }

    /// The leaked token's entry in the operator's token list, or why there
    /// is none. Only a rate limit is an error, so callers can retry.
    pub async fn lookup(&self, token: &SecretValue) -> Result<Lookup, ProviderError> {
        let Some(operator) = self.operator() else {
            return Ok(Lookup::Missing(
                "no operator token: set ROTATE_NPM_TOKEN or NPM_TOKEN to an `npm login` session \
                 token"
                    .into(),
            ));
        };
        if operator == token {
            return Ok(Lookup::Missing(
                "the operator token is the leaked token; rotate does not use it (decision D3)"
                    .into(),
            ));
        }
        match self.list(operator).await {
            Ok(entries) => Ok(find_entry(&entries, token)),
            Err(err @ NpmError::RateLimited { .. }) => Err(op_error(LIST, err)),
            Err(err @ NpmError::Status { status, .. }) if status == 401 || status == 403 => {
                Ok(Lookup::Missing(format!(
                    "{LIST}: {err}; {LIST_REFUSED} in ROTATE_NPM_TOKEN, not a granular access \
                     token; {SESSION_EXPIRY}"
                )))
            }
            Err(err) => Ok(Lookup::Missing(format!("{LIST}: {err}"))),
        }
    }

    /// `DELETE /-/npm/v1/tokens/token/{key}` signed with the operator
    /// token. 2xx and 404 (already deleted) are `Ok`.
    async fn delete(
        &self,
        key: &str,
        operator: &SecretValue,
        user: Option<&str>,
    ) -> Result<(), ProviderError> {
        if !is_token_id(key) {
            return Err(ProviderError::Permanent(format!(
                "{DELETE}: npm listed the token with an id rotate does not recognise; delete it \
                 at {}",
                self.tokens_page(user)
            )));
        }
        let url = format!("{}/-/npm/v1/tokens/token/{key}", self.base);
        match self.send(Method::DELETE, &url, operator).await {
            Ok(_) | Err(NpmError::Status { status: 404, .. }) => Ok(()),
            Err(NpmError::Status {
                status: 401,
                otp: true,
                ..
            }) => Err(ProviderError::Permanent(format!(
                "{DELETE}: npm requires a one-time password to delete tokens for this account; \
                 rotate does not send one. Delete the token at {}",
                self.tokens_page(user)
            ))),
            Err(err @ NpmError::Status { status: 403, .. }) if bypass_refusal(&err) => {
                Err(ProviderError::Permanent(format!(
                    "{DELETE}: {err}. A granular token that bypasses 2FA cannot delete tokens; use \
                     an npm login session token as ROTATE_NPM_TOKEN, or delete the token at {}",
                    self.tokens_page(user)
                )))
            }
            Err(err @ NpmError::Status { status: 403, .. }) => {
                Err(ProviderError::Permanent(format!(
                    "{DELETE}: {err}. The operator token may not delete tokens; use an npm login \
                     session token as ROTATE_NPM_TOKEN, or delete the token at {}",
                    self.tokens_page(user)
                )))
            }
            Err(err) => Err(op_error(DELETE, err)),
        }
    }
}

/// True for npm's 403 to a granular token that bypasses 2FA.
fn bypass_refusal(err: &NpmError) -> bool {
    match err {
        NpmError::Status { message, .. } => {
            let lower = message.to_ascii_lowercase();
            lower.contains("two-factor") || lower.contains("bypass")
        }
        _ => false,
    }
}

/// `Authorization: Bearer <token>` (sensitive) plus the standard headers.
fn headers(token: &SecretValue) -> Result<HeaderMap, NpmError> {
    let mut value = token.expose_secret(|t| {
        let mut bytes = Zeroizing::new(Vec::with_capacity(t.len() + 7));
        bytes.extend_from_slice(b"Bearer ");
        bytes.extend_from_slice(t);
        HeaderValue::from_bytes(&bytes).map_err(|_| NpmError::InvalidToken)
    })?;
    value.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, value);
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(concat!("rotate/", env!("CARGO_PKG_VERSION"))),
    );
    Ok(headers)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

async fn error_from(response: Response) -> NpmError {
    let status = response.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        return NpmError::RateLimited {
            retry_after: header(response.headers(), "retry-after")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs),
        };
    }
    let challenge = header(response.headers(), "www-authenticate")
        .is_some_and(|v| v.to_ascii_lowercase().contains("otp"));
    let body = response.bytes().await.unwrap_or_default();
    let body = &body[..body.len().min(MAX_ERROR_BODY)];
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            ["error", "message"]
                .iter()
                .find_map(|f| v.get(*f)?.as_str().map(clean_message))
        })
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned());
    let lower = message.to_ascii_lowercase();
    let otp = status == StatusCode::UNAUTHORIZED
        && (challenge || lower.contains("otp") || lower.contains("one-time"));
    NpmError::Status {
        status: status.as_u16(),
        message,
        otp,
    }
}

/// npm's message, single-line, capped and scrubbed of token shapes.
fn clean_message(message: &str) -> String {
    let line: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_MESSAGE)
        .collect();
    crate::redact::redact(&line).into_owned()
}

/// The single token in `credential`, when it has the npm format; anything
/// else is refused before any call, so rotate never sends an unrecognised
/// value to npm.
fn token(credential: &Credential) -> Result<&SecretValue, ProviderError> {
    match credential {
        Credential::Token(token) if token.expose_secret(body_len).is_some() => Ok(token),
        Credential::Token(_) => Err(ProviderError::Unsupported(
            "the value does not have the npm token format (npm_ plus 36 letters and digits)".into(),
        )),
        Credential::KeyPair(_) => Err(ProviderError::Unsupported(
            "an npm token is a single value, not a key pair".into(),
        )),
    }
}

/// The value of the scope line `name: value`.
fn line<'a>(scope: &'a Scope, name: &str) -> Option<&'a str> {
    scope
        .lines
        .iter()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(": "))
}

#[async_trait]
impl Provider for NpmProvider {
    fn name(&self) -> &'static str {
        NAME
    }

    fn replacement_mode(&self) -> ReplacementMode {
        ReplacementMode::Manual
    }

    /// The granular token page, plus the permissions, scopes, access and
    /// IP ranges `describe_scope` read from the token list.
    fn manual_instructions(&self, scope: &Scope) -> String {
        let user = &scope.identity;
        let copied: Vec<String> = ["permissions", "scopes", "access", "cidr", "bypass_2fa"]
            .iter()
            .filter_map(|name| line(scope, name).map(|v| format!("{name} {v}")))
            .collect();
        let same = if line(scope, "type").is_some() && !copied.is_empty() {
            format!(
                "with the same settings as the leaked one: {}",
                copied.join("; ")
            )
        } else {
            "with the same packages, scopes and permissions as the leaked one (rotate could not \
             read them: the token is not in the operator account's token list)"
                .to_owned()
        };
        let place = match self.web_url() {
            Some(web) => format!(
                "at {web}/settings/{user}/tokens/granular-access-tokens/new (or with `npm token \
                 create`)"
            ),
            None => format!("on {} (for example with `npm token create`)", self.base),
        };
        format!(
            "Create a new granular access token for {user} {place} {same}. Read-write tokens \
             last at most 90 days. Then paste it at the prompt."
        )
    }

    /// A blocker when revoke cannot work with the operator token as set:
    /// none set, the leaked token itself (decision D3), or one npm refused
    /// on the token list (the scope's [`NOT_VISIBLE`] line says
    /// [`LIST_REFUSED`]). Reads the environment once; no network.
    fn revoke_blocker(&self, credential: &Credential, scope: Option<&Scope>) -> Option<String> {
        let Credential::Token(leaked) = credential else {
            return None;
        };
        let Some(operator) = self.operator() else {
            return Some(format!(
                "{NO_OPERATOR}: set ROTATE_NPM_TOKEN to an `npm login` session token of the same \
                 account (npm lists tokens only for a session token, not a granular access \
                 token); {SESSION_EXPIRY}; {REVOKE_FAILS}"
            ));
        };
        if operator == leaked {
            return Some(format!(
                "the npm operator token is the leaked token and rotate never uses it (decision \
                 D3): set ROTATE_NPM_TOKEN to another `npm login` session token of the same \
                 account; {REVOKE_FAILS}"
            ));
        }
        let refused = scope.is_some_and(|s| {
            s.lines
                .iter()
                .any(|l| l.starts_with(NOT_VISIBLE) && l.contains(LIST_REFUSED))
        });
        refused.then(|| {
            format!(
                "npm refused the operator token on the token list: ROTATE_NPM_TOKEN (or \
                 NPM_TOKEN) must be an `npm login` session token, not a granular access token; \
                 {SESSION_EXPIRY}; {REVOKE_FAILS}"
            )
        })
    }

    fn identify(&self, finding: &Finding) -> Option<Confidence> {
        let Credential::Token(raw) = finding.credential() else {
            return None;
        };
        let hinted = HINTS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&finding.detector));
        match raw.expose_secret(body_len)? {
            BODY if hinted => Some(Confidence::High),
            BODY => Some(Confidence::Medium),
            _ if hinted => Some(Confidence::Low),
            _ => None,
        }
    }

    /// `GET /-/whoami` signed with the token: 200 valid, 401 invalid.
    async fn check_valid(&self, credential: &Credential) -> Result<Validity, ProviderError> {
        let token = token(credential)?;
        match self.whoami(token).await {
            Ok(_) => Ok(Validity::Valid),
            Err(NpmError::Status { status: 401, .. }) => Ok(Validity::Invalid),
            Err(err @ NpmError::Status { status, .. }) if status < 500 => Ok(Validity::Unknown {
                reason: format!("{WHOAMI}: {err}"),
            }),
            Err(err) => Err(op_error(WHOAMI, err)),
        }
    }

    /// The username from `whoami`, then the token's entry in the
    /// operator's token list: type, name, access, flags, IP ranges,
    /// permissions, scopes and dates, or [`NOT_VISIBLE`] with the reason.
    async fn describe_scope(&self, credential: &Credential) -> Result<Scope, ProviderError> {
        let token = token(credential)?;
        let user = self.whoami(token).await.map_err(|e| op_error(WHOAMI, e))?;
        let mut lines = vec![format!("user: {user}")];
        match self.lookup(token).await? {
            Lookup::Found(entry, by) => lines.extend(entry_lines(&entry, by)),
            Lookup::Missing(why) => lines.push(format!("{NOT_VISIBLE} ({why})")),
        }
        Ok(Scope {
            identity: Identity(user),
            lines,
        })
    }

    /// npm needs the account password and a one-time password to create a
    /// token: manual mode never calls this.
    async fn create_replacement(
        &self,
        _credential: &Credential,
    ) -> Result<Replacement, ProviderError> {
        Err(ProviderError::Unsupported(
            "npm creates tokens only with the account password and a one-time password; rotate \
             asks for the new token instead"
                .into(),
        ))
    }

    /// `GET /-/whoami` signed with the replacement; its username must be
    /// `identity`.
    async fn verify(
        &self,
        credential: &Credential,
        identity: &Identity,
    ) -> Result<(), ProviderError> {
        let token = token(credential)?;
        match self.whoami(token).await {
            Ok(user) if user.eq_ignore_ascii_case(&identity.0) => Ok(()),
            Ok(user) => Err(ProviderError::Permanent(format!(
                "the replacement token belongs to npm user {user} but the leaked token belongs \
                 to {identity}"
            ))),
            Err(NpmError::Status { status: 401, .. }) => Err(ProviderError::Permanent(format!(
                "{WHOAMI}: npm did not accept the replacement token (401)"
            ))),
            Err(err) => Err(op_error(WHOAMI, err)),
        }
    }

    /// Finds the token in the operator's list and deletes it by its `key`,
    /// signed with the operator token. An entry already revoked, a 404, or
    /// a token missing from the list that `whoami` rejects is `Ok`. Never
    /// restorable.
    async fn revoke(&self, credential: &Credential) -> Result<Revoked, ProviderError> {
        let token = token(credential)?;
        let Some(operator) = self.operator() else {
            return Err(ProviderError::Permanent(
                "no npm operator token: set ROTATE_NPM_TOKEN or NPM_TOKEN to an npm login session \
                 token to delete the leaked token"
                    .into(),
            ));
        };
        if operator == token {
            return Err(ProviderError::Permanent(
                "the npm operator token is the leaked token; rotate never uses the leaked token \
                 to revoke itself (decision D3). Set ROTATE_NPM_TOKEN to another session token"
                    .into(),
            ));
        }
        let entries = self.list(operator).await.map_err(|e| op_error(LIST, e))?;
        match find_entry(&entries, token) {
            Lookup::Found(entry, _) if entry.revoked.is_some() => {}
            Lookup::Found(entry, _) => {
                let key = entry.key.unwrap_or_default();
                self.delete(&key, operator, None).await?;
            }
            Lookup::Missing(why) => match self.whoami(token).await {
                Err(NpmError::Status { status: 401, .. }) => {}
                Ok(user) => {
                    return Err(ProviderError::Permanent(format!(
                        "{NOT_VISIBLE} ({why}); the token belongs to npm user {user}: delete it \
                         at {}",
                        self.tokens_page(Some(&user))
                    )))
                }
                Err(err) => return Err(op_error(WHOAMI, err)),
            },
        }
        Ok(Revoked { restore_ref: None })
    }

    /// npm cannot reactivate a deleted token.
    async fn restore(&self, _restore_ref: &str) -> Result<RestoreOutcome, ProviderError> {
        Ok(RestoreOutcome::Unsupported)
    }

    /// Deletes a replacement by its npm token id (a UUID or sha512 key),
    /// signed with the operator token. rotate records a pasted replacement
    /// as `manual`, with no id: that and any other ref are `Unsupported`
    /// with no call.
    async fn revoke_replacement(&self, replacement_ref: &str) -> Result<(), ProviderError> {
        if !is_token_id(replacement_ref) {
            return Err(ProviderError::Unsupported(
                "npm deletes a replacement only by its token id; revoke the pasted token by hand"
                    .into(),
            ));
        }
        let Some(operator) = self.operator() else {
            return Err(ProviderError::Permanent(
                "no npm operator token: set ROTATE_NPM_TOKEN or NPM_TOKEN to an npm login session \
                 token"
                    .into(),
            ));
        };
        self.delete(replacement_ref, operator, None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{SourceLocation, ACCESS_KEY_ID};

    /// A token built at runtime so no literal here matches a secret
    /// scanner pattern.
    fn tok(len: usize) -> String {
        format!(
            "{}{}",
            ["np", "m_"].concat(),
            &"Ab1C".repeat(len / 4 + 1)[..len]
        )
    }

    fn finding(value: &str, detector: &str) -> Finding {
        Finding::new(
            SecretValue::from(value),
            detector,
            SourceLocation::file(".npmrc"),
        )
    }

    fn provider() -> NpmProvider {
        NpmProvider::new(PUBLIC_REGISTRY).with_operator_token(None)
    }

    // T1 (AC1)
    #[test]
    fn identify_npm_tokens_not_openai() {
        let p = provider();
        let value = tok(BODY);
        for hint in HINTS {
            assert_eq!(
                p.identify(&finding(&value, hint)),
                Some(Confidence::High),
                "{hint}"
            );
        }
        assert_eq!(
            p.identify(&finding(&value, "npmtoken")),
            Some(Confidence::High)
        );
        assert_eq!(
            p.identify(&finding(&value, "stdin")),
            Some(Confidence::Medium)
        );
        // Another length only with a hint, at low confidence.
        assert_eq!(
            p.identify(&finding(&tok(40), "NpmToken")),
            Some(Confidence::Low)
        );
        assert_eq!(p.identify(&finding(&tok(40), "stdin")), None);

        // OpenAI keys, GitHub tokens and an AWS pair are not npm tokens.
        let openai = format!("{}{}", ["sk-", "proj-"].concat(), "Ab1C".repeat(12));
        assert_eq!(p.identify(&finding(&openai, "OpenAI")), None);
        assert_eq!(p.identify(&finding(&openai, "NpmToken")), None);
        let classic = format!("{}{}", ["gh", "p_"].concat(), "Ab1C".repeat(9));
        assert_eq!(p.identify(&finding(&classic, "Github")), None);
        let aws_id = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let pair = finding("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01", "AWS")
            .with_extra(ACCESS_KEY_ID, aws_id);
        assert_eq!(p.identify(&pair), None);

        // Shapes that are not tokens.
        assert_eq!(p.identify(&finding("", "NpmToken")), None);
        assert_eq!(p.identify(&finding(&tok(20), "NpmToken")), None);
        let dashed = format!("{}{}", ["np", "m_"].concat(), "a-b".repeat(12));
        assert_eq!(p.identify(&finding(&dashed, "NpmToken")), None);
        // A legacy UUID token: npm revoked them all.
        assert_eq!(
            p.identify(&finding("12345678-1234-1234-1234-123456789abc", "NpmToken")),
            None
        );
    }

    // T4 (AC4): known answer for the key scheme.
    #[test]
    fn key_is_sha512_hex() {
        assert_eq!(
            token_key(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        let key = token_key(tok(BODY).as_bytes());
        assert_eq!(key.len(), 128);
        assert!(is_token_id(&key));
    }

    #[test]
    fn token_ids() {
        assert!(is_token_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890"));
        assert!(!is_token_id("a1b2c3d4-e5f6-7890-abcd-ef123456789"));
        assert!(!is_token_id("a1b2c3d4xe5f6-7890-abcd-ef1234567890"));
        assert!(!is_token_id(&tok(BODY)));
        assert!(!is_token_id("manual"));
        assert!(!is_token_id(""));
        assert!(!is_token_id(&"g".repeat(128)));
    }

    fn entry(key: &str, redacted: &str) -> TokenEntry {
        TokenEntry {
            key: Some(key.into()),
            token: Some(redacted.into()),
            ..TokenEntry::default()
        }
    }

    #[test]
    fn find_by_key_or_unique_redaction() {
        let value = tok(BODY);
        let secret = SecretValue::from(value.as_str());
        let redacted = format!("{}...{}", &value[..8], &value[value.len() - 4..]);
        let uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

        let by_key = [
            entry(uuid, &redacted),
            entry(&token_key(value.as_bytes()), "abcdef"),
        ];
        assert!(matches!(
            find_entry(&by_key, &secret),
            Lookup::Found(e, MatchedBy::Key) if e.token.as_deref() == Some("abcdef")
        ));

        let by_redaction = [entry(uuid, &redacted), entry("other", "npm_zzzz...zzzz")];
        assert!(matches!(
            find_entry(&by_redaction, &secret),
            Lookup::Found(e, MatchedBy::Redacted) if e.key.as_deref() == Some(uuid)
        ));
        let unicode = format!("{}\u{2026}{}", &value[..8], &value[value.len() - 4..]);
        assert!(matches!(
            find_entry(&[entry(uuid, &unicode)], &secret),
            Lookup::Found(_, MatchedBy::Redacted)
        ));

        // Two fits are ambiguous; a short prefix alone never matches.
        let twice = [entry(uuid, &redacted), entry("other", &redacted)];
        assert!(matches!(
            find_entry(&twice, &secret),
            Lookup::Missing(why) if why.contains("2 of")
        ));
        let short = [entry(uuid, &value[..6])];
        assert!(matches!(find_entry(&short, &secret), Lookup::Missing(_)));
        let short_parts = [entry(uuid, &format!("{}...{}", &value[..6], &value[34..]))];
        assert!(matches!(
            find_entry(&short_parts, &secret),
            Lookup::Missing(_)
        ));
        assert!(matches!(find_entry(&[], &secret), Lookup::Missing(_)));
    }

    #[test]
    fn granular_entry_lines() {
        let e: TokenEntry = serde_json::from_value(serde_json::json!({
            "key": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "token": "npm_AbCd...wxyz",
            "name": "ci\npublish",
            "readonly": false,
            "bypass_2fa": true,
            "cidr": ["10.0.0.0/8", "192.168.1.0/24"],
            "permissions": [{ "name": "package", "action": "write" }],
            "scopes": [{ "type": "package", "name": "@acme/app" }, { "type": "org", "name": "acme" }],
            "created": "2026-09-01T00:00:00.000Z",
            "expiry": "2026-11-30T00:00:00.000Z",
            "revoked": null,
            "unknown_field": 1
        }))
        .unwrap();
        assert_eq!(
            entry_lines(&e, MatchedBy::Redacted),
            [
                "type: granular",
                "name: cipublish",
                "access: read-write",
                "bypass_2fa: true",
                "cidr: 10.0.0.0/8, 192.168.1.0/24",
                "permissions: package:write",
                "scopes: package:@acme/app, org:acme",
                "created: 2026-09-01T00:00:00.000Z",
                "expires: 2026-11-30T00:00:00.000Z",
            ]
        );
        assert!(!entry_lines(&e, MatchedBy::Redacted)
            .iter()
            .any(|l| l.contains("npm_AbCd")));
    }

    #[test]
    fn legacy_entry_types() {
        let legacy = |readonly: bool, automation: bool| TokenEntry {
            readonly: Some(readonly),
            automation: Some(automation),
            cidr_whitelist: Some(vec!["10.0.0.0/8".into()]),
            ..TokenEntry::default()
        };
        let lines = entry_lines(&legacy(false, false), MatchedBy::Key);
        assert_eq!(
            lines,
            [
                "type: publish",
                "access: read-write",
                "automation: false",
                "cidr: 10.0.0.0/8"
            ]
        );
        assert_eq!(
            entry_lines(&legacy(true, false), MatchedBy::Key)[0],
            "type: read-only"
        );
        assert_eq!(
            entry_lines(&legacy(false, true), MatchedBy::Key)[0],
            "type: automation"
        );
        assert!(entry_lines(&TokenEntry::default(), MatchedBy::Redacted)
            .contains(&"cidr: any".to_owned()));
    }

    fn scope_of(lines: &[&str]) -> Scope {
        Scope {
            identity: Identity("alice".into()),
            lines: lines.iter().map(|l| (*l).to_owned()).collect(),
        }
    }

    #[test]
    fn manual_instructions_copy_settings() {
        let text = provider().manual_instructions(&scope_of(&[
            "user: alice",
            "type: granular",
            "access: read-write",
            "cidr: 10.0.0.0/8",
            "permissions: package:write",
            "scopes: package:@acme/app",
        ]));
        assert!(
            text.contains("https://www.npmjs.com/settings/alice/tokens/granular-access-tokens/new"),
            "{text}"
        );
        assert!(text.contains("permissions package:write"), "{text}");
        assert!(text.contains("scopes package:@acme/app"), "{text}");
        assert!(text.contains("cidr 10.0.0.0/8"), "{text}");

        let hidden = provider().manual_instructions(&scope_of(&[
            "user: alice",
            "token not visible to operator account (x)",
        ]));
        assert!(hidden.contains("could not read them"), "{hidden}");

        let private = NpmProvider::new("https://npm.example.com/")
            .with_operator_token(None)
            .manual_instructions(&scope_of(&["user: alice"]));
        assert!(private.contains("on https://npm.example.com"), "{private}");
    }

    // SHA-292: the revoke blocker names the variable and the token kind,
    // and never the token.
    #[test]
    fn revoke_blocker_cases() {
        let leaked = tok(BODY);
        let operator = format!("{}x", &tok(BODY)[..BODY + 3]);
        let cred = Credential::Token(SecretValue::from(leaked.as_str()));

        let none = provider().revoke_blocker(&cred, None).unwrap();
        assert!(none.starts_with(NO_OPERATOR), "{none}");
        for part in ["ROTATE_NPM_TOKEN", "`npm login` session token", "two hours"] {
            assert!(none.contains(part), "{part} missing: {none}");
        }

        let same = NpmProvider::new(PUBLIC_REGISTRY)
            .with_operator_token(Some(SecretValue::from(leaked.as_str())))
            .revoke_blocker(&cred, None)
            .unwrap();
        assert!(same.contains("D3"), "{same}");

        let set = NpmProvider::new(PUBLIC_REGISTRY)
            .with_operator_token(Some(SecretValue::from(operator.as_str())));
        assert_eq!(set.revoke_blocker(&cred, None), None);
        let visible = scope_of(&["user: alice", "type: granular"]);
        assert_eq!(set.revoke_blocker(&cred, Some(&visible)), None);
        let missing = scope_of(&["user: alice", &format!("{NOT_VISIBLE} (none of 3 match)")]);
        assert_eq!(set.revoke_blocker(&cred, Some(&missing)), None);
        let refused_line = format!("{NOT_VISIBLE} (GET /-/npm/v1/tokens: 403; {LIST_REFUSED} ...)");
        let refused = scope_of(&["user: alice", &refused_line]);
        let text = set.revoke_blocker(&cred, Some(&refused)).unwrap();
        assert!(text.contains("ROTATE_NPM_TOKEN"), "{text}");
        assert!(text.contains("not a granular access token"), "{text}");

        for text in [&none, &same, &text] {
            assert!(!text.contains(&leaked) && !text.contains(&operator));
        }
        let pair = Credential::KeyPair(crate::secret::SecretPair::new(
            "key-id",
            SecretValue::from("x"),
        ));
        assert_eq!(provider().revoke_blocker(&pair, None), None);
    }

    #[test]
    fn operator_token_order() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(
            operator_token(env(&[("ROTATE_NPM_TOKEN", "a"), ("NPM_TOKEN", "b")])),
            Some(SecretValue::from("a"))
        );
        assert_eq!(
            operator_token(env(&[("ROTATE_NPM_TOKEN", ""), ("NPM_TOKEN", "b")])),
            Some(SecretValue::from("b"))
        );
        assert_eq!(operator_token(env(&[])), None);
    }

    #[test]
    fn debug_hides_operator_token() {
        let p = NpmProvider::new(PUBLIC_REGISTRY)
            .with_operator_token(Some(SecretValue::from(tok(BODY))));
        let debug = format!("{p:?}");
        assert!(debug.contains("[set]"), "{debug}");
        assert!(!debug.contains(&tok(BODY)), "{debug}");
        assert!(format!("{:?}", NpmProvider::new(PUBLIC_REGISTRY)).contains("[not loaded]"));
    }

    // T9 (AC9): no client is ever built.
    #[tokio::test]
    async fn restore_unsupported_without_calls() {
        // An unroutable base: any call would fail with a transport error.
        let p = NpmProvider::new("http://127.0.0.1:1").with_operator_token(None);
        assert_eq!(
            p.restore("anything").await.unwrap(),
            RestoreOutcome::Unsupported
        );
        assert_eq!(p.replacement_mode(), ReplacementMode::Manual);
        let live = Credential::Token(SecretValue::from(tok(BODY)));
        assert!(matches!(
            p.create_replacement(&live).await,
            Err(ProviderError::Unsupported(_))
        ));
        assert!(matches!(
            p.revoke_replacement("manual").await,
            Err(ProviderError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn refused_shapes_make_no_call() {
        let p = NpmProvider::new("http://127.0.0.1:1").with_operator_token(None);
        let other = Credential::Token(SecretValue::from("not-an-npm-token-canary-61"));
        for err in [
            p.check_valid(&other).await.unwrap_err(),
            p.describe_scope(&other).await.unwrap_err(),
            p.revoke(&other).await.unwrap_err(),
            p.verify(&other, &Identity("x".into())).await.unwrap_err(),
        ] {
            assert!(matches!(err, ProviderError::Unsupported(_)), "{err}");
            assert!(!err.to_string().contains("canary-61"));
        }
        // No operator token: revoke refuses before any call.
        let live = Credential::Token(SecretValue::from(tok(BODY)));
        assert!(matches!(
            p.revoke(&live).await,
            Err(ProviderError::Permanent(text)) if text.contains("ROTATE_NPM_TOKEN")
        ));
    }

    #[test]
    fn clean_message_scrubs_token_shapes() {
        let value = tok(BODY);
        let text = clean_message(&format!("bad\ntoken {value}"));
        assert!(!text.contains(&value), "{text}");
        assert!(!text.contains('\n'));
        assert!(clean_message(&"x".repeat(500)).len() <= MAX_MESSAGE);
    }
}
