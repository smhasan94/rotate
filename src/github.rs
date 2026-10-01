//! A small GitHub REST client shared by the GitHub Actions consumer
//! (SHA-253) and, later, the GitHub token provider (SHA-260).
//!
//! It knows the base URL, the operator token, the standard headers,
//! `Link`-header pagination and GitHub's rate-limit signals. It knows
//! nothing about any one endpoint. Building a client makes no call and does
//! not touch the OS trust store; the HTTP client is built on first use.
//!
//! The operator token is a [`SecretValue`] and only ever leaves it as a
//! header marked sensitive. Errors carry the HTTP status and GitHub's own
//! `message` field, never a request body.

use std::fmt;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, LINK, USER_AGENT};
use reqwest::{Method, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::consumer::ConsumerError;
use crate::secret::SecretValue;

/// Environment variables holding the operator token, in order of
/// preference (FR24). The rotate-specific one wins so an Actions job can
/// pass an admin token without shadowing the job's own `GITHUB_TOKEN`.
pub const TOKEN_VARS: [&str; 2] = ["ROTATE_GITHUB_TOKEN", "GITHUB_TOKEN"];

/// The REST API version every request asks for.
pub const API_VERSION: &str = "2022-11-28";

const PER_PAGE: u32 = 100;
/// Upper bound on followed pages, so a looping `Link` header cannot hang.
const MAX_PAGES: usize = 100;
const MAX_MESSAGE: usize = 200;
const MAX_ERROR_BODY: usize = 8 * 1024;
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

/// Reads the operator token from the process environment.
pub fn operator_token_from_env() -> Option<SecretValue> {
    operator_token(|name| std::env::var(name).ok())
}

/// Why a GitHub call failed. Never holds a token or a request body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GithubError {
    /// No operator token in the environment.
    #[error("no GitHub token: set ROTATE_GITHUB_TOKEN or GITHUB_TOKEN")]
    NoToken,
    /// The token has bytes that cannot go in an HTTP header.
    #[error("the GitHub token is not a valid HTTP header value")]
    InvalidToken,
    /// HTTP 429, or 403 with the rate-limit headers exhausted.
    #[error("rate limited by GitHub")]
    RateLimited {
        /// From `retry-after` or `x-ratelimit-reset`, when present.
        retry_after: Option<Duration>,
    },
    /// Any other non-success status, with GitHub's `message`.
    #[error("GitHub returned {status}: {message}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// GitHub's `message` field, or the status reason.
        message: String,
    },
    /// The request did not complete (DNS, TLS, timeout, connection).
    #[error("GitHub request failed: {0}")]
    Transport(String),
    /// The response did not have the expected shape.
    #[error("unexpected GitHub response: {0}")]
    Decode(String),
}

impl GithubError {
    /// The HTTP status, for [`GithubError::Status`].
    pub fn status(&self) -> Option<u16> {
        match self {
            GithubError::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl From<GithubError> for ConsumerError {
    fn from(err: GithubError) -> Self {
        match err {
            GithubError::RateLimited { retry_after } => ConsumerError::RateLimited { retry_after },
            GithubError::Status { status, .. } if status >= 500 => {
                ConsumerError::Transient(err.to_string())
            }
            GithubError::Transport(_) => ConsumerError::Transient(err.to_string()),
            other => ConsumerError::Permanent(other.to_string()),
        }
    }
}

/// A GitHub REST client for one API base URL and operator token.
pub struct GithubClient {
    base: String,
    token: Option<SecretValue>,
    http: OnceLock<Result<reqwest::Client, String>>,
}

impl fmt::Debug for GithubClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubClient")
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "[set]"))
            .finish()
    }
}

impl GithubClient {
    /// A client for `api_url` (for example `https://api.github.com`).
    /// Makes no call and builds no HTTP client yet.
    pub fn new(api_url: &str, token: Option<SecretValue>) -> Self {
        Self {
            base: api_url.trim_end_matches('/').to_owned(),
            token,
            http: OnceLock::new(),
        }
    }

    /// The API base URL without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// True when an operator token is set.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    fn http(&self) -> Result<&reqwest::Client, GithubError> {
        self.http
            .get_or_init(|| {
                reqwest::Client::builder()
                    .timeout(TIMEOUT)
                    .connect_timeout(CONNECT_TIMEOUT)
                    .build()
                    .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| GithubError::Transport(e.clone()))
    }

    fn headers(&self) -> Result<HeaderMap, GithubError> {
        let token = self.token.as_ref().ok_or(GithubError::NoToken)?;
        let mut auth = token.expose_secret(|t| {
            let mut bytes = Zeroizing::new(Vec::with_capacity(t.len() + 7));
            bytes.extend_from_slice(b"Bearer ");
            bytes.extend_from_slice(t);
            HeaderValue::from_bytes(&bytes).map_err(|_| GithubError::InvalidToken)
        })?;
        auth.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth);
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            "x-github-api-version",
            HeaderValue::from_static(API_VERSION),
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("rotate/", env!("CARGO_PKG_VERSION"))),
        );
        Ok(headers)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Sends one request to an absolute `url` under the base and returns
    /// the response when its status is a success.
    async fn send_url<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<Response, GithubError> {
        let mut request = self.http()?.request(method, url).headers(self.headers()?);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| GithubError::Transport(e.without_url().to_string()))?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(error_from(response).await)
        }
    }

    /// `GET {base}{path}` decoded as JSON.
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, GithubError> {
        let response = self
            .send_url::<()>(Method::GET, &self.url(path), None)
            .await?;
        decode(response).await
    }

    /// `GET {base}{path}` for a paged list wrapped in an object, for
    /// example `{"total_count": 2, "secrets": [...]}`: collects `field` from
    /// every page, following `Link: rel="next"` while it stays under the
    /// base URL. Pass `field = None` for endpoints that return a bare array.
    pub async fn get_paged<T: DeserializeOwned>(
        &self,
        path: &str,
        field: Option<&str>,
    ) -> Result<Vec<T>, GithubError> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut url = format!("{}{sep}per_page={PER_PAGE}", self.url(path));
        let mut items = Vec::new();
        for _ in 0..MAX_PAGES {
            let response = self.send_url::<()>(Method::GET, &url, None).await?;
            let next = next_link(response.headers());
            let page: serde_json::Value = decode(response).await?;
            let list = match field {
                Some(field) => page.get(field).cloned(),
                None => Some(page),
            };
            let list = list.ok_or_else(|| {
                GithubError::Decode(format!("missing `{}`", field.unwrap_or("list")))
            })?;
            let page_items: Vec<T> =
                serde_json::from_value(list).map_err(|e| GithubError::Decode(e.to_string()))?;
            items.extend(page_items);
            match next {
                None => return Ok(items),
                Some(next) if self.is_under_base(&next) => url = next,
                Some(_) => {
                    return Err(GithubError::Decode(
                        "pagination link points outside the API base URL".into(),
                    ))
                }
            }
        }
        Err(GithubError::Decode(format!(
            "more than {MAX_PAGES} pages; stopping"
        )))
    }

    /// `PUT {base}{path}` with a JSON body. The body must hold no plaintext
    /// secret; send sealed values only.
    pub async fn put_json<B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(), GithubError> {
        self.send_url(Method::PUT, &self.url(path), Some(body))
            .await
            .map(drop)
    }

    fn is_under_base(&self, url: &str) -> bool {
        url.strip_prefix(&self.base)
            .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('?'))
    }
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, GithubError> {
    let bytes = response
        .bytes()
        .await
        .map_err(|e| GithubError::Transport(e.without_url().to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| GithubError::Decode(e.to_string()))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The retry hint from `retry-after` (seconds) or `x-ratelimit-reset`
/// (epoch seconds).
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    if let Some(secs) = header(headers, "retry-after").and_then(|v| v.trim().parse::<u64>().ok()) {
        return Some(Duration::from_secs(secs));
    }
    let reset = header(headers, "x-ratelimit-reset")?
        .trim()
        .parse::<u64>()
        .ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(reset.saturating_sub(now)))
}

fn is_rate_limited(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (header(headers, "x-ratelimit-remaining") == Some("0")
                || headers.contains_key("retry-after")))
}

async fn error_from(response: Response) -> GithubError {
    let status = response.status();
    if is_rate_limited(status, response.headers()) {
        return GithubError::RateLimited {
            retry_after: retry_after(response.headers()),
        };
    }
    let body = response.bytes().await.unwrap_or_default();
    let body = &body[..body.len().min(MAX_ERROR_BODY)];
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("message")?.as_str().map(clean_message))
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("error").to_owned());
    GithubError::Status {
        status: status.as_u16(),
        message,
    }
}

/// GitHub's message, single-line and capped.
fn clean_message(message: &str) -> String {
    message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_MESSAGE)
        .collect()
}

/// The `rel="next"` URL from a `Link` header.
fn next_link(headers: &HeaderMap) -> Option<String> {
    let link = headers.get(LINK)?.to_str().ok()?;
    link.split(',').find_map(|part| {
        let (url, params) = part.split_once(';')?;
        let is_next = params
            .split(';')
            .any(|p| p.trim().replace(' ', "") == "rel=\"next\"");
        let url = url.trim().strip_prefix('<')?.strip_suffix('>')?;
        is_next.then(|| url.to_owned())
    })
}

/// Encrypts `value` for a GitHub secrets public key (base64 X25519, as
/// returned by the `.../secrets/public-key` endpoints) with a libsodium
/// sealed box, and returns the base64 ciphertext GitHub expects in
/// `encrypted_value`. The plaintext is read only inside `expose_secret`.
pub fn seal(public_key_b64: &str, value: &SecretValue) -> Result<String, GithubError> {
    let key = BASE64
        .decode(public_key_b64.trim())
        .map_err(|_| GithubError::Decode("public key is not base64".into()))?;
    let key: [u8; crypto_box::KEY_SIZE] = key
        .try_into()
        .map_err(|_| GithubError::Decode("public key is not 32 bytes".into()))?;
    let public = crypto_box::PublicKey::from(key);
    let sealed = value
        .expose_secret(|plain| public.seal(&mut crypto_box::aead::OsRng, plain))
        .map_err(|_| GithubError::Decode("sealing failed".into()))?;
    Ok(BASE64.encode(sealed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with libsodium's crypto_box_seal (PyNaCl 1.6.2, SealedBox) for
    // the secret key 0x01..=0x20. Opening it here proves interop.
    const KAT_PUBLIC: &str = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";
    const KAT_SEALED: &str = "zF1YPq9VlYoIb+oinbIl7XSgJiWGXRlRgGMP6c/Ori0ahMohcoT7iAGO69OugKVmLYR3qtZ+K7obOErID6qSycuvs9WhrlohxpqBV+Y=";
    const KAT_PLAIN: &[u8] = b"rotate known-answer plaintext";

    fn kat_secret() -> crypto_box::SecretKey {
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        crypto_box::SecretKey::from(bytes)
    }

    #[test]
    fn seal_known_answer_libsodium_vector() {
        let secret = kat_secret();
        assert_eq!(BASE64.encode(secret.public_key().as_bytes()), KAT_PUBLIC);
        let sealed = BASE64.decode(KAT_SEALED).unwrap();
        assert_eq!(secret.unseal(&sealed).unwrap(), KAT_PLAIN);
    }

    #[test]
    fn seal_round_trip() {
        let value = SecretValue::from("seal-round-trip-canary-41c2");
        let sealed = seal(KAT_PUBLIC, &value).unwrap();
        let bytes = BASE64.decode(&sealed).unwrap();
        // 32-byte ephemeral key plus a 16-byte tag.
        assert_eq!(bytes.len(), value.len() + 48);
        assert!(!sealed.contains("seal-round-trip-canary"));
        let opened = kat_secret().unseal(&bytes).unwrap();
        assert!(value.expose_secret(|v| v == opened.as_slice()));
        // A fresh ephemeral key every time.
        assert_ne!(seal(KAT_PUBLIC, &value).unwrap(), sealed);
    }

    #[test]
    fn seal_rejects_bad_keys() {
        let value = SecretValue::from("seal-bad-key-canary-77");
        for bad in ["not base64!", "AAAA"] {
            let err = seal(bad, &value).unwrap_err();
            assert!(matches!(err, GithubError::Decode(_)));
            assert!(!err.to_string().contains("seal-bad-key-canary"));
        }
    }

    #[test]
    fn operator_token_prefers_rotate_variable() {
        let both = |name: &str| match name {
            "ROTATE_GITHUB_TOKEN" => Some("rotate-tok-a".to_owned()),
            "GITHUB_TOKEN" => Some("job-tok-b".to_owned()),
            _ => None,
        };
        assert_eq!(
            operator_token(both),
            Some(SecretValue::from("rotate-tok-a"))
        );
        let fallback = |name: &str| match name {
            "ROTATE_GITHUB_TOKEN" => Some(String::new()),
            "GITHUB_TOKEN" => Some("job-tok-b".to_owned()),
            _ => None,
        };
        assert_eq!(
            operator_token(fallback),
            Some(SecretValue::from("job-tok-b"))
        );
        assert_eq!(operator_token(|_| None), None);
    }

    #[test]
    fn debug_hides_token() {
        let client = GithubClient::new(
            "https://api.example.test/",
            Some(SecretValue::from("debug-token-canary-9f")),
        );
        let shown = format!("{client:?}");
        assert!(!shown.contains("debug-token-canary"));
        assert!(shown.contains("[set]"));
        assert_eq!(client.base_url(), "https://api.example.test");
    }

    #[test]
    fn headers_mark_auth_sensitive_and_reject_bad_token() {
        let client = GithubClient::new("https://x.test", Some(SecretValue::from("tok\nbad")));
        assert_eq!(client.headers().unwrap_err(), GithubError::InvalidToken);
        let client = GithubClient::new("https://x.test", Some(SecretValue::from("hdr-tok-1")));
        let headers = client.headers().unwrap();
        assert!(headers[AUTHORIZATION].is_sensitive());
        assert!(!format!("{headers:?}").contains("hdr-tok-1"));
        let client = GithubClient::new("https://x.test", None);
        assert_eq!(client.headers().unwrap_err(), GithubError::NoToken);
    }

    #[test]
    fn next_link_parsing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            LINK,
            HeaderValue::from_static(
                r#"<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=5>; rel="last""#,
            ),
        );
        assert_eq!(
            next_link(&headers).as_deref(),
            Some("https://api.github.com/x?page=2")
        );
        headers.insert(
            LINK,
            HeaderValue::from_static(r#"<https://api.github.com/x?page=1>; rel="prev""#),
        );
        assert_eq!(next_link(&headers), None);
    }

    #[test]
    fn base_check_rejects_other_hosts() {
        let client = GithubClient::new("https://api.github.com", None);
        assert!(client.is_under_base("https://api.github.com/repos?page=2"));
        assert!(!client.is_under_base("https://api.github.com.evil.test/repos"));
        assert!(!client.is_under_base("https://evil.test/repos"));
    }

    #[test]
    fn rate_limit_detection_and_hint() {
        let mut headers = HeaderMap::new();
        assert!(is_rate_limited(StatusCode::TOO_MANY_REQUESTS, &headers));
        assert!(!is_rate_limited(StatusCode::FORBIDDEN, &headers));
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        assert!(is_rate_limited(StatusCode::FORBIDDEN, &headers));
        headers.insert("retry-after", HeaderValue::from_static("17"));
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(17)));
    }

    #[test]
    fn consumer_error_mapping() {
        let rate = GithubError::RateLimited {
            retry_after: Some(Duration::from_secs(3)),
        };
        assert_eq!(
            ConsumerError::from(rate),
            ConsumerError::RateLimited {
                retry_after: Some(Duration::from_secs(3))
            }
        );
        let s502 = GithubError::Status {
            status: 502,
            message: "Bad Gateway".into(),
        };
        assert!(ConsumerError::from(s502).is_retryable());
        let s401 = GithubError::Status {
            status: 401,
            message: "Bad credentials".into(),
        };
        assert_eq!(
            ConsumerError::from(s401),
            ConsumerError::Permanent("GitHub returned 401: Bad credentials".into())
        );
        assert!(ConsumerError::from(GithubError::Transport("timeout".into())).is_retryable());
        assert!(!ConsumerError::from(GithubError::NoToken).is_retryable());
    }

    #[test]
    fn clean_message_strips_control_and_caps() {
        assert_eq!(clean_message("a\nb"), "a b");
        assert_eq!(clean_message(&"x".repeat(500)).len(), MAX_MESSAGE);
    }
}
