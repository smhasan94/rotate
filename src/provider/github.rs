//! GitHub tokens (SHA-260): classic and fine-grained personal access
//! tokens, plus OAuth app and GitHub App tokens as far as GitHub allows.
//!
//! The leaked token signs only read-only calls: `GET /user` and `GET
//! /user/orgs` (or `GET /installation/repositories` for an installation
//! token) in [`GithubProvider::check_valid`] and
//! [`GithubProvider::describe_scope`]. GitHub has no API that reads a
//! token's owner or scopes with another credential, so this is the only
//! way to describe it; nothing state-changing is ever signed with it
//! (decision D3). The replacement signs `GET /user` in
//! [`GithubProvider::verify`].
//!
//! Revoke uses GitHub's credential revocation API, `POST
//! /credentials/revoke`, which takes up to 1000 tokens per request and
//! must be called without authentication: GitHub answers an authenticated
//! request with 403. So this provider needs no operator token at all.
//! GitHub allows 60 such requests an hour, so apply revokes every token of
//! a run through [`GithubProvider::revoke_batch`], one request per 1000
//! (SHA-286). The
//! API accepts `ghp_`, `github_pat_`, `gho_`, `ghu_` and `ghr_` tokens;
//! installation tokens (`ghs_`) are not on that list and are refused.
//! Revoked tokens cannot be reactivated, so [`GithubProvider::restore`]
//! is always `Unsupported`.
//!
//! GitHub has no API to create personal access tokens, so the provider runs
//! in manual replacement mode (decision D1):
//! [`GithubProvider::manual_instructions`] names the page and, for a
//! classic token, the scopes to copy.
//!
//! Nothing happens at construction: the HTTP client is built on first use.
//! Error text carries the endpoint, the status and GitHub's capped
//! `message`, never a token.

use async_trait::async_trait;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    Confidence, Credential, Identity, Provider, ProviderError, Replacement, ReplacementMode,
    RestoreOutcome, Revoked, Scope, Validity,
};
use crate::finding::Finding;
use crate::github::{Auth, GithubClient, GithubError};
use crate::secret::SecretValue;

/// Name used in plans, config and the audit log.
pub const NAME: &str = "github";

/// Scope line for a fine-grained token: GitHub does not list its
/// permissions through the API.
pub const FINE_GRAINED_NOTE: &str =
    "fine-grained: scopes not enumerable via API; check github.com/settings/tokens";

/// Most tokens `POST /credentials/revoke` takes in one request.
pub const REVOKE_BATCH: usize = 1000;

/// Why an installation token cannot be revoked or replaced here.
pub const INSTALLATION_UNSUPPORTED: &str =
    "unsupported: regenerate via the app. GitHub App installation tokens (ghs_) are not \
     accepted by the credential revocation API and expire within an hour; the app can \
     revoke one early with DELETE /installation/token";

/// `Unknown` reason for a GitHub App refresh token.
pub const REFRESH_NO_CHECK: &str =
    "refresh token: GitHub has no read-only check for it; it can still be revoked";

/// Identity named for an installation token, which has no user.
pub const INSTALLATION_IDENTITY: &str = "github-app-installation";

/// Detector names and gitleaks rule ids that name GitHub.
const HINTS: &[&str] = &[
    "Github",
    "github-pat",
    "github-fine-grained-pat",
    "github-oauth",
    "github-app-token",
    "github-refresh-token",
];

const USER: &str = "GET /user";
const ORGS: &str = "GET /user/orgs";
const INSTALLATION_REPOS: &str = "GET /installation/repositories";
const REVOKE: &str = "POST /credentials/revoke";

/// Shortest and longest token body after the prefix.
const MIN_BODY: usize = 20;
const MAX_BODY: usize = 255;

/// Longest login or org name kept in a scope line.
const MAX_NAME: usize = 100;

/// What kind of GitHub token a value is, from its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// `ghp_`: personal access token (classic).
    Classic,
    /// `github_pat_`: fine-grained personal access token.
    FineGrained,
    /// `gho_`: OAuth app access token.
    OAuthApp,
    /// `ghu_`: GitHub App user-to-server token.
    AppUser,
    /// `ghs_`: GitHub App installation token.
    AppInstallation,
    /// `ghr_`: GitHub App refresh token.
    AppRefresh,
    /// 40 hex characters with no prefix: the format before 2021.
    Legacy,
}

/// Prefixes, longest first so `github_pat_` is not read as anything else.
const PREFIXES: &[(&str, TokenKind)] = &[
    ("github_pat_", TokenKind::FineGrained),
    ("ghp_", TokenKind::Classic),
    ("gho_", TokenKind::OAuthApp),
    ("ghu_", TokenKind::AppUser),
    ("ghs_", TokenKind::AppInstallation),
    ("ghr_", TokenKind::AppRefresh),
];

impl TokenKind {
    /// The kind of `token`, when it has a GitHub prefix and a body of
    /// `[A-Za-z0-9_]`, or is a 40-hex legacy token.
    pub fn of(token: &[u8]) -> Option<TokenKind> {
        for (prefix, kind) in PREFIXES {
            if let Some(body) = token.strip_prefix(prefix.as_bytes()) {
                let shaped = (MIN_BODY..=MAX_BODY).contains(&body.len())
                    && body.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_');
                return shaped.then_some(*kind);
            }
        }
        let legacy = token.len() == 40
            && token
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
        legacy.then_some(TokenKind::Legacy)
    }

    /// The `type:` scope line value.
    pub fn label(self) -> &'static str {
        match self {
            TokenKind::Classic => "classic",
            TokenKind::FineGrained => "fine-grained",
            TokenKind::OAuthApp => "oauth app",
            TokenKind::AppUser => "github app user",
            TokenKind::AppInstallation => "github app installation",
            TokenKind::AppRefresh => "github app refresh",
            TokenKind::Legacy => "legacy",
        }
    }

    fn from_label(label: &str) -> Option<TokenKind> {
        [
            TokenKind::Classic,
            TokenKind::FineGrained,
            TokenKind::OAuthApp,
            TokenKind::AppUser,
            TokenKind::AppInstallation,
            TokenKind::AppRefresh,
            TokenKind::Legacy,
        ]
        .into_iter()
        .find(|k| k.label() == label)
    }
}

/// The GitHub token provider.
#[derive(Debug)]
pub struct GithubProvider {
    client: GithubClient,
}

impl GithubProvider {
    /// A provider for the REST API at `api_url` (`providers.github.api_url`,
    /// `https://api.github.com` by default). Makes no call.
    pub fn new(api_url: &str) -> Self {
        Self {
            client: GithubClient::new(api_url, None),
        }
    }

    /// The web host matching the API URL: `api.github.com` is
    /// `github.com`; GitHub Enterprise Server drops `/api/v3`.
    pub fn web_url(&self) -> String {
        let api = self.client.base_url();
        if let Some(web) = api.strip_suffix("/api/v3") {
            return web.to_owned();
        }
        if let Some((scheme, host)) = api.split_once("://") {
            if let Some(host) = host.strip_prefix("api.") {
                return format!("{scheme}://{host}");
            }
        }
        api.to_owned()
    }

    /// Revokes every token with `POST /credentials/revoke`, in batches of
    /// [`REVOKE_BATCH`], without authentication. Every token is checked
    /// first; one that the API does not accept fails the call before any
    /// request. A batch GitHub reports as already revoked is `Ok`.
    pub async fn revoke_many(&self, tokens: &[&SecretValue]) -> Result<(), ProviderError> {
        for token in tokens {
            revocable(token, &self.web_url())?;
        }
        for batch in tokens.chunks(REVOKE_BATCH) {
            self.revoke_chunk(batch).await?;
        }
        Ok(())
    }

    /// One `POST /credentials/revoke` with every token in `tokens` (at most
    /// [`REVOKE_BATCH`], each already checked with `revocable`), without
    /// authentication. GitHub saying they were already revoked is `Ok`.
    async fn revoke_chunk(&self, tokens: &[&SecretValue]) -> Result<(), ProviderError> {
        let body = revoke_body(tokens);
        match self
            .client
            .post_as("/credentials/revoke", &body, Auth::Anonymous)
            .await
        {
            Ok(_) => Ok(()),
            Err(GithubError::Status {
                status: 422,
                message,
            }) if message.to_ascii_lowercase().contains("already revoked") => Ok(()),
            Err(err) => Err(op_error(REVOKE, err)),
        }
    }

    /// `GET /user` signed with `token`: the login and response headers.
    async fn user(&self, token: &SecretValue) -> Result<(String, HeaderMap), GithubError> {
        let (user, headers): (User, HeaderMap) =
            self.client.get_json_as("/user", Auth::Token(token)).await?;
        let login = clean(&user.login);
        if login.is_empty() {
            return Err(GithubError::Decode("GET /user returned no login".into()));
        }
        Ok((login, headers))
    }

    /// Org memberships readable with `token`, or why they are not.
    async fn orgs(
        &self,
        token: &SecretValue,
    ) -> Result<Result<Vec<String>, String>, ProviderError> {
        match self
            .client
            .get_paged_as::<Org>("/user/orgs", None, Auth::Token(token))
            .await
        {
            Ok(orgs) => Ok(Ok(orgs.iter().map(|o| clean(&o.login)).collect())),
            Err(err @ GithubError::RateLimited { .. }) => Err(op_error(ORGS, err)),
            Err(err) => Ok(Err(err.to_string())),
        }
    }

    /// `GET /installation/repositories` signed with an installation token.
    async fn installation(&self, token: &SecretValue) -> Result<u64, GithubError> {
        let (repos, _): (Repos, HeaderMap) = self
            .client
            .get_json_as("/installation/repositories?per_page=1", Auth::Token(token))
            .await?;
        Ok(repos.total_count)
    }
}

#[derive(Deserialize)]
struct User {
    login: String,
}

#[derive(Deserialize)]
struct Org {
    login: String,
}

#[derive(Deserialize)]
struct Repos {
    total_count: u64,
}

/// The single token in `credential`.
fn token(credential: &Credential) -> Result<&SecretValue, ProviderError> {
    match credential {
        Credential::Token(token) => Ok(token),
        Credential::KeyPair(_) => Err(ProviderError::Unsupported(
            "a GitHub token is a single value, not a key pair".into(),
        )),
    }
}

/// The kind of a GitHub-shaped token; anything else is refused before any
/// call, so rotate never sends an unrecognised value to GitHub.
fn kind(token: &SecretValue) -> Result<TokenKind, ProviderError> {
    token.expose_secret(TokenKind::of).ok_or_else(|| {
        ProviderError::Unsupported("the value does not have a GitHub token format".into())
    })
}

/// The kind of a token the revocation API accepts.
fn revocable(token: &SecretValue, web: &str) -> Result<TokenKind, ProviderError> {
    match kind(token)? {
        TokenKind::AppInstallation => {
            Err(ProviderError::Unsupported(INSTALLATION_UNSUPPORTED.into()))
        }
        TokenKind::Legacy => Err(ProviderError::Unsupported(format!(
            "the credential revocation API does not accept legacy-format tokens; delete it at \
             {web}/settings/tokens"
        ))),
        other => Ok(other),
    }
}

/// `{"credentials":["...","..."]}` in zeroized memory. Callers have checked
/// every token is `[A-Za-z0-9_]`, so nothing needs escaping.
fn revoke_body(tokens: &[&SecretValue]) -> Zeroizing<Vec<u8>> {
    let size = tokens.iter().map(|t| t.len() + 3).sum::<usize>() + 20;
    let mut body = Zeroizing::new(Vec::with_capacity(size));
    body.extend_from_slice(b"{\"credentials\":[");
    for (i, token) in tokens.iter().enumerate() {
        if i > 0 {
            body.push(b',');
        }
        body.push(b'"');
        token.expose_secret(|t| body.extend_from_slice(t));
        body.push(b'"');
    }
    body.extend_from_slice(b"]}");
    body
}

/// `err` with the endpoint in front, keeping its retry class.
fn op_error(op: &str, err: GithubError) -> ProviderError {
    match ProviderError::from(err) {
        ProviderError::Transient(text) => ProviderError::Transient(format!("{op}: {text}")),
        ProviderError::Permanent(text) => ProviderError::Permanent(format!("{op}: {text}")),
        other => other,
    }
}

/// Validity from a read signed with the token: 200 valid, 401 invalid,
/// rate limits and server errors retryable, anything else unknown.
fn validity<T>(op: &str, result: Result<T, GithubError>) -> Result<Validity, ProviderError> {
    match result {
        Ok(_) => Ok(Validity::Valid),
        Err(GithubError::Status { status: 401, .. }) => Ok(Validity::Invalid),
        Err(err @ GithubError::Status { status, .. }) if status < 500 => Ok(Validity::Unknown {
            reason: format!("{op}: {err}"),
        }),
        Err(err) => Err(op_error(op, err)),
    }
}

/// A login or org name: no control characters, capped.
fn clean(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// `x-oauth-scopes` as a clean list: `repo, workflow`.
fn scope_list(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(|s| clean(s).replace(' ', ""))
        .filter(|s| !s.is_empty())
        .collect()
}

/// The scope lines for a user token (not an installation token). Pure, so
/// the fine-grained note and the scope list are unit-tested.
pub fn scope_lines(
    kind: TokenKind,
    login: &str,
    oauth_scopes: Option<&str>,
    expires: Option<&str>,
    orgs: &Result<Vec<String>, String>,
) -> Vec<String> {
    let mut lines = vec![format!("login: {login}"), format!("type: {}", kind.label())];
    match kind {
        TokenKind::FineGrained => lines.push(FINE_GRAINED_NOTE.to_owned()),
        TokenKind::AppUser => lines.push("scopes: set by the GitHub App's permissions".into()),
        _ => lines.push(match oauth_scopes.map(scope_list) {
            None => "scopes: not reported by GitHub".to_owned(),
            Some(list) if list.is_empty() => "scopes: none".to_owned(),
            Some(list) => format!("scopes: {}", list.join(", ")),
        }),
    }
    if let Some(expires) = expires.map(clean).filter(|e| !e.is_empty()) {
        lines.push(format!("expires: {expires}"));
    }
    lines.push(match orgs {
        Ok(orgs) if orgs.is_empty() => "orgs: none".to_owned(),
        Ok(orgs) => format!("orgs: {}", orgs.join(", ")),
        Err(why) => format!("orgs: not readable with this token ({why})"),
    });
    lines
}

/// The value of the scope line `name: value`.
fn line<'a>(scope: &'a Scope, name: &str) -> Option<&'a str> {
    scope
        .lines
        .iter()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(": "))
}

#[async_trait]
impl Provider for GithubProvider {
    fn name(&self) -> &'static str {
        NAME
    }

    fn replacement_mode(&self) -> ReplacementMode {
        ReplacementMode::Manual
    }

    /// Manual for a GitHub App installation token (SHA-289), named by the
    /// scope's `type` line: the credential revocation API refuses it.
    fn manual_revoke(&self, scope: Option<&Scope>) -> Option<&'static str> {
        let kind = scope
            .and_then(|s| line(s, "type"))
            .and_then(TokenKind::from_label);
        (kind == Some(TokenKind::AppInstallation)).then_some(INSTALLATION_UNSUPPORTED)
    }

    /// What to create on github.com, built from the scope lines
    /// `describe_scope` wrote: for a classic token, the exact scope list.
    fn manual_instructions(&self, scope: &Scope) -> String {
        let web = self.web_url();
        let login = &scope.identity;
        let kind = line(scope, "type").and_then(TokenKind::from_label);
        match kind {
            Some(TokenKind::Classic) | Some(TokenKind::Legacy) => {
                let scopes = match line(scope, "scopes") {
                    Some(list) if !list.starts_with("none") && !list.starts_with("not ") => {
                        format!("with these scopes: {list}")
                    }
                    _ => "with no scopes (the leaked token had none)".to_owned(),
                };
                format!(
                    "Create a new personal access token (classic) for {login} at \
                     {web}/settings/tokens/new {scopes}. Set an expiry, then paste it at the \
                     prompt."
                )
            }
            Some(TokenKind::FineGrained) => format!(
                "Create a new fine-grained personal access token for {login} at \
                 {web}/settings/personal-access-tokens/new with the same resource owner, \
                 repositories and permissions as the leaked one. {FINE_GRAINED_NOTE}. Then \
                 paste it at the prompt."
            ),
            Some(TokenKind::OAuthApp) => format!(
                "This is an OAuth app token for {login}: authorize the app again to get a new \
                 token, then paste it at the prompt."
            ),
            Some(TokenKind::AppUser) | Some(TokenKind::AppRefresh) => format!(
                "This is a GitHub App user token for {login}: sign in to the app again to get a \
                 new token, then paste it at the prompt."
            ),
            Some(TokenKind::AppInstallation) => INSTALLATION_UNSUPPORTED.to_owned(),
            None => format!(
                "Create a new GitHub token for {login} at {web}/settings/tokens with the same \
                 access as the leaked one, then paste it at the prompt."
            ),
        }
    }

    fn identify(&self, finding: &Finding) -> Option<Confidence> {
        let Credential::Token(raw) = finding.credential() else {
            return None;
        };
        let hinted = HINTS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&finding.detector));
        match raw.expose_secret(TokenKind::of)? {
            TokenKind::Legacy => hinted.then_some(Confidence::Low),
            _ if hinted => Some(Confidence::High),
            _ => Some(Confidence::Medium),
        }
    }

    /// `GET /user` signed with the token (an installation token reads
    /// `GET /installation/repositories`; a refresh token has no check).
    async fn check_valid(&self, credential: &Credential) -> Result<Validity, ProviderError> {
        let token = token(credential)?;
        match kind(token)? {
            TokenKind::AppRefresh => Ok(Validity::Unknown {
                reason: REFRESH_NO_CHECK.into(),
            }),
            TokenKind::AppInstallation => {
                validity(INSTALLATION_REPOS, self.installation(token).await)
            }
            _ => validity(USER, self.user(token).await),
        }
    }

    /// Login, token type, classic scopes or the fine-grained note, expiry
    /// and org memberships, read with the token itself.
    async fn describe_scope(&self, credential: &Credential) -> Result<Scope, ProviderError> {
        let token = token(credential)?;
        match kind(token)? {
            TokenKind::AppRefresh => Err(ProviderError::Unsupported(REFRESH_NO_CHECK.into())),
            TokenKind::AppInstallation => {
                let repos = self
                    .installation(token)
                    .await
                    .map_err(|e| op_error(INSTALLATION_REPOS, e))?;
                Ok(Scope {
                    identity: Identity(INSTALLATION_IDENTITY.into()),
                    lines: vec![
                        format!("type: {}", TokenKind::AppInstallation.label()),
                        format!("repositories: {repos}"),
                        format!("warning: {INSTALLATION_UNSUPPORTED}"),
                    ],
                })
            }
            kind => {
                let (login, headers) = self.user(token).await.map_err(|e| op_error(USER, e))?;
                let orgs = self.orgs(token).await?;
                let lines = scope_lines(
                    kind,
                    &login,
                    header(&headers, "x-oauth-scopes"),
                    header(&headers, "github-authentication-token-expiration"),
                    &orgs,
                );
                Ok(Scope {
                    identity: Identity(login),
                    lines,
                })
            }
        }
    }

    /// GitHub has no API to create tokens: manual mode never calls this.
    async fn create_replacement(
        &self,
        _credential: &Credential,
    ) -> Result<Replacement, ProviderError> {
        Err(ProviderError::Unsupported(
            "GitHub has no API to create tokens; rotate asks for the new token instead".into(),
        ))
    }

    /// `GET /user` signed with the replacement; its login must be
    /// `identity` (GitHub logins are case-insensitive).
    async fn verify(
        &self,
        credential: &Credential,
        identity: &Identity,
    ) -> Result<(), ProviderError> {
        let token = token(credential)?;
        match kind(token)? {
            TokenKind::AppInstallation => {
                return Err(ProviderError::Unsupported(INSTALLATION_UNSUPPORTED.into()))
            }
            TokenKind::AppRefresh => {
                return Err(ProviderError::Unsupported(REFRESH_NO_CHECK.into()))
            }
            _ => {}
        }
        match self.user(token).await {
            Ok((login, _)) if login.eq_ignore_ascii_case(&identity.0) => Ok(()),
            Ok((login, _)) => Err(ProviderError::Permanent(format!(
                "the replacement token belongs to {login} but the leaked token belongs to \
                 {identity}"
            ))),
            Err(GithubError::Status { status: 401, .. }) => Err(ProviderError::Permanent(format!(
                "{USER}: GitHub did not accept the replacement token (401)"
            ))),
            Err(err) => Err(op_error(USER, err)),
        }
    }

    /// `POST /credentials/revoke` with no authentication. A repeat, or a
    /// response saying it was already revoked, is `Ok`. Never restorable.
    async fn revoke(&self, credential: &Credential) -> Result<Revoked, ProviderError> {
        let token = token(credential)?;
        self.revoke_many(&[token]).await?;
        Ok(Revoked { restore_ref: None })
    }

    /// Every token GitHub's revocation API accepts goes in one `POST
    /// /credentials/revoke` per [`REVOKE_BATCH`] (SHA-286); one it does not
    /// (an installation or legacy-format token, or not a token at all) gets
    /// its own `Unsupported` result (for an installation token, with
    /// [`INSTALLATION_UNSUPPORTED`] as guidance) and is left out of the
    /// request. Each request's result is every token's in it. A
    /// rate-limited request stops the batch: that result is also every
    /// later token's, and no later request is sent. Any other error
    /// applies to its request only.
    async fn revoke_batch(
        &self,
        credentials: &[&Credential],
    ) -> Vec<Result<Revoked, ProviderError>> {
        let web = self.web_url();
        let mut results: Vec<Option<Result<Revoked, ProviderError>>> =
            vec![None; credentials.len()];
        let mut accepted: Vec<(usize, &SecretValue)> = Vec::new();
        for (i, credential) in credentials.iter().enumerate() {
            match token(credential).and_then(|t| revocable(t, &web).map(|_| t)) {
                Ok(t) => accepted.push((i, t)),
                // The text is rotate's own constant: as guidance it survives
                // where a resumed revoke keeps only a summary (SHA-298), so
                // the operator still learns what to do.
                Err(err) if err.unsupported() == Some(INSTALLATION_UNSUPPORTED) => {
                    results[i] = Some(Err(err.with_guidance(INSTALLATION_UNSUPPORTED)));
                }
                Err(err) => results[i] = Some(Err(err)),
            }
        }
        let mut limited: Option<ProviderError> = None;
        for chunk in accepted.chunks(REVOKE_BATCH) {
            let sent = match &limited {
                Some(err) => Err(err.clone()),
                None => {
                    let tokens: Vec<&SecretValue> = chunk.iter().map(|(_, t)| *t).collect();
                    let sent = self.revoke_chunk(&tokens).await;
                    if let Err(err) = &sent {
                        if matches!(err.base(), ProviderError::RateLimited { .. }) {
                            limited = Some(err.clone());
                        }
                    }
                    sent
                }
            };
            for (i, _) in chunk {
                results[*i] = Some(sent.clone().map(|()| Revoked { restore_ref: None }));
            }
        }
        results
            .into_iter()
            .map(|r| {
                r.unwrap_or_else(|| Err(ProviderError::Permanent(format!("{REVOKE}: no result"))))
            })
            .collect()
    }

    fn revoke_batch_size(&self) -> Option<usize> {
        Some(REVOKE_BATCH)
    }

    /// A token GitHub's revocation API accepts, as [`revoke_batch`] decides
    /// (SHA-330).
    ///
    /// [`revoke_batch`]: Provider::revoke_batch
    fn batchable(&self, credential: &Credential) -> bool {
        token(credential).is_ok_and(|t| revocable(t, &self.web_url()).is_ok())
    }

    /// GitHub cannot reactivate a revoked token.
    async fn restore(&self, _restore_ref: &str) -> Result<RestoreOutcome, ProviderError> {
        Ok(RestoreOutcome::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{SourceLocation, ACCESS_KEY_ID};

    /// A token built at runtime so no literal here matches a secret
    /// scanner pattern.
    fn tok(prefix: [&str; 2], len: usize) -> String {
        format!(
            "{}{}",
            prefix.concat(),
            "Ab1_".repeat(len / 4 + 1)[..len].to_owned()
        )
    }

    fn finding(value: &str, detector: &str) -> Finding {
        Finding::new(
            SecretValue::from(value),
            detector,
            SourceLocation::file("a.env"),
        )
    }

    fn provider() -> GithubProvider {
        GithubProvider::new("https://api.github.com")
    }

    // T1 (AC1)
    #[test]
    fn identify_each_prefix_and_not_aws() {
        let p = provider();
        let cases = [
            (tok(["gh", "p_"], 36), "Github", TokenKind::Classic),
            (
                tok(["github", "_pat_"], 82),
                "github-fine-grained-pat",
                TokenKind::FineGrained,
            ),
            (tok(["gh", "o_"], 36), "github-oauth", TokenKind::OAuthApp),
            (
                tok(["gh", "u_"], 36),
                "github-app-token",
                TokenKind::AppUser,
            ),
            (
                tok(["gh", "s_"], 36),
                "github-app-token",
                TokenKind::AppInstallation,
            ),
            (
                tok(["gh", "r_"], 76),
                "github-refresh-token",
                TokenKind::AppRefresh,
            ),
        ];
        for (value, hint, want) in &cases {
            assert_eq!(TokenKind::of(value.as_bytes()), Some(*want), "{want:?}");
            assert_eq!(
                p.identify(&finding(value, hint)),
                Some(Confidence::High),
                "{want:?} with hint"
            );
            assert_eq!(
                p.identify(&finding(value, "stdin")),
                Some(Confidence::Medium),
                "{want:?} without hint"
            );
        }
        assert_eq!(
            p.identify(&finding(&tok(["gh", "p_"], 36), "github-pat")),
            Some(Confidence::High)
        );

        // An AWS key pair and an AWS key id as a bare token.
        let aws_id = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let pair = finding("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01", "AWS")
            .with_extra(ACCESS_KEY_ID, aws_id.clone());
        assert_eq!(p.identify(&pair), None);
        assert_eq!(p.identify(&finding(&aws_id, "AWS")), None);
        assert_eq!(p.identify(&finding(&aws_id, "Github")), None);

        // Shapes that are not tokens.
        assert_eq!(p.identify(&finding("", "Github")), None);
        assert_eq!(p.identify(&finding(&tok(["gh", "p_"], 5), "Github")), None);
        let dashed = format!("{}{}", ["gh", "p_"].concat(), "a-b".repeat(12));
        assert_eq!(p.identify(&finding(&dashed, "Github")), None);
        // A legacy 40-hex token only with a hint, at low confidence.
        let legacy = "0123456789abcdef".repeat(3)[..40].to_owned();
        assert_eq!(
            p.identify(&finding(&legacy, "Github")),
            Some(Confidence::Low)
        );
        assert_eq!(p.identify(&finding(&legacy, "stdin")), None);
    }

    // T4 (AC4)
    #[test]
    fn fine_grained_scope_has_note() {
        let lines = scope_lines(
            TokenKind::FineGrained,
            "octocat",
            None,
            Some("2026-12-01 00:00:00 UTC"),
            &Ok(vec!["acme".into()]),
        );
        assert_eq!(
            lines,
            [
                "login: octocat",
                "type: fine-grained",
                FINE_GRAINED_NOTE,
                "expires: 2026-12-01 00:00:00 UTC",
                "orgs: acme",
            ]
        );
        // A fine-grained token never reports classic scopes, even if a
        // header were present.
        let lines = scope_lines(
            TokenKind::FineGrained,
            "octocat",
            Some("repo"),
            None,
            &Ok(vec![]),
        );
        assert!(!lines.iter().any(|l| l.starts_with("scopes:")));
    }

    #[test]
    fn classic_scope_lines() {
        let lines = scope_lines(
            TokenKind::Classic,
            "octocat",
            Some(" repo,  workflow "),
            None,
            &Err("GitHub returned 403: Forbidden".into()),
        );
        assert_eq!(
            lines,
            [
                "login: octocat",
                "type: classic",
                "scopes: repo, workflow",
                "orgs: not readable with this token (GitHub returned 403: Forbidden)",
            ]
        );
        let none = scope_lines(TokenKind::Classic, "o", Some(""), None, &Ok(vec![]));
        assert!(none.contains(&"scopes: none".to_owned()));
        let missing = scope_lines(TokenKind::Classic, "o", None, None, &Ok(vec![]));
        assert!(missing.contains(&"scopes: not reported by GitHub".to_owned()));
    }

    fn scope_of(lines: &[&str]) -> Scope {
        Scope {
            identity: Identity("octocat".into()),
            lines: lines.iter().map(|l| (*l).to_owned()).collect(),
        }
    }

    // T9 (AC9)
    #[test]
    fn manual_instructions_list_classic_scopes() {
        let scope = scope_of(
            &scope_lines(
                TokenKind::Classic,
                "octocat",
                Some("repo, workflow, read:org"),
                None,
                &Ok(vec![]),
            )
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        );
        let text = provider().manual_instructions(&scope);
        assert!(text.contains("personal access token (classic)"), "{text}");
        assert!(text.contains("octocat"), "{text}");
        assert!(
            text.contains("https://github.com/settings/tokens/new"),
            "{text}"
        );
        assert!(
            text.contains("with these scopes: repo, workflow, read:org"),
            "{text}"
        );

        let none = provider().manual_instructions(&scope_of(&["type: classic", "scopes: none"]));
        assert!(none.contains("with no scopes"), "{none}");
    }

    #[test]
    fn manual_instructions_other_kinds() {
        let p = provider();
        let fine = p.manual_instructions(&scope_of(&["type: fine-grained", FINE_GRAINED_NOTE]));
        assert!(
            fine.contains("fine-grained personal access token"),
            "{fine}"
        );
        assert!(
            fine.contains("/settings/personal-access-tokens/new"),
            "{fine}"
        );
        assert!(fine.contains(FINE_GRAINED_NOTE), "{fine}");
        let app = p.manual_instructions(&scope_of(&["type: github app installation"]));
        assert!(
            app.starts_with("unsupported: regenerate via the app"),
            "{app}"
        );
        let oauth = p.manual_instructions(&scope_of(&["type: oauth app"]));
        assert!(oauth.contains("authorize the app again"), "{oauth}");
        let unknown = p.manual_instructions(&scope_of(&[]));
        assert!(unknown.contains("octocat"), "{unknown}");
    }

    // SHA-289: plan shows a manual revoke for an installation token only.
    #[test]
    fn manual_revoke_for_installation_tokens() {
        let p = provider();
        assert_eq!(
            p.manual_revoke(Some(&scope_of(&["type: github app installation"]))),
            Some(INSTALLATION_UNSUPPORTED)
        );
        assert_eq!(p.manual_revoke(Some(&scope_of(&["type: classic"]))), None);
        assert_eq!(p.manual_revoke(Some(&scope_of(&[]))), None);
        assert_eq!(p.manual_revoke(None), None);
    }

    /// SHA-330 T3 (AC3): batchable is exactly what the revocation API
    /// accepts.
    #[test]
    fn batchable_matches_revocable() {
        let p = provider();
        let cred = |v: String| Credential::Token(SecretValue::from(v.as_str()));
        for accepted in [
            tok(["gh", "p_"], 36),
            tok(["github", "_pat_"], 82),
            tok(["gh", "o_"], 36),
            tok(["gh", "u_"], 36),
            tok(["gh", "r_"], 76),
        ] {
            assert!(p.batchable(&cred(accepted)));
        }
        let legacy = "0123456789abcdef".repeat(3)[..40].to_owned();
        for refused in [tok(["gh", "s_"], 36), legacy, "not a token".to_owned()] {
            assert!(!p.batchable(&cred(refused)));
        }
    }

    #[test]
    fn web_url_from_api_url() {
        assert_eq!(provider().web_url(), "https://github.com");
        assert_eq!(
            GithubProvider::new("https://ghe.example.com/api/v3/").web_url(),
            "https://ghe.example.com"
        );
        assert_eq!(
            GithubProvider::new("http://127.0.0.1:8080").web_url(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn revoke_body_shape() {
        let a = SecretValue::from(tok(["gh", "p_"], 36));
        let b = SecretValue::from(tok(["github", "_pat_"], 82));
        let body = revoke_body(&[&a, &b]);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let list = parsed["credentials"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert!(a.expose_secret(|v| list[0].as_str().unwrap().as_bytes() == v));
        assert!(b.expose_secret(|v| list[1].as_str().unwrap().as_bytes() == v));
    }

    // T8 (AC8), unit half: no client is ever built.
    #[tokio::test]
    async fn restore_and_create_make_no_call() {
        // An unroutable base: any call would fail with a transport error.
        let p = GithubProvider::new("http://127.0.0.1:1");
        assert_eq!(
            p.restore("anything").await.unwrap(),
            RestoreOutcome::Unsupported
        );
        let live = Credential::Token(SecretValue::from(tok(["gh", "p_"], 36)));
        assert!(matches!(
            p.create_replacement(&live).await,
            Err(ProviderError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn refused_shapes_make_no_call() {
        let p = GithubProvider::new("http://127.0.0.1:1");
        let installation = Credential::Token(SecretValue::from(tok(["gh", "s_"], 36)));
        let err = p.revoke(&installation).await.unwrap_err();
        assert_eq!(
            err,
            ProviderError::Unsupported(INSTALLATION_UNSUPPORTED.into())
        );
        let refresh = Credential::Token(SecretValue::from(tok(["gh", "r_"], 76)));
        assert_eq!(
            p.check_valid(&refresh).await.unwrap(),
            Validity::Unknown {
                reason: REFRESH_NO_CHECK.into()
            }
        );
        let legacy = Credential::Token(SecretValue::from(
            "0123456789abcdef".repeat(3)[..40].to_owned(),
        ));
        assert!(matches!(
            p.revoke(&legacy).await,
            Err(ProviderError::Unsupported(text)) if text.contains("legacy")
        ));
        let other = Credential::Token(SecretValue::from("not-a-github-token-canary-71"));
        for err in [
            p.check_valid(&other).await.unwrap_err(),
            p.describe_scope(&other).await.unwrap_err(),
            p.revoke(&other).await.unwrap_err(),
            p.verify(&other, &Identity("x".into())).await.unwrap_err(),
        ] {
            assert!(matches!(err, ProviderError::Unsupported(_)), "{err}");
            assert!(!err.to_string().contains("canary-71"));
        }
        // One bad token in a batch fails the whole call before any request.
        let good = SecretValue::from(tok(["gh", "p_"], 36));
        let bad = SecretValue::from("not-a-github-token");
        assert!(p.revoke_many(&[&good, &bad]).await.is_err());
    }

    #[test]
    fn clean_strips_control_and_caps() {
        assert_eq!(clean("oct\nocat"), "octocat");
        assert_eq!(clean(&"x".repeat(500)).len(), MAX_NAME);
    }
}
