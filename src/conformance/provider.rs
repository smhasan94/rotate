//! The provider half of the conformance suite.

use std::future::Future;
use std::sync::Arc;

use super::{
    canary, failed_if_any, mutations_during, MutationProbe, Outcome, Recorder, SuiteReport,
};
use crate::finding::{Finding, SourceLocation, ACCESS_KEY_ID};
use crate::provider::{Credential, Identity, Provider, ProviderError, ReplacementMode, Validity};
use crate::secret::SecretValue;

/// One provider wired to a test server, built fresh for every check.
pub struct ProviderFixture {
    /// The plugin under test.
    pub provider: Arc<dyn Provider>,
    /// A credential the server accepts as valid, owned by `identity`. Its
    /// replacement and revoke calls must succeed, and a second revoke must
    /// too (map "already deleted" to `Ok`).
    pub live: Credential,
    /// The owner of `live`, as `describe_scope` names it.
    pub identity: Identity,
    /// A credential the server reports as revoked or unknown: `check_valid`
    /// must return `Ok(Validity::Invalid)` for it. Answer it with the
    /// provider's real 401 or 404 so error paths get exercised.
    pub unknown: Credential,
    /// Where the plugin's state-changing calls show up.
    pub probe: Box<dyn MutationProbe>,
}

/// Runs every provider check. `factory` is called once per check.
///
/// Checks, in order: `identify_rejects_foreign`,
/// `check_valid_unknown_invalid`, `read_only_check_valid`,
/// `read_only_describe_scope`, `read_only_verify`, `replacement_differs`,
/// `verify_wrong_identity_fails`, `idempotent_revoke`, `restore_outcome`,
/// `errors_redacted`.
pub async fn provider_suite<F, Fut>(factory: F) -> SuiteReport
where
    F: Fn() -> Fut,
    Fut: Future<Output = ProviderFixture>,
{
    let mut rec = Recorder::default();
    let mut report = SuiteReport::new("provider");

    let fx = known(factory().await, &mut rec);
    report.plugin = fx.provider.name();
    report.push("identify_rejects_foreign", identify_rejects_foreign(&fx));

    let fx = known(factory().await, &mut rec);
    let outcome = check_valid_unknown_invalid(&fx, &mut rec).await;
    report.push("check_valid_unknown_invalid", outcome);

    for (name, method) in [
        ("read_only_check_valid", "check_valid"),
        ("read_only_describe_scope", "describe_scope"),
        ("read_only_verify", "verify"),
    ] {
        let fx = known(factory().await, &mut rec);
        let outcome = read_only(&fx, method, &mut rec).await;
        report.push(name, outcome);
    }

    let fx = known(factory().await, &mut rec);
    let outcome = replacement_differs(&fx, &mut rec).await;
    report.push("replacement_differs", outcome);

    let fx = known(factory().await, &mut rec);
    let outcome = verify_wrong_identity_fails(&fx, &mut rec).await;
    report.push("verify_wrong_identity_fails", outcome);

    let fx = known(factory().await, &mut rec);
    let outcome = idempotent_revoke(&fx, &mut rec).await;
    report.push("idempotent_revoke", outcome);

    let fx = known(factory().await, &mut rec);
    let outcome = restore_outcome(&fx, &mut rec).await;
    report.push("restore_outcome", outcome);

    let fx = known(factory().await, &mut rec);
    feed_canary(&fx, &mut rec).await;
    report.push("errors_redacted", rec.redaction_outcome());
    report
}

/// Remembers the fixture's secrets so errors can be searched for them.
fn known(fx: ProviderFixture, rec: &mut Recorder) -> ProviderFixture {
    rec.know(&fx.live);
    rec.know(&fx.unknown);
    fx
}

/// Runtime-built values shaped like each MVP provider's credentials, so no
/// literal in this file matches a secret scanner pattern.
fn foreign_samples() -> Vec<(&'static str, Finding)> {
    let at = || SourceLocation::file("conformance");
    let fill = |n: usize| "c0nf".repeat(n / 4 + 1)[..n].to_owned();
    let aws_id = format!("{}{}", ["AK", "IA"].concat(), fill(16).to_uppercase());
    let token =
        |prefix: [&str; 2], n: usize| SecretValue::from(format!("{}{}", prefix.concat(), fill(n)));
    vec![
        (
            "aws",
            Finding::new(SecretValue::from(fill(40)), "AWS", at())
                .with_extra(ACCESS_KEY_ID, aws_id),
        ),
        (
            "github",
            Finding::new(token(["gh", "p_"], 36), "Github", at()),
        ),
        (
            "npm",
            Finding::new(token(["np", "m_"], 36), "NpmToken", at()),
        ),
        (
            "openai",
            Finding::new(token(["sk-", "proj-"], 48), "OpenAI", at()),
        ),
    ]
}

fn identify_rejects_foreign(fx: &ProviderFixture) -> Outcome {
    let own = fx.provider.name();
    let empty = Finding::new(
        SecretValue::from(""),
        "",
        SourceLocation::file("conformance"),
    );
    let mut claimed = Vec::new();
    if let Some(c) = fx.provider.identify(&empty) {
        claimed.push(format!("identify claimed the empty value at {c:?}"));
    }
    for (name, finding) in foreign_samples() {
        if name == own {
            continue;
        }
        if let Some(c) = fx.provider.identify(&finding) {
            claimed.push(format!("identify claimed the {name} sample at {c:?}"));
        }
    }
    failed_if_any(claimed)
}

async fn check_valid_unknown_invalid(fx: &ProviderFixture, rec: &mut Recorder) -> Outcome {
    let mut problems = Vec::new();
    for (label, credential, want) in [
        ("unknown", &fx.unknown, Validity::Invalid),
        ("live", &fx.live, Validity::Valid),
    ] {
        match fx.provider.check_valid(credential).await {
            Ok(got) if got == want => {}
            Ok(got) => {
                problems.push(format!(
                    "check_valid({label}) returned {got:?}, want {want:?}"
                ));
            }
            Err(e) => {
                let text = rec.error("check_valid", &e);
                problems.push(format!("check_valid({label}) returned an error: {text}"));
            }
        }
    }
    failed_if_any(problems)
}

async fn read_only(fx: &ProviderFixture, method: &'static str, rec: &mut Recorder) -> Outcome {
    let provider = &fx.provider;
    let mut error = None;
    let made = mutations_during(fx.probe.as_ref(), async {
        let result = match method {
            "check_valid" => provider.check_valid(&fx.live).await.map(drop),
            "describe_scope" => provider.describe_scope(&fx.live).await.map(drop),
            _ => provider.verify(&fx.live, &fx.identity).await,
        };
        error = result.err();
    })
    .await;
    if let Some(e) = error {
        rec.error(method, &e);
    }
    if made.is_empty() {
        Outcome::Passed
    } else {
        Outcome::Failed(format!(
            "{method} made state-changing calls: {}",
            made.join(", ")
        ))
    }
}

async fn replacement_differs(fx: &ProviderFixture, rec: &mut Recorder) -> Outcome {
    if fx.provider.replacement_mode() == ReplacementMode::Manual {
        return Outcome::Skipped("manual replacement mode never calls create_replacement".into());
    }
    match fx.provider.create_replacement(&fx.live).await {
        Ok(replacement) => {
            rec.know(&replacement.credential);
            if replacement.credential.fingerprint() == fx.live.fingerprint() {
                Outcome::Failed("create_replacement returned the same secret".into())
            } else if rec.leaks(&replacement.replacement_ref) {
                Outcome::Failed("replacement_ref contains a secret value".into())
            } else {
                Outcome::Passed
            }
        }
        Err(e) => Outcome::Failed(format!(
            "create_replacement returned an error: {}",
            rec.error("create_replacement", &e)
        )),
    }
}

async fn verify_wrong_identity_fails(fx: &ProviderFixture, rec: &mut Recorder) -> Outcome {
    let mut problems = Vec::new();
    if let Err(e) = fx.provider.verify(&fx.live, &fx.identity).await {
        let text = rec.error("verify", &e);
        problems.push(format!("verify with the right identity failed: {text}"));
    }
    let wrong = Identity(format!("{}-conformance-other", fx.identity));
    match fx.provider.verify(&fx.live, &wrong).await {
        Ok(()) => problems.push("verify accepted a wrong identity".into()),
        Err(e) => {
            rec.error("verify", &e);
        }
    }
    failed_if_any(problems)
}

/// Why the revoke checks are skipped: the provider cannot revoke this
/// credential at all (for example OpenAI without an Admin API key).
fn revoke_unsupported(e: &ProviderError) -> Option<Outcome> {
    e.unsupported()
        .is_some()
        .then(|| Outcome::Skipped("revoke is unsupported for this credential".into()))
}

async fn idempotent_revoke(fx: &ProviderFixture, rec: &mut Recorder) -> Outcome {
    if let Err(e) = fx.provider.revoke(&fx.live).await {
        let text = rec.error("revoke", &e);
        if let Some(skipped) = revoke_unsupported(&e) {
            return skipped;
        }
        return Outcome::Failed(format!("first revoke returned an error: {text}"));
    }
    match fx.provider.revoke(&fx.live).await {
        Ok(_) => Outcome::Passed,
        Err(e) => Outcome::Failed(format!(
            "second revoke of the same credential returned an error: {}",
            rec.error("revoke", &e)
        )),
    }
}

async fn restore_outcome(fx: &ProviderFixture, rec: &mut Recorder) -> Outcome {
    let revoked = match fx.provider.revoke(&fx.live).await {
        Ok(revoked) => revoked,
        Err(e) => {
            if let Some(skipped) = revoke_unsupported(&e) {
                rec.error("revoke", &e);
                return skipped;
            }
            return Outcome::Failed(format!(
                "revoke returned an error: {}",
                rec.error("revoke", &e)
            ));
        }
    };
    let Some(restore_ref) = revoked.restore_ref else {
        return Outcome::Passed;
    };
    if rec.leaks(&restore_ref) {
        return Outcome::Failed("restore_ref contains a secret value".into());
    }
    match fx.provider.restore(&restore_ref).await {
        Ok(_) => Outcome::Passed,
        Err(e) => Outcome::Failed(format!(
            "restore returned an error instead of Restored or Unsupported: {}",
            rec.error("restore", &e)
        )),
    }
}

/// Calls every method that takes a credential with the canary, so a plugin
/// that echoes its input into errors gets caught.
async fn feed_canary(fx: &ProviderFixture, rec: &mut Recorder) {
    let canary = canary(&fx.live);
    rec.know(&canary);
    let p = &fx.provider;
    if let Err(e) = p.check_valid(&canary).await {
        rec.error("check_valid", &e);
    }
    if let Err(e) = p.describe_scope(&canary).await {
        rec.error("describe_scope", &e);
    }
    if p.replacement_mode() == ReplacementMode::Automatic {
        match p.create_replacement(&canary).await {
            Ok(r) => rec.know(&r.credential),
            Err(e) => {
                rec.error("create_replacement", &e);
            }
        }
    }
    if let Err(e) = p.verify(&canary, &fx.identity).await {
        rec.error("verify", &e);
    }
    if let Err(e) = p.revoke(&canary).await {
        rec.error("revoke", &e);
    }
}
