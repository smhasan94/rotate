//! The consumer half of the conformance suite.

use std::future::Future;
use std::sync::Arc;

use super::{
    canary, failed_if_any, mutations_during, MutationProbe, Outcome, Recorder, SuiteReport,
};
use crate::consumer::{Consumer, ConsumerMatch, MatchMethod, SecretRef};
use crate::provider::Credential;

/// One consumer wired to a test server, built fresh for every check.
pub struct ConsumerFixture {
    /// The plugin under test.
    pub consumer: Arc<dyn Consumer>,
    /// The credential the consumer stores now. `find(secret)` must return
    /// at least one updatable match for it.
    pub old: Credential,
    /// The credential the suite writes with `update`. Same shape as `old`.
    pub new: Credential,
    /// What the engine would ask `find` for `old`, including name hints.
    /// The suite asks for `new` with the same provider and names.
    pub secret: SecretRef,
    /// Where the plugin's state-changing calls show up.
    pub probe: Box<dyn MutationProbe>,
}

impl ConsumerFixture {
    /// The reference for `credential`, with the fixture's provider and names.
    fn reference(&self, credential: &Credential) -> SecretRef {
        SecretRef::new(self.secret.provider.clone(), credential)
            .with_names(self.secret.names.iter().cloned())
    }
}

/// Runs every consumer check. `factory` is called once per check.
///
/// Checks, in order: `find_unknown_empty`, `read_only_find`,
/// `update_then_find`, `restore_reverses_update`, `errors_redacted`.
pub async fn consumer_suite<F, Fut>(factory: F) -> SuiteReport
where
    F: Fn() -> Fut,
    Fut: Future<Output = ConsumerFixture>,
{
    let mut rec = Recorder::default();
    let mut report = SuiteReport::new("consumer");

    let fx = known(factory().await, &mut rec);
    report.plugin = fx.consumer.name();
    let outcome = find_unknown_empty(&fx, &mut rec).await;
    report.push("find_unknown_empty", outcome);

    let fx = known(factory().await, &mut rec);
    let outcome = read_only_find(&fx, &mut rec).await;
    report.push("read_only_find", outcome);

    let fx = known(factory().await, &mut rec);
    let outcome = update_then_find(&fx, &mut rec).await;
    report.push("update_then_find", outcome);

    let fx = known(factory().await, &mut rec);
    let outcome = restore_reverses_update(&fx, &mut rec).await;
    report.push("restore_reverses_update", outcome);

    let fx = known(factory().await, &mut rec);
    feed_canary(&fx, &mut rec).await;
    report.push("errors_redacted", rec.redaction_outcome());
    report
}

fn known(fx: ConsumerFixture, rec: &mut Recorder) -> ConsumerFixture {
    rec.know(&fx.old);
    rec.know(&fx.new);
    fx
}

async fn find_refs(
    fx: &ConsumerFixture,
    secret: &SecretRef,
    rec: &mut Recorder,
) -> Result<Vec<String>, String> {
    match fx.consumer.find(secret).await {
        Ok(found) => Ok(found.into_iter().map(|m| m.consumer_ref).collect()),
        Err(e) => Err(format!("find returned an error: {}", rec.error("find", &e))),
    }
}

/// The updatable matches for the fixture's `old` credential.
async fn targets(fx: &ConsumerFixture, rec: &mut Recorder) -> Result<Vec<ConsumerMatch>, String> {
    let found = match fx.consumer.find(&fx.secret).await {
        Ok(found) => found,
        Err(e) => return Err(format!("find returned an error: {}", rec.error("find", &e))),
    };
    let updatable: Vec<ConsumerMatch> = found.into_iter().filter(|m| m.is_updatable()).collect();
    if updatable.is_empty() {
        return Err("find returned no updatable match for the fixture's old credential".into());
    }
    Ok(updatable)
}

/// Updates every target to `new`, stopping at the first error.
async fn update_all(
    fx: &ConsumerFixture,
    targets: &[ConsumerMatch],
    rec: &mut Recorder,
) -> Result<(), String> {
    for target in targets {
        if let Err(e) = fx.consumer.update(target, &fx.new).await {
            return Err(format!(
                "update of {} returned an error: {}",
                target.consumer_ref,
                rec.error("update", &e)
            ));
        }
    }
    Ok(())
}

async fn find_unknown_empty(fx: &ConsumerFixture, rec: &mut Recorder) -> Outcome {
    let canary = canary(&fx.old);
    rec.know(&canary);
    let unknown = SecretRef::new(fx.secret.provider.clone(), &canary);
    match find_refs(fx, &unknown, rec).await {
        Ok(refs) if refs.is_empty() => Outcome::Passed,
        Ok(refs) => Outcome::Failed(format!(
            "find for an unknown fingerprint returned {}",
            refs.join(", ")
        )),
        Err(problem) => Outcome::Failed(problem),
    }
}

async fn read_only_find(fx: &ConsumerFixture, rec: &mut Recorder) -> Outcome {
    let mut error = None;
    let made = mutations_during(fx.probe.as_ref(), async {
        error = fx.consumer.find(&fx.secret).await.err();
    })
    .await;
    if let Some(e) = error {
        rec.error("find", &e);
    }
    if made.is_empty() {
        Outcome::Passed
    } else {
        Outcome::Failed(format!(
            "find made state-changing calls: {}",
            made.join(", ")
        ))
    }
}

async fn update_then_find(fx: &ConsumerFixture, rec: &mut Recorder) -> Outcome {
    let targets = match targets(fx, rec).await {
        Ok(targets) => targets,
        Err(problem) => return Outcome::Failed(problem),
    };
    if let Err(problem) = update_all(fx, &targets, rec).await {
        return Outcome::Failed(problem);
    }
    let found = match find_refs(fx, &fx.reference(&fx.new), rec).await {
        Ok(found) => found,
        Err(problem) => return Outcome::Failed(problem),
    };
    let missing: Vec<String> = targets
        .iter()
        .filter(|t| !found.contains(&t.consumer_ref))
        .map(|t| format!("find for the new credential misses {}", t.consumer_ref))
        .collect();
    failed_if_any(missing)
}

async fn restore_reverses_update(fx: &ConsumerFixture, rec: &mut Recorder) -> Outcome {
    let targets = match targets(fx, rec).await {
        Ok(targets) => targets,
        Err(problem) => return Outcome::Failed(problem),
    };
    if let Err(problem) = update_all(fx, &targets, rec).await {
        return Outcome::Failed(problem);
    }
    for target in &targets {
        if let Err(e) = fx.consumer.restore(target, &fx.old).await {
            return Outcome::Failed(format!(
                "restore of {} returned an error: {}",
                target.consumer_ref,
                rec.error("restore", &e)
            ));
        }
    }
    let with_old = match find_refs(fx, &fx.secret, rec).await {
        Ok(found) => found,
        Err(problem) => return Outcome::Failed(problem),
    };
    let with_new = match find_refs(fx, &fx.reference(&fx.new), rec).await {
        Ok(found) => found,
        Err(problem) => return Outcome::Failed(problem),
    };
    let mut problems = Vec::new();
    for target in &targets {
        if !with_old.contains(&target.consumer_ref) {
            problems.push(format!(
                "after restore, find for the old credential misses {}",
                target.consumer_ref
            ));
        }
        if target.match_method == MatchMethod::ByValue && with_new.contains(&target.consumer_ref) {
            problems.push(format!(
                "after restore, {} still holds the new credential",
                target.consumer_ref
            ));
        }
    }
    failed_if_any(problems)
}

/// Writes the canary through `update` and `restore` so a plugin that echoes
/// its input into errors gets caught. Restores `old` afterwards.
async fn feed_canary(fx: &ConsumerFixture, rec: &mut Recorder) {
    let canary = canary(&fx.old);
    rec.know(&canary);
    let Ok(targets) = targets(fx, rec).await else {
        return;
    };
    for target in &targets {
        if let Err(e) = fx.consumer.update(target, &canary).await {
            rec.error("update", &e);
        }
        if let Err(e) = fx.consumer.restore(target, &canary).await {
            rec.error("restore", &e);
        }
        if let Err(e) = fx.consumer.restore(target, &fx.old).await {
            rec.error("restore", &e);
        }
    }
}
