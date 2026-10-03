//! `rotate rollback` (SHA-259, FR18, US6): put the old secret back.
//!
//! rotate never stores a secret value, so rollback takes the original
//! report or stdin secret, matches it to rotations in the state file by
//! fingerprint ([`select`]), and undoes what apply did, in this order:
//!
//! 1. provider `restore` of the old secret, when apply revoked it and the
//!    provider gave a restore handle, so the old secret is live again
//!    before any consumer points at it;
//! 2. consumer `restore` of the old value, for every consumer apply
//!    updated (consumers whose update failed or was skipped still hold
//!    the old value and are left alone);
//! 3. provider `revoke_replacement` of the replacement, by its reference.
//!
//! Any error stops the rollback at that action: the replacement is never
//! revoked while a consumer may still use it, and consumers are not
//! restored when reactivating the old secret failed. A provider that
//! cannot reactivate the old secret (`Unsupported`) is not an error: the
//! consumers are still restored and the outcome carries a warning.
//!
//! After every action the rotation's [`RollbackProgress`] (and each
//! restored consumer's status) is saved to the state file and one audit
//! entry with step `rollback` is appended. A re-run continues from the
//! first action not done, so no action that succeeded is repeated; a
//! rotation already `rolled_back` makes no call at all.
//!
//! The old credential is borrowed from the caller, who read it from the
//! report or stdin; it stays registered with the redactor while the
//! command runs. Nothing returned from here holds a value. Nothing here
//! prints.

#![cfg(unix)]

use std::collections::HashMap;
use std::fmt::{self, Write as _};

use crate::audit::{
    AuditError, AuditEvent, AuditLog, AuditStep, Outcome as AuditOutcome, RedactedText,
    RollbackAction,
};
use crate::consumer::{ConsumerMatch, ConsumerRegistry, MatchMethod};
use crate::finding::{Finding, ACCESS_KEY_ID};
use crate::provider::{Credential, ProviderError, ProviderRegistry, RestoreOutcome};
use crate::secret::Fingerprint;
use crate::state::{
    ConsumerState, ConsumerStatus, RollbackProgress, Rotation, StateError, StateStore, Step,
};

// The `replacement_ref` apply records for a pasted replacement (SHA-257).
use crate::apply::MANUAL_REF;

/// One secret from the report or stdin, deduplicated by fingerprint.
#[derive(Debug, Clone)]
pub struct RollbackInput {
    /// Fingerprint of the secret half.
    pub fingerprint: Fingerprint,
    /// The old credential, a key pair when the report gave an access key id.
    pub credential: Credential,
}

/// Deduplicates `findings` by fingerprint, keeping a finding with an
/// access key id over one without, as assessment does. No provider call.
pub fn inputs(findings: Vec<Finding>) -> Vec<RollbackInput> {
    let mut out: Vec<RollbackInput> = Vec::new();
    let mut index: HashMap<Fingerprint, usize> = HashMap::new();
    for finding in findings {
        let fingerprint = finding.fingerprint();
        match index.get(&fingerprint) {
            Some(&at) => {
                if out[at].credential.key_id().is_none()
                    && finding.extra.contains_key(ACCESS_KEY_ID)
                {
                    out[at].credential = finding.credential();
                }
            }
            None => {
                index.insert(fingerprint.clone(), out.len());
                out.push(RollbackInput {
                    fingerprint,
                    credential: finding.credential(),
                });
            }
        }
    }
    out
}

/// Why no rotation could be selected. Exit 2, no call made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    /// No rotation in the state file has the input's fingerprint (or none
    /// of them is the one `--rotation` named).
    #[error(
        "no rotation found for fingerprint {}{}; rollback matches the input against the state file written by rotate apply",
        fingerprints.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
        rotation.as_ref().map(|id| format!(" with id {id}")).unwrap_or_default()
    )]
    NoMatch {
        /// The input fingerprints.
        fingerprints: Vec<Fingerprint>,
        /// The `--rotation` id, if one was given.
        rotation: Option<String>,
    },
}

/// A rotation matched to the input secret it rotated.
#[derive(Debug, Clone)]
pub struct Selected {
    /// The stored rotation.
    pub rotation: Rotation,
    /// Index into the inputs of the credential it rotated.
    pub input: usize,
}

/// The rotations in `rotations` whose fingerprint is one of the inputs',
/// in state order, narrowed to `only` when given. Pure.
pub fn select(
    rotations: &[Rotation],
    inputs: &[RollbackInput],
    only: Option<&str>,
) -> Result<Vec<Selected>, SelectError> {
    let selected: Vec<Selected> = rotations
        .iter()
        .filter(|r| only.is_none_or(|id| r.rotation_id == id))
        .filter_map(|r| {
            inputs
                .iter()
                .position(|i| i.fingerprint == r.fingerprint)
                .map(|input| Selected {
                    rotation: r.clone(),
                    input,
                })
        })
        .collect();
    if selected.is_empty() {
        return Err(SelectError::NoMatch {
            fingerprints: inputs.iter().map(|i| i.fingerprint.clone()).collect(),
            rotation: only.map(str::to_owned),
        });
    }
    Ok(selected)
}

/// What rollback does about the old secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OldSecretAction {
    /// Reactivate it with provider `restore` and this handle.
    Restore(String),
    /// It was revoked and the provider gave no handle: it cannot be
    /// reactivated; consumers are restored only.
    Unsupported,
    /// It was never revoked; nothing to reactivate.
    NotRevoked,
    /// An earlier rollback run finished this step.
    Done,
}

/// What rollback does about the replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplacementAction {
    /// Revoke it with provider `revoke_replacement` and this ref.
    Revoke(String),
    /// It was pasted by the operator (manual mode): rotate has no handle on
    /// it, so it must be revoked by hand.
    Manual,
    /// None was created.
    None,
    /// An earlier rollback run finished this step.
    Done,
}

/// What rollback will do for one rotation. Holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPlan {
    /// Rotation id; what the operator confirms.
    pub rotation_id: String,
    /// Provider name.
    pub provider: String,
    /// Fingerprint of the old secret.
    pub fingerprint: Fingerprint,
    /// The step apply reached.
    pub step: Step,
    /// The old secret.
    pub old: OldSecretAction,
    /// Consumers apply updated, to restore, in apply's order.
    pub restore: Vec<ConsumerState>,
    /// Consumers already restored by an earlier rollback run.
    pub restored: Vec<ConsumerState>,
    /// Consumers apply did not update (failed or skipped): left as they are.
    pub left: Vec<ConsumerState>,
    /// The replacement.
    pub replacement: ReplacementAction,
    /// A rollback of it started earlier and did not finish.
    pub resuming: bool,
}

impl RollbackPlan {
    /// The plan for `rotation`, minus what its saved progress says is done.
    pub fn of(rotation: &Rotation) -> Self {
        let progress = rotation.rollback.clone().unwrap_or_default();
        let old = if progress.restore_done {
            OldSecretAction::Done
        } else if let Some(handle) = &rotation.restore_ref {
            OldSecretAction::Restore(handle.clone())
        } else if rotation.step == Step::Revoked {
            OldSecretAction::Unsupported
        } else {
            OldSecretAction::NotRevoked
        };
        let replacement = if progress.revoke_done {
            ReplacementAction::Done
        } else {
            match rotation.replacement_ref.as_deref() {
                Some(MANUAL_REF) => ReplacementAction::Manual,
                Some(reference) => ReplacementAction::Revoke(reference.to_owned()),
                None => ReplacementAction::None,
            }
        };
        let with = |status: ConsumerStatus| {
            rotation
                .consumers
                .iter()
                .filter(|c| c.status == status)
                .cloned()
                .collect::<Vec<_>>()
        };
        Self {
            rotation_id: rotation.rotation_id.clone(),
            provider: rotation.provider.clone(),
            fingerprint: rotation.fingerprint.clone(),
            step: rotation.step,
            old,
            restore: with(ConsumerStatus::Updated),
            restored: with(ConsumerStatus::Restored),
            left: rotation
                .consumers
                .iter()
                .filter(|c| matches!(c.status, ConsumerStatus::Failed | ConsumerStatus::Skipped))
                .cloned()
                .collect(),
            replacement,
            resuming: rotation.is_rolling_back(),
        }
    }

    /// True when the rotation is already `rolled_back`.
    pub fn is_finished(&self) -> bool {
        self.step == Step::RolledBack
    }

    /// True when there is something to undo or a started rollback to
    /// finish. A bare `planned` record has nothing.
    pub fn has_work(&self) -> bool {
        !self.is_finished()
            && (self.resuming
                || matches!(
                    self.old,
                    OldSecretAction::Restore(_) | OldSecretAction::Unsupported
                )
                || !self.restore.is_empty()
                || matches!(
                    self.replacement,
                    ReplacementAction::Revoke(_) | ReplacementAction::Manual
                ))
    }
}

fn step_name(step: Step) -> &'static str {
    match step {
        Step::Planned => "planned",
        Step::Created => "created",
        Step::ConsumersUpdated => "consumers_updated",
        Step::Verified => "verified",
        Step::PendingRevoke => "pending_revoke",
        Step::Revoked => "revoked",
        Step::Failed => "failed",
        Step::NeedsRollback => "needs_rollback",
        Step::RolledBack => "rolled_back",
    }
}

fn status_name(status: ConsumerStatus) -> &'static str {
    match status {
        ConsumerStatus::Updated => "updated",
        ConsumerStatus::Failed => "update failed",
        ConsumerStatus::Skipped => "skipped",
        ConsumerStatus::Restored => "restored",
    }
}

/// The text shown for a rotation the old secret cannot come back for.
pub const UNSUPPORTED_TEXT: &str =
    "unsupported: old secret cannot be reactivated, consumers will be restored only";

/// The rollback plan, one block per rotation that has work, then a note
/// per rotation that has none.
pub fn render_plan(plans: &[RollbackPlan]) -> String {
    let work: Vec<&RollbackPlan> = plans.iter().filter(|p| p.has_work()).collect();
    let mut out = String::new();
    let noun = if work.len() == 1 {
        "rotation"
    } else {
        "rotations"
    };
    let _ = writeln!(
        out,
        "Rollback plan: {} {noun} to roll back. Nothing has been changed yet.",
        work.len()
    );
    for p in &work {
        let _ = writeln!(
            out,
            "\n{}  {}  {}  step {}{}",
            p.rotation_id,
            p.provider,
            p.fingerprint,
            step_name(p.step),
            if p.resuming {
                " (continuing an earlier rollback)"
            } else {
                ""
            }
        );
        let old = match &p.old {
            OldSecretAction::Restore(handle) => format!("reactivate with restore {handle}"),
            OldSecretAction::Unsupported => UNSUPPORTED_TEXT.to_owned(),
            OldSecretAction::NotRevoked => "never revoked; nothing to reactivate".to_owned(),
            OldSecretAction::Done => "done in an earlier run".to_owned(),
        };
        field(&mut out, "old secret", &old);
        let consumers = if p.restore.is_empty() {
            "nothing to roll back".to_owned()
        } else {
            p.restore
                .iter()
                .map(|c| format!("restore {}", c.consumer_ref))
                .collect::<Vec<_>>()
                .join(", ")
        };
        field(&mut out, "consumers", &consumers);
        if !p.restored.is_empty() {
            field(&mut out, "restored", &refs(&p.restored, false));
        }
        if !p.left.is_empty() {
            field(&mut out, "left as is", &refs(&p.left, true));
        }
        let replacement = match &p.replacement {
            ReplacementAction::Revoke(reference) => format!("revoke {reference}"),
            ReplacementAction::Manual => {
                "pasted by hand; rotate cannot revoke it, revoke it by hand".to_owned()
            }
            ReplacementAction::None => "none was created".to_owned(),
            ReplacementAction::Done => "done in an earlier run".to_owned(),
        };
        field(&mut out, "replacement", &replacement);
    }
    let idle: Vec<&RollbackPlan> = plans.iter().filter(|p| !p.has_work()).collect();
    if !idle.is_empty() {
        out.push('\n');
        for p in idle {
            if p.is_finished() {
                let _ = writeln!(out, "{}: already rolled back; nothing to do", p.rotation_id);
            } else {
                let _ = writeln!(
                    out,
                    "{}: nothing to roll back (step {}, no replacement, no consumer updated)",
                    p.rotation_id,
                    step_name(p.step)
                );
            }
        }
    }
    out
}

fn refs(consumers: &[ConsumerState], with_status: bool) -> String {
    consumers
        .iter()
        .map(|c| {
            if with_status {
                format!("{} ({})", c.consumer_ref, status_name(c.status))
            } else {
                c.consumer_ref.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn field(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "  {label:<14}{value}");
}

/// How one rollback ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackResult {
    /// Every step is done; the rotation is `rolled_back`.
    RolledBack,
    /// An action failed; the rollback stopped there and can be re-run.
    Failed {
        /// The action that failed.
        action: RollbackAction,
        /// Why, redacted.
        error: RedactedText,
    },
}

/// One rotation's rollback outcome, for the summary. Holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackOutcome {
    /// Rotation id.
    pub rotation_id: String,
    /// Provider name.
    pub provider: String,
    /// Fingerprint of the old secret.
    pub fingerprint: Fingerprint,
    /// Refs of consumers restored in this run.
    pub restored: Vec<String>,
    /// Things the operator must know or do by hand.
    pub warnings: Vec<String>,
    /// How it ended.
    pub result: RollbackResult,
}

/// A state or audit write failed mid-rollback.
#[derive(Debug, thiserror::Error)]
enum RecordError {
    #[error("could not save the state file: {0}")]
    State(#[from] StateError),
    #[error("could not append to the audit log: {0}")]
    Audit(#[from] AuditError),
}

/// Runs confirmed rollbacks, recording every action in the state file and
/// the audit log.
pub struct RollbackExecutor<'a> {
    providers: &'a ProviderRegistry,
    consumers: &'a ConsumerRegistry,
    store: &'a mut StateStore,
    audit: &'a mut AuditLog,
}

impl fmt::Debug for RollbackExecutor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RollbackExecutor")
            .field("providers", &self.providers)
            .field("consumers", &self.consumers)
            .finish_non_exhaustive()
    }
}

/// Progress of one rollback inside [`RollbackExecutor::run`].
struct Progress {
    record: Rotation,
    restored: Vec<String>,
    warnings: Vec<String>,
}

impl Progress {
    fn rollback(&mut self) -> &mut RollbackProgress {
        self.record.rollback.get_or_insert_with(Default::default)
    }
}

impl<'a> RollbackExecutor<'a> {
    /// An executor writing to `store` and `audit`.
    pub fn new(
        providers: &'a ProviderRegistry,
        consumers: &'a ConsumerRegistry,
        store: &'a mut StateStore,
        audit: &'a mut AuditLog,
    ) -> Self {
        Self {
            providers,
            consumers,
            store,
            audit,
        }
    }

    /// Rolls back the rotation `plan` describes, with `old` the credential
    /// it rotated (from the report or stdin, matched by fingerprint). The
    /// order is fixed: restore the old secret, restore each updated
    /// consumer, revoke the replacement. Stops at the first error.
    pub async fn run(&mut self, plan: &RollbackPlan, old: &Credential) -> RollbackOutcome {
        let record = self
            .store
            .get(&plan.rotation_id)
            .cloned()
            .unwrap_or_else(|| {
                Rotation::new(
                    plan.rotation_id.clone(),
                    plan.provider.clone(),
                    plan.fingerprint.clone(),
                )
            });
        let mut progress = Progress {
            record,
            restored: Vec::new(),
            warnings: Vec::new(),
        };
        let result = self.steps(plan, old, &mut progress).await;
        RollbackOutcome {
            rotation_id: plan.rotation_id.clone(),
            provider: plan.provider.clone(),
            fingerprint: plan.fingerprint.clone(),
            restored: progress.restored,
            warnings: progress.warnings,
            result,
        }
    }

    async fn steps(
        &mut self,
        plan: &RollbackPlan,
        old: &Credential,
        progress: &mut Progress,
    ) -> RollbackResult {
        if old.fingerprint() != progress.record.fingerprint {
            return self.fail(
                progress,
                RollbackAction::RestoreOld,
                "the input secret is not the one this rotation rotated",
                None,
            );
        }
        progress.rollback();
        if let Err(err) = self.save(progress) {
            return self.fail(progress, RollbackAction::RestoreOld, &err.to_string(), None);
        }
        let provider = self.providers.get(&plan.provider).cloned();

        // 1. The old secret first, so it is live before consumers use it.
        match &plan.old {
            OldSecretAction::Restore(handle) => {
                let Some(provider) = &provider else {
                    return self.fail(
                        progress,
                        RollbackAction::RestoreOld,
                        "the provider is not registered",
                        None,
                    );
                };
                match provider.restore(handle).await {
                    Ok(RestoreOutcome::Restored) => {
                        progress.rollback().restore_done = true;
                        if let Err(err) =
                            self.checkpoint(progress, RollbackAction::RestoreOld, None)
                        {
                            return self.fail(
                                progress,
                                RollbackAction::RestoreOld,
                                &err.to_string(),
                                None,
                            );
                        }
                    }
                    Ok(RestoreOutcome::Unsupported) => {
                        let reason = format!(
                            "{} cannot reactivate a revoked credential",
                            plan.provider
                        );
                        if let Err(err) = self.unsupported_old(progress, &reason) {
                            return self.fail(
                                progress,
                                RollbackAction::RestoreOld,
                                &err.to_string(),
                                None,
                            );
                        }
                    }
                    Err(err) => {
                        return self.fail(
                            progress,
                            RollbackAction::RestoreOld,
                            &format!(
                                "{err}; nothing was restored and the consumers still hold the replacement"
                            ),
                            None,
                        )
                    }
                }
            }
            OldSecretAction::Unsupported => {
                let reason = "the provider gave no handle to reactivate it";
                if let Err(err) = self.unsupported_old(progress, reason) {
                    return self.fail(progress, RollbackAction::RestoreOld, &err.to_string(), None);
                }
            }
            OldSecretAction::NotRevoked | OldSecretAction::Done => {
                progress.rollback().restore_done = true;
                if let Err(err) = self.save(progress) {
                    return self.fail(progress, RollbackAction::RestoreOld, &err.to_string(), None);
                }
            }
        }

        // 2. Every consumer apply updated gets the old value back.
        for state in &plan.restore {
            let reference = state.consumer_ref.clone();
            let Some(consumer) = self.consumers.get(&state.consumer) else {
                return self.fail(
                    progress,
                    RollbackAction::RestoreConsumer,
                    &format!("{reference}: the consumer is not registered"),
                    Some(&reference),
                );
            };
            let Some(holds) = state.holds else {
                return self.fail(
                    progress,
                    RollbackAction::RestoreConsumer,
                    &format!(
                        "{reference}: the state file does not say which part of the credential it holds; restore it by hand"
                    ),
                    Some(&reference),
                );
            };
            let target = ConsumerMatch {
                consumer_ref: reference.clone(),
                match_method: MatchMethod::ByName,
                holds,
                updatable: Ok(()),
            };
            if let Err(err) = consumer.restore(&target, old).await {
                return self.fail(
                    progress,
                    RollbackAction::RestoreConsumer,
                    &format!("{reference}: {err}; the replacement was not revoked"),
                    Some(&reference),
                );
            }
            if let Some(c) = progress
                .record
                .consumers
                .iter_mut()
                .find(|c| c.consumer_ref == reference && c.consumer == state.consumer)
            {
                c.status = ConsumerStatus::Restored;
            }
            progress.restored.push(reference.clone());
            if let Err(err) =
                self.checkpoint(progress, RollbackAction::RestoreConsumer, Some(&reference))
            {
                return self.fail(
                    progress,
                    RollbackAction::RestoreConsumer,
                    &err.to_string(),
                    Some(&reference),
                );
            }
        }

        // 3. The replacement, last: nothing uses it any more.
        let action = RollbackAction::RevokeReplacement;
        match &plan.replacement {
            ReplacementAction::Revoke(reference) => {
                let Some(provider) = &provider else {
                    return self.fail(progress, action, "the provider is not registered", None);
                };
                match provider.revoke_replacement(reference).await {
                    Ok(()) => {
                        progress.rollback().revoke_done = true;
                        if let Err(err) = self.checkpoint(progress, action, None) {
                            return self.fail(progress, action, &err.to_string(), None);
                        }
                    }
                    Err(ProviderError::Unsupported(why)) => {
                        let reason = format!("revoke the replacement {reference} by hand: {why}");
                        if let Err(err) = self.by_hand(progress, &reason) {
                            return self.fail(progress, action, &err.to_string(), None);
                        }
                    }
                    Err(err) => {
                        return self.fail(
                            progress,
                            action,
                            &format!(
                                "{err}; the consumers hold the old secret again, but the replacement {reference} is still live"
                            ),
                            None,
                        )
                    }
                }
            }
            ReplacementAction::Manual => {
                let reason =
                    "revoke the pasted replacement by hand: rotate has no handle on a secret it did not create";
                if let Err(err) = self.by_hand(progress, reason) {
                    return self.fail(progress, action, &err.to_string(), None);
                }
            }
            ReplacementAction::None | ReplacementAction::Done => {
                progress.rollback().revoke_done = true;
                if let Err(err) = self.save(progress) {
                    return self.fail(progress, action, &err.to_string(), None);
                }
            }
        }

        progress.record.step = Step::RolledBack;
        progress.record.failed_step = None;
        let finished = self
            .save(progress)
            .and_then(|()| self.event(progress, None, AuditOutcome::Ok, None, None));
        if let Err(err) = finished {
            return RollbackResult::Failed {
                action,
                error: RedactedText::new(&format!(
                    "every rollback action is done but {err}; re-run rotate rollback to record it"
                )),
            };
        }
        RollbackResult::RolledBack
    }

    /// The provider cannot bring the old secret back: warn, record a
    /// skipped `restore_old`, and carry on with the consumers.
    fn unsupported_old(
        &mut self,
        progress: &mut Progress,
        reason: &str,
    ) -> Result<(), RecordError> {
        progress.warnings.push(format!(
            "the old secret was not reactivated ({reason}); it stays revoked, so the restored consumers hold a revoked secret"
        ));
        progress.rollback().restore_done = true;
        self.save(progress)?;
        self.event(
            progress,
            Some(RollbackAction::RestoreOld),
            AuditOutcome::Skipped,
            None,
            Some(reason),
        )
    }

    /// The replacement cannot be revoked by rotate: warn and record a
    /// skipped `revoke_replacement`.
    fn by_hand(&mut self, progress: &mut Progress, reason: &str) -> Result<(), RecordError> {
        progress.warnings.push(reason.to_owned());
        progress.rollback().revoke_done = true;
        self.save(progress)?;
        self.event(
            progress,
            Some(RollbackAction::RevokeReplacement),
            AuditOutcome::Skipped,
            None,
            Some(reason),
        )
    }

    fn checkpoint(
        &mut self,
        progress: &Progress,
        action: RollbackAction,
        consumer: Option<&str>,
    ) -> Result<(), RecordError> {
        self.save(progress)?;
        self.event(progress, Some(action), AuditOutcome::Ok, consumer, None)
    }

    fn save(&mut self, progress: &Progress) -> Result<(), RecordError> {
        self.store.upsert(progress.record.clone())?;
        Ok(())
    }

    fn event(
        &mut self,
        progress: &Progress,
        action: Option<RollbackAction>,
        outcome: AuditOutcome,
        consumer: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), RecordError> {
        let record = &progress.record;
        let mut event = AuditEvent::new(
            record.rotation_id.clone(),
            record.provider.clone(),
            record.fingerprint.clone(),
            AuditStep::Rollback,
            outcome,
        );
        if let Some(fp) = &record.replacement_fingerprint {
            event = event.with_replacement(fp.clone());
        }
        if let Some(action) = action {
            event = event.with_action(action);
        }
        if let Some(consumer) = consumer {
            event = event.with_consumer(consumer);
        }
        if let Some(error) = error {
            event = event.with_error(error);
        }
        self.audit.append(event)?;
        Ok(())
    }

    /// Records the failed action, best effort, and returns it. The step is
    /// left as apply left it; the saved progress lets a re-run continue.
    fn fail(
        &mut self,
        progress: &mut Progress,
        action: RollbackAction,
        error: &str,
        consumer: Option<&str>,
    ) -> RollbackResult {
        let recorded = self.save(progress).and_then(|()| {
            self.event(
                progress,
                Some(action),
                AuditOutcome::Failed,
                consumer,
                Some(error),
            )
        });
        if let Err(err) = recorded {
            tracing::warn!(
                rotation_id = %progress.record.rotation_id,
                "could not record the rollback failure: {err}"
            );
        }
        RollbackResult::Failed {
            action,
            error: RedactedText::new(error),
        }
    }
}

fn action_name(action: RollbackAction) -> &'static str {
    match action {
        RollbackAction::RestoreOld => "restoring the old secret",
        RollbackAction::RestoreConsumer => "restoring a consumer",
        RollbackAction::RevokeReplacement => "revoking the replacement",
    }
}

/// True when any rollback failed (exit 1).
pub fn any_failed(outcomes: &[RollbackOutcome]) -> bool {
    outcomes
        .iter()
        .any(|o| matches!(o.result, RollbackResult::Failed { .. }))
}

/// The summary printed after rollback: a count, one row per rotation, then
/// a note per warning or failure.
pub fn render_summary(outcomes: &[RollbackOutcome]) -> String {
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o.result, RollbackResult::Failed { .. }))
        .count();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Rollback: {} rolled back, {failed} failed.",
        outcomes.len() - failed
    );
    let mut notes = Vec::new();
    for o in outcomes {
        let outcome = match &o.result {
            RollbackResult::RolledBack => "rolled back".to_owned(),
            RollbackResult::Failed { action, error } => {
                notes.push(format!(
                    "{}: {} failed: {error}; stopped there; re-run rotate rollback to continue",
                    o.rotation_id,
                    action_name(*action)
                ));
                "failed".to_owned()
            }
        };
        for warning in &o.warnings {
            notes.push(format!("{}: warning: {warning}", o.rotation_id));
        }
        let restored = if o.restored.is_empty() {
            "no consumer restored".to_owned()
        } else {
            format!("restored {}", o.restored.join(", "))
        };
        let _ = writeln!(
            out,
            "{}  {}  {}  {restored}  {outcome}",
            o.rotation_id, o.provider, o.fingerprint
        );
    }
    if !notes.is_empty() {
        out.push('\n');
        for note in notes {
            out.push_str(&note);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::audit::{read_all, AuditEntry};
    use crate::calls::CallLog;
    use crate::consumer::mock::MockConsumer;
    use crate::consumer::{ConsumerError, Holds};
    use crate::finding::SourceLocation;
    use crate::provider::mock::MockProvider;
    use crate::secret::{SecretPair, SecretValue};

    const OLD: &str = "npm_rollback-unit-old";
    const GHA: &str = "gha:org/repo:NPM_TOKEN";
    const SM: &str = "sm:prod/npm";

    fn token(value: &str) -> Credential {
        Credential::Token(SecretValue::from(value))
    }

    fn fp(value: &str) -> Fingerprint {
        SecretValue::from(value).fingerprint()
    }

    fn consumer(name: &str, reference: &str, status: ConsumerStatus) -> ConsumerState {
        ConsumerState {
            consumer: name.into(),
            consumer_ref: reference.into(),
            status,
            holds: Some(Holds::Secret),
        }
    }

    /// A rotation as apply leaves it after `revoked`: two consumers updated.
    fn revoked() -> Rotation {
        let mut r = Rotation::new("rot-unit", "npm", fp(OLD));
        r.replacement_fingerprint = Some(fp("npm_rollback-unit-new"));
        r.replacement_ref = Some("npm-ref-1".into());
        r.step = Step::Revoked;
        r.restore_ref = Some("npm-old-handle".into());
        r.consumers = vec![
            consumer("github-actions", GHA, ConsumerStatus::Updated),
            consumer("aws-secrets-manager", SM, ConsumerStatus::Updated),
        ];
        r
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        store: StateStore,
        audit: AuditLog,
        audit_path: std::path::PathBuf,
        log: CallLog,
        providers: ProviderRegistry,
        consumers: ConsumerRegistry,
        gha: Arc<MockConsumer>,
        sm: Arc<MockConsumer>,
    }

    fn fixture(provider: MockProvider, seed: &Rotation) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(dir.path().join("state.json")).unwrap();
        store.upsert(seed.clone()).unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open_as(&audit_path, "unit@test").unwrap();
        let log = CallLog::new();
        let mut providers = ProviderRegistry::new();
        providers.register(Arc::new(provider.log(log.clone())));
        let new = seed
            .replacement_fingerprint
            .clone()
            .unwrap_or_else(|| fp(OLD));
        let gha = Arc::new(
            MockConsumer::new("github-actions")
                .matching(new.clone(), ConsumerMatch::by_name(GHA))
                .log(log.clone()),
        );
        let sm = Arc::new(
            MockConsumer::new("aws-secrets-manager")
                .matching(new, ConsumerMatch::by_value(SM))
                .log(log.clone()),
        );
        let mut consumers = ConsumerRegistry::new();
        consumers.register(gha.clone());
        consumers.register(sm.clone());
        Fixture {
            _dir: dir,
            store,
            audit,
            audit_path,
            log,
            providers,
            consumers,
            gha,
            sm,
        }
    }

    async fn run(f: &mut Fixture, old: &Credential) -> RollbackOutcome {
        let plan = RollbackPlan::of(f.store.get("rot-unit").unwrap());
        let mut executor =
            RollbackExecutor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit);
        executor.run(&plan, old).await
    }

    fn mutating(log: &CallLog) -> Vec<String> {
        log.mutating()
            .into_iter()
            .map(|c| {
                format!(
                    "{}.{}({})",
                    c.target,
                    c.method,
                    c.reference.unwrap_or_default()
                )
            })
            .collect()
    }

    fn rollback_entries(f: &Fixture) -> Vec<AuditEntry> {
        read_all(&f.audit_path)
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| e.step == AuditStep::Rollback)
            .collect()
    }

    #[test]
    fn inputs_dedupe_and_prefer_key_pairs() {
        let secret = SecretValue::from("unit-pair-secret");
        let bare = Finding::new(secret.clone(), "AWS", SourceLocation::file("a"));
        let pair = bare.clone().with_extra(ACCESS_KEY_ID, "KEYIDUNIT");
        let other = Finding::new(SecretValue::from(OLD), "npm", SourceLocation::file("b"));
        let got = inputs(vec![bare, other, pair]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].fingerprint, secret.fingerprint());
        assert_eq!(
            got[0].credential,
            Credential::KeyPair(SecretPair::new("KEYIDUNIT", secret))
        );
        assert_eq!(got[1].fingerprint, fp(OLD));
    }

    #[test]
    fn select_by_fingerprint_and_id() {
        let mut other = revoked();
        other.rotation_id = "rot-other".into();
        other.fingerprint = fp("npm_unrelated");
        let rotations = vec![other, revoked()];
        let input = inputs(vec![Finding::new(
            SecretValue::from(OLD),
            "npm",
            SourceLocation::file("a"),
        )]);
        let got = select(&rotations, &input, None).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].rotation.rotation_id, "rot-unit");
        assert!(select(&rotations, &input, Some("rot-unit")).is_ok());

        let err = select(&rotations, &input, Some("rot-other")).unwrap_err();
        assert!(err.to_string().contains("with id rot-other"), "{err}");
        let unrelated = inputs(vec![Finding::new(
            SecretValue::from("npm_nobody"),
            "npm",
            SourceLocation::file("a"),
        )]);
        let err = select(&rotations, &unrelated, None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.starts_with(&format!(
                "no rotation found for fingerprint {}",
                fp("npm_nobody")
            )),
            "{msg}"
        );
        assert!(!msg.contains("npm_nobody"), "{msg}");
    }

    #[test]
    fn plan_of_each_step() {
        let p = RollbackPlan::of(&revoked());
        assert_eq!(p.old, OldSecretAction::Restore("npm-old-handle".into()));
        assert_eq!(p.restore.len(), 2);
        assert_eq!(p.replacement, ReplacementAction::Revoke("npm-ref-1".into()));
        assert!(p.has_work());

        let mut r = revoked();
        r.restore_ref = None;
        assert_eq!(RollbackPlan::of(&r).old, OldSecretAction::Unsupported);
        assert!(render_plan(&[RollbackPlan::of(&r)]).contains(UNSUPPORTED_TEXT));

        r.step = Step::PendingRevoke;
        assert_eq!(RollbackPlan::of(&r).old, OldSecretAction::NotRevoked);

        let mut created = revoked();
        created.step = Step::Created;
        created.restore_ref = None;
        created.consumers.clear();
        let p = RollbackPlan::of(&created);
        assert!(p.restore.is_empty() && p.has_work());
        assert!(render_plan(&[p]).contains("consumers     nothing to roll back"));

        let mut manual = revoked();
        manual.replacement_ref = Some(MANUAL_REF.into());
        assert_eq!(
            RollbackPlan::of(&manual).replacement,
            ReplacementAction::Manual
        );

        let planned = Rotation::new("rot-bare", "npm", fp(OLD));
        let p = RollbackPlan::of(&planned);
        assert!(!p.has_work());
        assert!(render_plan(&[p]).contains("rot-bare: nothing to roll back"));

        let mut done = revoked();
        done.step = Step::RolledBack;
        let p = RollbackPlan::of(&done);
        assert!(p.is_finished() && !p.has_work());
        assert!(render_plan(&[p]).contains("rot-unit: already rolled back"));
    }

    #[test]
    fn plan_skips_done_steps_and_lists_left_consumers() {
        let mut r = revoked();
        r.consumers[0].status = ConsumerStatus::Restored;
        r.consumers.push(consumer(
            "github-actions",
            "gha:org/repo:B",
            ConsumerStatus::Failed,
        ));
        r.rollback = Some(RollbackProgress {
            restore_done: true,
            revoke_done: false,
        });
        let p = RollbackPlan::of(&r);
        assert_eq!(p.old, OldSecretAction::Done);
        assert_eq!(p.restore.len(), 1);
        assert_eq!(p.restore[0].consumer_ref, SM);
        assert_eq!(p.restored.len(), 1);
        assert_eq!(p.left.len(), 1);
        let text = render_plan(&[p]);
        assert!(text.contains("continuing an earlier rollback"), "{text}");
        assert!(text.contains("gha:org/repo:B (update failed)"), "{text}");
    }

    // T1 (AC1), T2 (AC2)
    #[tokio::test]
    async fn executor_order_restore_consumers_revoke() {
        let mut f = fixture(MockProvider::new("npm"), &revoked());
        let outcome = run(&mut f, &token(OLD)).await;
        assert_eq!(outcome.result, RollbackResult::RolledBack, "{outcome:?}");
        assert!(outcome.warnings.is_empty());
        assert_eq!(
            mutating(&f.log),
            [
                "npm.restore(npm-old-handle)".to_owned(),
                format!("github-actions.restore({GHA})"),
                format!("aws-secrets-manager.restore({SM})"),
                "npm.revoke_replacement(npm-ref-1)".to_owned(),
            ]
        );
        assert_eq!(f.gha.current(GHA), Some(fp(OLD)));
        assert_eq!(f.sm.current(SM), Some(fp(OLD)));
        let saved = f.store.get("rot-unit").unwrap();
        assert_eq!(saved.step, Step::RolledBack);
        assert!(saved
            .consumers
            .iter()
            .all(|c| c.status == ConsumerStatus::Restored));
        let entries = rollback_entries(&f);
        let actions: Vec<_> = entries.iter().map(|e| e.action).collect();
        assert_eq!(
            actions,
            [
                Some(RollbackAction::RestoreOld),
                Some(RollbackAction::RestoreConsumer),
                Some(RollbackAction::RestoreConsumer),
                Some(RollbackAction::RevokeReplacement),
                None,
            ]
        );
        assert!(entries.iter().all(|e| e.outcome == AuditOutcome::Ok));
        assert_eq!(entries[1].consumer.as_deref(), Some(GHA));

        // Idempotent: a second run has nothing left to do.
        let p = RollbackPlan::of(f.store.get("rot-unit").unwrap());
        assert!(p.is_finished() && !p.has_work());
    }

    // T3 (AC3)
    #[tokio::test]
    async fn unsupported_restore_still_restores_and_revokes() {
        let provider = MockProvider::new("npm").restore_outcome(RestoreOutcome::Unsupported);
        let mut f = fixture(provider, &revoked());
        let outcome = run(&mut f, &token(OLD)).await;
        assert_eq!(outcome.result, RollbackResult::RolledBack);
        assert_eq!(outcome.warnings.len(), 1);
        assert!(outcome.warnings[0].contains("the old secret was not reactivated"));
        assert_eq!(mutating(&f.log).len(), 4);
        assert_eq!(f.gha.current(GHA), Some(fp(OLD)));
        let summary = render_summary(&[outcome]);
        assert!(summary.contains("warning: the old secret was not reactivated"));
        assert_eq!(rollback_entries(&f)[0].outcome, AuditOutcome::Skipped);
    }

    // T6 (AC6)
    #[tokio::test]
    async fn only_updated_consumers_are_restored() {
        let mut r = revoked();
        r.step = Step::Failed;
        r.failed_step = Some(AuditStep::Update);
        r.restore_ref = None;
        r.consumers[1].status = ConsumerStatus::Failed;
        let mut f = fixture(MockProvider::new("npm"), &r);
        let outcome = run(&mut f, &token(OLD)).await;
        assert_eq!(outcome.result, RollbackResult::RolledBack);
        assert_eq!(
            mutating(&f.log),
            [
                format!("github-actions.restore({GHA})"),
                "npm.revoke_replacement(npm-ref-1)".to_owned(),
            ]
        );
        assert_eq!(outcome.restored, [GHA]);
    }

    // T7 (AC7)
    #[tokio::test]
    async fn created_only_revokes_the_replacement() {
        let mut r = revoked();
        r.step = Step::Created;
        r.restore_ref = None;
        r.consumers.clear();
        let mut f = fixture(MockProvider::new("npm"), &r);
        let outcome = run(&mut f, &token(OLD)).await;
        assert_eq!(outcome.result, RollbackResult::RolledBack);
        assert_eq!(mutating(&f.log), ["npm.revoke_replacement(npm-ref-1)"]);
    }

    #[tokio::test]
    async fn consumer_failure_stops_before_revoke_and_rerun_continues() {
        let mut f = fixture(MockProvider::new("npm"), &revoked());
        f.sm.fail_next("restore", ConsumerError::Permanent("403 denied".into()));
        let outcome = run(&mut f, &token(OLD)).await;
        let RollbackResult::Failed { action, error } = &outcome.result else {
            panic!("{outcome:?}");
        };
        assert_eq!(*action, RollbackAction::RestoreConsumer);
        assert!(error.as_str().contains("the replacement was not revoked"));
        assert!(!mutating(&f.log).iter().any(|c| c.contains("revoke")));
        let saved = f.store.get("rot-unit").unwrap().clone();
        assert_eq!(
            saved.step,
            Step::Revoked,
            "the step is left as apply left it"
        );
        assert!(saved.is_rolling_back());
        assert_eq!(saved.consumers[0].status, ConsumerStatus::Restored);
        assert_eq!(saved.consumers[1].status, ConsumerStatus::Updated);

        f.log.clear();
        let outcome = run(&mut f, &token(OLD)).await;
        assert_eq!(outcome.result, RollbackResult::RolledBack);
        assert_eq!(
            mutating(&f.log),
            [
                format!("aws-secrets-manager.restore({SM})"),
                "npm.revoke_replacement(npm-ref-1)".to_owned(),
            ],
            "nothing that succeeded is repeated"
        );
    }

    #[tokio::test]
    async fn restore_error_touches_no_consumer() {
        let provider = MockProvider::new("npm");
        provider.fail_next("restore", ProviderError::Permanent("403".into()));
        let mut f = fixture(provider, &revoked());
        let outcome = run(&mut f, &token(OLD)).await;
        assert!(matches!(
            outcome.result,
            RollbackResult::Failed {
                action: RollbackAction::RestoreOld,
                ..
            }
        ));
        assert_eq!(mutating(&f.log), ["npm.restore(npm-old-handle)"]);
    }

    #[tokio::test]
    async fn manual_or_unsupported_replacement_is_a_warning() {
        let mut r = revoked();
        r.replacement_ref = Some(MANUAL_REF.into());
        let mut f = fixture(MockProvider::new("npm"), &r);
        let outcome = run(&mut f, &token(OLD)).await;
        assert_eq!(outcome.result, RollbackResult::RolledBack);
        assert!(outcome.warnings[0].contains("revoke the pasted replacement by hand"));
        assert!(!mutating(&f.log).iter().any(|c| c.contains("revoke")));

        let provider = MockProvider::new("npm");
        provider.fail_next(
            "revoke_replacement",
            ProviderError::Unsupported("no API".into()),
        );
        let mut f = fixture(provider, &revoked());
        let outcome = run(&mut f, &token(OLD)).await;
        assert_eq!(outcome.result, RollbackResult::RolledBack);
        assert!(outcome.warnings[0].contains("revoke the replacement npm-ref-1 by hand"));
    }

    #[tokio::test]
    async fn wrong_input_or_missing_holds_fails_safely() {
        let mut f = fixture(MockProvider::new("npm"), &revoked());
        let outcome = run(&mut f, &token("npm_not-the-one")).await;
        assert!(matches!(outcome.result, RollbackResult::Failed { .. }));
        f.log.assert_no_mutations();

        let mut r = revoked();
        r.consumers[0].holds = None;
        let mut f = fixture(MockProvider::new("npm"), &r);
        let outcome = run(&mut f, &token(OLD)).await;
        let RollbackResult::Failed { error, .. } = &outcome.result else {
            panic!("{outcome:?}");
        };
        assert!(error.as_str().contains("restore it by hand"), "{error}");
        assert!(!mutating(&f.log).iter().any(|c| c.contains("revoke_")));
    }

    #[tokio::test]
    async fn default_provider_cannot_revoke_by_ref() {
        struct Bare;
        #[async_trait::async_trait]
        impl crate::provider::Provider for Bare {
            fn name(&self) -> &'static str {
                "bare"
            }
            fn replacement_mode(&self) -> crate::provider::ReplacementMode {
                crate::provider::ReplacementMode::Automatic
            }
            fn identify(&self, _: &Finding) -> Option<crate::provider::Confidence> {
                None
            }
            async fn check_valid(
                &self,
                _: &Credential,
            ) -> Result<crate::provider::Validity, ProviderError> {
                unreachable!()
            }
            async fn describe_scope(
                &self,
                _: &Credential,
            ) -> Result<crate::provider::Scope, ProviderError> {
                unreachable!()
            }
            async fn create_replacement(
                &self,
                _: &Credential,
            ) -> Result<crate::provider::Replacement, ProviderError> {
                unreachable!()
            }
            async fn verify(
                &self,
                _: &Credential,
                _: &crate::provider::Identity,
            ) -> Result<(), ProviderError> {
                unreachable!()
            }
            async fn revoke(
                &self,
                _: &Credential,
            ) -> Result<crate::provider::Revoked, ProviderError> {
                unreachable!()
            }
            async fn restore(&self, _: &str) -> Result<RestoreOutcome, ProviderError> {
                unreachable!()
            }
        }
        use crate::provider::Provider as _;
        assert!(matches!(
            Bare.revoke_replacement("ref").await,
            Err(ProviderError::Unsupported(_))
        ));
    }
}
