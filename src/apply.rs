//! `rotate apply` (SHA-254): typed confirmation and the executor that turns
//! a confirmed [`PlannedRotation`] into changes (FR14, FR15, FR17).
//!
//! The executor runs the steps in a fixed order: `create_replacement`, then
//! `update` on every consumer, then `verify` on the replacement, then the
//! revoke gate, and only then `revoke`. After every step the rotation is
//! saved to the state file and an entry is appended to the audit log.
//!
//! Revoke is always the last step. Any error before it marks the rotation
//! `failed` and returns without calling `revoke`; the old secret stays
//! valid. [`revoke_gate`] holds the revoke while a consumer is not known to
//! hold the replacement, unless the operator passed `--force` (NFR5), and
//! defers it while the overlap window is open (decision D2). `--force` never
//! bypasses a failed create or verify; when it lets a revoke through, it is
//! recorded in the state file and the audit log before the revoke (SHA-256).
//!
//! The replacement credential is a local of [`Executor::run`]: it is held in
//! zeroized memory, registered with the redactor while alive, and dropped
//! when the rotation ends. Nothing returned from here holds a value.
//!
//! Nothing here prints. The binary prints the plan, asks the questions
//! through a [`Prompt`], and renders the [`Outcome`]s with
//! [`render_summary`].

#![cfg(unix)]

use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::audit::RedactedText;
use crate::audit::{AuditError, AuditEvent, AuditLog, AuditStep, Outcome as AuditOutcome};
use crate::consumer::ConsumerRegistry;
use crate::plan::{Plan, PlannedRotation};
use crate::provider::{Provider, ProviderRegistry, ReplacementMode};
use crate::secret::Fingerprint;
use crate::state::{ConsumerState, ConsumerStatus, Rotation, StateError, StateStore, Step};

/// What the operator typed to confirm every rotation with `--all`.
pub const CONFIRM_ALL: &str = "all";

/// Reads one line of confirmation from the operator.
pub trait Prompt {
    /// Reads one answer. The question has already been printed.
    fn read_line(&mut self) -> Result<String, PromptError>;
}

/// Why no answer could be read.
#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    /// There is no terminal to read from.
    #[error("no terminal to confirm on; pass --confirm <rotation-id>")]
    NoTerminal,
    /// Reading the terminal failed.
    #[error("could not read the confirmation from the terminal ({0})")]
    Io(io::ErrorKind),
}

/// Reads answers from `/dev/tty`, never stdin, so a secret piped to
/// `--stdin` and the confirmation do not share a stream.
#[derive(Debug, Default)]
pub struct TtyPrompt {
    tty: Option<BufReader<File>>,
}

impl TtyPrompt {
    /// A prompt that opens the terminal on first use.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Prompt for TtyPrompt {
    fn read_line(&mut self) -> Result<String, PromptError> {
        if self.tty.is_none() {
            let file = File::open("/dev/tty").map_err(|_| PromptError::NoTerminal)?;
            self.tty = Some(BufReader::new(file));
        }
        let Some(tty) = self.tty.as_mut() else {
            return Err(PromptError::NoTerminal);
        };
        let mut line = String::new();
        tty.read_line(&mut line)
            .map_err(|err| PromptError::Io(err.kind()))?;
        Ok(line)
    }
}

/// Answers given in advance, for tests. Running out reads as an empty line.
#[derive(Debug, Default)]
pub struct ScriptedPrompt {
    answers: VecDeque<String>,
    asked: usize,
}

impl ScriptedPrompt {
    /// A prompt that returns `answers` in order.
    pub fn new<I, S>(answers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            answers: answers.into_iter().map(Into::into).collect(),
            asked: 0,
        }
    }

    /// How many lines were read.
    pub fn asked(&self) -> usize {
        self.asked
    }
}

impl Prompt for ScriptedPrompt {
    fn read_line(&mut self) -> Result<String, PromptError> {
        self.asked += 1;
        Ok(self.answers.pop_front().unwrap_or_default())
    }
}

/// How the operator confirms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// `--confirm <id>`, repeatable: no prompt; only these rotations run.
    Ids(Vec<String>),
    /// One typed rotation id per rotation.
    Interactive,
    /// `--all`: one prompt listing every id, answered with [`CONFIRM_ALL`].
    All,
}

/// Why confirmation failed. Apply exits 2 and changes nothing.
#[derive(Debug, thiserror::Error)]
pub enum ConfirmError {
    /// The typed answer was not the rotation id.
    #[error("confirmation did not match rotation {expected}; nothing was changed")]
    Mismatch {
        /// The id that had to be typed.
        expected: String,
    },
    /// A `--confirm` id is not in the plan. The typed id is not repeated:
    /// it may be something pasted by mistake.
    #[error(
        "a --confirm id is not a rotation in this plan (rotations: {known}); nothing was changed"
    )]
    Unknown {
        /// The ids in the plan, comma separated, or `none`.
        known: String,
    },
    /// No answer could be read.
    #[error(transparent)]
    Prompt(#[from] PromptError),
}

/// Asks for confirmation and returns the confirmed rotation ids, in plan
/// order. `all_ids` are every rotation in the plan; `askable` are those
/// apply can run, the only ones a prompt asks about. Questions go to `out`.
/// Every answer is collected before anything changes.
pub fn confirm(
    all_ids: &[&str],
    askable: &[&str],
    request: &Confirmation,
    prompt: &mut dyn Prompt,
    out: &mut dyn Write,
) -> Result<Vec<String>, ConfirmError> {
    match request {
        Confirmation::Ids(ids) => {
            if let Some(_unknown) = ids.iter().find(|id| !all_ids.contains(&id.as_str())) {
                let known = if all_ids.is_empty() {
                    "none".to_owned()
                } else {
                    all_ids.join(", ")
                };
                return Err(ConfirmError::Unknown { known });
            }
            Ok(all_ids
                .iter()
                .filter(|id| ids.iter().any(|c| c == *id))
                .map(|id| (*id).to_owned())
                .collect())
        }
        Confirmation::Interactive => {
            for id in askable {
                // A closed stderr must not stop the prompt.
                let _ = write!(out, "Type the rotation id {id} to continue: ");
                let _ = out.flush();
                let answer = prompt.read_line()?;
                if answer.trim() != *id {
                    return Err(ConfirmError::Mismatch {
                        expected: (*id).to_owned(),
                    });
                }
            }
            Ok(askable.iter().map(|id| (*id).to_owned()).collect())
        }
        Confirmation::All => {
            if askable.is_empty() {
                return Ok(Vec::new());
            }
            let _ = writeln!(out, "Rotations to apply: {}", askable.join(", "));
            let _ = write!(
                out,
                "Type {CONFIRM_ALL} to rotate these {} secrets: ",
                askable.len()
            );
            let _ = out.flush();
            let answer = prompt.read_line()?;
            if answer.trim() != CONFIRM_ALL {
                return Err(ConfirmError::Mismatch {
                    expected: CONFIRM_ALL.to_owned(),
                });
            }
            Ok(askable.iter().map(|id| (*id).to_owned()).collect())
        }
    }
}

/// Why apply cannot run a rotation yet. Nothing is called for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible {
    /// The provider needs the operator to paste the replacement (SHA-257).
    Manual,
    /// An earlier apply left it at this step; resuming is SHA-258. A
    /// rotation at `verified` is not ineligible: it goes straight to the
    /// revoke gate (SHA-256).
    InProgress(Step),
    /// The owner identity is unknown, so the replacement cannot be verified.
    NoScope,
}

impl fmt::Display for Ineligible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ineligible::Manual => f.write_str("manual replacement is not supported yet"),
            Ineligible::InProgress(step) => write!(
                f,
                "already at step {}; resuming is not supported yet",
                step_name(*step)
            ),
            Ineligible::NoScope => f.write_str(
                "the owner identity is unknown, so the replacement could not be verified",
            ),
        }
    }
}

/// Whether apply can run `rotation` now.
pub fn eligibility(rotation: &PlannedRotation) -> Result<(), Ineligible> {
    if rotation.replacement_mode == ReplacementMode::Manual {
        return Err(Ineligible::Manual);
    }
    if !matches!(rotation.step, Step::Planned | Step::Verified) {
        return Err(Ineligible::InProgress(rotation.step));
    }
    if rotation.scope.is_none() {
        return Err(Ineligible::NoScope);
    }
    Ok(())
}

/// What the revoke gate decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// Revoke now.
    Revoke,
    /// Do not revoke: a consumer is not known to hold the replacement.
    Hold(String),
    /// Revoke later, once the overlap window has passed.
    Wait(OffsetDateTime),
}

/// The consumers that do not hold the replacement: the ref of every
/// consumer not `updated` (skipped as not updatable, or whose update
/// failed), then `<name> (not searched)` for every consumer whose `find`
/// failed. These block the revoke unless `--force` is given (NFR5).
pub fn not_updated(rotation: &PlannedRotation, consumers: &[ConsumerState]) -> Vec<String> {
    consumers
        .iter()
        .filter(|c| c.status != ConsumerStatus::Updated)
        .map(|c| c.consumer_ref.clone())
        .chain(
            rotation
                .lookup_errors
                .iter()
                .map(|e| format!("{} (not searched)", e.consumer)),
        )
        .collect()
}

/// The single decision before `revoke`. Holds while any consumer was not
/// updated or could not be searched, unless `force`; waits while the
/// overlap window is open (decision D2). Resume with `--wait` (SHA-258)
/// changes this function only.
pub fn revoke_gate(
    rotation: &PlannedRotation,
    consumers: &[ConsumerState],
    verified_at: OffsetDateTime,
    force: bool,
) -> Gate {
    let blocked = not_updated(rotation, consumers);
    if !blocked.is_empty() && !force {
        let noun = if blocked.len() == 1 {
            "consumer"
        } else {
            "consumers"
        };
        return Gate::Hold(format!(
            "{} {noun} not updated ({}); re-run with --force to revoke anyway; the old secret is still valid",
            blocked.len(),
            blocked.join(", ")
        ));
    }
    let window = rotation.overlap_window.as_duration();
    if window.is_zero() {
        Gate::Revoke
    } else {
        Gate::Wait(verified_at + window)
    }
}

/// How one rotation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunResult {
    /// The old secret is revoked.
    Revoked,
    /// Verified; the revoke waits for the overlap window.
    PendingRevoke {
        /// Earliest revoke time.
        not_before: OffsetDateTime,
    },
    /// Verified, but the revoke was held by [`revoke_gate`].
    Held {
        /// Why.
        reason: String,
    },
    /// A step failed. Revoke was not called unless `step` is revoke.
    Failed {
        /// The step that failed.
        step: AuditStep,
        /// Why, redacted.
        error: RedactedText,
    },
    /// Not attempted.
    Skipped(Ineligible),
}

/// One rotation's outcome, for the summary. Holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Rotation id.
    pub rotation_id: String,
    /// Provider name.
    pub provider: &'static str,
    /// Fingerprint of the old secret.
    pub fingerprint: Fingerprint,
    /// Fingerprint of the replacement, once created.
    pub replacement_fingerprint: Option<Fingerprint>,
    /// Consumers touched.
    pub consumers: Vec<ConsumerState>,
    /// Refs of planned consumers never touched: they still hold the old
    /// secret.
    pub unchanged: Vec<String>,
    /// Consumers `--force` revoked past (see [`not_updated`]); empty unless
    /// the force was used and recorded.
    pub forced: Vec<String>,
    /// How it ended.
    pub result: RunResult,
}

impl Outcome {
    /// A rotation that was not attempted.
    pub fn skipped(rotation: &PlannedRotation, why: Ineligible) -> Self {
        Self {
            rotation_id: rotation.rotation_id.clone(),
            provider: rotation.provider,
            fingerprint: rotation.fingerprint.clone(),
            replacement_fingerprint: None,
            consumers: Vec::new(),
            unchanged: Vec::new(),
            forced: Vec::new(),
            result: RunResult::Skipped(why),
        }
    }
}

/// The exit class of a run, worst first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    /// Every rotation was revoked.
    Done,
    /// Some rotation failed or was held before revoke (exit 1).
    Failed,
    /// Some revoke waits for its overlap window (exit 3).
    Pending,
    /// Some rotation needs a feature not built yet (exit 2).
    Unsupported,
}

/// Exit class for `outcomes`: failed, then pending, then unsupported.
pub fn run_status(outcomes: &[Outcome]) -> RunStatus {
    let any = |f: fn(&RunResult) -> bool| outcomes.iter().any(|o| f(&o.result));
    if any(|r| matches!(r, RunResult::Failed { .. } | RunResult::Held { .. })) {
        RunStatus::Failed
    } else if any(|r| matches!(r, RunResult::PendingRevoke { .. })) {
        RunStatus::Pending
    } else if any(|r| matches!(r, RunResult::Skipped(_))) {
        RunStatus::Unsupported
    } else {
        RunStatus::Done
    }
}

/// A state or audit write failed mid-rotation.
#[derive(Debug, thiserror::Error)]
enum RecordError {
    #[error("could not save the state file: {0}")]
    State(#[from] StateError),
    #[error("could not append to the audit log: {0}")]
    Audit(#[from] AuditError),
}

/// Runs confirmed rotations against the providers and consumers, recording
/// every step in the state file and the audit log.
pub struct Executor<'a> {
    providers: &'a ProviderRegistry,
    consumers: &'a ConsumerRegistry,
    store: &'a mut StateStore,
    audit: &'a mut AuditLog,
    clock: fn() -> OffsetDateTime,
    force: bool,
}

impl fmt::Debug for Executor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("providers", &self.providers)
            .field("consumers", &self.consumers)
            .field("force", &self.force)
            .finish_non_exhaustive()
    }
}

/// Progress of one rotation inside [`Executor::run`].
struct Progress {
    record: Rotation,
    provider: &'static str,
    forced: Vec<String>,
}

impl<'a> Executor<'a> {
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
            clock: OffsetDateTime::now_utc,
            force: false,
        }
    }

    /// `--force`: revoke even when some consumers were not updated
    /// (NFR5). Never bypasses a failed create or verify.
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Uses `clock` for the overlap window instead of the system clock.
    pub fn with_clock(mut self, clock: fn() -> OffsetDateTime) -> Self {
        self.clock = clock;
        self
    }

    /// Runs one confirmed rotation: create, update every consumer, verify,
    /// revoke gate, revoke. Never calls `revoke` after an earlier failure.
    /// A rotation already at `verified` (held by the gate on an earlier
    /// run) goes straight to the gate with the consumers in the state file.
    /// The caller checks [`eligibility`] first; an ineligible rotation is
    /// returned as skipped without a call.
    pub async fn run(&mut self, rotation: &PlannedRotation) -> Outcome {
        if let Err(why) = eligibility(rotation) {
            return Outcome::skipped(rotation, why);
        }
        let mut progress = Progress {
            record: self
                .store
                .get(&rotation.rotation_id)
                .cloned()
                .unwrap_or_else(|| {
                    Rotation::new(
                        rotation.rotation_id.clone(),
                        rotation.provider,
                        rotation.fingerprint.clone(),
                    )
                }),
            provider: rotation.provider,
            forced: Vec::new(),
        };
        let result = self.steps(rotation, &mut progress).await;
        let unchanged = rotation
            .consumers
            .iter()
            .map(|c| &c.found.consumer_ref)
            .filter(|r| {
                !progress
                    .record
                    .consumers
                    .iter()
                    .any(|c| &c.consumer_ref == *r)
            })
            .cloned()
            .collect();
        Outcome {
            rotation_id: rotation.rotation_id.clone(),
            provider: rotation.provider,
            fingerprint: rotation.fingerprint.clone(),
            replacement_fingerprint: progress.record.replacement_fingerprint.clone(),
            consumers: progress.record.consumers.clone(),
            unchanged,
            forced: progress.forced,
            result,
        }
    }

    async fn steps(&mut self, rotation: &PlannedRotation, progress: &mut Progress) -> RunResult {
        if let Err(err) = self.event(progress, AuditStep::Plan, AuditOutcome::Ok, None, None) {
            return self.fail(progress, AuditStep::Plan, &err.to_string(), None);
        }
        let Some(provider) = self.providers.get(rotation.provider) else {
            return self.fail(
                progress,
                AuditStep::Create,
                "the provider is not registered",
                None,
            );
        };
        if progress.record.step == Step::Verified {
            // Held at the gate by an earlier run: nothing is created or
            // updated again (SHA-256; other resumes are SHA-258).
            return self.finish(rotation, provider.as_ref(), progress).await;
        }

        // Create. The replacement lives in this frame only.
        let replacement = match provider.create_replacement(&rotation.credential).await {
            Ok(replacement) => replacement,
            Err(err) => return self.fail(progress, AuditStep::Create, &err.to_string(), None),
        };
        progress.record.step = Step::Created;
        progress.record.replacement_ref = Some(replacement.replacement_ref.clone());
        progress.record.replacement_fingerprint = Some(replacement.credential.fingerprint());
        if let Err(err) = self.checkpoint(progress, AuditStep::Create, None) {
            return self.fail(progress, AuditStep::Create, &err.to_string(), None);
        }

        // Update every consumer, saving after each.
        for planned in &rotation.consumers {
            let reference = planned.found.consumer_ref.clone();
            let state = |status| ConsumerState {
                consumer: planned.consumer.to_owned(),
                consumer_ref: reference.clone(),
                status,
            };
            if let Err(blocked) = &planned.found.updatable {
                progress
                    .record
                    .consumers
                    .push(state(ConsumerStatus::Skipped));
                let saved = self.save(progress).and_then(|()| {
                    self.event(
                        progress,
                        AuditStep::Update,
                        AuditOutcome::Skipped,
                        Some(&reference),
                        Some(&blocked.reason),
                    )
                });
                if let Err(err) = saved {
                    return self.fail(progress, AuditStep::Update, &err.to_string(), None);
                }
                continue;
            }
            let Some(consumer) = self.consumers.get(planned.consumer) else {
                progress
                    .record
                    .consumers
                    .push(state(ConsumerStatus::Failed));
                return self.fail(
                    progress,
                    AuditStep::Update,
                    &format!("{reference}: the consumer is not registered"),
                    Some(&reference),
                );
            };
            match consumer
                .update(&planned.found, &replacement.credential)
                .await
            {
                Ok(_receipt) => {
                    progress
                        .record
                        .consumers
                        .push(state(ConsumerStatus::Updated));
                    if let Err(err) = self.checkpoint(progress, AuditStep::Update, Some(&reference))
                    {
                        return self.fail(progress, AuditStep::Update, &err.to_string(), None);
                    }
                }
                Err(err) => {
                    progress
                        .record
                        .consumers
                        .push(state(ConsumerStatus::Failed));
                    let error = format!("{reference}: {err}");
                    if !self.force {
                        return self.fail(progress, AuditStep::Update, &error, Some(&reference));
                    }
                    // --force: record it and keep updating the others. The
                    // gate lists it among the consumers revoked past.
                    let recorded = self.save(progress).and_then(|()| {
                        self.event(
                            progress,
                            AuditStep::Update,
                            AuditOutcome::Failed,
                            Some(&reference),
                            Some(&error),
                        )
                    });
                    if let Err(err) = recorded {
                        return self.fail(progress, AuditStep::Update, &err.to_string(), None);
                    }
                }
            }
        }
        progress.record.step = Step::ConsumersUpdated;
        if let Err(err) = self.save(progress) {
            return self.fail(progress, AuditStep::Update, &err.to_string(), None);
        }

        // Verify the replacement belongs to the same owner (assumption A5).
        let Some(scope) = &rotation.scope else {
            return self.fail(
                progress,
                AuditStep::Verify,
                &Ineligible::NoScope.to_string(),
                None,
            );
        };
        if let Err(err) = provider
            .verify(&replacement.credential, &scope.identity)
            .await
        {
            return self.fail(progress, AuditStep::Verify, &err.to_string(), None);
        }
        progress.record.step = Step::Verified;
        if let Err(err) = self.checkpoint(progress, AuditStep::Verify, None) {
            return self.fail(progress, AuditStep::Verify, &err.to_string(), None);
        }
        drop(replacement);
        self.finish(rotation, provider.as_ref(), progress).await
    }

    /// The revoke gate, the force record, then revoke: always the last
    /// step. Runs only once the replacement is verified.
    async fn finish(
        &mut self,
        rotation: &PlannedRotation,
        provider: &dyn Provider,
        progress: &mut Progress,
    ) -> RunResult {
        let gate = revoke_gate(
            rotation,
            &progress.record.consumers,
            (self.clock)(),
            self.force,
        );
        if !matches!(gate, Gate::Hold(_)) && self.force {
            // NFR5: the force is on record before anything is revoked.
            if let Err(err) = self.record_force(rotation, progress) {
                return self.fail(progress, AuditStep::Force, &err.to_string(), None);
            }
        }
        match gate {
            Gate::Revoke => {}
            Gate::Hold(reason) => {
                if let Err(err) = self.event(
                    progress,
                    AuditStep::Revoke,
                    AuditOutcome::Skipped,
                    None,
                    Some(&reason),
                ) {
                    tracing::warn!(rotation_id = %progress.record.rotation_id, "{err}");
                }
                return RunResult::Held { reason };
            }
            Gate::Wait(not_before) => {
                progress.record.step = Step::PendingRevoke;
                progress.record.revoke_not_before = Some(not_before);
                if let Err(err) = self.save(progress) {
                    return self.fail(progress, AuditStep::Revoke, &err.to_string(), None);
                }
                return RunResult::PendingRevoke { not_before };
            }
        }
        if let Err(err) = provider.revoke(&rotation.credential).await {
            return self.fail(
                progress,
                AuditStep::Revoke,
                &format!("{err}; the replacement is live and the old secret may still be valid"),
                None,
            );
        }
        progress.record.step = Step::Revoked;
        if let Err(err) = self.checkpoint(progress, AuditStep::Revoke, None) {
            // The revoke happened; only the record is missing.
            return RunResult::Failed {
                step: AuditStep::Revoke,
                error: RedactedText::new(&format!("the old secret was revoked but {err}")),
            };
        }
        RunResult::Revoked
    }

    /// Records `--force` when it lets the revoke through past consumers
    /// that do not hold the replacement: `force: true` in the state file,
    /// then one `force` audit entry per such consumer (the log stamps the
    /// actor). Nothing is recorded when nothing was bypassed.
    fn record_force(
        &mut self,
        rotation: &PlannedRotation,
        progress: &mut Progress,
    ) -> Result<(), RecordError> {
        let bypassed = not_updated(rotation, &progress.record.consumers);
        if bypassed.is_empty() {
            return Ok(());
        }
        progress.record.force = true;
        self.save(progress)?;
        for consumer in &bypassed {
            self.event(
                progress,
                AuditStep::Force,
                AuditOutcome::Ok,
                Some(consumer),
                None,
            )?;
        }
        progress.forced = bypassed;
        Ok(())
    }

    /// Saves the record, then appends an ok entry for `step`.
    fn checkpoint(
        &mut self,
        progress: &Progress,
        step: AuditStep,
        consumer: Option<&str>,
    ) -> Result<(), RecordError> {
        self.save(progress)?;
        self.event(progress, step, AuditOutcome::Ok, consumer, None)
    }

    fn save(&mut self, progress: &Progress) -> Result<(), RecordError> {
        self.store.upsert(progress.record.clone())?;
        Ok(())
    }

    fn event(
        &mut self,
        progress: &Progress,
        step: AuditStep,
        outcome: AuditOutcome,
        consumer: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), RecordError> {
        let record = &progress.record;
        let mut event = AuditEvent::new(
            record.rotation_id.clone(),
            progress.provider,
            record.fingerprint.clone(),
            step,
            outcome,
        );
        if let Some(fp) = &record.replacement_fingerprint {
            event = event.with_replacement(fp.clone());
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

    /// Marks the rotation failed in state and audit, best effort: a second
    /// recording error is logged, and the first error is what is returned.
    /// Revoke is never called after this.
    fn fail(
        &mut self,
        progress: &mut Progress,
        step: AuditStep,
        error: &str,
        consumer: Option<&str>,
    ) -> RunResult {
        progress.record.step = Step::Failed;
        progress.record.failed_step = Some(step);
        let recorded = self
            .save(progress)
            .and_then(|()| self.event(progress, step, AuditOutcome::Failed, consumer, Some(error)));
        if let Err(err) = recorded {
            tracing::warn!(
                rotation_id = %progress.record.rotation_id,
                "could not record the failure: {err}"
            );
        }
        RunResult::Failed {
            step,
            error: RedactedText::new(error),
        }
    }
}

/// Every rotation id in `plan`, in order.
pub fn rotation_ids(plan: &Plan) -> Vec<&str> {
    plan.rotations
        .iter()
        .map(|r| r.rotation_id.as_str())
        .collect()
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
        Step::RolledBack => "rolled_back",
    }
}

fn audit_step_name(step: AuditStep) -> &'static str {
    match step {
        AuditStep::Identify => "identify",
        AuditStep::Check => "check",
        AuditStep::Plan => "plan",
        AuditStep::Create => "create",
        AuditStep::Update => "update",
        AuditStep::Verify => "verify",
        AuditStep::Revoke => "revoke",
        AuditStep::Rollback => "rollback",
        AuditStep::Force => "force",
    }
}

/// `<ref> updated, <ref> failed, <ref> unchanged`: where every consumer of a
/// rotation that stopped before revoke stands. `none` when it has none.
fn consumer_statuses(o: &Outcome) -> String {
    let parts: Vec<String> = o
        .consumers
        .iter()
        .map(|c| {
            let status = match c.status {
                ConsumerStatus::Updated => "updated",
                ConsumerStatus::Failed => "failed",
                ConsumerStatus::Skipped => "skipped",
            };
            format!("{} {status}", c.consumer_ref)
        })
        .chain(o.unchanged.iter().map(|r| format!("{r} unchanged")))
        .collect();
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join(", ")
    }
}

/// The summary printed after apply: one line per rotation with its outcome,
/// then a line per failure or hold explaining it.
pub fn render_summary(outcomes: &[Outcome]) -> String {
    let count = |f: fn(&RunResult) -> bool| outcomes.iter().filter(|o| f(&o.result)).count();
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Apply: {} revoked, {} pending revoke, {} held, {} failed, {} skipped.",
        count(|r| matches!(r, RunResult::Revoked)),
        count(|r| matches!(r, RunResult::PendingRevoke { .. })),
        count(|r| matches!(r, RunResult::Held { .. })),
        count(|r| matches!(r, RunResult::Failed { .. })),
        count(|r| matches!(r, RunResult::Skipped(_))),
    );
    if outcomes.is_empty() {
        return out;
    }
    out.push('\n');
    let mut rows = vec![[
        "ROTATION".to_owned(),
        "PROVIDER".to_owned(),
        "FINGERPRINT".to_owned(),
        "REPLACEMENT".to_owned(),
        "CONSUMERS".to_owned(),
        "OUTCOME".to_owned(),
    ]];
    let mut notes = Vec::new();
    for o in outcomes {
        let updated = o
            .consumers
            .iter()
            .filter(|c| c.status == ConsumerStatus::Updated)
            .count();
        if !o.forced.is_empty() {
            notes.push(format!(
                "{}: --force used; not updated: {}",
                o.rotation_id,
                o.forced.join(", ")
            ));
        }
        let outcome = match &o.result {
            RunResult::Revoked if !o.forced.is_empty() => "revoked (forced)".to_owned(),
            RunResult::Revoked => "revoked".to_owned(),
            RunResult::PendingRevoke { not_before } => {
                let when = not_before
                    .format(&Rfc3339)
                    .unwrap_or_else(|_| not_before.to_string());
                notes.push(format!(
                    "{}: revoke pending until {when}; the old secret stays valid until then",
                    o.rotation_id
                ));
                "pending revoke".to_owned()
            }
            RunResult::Held { reason } => {
                notes.push(format!("{}: {reason}", o.rotation_id));
                "held before revoke".to_owned()
            }
            RunResult::Failed { step, error } => {
                let tail = if *step == AuditStep::Revoke {
                    String::new()
                } else {
                    format!(
                        "; stopped before revoke; old secret still valid; consumers: {}",
                        consumer_statuses(o)
                    )
                };
                notes.push(format!(
                    "{}: {} failed: {error}{tail}",
                    o.rotation_id,
                    audit_step_name(*step)
                ));
                format!("failed at {}", audit_step_name(*step))
            }
            RunResult::Skipped(why) => {
                notes.push(format!("{}: skipped: {why}", o.rotation_id));
                "skipped".to_owned()
            }
        };
        rows.push([
            o.rotation_id.clone(),
            o.provider.to_owned(),
            o.fingerprint.to_string(),
            o.replacement_fingerprint
                .as_ref()
                .map_or_else(|| "-".to_owned(), ToString::to_string),
            format!("{updated}/{} updated", o.consumers.len()),
            outcome,
        ]);
    }
    let mut widths = [0usize; 6];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    for row in &rows {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(widths) {
            let _ = write!(line, "{cell:<width$}  ");
        }
        out.push_str(line.trim_end());
        out.push('\n');
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
    use crate::assess::{assess, AssessOptions};
    use crate::calls::CallLog;
    use crate::config::ConsumersConfig;
    use crate::consumer::mock::MockConsumer;
    use crate::consumer::{ConsumerError, ConsumerMatch};
    use crate::finding::{Finding, SourceLocation};
    use crate::provider::mock::MockProvider;
    use crate::provider::ProviderError;
    use crate::secret::SecretValue;

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
        provider: Arc<MockProvider>,
    }

    fn fp(value: &str) -> Fingerprint {
        SecretValue::from(value).fingerprint()
    }

    fn fixture(value: &str, provider: MockProvider) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let log = CallLog::new();
        let provider = Arc::new(provider.identify_prefix("npm_").log(log.clone()));
        let mut providers = ProviderRegistry::new();
        providers.register(provider.clone());
        let gha = Arc::new(
            MockConsumer::new("github-actions")
                .matching(fp(value), ConsumerMatch::by_name("gha:org/repo:NPM_TOKEN"))
                .log(log.clone()),
        );
        let sm = Arc::new(
            MockConsumer::new("aws-secrets-manager")
                .matching(fp(value), ConsumerMatch::by_value("sm:prod/npm"))
                .log(log.clone()),
        );
        let mut consumers = ConsumerRegistry::new();
        consumers.register(gha.clone());
        consumers.register(sm.clone());
        let store = StateStore::open(dir.path().join("state.json")).unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open_as(&audit_path, "tester@host").unwrap();
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
            provider,
        }
    }

    async fn plan(f: &mut Fixture, value: &str, overlap: &str) -> Plan {
        let finding = Finding::new(SecretValue::from(value), "Mock", SourceLocation::file("a"));
        let assessed = assess(vec![finding], &f.providers, &AssessOptions::default()).await;
        let mut plan = crate::plan::build(
            assessed,
            &f.providers,
            &f.consumers,
            overlap.parse().unwrap(),
            &ConsumersConfig::default(),
        )
        .await;
        crate::plan::assign_ids(&mut plan, &mut f.store).unwrap();
        f.log.clear();
        plan
    }

    async fn run(f: &mut Fixture, plan: &Plan) -> Outcome {
        let mut executor = Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit);
        executor.run(&plan.rotations[0]).await
    }

    fn mutating(log: &CallLog) -> Vec<String> {
        log.calls()
            .into_iter()
            .filter(|c| c.mutating || c.method == "verify")
            .map(|c| format!("{}.{}", c.target, c.method))
            .collect()
    }

    // T2 (AC2), T6 (AC6), T7 (AC7)
    #[tokio::test]
    async fn executor_runs_create_update_verify_revoke() {
        let value = "npm_apply_unit_happy";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "0s").await;
        let outcome = run(&mut f, &plan).await;

        assert_eq!(outcome.result, RunResult::Revoked);
        assert_eq!(
            mutating(&f.log),
            [
                "npm.create_replacement",
                "github-actions.update",
                "aws-secrets-manager.update",
                "npm.verify",
                "npm.revoke",
            ]
        );
        let new = outcome.replacement_fingerprint.clone().unwrap();
        assert_ne!(new, fp(value));
        assert_eq!(f.gha.current("gha:org/repo:NPM_TOKEN"), Some(new.clone()));
        assert_eq!(f.sm.current("sm:prod/npm"), Some(new.clone()));
        assert!(f.provider.is_revoked(&fp(value)));

        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::Revoked);
        assert_eq!(stored.replacement_ref.as_deref(), Some("npm-ref-1"));
        assert_eq!(stored.replacement_fingerprint, Some(new));
        assert!(stored
            .consumers
            .iter()
            .all(|c| c.status == ConsumerStatus::Updated));
        assert_eq!(stored.consumers.len(), 2);

        let steps: Vec<AuditStep> = crate::audit::read_all(&f.audit_path)
            .unwrap()
            .map(|e| e.unwrap().step)
            .collect();
        assert_eq!(
            steps,
            [
                AuditStep::Plan,
                AuditStep::Create,
                AuditStep::Update,
                AuditStep::Update,
                AuditStep::Verify,
                AuditStep::Revoke
            ]
        );
        assert!(render_summary(&[outcome]).contains("revoked"));
    }

    // Revoke is skipped on any earlier failure (CLAUDE.md safety rule).
    #[tokio::test]
    async fn any_failure_before_revoke_never_revokes() {
        for method in ["create_replacement", "update", "verify"] {
            let value = format!("npm_apply_unit_fail_{method}");
            let mut f = fixture(&value, MockProvider::new("npm"));
            let plan = plan(&mut f, &value, "0s").await;
            if method == "update" {
                f.sm.fail_always("update", ConsumerError::Permanent("403 denied".into()));
            } else {
                f.provider
                    .fail_always(method, ProviderError::Permanent("denied".into()));
            }
            let outcome = run(&mut f, &plan).await;
            assert!(
                matches!(outcome.result, RunResult::Failed { .. }),
                "{method}: {outcome:?}"
            );
            assert!(
                f.log.calls().iter().all(|c| c.method != "revoke"),
                "{method}: revoke called"
            );
            assert!(!f.provider.is_revoked(&fp(&value)));
            let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
            assert_eq!(stored.step, Step::Failed, "{method}");
            assert_eq!(run_status(&[outcome]), RunStatus::Failed);
        }
    }

    #[tokio::test]
    async fn not_updatable_consumer_holds_revoke() {
        let value = "npm_apply_unit_hold";
        let mut f = fixture(value, MockProvider::new("npm"));
        let blocked = Arc::new(
            MockConsumer::new("blocked")
                .matching(
                    fp(value),
                    ConsumerMatch::by_name("gha:org:NPM_TOKEN").not_updatable("needs admin"),
                )
                .log(f.log.clone()),
        );
        f.consumers.register(blocked);
        let plan = plan(&mut f, value, "0s").await;
        let outcome = run(&mut f, &plan).await;
        assert!(
            matches!(outcome.result, RunResult::Held { .. }),
            "{outcome:?}"
        );
        assert!(f.log.calls().iter().all(|c| c.method != "revoke"));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::Verified);
        assert_eq!(stored.consumers[2].status, ConsumerStatus::Skipped);
    }

    #[tokio::test]
    async fn overlap_window_records_pending_revoke() {
        let value = "npm_apply_unit_overlap";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "10m").await;
        let outcome = run(&mut f, &plan).await;
        let RunResult::PendingRevoke { not_before } = outcome.result else {
            panic!("{outcome:?}");
        };
        assert!(not_before > OffsetDateTime::now_utc() + time::Duration::minutes(9));
        assert!(f.log.calls().iter().all(|c| c.method != "revoke"));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::PendingRevoke);
        assert_eq!(stored.revoke_not_before, Some(not_before));
    }

    #[tokio::test]
    async fn manual_and_in_progress_are_ineligible() {
        let value = "npm_apply_unit_manual";
        let mut f = fixture(
            value,
            MockProvider::new("npm").mode(ReplacementMode::Manual),
        );
        let mut plan = plan(&mut f, value, "0s").await;
        assert_eq!(eligibility(&plan.rotations[0]), Err(Ineligible::Manual));
        let outcome = run(&mut f, &plan).await;
        assert_eq!(outcome.result, RunResult::Skipped(Ineligible::Manual));
        assert!(f.log.is_empty());

        plan.rotations[0].replacement_mode = ReplacementMode::Automatic;
        plan.rotations[0].step = Step::Created;
        assert_eq!(
            eligibility(&plan.rotations[0]),
            Err(Ineligible::InProgress(Step::Created))
        );
        plan.rotations[0].step = Step::Planned;
        plan.rotations[0].scope = None;
        assert_eq!(eligibility(&plan.rotations[0]), Err(Ineligible::NoScope));
        assert_eq!(run_status(&[outcome]), RunStatus::Unsupported);
    }

    // T1 (AC1), T3 (AC3), T4 (AC4)
    #[test]
    fn confirm_rules() {
        let ids = ["rot-aaaaaaaa", "rot-bbbbbbbb"];
        let mut out = Vec::new();

        let mut prompt = ScriptedPrompt::new(["rot-aaaaaaaa\n", "no\n"]);
        let err = confirm(
            &ids,
            &ids,
            &Confirmation::Interactive,
            &mut prompt,
            &mut out,
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfirmError::Mismatch { ref expected } if expected == "rot-bbbbbbbb")
        );
        assert!(err.to_string().contains("confirmation did not match"));

        let mut prompt = ScriptedPrompt::new([" rot-aaaaaaaa \n", "rot-bbbbbbbb\n"]);
        let ok = confirm(
            &ids,
            &ids,
            &Confirmation::Interactive,
            &mut prompt,
            &mut out,
        )
        .unwrap();
        assert_eq!(ok, ids);
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(text.contains("Type the rotation id rot-aaaaaaaa to continue: "));

        let mut prompt = ScriptedPrompt::new(Vec::<String>::new());
        let ok = confirm(
            &ids,
            &ids,
            &Confirmation::Ids(vec!["rot-bbbbbbbb".into()]),
            &mut prompt,
            &mut out,
        )
        .unwrap();
        assert_eq!(ok, ["rot-bbbbbbbb"]);
        assert_eq!(prompt.asked(), 0);

        let err = confirm(
            &ids,
            &ids,
            &Confirmation::Ids(vec!["WRONG-typed".into()]),
            &mut prompt,
            &mut out,
        )
        .unwrap_err();
        assert!(!err.to_string().contains("WRONG-typed"));
        assert_eq!(prompt.asked(), 0);

        let mut prompt = ScriptedPrompt::new(["all\n"]);
        let ok = confirm(&ids, &ids, &Confirmation::All, &mut prompt, &mut out).unwrap();
        assert_eq!(ok, ids);
        assert_eq!(prompt.asked(), 1);
        let mut prompt = ScriptedPrompt::new(["yes\n"]);
        assert!(confirm(&ids, &ids, &Confirmation::All, &mut prompt, &mut out).is_err());
    }

    #[test]
    fn gate_holds_waits_or_revokes() {
        let status = |s| ConsumerState {
            consumer: "c".into(),
            consumer_ref: "c:1".into(),
            status: s,
        };
        let rotation = PlannedRotation {
            rotation_id: "rot-1".into(),
            provider: "npm",
            fingerprint: fp("npm_gate"),
            credential: crate::provider::Credential::Token(SecretValue::from("npm_gate_value")),
            scope: None,
            scope_error: None,
            replacement_mode: ReplacementMode::Automatic,
            consumers: Vec::new(),
            lookup_errors: Vec::new(),
            revoke_action: "x",
            overlap_window: "0s".parse().unwrap(),
            blockers: Vec::new(),
            step: Step::Planned,
            sources: Vec::new(),
        };
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            revoke_gate(&rotation, &[status(ConsumerStatus::Updated)], now, false),
            Gate::Revoke
        );
        for blocked in [ConsumerStatus::Skipped, ConsumerStatus::Failed] {
            let Gate::Hold(reason) = revoke_gate(&rotation, &[status(blocked)], now, false) else {
                panic!("{blocked:?} did not hold");
            };
            assert!(
                reason.starts_with("1 consumer not updated (c:1); re-run with --force"),
                "{reason}"
            );
            assert_eq!(
                revoke_gate(&rotation, &[status(blocked)], now, true),
                Gate::Revoke
            );
        }
        let mut unsearched = rotation.clone();
        unsearched.lookup_errors.push(crate::plan::LookupError {
            consumer: "github-actions",
            error: "403".into(),
        });
        assert_eq!(
            not_updated(&unsearched, &[status(ConsumerStatus::Skipped)]),
            ["c:1", "github-actions (not searched)"]
        );
        assert!(matches!(
            revoke_gate(&unsearched, &[], now, false),
            Gate::Hold(ref r) if r.starts_with("1 consumer not updated (github-actions (not searched))")
        ));
        let mut waiting = rotation.clone();
        waiting.overlap_window = "1h".parse().unwrap();
        assert_eq!(
            revoke_gate(&waiting, &[], now, false),
            Gate::Wait(now + std::time::Duration::from_secs(3600))
        );
        assert_eq!(
            revoke_gate(&waiting, &[status(ConsumerStatus::Skipped)], now, true),
            Gate::Wait(now + std::time::Duration::from_secs(3600))
        );
    }

    async fn run_forced(f: &mut Fixture, plan: &Plan) -> Outcome {
        let mut executor =
            Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit).with_force(true);
        executor.run(&plan.rotations[0]).await
    }

    fn audit_steps(f: &Fixture) -> Vec<(AuditStep, AuditOutcome, Option<String>)> {
        crate::audit::read_all(&f.audit_path)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.step, e.outcome, e.consumer)
            })
            .collect()
    }

    fn add_blocked(f: &mut Fixture, value: &str) {
        let blocked = Arc::new(
            MockConsumer::new("blocked")
                .matching(
                    fp(value),
                    ConsumerMatch::by_name("gha:org:NPM_TOKEN").not_updatable("needs admin"),
                )
                .log(f.log.clone()),
        );
        f.consumers.register(blocked);
    }

    // T1 (AC1), T7 (AC7)
    #[tokio::test]
    async fn update_failure_without_force_stops_at_once() {
        let value = "npm_apply_unit_update_stop";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "0s").await;
        f.gha
            .fail_always("update", ConsumerError::Permanent("403 denied".into()));
        let outcome = run(&mut f, &plan).await;
        assert_eq!(
            mutating(&f.log),
            ["npm.create_replacement", "github-actions.update"]
        );
        assert_eq!(f.sm.current("sm:prod/npm"), Some(fp(value)));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::Failed);
        assert_eq!(stored.failed_step, Some(AuditStep::Update));
        assert!(!stored.force);
        assert_eq!(outcome.unchanged, ["sm:prod/npm"]);
        let summary = render_summary(std::slice::from_ref(&outcome));
        assert!(
            summary.contains(
                "update failed: gha:org/repo:NPM_TOKEN: 403 denied; stopped before revoke; \
                 old secret still valid; consumers: gha:org/repo:NPM_TOKEN failed, sm:prod/npm unchanged"
            ),
            "{summary}"
        );
        assert_eq!(run_status(&[outcome]), RunStatus::Failed);
    }

    // T2 (AC2), T7 (AC7): --force never bypasses a failed create or verify.
    #[tokio::test]
    async fn force_never_bypasses_create_or_verify() {
        for method in ["create_replacement", "verify"] {
            let value = format!("npm_apply_unit_force_{method}");
            let mut f = fixture(&value, MockProvider::new("npm"));
            add_blocked(&mut f, &value);
            let plan = plan(&mut f, &value, "0s").await;
            f.provider
                .fail_always(method, ProviderError::Permanent("denied".into()));
            let outcome = run_forced(&mut f, &plan).await;
            assert!(
                matches!(outcome.result, RunResult::Failed { .. }),
                "{method}"
            );
            assert!(f.log.calls().iter().all(|c| c.method != "revoke"));
            let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
            assert!(!stored.force, "{method}");
            assert!(outcome.forced.is_empty());
            assert!(audit_steps(&f).iter().all(|e| e.0 != AuditStep::Force));
            if method == "create_replacement" {
                assert!(f.log.calls().iter().all(|c| c.method != "update"));
                assert_eq!(f.gha.current("gha:org/repo:NPM_TOKEN"), Some(fp(&value)));
                assert_eq!(stored.failed_step, Some(AuditStep::Create));
            } else {
                assert_eq!(stored.failed_step, Some(AuditStep::Verify));
            }
        }
    }

    // T4 (AC4)
    #[tokio::test]
    async fn force_records_state_and_audit_before_revoke() {
        let value = "npm_apply_unit_force_record";
        let mut f = fixture(value, MockProvider::new("npm"));
        add_blocked(&mut f, value);
        let plan = plan(&mut f, value, "0s").await;
        let outcome = run_forced(&mut f, &plan).await;
        assert_eq!(outcome.result, RunResult::Revoked);
        assert_eq!(outcome.forced, ["gha:org:NPM_TOKEN"]);
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert!(stored.force);
        assert_eq!(stored.step, Step::Revoked);
        let steps = audit_steps(&f);
        let force = steps
            .iter()
            .position(|e| e.0 == AuditStep::Force)
            .expect("force entry");
        assert_eq!(steps[force].2.as_deref(), Some("gha:org:NPM_TOKEN"));
        assert_eq!(steps.last().unwrap().0, AuditStep::Revoke);
        assert!(force < steps.len() - 1);
        let summary = render_summary(&[outcome]);
        assert!(summary.contains("revoked (forced)"), "{summary}");
        assert!(summary.contains("--force used; not updated: gha:org:NPM_TOKEN"));
    }

    // With nothing to bypass, --force changes and records nothing.
    #[tokio::test]
    async fn unneeded_force_is_not_recorded() {
        let value = "npm_apply_unit_force_unneeded";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "0s").await;
        let outcome = run_forced(&mut f, &plan).await;
        assert_eq!(outcome.result, RunResult::Revoked);
        assert!(!f.store.get(&plan.rotations[0].rotation_id).unwrap().force);
        assert!(audit_steps(&f).iter().all(|e| e.0 != AuditStep::Force));
    }

    // T4 (AC4): a failed update is one of the consumers --force revokes past.
    #[tokio::test]
    async fn force_past_failed_update() {
        let value = "npm_apply_unit_force_update";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "0s").await;
        f.gha
            .fail_always("update", ConsumerError::Permanent("403 denied".into()));
        let outcome = run_forced(&mut f, &plan).await;
        assert_eq!(outcome.result, RunResult::Revoked);
        assert_eq!(
            mutating(&f.log),
            [
                "npm.create_replacement",
                "github-actions.update",
                "aws-secrets-manager.update",
                "npm.verify",
                "npm.revoke",
            ]
        );
        assert_eq!(outcome.forced, ["gha:org/repo:NPM_TOKEN"]);
        let steps = audit_steps(&f);
        assert!(steps.contains(&(
            AuditStep::Update,
            AuditOutcome::Failed,
            Some("gha:org/repo:NPM_TOKEN".into())
        )));
        assert!(steps.contains(&(
            AuditStep::Force,
            AuditOutcome::Ok,
            Some("gha:org/repo:NPM_TOKEN".into())
        )));
    }

    // AC3 then AC4: a held rotation is finished by a re-run with --force,
    // without creating or updating again.
    #[tokio::test]
    async fn held_rotation_finishes_with_force() {
        let value = "npm_apply_unit_held_rerun";
        let mut f = fixture(value, MockProvider::new("npm"));
        add_blocked(&mut f, value);
        let mut plan = plan(&mut f, value, "0s").await;
        let held = run(&mut f, &plan).await;
        assert!(matches!(held.result, RunResult::Held { .. }));
        f.log.clear();

        plan.rotations[0].step = Step::Verified;
        assert_eq!(eligibility(&plan.rotations[0]), Ok(()));
        let again = run(&mut f, &plan).await;
        assert!(matches!(again.result, RunResult::Held { .. }));
        assert!(mutating(&f.log).is_empty(), "{:?}", mutating(&f.log));

        let outcome = run_forced(&mut f, &plan).await;
        assert_eq!(outcome.result, RunResult::Revoked);
        assert_eq!(mutating(&f.log), ["npm.revoke"]);
        assert!(f.store.get(&plan.rotations[0].rotation_id).unwrap().force);
    }

    // T6 (AC6)
    #[tokio::test]
    async fn revoke_failure_says_replacement_is_live() {
        let value = "npm_apply_unit_revoke_fail";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "0s").await;
        f.provider
            .fail_always("revoke", ProviderError::Permanent("denied".into()));
        let outcome = run(&mut f, &plan).await;
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::Failed);
        assert_eq!(stored.failed_step, Some(AuditStep::Revoke));
        let summary = render_summary(std::slice::from_ref(&outcome));
        assert!(
            summary.contains("the replacement is live and the old secret may still be valid"),
            "{summary}"
        );
        assert!(!summary.contains("stopped before revoke"));
        assert_eq!(run_status(&[outcome]), RunStatus::Failed);
    }
}
