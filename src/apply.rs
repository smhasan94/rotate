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
//! hold the replacement, and defers it while the overlap window is open
//! (decision D2).
//!
//! A provider in manual replacement mode (decision D1, SHA-257) cannot mint
//! the replacement: the create step prints the provider's instructions,
//! reads the new secret from a hidden [`Prompt`] (or the value supplied
//! with `--replacement-from-env` or `--replacement-file`), and accepts it
//! only once `verify` confirms it belongs to the leaked secret's owner. No
//! consumer is touched before that.
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
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use zeroize::{Zeroize, Zeroizing};

use crate::audit::RedactedText;
use crate::audit::{AuditError, AuditEvent, AuditLog, AuditStep, Outcome as AuditOutcome};
use crate::console::Console;
use crate::consumer::ConsumerRegistry;
use crate::input::{self, ReplacementInputError, REPLACEMENT_MAX};
use crate::plan::{Plan, PlannedRotation};
use crate::provider::{Credential, Provider, ProviderRegistry, Replacement, ReplacementMode};
use crate::secret::{Fingerprint, SecretValue};
use crate::state::{ConsumerState, ConsumerStatus, Rotation, StateError, StateStore, Step};

/// What the operator typed to confirm every rotation with `--all`.
pub const CONFIRM_ALL: &str = "all";

/// How many pastes a manual replacement gets before the rotation fails.
pub const MANUAL_ATTEMPTS: usize = 3;

/// The `replacement_ref` recorded for a pasted replacement: rotate has no
/// provider-side handle on a credential the operator created.
pub const MANUAL_REF: &str = "manual";

/// Where apply writes while it runs: one redacted message per call, written
/// at once, so a question is on screen before rotate waits for the answer.
pub trait Terminal {
    /// Writes one message to stdout.
    fn stdout(&mut self, text: &str);
    /// Writes one message to stderr.
    fn stderr(&mut self, text: &str);
}

impl<O: Write, E: Write> Terminal for Console<O, E> {
    fn stdout(&mut self, text: &str) {
        let _ = self.out().write_all(text.as_bytes());
    }

    fn stderr(&mut self, text: &str) {
        let _ = self.err().write_all(text.as_bytes());
    }
}

/// A [`Write`] over [`Terminal::stderr`] that sends what it holds on every
/// `flush` and on drop, for [`confirm`]: the question shows before the
/// read. Callers flush only after whole messages.
pub struct QuestionWriter<'a> {
    term: &'a mut dyn Terminal,
    buf: Zeroizing<Vec<u8>>,
}

impl<'a> QuestionWriter<'a> {
    /// A writer to `term`'s stderr.
    pub fn new(term: &'a mut dyn Terminal) -> Self {
        Self {
            term,
            buf: Zeroizing::new(Vec::new()),
        }
    }
}

impl fmt::Debug for QuestionWriter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuestionWriter").finish_non_exhaustive()
    }
}

impl Write for QuestionWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let text = Zeroizing::new(String::from_utf8_lossy(&self.buf).into_owned());
            self.term.stderr(&text);
            self.buf.clear();
        }
        Ok(())
    }
}

impl Drop for QuestionWriter<'_> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Reads answers from the operator.
pub trait Prompt {
    /// Reads one answer. The question has already been printed.
    fn read_line(&mut self) -> Result<String, PromptError>;

    /// Writes `question` to `term` and reads one secret without echoing it
    /// (SHA-257). The value goes straight into a [`SecretValue`]; the
    /// trailing newline is not part of it.
    fn read_secret(
        &mut self,
        question: &str,
        term: &mut dyn Terminal,
    ) -> Result<SecretValue, PromptError>;
}

/// Why no answer could be read.
#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    /// There is no terminal to read from.
    #[error("no terminal to confirm on; pass --confirm <rotation-id>")]
    NoTerminal,
    /// There is no terminal to paste a replacement on.
    #[error(
        "no terminal to paste the replacement on; pass --replacement-from-env <VAR> or --replacement-file <PATH>"
    )]
    NoTerminalForSecret,
    /// Reading the terminal failed.
    #[error("could not read from the terminal ({0})")]
    Io(io::ErrorKind),
    /// Terminal echo could not be turned off, so nothing was read.
    #[error("could not turn off terminal echo ({0}); nothing was read")]
    Echo(io::ErrorKind),
}

/// Reads answers from `/dev/tty`, never stdin, so a secret piped to
/// `--stdin` and the confirmation do not share a stream.
#[derive(Debug, Default)]
pub struct TtyPrompt {
    path: Option<PathBuf>,
    tty: Option<BufReader<File>>,
}

impl TtyPrompt {
    /// A prompt that opens `/dev/tty` on first use.
    pub fn new() -> Self {
        Self::default()
    }

    /// A prompt that opens the terminal device at `path` instead, for the
    /// pseudo-terminal test.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
            tty: None,
        }
    }

    fn open(&mut self) -> Option<&mut BufReader<File>> {
        if self.tty.is_none() {
            let path = self
                .path
                .clone()
                .unwrap_or_else(|| PathBuf::from("/dev/tty"));
            let file = File::options().read(true).write(true).open(path).ok()?;
            self.tty = Some(BufReader::new(file));
        }
        self.tty.as_mut()
    }
}

/// Terminal echo off until dropped, then the saved mode back. `ECHONL`
/// stays on so Enter still moves the cursor to a new line.
struct EchoOff<'f> {
    tty: &'f File,
    saved: rustix::termios::Termios,
}

impl<'f> EchoOff<'f> {
    fn new(tty: &'f File) -> Result<Self, PromptError> {
        use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};

        let echo = |e: rustix::io::Errno| PromptError::Echo(io::Error::from(e).kind());
        let saved = tcgetattr(tty).map_err(echo)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        quiet.local_modes.insert(LocalModes::ECHONL);
        // Flush drops anything typed before echo went off.
        tcsetattr(tty, OptionalActions::Flush, &quiet).map_err(echo)?;
        Ok(Self { tty, saved })
    }
}

impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            self.tty,
            rustix::termios::OptionalActions::Now,
            &self.saved,
        );
    }
}

impl Prompt for TtyPrompt {
    fn read_line(&mut self) -> Result<String, PromptError> {
        let Some(tty) = self.open() else {
            return Err(PromptError::NoTerminal);
        };
        let mut line = String::new();
        tty.read_line(&mut line)
            .map_err(|err| PromptError::Io(err.kind()))?;
        Ok(line)
    }

    fn read_secret(
        &mut self,
        question: &str,
        term: &mut dyn Terminal,
    ) -> Result<SecretValue, PromptError> {
        let Some(tty) = self.open() else {
            return Err(PromptError::NoTerminalForSecret);
        };
        // Input typed ahead of an earlier answer was echoed; drop it.
        let ahead = tty.buffer().len();
        tty.consume(ahead);
        let file: &File = tty.get_ref();
        let _echo_off = EchoOff::new(file)?;
        term.stderr(question);
        // Byte by byte into a buffer that never reallocates: no copy of the
        // value is left behind. Longer lines are read to the end and
        // refused by `normalize_replacement`.
        let mut buf = Zeroizing::new(Vec::with_capacity(REPLACEMENT_MAX + 1));
        let mut byte = [0u8; 1];
        let result = loop {
            match (&*file).read(&mut byte) {
                Ok(0) => break Ok(()),
                Ok(_) if byte[0] == b'\n' => break Ok(()),
                Ok(_) => {
                    if buf.len() <= REPLACEMENT_MAX {
                        buf.push(byte[0]);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => break Err(PromptError::Io(err.kind())),
            }
        };
        byte.zeroize();
        result?;
        Ok(SecretValue::new(std::mem::take(&mut *buf)))
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

    fn read_secret(
        &mut self,
        question: &str,
        term: &mut dyn Terminal,
    ) -> Result<SecretValue, PromptError> {
        term.stderr(question);
        self.asked += 1;
        Ok(SecretValue::from(
            self.answers.pop_front().unwrap_or_default(),
        ))
    }
}

/// Where a manual replacement comes from.
pub enum ReplacementSource {
    /// Ask on the terminal with hidden input, up to [`MANUAL_ATTEMPTS`]
    /// times.
    Prompt(Box<dyn Prompt>),
    /// Read before the run from `--replacement-from-env` or
    /// `--replacement-file`: one attempt, for one rotation.
    Supplied(Option<SecretValue>),
}

impl fmt::Debug for ReplacementSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReplacementSource::Prompt(_) => f.write_str("Prompt"),
            ReplacementSource::Supplied(value) => {
                f.debug_tuple("Supplied").field(&value.is_some()).finish()
            }
        }
    }
}

/// The manual-mode input and output of an [`Executor`].
struct Manual<'a> {
    source: ReplacementSource,
    term: &'a mut dyn Terminal,
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
    /// An earlier apply left it at this step; resuming is SHA-258.
    InProgress(Step),
    /// The owner identity is unknown, so the replacement cannot be verified.
    NoScope,
}

impl fmt::Display for Ineligible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
    if rotation.step != Step::Planned {
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

/// The single decision before `revoke`. Holds while any consumer was not
/// updated or could not be searched; waits while the overlap window is open
/// (decision D2). `--force` (SHA-256) and resume with `--wait` (SHA-258)
/// change this function only.
pub fn revoke_gate(
    rotation: &PlannedRotation,
    consumers: &[ConsumerState],
    verified_at: OffsetDateTime,
) -> Gate {
    let not_updated = consumers
        .iter()
        .filter(|c| c.status != ConsumerStatus::Updated)
        .count()
        + rotation.lookup_errors.len();
    if not_updated > 0 {
        let noun = if not_updated == 1 {
            "consumer"
        } else {
            "consumers"
        };
        return Gate::Hold(format!(
            "{not_updated} {noun} not updated; revoke skipped, the old secret is still valid"
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
    manual: Option<Manual<'a>>,
}

impl fmt::Debug for Executor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("providers", &self.providers)
            .field("consumers", &self.consumers)
            .finish_non_exhaustive()
    }
}

/// Progress of one rotation inside [`Executor::run`].
struct Progress {
    record: Rotation,
    provider: &'static str,
    mode: ReplacementMode,
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
            manual: None,
        }
    }

    /// Where manual-mode rotations get their replacement, and where their
    /// instructions (stdout) and questions (stderr) go. Without it a
    /// manual rotation fails at create and nothing is changed.
    pub fn with_manual(mut self, source: ReplacementSource, term: &'a mut dyn Terminal) -> Self {
        self.manual = Some(Manual { source, term });
        self
    }

    /// Uses `clock` for the overlap window instead of the system clock.
    pub fn with_clock(mut self, clock: fn() -> OffsetDateTime) -> Self {
        self.clock = clock;
        self
    }

    /// Runs one confirmed rotation: create, update every consumer, verify,
    /// revoke gate, revoke. Never calls `revoke` after an earlier failure.
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
            mode: rotation.replacement_mode,
        };
        let result = self.steps(rotation, &mut progress).await;
        Outcome {
            rotation_id: rotation.rotation_id.clone(),
            provider: rotation.provider,
            fingerprint: rotation.fingerprint.clone(),
            replacement_fingerprint: progress.record.replacement_fingerprint.clone(),
            consumers: progress.record.consumers.clone(),
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

        // Create, or in manual mode take the operator's verified paste. The
        // replacement lives in this frame only.
        let replacement = match rotation.replacement_mode {
            ReplacementMode::Automatic => {
                match provider.create_replacement(&rotation.credential).await {
                    Ok(replacement) => replacement,
                    Err(err) => {
                        return self.fail(progress, AuditStep::Create, &err.to_string(), None)
                    }
                }
            }
            ReplacementMode::Manual => {
                match manual_replacement(self.manual.as_mut(), rotation, provider.as_ref()).await {
                    Ok(credential) => Replacement {
                        credential,
                        replacement_ref: MANUAL_REF.to_owned(),
                    },
                    Err(error) => return self.fail(progress, AuditStep::Create, &error, None),
                }
            }
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
                    return self.fail(
                        progress,
                        AuditStep::Update,
                        &format!("{reference}: {err}"),
                        Some(&reference),
                    );
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

        // The gate, then revoke: always the last step.
        match revoke_gate(rotation, &progress.record.consumers, (self.clock)()) {
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
        if step == AuditStep::Create {
            event = event.with_mode(progress.mode);
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

/// Obtains a manual replacement: prints the provider's instructions, then
/// reads and checks pastes until one is the leaked secret's owner's, at
/// most [`MANUAL_ATTEMPTS`] times (once for a supplied value). Read-only:
/// the only provider call is `verify`. The error is the reason to record.
async fn manual_replacement(
    manual: Option<&mut Manual<'_>>,
    rotation: &PlannedRotation,
    provider: &dyn Provider,
) -> Result<Credential, String> {
    let Some(manual) = manual else {
        return Err(PromptError::NoTerminalForSecret.to_string());
    };
    let Some(scope) = &rotation.scope else {
        return Err(Ineligible::NoScope.to_string());
    };
    let id = &rotation.rotation_id;
    manual.term.stdout(&format!(
        "\nRotation {id}: {} cannot create the replacement itself.\n{}\n",
        provider.name(),
        provider.manual_instructions(scope)
    ));
    let attempts = match manual.source {
        ReplacementSource::Prompt(_) => MANUAL_ATTEMPTS,
        ReplacementSource::Supplied(_) => 1,
    };
    let question =
        format!("Paste the new secret for rotation {id} (input is hidden), then press Enter: ");
    let mut last = String::new();
    for attempt in 1..=attempts {
        let value = match &mut manual.source {
            ReplacementSource::Prompt(prompt) => prompt
                .read_secret(&question, &mut *manual.term)
                .map_err(|err| err.to_string())?,
            ReplacementSource::Supplied(value) => value.take().ok_or_else(|| {
                "the supplied replacement was already used by another rotation".to_owned()
            })?,
        };
        last = match check_paste(value, rotation, provider, &scope.identity).await {
            Ok(credential) => return Ok(credential),
            Err(reason) => reason,
        };
        if attempt < attempts {
            manual.term.stderr(&format!(
                "The pasted secret was rejected: {last}. Try again (attempt {} of {attempts}).\n",
                attempt + 1
            ));
        }
    }
    Err(match manual.source {
        ReplacementSource::Prompt(_) => format!(
            "the pasted replacement was rejected {attempts} times, last: {last}; no consumer was updated"
        ),
        ReplacementSource::Supplied(_) => format!(
            "the supplied replacement was rejected: {last}; no consumer was updated"
        ),
    })
}

/// Accepts a pasted value when it is not blank, not the leaked secret, and
/// `verify` says it belongs to `identity`.
async fn check_paste(
    value: SecretValue,
    rotation: &PlannedRotation,
    provider: &dyn Provider,
    identity: &crate::provider::Identity,
) -> Result<Credential, String> {
    let value = input::normalize_replacement(value).map_err(|err| match err {
        ReplacementInputError::Empty => "nothing was pasted".to_owned(),
        other => other.to_string(),
    })?;
    let credential =
        input::replacement_credential(value, &rotation.credential).map_err(|e| e.to_string())?;
    if credential.fingerprint() == rotation.fingerprint {
        return Err("it is the leaked secret itself; paste the new one".to_owned());
    }
    provider
        .verify(&credential, identity)
        .await
        .map_err(|err| format!("it did not verify as {identity}: {err}"))?;
    Ok(credential)
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
        let outcome = match &o.result {
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
                    ""
                } else {
                    "; stopped before revoke, the old secret is still valid"
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
    async fn in_progress_and_no_scope_are_ineligible() {
        let value = "npm_apply_unit_inprogress";
        let mut f = fixture(value, MockProvider::new("npm"));
        let mut plan = plan(&mut f, value, "0s").await;
        assert_eq!(eligibility(&plan.rotations[0]), Ok(()));

        plan.rotations[0].step = Step::Created;
        let outcome = run(&mut f, &plan).await;
        assert_eq!(
            outcome.result,
            RunResult::Skipped(Ineligible::InProgress(Step::Created))
        );
        assert!(f.log.is_empty());
        assert_eq!(
            eligibility(&plan.rotations[0]),
            Err(Ineligible::InProgress(Step::Created))
        );
        plan.rotations[0].step = Step::Planned;
        plan.rotations[0].scope = None;
        assert_eq!(eligibility(&plan.rotations[0]), Err(Ineligible::NoScope));
        assert_eq!(run_status(&[outcome]), RunStatus::Unsupported);
    }

    /// Records what the executor writes, as the console would print it.
    #[derive(Default)]
    struct Recorder {
        out: String,
        err: String,
    }

    impl Terminal for Recorder {
        fn stdout(&mut self, text: &str) {
            self.out.push_str(text);
        }

        fn stderr(&mut self, text: &str) {
            self.err.push_str(text);
        }
    }

    async fn run_manual(
        f: &mut Fixture,
        plan: &Plan,
        source: ReplacementSource,
        term: &mut Recorder,
    ) -> Outcome {
        let mut executor = Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit)
            .with_manual(source, term);
        executor.run(&plan.rotations[0]).await
    }

    fn manual_mock() -> MockProvider {
        MockProvider::new("npm").mode(ReplacementMode::Manual)
    }

    // SHA-257 T1 (AC1), T2 (AC2)
    #[tokio::test]
    async fn manual_create_never_calls_create_replacement() {
        let value = "npm_manual_unit_leaked";
        let pasted = "npm_manual_unit_pasted_ok";
        let mut f = fixture(value, manual_mock());
        let plan = plan(&mut f, value, "0s").await;
        assert_eq!(eligibility(&plan.rotations[0]), Ok(()));
        let mut term = Recorder::default();
        let prompt = ScriptedPrompt::new([format!("{pasted}\n")]);
        let outcome = run_manual(
            &mut f,
            &plan,
            ReplacementSource::Prompt(Box::new(prompt)),
            &mut term,
        )
        .await;

        assert_eq!(outcome.result, RunResult::Revoked, "{}", term.err);
        assert_eq!(
            mutating(&f.log),
            [
                "npm.verify",
                "github-actions.update",
                "aws-secrets-manager.update",
                "npm.verify",
                "npm.revoke",
            ]
        );
        assert!(f
            .log
            .calls()
            .iter()
            .all(|c| c.method != "create_replacement"));
        assert!(term.out.contains("cannot create the replacement itself"));
        assert!(term
            .out
            .contains("Create a new npm credential for npm-user"));
        assert!(term.err.contains("(input is hidden)"));
        assert!(!term.out.contains(pasted) && !term.err.contains(pasted));

        assert_eq!(outcome.replacement_fingerprint, Some(fp(pasted)));
        assert_eq!(f.gha.current("gha:org/repo:NPM_TOKEN"), Some(fp(pasted)));
        assert_eq!(f.sm.current("sm:prod/npm"), Some(fp(pasted)));
        assert!(f.provider.is_revoked(&fp(value)));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.replacement_ref.as_deref(), Some(MANUAL_REF));
        assert_eq!(stored.replacement_fingerprint, Some(fp(pasted)));

        let create = crate::audit::read_all(&f.audit_path)
            .unwrap()
            .map(|e| e.unwrap())
            .find(|e| e.step == AuditStep::Create)
            .unwrap();
        assert_eq!(create.replacement_mode, Some(ReplacementMode::Manual));
        assert_eq!(create.replacement_fingerprint, Some(fp(pasted)));
    }

    // SHA-257 T3 (AC3): blank, the leaked secret itself and a foreign
    // secret are each one attempt; only the last reaches verify.
    #[tokio::test]
    async fn pasting_the_leaked_secret_is_rejected() {
        let value = "npm_manual_unit_leaked_again";
        let foreign = "npm_manual_unit_foreign";
        let mut f = fixture(
            value,
            manual_mock().owner(fp(foreign), crate::provider::Identity("other".into())),
        );
        let plan = plan(&mut f, value, "0s").await;
        let mut term = Recorder::default();
        let prompt = ScriptedPrompt::new(["\n".to_owned(), format!("{value}\n"), foreign.into()]);
        let outcome = run_manual(
            &mut f,
            &plan,
            ReplacementSource::Prompt(Box::new(prompt)),
            &mut term,
        )
        .await;

        let RunResult::Failed { step, error } = &outcome.result else {
            panic!("{outcome:?}");
        };
        assert_eq!(*step, AuditStep::Create);
        assert!(error.to_string().contains("rejected 3 times"), "{error}");
        assert!(term.err.contains("nothing was pasted"));
        assert!(term.err.contains("the leaked secret itself"));
        assert!(term.err.contains("attempt 3 of 3"));
        assert_eq!(mutating(&f.log), ["npm.verify"]);
        assert_eq!(f.gha.current("gha:org/repo:NPM_TOKEN"), Some(fp(value)));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::Failed);
        assert!(stored.consumers.is_empty());
        assert!(!term.out.contains(foreign) && !term.err.contains(foreign));
    }

    // SHA-257: a supplied value gets one attempt and no prompt.
    #[tokio::test]
    async fn supplied_replacement_gets_one_attempt() {
        let value = "npm_manual_unit_supplied_leaked";
        let foreign = "npm_manual_unit_supplied_foreign";
        let mut f = fixture(
            value,
            manual_mock().owner(fp(foreign), crate::provider::Identity("other".into())),
        );
        let first = plan(&mut f, value, "0s").await;
        let mut term = Recorder::default();
        let outcome = run_manual(
            &mut f,
            &first,
            ReplacementSource::Supplied(Some(SecretValue::from(foreign))),
            &mut term,
        )
        .await;
        let RunResult::Failed { step, error } = &outcome.result else {
            panic!("{outcome:?}");
        };
        assert_eq!(*step, AuditStep::Create);
        assert!(
            error
                .to_string()
                .contains("supplied replacement was rejected"),
            "{error}"
        );
        assert!(!term.err.contains("Try again"));
        assert_eq!(mutating(&f.log), ["npm.verify"]);

        let value = "npm_manual_unit_supplied_ok_leaked";
        let mut f = fixture(value, manual_mock());
        let second = plan(&mut f, value, "0s").await;
        let outcome = run_manual(
            &mut f,
            &second,
            ReplacementSource::Supplied(Some(SecretValue::from("npm_manual_unit_supplied_new\n"))),
            &mut term,
        )
        .await;
        assert_eq!(outcome.result, RunResult::Revoked);
        assert_eq!(
            outcome.replacement_fingerprint,
            Some(fp("npm_manual_unit_supplied_new"))
        );
    }

    #[tokio::test]
    async fn manual_without_input_fails_at_create() {
        let value = "npm_manual_unit_no_input";
        let mut f = fixture(value, manual_mock());
        let plan = plan(&mut f, value, "0s").await;
        let outcome = run(&mut f, &plan).await;
        let RunResult::Failed { step, error } = &outcome.result else {
            panic!("{outcome:?}");
        };
        assert_eq!(*step, AuditStep::Create);
        assert!(error.to_string().contains("--replacement-from-env"));
        assert!(mutating(&f.log).is_empty());
    }

    #[test]
    fn question_writer_sends_on_flush() {
        let mut term = Recorder::default();
        {
            let mut w = QuestionWriter::new(&mut term);
            write!(w, "Type ").unwrap();
            write!(w, "it: ").unwrap();
            w.flush().unwrap();
            write!(w, "tail").unwrap();
        }
        assert_eq!(term.err, "Type it: tail");
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
            revoke_gate(&rotation, &[status(ConsumerStatus::Updated)], now),
            Gate::Revoke
        );
        assert!(matches!(
            revoke_gate(&rotation, &[status(ConsumerStatus::Skipped)], now),
            Gate::Hold(_)
        ));
        let mut waiting = rotation.clone();
        waiting.overlap_window = "1h".parse().unwrap();
        assert_eq!(
            revoke_gate(&waiting, &[], now),
            Gate::Wait(now + std::time::Duration::from_secs(3600))
        );
    }
}
