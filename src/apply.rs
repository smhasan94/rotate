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
//! A provider in manual replacement mode (decision D1, SHA-257) cannot mint
//! the replacement: the create step prints the provider's instructions,
//! reads the new secret from a hidden [`Prompt`] (or the value supplied
//! with `--replacement-from-env` or `--replacement-file`), and accepts it
//! only once `verify` confirms it belongs to the leaked secret's owner. No
//! consumer is touched before that.
//!
//! Every run picks the rotation up where the state file says it is
//! (SHA-258, FR15, FR22): see [`resume_point`]. A step an earlier run
//! finished is never repeated; it gets a `skipped` audit entry. A pending
//! revoke keeps its recorded `revoke_not_before`; a re-run before then makes
//! no state-changing call, one after it revokes, and `--wait` sleeps until
//! then in the same run. A rotation that stopped after create in a process
//! that has exited cannot go on, since its replacement's value is gone: it
//! is marked `needs_rollback`.
//!
//! [`Executor::run_all`] runs every confirmed rotation in two phases
//! (SHA-286). Phase 1 takes each in turn through create, update, verify and
//! the revoke gate (with the force record); a rotation that ends there is
//! finished. Phase 2 revokes the rest, last, grouped by provider: one
//! [`Provider::revoke_batch`] per group, so GitHub tokens go to the
//! credential revocation API up to 1000 per request instead of one each
//! against its hourly limit. Every rotation still gets its own revoke audit
//! entry and state checkpoint. With `--wait`, each group sleeps once, until
//! the latest `revoke_not_before` in it.
//!
//! The replacement credential is held by the [`Executor`] from create until
//! it is verified, so a second run of the same rotation in the same process
//! can still update the consumers that missed it. Once verified it moves
//! into that rotation's place in phase 2 and lives until its revoke result
//! is recorded, so revoke text that echoes it is redacted; with many
//! rotations that is until the last one reaches its gate. It is zeroized,
//! registered with the redactor while alive, and dropped with the executor
//! or after its revoke. Nothing returned from here holds a value.
//!
//! Nothing here prints. The binary prints the plan, asks the questions
//! through a [`Prompt`], and renders the [`Outcome`]s with
//! [`render_summary`].

#![cfg(unix)]

use std::collections::{HashMap, VecDeque};
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use zeroize::{Zeroize, Zeroizing};

use crate::audit::RedactedText;
use crate::audit::{AuditError, AuditEvent, AuditLog, AuditStep, Outcome as AuditOutcome};
use crate::console::Console;
use crate::consumer::ConsumerRegistry;
use crate::input::{self, ReplacementInputError, REPLACEMENT_MAX};
use crate::plan::{Plan, PlannedRotation, Skipped};
use crate::provider::otp::{self, OtpError, OtpSource};
use crate::provider::{
    Credential, Provider, ProviderError, ProviderRegistry, Replacement, ReplacementMode, Revoked,
    Validity,
};
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

/// A one-time password typed at a hidden prompt (SHA-288), for a provider
/// that npm challenges on a token delete. The read blocks, so it runs on
/// the blocking pool: the binary's runtime has one thread, and the HTTP
/// client must keep running. The question goes to stderr like every other
/// question. No terminal is [`OtpError::NoSource`].
pub struct PromptOtp {
    prompt: Arc<Mutex<Box<dyn Prompt + Send>>>,
    term: Arc<Mutex<Box<dyn Terminal + Send>>>,
}

impl PromptOtp {
    /// Asks `prompt`, writing the question to `term`.
    pub fn new(prompt: Box<dyn Prompt + Send>, term: Box<dyn Terminal + Send>) -> Self {
        Self {
            prompt: Arc::new(Mutex::new(prompt)),
            term: Arc::new(Mutex::new(term)),
        }
    }

    /// Asks `prompt`, with the question on stderr.
    pub fn with_prompt(prompt: Box<dyn Prompt + Send>) -> Self {
        Self::new(prompt, Box::new(StdTerminal))
    }

    /// Asks on `/dev/tty`, opened only when a code is needed, with the
    /// question on stderr.
    pub fn tty() -> Self {
        Self::with_prompt(Box::new(TtyPrompt::new()))
    }
}

impl fmt::Debug for PromptOtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PromptOtp").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl OtpSource for PromptOtp {
    async fn one_time_password(&self, question: &str) -> Result<SecretValue, OtpError> {
        let prompt = Arc::clone(&self.prompt);
        let term = Arc::clone(&self.term);
        let question = question.to_owned();
        let read = tokio::task::spawn_blocking(move || {
            let mut prompt = prompt.lock().unwrap_or_else(PoisonError::into_inner);
            let mut term = term.lock().unwrap_or_else(PoisonError::into_inner);
            prompt.read_secret(&question, &mut **term)
        })
        .await
        .map_err(|_| OtpError::Failed("the one-time password prompt stopped".to_owned()))?;
        match read {
            Ok(typed) => {
                let code = typed.expose_secret(|b| SecretValue::new(b.trim_ascii().to_vec()));
                drop(typed);
                otp::check(code, "the typed one-time password is empty or not usable")
            }
            Err(PromptError::NoTerminal | PromptError::NoTerminalForSecret) => {
                Err(OtpError::NoSource)
            }
            Err(err) => Err(OtpError::Failed(err.to_string())),
        }
    }
}

/// The process's stdout and stderr as a [`Terminal`], each message
/// redacted, for a prompt that has no [`Console`] to borrow.
struct StdTerminal;

impl Terminal for StdTerminal {
    fn stdout(&mut self, text: &str) {
        let mut out = crate::redact::RedactingWriter::new(io::stdout());
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }

    fn stderr(&mut self, text: &str) {
        let mut err = crate::redact::RedactingWriter::new(io::stderr());
        let _ = err.write_all(text.as_bytes());
        let _ = err.flush();
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

/// Why apply cannot run a rotation. Nothing is called for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ineligible {
    /// An earlier run marked it `needs_rollback` (SHA-258): only `rotate
    /// rollback` moves it on.
    NeedsRollback,
    /// It is finished: `revoked` or `rolled_back`.
    Finished(Step),
    /// The owner identity is unknown, so the replacement cannot be verified.
    NoScope,
    /// `rotate rollback` started on it and has not finished (SHA-259).
    RollingBack,
}

impl fmt::Display for Ineligible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ineligible::NeedsRollback => f.write_str(
                "it needs rollback: the replacement value from an earlier run is gone; run rotate rollback with the same input",
            ),
            Ineligible::Finished(step) => {
                write!(f, "already finished at step {}", step_name(*step))
            }
            Ineligible::NoScope => f.write_str(
                "the owner identity is unknown, so the replacement could not be verified",
            ),
            Ineligible::RollingBack => {
                f.write_str("a rollback of it is in progress; finish it with rotate rollback")
            }
        }
    }
}

/// [`eligibility`], checked against the stored rotation too: not while a
/// rollback of it is in progress (SHA-259), since continuing would revoke
/// the old secret the rollback put back, and not when the stored step is
/// `needs_rollback` or finished.
pub fn eligibility_in(rotation: &PlannedRotation, store: &StateStore) -> Result<(), Ineligible> {
    if let Some(stored) = store.get(&rotation.rotation_id) {
        if stored.is_rolling_back() {
            return Err(Ineligible::RollingBack);
        }
        step_eligibility(stored.step)?;
    }
    eligibility(rotation)
}

/// Whether apply can run `rotation` now, from the plan alone. Every
/// unfinished step can be resumed (SHA-258) except `needs_rollback`. The
/// binary uses [`eligibility_in`], which also reads the state file.
pub fn eligibility(rotation: &PlannedRotation) -> Result<(), Ineligible> {
    step_eligibility(rotation.step)?;
    if rotation.scope.is_none() {
        return Err(Ineligible::NoScope);
    }
    Ok(())
}

fn step_eligibility(step: Step) -> Result<(), Ineligible> {
    match step {
        Step::NeedsRollback => Err(Ineligible::NeedsRollback),
        Step::Revoked | Step::RolledBack => Err(Ineligible::Finished(step)),
        _ => Ok(()),
    }
}

/// Where apply picks a rotation up, from what an earlier run recorded
/// (SHA-258). Ordered: every phase from the resume point on runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resume {
    /// Nothing was created: create, update, verify, revoke.
    Create,
    /// The replacement exists; some consumers may not hold it yet.
    Update,
    /// Every consumer was dealt with; verify, then revoke.
    Verify,
    /// Verified; only the revoke gate and revoke are left.
    Revoke,
}

/// The resume point for `record`. A `failed` rotation resumes at the step
/// that failed; with no replacement recorded it starts over, since nothing
/// was created. Not meaningful for an ineligible step.
pub fn resume_point(record: &Rotation) -> Resume {
    match record.step {
        Step::Planned => Resume::Create,
        Step::Created => Resume::Update,
        Step::ConsumersUpdated => Resume::Verify,
        Step::Verified | Step::PendingRevoke => Resume::Revoke,
        Step::Failed if record.replacement_ref.is_none() => Resume::Create,
        Step::Failed => match record.failed_step {
            Some(AuditStep::Verify) => Resume::Verify,
            Some(AuditStep::Force | AuditStep::Revoke) => Resume::Revoke,
            _ => Resume::Update,
        },
        // A revoke by hand is confirmed in `finish` with `check_valid`.
        Step::RevokeManual => Resume::Revoke,
        Step::NeedsRollback | Step::Revoked | Step::RolledBack => Resume::Revoke,
    }
}

/// Why a rotation that stopped after create cannot go on in a new process.
const LOST_REPLACEMENT: &str = "the replacement value from the earlier run is gone (rotate never stores it), so the consumers that do not hold it yet cannot be updated; run rotate rollback with the same input to restore the updated consumers and revoke the replacement, then run rotate apply again";

/// Audit detail of a step a resume does not repeat.
const DONE_EARLIER: &str = "already done in an earlier run";

/// Audit detail of the `ok` revoke entry written when a later run finds the
/// old secret no longer works after a revoke by hand (SHA-289).
pub const REVOKED_BY_HAND: &str = "revoked by hand, confirmed by check_valid";

/// Instructions for a `revoke_manual` rotation whose record has none.
const REVOKE_BY_HAND_FALLBACK: &str =
    "delete the old secret at the provider by hand, then re-run rotate apply";

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
/// overlap window is open (decision D2).
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

/// [`revoke_gate`] for a rotation that may already have a pending revoke
/// (SHA-258): a recorded `revoke_not_before` replaces the window, so a
/// re-run neither moves the time nor revokes early, whatever `--overlap`
/// says now.
pub fn resume_gate(
    rotation: &PlannedRotation,
    consumers: &[ConsumerState],
    now: OffsetDateTime,
    recorded: Option<OffsetDateTime>,
    force: bool,
) -> Gate {
    match (revoke_gate(rotation, consumers, now, force), recorded) {
        (Gate::Hold(reason), _) => Gate::Hold(reason),
        (_, Some(at)) if now < at => Gate::Wait(at),
        (_, Some(_)) => Gate::Revoke,
        (gate, None) => gate,
    }
}

/// `1h 5m`, `9m 59s`, `45s`: whole seconds, rounded down, never negative.
pub fn remaining_text(remaining: time::Duration) -> String {
    let secs = remaining.whole_seconds().max(0);
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m {s}s"),
        _ => format!("{h}h {m}m"),
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
        /// Time left until then, by apply's clock.
        remaining: time::Duration,
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
    /// Marked `needs_rollback` (SHA-258): the replacement exists but its
    /// value is gone, so apply cannot go on. Revoke was not called.
    NeedsRollback {
        /// Why, and what to do, redacted.
        reason: RedactedText,
    },
    /// The replacement is live and verified, but the provider cannot revoke
    /// the old secret: the operator must delete it by hand (SHA-289).
    RevokeManual {
        /// The provider's instructions, redacted.
        instructions: RedactedText,
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
    /// Every rotation was revoked (or was already finished).
    Done,
    /// Some rotation failed, was held before revoke or needs rollback
    /// (exit 1).
    Failed,
    /// Some old secret has to be revoked by hand (exit 4, SHA-289).
    RevokeManual,
    /// Some revoke waits for its overlap window (exit 3).
    Pending,
    /// Some rotation could not be attempted (exit 2).
    Unsupported,
}

/// Exit class for `outcomes`: failed, then revoke by hand, then pending,
/// then unsupported.
pub fn run_status(outcomes: &[Outcome]) -> RunStatus {
    let any = |f: fn(&RunResult) -> bool| outcomes.iter().any(|o| f(&o.result));
    if any(|r| {
        matches!(
            r,
            RunResult::Failed { .. }
                | RunResult::Held { .. }
                | RunResult::NeedsRollback { .. }
                | RunResult::Skipped(Ineligible::NeedsRollback)
        )
    }) {
        RunStatus::Failed
    } else if any(|r| matches!(r, RunResult::RevokeManual { .. })) {
        RunStatus::RevokeManual
    } else if any(|r| matches!(r, RunResult::PendingRevoke { .. })) {
        RunStatus::Pending
    } else if any(|r| {
        matches!(
            r,
            RunResult::Skipped(Ineligible::NoScope | Ineligible::RollingBack)
        )
    }) {
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
    force: bool,
    wait: bool,
    /// Replacements created by this executor and not yet verified, by
    /// rotation id (SHA-258): a second [`run`](Self::run) of a rotation
    /// that stopped before verify uses it instead of marking the rotation
    /// `needs_rollback`. Zeroized and registered with the redactor while
    /// held; gone when this executor is dropped.
    held: HashMap<String, Credential>,
}

impl fmt::Debug for Executor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("providers", &self.providers)
            .field("consumers", &self.consumers)
            .field("force", &self.force)
            .field("wait", &self.wait)
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

/// Progress of one rotation inside [`Executor::run_all`].
struct Progress {
    record: Rotation,
    provider: &'static str,
    mode: ReplacementMode,
    /// The replacement is broader than the leaked credential (SHA-291).
    scope_widened: bool,
    forced: Vec<String>,
}

/// A rotation that passed its revoke gate in phase 1 of
/// [`Executor::run_all`] and waits for its revoke in phase 2 (SHA-286). No
/// `Debug`: it holds the verified replacement. Nothing in it reaches the
/// state file or the audit log but `progress.record`.
struct Ready<'r> {
    /// Position in the `run_all` input.
    index: usize,
    rotation: &'r PlannedRotation,
    progress: Progress,
    /// The replacement this run verified, alive (zeroized, registered with
    /// the redactor) until this rotation's revoke result is recorded, so
    /// revoke text that echoes it is redacted (SHA-293). `None` when an
    /// earlier run verified it.
    verified: Option<Credential>,
    /// With `--wait`: revoke no earlier than this.
    not_before: Option<OffsetDateTime>,
}

/// How phase 1 left one rotation.
enum Prepared<'r> {
    /// Finished without a revoke from rotate.
    Done(Progress, RunResult),
    /// Through the gate; revoked in phase 2.
    Ready(Ready<'r>),
}

/// The [`Outcome`] of `rotation` from its progress and result.
fn outcome(rotation: &PlannedRotation, progress: Progress, result: RunResult) -> Outcome {
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

/// The outcome of a rotation [`Executor::run_all`] recorded none for. It
/// records one for every rotation; this keeps the call total without a
/// panic, and fails rather than claims success.
fn no_outcome(rotation: &PlannedRotation) -> Outcome {
    Outcome {
        result: RunResult::Failed {
            step: AuditStep::Plan,
            error: RedactedText::new("apply recorded no outcome for this rotation"),
        },
        ..Outcome::skipped(rotation, Ineligible::NoScope)
    }
}

/// What to do after a rate-limited revoke (SHA-286): re-run once the
/// provider's hint has passed. Nothing is retried in the same run.
fn retry_hint(now: OffsetDateTime, retry_after: Option<std::time::Duration>) -> String {
    match retry_after.and_then(|d| time::Duration::try_from(d).ok()) {
        Some(wait) => format!(
            "re-run rotate apply after {} (in {}) to revoke it",
            rfc3339(now + wait),
            remaining_text(wait)
        ),
        None => "re-run rotate apply once the provider's rate limit resets to revoke it".to_owned(),
    }
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
            force: false,
            wait: false,
            held: HashMap::new(),
        }
    }

    /// Where manual-mode rotations get their replacement, and where their
    /// instructions (stdout) and questions and notes (stderr) go. Without
    /// it a manual rotation fails at create and nothing is changed.
    pub fn with_manual(mut self, source: ReplacementSource, term: &'a mut dyn Terminal) -> Self {
        self.manual = Some(Manual { source, term });
        self
    }

    /// `--force`: revoke even when some consumers were not updated
    /// (NFR5). Never bypasses a failed create or verify.
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// `--wait` (SHA-258): when the overlap window is open, record the
    /// pending revoke, sleep until it has passed, then revoke in the same
    /// run instead of returning [`RunResult::PendingRevoke`].
    pub fn with_wait(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }

    /// Uses `clock` for the overlap window instead of the system clock.
    pub fn with_clock(mut self, clock: fn() -> OffsetDateTime) -> Self {
        self.clock = clock;
        self
    }

    /// Runs one confirmed rotation: [`run_all`](Self::run_all) with one
    /// rotation.
    pub async fn run(&mut self, rotation: &PlannedRotation) -> Outcome {
        self.run_all(&[rotation])
            .await
            .pop()
            .unwrap_or_else(|| no_outcome(rotation))
    }

    /// Runs confirmed rotations from where the state file says each is
    /// (SHA-258), in two phases (SHA-286). Phase 1 takes each in turn
    /// through create, update every consumer not yet updated, verify and
    /// the revoke gate; one that ends there (failed, held, pending,
    /// revoke by hand) is finished. Phase 2 revokes the rest, last, one
    /// [`Provider::revoke_batch`] per provider. A step finished by an
    /// earlier run is not repeated; it gets a `skipped` audit entry. Never
    /// revokes after an earlier failure. An ineligible rotation is returned
    /// as skipped without a call. Outcomes are in input order.
    pub async fn run_all(&mut self, rotations: &[&PlannedRotation]) -> Vec<Outcome> {
        let mut outcomes: Vec<Option<Outcome>> = vec![None; rotations.len()];
        let mut ready = Vec::new();
        for (index, rotation) in rotations.iter().copied().enumerate() {
            if let Err(why) = eligibility_in(rotation, self.store) {
                outcomes[index] = Some(Outcome::skipped(rotation, why));
                continue;
            }
            match self.prepare(index, rotation).await {
                Prepared::Done(progress, result) => {
                    outcomes[index] = Some(outcome(rotation, progress, result));
                }
                Prepared::Ready(r) => ready.push(r),
            }
        }
        for (index, progress, result) in self.revoke_ready(ready).await {
            outcomes[index] = Some(outcome(rotations[index], progress, result));
        }
        outcomes
            .into_iter()
            .zip(rotations)
            .map(|(o, rotation)| o.unwrap_or_else(|| no_outcome(rotation)))
            .collect()
    }

    /// Phase 1 for one rotation: everything up to and including the revoke
    /// gate. A rotation the gate lets through comes back [`Ready`], holding
    /// the verified replacement when this run verified it.
    async fn prepare<'r>(&mut self, index: usize, rotation: &'r PlannedRotation) -> Prepared<'r> {
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
            scope_widened: rotation.widens_scope().is_some(),
            forced: Vec::new(),
        };
        if let Err(err) = self.event(&progress, AuditStep::Plan, AuditOutcome::Ok, None, None) {
            // Nothing was done; the stored step stays as it is.
            let result = RunResult::Failed {
                step: AuditStep::Plan,
                error: RedactedText::new(&err.to_string()),
            };
            return Prepared::Done(progress, result);
        }
        let Some(provider) = self.providers.get(rotation.provider) else {
            let result = self.fail(
                &mut progress,
                AuditStep::Create,
                "the provider is not registered",
                None,
            );
            return Prepared::Done(progress, result);
        };
        let from = resume_point(&progress.record);
        let id = rotation.rotation_id.clone();
        if let Err(err) = self.audit_done(&progress, from) {
            // Nothing was done; the stored step stays as it is.
            let result = RunResult::Failed {
                step: AuditStep::Plan,
                error: RedactedText::new(&err.to_string()),
            };
            return Prepared::Done(progress, result);
        }

        if from == Resume::Create {
            // Nothing was created (a fresh rotation, or one whose create
            // failed): start over.
            progress.record.failed_step = None;
            progress.record.consumers.clear();
            if let Err(result) = self
                .create(rotation, provider.as_ref(), &mut progress)
                .await
            {
                return Prepared::Done(progress, result);
            }
        }
        if from <= Resume::Update {
            // The replacement lives in `held` until it is verified; a copy
            // lives in this frame. Without it nothing can be updated.
            let Some(credential) = self.held.get(&id).cloned() else {
                let result =
                    self.needs_rollback(&mut progress, AuditStep::Update, LOST_REPLACEMENT);
                return Prepared::Done(progress, result);
            };
            progress.record.failed_step = None;
            if let Err(result) = self.update_all(rotation, &mut progress, &credential).await {
                return Prepared::Done(progress, result);
            }
        }
        // The verified replacement leaves `held` but stays alive, and so
        // registered with the redactor, until this rotation's revoke is
        // recorded in phase 2: a revoke error or revoke-by-hand text that
        // echoes it is printed and stored after this point (SHA-293).
        let verified = if from <= Resume::Verify {
            progress.record.failed_step = None;
            if let Err(result) = self
                .verify(rotation, provider.as_ref(), &mut progress)
                .await
            {
                return Prepared::Done(progress, result);
            }
            self.held.remove(&id)
        } else {
            None
        };
        match self.gate(rotation, provider.as_ref(), &mut progress).await {
            Ok(not_before) => Prepared::Ready(Ready {
                index,
                rotation,
                progress,
                verified,
                not_before,
            }),
            Err(result) => {
                drop(verified);
                Prepared::Done(progress, result)
            }
        }
    }

    /// One `skipped` audit entry for every step an earlier run finished
    /// and this one does not repeat: create, each consumer updated, verify.
    /// Consumers left for this run are handled by [`update_all`].
    fn audit_done(&mut self, progress: &Progress, from: Resume) -> Result<(), RecordError> {
        if from >= Resume::Update {
            self.event(
                progress,
                AuditStep::Create,
                AuditOutcome::Skipped,
                None,
                Some(DONE_EARLIER),
            )?;
        }
        if from >= Resume::Verify {
            let refs: Vec<String> = progress
                .record
                .consumers
                .iter()
                .filter(|c| c.status == ConsumerStatus::Updated)
                .map(|c| c.consumer_ref.clone())
                .collect();
            for consumer in &refs {
                self.event(
                    progress,
                    AuditStep::Update,
                    AuditOutcome::Skipped,
                    Some(consumer),
                    Some(DONE_EARLIER),
                )?;
            }
        }
        if from >= Resume::Revoke {
            self.event(
                progress,
                AuditStep::Verify,
                AuditOutcome::Skipped,
                None,
                Some(DONE_EARLIER),
            )?;
        }
        Ok(())
    }

    /// Create, or in manual mode take the operator's verified paste, and
    /// hold the replacement until it is verified.
    async fn create(
        &mut self,
        rotation: &PlannedRotation,
        provider: &dyn Provider,
        progress: &mut Progress,
    ) -> Result<(), RunResult> {
        let replacement = match rotation.replacement_mode {
            ReplacementMode::Automatic => {
                match provider.create_replacement(&rotation.credential).await {
                    Ok(replacement) => replacement,
                    Err(err) => {
                        return Err(self.fail(progress, AuditStep::Create, &err.to_string(), None))
                    }
                }
            }
            ReplacementMode::Manual => {
                match manual_replacement(self.manual.as_mut(), rotation, provider).await {
                    Ok(credential) => Replacement {
                        credential,
                        replacement_ref: MANUAL_REF.to_owned(),
                    },
                    Err(error) => return Err(self.fail(progress, AuditStep::Create, &error, None)),
                }
            }
        };
        progress.record.step = Step::Created;
        progress.record.replacement_ref = Some(replacement.replacement_ref.clone());
        progress.record.replacement_fingerprint = Some(replacement.credential.fingerprint());
        self.held
            .insert(rotation.rotation_id.clone(), replacement.credential);
        if let Err(err) = self.checkpoint(progress, AuditStep::Create, None) {
            return Err(self.fail(progress, AuditStep::Create, &err.to_string(), None));
        }
        Ok(())
    }

    /// Updates every planned consumer that does not hold the replacement
    /// yet, saving after each. One an earlier run updated is not called
    /// again; it gets a `skipped` audit entry.
    async fn update_all(
        &mut self,
        rotation: &PlannedRotation,
        progress: &mut Progress,
        credential: &Credential,
    ) -> Result<(), RunResult> {
        for planned in &rotation.consumers {
            let reference = planned.found.consumer_ref.clone();
            let earlier = progress
                .record
                .consumers
                .iter()
                .position(|c| c.consumer == planned.consumer && c.consumer_ref == reference);
            if let Some(i) = earlier {
                if progress.record.consumers[i].status == ConsumerStatus::Updated {
                    if let Err(err) = self.event(
                        progress,
                        AuditStep::Update,
                        AuditOutcome::Skipped,
                        Some(&reference),
                        Some(DONE_EARLIER),
                    ) {
                        return Err(self.fail(progress, AuditStep::Update, &err.to_string(), None));
                    }
                    continue;
                }
                // Failed or skipped last time: try again.
                progress.record.consumers.remove(i);
            }
            let state = |status| ConsumerState {
                consumer: planned.consumer.to_owned(),
                consumer_ref: reference.clone(),
                status,
                holds: Some(planned.found.holds),
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
                    return Err(self.fail(progress, AuditStep::Update, &err.to_string(), None));
                }
                continue;
            }
            let Some(consumer) = self.consumers.get(planned.consumer) else {
                progress
                    .record
                    .consumers
                    .push(state(ConsumerStatus::Failed));
                return Err(self.fail(
                    progress,
                    AuditStep::Update,
                    &format!("{reference}: the consumer is not registered"),
                    Some(&reference),
                ));
            };
            match consumer.update(&planned.found, credential).await {
                Ok(_receipt) => {
                    progress
                        .record
                        .consumers
                        .push(state(ConsumerStatus::Updated));
                    if let Err(err) = self.checkpoint(progress, AuditStep::Update, Some(&reference))
                    {
                        return Err(self.fail(progress, AuditStep::Update, &err.to_string(), None));
                    }
                }
                Err(err) => {
                    progress
                        .record
                        .consumers
                        .push(state(ConsumerStatus::Failed));
                    let error = format!("{reference}: {err}");
                    if !self.force {
                        return Err(self.fail(
                            progress,
                            AuditStep::Update,
                            &error,
                            Some(&reference),
                        ));
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
                        return Err(self.fail(progress, AuditStep::Update, &err.to_string(), None));
                    }
                }
            }
        }
        progress.record.step = Step::ConsumersUpdated;
        if let Err(err) = self.save(progress) {
            return Err(self.fail(progress, AuditStep::Update, &err.to_string(), None));
        }
        Ok(())
    }

    /// Verifies the replacement belongs to the same owner (assumption A5):
    /// with its value when this executor holds it, else by its ref
    /// (SHA-258, read-only). A provider that cannot check by ref, or a
    /// manual replacement, leaves the rotation `needs_rollback`.
    async fn verify(
        &mut self,
        rotation: &PlannedRotation,
        provider: &dyn Provider,
        progress: &mut Progress,
    ) -> Result<(), RunResult> {
        let Some(scope) = &rotation.scope else {
            return Err(self.fail(
                progress,
                AuditStep::Verify,
                &Ineligible::NoScope.to_string(),
                None,
            ));
        };
        let held = self.held.get(&rotation.rotation_id).cloned();
        let checked = match (&held, progress.record.replacement_ref.as_deref()) {
            (Some(credential), _) => provider.verify(credential, &scope.identity).await,
            (None, Some(reference)) if reference != MANUAL_REF => {
                provider
                    .verify_replacement(reference, &scope.identity)
                    .await
            }
            (None, _) => Err(ProviderError::Unsupported(
                "a pasted replacement has no provider reference to check".into(),
            )),
        };
        drop(held);
        match checked {
            Ok(()) => {}
            Err(err) if err.unsupported().is_some() => {
                let why = err.unsupported().unwrap_or_default();
                let reason = format!(
                    "the replacement value from the earlier run is gone and it cannot be verified without it ({why}); run rotate rollback with the same input to restore the updated consumers and revoke the replacement, then run rotate apply again"
                );
                return Err(self.needs_rollback(progress, AuditStep::Verify, &reason));
            }
            Err(err) => {
                return Err(self.fail(progress, AuditStep::Verify, &err.to_string(), None));
            }
        }
        progress.record.step = Step::Verified;
        if let Err(err) = self.checkpoint(progress, AuditStep::Verify, None) {
            return Err(self.fail(progress, AuditStep::Verify, &err.to_string(), None));
        }
        Ok(())
    }

    /// The revoke gate and the force record (SHA-256): `Ok(None)` is revoke
    /// now, `Ok(Some(t))` is revoke once `t` has passed (`--wait`), `Err` is
    /// how the rotation ends without a revoke from rotate. Runs only once
    /// the replacement is verified. A rotation an earlier run left at
    /// `revoke_manual` is only checked (SHA-289).
    async fn gate(
        &mut self,
        rotation: &PlannedRotation,
        provider: &dyn Provider,
        progress: &mut Progress,
    ) -> Result<Option<OffsetDateTime>, RunResult> {
        if progress.record.step == Step::RevokeManual {
            return Err(self.recheck_by_hand(rotation, provider, progress).await);
        }
        let now = (self.clock)();
        // A force recorded by an earlier run still stands.
        let force = self.force || progress.record.force;
        let gate = resume_gate(
            rotation,
            &progress.record.consumers,
            now,
            progress.record.revoke_not_before,
            force,
        );
        if !matches!(gate, Gate::Hold(_)) && force {
            // NFR5: the force is on record before anything is revoked, so
            // before the batch request of phase 2 too.
            if let Err(err) = self.record_force(rotation, progress) {
                return Err(self.fail(progress, AuditStep::Force, &err.to_string(), None));
            }
        }
        match gate {
            Gate::Revoke => Ok(None),
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
                Err(RunResult::Held { reason })
            }
            Gate::Wait(not_before) => {
                let remaining = not_before - now;
                let when = rfc3339(not_before);
                progress.record.step = Step::PendingRevoke;
                progress.record.revoke_not_before = Some(not_before);
                let recorded = self.save(progress).and_then(|()| {
                    self.event(
                        progress,
                        AuditStep::Revoke,
                        AuditOutcome::Skipped,
                        None,
                        Some(&format!("overlap window open until {when}")),
                    )
                });
                if let Err(err) = recorded {
                    return Err(self.fail(progress, AuditStep::Revoke, &err.to_string(), None));
                }
                if !self.wait {
                    return Err(RunResult::PendingRevoke {
                        not_before,
                        remaining,
                    });
                }
                Ok(Some(not_before))
            }
        }
    }

    /// Phase 2 (SHA-286): revokes every rotation that passed its gate, one
    /// [`Provider::revoke_batch`] per provider. Groups with nothing to wait
    /// for go first, then by the latest `not_before` in the group; with
    /// `--wait` each group sleeps once, until its latest time, so nothing
    /// is revoked before its own time. A rotation the provider can only
    /// have revoked by hand never enters the batch. Each rotation's result
    /// is recorded on its own, in group order, after the batch returns.
    async fn revoke_ready(&mut self, ready: Vec<Ready<'_>>) -> Vec<(usize, Progress, RunResult)> {
        let mut groups: Vec<(&'static str, Vec<Ready<'_>>)> = Vec::new();
        for r in ready {
            match groups
                .iter_mut()
                .find(|(name, _)| *name == r.rotation.provider)
            {
                Some((_, group)) => group.push(r),
                None => groups.push((r.rotation.provider, vec![r])),
            }
        }
        // Stable: ties keep their first appearance.
        groups.sort_by_key(|(_, group)| group.iter().filter_map(|r| r.not_before).max());

        let mut done = Vec::new();
        for (name, group) in groups {
            if let Some(latest) = group.iter().filter_map(|r| r.not_before).max() {
                self.wait_for(&group, latest).await;
            }
            let Some(provider) = self.providers.get(name).cloned() else {
                // Cannot happen after phase 1, which needed the provider.
                for mut r in group {
                    let result = self.fail(
                        &mut r.progress,
                        AuditStep::Revoke,
                        "the provider is not registered; the old secret may still be valid",
                        None,
                    );
                    done.push((r.index, r.progress, result));
                }
                continue;
            };
            let mut batch = Vec::new();
            for mut r in group {
                // SHA-289: a credential rotate cannot revoke ends at
                // revoke_manual, not failed: everything up to the revoke
                // worked.
                match provider.manual_revoke(r.rotation.scope.as_ref()) {
                    Some(instructions) => {
                        let result = self.revoke_by_hand(&mut r.progress, instructions);
                        done.push((r.index, r.progress, result));
                    }
                    None => batch.push(r),
                }
            }
            if batch.is_empty() {
                continue;
            }
            if let Some(size) = provider.revoke_batch_size().filter(|s| *s > 0) {
                // SHA-330: only what the requests will carry, chunked as
                // the provider chunks it.
                let mut left = batch
                    .iter()
                    .filter(|r| provider.batchable(&r.rotation.credential))
                    .count();
                while left > 1 {
                    let sent = left.min(size);
                    self.notice(&format!("revoking {sent} {name} tokens in one request\n"));
                    left -= sent;
                }
            }
            let credentials: Vec<&Credential> =
                batch.iter().map(|r| &r.rotation.credential).collect();
            let results = provider.revoke_batch(&credentials).await;
            drop(credentials);
            if results.len() != batch.len() {
                let error = format!(
                    "the provider returned {} results for {} credentials; the old secret may still be valid",
                    results.len(),
                    batch.len()
                );
                for mut r in batch {
                    let result = self.fail(&mut r.progress, AuditStep::Revoke, &error, None);
                    done.push((r.index, r.progress, result));
                }
                continue;
            }
            for (mut r, revoked) in batch.into_iter().zip(results) {
                let result = self.record_revoke(&mut r, revoked);
                done.push((r.index, r.progress, result));
            }
        }
        done
    }

    /// `--wait` for one provider group: one notice naming every rotation in
    /// it, then a sleep until `latest`.
    async fn wait_for(&mut self, group: &[Ready<'_>], latest: OffsetDateTime) {
        let remaining = latest - (self.clock)();
        let ids: Vec<&str> = group
            .iter()
            .map(|r| r.progress.record.rotation_id.as_str())
            .collect();
        let (noun, secret) = if ids.len() == 1 {
            ("Rotation", "secret")
        } else {
            ("Rotations", "secrets")
        };
        self.notice(&format!(
            "{noun} {}: waiting until {} ({}) to revoke the old {secret}; interrupt to stop, then re-run rotate apply after that time.\n",
            ids.join(", "),
            rfc3339(latest),
            remaining_text(remaining)
        ));
        let pause = std::time::Duration::try_from(remaining).unwrap_or_default();
        tokio::time::sleep(pause).await;
    }

    /// Records one rotation's revoke result from phase 2: `revoked` with
    /// its restore handle, a revoke by hand, or a failure. The error text
    /// is kept, redacted, when this run held the verified replacement, and
    /// summarized when it did not (SHA-294). Drops the replacement.
    fn record_revoke(
        &mut self,
        ready: &mut Ready<'_>,
        result: Result<Revoked, ProviderError>,
    ) -> RunResult {
        let upstream = match ready.verified {
            Some(_) => UpstreamText::Redacted,
            None => UpstreamText::Summary,
        };
        let result = self.revoke_result(&mut ready.progress, upstream, result);
        // Zeroized, and unregistered from the redactor with the last copy.
        ready.verified = None;
        result
    }

    fn revoke_result(
        &mut self,
        progress: &mut Progress,
        upstream: UpstreamText,
        result: Result<Revoked, ProviderError>,
    ) -> RunResult {
        let revoked = match result {
            Ok(revoked) => revoked,
            Err(err) if err.unsupported().is_some() => {
                let instructions = match upstream {
                    UpstreamText::Redacted => err.unsupported().unwrap_or_default().to_owned(),
                    // SHA-298: rotate's own guidance, when the provider gave
                    // one, says more than the generic fallback.
                    UpstreamText::Summary => format!(
                        "{} ({})",
                        err.guidance().unwrap_or(REVOKE_BY_HAND_FALLBACK),
                        revoke_error_summary(progress.provider, &err)
                    ),
                };
                return self.revoke_by_hand(progress, &instructions);
            }
            Err(err) => {
                let text = match upstream {
                    UpstreamText::Redacted => err.to_string(),
                    UpstreamText::Summary => match err.guidance() {
                        Some(guidance) => format!(
                            "{}. {guidance}",
                            revoke_error_summary(progress.provider, &err)
                        ),
                        None => revoke_error_summary(progress.provider, &err),
                    },
                };
                let mut error = format!(
                    "{text}; the replacement is live and the old secret may still be valid"
                );
                // SHA-286: nothing is retried; say when a re-run can revoke.
                if let ProviderError::RateLimited { retry_after } = err.base() {
                    let _ = write!(error, "; {}", retry_hint((self.clock)(), *retry_after));
                }
                return self.fail(progress, AuditStep::Revoke, &error, None);
            }
        };
        progress.record.step = Step::Revoked;
        progress.record.failed_step = None;
        // Kept for `rotate rollback` (SHA-259).
        progress.record.restore_ref = revoked.restore_ref;
        if let Err(err) = self.checkpoint(progress, AuditStep::Revoke, None) {
            // The revoke happened; only the record is missing.
            return RunResult::Failed {
                step: AuditStep::Revoke,
                error: RedactedText::new(&format!("the old secret was revoked but {err}")),
            };
        }
        RunResult::Revoked
    }

    /// Records `revoke_manual` (SHA-289): the old secret has to be deleted
    /// by hand as `instructions` say. One `skipped` revoke audit entry with
    /// the instructions. Revoke was not called, or the provider refused it.
    fn revoke_by_hand(&mut self, progress: &mut Progress, instructions: &str) -> RunResult {
        let instructions = RedactedText::new(instructions);
        progress.record.step = Step::RevokeManual;
        progress.record.failed_step = None;
        progress.record.revoke_instructions = Some(instructions.as_str().to_owned());
        let recorded = self.save(progress).and_then(|()| {
            self.event(
                progress,
                AuditStep::Revoke,
                AuditOutcome::Skipped,
                None,
                Some(instructions.as_str()),
            )
        });
        if let Err(err) = recorded {
            return self.fail(progress, AuditStep::Revoke, &err.to_string(), None);
        }
        RunResult::RevokeManual { instructions }
    }

    /// A rotation an earlier run left at `revoke_manual` (SHA-289): one
    /// read-only `check_valid` on the old secret, and no other call. Invalid
    /// means the operator deleted it: `revoked`. Valid, unknown or an error
    /// leaves it at `revoke_manual`, with a `skipped` revoke audit entry.
    async fn recheck_by_hand(
        &mut self,
        rotation: &PlannedRotation,
        provider: &dyn Provider,
        progress: &mut Progress,
    ) -> RunResult {
        let instructions = progress
            .record
            .revoke_instructions
            .clone()
            .unwrap_or_else(|| REVOKE_BY_HAND_FALLBACK.to_owned());
        let still = match provider.check_valid(&rotation.credential).await {
            Ok(Validity::Invalid) => return self.revoked_by_hand(progress),
            Ok(Validity::Valid) => "the old secret still works".to_owned(),
            Ok(Validity::Unknown { reason }) => {
                format!("could not tell whether the old secret still works ({reason})")
            }
            Err(err) => format!("could not check the old secret ({err})"),
        };
        if let Err(err) = self.event(
            progress,
            AuditStep::Revoke,
            AuditOutcome::Skipped,
            None,
            Some(&format!("{still}; {instructions}")),
        ) {
            tracing::warn!(rotation_id = %progress.record.rotation_id, "{err}");
        }
        RunResult::RevokeManual {
            instructions: RedactedText::new(&instructions),
        }
    }

    /// Records a revoke by hand as done: step `revoked` and an `ok` revoke
    /// audit entry saying how it was confirmed.
    fn revoked_by_hand(&mut self, progress: &mut Progress) -> RunResult {
        progress.record.step = Step::Revoked;
        progress.record.failed_step = None;
        progress.record.revoke_instructions = None;
        let recorded = self.save(progress).and_then(|()| {
            self.event(
                progress,
                AuditStep::Revoke,
                AuditOutcome::Ok,
                None,
                Some(REVOKED_BY_HAND),
            )
        });
        if let Err(err) = recorded {
            return RunResult::Failed {
                step: AuditStep::Revoke,
                error: RedactedText::new(&format!("the old secret was revoked by hand but {err}")),
            };
        }
        RunResult::Revoked
    }

    /// Records the old secret of a `revoke_manual` rotation as revoked when
    /// the plan found it no longer works (SHA-289): assessment's
    /// `check_valid` said `Invalid`, so the plan skipped it with reason
    /// [`plan::REVOKED_BY_HAND`](crate::plan::REVOKED_BY_HAND) and the
    /// rotation's id. Makes no call. `None` when that rotation is not at
    /// `revoke_manual` for this secret, or a rollback of it is in progress.
    pub fn confirm_revoked_by_hand(&mut self, skipped: &Skipped) -> Option<Outcome> {
        let provider = skipped.provider?;
        let record = self
            .store
            .get(skipped.rotation_id.as_deref()?)
            .filter(|r| {
                r.step == Step::RevokeManual
                    && !r.is_rolling_back()
                    && r.provider == provider
                    && r.fingerprint == skipped.fingerprint
            })
            .cloned()?;
        let mut progress = Progress {
            record,
            provider,
            mode: ReplacementMode::Automatic,
            scope_widened: false,
            forced: Vec::new(),
        };
        let result = self.revoked_by_hand(&mut progress);
        Some(Outcome {
            rotation_id: progress.record.rotation_id.clone(),
            provider,
            fingerprint: progress.record.fingerprint.clone(),
            replacement_fingerprint: progress.record.replacement_fingerprint.clone(),
            consumers: progress.record.consumers.clone(),
            unchanged: Vec::new(),
            forced: Vec::new(),
            result,
        })
    }

    /// Records `--force` when it lets the revoke through past consumers
    /// that do not hold the replacement: `force: true` in the state file,
    /// then one `force` audit entry per such consumer (the log stamps the
    /// actor). Nothing is recorded when nothing was bypassed, or again when
    /// an earlier run already recorded it.
    fn record_force(
        &mut self,
        rotation: &PlannedRotation,
        progress: &mut Progress,
    ) -> Result<(), RecordError> {
        let bypassed = not_updated(rotation, &progress.record.consumers);
        if bypassed.is_empty() {
            return Ok(());
        }
        if !progress.record.force {
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
        }
        progress.forced = bypassed;
        Ok(())
    }

    /// Writes a note to the operator's stderr, when there is a terminal.
    fn notice(&mut self, text: &str) {
        match self.manual.as_mut() {
            Some(manual) => manual.term.stderr(text),
            None => tracing::info!("{}", text.trim_end()),
        }
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
            if progress.scope_widened {
                event = event.with_scope_widened();
            }
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

    /// Marks the rotation `needs_rollback` (SHA-258): it stopped at `step`
    /// because the replacement's value is gone. Recorded like a failure,
    /// best effort. Nothing is changed remotely; revoke is never called.
    fn needs_rollback(
        &mut self,
        progress: &mut Progress,
        step: AuditStep,
        reason: &str,
    ) -> RunResult {
        progress.record.step = Step::NeedsRollback;
        progress.record.failed_step = Some(step);
        let recorded = self
            .save(progress)
            .and_then(|()| self.event(progress, step, AuditOutcome::Failed, None, Some(reason)));
        if let Err(err) = recorded {
            tracing::warn!(
                rotation_id = %progress.record.rotation_id,
                "could not record that the rotation needs rollback: {err}"
            );
        }
        RunResult::NeedsRollback {
            reason: RedactedText::new(reason),
        }
    }
}

/// What a failed revoke may keep of the provider's error text (SHA-294).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamText {
    /// This process holds the verified replacement, registered with the
    /// redactor: the text is kept, redacted (SHA-293).
    Redacted,
    /// This process never held the replacement, so the redactor cannot
    /// find it in the text: only [`revoke_error_summary`] is kept.
    Summary,
}

/// Longest [`revoke_error_summary`], in characters.
pub const SUMMARY_MAX: usize = 200;

/// Provider error codes a summary may name: fixed identifiers that never
/// carry a value. AWS IAM and STS, OpenAI and npm.
const SAFE_ERROR_CODES: &[&str] = &[
    "AccessDenied",
    "AccessDeniedException",
    "ConcurrentModification",
    "EntityTemporarilyUnmodifiable",
    "ExpiredToken",
    "InvalidClientTokenId",
    "InvalidInput",
    "LimitExceeded",
    "NoSuchEntity",
    "ServiceFailure",
    "SignatureDoesNotMatch",
    "Throttling",
    "UnrecognizedClientException",
    "insufficient_permissions",
    "invalid_api_key",
    "invalid_request_error",
    "not_found",
    "rate_limit_exceeded",
    "server_error",
    "E401",
    "E403",
    "E404",
    "EOTP",
];

/// The safe summary of a revoke error (SHA-294) for a process that never
/// held the replacement: the provider and the kind of failure, then, when
/// the error text has them, the operation rotate named (`iam:...` or
/// `METHOD /path`), the HTTP status and an allowlisted provider error code.
/// Nothing else of the upstream text is kept. Redacted, and at most
/// [`SUMMARY_MAX`] characters.
pub fn revoke_error_summary(provider: &str, err: &ProviderError) -> String {
    use std::sync::LazyLock;

    static OPERATION: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"^((?:[a-z0-9-]+:[A-Za-z]+)|(?:(?:GET|POST|PUT|PATCH|DELETE) /[A-Za-z0-9_{}./-]{0,80})): ",
        )
        .expect("valid regex")
    });
    static STATUS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\b(?:HTTP|returned) ([1-5][0-9]{2})\b").expect("valid regex")
    });
    static CODE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(&format!(r"\b({})\b", SAFE_ERROR_CODES.join("|"))).expect("valid regex")
    });

    let (kind, text) = match err.base() {
        // `base()` never returns one; kept total without a panic.
        ProviderError::Guided { .. } => ("failed", ""),
        ProviderError::RateLimited { .. } => ("rate limited", ""),
        ProviderError::Transient(text) => ("transient failure", text.as_str()),
        ProviderError::Permanent(text) => ("failed", text.as_str()),
        ProviderError::Unsupported(text) => ("not supported by the provider", text.as_str()),
    };
    let mut summary = format!("{provider} revoke {kind}");
    if let Some(op) = OPERATION.captures(text) {
        let _ = write!(summary, "; operation {}", &op[1]);
    }
    if let Some(status) = STATUS.captures(text) {
        let _ = write!(summary, "; HTTP {}", &status[1]);
    }
    if let Some(code) = CODE.captures(text) {
        let _ = write!(summary, "; code {}", &code[1]);
    }
    summary.push_str("; provider message not kept: this run did not hold the replacement");
    let summary = crate::redact::redact(&summary).into_owned();
    match summary.char_indices().nth(SUMMARY_MAX) {
        Some((end, _)) => summary[..end].to_owned(),
        None => summary,
    }
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_else(|_| at.to_string())
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
        Step::NeedsRollback => "needs_rollback",
        Step::RevokeManual => "revoke_manual",
        Step::RolledBack => "rolled_back",
    }
}

/// The provider's revoke-by-hand text without its leading `manual: ` or
/// `unsupported: ` tag, for a sentence.
pub fn by_hand_text(instructions: &str) -> &str {
    ["manual: ", "unsupported: "]
        .iter()
        .find_map(|tag| instructions.strip_prefix(tag))
        .unwrap_or(instructions)
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
                ConsumerStatus::Restored => "restored",
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
        "Apply: {} revoked, {} pending revoke, {} held, {} failed, {} need rollback, {} revoke by hand, {} skipped.",
        count(|r| matches!(r, RunResult::Revoked)),
        count(|r| matches!(r, RunResult::PendingRevoke { .. })),
        count(|r| matches!(r, RunResult::Held { .. })),
        count(|r| matches!(r, RunResult::Failed { .. })),
        count(|r| matches!(r, RunResult::NeedsRollback { .. })),
        count(|r| matches!(r, RunResult::RevokeManual { .. })),
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
            RunResult::PendingRevoke {
                not_before,
                remaining,
            } => {
                notes.push(format!(
                    "{}: revoke pending until {} (in {}); the old secret stays valid until then; re-run rotate apply after that time to revoke it",
                    o.rotation_id,
                    rfc3339(*not_before),
                    remaining_text(*remaining)
                ));
                "pending revoke".to_owned()
            }
            RunResult::NeedsRollback { reason } => {
                notes.push(format!("{}: needs rollback: {reason}", o.rotation_id));
                "needs rollback".to_owned()
            }
            RunResult::RevokeManual { instructions } => {
                notes.push(format!(
                    "{}: revoke by hand: {}; the replacement is live and verified; re-run rotate apply once the old secret is deleted to record it",
                    o.rotation_id,
                    by_hand_text(instructions.as_str())
                ));
                "revoke by hand".to_owned()
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
        let RunResult::PendingRevoke { not_before, .. } = outcome.result else {
            panic!("{outcome:?}");
        };
        assert!(not_before > OffsetDateTime::now_utc() + time::Duration::minutes(9));
        assert!(f.log.calls().iter().all(|c| c.method != "revoke"));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::PendingRevoke);
        assert_eq!(stored.revoke_not_before, Some(not_before));
    }

    #[tokio::test]
    async fn needs_rollback_finished_and_no_scope_are_ineligible() {
        let value = "npm_apply_unit_inprogress";
        let mut f = fixture(value, MockProvider::new("npm"));
        let mut plan = plan(&mut f, value, "0s").await;
        assert_eq!(eligibility(&plan.rotations[0]), Ok(()));
        for step in [
            Step::Created,
            Step::ConsumersUpdated,
            Step::Verified,
            Step::PendingRevoke,
            Step::Failed,
        ] {
            plan.rotations[0].step = step;
            assert_eq!(eligibility(&plan.rotations[0]), Ok(()), "{step:?}");
        }

        plan.rotations[0].step = Step::NeedsRollback;
        let outcome = run(&mut f, &plan).await;
        assert_eq!(
            outcome.result,
            RunResult::Skipped(Ineligible::NeedsRollback)
        );
        assert!(f.log.is_empty());
        assert_eq!(run_status(&[outcome]), RunStatus::Failed);
        plan.rotations[0].step = Step::Revoked;
        assert_eq!(
            eligibility(&plan.rotations[0]),
            Err(Ineligible::Finished(Step::Revoked))
        );
        let outcome = Outcome::skipped(&plan.rotations[0], Ineligible::Finished(Step::Revoked));
        assert_eq!(run_status(&[outcome]), RunStatus::Done);

        // The stored step counts too.
        plan.rotations[0].step = Step::Planned;
        let mut stored = f.store.get(&plan.rotations[0].rotation_id).unwrap().clone();
        stored.step = Step::NeedsRollback;
        f.store.upsert(stored).unwrap();
        assert_eq!(
            eligibility_in(&plan.rotations[0], &f.store),
            Err(Ineligible::NeedsRollback)
        );

        plan.rotations[0].scope = None;
        assert_eq!(eligibility(&plan.rotations[0]), Err(Ineligible::NoScope));
        let outcome = Outcome::skipped(&plan.rotations[0], Ineligible::NoScope);
        assert_eq!(run_status(&[outcome]), RunStatus::Unsupported);
    }

    // SHA-258: where each recorded step resumes.
    /// SHA-288: no terminal is "no source", so a chain falls through to
    /// the plain failure; a typed code is trimmed; an empty one is refused.
    #[tokio::test]
    async fn prompt_otp_without_terminal_is_no_source() {
        struct Gone;
        impl Prompt for Gone {
            fn read_line(&mut self) -> Result<String, PromptError> {
                Err(PromptError::NoTerminal)
            }
            fn read_secret(
                &mut self,
                _: &str,
                _: &mut dyn Terminal,
            ) -> Result<SecretValue, PromptError> {
                Err(PromptError::NoTerminalForSecret)
            }
        }
        #[derive(Default)]
        struct Quiet;
        impl Terminal for Quiet {
            fn stdout(&mut self, _: &str) {}
            fn stderr(&mut self, _: &str) {}
        }
        let none = PromptOtp::new(Box::new(Gone), Box::new(Quiet));
        assert_eq!(
            none.one_time_password("q").await.unwrap_err(),
            OtpError::NoSource
        );
        let typed = PromptOtp::new(
            Box::new(ScriptedPrompt::new([" 271828\r"])),
            Box::new(Quiet),
        );
        let code = typed.one_time_password("q").await.unwrap();
        assert!(code.expose_secret(|b| b == b"271828"));
        let empty = PromptOtp::new(Box::new(ScriptedPrompt::new([""])), Box::new(Quiet));
        assert!(matches!(
            empty.one_time_password("q").await.unwrap_err(),
            OtpError::Failed(_)
        ));
    }

    #[test]
    fn resume_points() {
        let mut r = Rotation::new("rot-1", "npm", fp("npm_resume_points"));
        let at = |r: &Rotation| resume_point(r);
        assert_eq!(at(&r), Resume::Create);
        r.step = Step::Failed;
        r.failed_step = Some(AuditStep::Create);
        assert_eq!(at(&r), Resume::Create, "nothing was created");
        r.replacement_ref = Some("npm-ref-1".into());
        assert_eq!(at(&r), Resume::Update);
        r.failed_step = Some(AuditStep::Update);
        assert_eq!(at(&r), Resume::Update);
        r.failed_step = Some(AuditStep::Verify);
        assert_eq!(at(&r), Resume::Verify);
        for step in [AuditStep::Force, AuditStep::Revoke] {
            r.failed_step = Some(step);
            assert_eq!(at(&r), Resume::Revoke);
        }
        r.failed_step = None;
        for (step, point) in [
            (Step::Created, Resume::Update),
            (Step::ConsumersUpdated, Resume::Verify),
            (Step::Verified, Resume::Revoke),
            (Step::PendingRevoke, Resume::Revoke),
        ] {
            r.step = step;
            assert_eq!(at(&r), point, "{step:?}");
        }
        assert!(Resume::Create < Resume::Update && Resume::Verify < Resume::Revoke);
    }

    // SHA-258: a recorded time wins over the window; a hold still holds.
    #[test]
    fn resume_gate_uses_recorded_time() {
        let mut rotation = gate_rotation();
        rotation.overlap_window = "0s".parse().unwrap();
        let now = OffsetDateTime::now_utc();
        let later = now + time::Duration::minutes(5);
        let updated = [ConsumerState {
            consumer: "c".into(),
            consumer_ref: "c:1".into(),
            status: ConsumerStatus::Updated,
            holds: None,
        }];
        assert_eq!(
            resume_gate(&rotation, &updated, now, None, false),
            Gate::Revoke
        );
        assert_eq!(
            resume_gate(&rotation, &updated, now, Some(later), false),
            Gate::Wait(later)
        );
        assert_eq!(
            resume_gate(&rotation, &updated, later, Some(later), false),
            Gate::Revoke
        );
        rotation.overlap_window = "1h".parse().unwrap();
        assert_eq!(
            resume_gate(&rotation, &updated, later, Some(later), false),
            Gate::Revoke,
            "a longer --overlap does not move a recorded time"
        );
        let mut skipped = updated.clone();
        skipped[0].status = ConsumerStatus::Skipped;
        assert!(matches!(
            resume_gate(&rotation, &skipped, later, Some(later), false),
            Gate::Hold(_)
        ));
    }

    #[test]
    fn remaining_time_text() {
        let text = |secs| remaining_text(time::Duration::seconds(secs));
        assert_eq!(text(45), "45s");
        assert_eq!(text(599), "9m 59s");
        assert_eq!(text(3600 + 5 * 60 + 7), "1h 5m");
        assert_eq!(text(-3), "0s");
    }

    // SHA-258 AC6 in one process: a new executor does not hold the
    // replacement an earlier one created, so the rotation needs rollback.
    #[tokio::test]
    async fn new_executor_after_create_needs_rollback() {
        let value = "npm_apply_unit_lost";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "0s").await;
        f.gha
            .fail_next("update", ConsumerError::Transient("503".into()));
        let first = run(&mut f, &plan).await;
        assert!(matches!(first.result, RunResult::Failed { .. }));
        f.log.clear();

        let second = run(&mut f, &plan).await;
        let RunResult::NeedsRollback { reason } = &second.result else {
            panic!("{second:?}");
        };
        assert!(reason.to_string().contains("run rotate rollback"));
        assert!(mutating(&f.log).is_empty(), "{:?}", mutating(&f.log));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::NeedsRollback);
        assert_eq!(stored.failed_step, Some(AuditStep::Update));
        assert_eq!(run_status(std::slice::from_ref(&second)), RunStatus::Failed);
        let summary = render_summary(&[second]);
        assert!(summary.contains("1 need rollback"), "{summary}");
        assert!(
            summary.contains("needs rollback: the replacement value"),
            "{summary}"
        );

        let third = run(&mut f, &plan).await;
        assert_eq!(third.result, RunResult::Skipped(Ineligible::NeedsRollback));
        assert!(f.log.is_empty());
    }

    // SHA-258: --wait sleeps out the window, then revokes in the same run.
    #[tokio::test]
    async fn wait_revokes_after_the_window() {
        let value = "npm_apply_unit_wait";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "1s").await;
        let mut term = Recorder::default();
        let started = std::time::Instant::now();
        let outcome = {
            let mut executor =
                Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit)
                    .with_wait(true)
                    .with_manual(ReplacementSource::Supplied(None), &mut term);
            executor.run(&plan.rotations[0]).await
        };
        assert_eq!(outcome.result, RunResult::Revoked);
        assert!(started.elapsed() >= std::time::Duration::from_secs(1));
        assert!(term.err.contains("waiting until"), "{}", term.err);
        let steps = audit_steps(&f);
        assert!(steps.contains(&(AuditStep::Revoke, AuditOutcome::Skipped, None)));
        assert_eq!(steps.last().unwrap().0, AuditStep::Revoke);
        assert_eq!(steps.last().unwrap().1, AuditOutcome::Ok);
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

    fn gate_rotation() -> PlannedRotation {
        PlannedRotation {
            rotation_id: "rot-1".into(),
            provider: "npm",
            fingerprint: fp("npm_gate"),
            credential: crate::provider::Credential::Token(SecretValue::from("npm_gate_value")),
            scope: None,
            scope_error: None,
            replacement_mode: ReplacementMode::Automatic,
            scope_widening: None,
            consumers: Vec::new(),
            lookup_errors: Vec::new(),
            revoke_action: "x",
            overlap_window: "0s".parse().unwrap(),
            revoke_blocker: None,
            blockers: Vec::new(),
            step: Step::Planned,
            sources: Vec::new(),
            recorded: None,
        }
    }

    #[test]
    fn gate_holds_waits_or_revokes() {
        let status = |s| ConsumerState {
            consumer: "c".into(),
            consumer_ref: "c:1".into(),
            status: s,
            holds: None,
        };
        let rotation = gate_rotation();
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

    // SHA-289: revoke by hand.

    const BY_HAND: &str = crate::provider::openai::REVOKE_NEEDS_ADMIN;

    fn last_audit(f: &Fixture) -> crate::audit::AuditEntry {
        crate::audit::read_all(&f.audit_path)
            .unwrap()
            .map(Result::unwrap)
            .last()
            .unwrap()
    }

    fn calls(log: &CallLog) -> Vec<String> {
        log.calls()
            .into_iter()
            .map(|c| format!("{}.{}", c.target, c.method))
            .collect()
    }

    /// Runs `value` to `revoke_manual` with a provider that cannot revoke.
    async fn to_revoke_manual(value: &str) -> (Fixture, Plan) {
        let mut f = fixture(value, MockProvider::new("npm").manual_revoke(BY_HAND));
        let plan = plan(&mut f, value, "0s").await;
        let outcome = run(&mut f, &plan).await;
        assert_eq!(
            outcome.result,
            RunResult::RevokeManual {
                instructions: RedactedText::new(BY_HAND)
            }
        );
        f.log.clear();
        (f, plan)
    }

    // T1 (AC1)
    #[tokio::test]
    async fn manual_revoke_never_calls_revoke() {
        let value = "npm_apply_unit_by_hand";
        let (f, plan) = to_revoke_manual(value).await;
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::RevokeManual);
        assert_eq!(stored.revoke_instructions.as_deref(), Some(BY_HAND));
        assert_eq!(stored.failed_step, None);
        assert!(!f.provider.is_revoked(&fp(value)));
        let entry = last_audit(&f);
        assert_eq!(entry.step, AuditStep::Revoke);
        assert_eq!(entry.outcome, AuditOutcome::Skipped);
        assert_eq!(entry.error.unwrap().as_str(), BY_HAND);
        assert!(
            !f.store
                .get(&plan.rotations[0].rotation_id)
                .unwrap()
                .step
                .is_terminal(),
            "revoke_manual is not terminal"
        );
    }

    #[tokio::test]
    async fn unsupported_revoke_becomes_revoke_manual() {
        let value = "npm_apply_unit_unsupported";
        let mut f = fixture(value, MockProvider::new("npm"));
        let plan = plan(&mut f, value, "0s").await;
        f.provider.fail_always(
            "revoke",
            ProviderError::Unsupported("delete it at https://example.test".into()),
        );
        let outcome = run(&mut f, &plan).await;
        assert_eq!(
            run_status(std::slice::from_ref(&outcome)),
            RunStatus::RevokeManual
        );
        assert!(mutating(&f.log).contains(&"npm.revoke".to_owned()));
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::RevokeManual);
        assert_eq!(
            stored.revoke_instructions.as_deref(),
            Some("delete it at https://example.test")
        );
    }

    /// SHA-293: a revoke error or revoke-by-hand text that echoes the
    /// replacement is redacted. The replacement is out of `held` once
    /// verified, but stays registered until revoke is over.
    #[tokio::test]
    async fn revoke_text_echoing_the_replacement_is_redacted() {
        // A provider name of its own per case, so no other test registers
        // the same replacement value.
        let cases = [
            ("unsupported", "sha293unsupported", Step::RevokeManual),
            ("permanent", "sha293permanent", Step::Failed),
        ];
        for (kind, name, step) in cases {
            let value = format!("npm_apply_unit_echo_{kind}");
            let replacement = format!("npm_{name}-replacement-1");
            let mut f = fixture(&value, MockProvider::new(name));
            let plan = plan(&mut f, &value, "0s").await;
            let echo = format!("refused; the new key {replacement} stays live");
            let error = match kind {
                "unsupported" => ProviderError::Unsupported(echo),
                _ => ProviderError::Permanent(echo),
            };
            f.provider.fail_always("revoke", error);
            let outcome = run(&mut f, &plan).await;
            drop(plan);
            let stored = f.store.get(&outcome.rotation_id).unwrap().clone();
            assert_eq!(stored.step, step, "{kind}");
            // The state record holds the text only as revoke instructions.
            let state = serde_json::to_string(&stored).unwrap();
            let texts = [
                format!("{:?}", outcome.result),
                format!("{:?}", last_audit(&f)),
                stored.revoke_instructions.clone().unwrap_or_default(),
            ];
            for (i, text) in texts.iter().enumerate() {
                assert!(
                    !text.contains(&replacement),
                    "{kind}: the replacement leaked"
                );
                assert!(
                    text.contains("[REDACTED") || (i == 2 && step == Step::Failed),
                    "{kind}: {text}"
                );
            }
            assert!(!state.contains(&replacement), "{kind}: in the state record");
        }
    }

    fn two_hours_later() -> OffsetDateTime {
        OffsetDateTime::now_utc() + time::Duration::hours(2)
    }

    /// SHA-294 T5 (AC5): a revoke resumed by a new executor after the
    /// overlap window, which never held the replacement, keeps only the
    /// safe summary of an error that echoes it, in the result, the audit
    /// entry and `revoke_instructions`.
    #[tokio::test]
    async fn resumed_revoke_keeps_only_a_safe_summary() {
        let cases = [
            ("unsupported", "sha294unsupported", Step::RevokeManual),
            ("permanent", "sha294permanent", Step::Failed),
        ];
        for (kind, name, step) in cases {
            let value = format!("npm_apply_unit_resume_{kind}");
            let replacement = format!("npm_{name}-replacement-1");
            let mut f = fixture(&value, MockProvider::new(name));
            let plan = plan(&mut f, &value, "1h").await;
            let first = run(&mut f, &plan).await;
            assert!(
                matches!(first.result, RunResult::PendingRevoke { .. }),
                "{kind}: {first:?}"
            );
            let echo = format!(
                "DELETE /-/npm/v1/tokens/token: npm returned 403: E403 the new key {replacement} stays live"
            );
            let error = match kind {
                "unsupported" => ProviderError::Unsupported(echo),
                _ => ProviderError::Permanent(echo),
            };
            f.provider.fail_always("revoke", error);
            let outcome = {
                let mut executor =
                    Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit)
                        .with_clock(two_hours_later);
                executor.run(&plan.rotations[0]).await
            };
            let stored = f.store.get(&outcome.rotation_id).unwrap().clone();
            assert_eq!(stored.step, step, "{kind}");
            let summary = format!(
                "{name} revoke {}; operation DELETE /-/npm/v1/tokens/token; HTTP 403; code E403; provider message not kept",
                match kind {
                    "unsupported" => "not supported by the provider",
                    _ => "failed",
                }
            );
            let audit = last_audit(&f);
            let texts = [
                format!("{:?}", outcome.result),
                audit.error.as_ref().unwrap().as_str().to_owned(),
                stored.revoke_instructions.clone().unwrap_or_default(),
                serde_json::to_string(&stored).unwrap(),
            ];
            for (i, text) in texts.iter().enumerate() {
                assert!(
                    !text.contains(&replacement),
                    "{kind} {i}: the replacement leaked"
                );
                assert!(
                    !text.contains("stays live"),
                    "{kind} {i}: upstream text kept"
                );
                if i < 2 || step == Step::RevokeManual {
                    assert!(text.contains(&summary), "{kind} {i}: {text}");
                }
            }
        }
    }

    /// SHA-298 T3 (AC3): rotate's own guidance on a provider error survives
    /// a resumed revoke's summary; the upstream text still does not.
    #[tokio::test]
    async fn resumed_revoke_keeps_guidance() {
        const GUIDANCE: &str = "set ROTATE_TEST_OPERATOR to a session token";
        let cases = [
            ("unsupported", "sha298unsupported", Step::RevokeManual),
            ("permanent", "sha298permanent", Step::Failed),
        ];
        for (kind, name, step) in cases {
            let value = format!("npm_apply_unit_guided_{kind}");
            let replacement = format!("npm_{name}-replacement-1");
            let mut f = fixture(&value, MockProvider::new(name));
            let plan = plan(&mut f, &value, "1h").await;
            let first = run(&mut f, &plan).await;
            assert!(
                matches!(first.result, RunResult::PendingRevoke { .. }),
                "{kind}: {first:?}"
            );
            let echo = format!("npm returned 403: the new key {replacement} stays live");
            let error = match kind {
                "unsupported" => ProviderError::Unsupported(echo),
                _ => ProviderError::Permanent(echo),
            };
            f.provider
                .fail_always("revoke", error.with_guidance(GUIDANCE));
            let outcome = {
                let mut executor =
                    Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit)
                        .with_clock(two_hours_later);
                executor.run(&plan.rotations[0]).await
            };
            let stored = f.store.get(&outcome.rotation_id).unwrap().clone();
            assert_eq!(stored.step, step, "{kind}");
            let audit = last_audit(&f);
            let mut texts = vec![
                format!("{:?}", outcome.result),
                audit.error.as_ref().unwrap().as_str().to_owned(),
                serde_json::to_string(&stored).unwrap(),
            ];
            if step == Step::RevokeManual {
                let instructions = stored.revoke_instructions.clone().unwrap_or_default();
                // The guidance replaces the generic fallback.
                assert!(instructions.starts_with(GUIDANCE), "{instructions}");
                assert!(!instructions.contains(REVOKE_BY_HAND_FALLBACK));
                texts.push(instructions);
            }
            for (i, text) in texts.iter().enumerate() {
                assert!(
                    !text.contains(&replacement),
                    "{kind} {i}: the replacement leaked"
                );
                assert!(
                    !text.contains("stays live"),
                    "{kind} {i}: upstream text kept"
                );
                // The state record (2) keeps text only as revoke_instructions.
                if i != 2 || step == Step::RevokeManual {
                    assert!(text.contains("provider message not kept"), "{kind} {i}");
                    assert!(text.contains(GUIDANCE), "{kind} {i}: {text}");
                }
            }
        }
    }

    /// SHA-298 T4 (AC4): in the process that holds the replacement, a
    /// guided `Unsupported` revoke is still a revoke by hand with the
    /// provider's (redacted) instructions.
    #[tokio::test]
    async fn guided_unsupported_revoke_in_process_is_by_hand() {
        let value = "npm_apply_unit_guided_inprocess";
        let mut f = fixture(value, MockProvider::new("sha298inproc"));
        f.provider.fail_always(
            "revoke",
            ProviderError::Unsupported("delete it at https://example.test".into())
                .with_guidance("guidance"),
        );
        let plan = plan(&mut f, value, "0s").await;
        let outcome = run(&mut f, &plan).await;
        match &outcome.result {
            RunResult::RevokeManual { instructions } => {
                assert_eq!(instructions.as_str(), "delete it at https://example.test");
            }
            other => panic!("expected a revoke by hand, got {other:?}"),
        }
    }

    /// SHA-294 T5: the summary keeps the operation, status and an
    /// allowlisted code only, is redacted and at most 200 characters.
    #[test]
    fn revoke_error_summary_format() {
        let echo = "npm_npmreplacement-xyz";
        let cases = [
            (
                ProviderError::Permanent(format!(
                    "iam:UpdateAccessKey: AccessDenied (HTTP 403) {echo}"
                )),
                "aws revoke failed; operation iam:UpdateAccessKey; HTTP 403; code AccessDenied; ",
            ),
            (
                ProviderError::Transient(format!(
                    "DELETE /v1/organization/projects/{{id}}/api_keys/{{key_id}}: OpenAI returned 503 (server_error) {echo}"
                )),
                "aws revoke transient failure; operation DELETE /v1/organization/projects/{id}/api_keys/{key_id}; HTTP 503; code server_error; ",
            ),
            (
                ProviderError::Permanent(format!("POST /credentials/revoke: GitHub returned 422: {echo}")),
                "aws revoke failed; operation POST /credentials/revoke; HTTP 422; provider",
            ),
            (
                ProviderError::Permanent(format!("{echo}: refused")),
                "aws revoke failed; provider message not kept",
            ),
            (
                ProviderError::RateLimited { retry_after: None },
                "aws revoke rate limited; provider",
            ),
        ];
        for (err, start) in cases {
            let summary = revoke_error_summary("aws", &err);
            assert!(summary.starts_with(start), "{summary}");
            assert!(!summary.contains(echo), "{summary}");
            assert!(summary.chars().count() <= SUMMARY_MAX, "{summary}");
        }
        let long = ProviderError::Permanent(format!("{}: x", "a".repeat(500)));
        assert!(
            revoke_error_summary(&"p".repeat(300), &long)
                .chars()
                .count()
                == SUMMARY_MAX
        );
    }

    // T7 (AC7)
    #[tokio::test]
    async fn permanent_or_transient_revoke_error_is_failed() {
        for error in [
            ProviderError::Permanent("denied".into()),
            ProviderError::Transient("503".into()),
        ] {
            let value = format!("npm_apply_unit_revoke_err_{}", error.is_retryable());
            let mut f = fixture(&value, MockProvider::new("npm"));
            let plan = plan(&mut f, &value, "0s").await;
            f.provider.fail_always("revoke", error.clone());
            let outcome = run(&mut f, &plan).await;
            assert!(
                matches!(
                    outcome.result,
                    RunResult::Failed {
                        step: AuditStep::Revoke,
                        ..
                    }
                ),
                "{error}: {outcome:?}"
            );
            let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
            assert_eq!(stored.step, Step::Failed);
            assert_eq!(stored.failed_step, Some(AuditStep::Revoke));
            assert_eq!(stored.revoke_instructions, None);
        }
    }

    // T8 (AC8)
    #[tokio::test]
    async fn manual_revoke_waits_for_the_window_first() {
        fn later() -> OffsetDateTime {
            OffsetDateTime::now_utc() + time::Duration::hours(1)
        }
        let value = "npm_apply_unit_by_hand_window";
        let mut f = fixture(value, MockProvider::new("npm").manual_revoke(BY_HAND));
        let plan = plan(&mut f, value, "10m").await;
        let outcome = run(&mut f, &plan).await;
        assert!(
            matches!(outcome.result, RunResult::PendingRevoke { .. }),
            "{outcome:?}"
        );
        assert_eq!(run_status(&[outcome]), RunStatus::Pending);
        let id = &plan.rotations[0].rotation_id;
        assert_eq!(f.store.get(id).unwrap().step, Step::PendingRevoke);
        assert_eq!(f.store.get(id).unwrap().revoke_instructions, None);

        let outcome = Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit)
            .with_clock(later)
            .run(&plan.rotations[0])
            .await;
        assert!(
            matches!(outcome.result, RunResult::RevokeManual { .. }),
            "{outcome:?}"
        );
        assert_eq!(f.store.get(id).unwrap().step, Step::RevokeManual);
        assert!(f.log.calls().iter().all(|c| c.method != "revoke"));
    }

    // T5 (AC5): the old secret stopped working between plan and apply.
    #[tokio::test]
    async fn rerun_records_revoked_once_check_valid_says_invalid() {
        let value = "npm_apply_unit_by_hand_done";
        let (mut f, plan) = to_revoke_manual(value).await;
        f.provider.mark_revoked(fp(value));
        let outcome = run(&mut f, &plan).await;
        assert_eq!(outcome.result, RunResult::Revoked);
        assert_eq!(calls(&f.log), ["npm.check_valid"]);
        assert_eq!(run_status(&[outcome]), RunStatus::Done);
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::Revoked);
        assert_eq!(stored.revoke_instructions, None);
        let entry = last_audit(&f);
        assert_eq!(entry.step, AuditStep::Revoke);
        assert_eq!(entry.outcome, AuditOutcome::Ok);
        assert_eq!(entry.error.unwrap().as_str(), REVOKED_BY_HAND);
    }

    // T5 (AC5): the plan already saw it invalid; apply records it with no
    // call at all.
    #[tokio::test]
    async fn plan_skip_records_revoked_by_hand_without_a_call() {
        let value = "npm_apply_unit_by_hand_plan";
        let (mut f, first) = to_revoke_manual(value).await;
        let id = first.rotations[0].rotation_id.clone();
        f.provider.mark_revoked(fp(value));
        let mut again = plan(&mut f, value, "0s").await;
        assert!(again.rotations.is_empty());
        assert_eq!(again.skipped[0].reason, "invalid");
        crate::plan::mark_revoked_by_hand(&mut again, f.store.rotations());
        assert_eq!(again.skipped[0].reason, crate::plan::REVOKED_BY_HAND);
        assert_eq!(again.skipped[0].rotation_id.as_deref(), Some(id.as_str()));

        let mut executor = Executor::new(&f.providers, &f.consumers, &mut f.store, &mut f.audit);
        let outcome = executor.confirm_revoked_by_hand(&again.skipped[0]).unwrap();
        assert_eq!(outcome.rotation_id, id);
        assert_eq!(outcome.result, RunResult::Revoked);
        // Already recorded: nothing to do a second time.
        assert!(executor
            .confirm_revoked_by_hand(&again.skipped[0])
            .is_none());
        drop(executor);
        assert!(f.log.calls().is_empty(), "{:?}", calls(&f.log));
        assert_eq!(f.store.get(&id).unwrap().step, Step::Revoked);
        let entry = last_audit(&f);
        assert_eq!(entry.outcome, AuditOutcome::Ok);
        assert_eq!(entry.error.unwrap().as_str(), REVOKED_BY_HAND);
    }

    // T6 (AC6)
    #[tokio::test]
    async fn rerun_while_still_valid_only_checks() {
        let value = "npm_apply_unit_by_hand_valid";
        let (mut f, plan) = to_revoke_manual(value).await;
        let outcome = run(&mut f, &plan).await;
        assert_eq!(calls(&f.log), ["npm.check_valid"]);
        assert_eq!(
            outcome.result,
            RunResult::RevokeManual {
                instructions: RedactedText::new(BY_HAND)
            }
        );
        assert_eq!(run_status(&[outcome]), RunStatus::RevokeManual);
        let stored = f.store.get(&plan.rotations[0].rotation_id).unwrap();
        assert_eq!(stored.step, Step::RevokeManual);
        let entry = last_audit(&f);
        assert_eq!(entry.outcome, AuditOutcome::Skipped);
        let text = entry.error.unwrap();
        assert!(
            text.as_str().starts_with("the old secret still works; "),
            "{text}"
        );

        // A check that fails leaves it too.
        f.log.clear();
        f.provider
            .fail_next("check_valid", ProviderError::Transient("timeout".into()));
        let outcome = run(&mut f, &plan).await;
        assert!(matches!(outcome.result, RunResult::RevokeManual { .. }));
        assert_eq!(calls(&f.log), ["npm.check_valid"]);
    }

    // T3 (AC3)
    #[test]
    fn summary_line_for_revoke_by_hand() {
        let mut o = Outcome::skipped(&gate_rotation(), Ineligible::NoScope);
        o.rotation_id = "rot-3".into();
        o.result = RunResult::RevokeManual {
            instructions: RedactedText::new(BY_HAND),
        };
        let summary = render_summary(&[o]);
        assert!(
            summary.starts_with(
                "Apply: 0 revoked, 0 pending revoke, 0 held, 0 failed, 0 need rollback, 1 revoke by hand, 0 skipped."
            ),
            "{summary}"
        );
        let line = summary
            .lines()
            .find(|l| l.starts_with("rot-3: "))
            .expect("a note line");
        assert_eq!(
            line,
            "rot-3: revoke by hand: without an Admin API key rotate cannot delete OpenAI keys; delete it at https://platform.openai.com/api-keys; the replacement is live and verified; re-run rotate apply once the old secret is deleted to record it"
        );
        assert!(summary.contains("revoke by hand\n"), "{summary}");
        assert_eq!(
            by_hand_text(crate::provider::github::INSTALLATION_UNSUPPORTED),
            &crate::provider::github::INSTALLATION_UNSUPPORTED["unsupported: ".len()..]
        );
    }

    // T4 (AC4)
    #[test]
    fn run_status_precedence_with_revoke_by_hand() {
        let with = |result: RunResult| {
            let mut o = Outcome::skipped(&gate_rotation(), Ineligible::NoScope);
            o.result = result;
            o
        };
        let manual = || {
            with(RunResult::RevokeManual {
                instructions: RedactedText::new(BY_HAND),
            })
        };
        let failed = || {
            with(RunResult::Failed {
                step: AuditStep::Update,
                error: RedactedText::new("denied"),
            })
        };
        let pending = || {
            with(RunResult::PendingRevoke {
                not_before: OffsetDateTime::now_utc(),
                remaining: time::Duration::minutes(1),
            })
        };
        let unsupported = || with(RunResult::Skipped(Ineligible::NoScope));
        let cases = [
            (vec![failed(), manual()], RunStatus::Failed),
            (vec![manual(), pending()], RunStatus::RevokeManual),
            (vec![pending(), manual()], RunStatus::RevokeManual),
            (vec![manual(), unsupported()], RunStatus::RevokeManual),
            (vec![pending(), unsupported()], RunStatus::Pending),
            (
                vec![manual(), with(RunResult::Revoked)],
                RunStatus::RevokeManual,
            ),
        ];
        for (outcomes, expected) in cases {
            assert_eq!(run_status(&outcomes), expected, "{outcomes:?}");
        }
    }

    #[test]
    fn revoke_manual_resumes_at_revoke_and_is_eligible() {
        let mut r = Rotation::new("rot-1", "npm", fp("npm_resume_manual"));
        r.step = Step::RevokeManual;
        r.replacement_ref = Some("npm-ref-1".into());
        assert_eq!(resume_point(&r), Resume::Revoke);
        assert_eq!(step_eligibility(Step::RevokeManual), Ok(()));
    }

    // SHA-286: batched revokes.

    /// Delegates every method to a [`MockProvider`] and records the size of
    /// each `revoke_batch` call, in a list shared between recorders.
    struct BatchRecorder {
        inner: MockProvider,
        sizes: Arc<Mutex<Vec<usize>>>,
    }

    #[async_trait::async_trait]
    impl Provider for BatchRecorder {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn replacement_mode(&self) -> ReplacementMode {
            self.inner.replacement_mode()
        }
        fn manual_revoke(&self, scope: Option<&crate::provider::Scope>) -> Option<&'static str> {
            Provider::manual_revoke(&self.inner, scope)
        }
        fn identify(&self, finding: &Finding) -> Option<crate::provider::Confidence> {
            self.inner.identify(finding)
        }
        async fn check_valid(&self, credential: &Credential) -> Result<Validity, ProviderError> {
            self.inner.check_valid(credential).await
        }
        async fn describe_scope(
            &self,
            credential: &Credential,
        ) -> Result<crate::provider::Scope, ProviderError> {
            self.inner.describe_scope(credential).await
        }
        async fn create_replacement(
            &self,
            credential: &Credential,
        ) -> Result<Replacement, ProviderError> {
            self.inner.create_replacement(credential).await
        }
        async fn verify(
            &self,
            credential: &Credential,
            identity: &crate::provider::Identity,
        ) -> Result<(), ProviderError> {
            self.inner.verify(credential, identity).await
        }
        async fn revoke(&self, credential: &Credential) -> Result<Revoked, ProviderError> {
            self.inner.revoke(credential).await
        }
        async fn revoke_batch(
            &self,
            credentials: &[&Credential],
        ) -> Vec<Result<Revoked, ProviderError>> {
            self.sizes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(credentials.len());
            self.inner.revoke_batch(credentials).await
        }
        async fn restore(
            &self,
            restore_ref: &str,
        ) -> Result<crate::provider::RestoreOutcome, ProviderError> {
            self.inner.restore(restore_ref).await
        }
    }

    /// Two batch-recording mock providers, `npm` (`npm_`) and `pypi`
    /// (`pypi_`), sharing one call log and one size list; no consumers.
    struct Batch {
        _dir: tempfile::TempDir,
        store: StateStore,
        audit: AuditLog,
        audit_path: std::path::PathBuf,
        log: CallLog,
        providers: ProviderRegistry,
        consumers: ConsumerRegistry,
        sizes: Arc<Mutex<Vec<usize>>>,
    }

    fn batch_fixture() -> Batch {
        let dir = tempfile::tempdir().unwrap();
        let log = CallLog::new();
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let mut providers = ProviderRegistry::new();
        for (name, prefix) in [("npm", "npm_"), ("pypi", "pypi_")] {
            providers.register(Arc::new(BatchRecorder {
                inner: MockProvider::new(name)
                    .identify_prefix(prefix)
                    .log(log.clone()),
                sizes: sizes.clone(),
            }));
        }
        let audit_path = dir.path().join("audit.jsonl");
        Batch {
            store: StateStore::open(dir.path().join("state.json")).unwrap(),
            audit: AuditLog::open_as(&audit_path, "tester@host").unwrap(),
            audit_path,
            _dir: dir,
            log,
            providers,
            consumers: ConsumerRegistry::new(),
            sizes,
        }
    }

    async fn plan_many(b: &mut Batch, values: &[&str]) -> Plan {
        let findings = values
            .iter()
            .map(|v| Finding::new(SecretValue::from(*v), "Mock", SourceLocation::file("a")))
            .collect();
        let assessed = assess(findings, &b.providers, &AssessOptions::default()).await;
        let mut plan = crate::plan::build(
            assessed,
            &b.providers,
            &b.consumers,
            "0s".parse().unwrap(),
            &ConsumersConfig::default(),
        )
        .await;
        crate::plan::assign_ids(&mut plan, &mut b.store).unwrap();
        assert_eq!(plan.rotations.len(), values.len());
        b.log.clear();
        plan
    }

    /// The rotation of `value` in `plan`, by fingerprint.
    fn rotation_of<'p>(plan: &'p Plan, value: &str) -> &'p PlannedRotation {
        plan.rotations
            .iter()
            .find(|r| r.fingerprint == fp(value))
            .unwrap()
    }

    /// Moves `value`'s rotation to `pending_revoke` until `at`, as an
    /// earlier run with an overlap window would have left it.
    fn seed_pending(b: &mut Batch, plan: &Plan, value: &str, at: OffsetDateTime) {
        let id = &rotation_of(plan, value).rotation_id;
        let mut record = b.store.get(id).unwrap().clone();
        record.step = Step::PendingRevoke;
        record.revoke_not_before = Some(at);
        record.replacement_ref = Some(format!("{id}-ref"));
        record.replacement_fingerprint = Some(fp(&format!("{value}-replacement")));
        b.store.upsert(record).unwrap();
    }

    fn sizes(b: &Batch) -> Vec<usize> {
        b.sizes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// SHA-286 T2 (AC2), executor side: the rotations that pass their gate
    /// are revoked with one `revoke_batch` per provider, in order of first
    /// appearance, each recorded on its own.
    #[tokio::test]
    async fn ready_rotations_are_revoked_in_one_batch_per_provider() {
        let mut b = batch_fixture();
        let values = [
            "npm_sha286_batch_a",
            "pypi_sha286_batch_a",
            "npm_sha286_batch_b",
            "pypi_sha286_batch_b",
            "npm_sha286_batch_c",
        ];
        let plan = plan_many(&mut b, &values).await;
        let requested: Vec<&PlannedRotation> =
            values.iter().map(|v| rotation_of(&plan, v)).collect();
        let outcomes = Executor::new(&b.providers, &b.consumers, &mut b.store, &mut b.audit)
            .run_all(&requested)
            .await;

        assert_eq!(sizes(&b), [3, 2]);
        assert_eq!(outcomes.len(), values.len());
        for (outcome, value) in outcomes.iter().zip(values) {
            assert_eq!(outcome.fingerprint, fp(value), "input order");
            assert_eq!(outcome.result, RunResult::Revoked, "{value}");
            let stored = b.store.get(&outcome.rotation_id).unwrap();
            assert_eq!(stored.step, Step::Revoked);
            assert!(stored.restore_ref.is_some(), "{value}");
        }
        // Every create and verify comes before the first revoke.
        let methods: Vec<String> = b.log.calls().into_iter().map(|c| c.method).collect();
        let first_revoke = methods.iter().position(|m| m == "revoke").unwrap();
        assert!(methods[first_revoke..].iter().all(|m| m == "revoke"));
        assert_eq!(methods[first_revoke..].len(), values.len());
        let revokes = crate::audit::read_all(&b.audit_path)
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| e.step == AuditStep::Revoke && e.outcome == AuditOutcome::Ok)
            .count();
        assert_eq!(revokes, values.len());
        assert_eq!(run_status(&outcomes), RunStatus::Done);
    }

    /// SHA-286 T8 (AC8), unit half: with `--wait`, a provider group waits
    /// once, for its latest `not_before`, and a group with nothing to wait
    /// for is revoked first. A clock past every time means no wait at all.
    #[tokio::test]
    async fn wait_groups_by_latest_not_before() {
        let now = OffsetDateTime::now_utc();
        let values = ["npm_sha286_wait_a", "npm_sha286_wait_b"];

        let mut b = batch_fixture();
        let plan = plan_many(&mut b, &values).await;
        seed_pending(&mut b, &plan, values[0], now + time::Duration::seconds(1));
        seed_pending(&mut b, &plan, values[1], now + time::Duration::seconds(2));
        let mut term = Recorder::default();
        let started = std::time::Instant::now();
        let outcomes = {
            let requested: Vec<&PlannedRotation> = plan.rotations.iter().collect();
            Executor::new(&b.providers, &b.consumers, &mut b.store, &mut b.audit)
                .with_wait(true)
                .with_clock(two_hours_later)
                .with_manual(ReplacementSource::Supplied(None), &mut term)
                .run_all(&requested)
                .await
        };
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(outcomes.iter().all(|o| o.result == RunResult::Revoked));
        assert_eq!(sizes(&b), [2]);
        assert!(!term.err.contains("waiting until"), "{}", term.err);

        let mut b = batch_fixture();
        let other = "pypi_sha286_wait_c";
        let plan = plan_many(&mut b, &[values[0], values[1], other]).await;
        let started = std::time::Instant::now();
        let now = OffsetDateTime::now_utc();
        seed_pending(&mut b, &plan, values[0], now + time::Duration::seconds(1));
        seed_pending(
            &mut b,
            &plan,
            values[1],
            now + time::Duration::milliseconds(1500),
        );
        let ids: Vec<String> = values
            .iter()
            .map(|v| rotation_of(&plan, v).rotation_id.clone())
            .collect();
        let mut term = Recorder::default();
        let outcomes = {
            let requested: Vec<&PlannedRotation> = [values[0], values[1], other]
                .iter()
                .map(|v| rotation_of(&plan, v))
                .collect();
            Executor::new(&b.providers, &b.consumers, &mut b.store, &mut b.audit)
                .with_wait(true)
                .with_manual(ReplacementSource::Supplied(None), &mut term)
                .run_all(&requested)
                .await
        };
        assert!(started.elapsed() >= std::time::Duration::from_millis(1400));
        assert!(outcomes.iter().all(|o| o.result == RunResult::Revoked));
        // The other provider's batch precedes the npm group's wait.
        assert_eq!(sizes(&b), [1, 2]);
        assert_eq!(term.err.matches("waiting until").count(), 1, "{}", term.err);
        let notice = term
            .err
            .lines()
            .find(|l| l.contains("waiting until"))
            .unwrap();
        assert!(
            notice.contains(&ids[0]) && notice.contains(&ids[1]),
            "{notice}"
        );
        assert!(notice.contains(&rfc3339(now + time::Duration::milliseconds(1500))));
        let revoked: Vec<String> = crate::audit::read_all(&b.audit_path)
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| e.step == AuditStep::Revoke && e.outcome == AuditOutcome::Ok)
            .map(|e| e.rotation_id)
            .collect();
        assert_eq!(revoked[0], rotation_of(&plan, other).rotation_id);
        assert_eq!(revoked[1..], ids);
    }

    /// SHA-286: a rate-limited revoke says when to re-run; nothing else
    /// does.
    #[test]
    fn retry_hint_text() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(
            retry_hint(now, Some(std::time::Duration::from_secs(1800))),
            "re-run rotate apply after 1970-01-01T00:30:00Z (in 30m 0s) to revoke it"
        );
        assert_eq!(
            retry_hint(now, None),
            "re-run rotate apply once the provider's rate limit resets to revoke it"
        );
    }
}
